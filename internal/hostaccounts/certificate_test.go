package hostaccounts

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/olsweb"
)

// testIssuer is a CA made for one test: a root, or an intermediate below one.
type testIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// sameSiteTLS reports whether a rendered site names its own certificate
// files and maps exactly these domains on the HTTPS listener.
func sameSiteTLS(s olsweb.Site, covered ...string) bool {
	want := siteTLS(s.Name)
	return s.TLS.CertFile == want.CertFile && s.TLS.KeyFile == want.KeyFile && strings.Join(s.TLS.Domains, ",") == strings.Join(covered, ",")
}

func newTestKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func newTestIssuer(t *testing.T, name string, parent *testIssuer) *testIssuer {
	t.Helper()
	key := newTestKey(t, elliptic.P256())
	template := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testIssuer{cert: cert, key: key}
}

// leafSpec describes a leaf certificate; zero fields take working defaults.
type leafSpec struct {
	dns       []string
	cn        string
	notBefore time.Time
	notAfter  time.Time
	eku       []x509.ExtKeyUsage
	key       crypto.Signer
}

func (ca *testIssuer) leaf(t *testing.T, spec leafSpec) (*x509.Certificate, []byte) {
	t.Helper()
	if spec.notBefore.IsZero() {
		spec.notBefore = time.Now().Add(-time.Hour)
	}
	if spec.notAfter.IsZero() {
		spec.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: spec.cn},
		DNSNames:              spec.dns,
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           spec.eku,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, spec.key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pemOf("CERTIFICATE", der)
}

func pemOf(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func sec1PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf("EC PRIVATE KEY", der)
}

func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf("PRIVATE KEY", der)
}

// testChain is a working certificate for domain: leaf, intermediate and the
// key, as a panel would send them, and the root above them.
type testChain struct {
	leaf         *x509.Certificate
	leafPEM      []byte
	intermediate []byte
	root         []byte
	key          *ecdsa.PrivateKey
}

func newTestChain(t *testing.T, domain string) testChain {
	t.Helper()
	return newTestChainFor(t, domain)
}

// newTestChainFor is a chain whose leaf names these domains.
func newTestChainFor(t *testing.T, domains ...string) testChain {
	t.Helper()
	root := newTestIssuer(t, "Test Root", nil)
	mid := newTestIssuer(t, "Test Intermediate", root)
	key := newTestKey(t, elliptic.P256())
	leaf, leafPEM := mid.leaf(t, leafSpec{dns: domains, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, key: key})
	return testChain{leaf: leaf, leafPEM: leafPEM, intermediate: pemOf("CERTIFICATE", mid.cert.Raw), root: pemOf("CERTIFICATE", root.cert.Raw), key: key}
}

func (c testChain) certPEM() string { return string(c.leafPEM) + string(c.intermediate) }

func (c testChain) input(t *testing.T, revision uint64) CertificateInput {
	return CertificateInput{ExpectedRevision: revision, CertPEM: c.certPEM(), KeyPEM: string(sec1PEM(t, c.key)), Reason: "Let's Encrypt certificate"}
}

func fingerprintOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func TestParseCertificateAcceptsAndCanonicalises(t *testing.T) {
	c := newTestChain(t, "fixture.test")
	// CRLF line ends and blank lines around the blocks are only whitespace.
	certPEM := "\r\n" + strings.ReplaceAll(c.certPEM(), "\n", "\r\n") + "\n\n"
	b, err := parseCertificate(certPEM, string(sec1PEM(t, c.key)))
	if err != nil {
		t.Fatal(err)
	}
	if b.state != (CertificateState{NotAfter: c.leaf.NotAfter.Unix(), Fingerprint: fingerprintOf(c.leaf), Names: "fixture.test"}) || !validCertificateState(b.state) {
		t.Fatalf("state %+v", b.state)
	}
	if string(b.chainPEM) != c.certPEM() {
		t.Fatalf("chain is not the canonical leaf-first PEM:\n%s", b.chainPEM)
	}
	if string(b.keyPEM) != string(pkcs8PEM(t, c.key)) {
		t.Fatal("key is not written as PKCS #8")
	}
	// The canonical form parses to the same certificate: what is staged can
	// be read back by a recovery.
	again, err := parseCertificate(string(b.chainPEM), string(b.keyPEM))
	if err != nil || again.state != b.state {
		t.Fatalf("canonical form does not round-trip: %v", err)
	}

	// The other accepted key forms: PKCS #8 EC, P-384, RSA in PKCS #1 and #8.
	root := newTestIssuer(t, "Test Root", nil)
	p384 := newTestKey(t, elliptic.P384())
	_, p384Leaf := root.leaf(t, leafSpec{dns: []string{"fixture.test"}, key: p384})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, rsaLeaf := root.leaf(t, leafSpec{dns: []string{"fixture.test"}, key: rsaKey})
	for name, pair := range map[string][2][]byte{
		"pkcs8 ec": {c.leafPEM, pkcs8PEM(t, c.key)},
		"p-384":    {p384Leaf, sec1PEM(t, p384)},
		"rsa 1":    {rsaLeaf, pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))},
		"rsa 8":    {rsaLeaf, pkcs8PEM(t, rsaKey)},
	} {
		if _, err := parseCertificate(string(pair[0]), string(pair[1])); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseCertificateRefusesBadInput(t *testing.T) {
	c := newTestChain(t, "fixture.test")
	key := string(sec1PEM(t, c.key))
	root := newTestIssuer(t, "Test Root", nil)
	mid := newTestIssuer(t, "Test Intermediate", root)
	_, clientOnly := mid.leaf(t, leafSpec{dns: []string{"fixture.test"}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, key: c.key})
	p521 := newTestKey(t, elliptic.P521())
	_, p521Leaf := root.leaf(t, leafSpec{dns: []string{"fixture.test"}, key: p521})
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, smallLeaf := root.leaf(t, leafSpec{dns: []string{"fixture.test"}, key: small})
	block := strings.TrimSuffix(string(c.leafPEM), "\n")
	cases := []struct {
		name      string
		cert, key string
	}{
		{"empty certificate", "", key},
		{"empty key", c.certPEM(), ""},
		{"certificate too large", c.certPEM() + strings.Repeat("\n", maxCertificatePEM), key},
		{"key too large", c.certPEM(), key + strings.Repeat(" ", maxCertificatePEM)},
		{"garbage", "not a certificate", key},
		{"text before the chain", "chain:\n" + c.certPEM(), key},
		{"text after the chain", c.certPEM() + "trailing\n", key},
		{"truncated block", block[:len(block)-20], key},
		{"broken block before a good one", "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n" + c.certPEM(), key},
		{"undecodable DER", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", key},
		{"wrong block type", strings.ReplaceAll(c.certPEM(), "CERTIFICATE", "PUBLIC KEY"), key},
		{"headers in a block", strings.Replace(c.certPEM(), "-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1), key},
		{"intermediate before the leaf", string(c.intermediate) + string(c.leafPEM), key},
		// The key matches the leaf here, so only the order check refuses.
		{"root before the intermediate", string(c.leafPEM) + string(c.root) + string(c.intermediate), key},
		{"intermediate left out", string(c.leafPEM) + string(c.root), key},
		{"leaf repeated", string(c.leafPEM) + string(c.leafPEM), key},
		{"five certificates", c.certPEM() + string(c.intermediate) + string(c.intermediate) + string(c.intermediate), key},
		{"key of another certificate", c.certPEM(), string(sec1PEM(t, newTestKey(t, elliptic.P256())))},
		{"two keys", c.certPEM(), key + key},
		{"certificate as key", c.certPEM(), string(c.leafPEM)},
		{"no serverAuth", string(clientOnly), key},
		{"P-521 key", string(p521Leaf), string(sec1PEM(t, p521))},
		{"RSA 1024 key", string(smallLeaf), string(pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(small)))},
	}
	for _, tc := range cases {
		if _, err := parseCertificate(tc.cert, tc.key); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", tc.name, err)
		}
	}
}

func TestCertificateFitsTheAccount(t *testing.T) {
	root := newTestIssuer(t, "Test Root", nil)
	key := newTestKey(t, elliptic.P256())
	now := time.Now()
	parse := func(spec leafSpec) certificateBundle {
		t.Helper()
		spec.key = key
		_, leafPEM := root.leaf(t, spec)
		b, err := parseCertificate(string(leafPEM), string(sec1PEM(t, key)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	site := []string{"fixture.test", "www.fixture.test", "shop.fixture.test"}
	if err := parse(leafSpec{dns: []string{"fixture.test"}}).fits(site, "fixture.test", now); err != nil {
		t.Fatalf("the account's domain alone: %v", err)
	}
	every := parse(leafSpec{dns: []string{"www.fixture.test", "shop.fixture.test", "fixture.test"}})
	if err := every.fits(site, "fixture.test", now); err != nil || every.state.Names != "fixture.test,shop.fixture.test,www.fixture.test" {
		t.Fatalf("every domain of the site: %v, names %q", err, every.state.Names)
	}
	for name, spec := range map[string]leafSpec{
		"wrong domain":                {dns: []string{"other.test"}},
		"only in the CN":              {dns: []string{"other.test"}, cn: "fixture.test"},
		"wildcard":                    {dns: []string{"*.test"}},
		"a wildcard beside":           {dns: []string{"fixture.test", "*.fixture.test"}},
		"a name the site lacks":       {dns: []string{"fixture.test", "www.fixture.test", "other.test"}},
		"the aliases without it":      {dns: []string{"www.fixture.test", "shop.fixture.test"}},
		"a name twice":                {dns: []string{"fixture.test", "fixture.test"}},
		"no names":                    {cn: "fixture.test"},
		"expired":                     {dns: []string{"fixture.test"}, notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)},
		"not yet valid":               {dns: []string{"fixture.test"}, notBefore: now.Add(time.Hour), notAfter: now.Add(48 * time.Hour)},
		"different spelling":          {dns: []string{"FIXTURE.test"}},
		"a different spelling beside": {dns: []string{"fixture.test", "WWW.fixture.test"}},
	} {
		if err := parse(spec).fits(site, "fixture.test", now); !errors.Is(err, ErrCertificateRejected) {
			t.Errorf("%s: %v, want ErrCertificateRejected", name, err)
		}
	}
	// Names other than DNS names make the certificate something else.
	ipLeaf := &x509.Certificate{SerialNumber: testSerial(t), DNSNames: []string{"fixture.test"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ipLeaf, root.cert, key.Public(), root.key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseCertificate(string(pemOf("CERTIFICATE", der)), string(sec1PEM(t, key)))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.fits(site, "fixture.test", now); !errors.Is(err, ErrCertificateRejected) {
		t.Errorf("an IP address beside the domain: %v", err)
	}
}

// TestCertificateForEveryDomainOfTheSite: a certificate may name the site's
// aliases; the HTTPS listener maps the names it covers, and no others.
func TestCertificateForEveryDomainOfTheSite(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	ctx := context.Background()
	live := recordFor(t, s, a.ID)
	got, err := s.setSiteDomains(ctx, a.ID, domainsInput(live, []string{"www.fixture.test", "shop.fixture.test", "later.fixture.test"}), "test operator")
	if err != nil {
		t.Fatal(err)
	}
	// later.fixture.test does not point here yet: the certificate leaves it out.
	c := newTestChainFor(t, "fixture.test", "www.fixture.test", "shop.fixture.test")
	installed, err := s.setCertificate(ctx, a.ID, c.input(t, got.Account.Revision), "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if installed.Certificate.Names != "fixture.test,shop.fixture.test,www.fixture.test" || installed.Account.Certificate != installed.Certificate {
		t.Fatalf("installed %+v", installed.Certificate)
	}
	site := siteOf(t, f.sites, a.ID)
	if !sameSiteTLS(site, "fixture.test", "shop.fixture.test", "www.fixture.test") {
		t.Fatalf("HTTPS maps %v", site.TLS.Domains)
	}
	files, err := renderUnderHome(f.sites)
	if err != nil {
		t.Fatal(err)
	}
	server := string(files[olsweb.ServerConfigPath])
	https := server[strings.Index(server, "listener sifruno-https {"):]
	if !strings.Contains(https, " fixture.test, shop.fixture.test, www.fixture.test\n") || strings.Contains(https, "later.fixture.test") || !strings.Contains(server, "later.fixture.test") {
		t.Fatalf("listeners:\n%s", server)
	}
	// A certificate naming a domain the site does not have is refused, and
	// so is one that leaves out the account's own domain.
	for name, chain := range map[string]testChain{
		"another account's name": newTestChainFor(t, "fixture.test", "other.test"),
		"without the domain":     newTestChainFor(t, "www.fixture.test"),
	} {
		if _, err := s.setCertificate(ctx, a.ID, chain.input(t, installed.Account.Revision), "test operator"); !errors.Is(err, ErrCertificateRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Removing an alias the certificate names takes it off HTTPS too.
	live = recordFor(t, s, a.ID)
	if _, err := s.setSiteDomains(ctx, a.ID, domainsInput(live, []string{"www.fixture.test", "later.fixture.test"}), "test operator"); err != nil {
		t.Fatal(err)
	}
	if site := siteOf(t, f.sites, a.ID); !sameSiteTLS(site, "fixture.test", "www.fixture.test") {
		t.Fatalf("after removing shop, HTTPS maps %v", site.TLS.Domains)
	}
	// The record keeps what the certificate names; a damaged list is refused.
	r := recordFor(t, s, a.ID)
	if r.TLS.Names != "fixture.test,shop.fixture.test,www.fixture.test" {
		t.Fatalf("record names %q", r.TLS.Names)
	}
	for _, bad := range []string{"www.fixture.test,fixture.test", "fixture.test,fixture.test", "fixture.test,bad name", ","} {
		damaged := r
		damaged.TLS.Names, damaged.Account.Certificate.Names = bad, bad
		if err := s.save(damaged); err != nil {
			t.Fatal(err)
		}
		if _, err := s.list(ctx); !errors.Is(err, ErrRecovery) {
			t.Errorf("names %q: %v", bad, err)
		}
	}
	if err := s.save(r); err != nil {
		t.Fatal(err)
	}
}

// A certificate recorded before the broker kept its names covers the
// account's own domain only.
func TestCertificateWithoutNamesCoversTheDomain(t *testing.T) {
	if got := coveredDomains(CertificateState{NotAfter: 1, Fingerprint: strings.Repeat("ab", 32)}, []string{"fixture.test", "www.fixture.test"}, "fixture.test"); strings.Join(got, ",") != "fixture.test" {
		t.Fatalf("covered %v", got)
	}
}

func TestListenerCertificate(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := newListenerCertificate(now)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("not one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || cert.Subject.CommonName != "sifruno" || cert.IsCA {
		t.Fatalf("key %T, CN %q, CA %v", cert.PublicKey, cert.Subject.CommonName, cert.IsCA)
	}
	if cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
		t.Fatal("not self-signed")
	}
	if !strings.HasPrefix(string(keyPEM), "-----BEGIN PRIVATE KEY-----\n") {
		t.Fatal("key is not PKCS #8")
	}
	if !listenerCertificateUsable(certPEM, keyPEM, now) {
		t.Fatal("a fresh listener pair is not usable")
	}
	otherCert, otherKey, err := newListenerCertificate(now)
	if err != nil {
		t.Fatal(err)
	}
	for name, ok := range map[string]bool{
		"mismatched pair":  listenerCertificateUsable(certPEM, otherKey, now),
		"other way round":  listenerCertificateUsable(otherCert, keyPEM, now),
		"expired":          listenerCertificateUsable(certPEM, keyPEM, now.AddDate(11, 0, 0)),
		"empty":            listenerCertificateUsable(nil, nil, now),
		"key as the cert":  listenerCertificateUsable(keyPEM, keyPEM, now),
		"two certificates": listenerCertificateUsable(append(append([]byte(nil), certPEM...), certPEM...), keyPEM, now),
	} {
		if ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// liveCertificateStore is a web store with one live site.
func liveCertificateStore(t *testing.T) (*store, *fakeNative, Account) {
	t.Helper()
	s, f := webStore(t)
	a := createFixture(t, s)
	got, err := s.setWeb(context.Background(), a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	return s, f, got.Account
}

func historyActions(t *testing.T, s *store, id string) []string {
	t.Helper()
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(historyBucket).Cursor()
		prefix := []byte(id + "/")
		for k, v := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, v = c.Next() {
			var e operationEvent
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e.Action+":"+e.Status)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCertificateOperationOffByDefault(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	c := newTestChain(t, a.Domain)
	if _, err := s.setCertificate(context.Background(), a.ID, c.input(t, a.Revision), "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("certificate without --web-user: %v", err)
	}
}

func TestCertificateInstallsAndJournals(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	ctx := context.Background()
	c := newTestChain(t, a.Domain)
	want := CertificateState{NotAfter: c.leaf.NotAfter.Unix(), Fingerprint: fingerprintOf(c.leaf), Names: a.Domain}
	got, err := s.setCertificate(ctx, a.ID, c.input(t, a.Revision), "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if got.Certificate != want || got.Account.Certificate != want || got.Account.Revision != a.Revision+1 {
		t.Fatalf("result %+v", got)
	}
	r := recordFor(t, s, a.ID)
	if r.TLS != want || r.TLSNext != (CertificateState{}) || r.Pending != nil || r.Account != got.Account {
		t.Fatalf("record %+v", r)
	}
	if f.live[a.Username] != want || len(f.staged) != 0 {
		t.Fatalf("installed %+v, staged pairs left %d", f.live[a.Username], len(f.staged))
	}
	if len(f.sites) != 1 || !sameSiteTLS(f.sites[0], a.Domain) {
		t.Fatalf("the config does not name the site's certificate: %+v", f.sites)
	}
	if f.sites[0].TLS.CertFile != "/etc/sifruno/tls/"+siteName(a.ID)+"/cert.pem" || f.sites[0].TLS.KeyFile != "/etc/sifruno/tls/"+siteName(a.ID)+"/key.pem" {
		t.Fatalf("certificate paths %+v", f.sites[0].TLS)
	}
	actions := historyActions(t, s, a.ID)
	if tail := strings.Join(actions[len(actions)-2:], " "); tail != "certificate:intended certificate:succeeded" {
		t.Fatalf("journal ends with %s", tail)
	}
	items, err := s.list(ctx)
	if err != nil || len(items) != 1 || items[0].Certificate != want {
		t.Fatalf("the list does not show the certificate: %+v %v", items, err)
	}
	// A renewal replaces it the same way.
	renewed := newTestChain(t, a.Domain)
	again, err := s.setCertificate(ctx, a.ID, renewed.input(t, got.Account.Revision), "renewal")
	if err != nil || again.Certificate.Fingerprint != fingerprintOf(renewed.leaf) || again.Account.Revision != got.Account.Revision+1 {
		t.Fatalf("renewal: %+v %v", again, err)
	}
	// Other operations keep the certificate in the config.
	if _, err := s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.4", QuotaMiB: 200, ExpectedRevision: again.Account.Revision, Reason: "Upgrade PHP"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if !sameSiteTLS(f.sites[0], a.Domain) || f.sites[0].PHPVersion != "8.4" {
		t.Fatalf("a web change dropped the certificate: %+v", f.sites[0])
	}
	// The journal replays on a fresh open.
	opts := s.opts
	s.close()
	reopened, err := openStore(ctx, opts, f)
	if err != nil {
		t.Fatalf("journal with certificate rows does not replay: %v", err)
	}
	defer reopened.close()
}

func TestCertificateRefusalsJournalNothing(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	ctx := context.Background()
	good := newTestChain(t, a.Domain)
	before := recordFor(t, s, a.ID)
	root := newTestIssuer(t, "Test Root", nil)
	expired := func() CertificateInput {
		_, leafPEM := root.leaf(t, leafSpec{dns: []string{a.Domain}, notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Minute), key: good.key})
		in := good.input(t, a.Revision)
		in.CertPEM = string(leafPEM)
		return in
	}()
	wrongKey := good.input(t, a.Revision)
	wrongKey.KeyPEM = string(sec1PEM(t, newTestKey(t, elliptic.P256())))
	tooLarge := good.input(t, a.Revision)
	tooLarge.CertPEM += strings.Repeat("\n", maxCertificatePEM)
	garbage := good.input(t, a.Revision)
	garbage.CertPEM = "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"
	misordered := good.input(t, a.Revision)
	misordered.CertPEM = string(good.leafPEM) + string(good.root) + string(good.intermediate)
	noReason := good.input(t, a.Revision)
	noReason.Reason = ""
	cases := []struct {
		name string
		in   CertificateInput
		want error
	}{
		{"wrong domain", newTestChain(t, "other.test").input(t, a.Revision), ErrCertificateRejected},
		{"expired", expired, ErrCertificateRejected},
		{"key mismatch", wrongKey, ErrInvalid},
		{"too large", tooLarge, ErrInvalid},
		{"garbage PEM", garbage, ErrInvalid},
		{"chain in the wrong order", misordered, ErrInvalid},
		{"no reason", noReason, ErrInvalid},
		{"stale revision", good.input(t, a.Revision+1), ErrConflict},
	}
	for _, tc := range cases {
		if _, err := s.setCertificate(ctx, a.ID, tc.in, "test operator"); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := s.setCertificate(ctx, strings.Repeat("f", 32), good.input(t, a.Revision), "test operator"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown account: %v", err)
	}
	if after := recordFor(t, s, a.ID); after != before {
		t.Fatalf("a refused certificate changed the record: %+v", after)
	}
	if f.certApply != 0 || len(f.staged) != 0 {
		t.Fatalf("a refused certificate was staged or applied (%d applies)", f.certApply)
	}

	// An account without a live site, or a suspended one, is refused.
	b, err := s.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Synthetic core verification"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.setCertificate(ctx, b.ID, newTestChain(t, b.Domain).input(t, b.Revision), "test operator"); !errors.Is(err, ErrConflict) {
		t.Errorf("no live site: %v", err)
	}
	suspended, err := s.setState(ctx, a.ID, StateInput{State: "suspended", ExpectedRevision: a.Revision, Reason: "Suspend"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.setCertificate(ctx, a.ID, good.input(t, suspended.Revision), "test operator"); !errors.Is(err, ErrConflict) {
		t.Errorf("suspended account: %v", err)
	}
	// A staging failure leaves nothing journaled either.
	if _, err := s.setState(ctx, a.ID, StateInput{State: "active", ExpectedRevision: suspended.Revision, Reason: "Resume"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	current := recordFor(t, s, a.ID)
	f.failure = "stage"
	if _, err := s.setCertificate(ctx, a.ID, good.input(t, current.Account.Revision), "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("staging failure: %v", err)
	}
	if after := recordFor(t, s, a.ID); after != current {
		t.Fatal("a staging failure journaled the operation")
	}
}

func TestCertificateRejectedConfigLeavesAccountUnchanged(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	ctx := context.Background()
	c := newTestChain(t, a.Domain)
	before := recordFor(t, s, a.ID)
	f.failure = "cert-reject"
	if _, err := s.setCertificate(ctx, a.ID, c.input(t, a.Revision), "test operator"); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("rejected config: %v", err)
	}
	after := recordFor(t, s, a.ID)
	if after.Pending != nil || after.Account != before.Account || after.TLS != (CertificateState{}) || after.TLSNext != (CertificateState{}) || after.HistorySequence != before.HistorySequence+2 {
		t.Fatalf("a rejected certificate changed the account: %+v", after)
	}
	if actions := historyActions(t, s, a.ID); actions[len(actions)-1] != "certificate:rejected" {
		t.Fatalf("journal ends with %s", actions[len(actions)-1])
	}
	if len(f.staged) != 0 {
		t.Fatal("the staged pair of a rejected certificate was kept")
	}
	// Nothing is pending, so the same request works later.
	f.failure = ""
	if _, err := s.setCertificate(ctx, a.ID, c.input(t, a.Revision), "test operator"); err != nil {
		t.Fatalf("retry after rejection: %v", err)
	}
}

func TestCertificateInterruptedApplyIsFinishedByRefresh(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	ctx := context.Background()
	c := newTestChain(t, a.Domain)
	want := CertificateState{NotAfter: c.leaf.NotAfter.Unix(), Fingerprint: fingerprintOf(c.leaf), Names: a.Domain}
	f.failure = "cert-after"
	if _, err := s.setCertificate(ctx, a.ID, c.input(t, a.Revision), "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	r := recordFor(t, s, a.ID)
	if r.Pending == nil || r.Pending.Action != "certificate" || r.Pending.Target != certificateDigest(want) || r.TLSNext != want || r.TLS != (CertificateState{}) {
		t.Fatalf("pending certificate not durable: %+v", r)
	}
	if _, ok := f.staged[a.Username]; !ok {
		t.Fatal("the staged pair is gone while the operation is pending")
	}
	items, err := s.list(ctx)
	if err != nil || items[0].State != "recovery_required" {
		t.Fatalf("list during recovery: %+v %v", items, err)
	}
	f.failure = ""
	s.mu.Lock()
	err = s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r = recordFor(t, s, a.ID)
	if r.Pending != nil || r.TLS != want || r.Account.Certificate != want || r.TLSNext != (CertificateState{}) || r.Account.Revision != a.Revision+1 {
		t.Fatalf("refresh did not finish the certificate: %+v", r)
	}
	if actions := historyActions(t, s, a.ID); actions[len(actions)-1] != "certificate:reconciled" {
		t.Fatalf("journal ends with %s", actions[len(actions)-1])
	}
	if len(f.staged) != 0 {
		t.Fatal("the staged pair was kept after the recovery")
	}
}

func TestCertificateRecoveryCanEndRejected(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	ctx := context.Background()
	f.failure = "cert-before"
	if _, err := s.setCertificate(ctx, a.ID, newTestChain(t, a.Domain).input(t, a.Revision), "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	f.failure = "cert-reject"
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r := recordFor(t, s, a.ID)
	if r.Pending != nil || r.TLS != (CertificateState{}) || r.Account.Revision != a.Revision {
		t.Fatalf("recovery that failed its test must end rejected and unchanged: %+v", r)
	}
}

// Without the staged pair the broker cannot know what to install, so the
// operation stays pending for a person instead of guessing.
func TestCertificateRecoveryWithoutStagedPairStaysPending(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	ctx := context.Background()
	f.failure = "cert-before"
	if _, err := s.setCertificate(ctx, a.ID, newTestChain(t, a.Domain).input(t, a.Revision), "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	f.failure = ""
	delete(f.staged, a.Username)
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if r := recordFor(t, s, a.ID); r.Pending == nil || r.Pending.Action != "certificate" || r.TLS != (CertificateState{}) {
		t.Fatalf("a recovery without its staged pair did not stay pending: %+v", r)
	}
}

func TestDeleteRemovesTheTLSDirectory(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	ctx := context.Background()
	got, err := s.setCertificate(ctx, a.ID, newTestChain(t, a.Domain).input(t, a.Revision), "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: got.Account.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.live[a.Username]; ok {
		t.Fatal("the TLS directory survived the delete")
	}
	if f.tlsGoneWhileServed {
		t.Fatal("the TLS directory went before the site left the config")
	}
	if len(f.sites) != 0 {
		t.Fatalf("the deleted site is still configured: %+v", f.sites)
	}
}

// The site list names certificate files only for sites that have one, and
// the HTTPS listener exists only then.
func TestWebSitesCarryCertificates(t *testing.T) {
	now := time.Now().UTC()
	mk := func(id, user string, cert CertificateState) record {
		r := record{Account: Account{ID: strings.Repeat(id, 32), Username: user, Domain: user + ".test", PublicHTML: "/home/" + user + "/public_html", Certificate: cert, CreatedAt: now, UpdatedAt: now}, Web: WebState{PHPVersion: "8.3", QuotaMiB: 200}, TLS: cert}
		return r
	}
	cert := CertificateState{NotAfter: now.Add(time.Hour).Unix(), Fingerprint: strings.Repeat("ab", 32)}
	plain, secure := mk("a", "plainacct", CertificateState{}), mk("b", "secureacct", cert)
	render := func(items []record) string {
		t.Helper()
		files, err := olsweb.Render(webServer(webSites(items, "")))
		if err != nil {
			t.Fatal(err)
		}
		return string(files[olsweb.ServerConfigPath])
	}
	if server := render([]record{plain}); strings.Contains(server, "secure                  1") {
		t.Fatalf("HTTPS listener without a certificate:\n%s", server)
	}
	server := render([]record{plain, secure})
	https := server[strings.Index(server, "listener sifruno-https {"):]
	if !strings.Contains(https, "certFile                /etc/sifruno/tls/listener.crt\n") || !strings.Contains(https, "keyFile                 /etc/sifruno/tls/listener.key\n") || !strings.Contains(https, "secureacct.test") || strings.Contains(https, "plainacct.test") {
		t.Fatalf("HTTPS listener:\n%s", https)
	}
	// A pending certificate is rendered with the certificate it installs.
	pendingFirst := plain
	pendingFirst.Pending = &pending{Action: "certificate"}
	pendingFirst.TLSNext = cert
	for _, s := range webSites([]record{pendingFirst}, "") {
		if !sameSiteTLS(s, "plainacct.test") {
			t.Fatalf("pending certificate not rendered: %+v", s.TLS)
		}
	}
	if anyCertificate(webSites([]record{plain}, "")) || !anyCertificate(webSites([]record{plain, secure}, "")) {
		t.Fatal("anyCertificate")
	}
}

func TestCertificateHTTPAnswers(t *testing.T) {
	s, f, a := liveCertificateStore(t)
	post := func(body string) (int, string) {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+a.ID+"/certificate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(s).ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	body := func(in CertificateInput) string {
		b, err := json.Marshal(struct {
			Input CertificateInput `json:"input"`
			Actor string           `json:"actor"`
		}{in, "test operator"})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	good := newTestChain(t, a.Domain)
	if code, out := post(body(newTestChain(t, "other.test").input(t, a.Revision))); code != 422 || !strings.Contains(out, `"certificate_rejected"`) {
		t.Fatalf("wrong domain: %d %s", code, out)
	}
	bad := good.input(t, a.Revision)
	bad.KeyPEM = "garbage"
	if code, out := post(body(bad)); code != 400 || !strings.Contains(out, `"invalid"`) {
		t.Fatalf("garbage key: %d %s", code, out)
	}
	if code, _ := post(strings.Replace(body(good.input(t, a.Revision)), `"reason"`, `"comment"`, 1)); code != 400 {
		t.Fatalf("unknown key: %d", code)
	}
	if code, _ := post(`{"actor":"test operator","input":{"expected_revision":2}}`); code != 400 {
		t.Fatalf("missing keys: %d", code)
	}
	tooLarge := good.input(t, a.Revision)
	tooLarge.CertPEM += strings.Repeat(" ", maxCertificateRequestBytes)
	if code, _ := post(body(tooLarge)); code != 400 {
		t.Fatalf("oversized body: %d", code)
	}
	if f.certApply != 0 {
		t.Fatal("a refused request reached the apply")
	}
	// A request larger than the usual 16 KiB bound is accepted here.
	padded := good.input(t, a.Revision)
	padded.CertPEM += strings.Repeat("\n", 40<<10)
	code, out := post(body(padded))
	if code != 200 {
		t.Fatalf("padded certificate: %d %s", code, out)
	}
	var result CertificateResult
	if err := json.Unmarshal([]byte(out), &result); err != nil || result.Certificate.Fingerprint != fingerprintOf(good.leaf) || result.Account.Certificate != result.Certificate {
		t.Fatalf("answer %s: %v", out, err)
	}
}

func TestCertificateClientChecksBeforeSending(t *testing.T) {
	c := NewClient("").(CertificateService)
	good := newTestChain(t, "fixture.test")
	in := good.input(t, 2)
	id := strings.Repeat("a", 32)
	if _, err := c.SetCertificate(context.Background(), id, in, "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unconfigured client: %v", err)
	}
	large := in
	large.KeyPEM += strings.Repeat(" ", maxCertificatePEM)
	for name, tc := range map[string]struct {
		id string
		in CertificateInput
	}{
		"bad id":       {"x", in},
		"no revision":  {id, CertificateInput{CertPEM: in.CertPEM, KeyPEM: in.KeyPEM, Reason: in.Reason}},
		"key too long": {id, large},
	} {
		if _, err := c.SetCertificate(context.Background(), tc.id, tc.in, "test operator"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An install journaled by a broker that kept no names is finished from its
// staged pair after an upgrade, not left pending for every account.
func TestStagedPairMatchesItsIntentAcrossTheUpgrade(t *testing.T) {
	staged := CertificateState{NotAfter: 1803311049, Fingerprint: strings.Repeat("ab", 32), Names: "fixture.test,www.fixture.test"}
	for name, tc := range map[string]struct {
		journaled CertificateState
		want      bool
	}{
		"the same":                {staged, true},
		"journaled with no names": {CertificateState{NotAfter: staged.NotAfter, Fingerprint: staged.Fingerprint}, true},
		"other names":             {CertificateState{NotAfter: staged.NotAfter, Fingerprint: staged.Fingerprint, Names: "fixture.test"}, false},
		"another leaf":            {CertificateState{NotAfter: staged.NotAfter, Fingerprint: strings.Repeat("cd", 32), Names: staged.Names}, false},
		"another expiry":          {CertificateState{NotAfter: staged.NotAfter + 1, Fingerprint: staged.Fingerprint, Names: staged.Names}, false},
		"another leaf, no names":  {CertificateState{NotAfter: staged.NotAfter, Fingerprint: strings.Repeat("cd", 32)}, false},
	} {
		if got := stagedIsJournaled(staged, tc.journaled); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
