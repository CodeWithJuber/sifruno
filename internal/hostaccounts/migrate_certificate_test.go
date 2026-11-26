package hostaccounts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"sifruno/internal/cpsource"
)

// oldCertificate is the certificate an old cPanel server serves for a site,
// as fetch_vhost_ssl_components gives it: a leaf from an intermediate,
// its key, and a CA bundle with the intermediate and the root. roots holds
// only that root and stands for this server's trusted authorities.
type oldCertificate struct {
	ssl   cpsource.VhostSSL
	leaf  *x509.Certificate
	mid   *testIssuer
	root  *testIssuer
	roots *x509.CertPool
}

var serverAuth = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

func newOldCertificate(t *testing.T, spec leafSpec) oldCertificate {
	t.Helper()
	root := newTestIssuer(t, "Old Server Root", nil)
	mid := newTestIssuer(t, "Old Server Intermediate", root)
	if spec.key == nil {
		spec.key = newTestKey(t, elliptic.P256())
	}
	if spec.eku == nil {
		spec.eku = serverAuth
	}
	leaf, leafPEM := mid.leaf(t, spec)
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	return oldCertificate{
		ssl:  cpsource.VhostSSL{Certificate: string(leafPEM), Key: string(pkcs8PEM(t, spec.key)), CABundle: string(pemOf("CERTIFICATE", mid.cert.Raw)) + string(pemOf("CERTIFICATE", root.cert.Raw))},
		leaf: leaf, mid: mid, root: root, roots: roots,
	}
}

// sslAnswer is whmapi1's fetch_vhost_ssl_components answer for one virtual
// host.
func sslAnswer(t *testing.T, servername string, ssl cpsource.VhostSSL) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"data":     map[string]any{"components": []map[string]any{{"servername": servername, "certificate": ssl.Certificate, "key": ssl.Key, "cabundle": ssl.CABundle, "certificate_id": "c", "key_id": "k"}}},
		"metadata": map[string]any{"command": "fetch_vhost_ssl_components", "result": 1, "reason": "OK", "version": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

var fixtureNames = []string{"fixture.test", "www.fixture.test", "mail.fixture.test"}

// TestCopiedCertificateIsCheckedFirst: a certificate from the old server is
// copied only when its key matches it, it is valid now and for 7 days more,
// it covers the site's domain, a certificate authority this server trusts
// vouches for it, and its chain parses. Everything else is refused with a
// reason in plain words, before anything is staged.
func TestCopiedCertificateIsCheckedFirst(t *testing.T) {
	now := time.Now()
	old := newOldCertificate(t, leafSpec{dns: fixtureNames})
	midPEM := string(pemOf("CERTIFICATE", old.mid.cert.Raw))
	rootPEM := string(pemOf("CERTIFICATE", old.root.cert.Raw))
	b, refusal := copiedCertificate(old.ssl, "fixture.test", old.roots, now)
	if refusal != nil {
		t.Fatalf("a good certificate refused: %+v", refusal)
	}
	// The chain served is the leaf and the intermediate; the root is the
	// visitor's own.
	if string(b.chainPEM) != old.ssl.Certificate+midPEM {
		t.Fatalf("chain:\n%s", b.chainPEM)
	}
	want := CertificateState{NotAfter: old.leaf.NotAfter.Unix(), Fingerprint: fingerprintOf(old.leaf), Names: "fixture.test,mail.fixture.test,www.fixture.test"}
	if b.state != want || b.fitsCopy("fixture.test", now) != nil {
		t.Fatalf("state %+v", b.state)
	}
	// The bundle's order, an unrelated certificate in it, or no root: the
	// same chain.
	stranger := newTestIssuer(t, "Unrelated CA", nil)
	for _, bundle := range []string{rootPEM + midPEM, midPEM + string(pemOf("CERTIFICATE", stranger.cert.Raw)), midPEM, "\n" + midPEM + "\r\n"} {
		ssl := old.ssl
		ssl.CABundle = bundle
		if b, refusal := copiedCertificate(ssl, "fixture.test", old.roots, now); refusal != nil || string(b.chainPEM) != old.ssl.Certificate+midPEM {
			t.Errorf("bundle %q: %+v %s", bundle, refusal, b.chainPEM)
		}
	}
	// A leaf straight from a trusted root needs no bundle.
	direct := newTestKey(t, elliptic.P384())
	_, directPEM := old.root.leaf(t, leafSpec{dns: []string{"fixture.test"}, eku: serverAuth, key: direct})
	if b, refusal := copiedCertificate(cpsource.VhostSSL{Certificate: string(directPEM), Key: string(sec1PEM(t, direct))}, "fixture.test", old.roots, now); refusal != nil || string(b.chainPEM) != string(directPEM) {
		t.Fatalf("a leaf from the root: %+v", refusal)
	}
	// A wildcard covers the domain the way a browser reads it; the record
	// then names no domains, and the site's own domain is the one served.
	wild := newOldCertificate(t, leafSpec{dns: []string{"*.fixture.test", "fixture.test"}})
	if b, refusal := copiedCertificate(wild.ssl, "fixture.test", wild.roots, now); refusal != nil || b.state.Names != "" || b.fitsCopy("fixture.test", now) != nil {
		t.Fatalf("wildcard: %+v %+v", refusal, b.state)
	}
	if b, refusal := copiedCertificate(wild.ssl, "shop.fixture.test", wild.roots, now); refusal != nil || b.fitsCopy("shop.fixture.test", now) != nil {
		t.Fatalf("a wildcard for a subdomain site: %+v", refusal)
	}

	self := newTestIssuer(t, "fixture.test", nil)
	selfLeaf := cpsource.VhostSSL{Certificate: string(pemOf("CERTIFICATE", self.cert.Raw)), Key: string(sec1PEM(t, self.key))}
	selfSigned := selfSignedLeaf(t, "fixture.test")
	expired := newOldCertificate(t, leafSpec{dns: fixtureNames, notBefore: now.Add(-100 * 24 * time.Hour), notAfter: now.Add(-24 * time.Hour)})
	soon := newOldCertificate(t, leafSpec{dns: fixtureNames, notAfter: now.Add(3 * 24 * time.Hour)})
	later := newOldCertificate(t, leafSpec{dns: fixtureNames, notBefore: now.Add(48 * time.Hour)})
	other := newOldCertificate(t, leafSpec{dns: []string{"other.test", "www.other.test"}})
	mismatch := old.ssl
	mismatch.Key = string(pkcs8PEM(t, newTestKey(t, elliptic.P256())))
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ed := newOldCertificate(t, leafSpec{dns: fixtureNames, key: edKey})
	clientOnly := newOldCertificate(t, leafSpec{dns: fixtureNames, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	long := longChain(t, "fixture.test")
	cases := []struct {
		name  string
		ssl   cpsource.VhostSSL
		roots *x509.CertPool
		code  string
		says  string
	}{
		{"a self-signed CA certificate", selfLeaf, old.roots, "self_signed", "self-signed"},
		{"a self-signed leaf", selfSigned, old.roots, "self_signed", "self-signed"},
		{"an expired one", expired.ssl, expired.roots, "expired", "expired on " + expired.leaf.NotAfter.UTC().Format(time.DateOnly)},
		{"one that expires in 3 days", soon.ssl, soon.roots, "expires_soon", "in less than 7 days"},
		{"one valid only from tomorrow", later.ssl, later.roots, "not_yet_valid", "valid only from"},
		{"one for other names", other.ssl, other.roots, "other_domain", "other.test, www.other.test"},
		{"one no trusted authority vouches for", old.ssl, x509.NewCertPool(), "untrusted", "Old Server Intermediate"},
		{"one without its intermediate", cpsource.VhostSSL{Certificate: old.ssl.Certificate, Key: old.ssl.Key}, old.roots, "untrusted", "vouches"},
		{"one for client sign-in only", clientOnly.ssl, clientOnly.roots, "untrusted", "vouches"},
		{"a key that is not its own", mismatch, old.roots, "key_mismatch", "does not match"},
		{"an Ed25519 key", ed.ssl, ed.roots, "unusable", "RSA"},
		{"a chain of 5", long.ssl, long.roots, "unusable", "4 certificates"},
		{"text that is not PEM", cpsource.VhostSSL{Certificate: "not a certificate", Key: old.ssl.Key}, old.roots, "unusable", "certificate"},
		{"a bundle that is not PEM", cpsource.VhostSSL{Certificate: old.ssl.Certificate, Key: old.ssl.Key, CABundle: "not a bundle"}, old.roots, "unusable", "CA bundle"},
		{"a key that is not PEM", cpsource.VhostSSL{Certificate: old.ssl.Certificate, Key: "secret", CABundle: old.ssl.CABundle}, old.roots, "unusable", "key"},
	}
	for _, c := range cases {
		b, refusal := copiedCertificate(c.ssl, "fixture.test", c.roots, now)
		if refusal == nil || refusal.Code != c.code || !strings.Contains(refusal.Detail, c.says) || b.keyPEM != nil {
			t.Errorf("%s: %+v", c.name, refusal)
			continue
		}
		// The words never carry the key.
		if strings.Contains(refusal.Detail, "PRIVATE") || strings.Contains(refusal.Detail, c.ssl.Key) && c.ssl.Key != "" {
			t.Errorf("%s: the refusal quotes the key", c.name)
		}
	}
}

// selfSignedLeaf is a leaf certificate signed by its own key, as cPanel
// installs on a virtual host when no authority issued one.
func selfSignedLeaf(t *testing.T, domain string) cpsource.VhostSSL {
	t.Helper()
	key := newTestKey(t, elliptic.P256())
	template := &x509.Certificate{SerialNumber: testSerial(t), DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: serverAuth, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return cpsource.VhostSSL{Certificate: string(pemOf("CERTIFICATE", der)), Key: string(sec1PEM(t, key))}
}

// longChain is a leaf four intermediates below a trusted root.
func longChain(t *testing.T, domain string) oldCertificate {
	t.Helper()
	root := newTestIssuer(t, "Long Root", nil)
	issuer, bundle := root, ""
	for i := 0; i < 4; i++ {
		issuer = newTestIssuer(t, "Long Intermediate", issuer)
		bundle = string(pemOf("CERTIFICATE", issuer.cert.Raw)) + bundle
	}
	key := newTestKey(t, elliptic.P256())
	leaf, leafPEM := issuer.leaf(t, leafSpec{dns: []string{domain}, eku: serverAuth, key: key})
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	return oldCertificate{ssl: cpsource.VhostSSL{Certificate: string(leafPEM), Key: string(sec1PEM(t, key)), CABundle: bundle}, leaf: leaf, root: root, roots: roots}
}

// certificateMigration is a live fixture.test site, a pinned SSH migration,
// and the old server serving old's certificate for its virtual host.
func certificateMigration(t *testing.T, old oldCertificate) (*store, *fakeMigrate, *fakeNative, Migration, record, string) {
	t.Helper()
	s, f, _ := migrateStore(t)
	native := s.native.(*fakeNative)
	s.web = &WebOptions{ServerUser: "nobody"}
	s.certRoots = old.roots
	m := pinnedMigration(t, s)
	live := liveFixture(t, s)
	command, err := cpsource.VhostSSLCommand("fixture.test")
	if err != nil {
		t.Fatal(err)
	}
	f.answers[command] = sslAnswer(t, "fixture.test", old.ssl)
	return s, f, native, m, live, command
}

// TestMigrateCertificateCopiesTheOldSitesCertificate: the broker reads the
// certificate the old site's virtual host serves, checks it, and installs
// it through the certificate operation, so the moved site answers https
// at once. The key reaches the staged pair and the live files only: no
// record, journal row or answer holds it.
func TestMigrateCertificateCopiesTheOldSitesCertificate(t *testing.T) {
	old := newOldCertificate(t, leafSpec{dns: fixtureNames})
	s, f, native, m, live, command := certificateMigration(t, old)
	ctx := context.Background()
	in := MigrateCertificateInput{Migration: m.ID, ExpectedRevision: live.Account.Revision, Reason: "Move a website here"}
	if _, err := s.migrateCertificate(ctx, live.Account.ID, MigrateCertificateInput{Migration: m.ID, ExpectedRevision: live.Account.Revision + 1, Reason: "x"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a stale revision: %v", err)
	}
	got, err := s.migrateCertificate(ctx, live.Account.ID, in, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	want := CertificateState{NotAfter: old.leaf.NotAfter.Unix(), Fingerprint: fingerprintOf(old.leaf), Names: "fixture.test,mail.fixture.test,www.fixture.test"}
	if !got.Copied || got.Certificate != want || got.Revision != live.Account.Revision+1 || got.Refused != "" || got.Issuer != "Old Server Intermediate" {
		t.Fatalf("result %+v", got)
	}
	r := recordFor(t, s, live.Account.ID)
	if r.Account.Certificate != want || r.TLS != want || r.Pending != nil || r.Account.Revision != got.Revision {
		t.Fatalf("record %+v", r)
	}
	if native.live["fixtureacct"] != want || len(native.staged) != 0 {
		t.Fatalf("installed %+v, staged left %d", native.live["fixtureacct"], len(native.staged))
	}
	// Only the site's own domain is served over https: www. and mail. are
	// on the certificate but are no domains of this site.
	if site := siteOf(t, native.sites, live.Account.ID); !sameSiteTLS(site, "fixture.test") {
		t.Fatalf("site %+v", site.TLS)
	}
	actions := historyActions(t, s, live.Account.ID)
	if tail := strings.Join(actions[len(actions)-2:], " "); tail != "certificate:intended certificate:succeeded" {
		t.Fatalf("journal ends with %s", tail)
	}
	if !strings.Contains(strings.Join(f.commands, "\n"), command) {
		t.Fatalf("the old server was not asked for the site's virtual host: %v", f.commands)
	}
	keyBody := strings.Split(strings.TrimSpace(old.ssl.Key), "\n")[1]
	answer, _ := json.Marshal(got)
	if strings.Contains(string(answer), "PRIVATE") || strings.Contains(string(answer), keyBody) {
		t.Fatalf("the answer carries the key: %s", answer)
	}
	if raw, err := os.ReadFile(s.db.Path()); err != nil || bytes.Contains(raw, []byte(keyBody)) {
		t.Fatalf("the broker's state holds the key: %v", err)
	}
	// Copying again installs the same certificate again, as a renewal would.
	in.ExpectedRevision = got.Revision
	if again, err := s.migrateCertificate(ctx, live.Account.ID, in, "test operator"); err != nil || !again.Copied || again.Revision != got.Revision+1 {
		t.Fatalf("again: %+v %v", again, err)
	}
	// The account must be live: the web operation installs certificates.
	other := createFixtureNamed(t, s, "otheracct", "other.test")
	if _, err := s.migrateCertificate(ctx, other.ID, MigrateCertificateInput{Migration: m.ID, ExpectedRevision: other.Revision, Reason: "x"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a site that is not live: %v", err)
	}
}

// TestMigrateCertificateLeavesAnUnusableOneBehind: a certificate that
// cannot be used is not copied, and nothing changes here: the answer says
// why, and the move goes on. A failing cPanel tool is a failed step, its
// error output kept apart.
func TestMigrateCertificateLeavesAnUnusableOneBehind(t *testing.T) {
	now := time.Now()
	expired := newOldCertificate(t, leafSpec{dns: fixtureNames, notBefore: now.Add(-100 * 24 * time.Hour), notAfter: now.Add(-24 * time.Hour)})
	s, f, native, m, live, command := certificateMigration(t, expired)
	ctx := context.Background()
	in := MigrateCertificateInput{Migration: m.ID, ExpectedRevision: live.Account.Revision, Reason: "Move a website here"}
	before := historyActions(t, s, live.Account.ID)
	got, err := s.migrateCertificate(ctx, live.Account.ID, in, "test operator")
	if err != nil || got.Copied || got.Refused != "expired" || !strings.Contains(got.Detail, "expired on") || got.Revision != live.Account.Revision || got.Certificate != (CertificateState{}) {
		t.Fatalf("expired: %+v %v", got, err)
	}
	unchanged := func(what string) {
		t.Helper()
		r := recordFor(t, s, live.Account.ID)
		if r.Account != live.Account || r.TLS != (CertificateState{}) || native.certApply != 0 || len(native.staged) != 0 || strings.Join(historyActions(t, s, live.Account.ID), " ") != strings.Join(before, " ") {
			t.Fatalf("%s changed the site: %+v", what, r.Account)
		}
	}
	unchanged("an expired certificate")
	f.answers[command] = `{"data":{"components":[]},"metadata":{"result":1}}`
	if got, err = s.migrateCertificate(ctx, live.Account.ID, in, "test operator"); err != nil || got.Copied || got.Refused != "no_certificate" || got.Detail == "" {
		t.Fatalf("none: %+v %v", got, err)
	}
	unchanged("no certificate")
	var failed *MigrationError
	f.answers[command] = "not JSON"
	if _, err = s.migrateCertificate(ctx, live.Account.ID, in, "test operator"); !errors.As(err, &failed) || failed.Step != "cpanel_output" {
		t.Fatalf("not JSON: %v", err)
	}
	f.fails = map[string]fakeFailure{command: {"whmapi1: refused to run", 3}}
	if _, err = s.migrateCertificate(ctx, live.Account.ID, in, "test operator"); !errors.As(err, &failed) || failed.Step != "cpanel_tool" || failed.Output != "whmapi1: refused to run" {
		t.Fatalf("a failing tool: %+v %v", failed, err)
	}
	unchanged("a failed read")
}

// TestWHMMigrationCopiesTheCertificateFromThePanelsAnswer: over the WHM
// login, the panel reads fetch_vhost_ssl_components through WHM's API and
// passes the answer; no cPanel tool runs over SSH.
func TestWHMMigrationCopiesTheCertificateFromThePanelsAnswer(t *testing.T) {
	old := newOldCertificate(t, leafSpec{dns: fixtureNames})
	s, f, _ := migrateStore(t)
	s.web = &WebOptions{ServerUser: "nobody"}
	s.certRoots = old.roots
	ctx := context.Background()
	opened, err := s.openMigration(ctx, MigrationOpenInput{Host: "source.example.test", Port: 22, Via: ViaWHM, Reason: "Move a website here"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.pinMigrationHostKey(ctx, opened.ID, MigrationPinInput{Fingerprint: opened.HostKeys[0].Fingerprint, Reason: "Fingerprint checked"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	live := liveFixture(t, s)
	answers := fixtureAnswers(f)
	in := MigrateCertificateInput{Migration: m.ID, ExpectedRevision: live.Account.Revision, CPanel: answers, Reason: "Move a website here"}
	var failed *MigrationError
	if _, err = s.migrateCertificate(ctx, live.Account.ID, in, "test operator"); !errors.As(err, &failed) || failed.Step != "whm_output" {
		t.Fatalf("no certificate answer: %v", err)
	}
	answers.SSL = json.RawMessage(sslAnswer(t, "fixture.test", old.ssl))
	got, err := s.migrateCertificate(ctx, live.Account.ID, in, "test operator")
	if err != nil || !got.Copied || got.Certificate.Fingerprint != fingerprintOf(old.leaf) {
		t.Fatalf("copy: %+v %v", got, err)
	}
	for _, c := range f.commands {
		if strings.Contains(c, "/usr/local/cpanel/") {
			t.Fatalf("a cPanel tool ran over SSH for a WHM migration: %s", c)
		}
	}
	ssh := pinnedMigration(t, s)
	if _, err = s.migrateCertificate(ctx, live.Account.ID, MigrateCertificateInput{Migration: ssh.ID, ExpectedRevision: got.Revision, CPanel: answers, Reason: "x"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an SSH migration took the panel's answers: %v", err)
	}
}

// TestMigrateCertificateHTTP: the route takes the copy's keys only, and
// neither a copy nor a refusal answers with the key.
func TestMigrateCertificateHTTP(t *testing.T) {
	old := newOldCertificate(t, leafSpec{dns: fixtureNames})
	s, f, _, m, live, command := certificateMigration(t, old)
	h := handler(s)
	call := func(payload any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+live.Account.ID+"/migrate-certificate", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	keyBody := strings.Split(strings.TrimSpace(old.ssl.Key), "\n")[1]
	rec := call(map[string]any{"actor": "test operator", "input": map[string]any{"migration": m.ID, "expected_revision": live.Account.Revision, "reason": "Move a website here", "key_pem": "x"}})
	if rec.Code != 400 {
		t.Fatalf("an unknown key: %d %s", rec.Code, rec.Body)
	}
	rec = call(map[string]any{"actor": "test operator", "input": map[string]any{"migration": m.ID, "expected_revision": live.Account.Revision, "reason": "Move a website here"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"copied":true`) || strings.Contains(rec.Body.String(), keyBody) {
		t.Fatalf("copy over HTTP: %d %s", rec.Code, rec.Body)
	}
	f.answers[command] = sslAnswer(t, "fixture.test", selfSignedLeaf(t, "fixture.test"))
	rec = call(map[string]any{"actor": "test operator", "input": map[string]any{"migration": m.ID, "expected_revision": live.Account.Revision + 1, "reason": "Move a website here"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"refused":"self_signed"`) || strings.Contains(rec.Body.String(), "PRIVATE") {
		t.Fatalf("a refusal over HTTP: %d %s", rec.Code, rec.Body)
	}
	// The client checks before it sends.
	c := &client{}
	if _, err := c.MigrateCertificate(context.Background(), "bad", MigrateCertificateInput{Migration: m.ID, ExpectedRevision: 1, Reason: "x"}, "a"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("client: %v", err)
	}
	if _, err := c.MigrateCertificate(context.Background(), live.Account.ID, MigrateCertificateInput{Migration: "bad", ExpectedRevision: 1, Reason: "x"}, "a"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("client: %v", err)
	}
}
