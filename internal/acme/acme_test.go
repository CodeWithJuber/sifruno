package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
)

// No ACME server runs here: lego sits behind Issuer, and these tests cover
// what the panel itself does with files, keys, records and the loop.

func TestChallengeFilesWriteAndRemoveTheAnswer(t *testing.T) {
	dir := t.TempDir()
	c := challengeFiles{dir: dir}
	token, keyAuth := "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA", "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.thumbprint"
	if err := c.Present(context.Background(), "example.com", token, keyAuth); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, token)
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != keyAuth {
		t.Fatalf("answer %q %v", raw, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
		t.Fatalf("answer mode %v %v", info.Mode(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".token-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %q", left)
	}
	// Written again (a retried challenge): replaced, not refused.
	if err = c.Present(context.Background(), "example.com", token, keyAuth); err != nil {
		t.Fatal(err)
	}
	if err = c.CleanUp(context.Background(), "example.com", token, keyAuth); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("answer still there: %v", err)
	}
	// Removing one already gone is fine.
	if err = c.CleanUp(context.Background(), "example.com", token, keyAuth); err != nil {
		t.Fatal(err)
	}
}

func TestChallengeFilesRefuseTokensThatAreNotPlainNames(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(filepath.Dir(dir), "outside")
	c := challengeFiles{dir: dir}
	for _, token := range []string{"", "../outside", "a/b", ".hidden", "a.b", "a b", "tok=", strings.Repeat("a", 257), "a\x00b"} {
		if err := c.Present(context.Background(), "example.com", token, "x"); err == nil {
			t.Errorf("token %q accepted", token)
		}
		if err := c.CleanUp(context.Background(), "example.com", token, "x"); err == nil {
			t.Errorf("cleanup of token %q accepted", token)
		}
	}
	if items, _ := os.ReadDir(dir); len(items) != 0 {
		t.Fatalf("files written: %v", items)
	}
	if _, err := os.Lstat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a file was written outside the challenge directory")
	}
}

func TestChallengeFilesNeedTheProvisionedDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "sifruno-acme")
	err := challengeFiles{dir: missing}.Present(context.Background(), "example.com", "token", "x")
	if err == nil || !strings.Contains(err.Error(), "is missing; provisioning creates it") {
		t.Fatalf("missing directory: %v", err)
	}
	if _, serr := os.Lstat(missing); !errors.Is(serr, os.ErrNotExist) {
		t.Fatal("the panel made the challenge directory itself")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err = os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if err = (challengeFiles{dir: link}).Present(context.Background(), "example.com", "token", "x"); err == nil {
		t.Fatal("a symlinked challenge directory was used")
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{Email: "admin@example.com", StateDir: filepath.Join(t.TempDir(), "acme"), ChallengeDir: t.TempDir()}
}

func TestAccountKeyIsMadeOncePrivateAndReused(t *testing.T) {
	cfg := testConfig(t)
	first, err := newLegoIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first.cfg.Directory != LetsEncrypt {
		t.Fatalf("default directory %q", first.cfg.Directory)
	}
	keyPath := filepath.Join(cfg.StateDir, accountKeyFile)
	info, err := os.Lstat(keyPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v %v", info.Mode(), err)
	}
	dirInfo, err := os.Lstat(cfg.StateDir)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode %v %v", dirInfo.Mode(), err)
	}
	raw, _ := os.ReadFile(keyPath)
	if block, _ := pem.Decode(raw); block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("key file is not one EC PEM block")
	}
	key := first.user.key.(*ecdsa.PrivateKey)
	if key.Curve != elliptic.P256() {
		t.Fatalf("key curve %v", key.Curve.Params().Name)
	}
	second, err := newLegoIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(second.user.key) {
		t.Fatal("a second start made a new account key")
	}
	// No registration happens before the first certificate is needed.
	if _, err = os.Lstat(filepath.Join(cfg.StateDir, accountFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("account record written at start: %v", err)
	}

	// A key file others can read is refused, not quietly used or repaired.
	if err = os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = newLegoIssuer(cfg); err == nil || !strings.Contains(err.Error(), "mode 0600") {
		t.Fatalf("readable key: %v", err)
	}
	if info, _ = os.Lstat(keyPath); info.Mode().Perm() != 0o644 {
		t.Fatal("the key file's mode was changed")
	}
	// So is a file that is not one P-256 key.
	for _, content := range []string{"not a key", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}))} {
		if err = os.WriteFile(keyPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(keyPath, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err = newLegoIssuer(cfg); err == nil {
			t.Fatalf("key file %q accepted", content)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(p384)
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = newLegoIssuer(cfg); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("P-384 key: %v", err)
	}
}

// A certificate authority that forgot the account (Pebble after a restart):
// the saved registration is dropped and the key kept, so the next attempt
// registers the same key again.
func TestForgottenAccountIsRegisteredAgain(t *testing.T) {
	cfg := testConfig(t)
	issuer, err := newLegoIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(cfg.StateDir, accountFile)
	if err = writePrivate(record, []byte(`{"version":1,"email":"admin@example.com","directory":"`+LetsEncrypt+`","location":"https://ca.example/acct/1"}`)); err != nil {
		t.Fatal(err)
	}
	issuer.user.account = &legoacme.ExtendedAccount{Location: "https://ca.example/acct/1"}
	forgotten := fmt.Errorf("certificates: %w", &legoacme.ProblemDetails{Type: legoacme.AccountDoesNotExistErrorType, HTTPStatus: 400})
	if !accountUnknown(forgotten) || accountUnknown(errors.New("other")) || accountUnknown(&legoacme.ProblemDetails{Type: legoacme.ConnectionErrorType}) {
		t.Fatal("accountUnknown does not single out accountDoesNotExist")
	}
	if err = issuer.forgetAccount(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(record); !errors.Is(err, os.ErrNotExist) || issuer.user.account != nil || issuer.client != nil {
		t.Fatalf("registration kept: %v", err)
	}
	if _, err = os.Lstat(filepath.Join(cfg.StateDir, accountKeyFile)); err != nil {
		t.Fatalf("account key removed: %v", err)
	}
	if err = issuer.forgetAccount(); err != nil {
		t.Fatalf("forgetting twice: %v", err)
	}
}

func testCA(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestConfigIsCheckedAtStart(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testCA(t), 0o644); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"no email", func(c *Config) { c.Email = "" }, "--acme-email"},
		{"display name", func(c *Config) { c.Email = "Admin <admin@example.com>" }, "--acme-email"},
		{"http directory", func(c *Config) { c.Directory = "http://127.0.0.1:14000/dir" }, "--acme-directory"},
		{"not a URL", func(c *Config) { c.Directory = "pebble" }, "--acme-directory"},
		{"missing CA file", func(c *Config) { c.CAFile = filepath.Join(t.TempDir(), "none.pem") }, "--acme-ca-file"},
		{"CA file without a certificate", func(c *Config) { c.CAFile = notPEM }, "holds no PEM certificate"},
		{"relative challenge directory", func(c *Config) { c.ChallengeDir = "sifruno-acme" }, "absolute"},
	} {
		cfg := testConfig(t)
		tc.change(&cfg)
		if _, err := newLegoIssuer(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	cfg := testConfig(t)
	cfg.Directory, cfg.CAFile = "https://127.0.0.1:14000/dir", caFile
	issuer, err := newLegoIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The CA file replaces the system roots, for the ACME client only.
	if tr := issuer.http.Transport.(*http.Transport); tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil || tr == http.DefaultTransport {
		t.Fatal("the CA file is not the ACME client's trust")
	}
	if tr := http.DefaultTransport.(*http.Transport); tr.TLSClientConfig != nil && tr.TLSClientConfig.RootCAs != nil {
		t.Fatal("the CA file reached the process-wide transport")
	}
}

func TestClassifyLegoErrors(t *testing.T) {
	problem := func(kind string) error {
		return fmt.Errorf("invalid challenge: %w", &legoacme.ProblemDetails{Type: kind, Detail: "detail", HTTPStatus: 403})
	}
	for _, tc := range []struct {
		err  error
		want error
	}{
		{problem(legoacme.ConnectionErrorType), ErrValidation},
		{problem(legoacme.DNSErrorType), ErrValidation},
		{problem(legoacme.UnauthorizedErrorType), ErrValidation},
		{problem(legoacme.IncorrectResponseErrorType), ErrValidation},
		{problem(legoacme.TLSErrorType), ErrValidation},
		{problem(legoacme.RateLimitedErrorType), ErrRateLimited},
		{&legoacme.RateLimitedError{ProblemDetails: &legoacme.ProblemDetails{Type: legoacme.RateLimitedErrorType}}, ErrRateLimited},
		{problem(legoacme.CaaErrorType), ErrAuthority},
		{problem(legoacme.ServerInternalErrorType), ErrAuthority},
		{errors.Join(errors.New("other domain"), problem(legoacme.ConnectionErrorType)), ErrValidation},
		{errors.New("dial tcp 127.0.0.1:14000: connection refused"), ErrAuthority},
		{context.DeadlineExceeded, ErrAuthority},
		{fmt.Errorf("%w: kept", ErrInstall), ErrInstall},
	} {
		got := classify(tc.err)
		if !errors.Is(got, tc.want) || !errors.Is(got, tc.err) {
			t.Errorf("%v: got %v, want %v", tc.err, got, tc.want)
		}
	}
}

// ---- Manager ----------------------------------------------------------------

type issuerFake struct {
	mu      sync.Mutex
	err     error
	domains []string
	keys    [][]byte
	// unreachable names the domains that do not reach this server;
	// failMany fails a request for more than one name.
	unreachable map[string]bool
	failMany    error
	probes      []string
}

func (f *issuerFake) Reaches(_ context.Context, domain string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes = append(f.probes, domain)
	return !f.unreachable[domain]
}

func (f *issuerFake) Issue(_ context.Context, names []string) (Certificate, error) {
	domain := strings.Join(names, ",")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains = append(f.domains, domain)
	if f.err != nil {
		return Certificate{}, f.err
	}
	if f.failMany != nil && len(names) > 1 {
		return Certificate{}, f.failMany
	}
	key := []byte("-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----\n")
	f.keys = append(f.keys, key)
	return Certificate{ChainPEM: []byte("chain " + domain), KeyPEM: key}, nil
}

type installerFake struct {
	mu       sync.Mutex
	err      error
	notAfter time.Time
	calls    []string
	keys     []string
}

func (f *installerFake) Install(_ context.Context, id string, revision uint64, certPEM, keyPEM []byte) (uint64, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("%s rev=%d %s", id, revision, certPEM))
	f.keys = append(f.keys, string(keyPEM))
	if f.err != nil {
		return 0, time.Time{}, f.err
	}
	return revision + 1, f.notAfter, nil
}

type sitesFake struct {
	sites []Site
	err   error
}

func (f *sitesFake) Sites(context.Context) ([]Site, error) { return slices.Clone(f.sites), f.err }

type managerFixture struct {
	m         *Manager
	issuer    *issuerFake
	installer *installerFake
	sites     *sitesFake
	log       *bytes.Buffer
	dir       string
	now       time.Time
}

func newManagerFixture(t *testing.T) *managerFixture {
	t.Helper()
	f := &managerFixture{issuer: &issuerFake{}, sites: &sitesFake{}, log: &bytes.Buffer{}, dir: filepath.Join(t.TempDir(), "acme"), now: time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	f.installer = &installerFake{notAfter: f.now.Add(90 * 24 * time.Hour)}
	m, err := NewManager(f.issuer, f.installer, f.sites, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	m.log = f.log
	m.records.log = f.log
	m.now = func() time.Time { return f.now }
	f.m = m
	return f
}

func (f *managerFixture) lines() []string {
	return strings.Split(strings.TrimSuffix(f.log.String(), "\n"), "\n")
}

func TestSecureInstallsAndRecords(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("a", 32)
	revision, notAfter, err := f.m.Secure(context.Background(), id, "example.com", 2)
	if err != nil || revision != 3 || !notAfter.Equal(f.installer.notAfter) {
		t.Fatalf("secure: %d %v %v", revision, notAfter, err)
	}
	if !slices.Equal(f.installer.calls, []string{id + " rev=2 chain example.com"}) || !strings.Contains(f.installer.keys[0], "PRIVATE KEY") {
		t.Fatalf("installer calls %q", f.installer.calls)
	}
	// The panel keeps no copy of the key once it is installed.
	if !bytes.Equal(f.issuer.keys[0], make([]byte, len(f.issuer.keys[0]))) {
		t.Fatal("key bytes not cleared after the install")
	}
	if got := f.lines(); len(got) != 1 || got[0] != "acme: example.com (account "+id+"): certificate installed, valid until 2027-02-21" {
		t.Fatalf("log %q", got)
	}
	r, ok := f.m.records.get(id)
	if !ok || r.Domain != "example.com" || !r.NotAfter.Equal(f.installer.notAfter) || !r.LastAttempt.Equal(f.now) || r.LastResult != "installed" {
		t.Fatalf("record %+v", r)
	}
	// The record is on disk, private, and read back by the next start.
	path := filepath.Join(f.dir, recordsFile)
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("records mode %v %v", info, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "chain") {
		t.Fatalf("records hold certificate material: %s", raw)
	}
	again, err := NewManager(f.issuer, f.installer, f.sites, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if r2, ok := again.records.get(id); !ok || !r2.NotAfter.Equal(r.NotAfter) {
		t.Fatalf("record after restart %+v", r2)
	}
}

func TestSecureFailuresAreClassifiedRecordedAndLoggedOnce(t *testing.T) {
	id := strings.Repeat("b", 32)
	for _, tc := range []struct {
		name      string
		issueErr  error
		installEr error
		want      error
		log       string
	}{
		{"not pointing", &legoacme.ProblemDetails{Type: legoacme.ConnectionErrorType, Detail: "Fetching http://example.com/.well-known/acme-challenge/x: Connection refused"}, nil, ErrValidation, "no certificate: acme: the certificate authority could not validate the domain: acme: error: 0 :: urn:ietf:params:acme:error:connection"},
		{"unreachable", errors.New("dial tcp: connection refused"), nil, ErrAuthority, "no certificate: acme: the certificate authority did not issue a certificate: dial tcp: connection refused"},
		{"install", nil, errors.New("certificate refused\n-----BEGIN EC PRIVATE KEY-----\nAAAA"), ErrInstall, "certificate issued but not installed: [error text removed: it quoted key material]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagerFixture(t)
			f.issuer.err, f.installer.err = tc.issueErr, tc.installEr
			_, _, err := f.m.Secure(context.Background(), id, "example.com", 2)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			got := f.lines()
			if len(got) != 1 || !strings.Contains(got[0], "acme: example.com (account "+id+"): "+tc.log) {
				t.Fatalf("log %q", got)
			}
			r, _ := f.m.records.get(id)
			if !r.NotAfter.IsZero() || !r.LastAttempt.Equal(f.now) || r.LastResult != tc.want.Error() {
				t.Fatalf("record %+v", r)
			}
		})
	}
}

func TestRenewalCheck(t *testing.T) {
	f := newManagerFixture(t)
	day := 24 * time.Hour
	ids := map[string]string{}
	for _, name := range []string{"fresh", "expiring", "pending", "tried", "gone", "moved", "suspended", "brokerOnly", "unknown"} {
		ids[name] = fmt.Sprintf("%032x", len(ids)+1)
	}
	set := func(name, domain string, notAfter, last time.Time) {
		f.m.records.change(ids[name], func(r *record) { r.Domain, r.NotAfter, r.LastAttempt = domain, notAfter, last })
	}
	set("fresh", "fresh.example", f.now.Add(60*day), f.now.Add(-30*day))        // 60 days left: nothing to do
	set("expiring", "expiring.example", f.now.Add(10*day), f.now.Add(-80*day))  // 10 days left: renew
	set("pending", "pending.example", time.Time{}, f.now.Add(-7*time.Hour))     // no certificate, tried 7 h ago: try again
	set("tried", "tried.example", time.Time{}, f.now.Add(-2*time.Hour))         // tried 2 h ago: wait
	set("gone", "gone.example", f.now.Add(60*day), f.now.Add(-30*day))          // the account was removed
	set("moved", "old.example", f.now.Add(60*day), f.now.Add(-30*day))          // the account's domain changed
	set("suspended", "suspended.example", time.Time{}, f.now.Add(-7*time.Hour)) // not active: left alone
	f.sites.sites = []Site{
		{AccountID: ids["fresh"], Domain: "fresh.example", Revision: 4, Active: true},
		{AccountID: ids["expiring"], Domain: "expiring.example", Revision: 5, Active: true},
		{AccountID: ids["pending"], Domain: "pending.example", Revision: 6, Active: true},
		{AccountID: ids["tried"], Domain: "tried.example", Revision: 7, Active: true},
		{AccountID: ids["moved"], Domain: "new.example", Revision: 8, Active: true},
		{AccountID: ids["suspended"], Domain: "suspended.example", Revision: 9, Active: false},
		// The broker reports a certificate the panel has no record of.
		{AccountID: ids["brokerOnly"], Domain: "broker.example", Revision: 10, Active: true, NotAfter: f.now.Add(5 * day)},
		// A live account with no record and no certificate: the panel
		// cannot tell whether its site is live, so it is left alone.
		{AccountID: ids["unknown"], Domain: "unknown.example", Revision: 11, Active: true},
	}
	wait := f.m.check(context.Background())
	if !slices.Equal(f.issuer.domains, []string{"expiring.example", "pending.example", "broker.example"}) {
		t.Fatalf("issued for %q", f.issuer.domains)
	}
	want := []string{ids["expiring"] + " rev=5 chain expiring.example", ids["pending"] + " rev=6 chain pending.example", ids["brokerOnly"] + " rev=10 chain broker.example"}
	if !slices.Equal(f.installer.calls, want) {
		t.Fatalf("installed %q", f.installer.calls)
	}
	for _, name := range []string{"gone", "moved"} {
		if _, ok := f.m.records.get(ids[name]); ok {
			t.Errorf("%s: record kept", name)
		}
	}
	if _, ok := f.m.records.get(ids["unknown"]); ok {
		t.Error("an unknown account was recorded")
	}
	// One line per attempt and per dropped record, nothing else.
	if got := f.lines(); len(got) != 5 {
		t.Fatalf("log %q", got)
	}
	// "tried" becomes due 4 hours from now (6 hours after its attempt).
	if wait != 4*time.Hour {
		t.Fatalf("next check in %v", wait)
	}

	// With nothing due soon, the next check is 12 hours away.
	f.now = f.now.Add(5 * time.Hour)
	f.issuer.domains, f.installer.calls = nil, nil
	f.issuer.err = errors.New("dial tcp: connection refused")
	if wait = f.m.check(context.Background()); wait != 6*time.Hour {
		t.Fatalf("after a failed retry the next check is in %v", wait)
	}
	if !slices.Equal(f.issuer.domains, []string{"tried.example"}) {
		t.Fatalf("issued for %q", f.issuer.domains)
	}

	// The account list cannot be read: nothing is tried or forgotten.
	f.sites.err = errors.New("broker down")
	f.issuer.domains = nil
	f.log.Reset()
	f.m.check(context.Background())
	if len(f.issuer.domains) != 0 || len(f.m.records.all()) != 6 || !strings.Contains(f.log.String(), "the account list could not be read: broker down") {
		t.Fatalf("broker down: %q %d %q", f.issuer.domains, len(f.m.records.all()), f.log.String())
	}
}

func TestNextWaitIsAtMost12HoursAndAtLeastAMinute(t *testing.T) {
	f := newManagerFixture(t)
	if got := f.m.nextWait(); got != checkEvery {
		t.Fatalf("no records: %v", got)
	}
	f.m.records.change("a", func(r *record) { r.Domain, r.LastAttempt = "a.example", f.now.Add(-6*time.Hour+30*time.Second) })
	if got := f.m.nextWait(); got != minWait {
		t.Fatalf("due in 30 s: %v", got)
	}
	// Already due but left alone (a suspended account): the regular check.
	f.m.records.change("a", func(r *record) { r.LastAttempt = f.now.Add(-7 * time.Hour) })
	if got := f.m.nextWait(); got != checkEvery {
		t.Fatalf("overdue: %v", got)
	}
}

func TestRunStopsWithItsContext(t *testing.T) {
	f := newManagerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.m.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestUnusableRecordsFileIsSetAside(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, recordsFile)
	if err := os.WriteFile(path, []byte(`{"version":1,"sites":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	r, err := openRecords(dir, &log)
	if err != nil || len(r.all()) != 0 {
		t.Fatalf("open %v", err)
	}
	aside, _ := filepath.Glob(path + ".corrupt-*")
	if len(aside) != 1 || strings.Count(log.String(), "\n") != 1 || !strings.Contains(log.String(), aside[0]) {
		t.Fatalf("aside %q log %q", aside, log.String())
	}
	// A valid file is read back.
	data, _ := json.Marshal(recordsData{Version: 1, Sites: []record{{AccountID: "x", Domain: "x.example"}}})
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if r, err = openRecords(dir, &log); err != nil || len(r.all()) != 1 {
		t.Fatalf("reopen %v %d", err, len(r.all()))
	}
}
