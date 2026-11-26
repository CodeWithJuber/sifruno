package panelcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/acme"
)

const panelName = "panel.203-0-113-9.sslip.io"

// issue signs a leaf for names with a throwaway CA, valid from notBefore to
// notAfter, and answers its chain (leaf first) and its key, as lego does.
func issue(t *testing.T, names []string, notBefore, notAfter time.Time) (chainPEM, keyPEM []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return chainPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func hello(name string) *tls.ClientHelloInfo { return &tls.ClientHelloInfo{ServerName: name} }

func TestPublicNames(t *testing.T) {
	got := PublicNames([]string{
		panelName, "203.0.113.9", "2001:db8::1", "localhost", "panel", "panel.test", "box.local",
		"site.example", "a.invalid", "h.localhost", "srv.internal", "9.113.0.203.in-addr.arpa",
		"nas.home.arpa", "panel.example.com", "x.example.net", "abc.onion",
		"www." + panelName, "admin.hostname.dev", panelName,
	})
	want := []string{panelName, "www." + panelName, "admin.hostname.dev"}
	if !slices.Equal(got, want) {
		t.Fatalf("public names %q, want %q", got, want)
	}
	if PublicNames([]string{"203.0.113.9", "panel.test"}) != nil {
		t.Fatal("names with no public one gave some")
	}
}

func TestIssuedInstallSavesServesAndSurvivesARestart(t *testing.T) {
	state := t.TempDir()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	names := []string{panelName, "admin.hostname.dev"}
	i, err := OpenIssued(state, names, clock)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing yet: the listener serves its self-signed certificate.
	if c, err := i.GetCertificate(hello(panelName)); c != nil || err != nil {
		t.Fatalf("a certificate before any was issued: %v %v", c, err)
	}
	site := i.Site()
	if site.AccountID != AccountID || site.Domain != panelName || !slices.Equal(site.Aliases, []string{"admin.hostname.dev"}) || !site.Active || !site.NotAfter.IsZero() || site.Covered != nil {
		t.Fatalf("site before a certificate %+v", site)
	}
	if sites, err := i.Sites(context.Background()); err != nil || len(sites) != 1 || sites[0].Domain != panelName {
		t.Fatalf("sites %+v %v", sites, err)
	}

	notAfter := now.Add(90 * 24 * time.Hour).Truncate(time.Second)
	chain, key := issue(t, names, now.Add(-time.Hour), notAfter)
	revision, got, err := i.Install(context.Background(), AccountID, site.Revision, chain, key)
	if err != nil || !got.Equal(notAfter) || revision <= site.Revision {
		t.Fatalf("install: %d %v %v", revision, got, err)
	}
	served, err := i.GetCertificate(hello(panelName))
	if err != nil || served == nil || !bytes.Contains(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: served.Certificate[0]})) {
		t.Fatalf("not served for the panel's name: %v", err)
	}
	if len(served.Certificate) != 2 {
		t.Fatalf("the chain is not served whole: %d certificates", len(served.Certificate))
	}
	// Another name, and a client that sends none (an IP address), get the
	// self-signed one.
	for _, other := range []string{"other.hostname.dev", ""} {
		if c, _ := i.GetCertificate(hello(other)); c != nil {
			t.Fatalf("served for %q", other)
		}
	}
	site = i.Site()
	if site.Revision != revision || !site.NotAfter.Equal(notAfter) || !slices.Equal(site.Covered, names) {
		t.Fatalf("site after the install %+v", site)
	}
	// One private file holds the chain and its key.
	path := filepath.Join(state, "tls", issuedFile)
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved file %v %v", info, err)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, chain) || !bytes.Contains(raw, key) {
		t.Fatal("the saved file does not hold the chain and the key")
	}

	// The next start serves it at once.
	again, err := OpenIssued(state, names, clock)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := again.GetCertificate(hello("admin.hostname.dev")); c == nil || !again.NotAfter().Equal(notAfter) {
		t.Fatal("the saved certificate is not served after a restart")
	}

	// A renewal replaces it while the listener runs.
	renewed, renewedKey := issue(t, names, now, now.Add(120*24*time.Hour))
	if _, _, err = i.Install(context.Background(), AccountID, revision, renewed, renewedKey); err != nil {
		t.Fatal(err)
	}
	if c, _ := i.GetCertificate(hello(panelName)); c == nil || !bytes.Contains(renewed, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})) {
		t.Fatal("the renewed certificate is not served")
	}
	// An expired one is not served.
	now = now.Add(200 * 24 * time.Hour)
	if c, _ := i.GetCertificate(hello(panelName)); c != nil {
		t.Fatal("an expired certificate is served")
	}
	entries, _ := os.ReadDir(filepath.Join(state, "tls"))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary file left: %s", e.Name())
		}
	}
}

func TestIssuedRefusesACertificateThatIsNotThePanels(t *testing.T) {
	state := t.TempDir()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	i, err := OpenIssued(state, []string{panelName}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	good, goodKey := issue(t, []string{panelName}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	other, otherKey := issue(t, []string{"other.hostname.dev"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	expired, expiredKey := issue(t, []string{panelName}, now.Add(-100*24*time.Hour), now.Add(-time.Hour))
	for name, tc := range map[string]struct {
		account    string
		chain, key []byte
	}{
		"another account": {"0123456789abcdef0123456789abcdef", good, goodKey},
		"another name":    {AccountID, other, otherKey},
		"expired":         {AccountID, expired, expiredKey},
		"not its key":     {AccountID, good, otherKey},
		"no certificate":  {AccountID, nil, goodKey},
	} {
		if _, _, err := i.Install(context.Background(), tc.account, 0, tc.chain, tc.key); err == nil {
			t.Errorf("%s: installed", name)
		} else if strings.Contains(err.Error(), "PRIVATE") {
			t.Errorf("%s: the error quotes the key: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(state, "tls", issuedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused certificate was saved: %v", err)
	}
	if c, _ := i.GetCertificate(hello(panelName)); c != nil {
		t.Fatal("a refused certificate is served")
	}
}

// A saved file the panel cannot use (others may read it, or it is not a
// pair) is not served; the next certificate replaces it.
func TestIssuedLeavesAnUnusableSavedFile(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	chain, key := issue(t, []string{panelName}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for name, write := range map[string]func(path string) error{
		"readable by others": func(path string) error { return os.WriteFile(path, append(slices.Clone(chain), key...), 0o644) },
		"not a pair":         func(path string) error { return os.WriteFile(path, chain, 0o600) },
		"not PEM":            func(path string) error { return os.WriteFile(path, []byte("garbage"), 0o600) },
	} {
		// The self-signed certificate is made first, as at the panel's start.
		state := t.TempDir()
		if _, err := Load(state, "", "", []string{panelName}, now); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(state, "tls", issuedFile)
		if err := write(path); err != nil {
			t.Fatal(err)
		}
		i, err := OpenIssued(state, []string{panelName}, func() time.Time { return now })
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c, _ := i.GetCertificate(hello(panelName)); c != nil || !i.NotAfter().IsZero() {
			t.Fatalf("%s: served", name)
		}
		if _, _, err = i.Install(context.Background(), AccountID, 0, chain, key); err != nil {
			t.Fatalf("%s: install over it: %v", name, err)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: replaced file %v %v", name, info, err)
		}
	}
}

type certificatesFake struct {
	mu        sync.Mutex
	err       error
	reachable []bool // what each probe answers in turn; true once they run out
	probes    int
	refreshes []acme.Site
	install   func() // runs inside Refresh, as an issued certificate's install
}

func (f *certificatesFake) Reaches(context.Context, string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	if len(f.reachable) == 0 {
		return true
	}
	ok := f.reachable[0]
	f.reachable = f.reachable[1:]
	return ok
}

func (f *certificatesFake) Refresh(_ context.Context, s acme.Site) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes = append(f.refreshes, s)
	if f.install != nil {
		f.install()
	}
	return f.err
}

func TestObtainAsksOnceAndSaysWhatHappened(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"not pointing": {fmt.Errorf("%w: connection refused", acme.ErrValidation), "Panel certificate: Let's Encrypt could not check " + panelName + " over http on port 80 of this server, so the panel keeps its self-signed certificate. Point the name's DNS at this server and open TCP port 80 to the internet; the panel asks again within 6 hours."},
		"rate limit":   {fmt.Errorf("%w: too many", acme.ErrRateLimited), "Panel certificate: Let's Encrypt has had too many requests for " + panelName + " or from this server, so the panel keeps its self-signed certificate. The panel asks again within 6 hours; if this lasts more than a day, read https://letsencrypt.org/docs/rate-limits/."},
		"not saved":    {fmt.Errorf("%w: disk full", acme.ErrInstall), "Panel certificate: Let's Encrypt issued a certificate for " + panelName + ", but the panel could not save it in its state folder, so it keeps its self-signed certificate. Check that the folder belongs to the panel's user and the disk has room; the panel asks again in a week."},
		"too soon":     {acme.ErrTooSoon, "Panel certificate: the panel asked Let's Encrypt for " + panelName + " less than an hour ago, so it does not ask again now and keeps its self-signed certificate. The renewal check asks again within 6 hours of that try."},
		"no answer":    {fmt.Errorf("%w: dial tcp: i/o timeout", acme.ErrAuthority), "Panel certificate: Let's Encrypt did not answer or did not issue a certificate for " + panelName + ", so the panel keeps its self-signed certificate. Check that this server reaches acme-v02.api.letsencrypt.org on port 443; the panel asks again within 6 hours."},
	} {
		i, err := OpenIssued(t.TempDir(), []string{panelName}, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		certs := &certificatesFake{err: tc.err}
		var log bytes.Buffer
		i.Obtain(context.Background(), certs, &log)
		if len(certs.refreshes) != 1 || certs.refreshes[0].Domain != panelName || certs.refreshes[0].AccountID != AccountID {
			t.Fatalf("%s: refreshes %+v", name, certs.refreshes)
		}
		if got := strings.TrimSuffix(log.String(), "\n"); got != tc.want {
			t.Errorf("%s: log\n%q\nwant\n%q", name, got, tc.want)
		}
	}
}

func TestObtainLogsTheIssuedCertificate(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	state := t.TempDir()
	i, err := OpenIssued(state, []string{panelName}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	chain, key := issue(t, []string{panelName}, now.Add(-time.Hour), time.Date(2027, 2, 24, 11, 0, 0, 0, time.UTC))
	certs := &certificatesFake{}
	certs.install = func() {
		if _, _, err := i.Install(context.Background(), AccountID, 0, chain, key); err != nil {
			t.Error(err)
		}
	}
	var log bytes.Buffer
	i.Obtain(context.Background(), certs, &log)
	want := "Panel certificate: from Let's Encrypt for " + panelName + ", valid until 2027-02-24. The renewal check, 2 minutes after start and then every 12 hours, renews it 30 days before then.\n"
	if log.String() != want {
		t.Fatalf("log %q", log.String())
	}
	// At the next start a certificate with more than 30 days left is kept:
	// nothing is asked for.
	again, _ := OpenIssued(state, []string{panelName}, func() time.Time { return now.Add(24 * time.Hour) })
	certs = &certificatesFake{}
	log.Reset()
	again.Obtain(context.Background(), certs, &log)
	if len(certs.refreshes) != 0 || certs.probes != 0 || log.String() != want {
		t.Fatalf("a good certificate was asked for again: %d refreshes, %d probes, log %q", len(certs.refreshes), certs.probes, log.String())
	}
	// With 30 days or less left it asks, as the renewal check would.
	late, _ := OpenIssued(state, []string{panelName}, func() time.Time { return time.Date(2027, 1, 30, 0, 0, 0, 0, time.UTC) })
	certs = &certificatesFake{}
	late.Obtain(context.Background(), certs, &bytes.Buffer{})
	if len(certs.refreshes) != 1 {
		t.Fatalf("an expiring certificate was not renewed: %d refreshes", len(certs.refreshes))
	}
	// If that fails, the panel says it keeps the certificate it serves,
	// which is still valid, not the self-signed one.
	certs = &certificatesFake{err: fmt.Errorf("%w: connection refused", acme.ErrValidation)}
	log.Reset()
	late.Obtain(context.Background(), certs, &log)
	want = "Panel certificate: Let's Encrypt could not check " + panelName + " over http on port 80 of this server, so the panel keeps its Let's Encrypt certificate, valid until 2027-02-24. Point the name's DNS at this server and open TCP port 80 to the internet; the panel asks again within 6 hours.\n"
	if log.String() != want {
		t.Fatalf("log\n%q\nwant\n%q", log.String(), want)
	}
}

// On a fresh start the broker may still be loading the web server's config
// with the panel's name: the panel waits a short while for the name to
// answer on port 80, then asks either way.
func TestObtainWaitsForTheNameToAnswer(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	i, err := OpenIssued(t.TempDir(), []string{panelName}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	i.reachEvery, i.reachWait = time.Millisecond, time.Minute
	certs := &certificatesFake{reachable: []bool{false, false, true}}
	i.Obtain(context.Background(), certs, &bytes.Buffer{})
	if certs.probes != 3 || len(certs.refreshes) != 1 {
		t.Fatalf("%d probes, %d refreshes", certs.probes, len(certs.refreshes))
	}

	// A name that never answers from here (a server behind NAT may not
	// reach its own public address) is asked for once the wait is over.
	i.reachEvery, i.reachWait = time.Millisecond, 20*time.Millisecond
	never := make([]bool, 1000)
	certs = &certificatesFake{reachable: never}
	var log bytes.Buffer
	i.Obtain(context.Background(), certs, &log)
	if len(certs.refreshes) != 1 || !strings.HasPrefix(log.String(), "Panel certificate: "+panelName+" does not answer on port 80 from this server yet; asking Let's Encrypt anyway.\n") {
		t.Fatalf("%d refreshes, log %q", len(certs.refreshes), log.String())
	}

	// A panel that stops while it waits asks for nothing.
	i.reachEvery, i.reachWait = time.Hour, 2*time.Hour
	certs = &certificatesFake{reachable: []bool{false}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var stopped bytes.Buffer
	go func() { i.Obtain(ctx, certs, &stopped); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Obtain did not stop with its context")
	}
	if len(certs.refreshes) != 0 || stopped.Len() != 0 {
		t.Fatalf("a stopped panel asked for a certificate or logged %q", stopped.String())
	}
}
