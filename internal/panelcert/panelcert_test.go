package panelcert

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSelfSignedCreateReuseAndRenew(t *testing.T) {
	state := t.TempDir()
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	hosts := []string{"panel.example.test", "192.0.2.10"}
	first, err := Load(state, "", "", hosts, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first.SelfSigned || len(first.Fingerprint) != 95 {
		t.Fatalf("unexpected result %+v", first)
	}
	leaf, _ := x509.ParseCertificate(first.Certificate.Certificate[0])
	if leaf.VerifyHostname("panel.example.test") != nil || leaf.VerifyHostname("192.0.2.10") != nil || leaf.VerifyHostname("other.test") == nil {
		t.Fatal("certificate names are wrong")
	}
	if leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.IsCA {
		t.Fatal("certificate must be a server leaf, not a CA")
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{certFile, keyFile} {
			st, err := os.Stat(filepath.Join(state, "tls", name))
			if err != nil || st.Mode().Perm() != 0600 {
				t.Fatalf("%s mode: %v %v", name, st, err)
			}
		}
	}
	again, err := Load(state, "", "", hosts, now.Add(24*time.Hour))
	if err != nil || again.Fingerprint != first.Fingerprint {
		t.Fatal("an unchanged certificate must be reused")
	}
	changed, err := Load(state, "", "", []string{"panel.example.test"}, now)
	if err != nil || changed.Fingerprint == first.Fingerprint {
		t.Fatal("a changed host list must give a new certificate")
	}
	late, err := Load(state, "", "", []string{"panel.example.test"}, now.Add(lifetime-renewBefore+time.Hour))
	if err != nil || late.Fingerprint == changed.Fingerprint {
		t.Fatal("a certificate near expiry must be renewed")
	}
	entries, _ := os.ReadDir(filepath.Join(state, "tls"))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary file left: %s", e.Name())
		}
	}
}

func TestOperatorFilesMustCoverHosts(t *testing.T) {
	src := t.TempDir()
	now := time.Now()
	if _, err := Load(src, "", "", []string{"panel.example.test"}, now); err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(src, "tls", certFile), filepath.Join(src, "tls", keyFile)
	other := t.TempDir()
	got, err := Load(other, cert, key, []string{"panel.example.test"}, now)
	if err != nil || got.SelfSigned {
		t.Fatalf("operator files refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(other, "tls")); !os.IsNotExist(err) {
		t.Fatal("operator files must not create self-signed state")
	}
	if _, err := Load(other, cert, key, []string{"elsewhere.test"}, now); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
	if _, err := Load(other, cert, "", []string{"panel.example.test"}, now); err == nil {
		t.Fatal("a certificate without its key was accepted")
	}
	if _, err := Load(other, cert, key, []string{"panel.example.test"}, now.Add(2*lifetime)); err == nil {
		t.Fatal("an expired certificate was accepted")
	}
}

func TestHostValidation(t *testing.T) {
	for _, ok := range []string{"panel.example.test", "a", "x-1.example", "192.0.2.10", "2001:db8::1"} {
		if !ValidHost(ok) {
			t.Fatalf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "Panel.example", "-a.test", "a_b.test", "exa mple", "a..b", "a.test/", "*.example.test"} {
		if ValidHost(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, err := Load(t.TempDir(), "", "", []string{"bad host"}, time.Now()); err == nil {
		t.Fatal("invalid host accepted")
	}
	if _, err := Load(t.TempDir(), "", "", nil, time.Now()); err == nil {
		t.Fatal("empty host list accepted")
	}
}
