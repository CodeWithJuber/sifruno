//go:build linux

package hostaccounts

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Without root the TLS root's parent is not root-owned, so nothing is
// written; a missing TLS root is a completed removal and has nothing to
// install from.
func TestCertificateFilesNeedARootOwnedParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("covered by the root test")
	}
	tls := filepath.Join(t.TempDir(), "tls")
	n := &linuxSystem{webUID: 65534, tlsDir: tls}
	r := record{Account: Account{ID: strings.Repeat("c", 32), Username: "fixtureacct", Domain: "fixture.test"}}
	c := newTestChain(t, "fixture.test")
	b, err := parseCertificate(c.certPEM(), string(sec1PEM(t, c.key)))
	if err != nil {
		t.Fatal(err)
	}
	if e := n.StageCertificate(t.Context(), r, b.chainPEM, b.keyPEM); e != ErrUnavailable {
		t.Fatalf("staging under a parent that is not root's: %v", e)
	}
	if _, e := os.Lstat(tls); !os.IsNotExist(e) {
		t.Fatal("the TLS root was made under an unadmitted parent")
	}
	if e := n.removeSiteTLS(r); e != nil {
		t.Fatalf("removing from a missing TLS root: %v", e)
	}
	if e := n.StageCertificate(t.Context(), r, nil, nil); e != nil {
		t.Fatalf("unstaging from a missing TLS root: %v", e)
	}
	if e := n.ApplyCertificate(t.Context(), r, b.state, nil, nil); e != ErrRecovery {
		t.Fatalf("installing without a staged pair: %v", e)
	}
}

// Root-only: the real file effects of the certificate operation, except the
// OpenLiteSpeed test and reload. Run on the dev VM with:
// go test -c ./internal/hostaccounts && sudo ./hostaccounts.test -test.run RootOnly
func TestRootOnlyCertificateFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: checks root ownership and modes of the TLS files")
	}
	base, e := os.MkdirTemp("/etc", "sifruno-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if os.Chmod(base, 0755) != nil {
		t.Fatal("fixture")
	}
	tls := filepath.Join(base, "tls")
	n := &linuxSystem{webUID: 65534, tlsDir: tls}
	r := record{Account: Account{ID: strings.Repeat("c", 32), Username: "fixtureacct", Domain: "fixture.test"}}
	site := filepath.Join(tls, siteName(r.Account.ID))
	rootOnly := func(path string, dir bool) {
		t.Helper()
		info, e := os.Lstat(path)
		if e != nil {
			t.Fatal(e)
		}
		st := info.Sys().(*syscall.Stat_t)
		want := os.FileMode(0600)
		if dir {
			want = os.ModeDir | 0700
		} else if !info.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file", path)
		}
		if info.Mode() != want || st.Uid != 0 || st.Gid != 0 {
			t.Fatalf("%s is %v uid %d gid %d", path, info.Mode(), st.Uid, st.Gid)
		}
	}
	c := newTestChain(t, "fixture.test")
	b, err := parseCertificate(c.certPEM(), string(sec1PEM(t, c.key)))
	if err != nil {
		t.Fatal(err)
	}
	if e := n.StageCertificate(t.Context(), r, b.chainPEM, b.keyPEM); e != nil {
		t.Fatal(e)
	}
	rootOnly(tls, true)
	rootOnly(site, true)
	for name, want := range map[string][]byte{stagedCertFile: b.chainPEM, stagedKeyFile: b.keyPEM} {
		rootOnly(filepath.Join(site, name), false)
		if got, e := os.ReadFile(filepath.Join(site, name)); e != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s holds the wrong bytes", name)
		}
	}

	// The listener pair is made once and kept while it is usable.
	tx := &configTxn{}
	if e := n.ensureListenerCertificate(tx); e != nil {
		t.Fatal(e)
	}
	tx.close()
	rootOnly(filepath.Join(tls, listenerCertFile), false)
	rootOnly(filepath.Join(tls, listenerKeyFile), false)
	first, _ := os.ReadFile(filepath.Join(tls, listenerCertFile))
	tx = &configTxn{}
	if e := n.ensureListenerCertificate(tx); e != nil {
		t.Fatal(e)
	}
	tx.close()
	if again, _ := os.ReadFile(filepath.Join(tls, listenerCertFile)); !bytes.Equal(first, again) {
		t.Fatal("a usable listener certificate was replaced")
	}

	// Unstaging removes only the staged pair.
	if os.WriteFile(filepath.Join(site, siteCertFile), b.chainPEM, 0600) != nil || os.WriteFile(filepath.Join(site, siteKeyFile), b.keyPEM, 0600) != nil {
		t.Fatal("fixture")
	}
	if e := n.StageCertificate(t.Context(), r, nil, nil); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(site)
	if len(entries) != 2 {
		t.Fatalf("unstaging left %v", entries)
	}

	// A file the broker never writes keeps the directory and is reported.
	stray := filepath.Join(site, "notes.txt")
	if os.WriteFile(stray, []byte("x"), 0600) != nil {
		t.Fatal("fixture")
	}
	if e := n.removeSiteTLS(r); e != ErrRecovery {
		t.Fatalf("unknown file: %v", e)
	}
	if _, e := os.Lstat(stray); e != nil {
		t.Fatal("an unknown file was removed")
	}
	if os.Remove(stray) != nil {
		t.Fatal("fixture")
	}
	// A temporary file left by a crash goes with the rest.
	if os.WriteFile(filepath.Join(site, siteKeyFile+".sifruno-new"), []byte("x"), 0600) != nil {
		t.Fatal("fixture")
	}
	if e := n.removeSiteTLS(r); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(site); !os.IsNotExist(e) {
		t.Fatal("the site's TLS directory survived")
	}
	if e := n.removeSiteTLS(r); e != nil {
		t.Fatalf("a repeated removal: %v", e)
	}

	// A site directory replaced by a link, or a loosened TLS root, is refused.
	target := filepath.Join(base, "elsewhere")
	if os.Mkdir(target, 0700) != nil || os.Symlink(target, site) != nil {
		t.Fatal("fixture")
	}
	if e := n.StageCertificate(t.Context(), r, b.chainPEM, b.keyPEM); e != ErrUnavailable {
		t.Fatalf("staging through a link: %v", e)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatal("staging wrote through a link")
	}
	if os.Remove(site) != nil || os.Chmod(tls, 0755) != nil {
		t.Fatal("fixture")
	}
	if e := n.StageCertificate(t.Context(), r, b.chainPEM, b.keyPEM); e != ErrUnavailable {
		t.Fatalf("staging into a TLS root others may read: %v", e)
	}
}
