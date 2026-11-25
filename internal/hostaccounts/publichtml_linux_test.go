//go:build linux

package hostaccounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The adopt's native step reaches public_html through handles that follow
// no link: a link, a file, a missing folder or someone else's directory is
// refused with nothing changed, and only the account's own directory is
// returned, set to mode 0750 together with the home.
func TestRootOnlyAdoptPublicHTMLFollowsNoLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: makes directories another user owns")
	}
	base, e := os.MkdirTemp("/etc", "sifruno-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	const uid, gid = 54324, 54324
	homes, target := filepath.Join(base, "homes"), filepath.Join(base, "target")
	home := filepath.Join(homes, "webacct")
	public := filepath.Join(home, "public_html")
	tenantDir := func(p string, mode os.FileMode) {
		t.Helper()
		if os.Mkdir(p, mode) != nil || os.Chown(p, uid, gid) != nil || os.Chmod(p, mode) != nil {
			t.Fatalf("fixture %s", p)
		}
	}
	if os.Chmod(base, 0755) != nil || os.Mkdir(homes, 0755) != nil || os.Chmod(homes, 0755) != nil || os.Mkdir(target, 0700) != nil {
		t.Fatal("fixture")
	}
	tenantDir(home, 0750)
	tenantDir(public, 0750)
	homeID, e1 := dirIdentity(home, uid, gid, 0750)
	publicID, e2 := dirIdentity(public, uid, gid, 0750)
	if e1 != nil || e2 != nil {
		t.Fatal("fixture identity")
	}
	n := &linuxSystem{opts: BrokerOptions{HomesDir: homes}}
	r := record{Account: Account{ID: strings.Repeat("d", 32), Username: "webacct", Home: home, PublicHTML: public, UID: uid, GID: gid}, Ownership: ownership{Home: homeID, Public: publicID}}
	modeOf := func(p string) os.FileMode {
		info, e := os.Lstat(p)
		if e != nil {
			t.Fatal(e)
		}
		return info.Mode().Perm()
	}

	// The tenant moves public_html away and leaves a link to a root
	// directory, then a file, then nothing, then a directory it does not own.
	if os.Rename(public, filepath.Join(home, "public_old")) != nil {
		t.Fatal("move")
	}
	refused := func(name string) {
		t.Helper()
		if _, e := n.AdoptPublicHTML(t.Context(), r); !errors.Is(e, ErrConflict) {
			t.Fatalf("%s: %v", name, e)
		}
		if modeOf(target) != 0700 {
			t.Fatalf("%s: the link's target changed", name)
		}
	}
	refused("missing")
	if os.Symlink(target, public) != nil {
		t.Fatal("link")
	}
	refused("a link")
	if os.Remove(public) != nil || os.WriteFile(public, []byte("x"), 0644) != nil {
		t.Fatal("file")
	}
	refused("a file")
	if os.Remove(public) != nil || os.Mkdir(public, 0755) != nil {
		t.Fatal("root's directory")
	}
	refused("a directory the account does not own")
	if os.Remove(public) != nil {
		t.Fatal("unfixture")
	}

	// Its own new directory, with loose modes on both, is adopted.
	tenantDir(public, 0777)
	if os.Chmod(home, 0755) != nil {
		t.Fatal("home mode")
	}
	got, e := n.AdoptPublicHTML(t.Context(), r)
	want, idErr := dirIdentity(public, uid, gid, 0)
	if e != nil || idErr != nil || got != want || got == publicID {
		t.Fatalf("adopt: %+v %v, want %+v", got, e, want)
	}
	if modeOf(home) != 0750 || modeOf(public) != 0750 {
		t.Fatalf("modes after adopt: home %o, public_html %o", modeOf(home), modeOf(public))
	}
	next := r
	next.Ownership.Public = got
	if e := n.VerifySiteFiles(next); e != nil {
		t.Fatalf("the adopted folder does not verify: %v", e)
	}

	// A home that is not the recorded one is refused.
	other := r
	other.Ownership.Home.Ino++
	if _, e := n.AdoptPublicHTML(t.Context(), other); !errors.Is(e, ErrConflict) {
		t.Fatalf("another home: %v", e)
	}
}
