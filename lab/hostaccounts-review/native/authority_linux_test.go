//go:build linux && hostaccounts_review_overlay

// Compile as a virtual additional test file in internal/hostaccounts via a Go
// compiler overlay. The implementation is read only; this file calls the
// repaired production directory-opening helper directly.
package hostaccounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReviewerNativePathAuthority(t *testing.T) {
	if os.Getenv("SIFRUNO_HOSTACCOUNTS_REVIEW_GUEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires explicit disposable-guest root admission")
	}
	base, err := os.MkdirTemp("/run", "sfr-authority-")
	if err != nil {
		t.Fatal("fresh guest authority fixture unavailable")
	}
	defer os.RemoveAll(base)
	home := filepath.Join(base, "home")
	target := filepath.Join(base, "unrelated-root-target")
	state := filepath.Join(base, "root-state")
	owners := filepath.Join(state, "owners")
	for _, path := range []string{home, target, state, owners} {
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("fresh authority directory unavailable")
		}
	}
	// Numeric ownership of a newly created fixture directory is not an OS
	// account creation. It models a tenant-writable parent for path swaps.
	if os.Chown(home, 20000, 20000) != nil {
		t.Fatal("fixture parent ownership failed")
	}
	before := reviewerDirectorySnapshot(t, target)
	homeFD, err := openDirectoryAt(unix.AT_FDCWD, home)
	if err != nil {
		t.Fatal("production home opener failed")
	}
	defer homeFD.Close()
	public := filepath.Join(home, "public_html")
	if os.Symlink(target, public) != nil {
		t.Fatal("isolated symlink fixture unavailable")
	}
	if opened, err := openDirectoryAt(int(homeFD.Fd()), "public_html"); !errors.Is(err, ErrRecovery) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("production opener followed tenant public_html symlink")
	}
	if reviewerDirectorySnapshot(t, target) != before {
		t.Fatal("symlink rejection modified unrelated target")
	}
	if os.Remove(public) != nil || os.Mkdir(public, 0700) != nil {
		t.Fatal("fresh real public directory unavailable")
	}
	publicFD, err := openDirectoryAt(int(homeFD.Fd()), "public_html")
	if err != nil {
		t.Fatal("production public opener failed")
	}
	defer publicFD.Close()
	identity, err := heldIdentity(publicFD, 0, 0, 0700)
	if err != nil {
		t.Fatal("held public identity unavailable")
	}
	parked := filepath.Join(home, "parked-public")
	if os.Rename(public, parked) != nil || os.Symlink(target, public) != nil {
		t.Fatal("deterministic tenant-parent path swap failed")
	}
	if publicFD.Chmod(0750) != nil || publicFD.Chown(20000, 20000) != nil {
		t.Fatal("held-descriptor mutation failed")
	}
	after, err := heldIdentity(publicFD, 20000, 20000, 0750)
	if err != nil || after != identity {
		t.Fatal("descriptor mutation changed selected directory identity")
	}
	if reviewerDirectorySnapshot(t, target) != before {
		t.Fatal("descriptor mutation followed replacement symlink")
	}
	if _, err := heldIdentity(publicFD, 0, 0, 0750); !errors.Is(err, ErrRecovery) {
		t.Fatal("ownership guard accepted unexpected owner")
	}

	r := record{Account: Account{ID: strings.Repeat("a", 32), Home: home}, Tag: "sifruno-managed:" + strings.Repeat("a", 32)}
	n := linuxSystem{opts: BrokerOptions{StateDir: state, HomesDir: base}}
	marker := n.markerPath(r)
	if marker != filepath.Join(owners, r.Account.ID) {
		t.Fatal("authoritative marker is not under root-only broker state")
	}
	if os.WriteFile(marker, []byte(r.Tag+"\n"), 0600) != nil {
		t.Fatal("fresh private marker unavailable")
	}
	if _, err := markerIdentity(marker, r.Tag); err != nil {
		t.Fatal("private marker was not recognized")
	}
	// A same-content marker under the tenant-owned home is never substituted
	// for the missing private authoritative marker.
	if os.WriteFile(filepath.Join(home, ".sifruno-host-account"), []byte(r.Tag+"\n"), 0600) != nil || os.Remove(marker) != nil {
		t.Fatal("marker authority challenge failed")
	}
	if _, err := markerIdentity(n.markerPath(r), r.Tag); !errors.Is(err, ErrRecovery) {
		t.Fatal("home marker substituted for missing private authority")
	}
}

type reviewerDirSnapshot struct {
	UID, GID uint32
	Mode     os.FileMode
	Dev      uint64
	Ino      uint64
}

func reviewerDirectorySnapshot(t *testing.T, path string) reviewerDirSnapshot {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		t.Fatal("authority target snapshot unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("authority target metadata unavailable")
	}
	return reviewerDirSnapshot{stat.Uid, stat.Gid, info.Mode().Perm(), uint64(stat.Dev), stat.Ino}
}
