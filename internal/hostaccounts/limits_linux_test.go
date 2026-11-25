//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// list-units names a loaded slice first on its line; any other unit, or no
// line, is not that slice.
func TestSliceListed(t *testing.T) {
	name := "user-20001.slice"
	for out, want := range map[string]bool{
		"user-20001.slice loaded active active User Slice of UID 20001\n":   true,
		"user-20001.slice loaded inactive dead User Slice of UID 20001\n":   true,
		"● user-20001.slice loaded failed failed User Slice of UID 20001\n": true,
		"": false,
		"user-200011.slice loaded active active User Slice of UID 200011\n": false,
		"0 loaded units listed.\n": false,
	} {
		if got := sliceListed([]byte(out), name); got != want {
			t.Errorf("%q: %v", out, got)
		}
	}
	n := &linuxSystem{opts: BrokerOptions{ControllerUID: 20500}}
	for _, uid := range []int{0, 999, 20500, 60001} {
		if _, e := n.sliceLoaded(context.Background(), uid); !errors.Is(e, ErrInvalid) {
			t.Fatalf("UID %d: %v", uid, e)
		}
	}
}

// Only a UID in the account range that is not the controller's names a
// drop-in; the native operations refuse every other before touching a file.
func TestLimitsRefuseUIDsOutsideTheAccountRange(t *testing.T) {
	n := &linuxSystem{opts: BrokerOptions{ControllerUID: 20500}, unitDir: filepath.Join(t.TempDir(), "absent")}
	ctx := context.Background()
	for _, uid := range []int{0, 1, 999, 19999, 20500, 60001, 65534, -1} {
		if e := n.ApplyLimits(ctx, uid, DefaultLimits); !errors.Is(e, ErrInvalid) {
			t.Fatalf("apply for UID %d: %v", uid, e)
		}
		if e := n.limitsUID(uid); !errors.Is(e, ErrInvalid) {
			t.Fatalf("UID %d admitted", uid)
		}
		if e := n.RemoveLimits(ctx, uid); !errors.Is(e, ErrInvalid) {
			t.Fatalf("remove for UID %d: %v", uid, e)
		}
		if e := n.VerifyLimits(uid, DefaultLimits); !errors.Is(e, ErrInvalid) {
			t.Fatalf("verify for UID %d: %v", uid, e)
		}
	}
	if e := n.limitsUID(20501); e != nil {
		t.Fatal(e)
	}
}

func TestRootOnlyLimitsDropInFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: checks the owner and mode of the drop-in and its directory")
	}
	base, e := os.MkdirTemp("/etc", "sifruno-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	units := filepath.Join(base, "system")
	elsewhere := filepath.Join(base, "elsewhere")
	if os.Chmod(base, 0755) != nil || os.Mkdir(units, 0755) != nil || os.Mkdir(elsewhere, 0755) != nil {
		t.Fatal("fixture")
	}
	n := &linuxSystem{unitDir: units}
	dir, e := n.openUnitDir()
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	const uid = 54321
	changed, e := n.writeLimits(dir, uid, DefaultLimits)
	if e != nil || !changed {
		t.Fatalf("first write: %v %v", changed, e)
	}
	target := filepath.Join(units, "user-54321.slice.d", limitsDropIn)
	info, e := os.Lstat(target)
	if e != nil {
		t.Fatal(e)
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || st.Uid != 0 || st.Gid != 0 {
		t.Fatalf("drop-in is %v uid %d gid %d", info.Mode(), st.Uid, st.Gid)
	}
	if dirInfo, e := os.Lstat(filepath.Dir(target)); e != nil || dirInfo.Mode() != os.ModeDir|0755 {
		t.Fatalf("drop-in directory: %v %v", dirInfo, e)
	}
	want, _ := renderSliceLimits(DefaultLimits)
	if got, e := os.ReadFile(target); e != nil || string(got) != string(want) {
		t.Fatalf("content %q %v", got, e)
	}
	if e := n.VerifyLimits(uid, DefaultLimits); e != nil {
		t.Fatal(e)
	}
	if changed, e := n.writeLimits(dir, uid, DefaultLimits); e != nil || changed {
		t.Fatalf("an unchanged write changed: %v %v", changed, e)
	}
	bigger := AccountLimits{Processes: 200, MemoryMiB: 2048, CPUPercent: 200}
	if changed, e := n.writeLimits(dir, uid, bigger); e != nil || !changed || n.VerifyLimits(uid, DefaultLimits) == nil || n.VerifyLimits(uid, bigger) != nil {
		t.Fatalf("second write: %v %v", changed, e)
	}
	// An administrator's own drop-in keeps the directory; ours goes.
	own := filepath.Join(units, "user-54321.slice.d", "10-admin.conf")
	if os.WriteFile(own, []byte("[Slice]\n"), 0644) != nil {
		t.Fatal("fixture")
	}
	if removed, e := removeLimitsFile(dir, uid); e != nil || !removed {
		t.Fatalf("remove: %v %v", removed, e)
	}
	if _, e := os.Lstat(target); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("drop-in still there")
	}
	if _, e := os.Lstat(own); e != nil {
		t.Fatal("the administrator's drop-in was removed")
	}
	os.Remove(own)
	if removed, e := removeLimitsFile(dir, uid); e != nil || removed {
		t.Fatalf("second remove: %v %v", removed, e)
	}
	if _, e := os.Lstat(filepath.Dir(target)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("the empty drop-in directory is still there")
	}
	// A link in place of the drop-in directory is refused and nothing is
	// written where it points; so is a directory someone else owns.
	link := filepath.Join(units, "user-54322.slice.d")
	if os.Symlink(elsewhere, link) != nil {
		t.Fatal("fixture")
	}
	if _, e := n.writeLimits(dir, 54322, DefaultLimits); e == nil {
		t.Fatal("wrote through a link")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("a file appeared behind the link")
	}
	foreign := filepath.Join(units, "user-54323.slice.d")
	if os.Mkdir(foreign, 0755) != nil || os.Chown(foreign, 54323, 54323) != nil {
		t.Fatal("fixture")
	}
	if _, e := n.writeLimits(dir, 54323, DefaultLimits); e == nil {
		t.Fatal("wrote into a directory root does not own")
	}
}
