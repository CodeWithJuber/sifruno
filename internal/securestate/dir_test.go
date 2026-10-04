package securestate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateDirectoryAndUnrelatedDirectoryGuard(t *testing.T) {
	root := realTempDir(t)
	state := filepath.Join(root, "state")
	if _, e := Dir(state); e != nil {
		t.Fatal(e)
	}
	if _, e := Dir(state); e != nil {
		t.Fatal(e)
	}
	unrelated := filepath.Join(root, "unrelated")
	os.Mkdir(unrelated, 0700)
	os.WriteFile(filepath.Join(unrelated, "document"), []byte("keep"), 0600)
	if _, e := Dir(unrelated); e == nil {
		t.Fatal("hardened unrelated nonempty directory")
	}
	os.WriteFile(filepath.Join(state, ".sifruno-state"), []byte("invalid"), 0600)
	if _, e := Dir(state); e == nil {
		t.Fatal("invalid marker allowed")
	}
}
func TestRejectStateParentAndMarkerSymlink(t *testing.T) {
	root := realTempDir(t)
	outside := filepath.Join(root, "outside")
	os.Mkdir(outside, 0700)
	link := filepath.Join(root, "linked")
	if e := os.Symlink(outside, link); e != nil {
		t.Skip("OS identity cannot create symlinks:", e)
	}
	if _, e := Dir(filepath.Join(link, "state")); e == nil {
		t.Fatal("followed symlink parent")
	}
	state := filepath.Join(root, "state")
	os.Mkdir(state, 0700)
	marker := filepath.Join(state, ".sifruno-state")
	os.Symlink(filepath.Join(outside, "missing"), marker)
	if _, e := Dir(state); e == nil {
		t.Fatal("followed marker symlink")
	}
	if _, e := os.Stat(filepath.Join(outside, "missing")); !os.IsNotExist(e) {
		t.Fatal("wrote through rejected marker")
	}
}

func realTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		return dir
	}
	dir, e := filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	return dir
}
