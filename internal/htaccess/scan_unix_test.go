//go:build unix

package htaccess

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestScanFIFOAndUnreadableFiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"fifo/index.html":     "x",
		"locked/.htaccess":    "RewriteEngine On\n",
		"lockeddir/sub/x.txt": "x",
	})
	if err := syscall.Mkfifo(filepath.Join(root, "fifo", ".htaccess"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo", "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	privileged := os.Geteuid() == 0
	if !privileged {
		if err := os.Chmod(filepath.Join(root, "locked", ".htaccess"), 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, "lockeddir", "sub"), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "lockeddir", "sub"), 0o755) })
	}
	r := scan(t, root, LayoutDir, DefaultLimits())
	causes := map[string][]string{}
	for _, s := range r.Sites {
		causes[s.Name] = s.Causes
	}
	want := map[string][]string{"fifo": {CauseIrregularFile}, "locked": nil, "lockeddir": nil}
	if !privileged {
		want["locked"] = []string{CauseUnreadableFile}
		want["lockeddir"] = []string{CauseUnreadableDir}
	}
	if !reflect.DeepEqual(causes, want) {
		t.Fatalf("causes %v, want %v", causes, want)
	}
}
