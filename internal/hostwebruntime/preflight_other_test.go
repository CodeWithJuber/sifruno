//go:build !linux

package hostwebruntime

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallationUnsupportedDoesNotChangeTemporaryTree(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	// A Windows absolute path is intentionally not a Linux installation profile.
	invalid := CheckInstallation(context.Background(), dir, 42)
	if runtime.GOOS == "windows" && (invalid.Ready || invalid.Status != "invalid") {
		t.Fatal("Windows path admitted")
	}
	out := CheckInstallation(context.Background(), "/unconfigured/private/runtime", 42)
	if out.Ready || out.Status != "unavailable" || len(out.Checks) != 2 || out.Checks[1].Name != "native_linux" || out.Checks[1].Passed {
		t.Fatal("unsupported platform not explicit")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary tree changed")
	}
	b, err := os.ReadFile(sentinel)
	if err != nil || string(b) != "unchanged" {
		t.Fatal("sentinel changed")
	}
}
