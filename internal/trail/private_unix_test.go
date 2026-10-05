//go:build !windows

package trail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixStoreAndKeyHavePrivatePermissions(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "config.txt", "original")
	change := checkpoint(t, s, root, "config.txt")
	for _, path := range []string{s.dir, filepath.Join(s.dir, "key"), filepath.Join(s.dir, "events.jsonl"), filepath.Join(s.dir, "changes", change.ID+".enc")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatalf("private trail permissions on %s allow other identities", filepath.Base(path))
		}
	}
}
