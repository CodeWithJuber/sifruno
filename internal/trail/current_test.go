package trail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyCurrentBindsSealedBytesAndAbsence(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "managed.json", "before")
	change, err := s.Checkpoint(root, []string{"managed.json", "absent.txt"}, "current image fixture", "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	if s.VerifyCurrent(change.ID) == nil {
		t.Fatal("unsealed checkpoint certified")
	}
	put(t, root, "managed.json", "after")
	if _, err = s.Seal(change.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifyCurrent(change.ID); err != nil {
		t.Fatal(err)
	}
	put(t, root, "managed.json", "tampered")
	if s.VerifyCurrent(change.ID) == nil {
		t.Fatal("changed bytes certified")
	}
	put(t, root, "managed.json", "after")
	put(t, root, "absent.txt", "unexpected")
	if s.VerifyCurrent(change.ID) == nil {
		t.Fatal("unexpected scoped file certified")
	}
	if err = os.Remove(filepath.Join(root, "absent.txt")); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifyCurrent(change.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Rollback(change.ID); err != nil {
		t.Fatal(err)
	}
	if s.VerifyCurrent(change.ID) == nil {
		t.Fatal("rolled-back checkpoint certified as applied")
	}
}
