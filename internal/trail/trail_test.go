package trail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T) (*Store, string) {
	t.Helper()
	// macOS temporary-directory aliases can contain system symlink ancestors.
	// Use their canonical target so the root rejection policy is still tested.
	base := t.TempDir()
	if runtime.GOOS == "darwin" {
		var err error
		base, err = filepath.EvalSymlinks(base)
		if err != nil {
			t.Fatalf("canonical temporary root: %v", err)
		}
	}
	root := filepath.Join(base, "scope")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(base, "private-trail"))
	if err != nil {
		t.Fatal(err)
	}
	return s, root
}
func put(t *testing.T, root, name, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func get(t *testing.T, root, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func checkpoint(t *testing.T, s *Store, root string, files ...string) Summary {
	t.Helper()
	change, err := s.Checkpoint(root, files, "reviewed config update", "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	return change
}

func TestRoundTripRestoresModificationDeletionAndNewFile(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "modified.txt", "original configuration")
	put(t, root, "deleted.txt", "restore this file")
	beforeInfo, err := os.Stat(filepath.Join(root, "modified.txt"))
	if err != nil {
		t.Fatal(err)
	}
	change := checkpoint(t, s, root, "modified.txt", "deleted.txt", "created.txt")
	put(t, root, "modified.txt", "updated configuration")
	if err := os.Remove(filepath.Join(root, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	put(t, root, "created.txt", "new data")
	sealed, err := s.Seal(change.ID)
	if err != nil || sealed.State != "applied" {
		t.Fatalf("seal: %v, %#v", err, sealed)
	}
	s, err = Open(s.dir) // Exercise persistence and decryption across opens.
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := s.Rollback(change.ID)
	if err != nil || rolled.State != "rolled_back" {
		t.Fatalf("rollback: %v, %#v", err, rolled)
	}
	if got := get(t, root, "modified.txt"); got != "original configuration" {
		t.Fatalf("modified content: %q", got)
	}
	if got := get(t, root, "deleted.txt"); got != "restore this file" {
		t.Fatalf("deleted content: %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "created.txt")); !os.IsNotExist(err) {
		t.Fatalf("created file retained: %v", err)
	}
	afterInfo, err := os.Stat(filepath.Join(root, "modified.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() {
		t.Fatalf("permissions changed: %v -> %v", beforeInfo.Mode(), afterInfo.Mode())
	}
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
	items, err := s.List()
	if err != nil || len(items) != 1 || items[0].Files != 3 || items[0].Actor != "local-operator" || items[0].Reason != "reviewed config update" {
		t.Fatalf("list: %#v, %v", items, err)
	}
	if _, err := s.Rollback(change.ID); err == nil {
		t.Fatal("repeated rollback accepted")
	}
}

func TestRollbackRestoresPermissionsIncludingReadonlyChanges(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "config.txt", "original")
	before, err := os.Stat(filepath.Join(root, "config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	change := checkpoint(t, s, root, "config.txt")
	put(t, root, "config.txt", "updated")
	if err := os.Chmod(filepath.Join(root, "config.txt"), 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal(change.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(change.ID); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(root, "config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() || get(t, root, "config.txt") != "original" {
		t.Fatal("rollback did not restore content and permissions")
	}
}

func TestEncryptionKeepsFileContentAndMetadataOutOfPlaintextJournal(t *testing.T) {
	s, root := fixture(t)
	content := "distinctive private checkpoint body 63c7ee81"
	reason := "private operator reason e591ded9"
	actor := "private-actor-724c22be"
	put(t, root, "config.txt", content)
	change, err := s.Checkpoint(root, []string{"config.txt"}, reason, actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(s.dir, "events.jsonl"), filepath.Join(s.dir, "changes", change.ID+".enc")} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, sensitive := range []string{content, reason, actor, root} {
			if bytes.Contains(b, []byte(sensitive)) {
				t.Fatalf("private checkpoint field appeared in %s", filepath.Base(path))
			}
		}
	}
}

func TestConflictPreflightWritesNothing(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "first.txt", "before first")
	put(t, root, "second.txt", "before second")
	change := checkpoint(t, s, root, "first.txt", "second.txt")
	put(t, root, "first.txt", "after first")
	put(t, root, "second.txt", "after second")
	if _, err := s.Seal(change.ID); err != nil {
		t.Fatal(err)
	}
	journalBefore, err := os.ReadFile(filepath.Join(s.dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	put(t, root, "second.txt", "a later edit")
	if _, err := s.Rollback(change.ID); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected conflict: %v", err)
	}
	if get(t, root, "first.txt") != "after first" || get(t, root, "second.txt") != "a later edit" {
		t.Fatal("conflict caused partial rollback")
	}
	journalAfter, err := os.ReadFile(filepath.Join(s.dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(journalBefore, journalAfter) {
		t.Fatal("conflict appended a recovery event")
	}
}

func TestResumesCommittedPartialRecovery(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "first.txt", "before first")
	put(t, root, "second.txt", "before second")
	change := checkpoint(t, s, root, "first.txt", "second.txt")
	put(t, root, "first.txt", "after first")
	put(t, root, "second.txt", "after second")
	if _, err := s.Seal(change.ID); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after recovery was journaled and only one file restored.
	if err := s.acquire(); err != nil {
		t.Fatal(err)
	}
	c, err := s.read(change.ID)
	if err != nil {
		s.release()
		t.Fatal(err)
	}
	c.State = "recovering"
	err = s.persist(c)
	s.release()
	if err != nil {
		t.Fatal(err)
	}
	put(t, root, "first.txt", "before first")
	s, err = Open(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(change.ID); err != nil {
		t.Fatal(err)
	}
	if get(t, root, "first.txt") != "before first" || get(t, root, "second.txt") != "before second" {
		t.Fatal("partial recovery was not completed")
	}
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
}

func assertFailClosed(t *testing.T, s *Store, root, changeID string) {
	t.Helper()
	if err := s.Verify(); err == nil {
		t.Fatal("damaged journal verified")
	}
	if _, err := s.List(); err == nil {
		t.Fatal("damaged journal listed")
	}
	if _, err := s.Checkpoint(root, []string{"config.txt"}, "another update", "operator"); err == nil {
		t.Fatal("damaged journal accepted checkpoint")
	}
	if _, err := s.Seal(changeID); err == nil {
		t.Fatal("damaged journal accepted seal")
	}
	if _, err := s.Rollback(changeID); err == nil {
		t.Fatal("damaged journal accepted rollback")
	}
	if _, err := Open(s.dir); err == nil {
		t.Fatal("damaged journal reopened")
	}
	if get(t, root, "config.txt") != "original" {
		t.Fatal("failed verification changed scoped content")
	}
}

func TestTamperAndCrashStatesFailClosed(t *testing.T) {
	for _, scenario := range []string{"ciphertext", "truncated-ciphertext", "journal-signature", "partial-journal-write", "missing-manifest", "orphan-manifest", "manifest-before-event", "missing-key", "changed-key"} {
		t.Run(scenario, func(t *testing.T) {
			s, root := fixture(t)
			put(t, root, "config.txt", "original")
			change := checkpoint(t, s, root, "config.txt")
			manifest := filepath.Join(s.dir, "changes", change.ID+".enc")
			journal := filepath.Join(s.dir, "events.jsonl")
			switch scenario {
			case "ciphertext", "truncated-ciphertext":
				b, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "ciphertext" {
					b[len(b)-1] ^= 1
				} else {
					b = b[:5]
				}
				if err = os.WriteFile(manifest, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "journal-signature":
				b, err := os.ReadFile(journal)
				if err != nil {
					t.Fatal(err)
				}
				var ev event
				if err = json.Unmarshal(bytes.TrimSpace(b), &ev); err != nil {
					t.Fatal(err)
				}
				ev.ManifestHash = strings.Repeat("0", 64)
				b, _ = json.Marshal(ev)
				if err = os.WriteFile(journal, append(b, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "partial-journal-write":
				f, err := os.OpenFile(journal, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("{\"change_id\":")
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "missing-manifest":
				if err := os.Remove(manifest); err != nil {
					t.Fatal(err)
				}
			case "orphan-manifest":
				b, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(s.dir, "changes", strings.Repeat("1", 32)+".enc"), b, 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest-before-event":
				c, err := s.read(change.ID)
				if err != nil {
					t.Fatal(err)
				}
				c.Reason = "an interrupted update"
				b, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				b, err = s.seal(b)
				if err != nil {
					t.Fatal(err)
				}
				if err = writeAtomic(manifest, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if err := os.Remove(filepath.Join(s.dir, "key")); err != nil {
					t.Fatal(err)
				}
			case "changed-key":
				if err := os.WriteFile(filepath.Join(s.dir, "key"), bytes.Repeat([]byte{9}, 32), 0600); err != nil {
					t.Fatal(err)
				}
			}
			assertFailClosed(t, s, root, change.ID)
		})
	}
}

func TestRejectedScopeAndSecretMetadataLeaveNoCheckpoints(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "config.txt", "original")
	for _, p := range []string{"../config.txt", "a/../config.txt", "a\\..\\config.txt", filepath.Join(root, "config.txt"), ".env", ".git/config", "node_modules/code.js", "credentials/item", "secret.pem", "secret.key", "secret.p12", "id_ed25519", "kubeconfig", "missing-parent/file.txt", ".", "config.txt:stream"} {
		if _, err := s.Checkpoint(root, []string{p}, "scope rejection check", "operator"); err == nil {
			t.Fatalf("unsafe scope accepted: %q", p)
		}
	}
	for _, reason := range []string{"", "Bearer example-denied", "password=example-denied", "api_key:example-denied", strings.Repeat("x", 501)} {
		if _, err := s.Checkpoint(root, []string{"config.txt"}, reason, "operator"); err == nil {
			t.Fatal("unsafe metadata accepted")
		}
	}
	if _, err := s.Checkpoint(root, []string{"config.txt", "./config.txt"}, "duplicate check", "operator"); err == nil {
		t.Fatal("duplicate scope accepted")
	}
	if runtime.GOOS == "windows" {
		if _, err := s.Checkpoint(root, []string{"config.txt", "CONFIG.TXT"}, "case duplicate check", "operator"); err == nil {
			t.Fatal("case duplicate scope accepted on Windows")
		}
	}
	if _, err := s.Checkpoint(root, nil, "empty check", "operator"); err == nil {
		t.Fatal("empty scope accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "oversize.txt"), make([]byte, maxFile+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkpoint(root, []string{"oversize.txt"}, "oversize check", "operator"); err == nil {
		t.Fatal("oversize file accepted")
	}
	if _, err := s.Checkpoint(root, []string{"."}, "directory check", "operator"); err == nil {
		t.Fatal("directory accepted")
	}
	items, err := s.List()
	if err != nil || len(items) != 0 {
		t.Fatalf("rejected scope changed journal: %#v, %v", items, err)
	}
}

func TestSymlinkFilesParentsAndRootsAreRejected(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "config.txt", "original")
	link := filepath.Join(root, "linked.txt")
	if err := os.Symlink("config.txt", link); err != nil {
		t.Skipf("host cannot create test symlinks: %v", err)
	}
	if _, err := s.Checkpoint(root, []string{"linked.txt"}, "symlink check", "operator"); err == nil {
		t.Fatal("file symlink accepted")
	}
	if err := os.Symlink(root, filepath.Join(filepath.Dir(root), "root-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkpoint(filepath.Join(filepath.Dir(root), "root-link"), []string{"config.txt"}, "root symlink check", "operator"); err == nil {
		t.Fatal("symlink root accepted")
	}
	if _, err := Open(filepath.Join(filepath.Dir(root), "root-link", "store")); err == nil {
		t.Fatal("store through symlink accepted")
	}
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	put(t, root, "nested/config.txt", "nested")
	if err := os.Symlink("nested", filepath.Join(root, "parent-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkpoint(root, []string{"parent-link/config.txt"}, "parent symlink check", "operator"); err == nil {
		t.Fatal("symlink parent accepted")
	}
	change := checkpoint(t, s, root, "config.txt")
	if _, err := s.Seal(change.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "config.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested/config.txt", filepath.Join(root, "config.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(change.ID); err == nil {
		t.Fatal("rollback through symlink accepted")
	}
	if get(t, root, "nested/config.txt") != "nested" {
		t.Fatal("rollback followed replacement symlink")
	}
}

func TestConcurrentClientsSerializeAndPreserveEventChain(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "config.txt", "original")
	second, err := Open(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 24)
	for n := 0; n < 24; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			client := s
			if n%3 == 0 {
				client = second
			}
			_, err := client.Checkpoint(root, []string{"config.txt"}, "parallel checkpoint", fmt.Sprintf("operator-%d", n))
			if err == nil {
				err = client.Verify()
			}
			if err == nil {
				_, err = client.List()
			}
			errors <- err
		}(n)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.List()
	if err != nil || len(items) != 24 {
		t.Fatalf("serialized checkpoints: %d, %v", len(items), err)
	}
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestCrossProcessSerialization(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "config.txt", "original")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 3)
	for n := 0; n < 3; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^TestTrailProcessWorker$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "SIFRUNO_TRAIL_TEST_STORE="+s.dir, "SIFRUNO_TRAIL_TEST_ROOT="+root)
			b, err := cmd.CombinedOutput()
			if err != nil {
				err = fmt.Errorf("child checkpoint process: %w: %s", err, b)
			}
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.List()
	if err != nil || len(items) != 15 {
		t.Fatalf("cross-process checkpoints: %d, %v", len(items), err)
	}
}
func TestTrailProcessWorker(t *testing.T) {
	dir := os.Getenv("SIFRUNO_TRAIL_TEST_STORE")
	if dir == "" {
		t.Skip("worker invoked only by cross-process test")
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 5; n++ {
		checkpoint(t, s, os.Getenv("SIFRUNO_TRAIL_TEST_ROOT"), "config.txt")
	}
}

func TestValidationRejectsCorruptDecryptedStructure(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "config.txt", "original")
	change := checkpoint(t, s, root, "config.txt")
	c, err := s.read(change.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Change){
		func(c *Change) { c.State = "applied" },
		func(c *Change) { c.Before[0].Path = "../escape" },
		func(c *Change) { c.Before[0].Data = []byte("corrupt") },
		func(c *Change) { c.Before[0].Mode = 0xffffffff },
		func(c *Change) { c.State = "unknown" },
	} {
		b, _ := json.Marshal(c)
		var broken Change
		if err := json.Unmarshal(b, &broken); err != nil {
			t.Fatal(err)
		}
		mutate(&broken)
		if err := validateChange(broken); err == nil {
			t.Fatal("invalid decrypted structure accepted")
		}
	}
}
