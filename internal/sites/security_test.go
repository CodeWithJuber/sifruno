package sites

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestConflictPreflightAndManagedConcurrentCAS(t *testing.T) {
	s, _, _ := fixture(t)
	site := makeSite(t, s)
	file, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []WriteInput{{Path: "index.html", Content: "wrong revision", ExpectedSHA256: file.SHA256, ExpectedRevision: 99}, {Path: "index.html", Content: "wrong hash", ExpectedSHA256: strings.Repeat("0", 64), ExpectedRevision: site.Revision}, {Path: "new.txt", Content: "new", ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}} {
		if _, err = s.WriteFile(site.ID, input, "local-operator"); !errors.Is(err, ErrConflict) {
			t.Fatal("CAS accepted stale inputs", err)
		}
	}
	unchanged, err := s.ReadFile(site.ID, "index.html")
	if err != nil || unchanged != file {
		t.Fatal("conflict changed real files", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, conflict := 0, 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.WriteFile(site.ID, WriteInput{Path: "index.html", Content: "one concurrent winner", ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}, "local-operator")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				success++
			} else if errors.Is(err, ErrConflict) {
				conflict++
			} else {
				t.Errorf("unexpected managed race result: %v", err)
			}
		}()
	}
	wg.Wait()
	if success != 1 || conflict != 11 {
		t.Fatal("managed changes were not serialized", success, conflict)
	}
	current, err := s.Get(site.ID)
	if err != nil || current.Revision != 2 {
		t.Fatal("race committed more than one revision", err)
	}
}

func TestPrivatePathsDomainAndLimits(t *testing.T) {
	s, _, _ := fixture(t)
	site := makeSite(t, s)
	for _, p := range []string{"../escape.html", "/escape.html", "a\\escape.html", "a/../escape.html", ".env", ".git/config.txt", "credentials.txt", "id_rsa.txt", "C:/escape.html", "index.php", "source.go", "config.json", "con.txt", "nested/NUL.txt", "trailing./file.txt", "file.txt:stream", "index.html/child.txt"} {
		if _, err := s.WriteFile(site.ID, WriteInput{Path: p, Content: "blocked", ExpectedRevision: site.Revision}, "local-operator"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe path %q accepted: %v", p, err)
		}
		if w := served(s, site.PreviewHost, "/"+p, "GET"); w.Code == 200 {
			t.Fatal("unsafe path served", p)
		}
	}
	if _, err := s.WriteFile(site.ID, WriteInput{Path: "large.txt", Content: strings.Repeat("x", MaxFileBytes+1), ExpectedRevision: site.Revision}, "local-operator"); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized edit accepted", err)
	}
	for _, d := range []string{"http://example.test", "example.test/path", "user@example.test", "*.example.test", "127.0.0.1", "localhost", "site-other.localhost", "bad_domain.test", "example.test.", " example.test"} {
		if _, err := s.Create(CreateInput{Name: "invalid", Domain: d}, "local-operator"); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid domain accepted", d, err)
		}
	}
	if _, err := s.Create(CreateInput{Name: "duplicate", Domain: "EXAMPLE.TEST"}, "local-operator"); !errors.Is(err, ErrConflict) {
		t.Fatal("canonical duplicate domain accepted", err)
	}
	idn, err := s.Create(CreateInput{Name: "Unicode domain", Domain: "bücher.test"}, "local-operator")
	if err != nil || idn.Domain != "xn--bcher-kva.test" {
		t.Fatal("official IDNA normalization failed", err)
	}
	if _, err = s.Create(CreateInput{Name: "wrong actor", Domain: "different.test"}, "root"); !errors.Is(err, ErrInvalid) {
		t.Fatal("OS identity falsely accepted as account owner", err)
	}
	current, err := s.Get(site.ID)
	if err != nil || current.Revision != site.Revision {
		t.Fatal("validation changed persisted revision", err)
	}
	data := map[string][]byte{}
	for i := 0; i < MaxFiles; i++ {
		data[strings.Repeat("a", i+1)+".txt"] = []byte{}
	}
	if _, err = fileCatalog(data); err != nil {
		t.Fatal("64 bounded files rejected", err)
	}
	data["extra.txt"] = []byte{}
	if _, err = fileCatalog(data); !errors.Is(err, ErrInvalid) {
		t.Fatal("file count not bounded")
	}
	data = map[string][]byte{"a.txt": []byte("a"), "A.txt": []byte("b")}
	if _, err = fileCatalog(data); !errors.Is(err, ErrInvalid) {
		t.Fatal("portable case alias collision accepted")
	}
}

func TestActualHTTPHostRoutingAndNoRawPrivateFiles(t *testing.T) {
	s, _, base := fixture(t)
	site := makeSite(t, s)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	request, err := http.NewRequest("GET", server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = site.PreviewHost
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || !bytes.Contains(data, []byte("Real local site")) {
		t.Fatal("actual socket Host route failed", err)
	}
	if err = os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "content", "secret.php"), []byte("private php source"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/secret.php", "/state.json", "/backups/private.zip", "/%2eenv", "/assets/../state.json"} {
		w := served(s, site.PreviewHost, p, "GET")
		if w.Code == 200 || strings.Contains(w.Body.String(), "private php source") {
			t.Fatal("private/source file disclosed", p, w.Code)
		}
	}
}

func TestHardlinkAndSymlinkFailClosed(t *testing.T) {
	t.Run("hardlink", func(t *testing.T) {
		s, _, base := fixture(t)
		site := makeSite(t, s)
		target := filepath.Join(base, "sites", "data", site.ID, "content", "index.html")
		if err := os.Link(target, filepath.Join(base, "outside-copy.txt")); err != nil {
			t.Fatal("actual hardlink fixture", err)
		}
		if w := served(s, site.PreviewHost, "/", "GET"); w.Code != 503 {
			t.Fatal("hardlinked content served", w.Code)
		}
		if _, err := s.ReadFile(site.ID, "index.html"); !errors.Is(err, ErrUnavailable) {
			t.Fatal("hardlinked content read", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		s, _, base := fixture(t)
		site := makeSite(t, s)
		outside := filepath.Join(base, "outside.txt")
		if err := os.WriteFile(outside, []byte("outside secret"), 0600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(base, "sites", "data", site.ID, "content", "index.html")
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, target); err != nil {
			t.Skip("native symlink creation unavailable", err)
		}
		if w := served(s, site.PreviewHost, "/", "GET"); w.Code != 503 || strings.Contains(w.Body.String(), "outside secret") {
			t.Fatal("symlink escaped or served", w.Code)
		}
	})
}

func TestSignedStateAndDatabaseCorruption(t *testing.T) {
	t.Run("coordinated metadata change", func(t *testing.T) {
		s, _, base := fixture(t)
		site := makeSite(t, s)
		r, err := s.load(site.ID)
		if err != nil {
			t.Fatal(err)
		}
		r.Site.Name = "forged metadata"
		if err = s.save(r); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(r)
		if err = os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "state.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Get(site.ID); !errors.Is(err, ErrUnavailable) {
			t.Fatal("metadata changed outside signed trail accepted", err)
		}
		if served(s, site.PreviewHost, "/", "GET").Code != 503 {
			t.Fatal("tampered state served")
		}
	})
	t.Run("invalid record", func(t *testing.T) {
		s, j, base := fixture(t)
		site := makeSite(t, s)
		if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put([]byte(site.ID), []byte("{}")) }); err != nil {
			t.Fatal(err)
		}
		if _, err := s.List(); !errors.Is(err, ErrUnavailable) {
			t.Fatal("corrupt DB record accepted", err)
		}
		s.Close()
		if again, err := Open(filepath.Join(base, "sites"), j); err == nil {
			again.Close()
			t.Fatal("corrupt persisted record reopened")
		}
	})
	t.Run("invalid bbolt file", func(t *testing.T) {
		s, j, base := fixture(t)
		s.Close()
		if err := os.WriteFile(filepath.Join(base, "sites", "sites.db"), make([]byte, 4096), 0600); err != nil {
			t.Fatal(err)
		}
		if again, err := Open(filepath.Join(base, "sites"), j); err == nil {
			again.Close()
			t.Fatal("corrupt actual database accepted")
		}
	})
}

func TestInterruptedOperationPersistsRecoveryRequired(t *testing.T) {
	s, j, base := fixture(t)
	site := makeSite(t, s)
	r, err := s.load(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := j.Checkpoint(filepath.Join(base, "sites", "data", site.ID), []string{"state.json", "content/index.html"}, "interruption test", "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	r.Pending = &pendingChange{Action: "write", Checkpoints: []string{cp.ID}}
	if s.save(r) != nil {
		t.Fatal("persist interruption marker")
	}
	s.Close()
	again, err := Open(filepath.Join(base, "sites"), j)
	if err != nil {
		t.Fatal("reopen recovery marker", err)
	}
	defer again.Close()
	current, err := again.Get(site.ID)
	if err != nil || current.State != "recovery_required" {
		t.Fatal("interruption falsely active", err)
	}
	if served(again, site.PreviewHost, "/", "GET").Code != 503 {
		t.Fatal("interrupted website served")
	}
	if _, err = again.WriteFile(site.ID, WriteInput{Path: "new.txt", Content: "x", ExpectedRevision: site.Revision}, "local-operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("interrupted mutation accepted", err)
	}
	list, err := again.List()
	if err != nil || len(list) != 1 || list[0].State != "recovery_required" {
		t.Fatal("recovery status hidden", err)
	}
}

func TestCorruptBackupPreflightNoPartialRestore(t *testing.T) {
	s, _, base := fixture(t)
	site := makeSite(t, s)
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	file, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.WriteFile(site.ID, WriteInput{Path: "index.html", Content: "must remain unchanged", ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(base, "sites", "data", site.ID, "backups", backup.ID+".zip")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err = os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Restore(site.ID, RestoreInput{BackupID: backup.ID, ExpectedRevision: site.Revision}, "local-operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("corrupt ZIP restored", err)
	}
	after, err := s.ReadFile(site.ID, "index.html")
	if err != nil || before != after {
		t.Fatal("corrupt ZIP partially changed files", err)
	}
	current, err := s.Get(site.ID)
	if err != nil || current.Revision != site.Revision {
		t.Fatal("failed restore changed revision", err)
	}
}

func TestArchiveRejectsTraversalDuplicateLinksAndBombs(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		mode       os.FileMode
		content    []byte
	}{{"traversal", "files/../escape.html", 0600, []byte("x")}, {"absolute", "/absolute.html", 0600, []byte("x")}, {"backslash", "files/a\\escape.html", 0600, []byte("x")}, {"source", "files/source.php", 0600, []byte("x")}, {"link", "files/index.html", os.ModeSymlink | 0777, []byte("../outside")}, {"bomb", "files/index.html", 0600, bytes.Repeat([]byte("x"), MaxFileBytes+1)}} {
		t.Run(tc.name, func(t *testing.T) {
			var raw bytes.Buffer
			writer := zip.NewWriter(&raw)
			m, _ := writer.Create("manifest.json")
			m.Write([]byte(`{}`))
			header := &zip.FileHeader{Name: tc.path, Method: zip.Deflate}
			header.SetMode(tc.mode)
			f, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			f.Write(tc.content)
			writer.Close()
			info := BackupInfo{Bytes: int64(raw.Len()), SHA256: sum(raw.Bytes()), Files: 1}
			if _, err = parseArchive(raw.Bytes(), info); err == nil {
				t.Fatal("unsafe ZIP accepted")
			}
		})
	}
	var raw bytes.Buffer
	writer := zip.NewWriter(&raw)
	for _, name := range []string{"manifest.json", "files/index.html", "files/INDEX.html"} {
		f, _ := writer.Create(name)
		f.Write([]byte("x"))
	}
	writer.Close()
	if _, err := parseArchive(raw.Bytes(), BackupInfo{Bytes: int64(raw.Len()), SHA256: sum(raw.Bytes()), Files: 2}); err == nil {
		t.Fatal("case duplicate ZIP accepted")
	}
}

func TestIndependentStoreLockAndBackupCount(t *testing.T) {
	s, j, base := fixture(t)
	if other, err := Open(filepath.Join(base, "sites"), j); err == nil {
		other.Close()
		t.Fatal("two writers opened same bbolt database")
	}
	site := makeSite(t, s)
	for i := 0; i < MaxBackups; i++ {
		if _, err := s.Backup(site.ID, site.Revision, "local-operator"); err != nil {
			t.Fatal("bounded backup", i, err)
		}
		var err error
		site, err = s.Get(site.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Backup(site.ID, site.Revision, "local-operator"); !errors.Is(err, ErrInvalid) {
		t.Fatal("backup count unbounded", err)
	}
	backups, err := s.Backups(site.ID)
	if err != nil || len(backups) != MaxBackups {
		t.Fatal("backups not actual persisted inventory", err)
	}
}
