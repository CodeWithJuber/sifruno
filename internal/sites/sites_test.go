package sites

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sifruno/internal/trail"
)

func fixture(t *testing.T) (*Store, *trail.Store, string) {
	t.Helper()
	base := t.TempDir()
	if runtime.GOOS != "windows" {
		var err error
		base, err = filepath.EvalSymlinks(base)
		if err != nil {
			t.Fatal(err)
		}
	}
	j, err := trail.Open(filepath.Join(base, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(base, "sites"), j)
	if err != nil {
		t.Fatal("fresh empty Open", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, j, base
}
func makeSite(t *testing.T, s *Store) Site {
	t.Helper()
	v, err := s.Create(CreateInput{Name: "Real local site", Domain: "example.test"}, "local-operator")
	if err != nil {
		t.Fatal("Create", err)
	}
	return v
}
func served(s *Store, host, p, method string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, p, nil)
	r.Host = host
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestFreshEmptyStoreAndRoundTripRestart(t *testing.T) {
	s, j, base := fixture(t)
	items, err := s.List()
	if err != nil || len(items) != 0 {
		t.Fatal("fresh list", err)
	}
	site := makeSite(t, s)
	files, err := s.Files(site.ID)
	if err != nil || len(files) != 1 || files[0].Path != "index.html" {
		t.Fatal("real seed files", err)
	}
	original, err := s.ReadFile(site.ID, "index.html")
	if err != nil || !strings.Contains(original.Content, "Real local site") {
		t.Fatal("real seed content", err)
	}
	for _, host := range []string{site.Domain, site.PreviewHost, site.PreviewHost + ":8082", site.PreviewHost + ":18082"} {
		w := served(s, host, "/", "GET")
		if w.Code != 200 || w.Body.String() != original.Content {
			t.Fatal("actual Host serving", host, w.Code)
		}
	}
	if served(s, "other.test", "/", "GET").Code != 404 || served(s, site.Domain, "/", "POST").Code != 405 {
		t.Fatal("Host/mutation guards")
	}
	updated, err := s.WriteFile(site.ID, WriteInput{Path: "index.html", Content: "<html>actual edited site</html>", ExpectedSHA256: original.SHA256, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil || updated.Revision != 2 {
		t.Fatal("write", err)
	}
	backup, err := s.Backup(site.ID, updated.Revision, "local-operator")
	if err != nil || backup.Files != 1 || backup.Bytes == 0 || len(backup.SHA256) != 64 {
		t.Fatal("backup", err)
	}
	updated, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	updated, err = s.WriteFile(site.ID, WriteInput{Path: "assets/style.css", Content: "body { color: teal }", ExpectedRevision: updated.Revision}, "local-operator")
	if err != nil {
		t.Fatal("new nested file", err)
	}
	current, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	updated, err = s.WriteFile(site.ID, WriteInput{Path: "index.html", Content: "<html>changed after backup</html>", ExpectedSHA256: current.SHA256, ExpectedRevision: updated.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	updated, err = s.Restore(site.ID, RestoreInput{BackupID: backup.ID, ExpectedRevision: updated.Revision}, "local-operator")
	if err != nil {
		t.Fatal("restore", err)
	}
	if _, err = s.ReadFile(site.ID, "assets/style.css"); !errors.Is(err, ErrNotFound) {
		t.Fatal("restore did not remove new file", err)
	}
	if w := served(s, site.PreviewHost, "/", "GET"); w.Code != 200 || w.Body.String() != "<html>actual edited site</html>" {
		t.Fatal("restored actual HTTP bytes", w.Code)
	}
	updated, err = s.SetState(site.ID, StateInput{State: "suspended", ExpectedRevision: updated.Revision}, "local-operator")
	if err != nil || served(s, site.Domain, "/", "GET").Code != 503 {
		t.Fatal("suspend", err)
	}
	updated, err = s.SetState(site.ID, StateInput{State: "active", ExpectedRevision: updated.Revision}, "local-operator")
	if err != nil {
		t.Fatal("resume", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), j)
	if err != nil {
		t.Fatal("restart", err)
	}
	defer again.Close()
	persisted, err := again.Get(site.ID)
	if err != nil || persisted != updated {
		t.Fatal("persisted site differs", err)
	}
	if w := served(again, site.Domain, "/", "GET"); w.Code != http.StatusOK || w.Body.String() != "<html>actual edited site</html>" {
		t.Fatal("restart serving", w.Code)
	}
	backups, err := again.Backups(site.ID)
	if err != nil || len(backups) != 1 || backups[0] != backup {
		t.Fatal("persisted real backup", err)
	}
	if j.Verify() != nil {
		t.Fatal("signed change history invalid")
	}
	stat, err := os.Stat(filepath.Join(base, "sites", "data", site.ID, "backups", backup.ID+".zip"))
	if err != nil || stat.Size() != backup.Bytes {
		t.Fatal("backup is not an actual ZIP file", err)
	}
}
