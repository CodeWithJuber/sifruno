package sites

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeleteFileServedBytesEmptyReopenAndRestore(t *testing.T) {
	s, journal, base := fixture(t)
	site := makeSite(t, s)
	index, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.WriteFile(site.ID, WriteInput{Path: "assets/style.css", Content: "body { color: teal }", ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	css, err := s.ReadFile(site.ID, "assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	before := site
	site, err = s.DeleteFile(site.ID, DeleteInput{Path: css.Path, ExpectedSHA256: css.SHA256, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil || site.Revision != before.Revision+1 || !site.UpdatedAt.After(before.UpdatedAt) {
		t.Fatal("delete did not commit one revision", site, err)
	}
	if w := served(s, site.PreviewHost, "/assets/style.css", "GET"); w.Code != 404 {
		t.Fatal("deleted file still served", w.Code)
	}
	if w := served(s, site.Domain, "/", "GET"); w.Code != 200 || w.Body.String() != index.Content {
		t.Fatal("delete changed another file", w.Code)
	}
	if _, err = s.ReadFile(site.ID, css.Path); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted file still readable", err)
	}
	site, err = s.DeleteFile(site.ID, DeleteInput{Path: index.Path, ExpectedSHA256: index.SHA256, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal("last file deletion", err)
	}
	if files, err := s.Files(site.ID); err != nil || files == nil || len(files) != 0 {
		t.Fatal("empty catalog", files, err)
	}
	if w := served(s, site.Domain, "/", "GET"); w.Code != 404 {
		t.Fatal("empty site not healthy 404", w.Code)
	}
	// Empty archives remain outside the existing native archive schema.
	if _, err = s.Backup(site.ID, site.Revision, "local-operator"); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty backup contract changed", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), journal)
	if err != nil {
		t.Fatal("empty site failed reopen", err)
	}
	defer again.Close()
	if persisted, err := again.Get(site.ID); err != nil || persisted != site {
		t.Fatal("empty site not persisted", persisted, err)
	}
	site, err = again.Restore(site.ID, RestoreInput{BackupID: backup.ID, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal("restore from empty site", err)
	}
	for _, row := range []struct{ path, content string }{{"/", index.Content}, {"/assets/style.css", css.Content}} {
		if w := served(again, site.PreviewHost, row.path, "GET"); w.Code != 200 || w.Body.String() != row.content {
			t.Fatal("backup bytes did not return", row.path, w.Code)
		}
	}
	if journal.Verify() != nil {
		t.Fatal("signed delete/restore history invalid")
	}
}

func TestDeleteFileRefusalsPreserveFile(t *testing.T) {
	s, journal, _ := fixture(t)
	site := makeSite(t, s)
	file, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	valid := DeleteInput{Path: file.Path, ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}
	for _, row := range []struct {
		name  string
		input DeleteInput
		actor string
		want  error
	}{
		{"stale revision", DeleteInput{Path: file.Path, ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision + 1}, "local-operator", ErrConflict},
		{"wrong hash", DeleteInput{Path: file.Path, ExpectedSHA256: strings.Repeat("0", 64), ExpectedRevision: site.Revision}, "local-operator", ErrConflict},
		{"missing file", DeleteInput{Path: "absent.txt", ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}, "local-operator", ErrNotFound},
		{"missing hash", DeleteInput{Path: file.Path, ExpectedRevision: site.Revision}, "local-operator", ErrInvalid},
		{"traversal", DeleteInput{Path: "../index.html", ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}, "local-operator", ErrInvalid},
		{"directory", DeleteInput{Path: "assets", ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}, "local-operator", ErrInvalid},
		{"wrong actor", valid, "root", ErrInvalid},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got, err := s.DeleteFile(site.ID, row.input, row.actor); got != (Site{}) || !errors.Is(err, row.want) {
				t.Fatal("refusal", got, err)
			}
		})
	}
	if got, err := s.ReadFile(site.ID, file.Path); err != nil || got != file {
		t.Fatal("refused delete changed file", got, err)
	}
	r, err := s.load(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.Pending = &pendingChange{Action: "interrupted", Checkpoints: []string{}}
	if err = s.save(r); err != nil {
		t.Fatal(err)
	}
	if got, err := s.DeleteFile(site.ID, valid, "local-operator"); got != (Site{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("recovery_required delete accepted", got, err)
	}
	if current, err := s.Get(site.ID); err != nil || current.State != "recovery_required" || current.Revision != site.Revision {
		t.Fatal("recovery marker changed", current, err)
	}
	if journal.Verify() != nil {
		t.Fatal("refused operations changed journal")
	}
}

func TestDeleteFileRefusesReplacedDirectoryAndSymlink(t *testing.T) {
	for _, kind := range []string{"directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, _, base := fixture(t)
			site := makeSite(t, s)
			file, err := s.ReadFile(site.ID, "index.html")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, "sites", "data", site.ID, "content", file.Path)
			if err = os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if kind == "directory" {
				err = os.Mkdir(path, 0700)
			} else {
				target := filepath.Join(base, "outside.txt")
				if err = os.WriteFile(target, []byte("outside bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, path)
				if err != nil {
					t.Skip("symlink creation unavailable on this test host")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := s.DeleteFile(site.ID, DeleteInput{Path: file.Path, ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}, "local-operator"); got != (Site{}) || err == nil {
				t.Fatal("nonregular file deletion accepted", got, err)
			}
			info, err := os.Lstat(path)
			if err != nil || (kind == "directory" && !info.IsDir()) || (kind == "symlink" && info.Mode()&os.ModeSymlink == 0) {
				t.Fatal("refusal removed nonregular entry", err)
			}
		})
	}
}
