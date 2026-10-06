package sites

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Capture every actual fixture file (including the database and signed trail),
// rather than just checking the revision returned by Get.
func previewDisk(t *testing.T, base string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		result[rel] = sum(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func previewWrite(t *testing.T, s *Store, site Site, path, content string) Site {
	t.Helper()
	expected := ""
	if f, err := s.ReadFile(site.ID, path); err == nil {
		expected = f.SHA256
	} else if !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	next, err := s.WriteFile(site.ID, WriteInput{Path: path, Content: content, ExpectedSHA256: expected, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestRestorePreviewActualDiffReadOnlyAndReopen(t *testing.T) {
	s, j, base := fixture(t)
	site := makeSite(t, s)
	site = previewWrite(t, s, site, "unchanged.txt", "stable")
	a, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, _ = s.Get(site.ID)
	site = previewWrite(t, s, site, "Added.txt", "archive only")
	site = previewWrite(t, s, site, "index.html", "archived modified bytes")
	b, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, _ = s.Get(site.ID)
	site, err = s.Restore(site.ID, RestoreInput{a.ID, site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site = previewWrite(t, s, site, "removed.txt", "current only")
	enabled := false
	if _, err = s.SetBackupSchedule(site.ID, BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "daily", Enabled: &enabled}, "local-operator"); err != nil {
		t.Fatal(err)
	}
	before := previewDisk(t, base)
	input := RestoreInput{b.ID, site.Revision}
	p, err := s.PreviewRestore(site.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, previewDisk(t, base)) {
		t.Fatal("preview changed actual state, content, archive, schedule or journal")
	}
	if p.SiteID != site.ID || p.CurrentRevision != site.Revision || p.BackupID != b.ID || p.BackupSHA256 != b.SHA256 || p.BackupRevision != b.Revision || len(p.Files) != 4 || p.Counts != (RestorePreviewCounts{1, 1, 1, 1}) {
		t.Fatalf("wrong preview identity/counts: %+v", p)
	}
	paths := []string{"Added.txt", "index.html", "removed.txt", "unchanged.txt"}
	kinds := []string{"added", "modified", "removed", "unchanged"}
	for i, f := range p.Files {
		if f.Path != paths[i] || f.Kind != kinds[i] || (f.Before != nil && f.Before.Path != f.Path) || (f.After != nil && f.After.Path != f.Path) {
			t.Fatalf("wrong ordered diff entry %+v", f)
		}
	}
	if p.Files[0].Before != nil || p.Files[0].After == nil || p.Files[2].Before == nil || p.Files[2].After != nil || p.Files[3].Before.SHA256 != p.Files[3].After.SHA256 || p.Files[3].Before.Bytes != p.Files[3].After.Bytes {
		t.Fatal("wrong nullable before/after")
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "archived modified bytes") || strings.Contains(string(raw), base) || strings.Contains(string(raw), "content\"") {
		t.Fatal("preview leaked file contents or private paths")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), j)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := again.Close(); err != nil {
			t.Error("owned reopened preview store cleanup", err)
		}
	}()
	p2, err := again.PreviewRestore(site.ID, input)
	if err != nil || !reflect.DeepEqual(p, p2) {
		t.Fatal("preview changed after reopening", err)
	}
}

func TestRestorePreviewFailuresAreReadOnly(t *testing.T) {
	for _, mode := range []string{"stale", "missing-site", "missing-backup", "other-site", "invalid-site", "invalid-backup", "zero", "unsafe", "tamper", "sealed-tamper", "missing-content", "corrupt", "manifest", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			s, _, base := fixture(t)
			site := makeSite(t, s)
			b, err := s.Backup(site.ID, site.Revision, "local-operator")
			if err != nil {
				t.Fatal(err)
			}
			site, _ = s.Get(site.ID)
			id, input, want := site.ID, RestoreInput{b.ID, site.Revision}, ErrInvalid
			switch mode {
			case "stale":
				input.ExpectedRevision--
				want = ErrConflict
			case "missing-site":
				id = strings.Repeat("a", 32)
				want = ErrNotFound
			case "missing-backup":
				input.BackupID = strings.Repeat("b", 32)
				want = ErrNotFound
			case "other-site":
				other, e := s.Create(CreateInput{Name: "Other", Domain: "other.test"}, "local-operator")
				if e != nil {
					t.Fatal(e)
				}
				id = other.ID
				input.ExpectedRevision = other.Revision
				want = ErrNotFound
			case "invalid-site":
				id = "../site"
			case "invalid-backup":
				input.BackupID = strings.ToUpper(b.ID)
			case "zero":
				input.ExpectedRevision = 0
			case "unsafe":
				input.ExpectedRevision = 9007199254740992
			case "tamper":
				if os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "content", "index.html"), []byte("external edit"), 0600) != nil {
					t.Fatal("tamper fixture")
				}
				want = ErrConflict
			case "sealed-tamper":
				site = previewWrite(t, s, site, "index.html", "sealed current bytes")
				input.ExpectedRevision = site.Revision
				if os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "content", "index.html"), []byte("external edit after sealed write"), 0600) != nil {
					t.Fatal("sealed tamper fixture")
				}
				want = ErrUnavailable
			case "missing-content":
				if os.Remove(filepath.Join(base, "sites", "data", site.ID, "content", "index.html")) != nil {
					t.Fatal("remove fixture")
				}
				want = ErrConflict
			case "corrupt":
				if os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "backups", b.ID+".zip"), []byte("invalid zip"), 0600) != nil {
					t.Fatal("corrupt fixture")
				}
				want = ErrUnavailable
			case "manifest":
				r, e := s.load(site.ID)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := buildArchive(r, b.ID, map[string][]byte{"index.html": []byte("different revision manifest")})
				if e != nil {
					t.Fatal(e)
				}
				// Rehash the stored metadata to force manifest matching, rather
				// than stopping at the simpler raw checksum validation.
				next := r
				next.Backups = append([]BackupInfo{}, r.Backups...)
				next.Backups[0].Bytes = int64(len(raw))
				next.Backups[0].SHA256 = sum(raw)
				next.Site.Revision++
				if os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "backups", b.ID+".zip"), raw, 0600) != nil || s.change(r, next, nil, "backup", "local-operator") != nil {
					t.Fatal("manifest fixture")
				}
				input.ExpectedRevision = next.Site.Revision
				if _, e = s.checked(site.ID); e != nil {
					t.Fatal("manifest fixture must pass current integrity checks", e)
				}
				if _, e = parseArchive(raw, next.Backups[0]); !errors.Is(e, ErrInvalid) {
					t.Fatal("manifest fixture must fail native metadata match", e)
				}
				want = ErrUnavailable
			case "recovery":
				r, e := s.load(site.ID)
				if e != nil {
					t.Fatal(e)
				}
				r.Pending = &pendingChange{Action: "restore", Checkpoints: []string{}}
				if s.save(r) != nil {
					t.Fatal("recovery fixture")
				}
				want = ErrUnavailable
			}
			before := previewDisk(t, base)
			if _, err = s.PreviewRestore(id, input); !errors.Is(err, want) {
				t.Fatalf("want %v got %v", want, err)
			}
			if !reflect.DeepEqual(before, previewDisk(t, base)) {
				t.Fatal("failed preview mutated fixture")
			}
		})
	}
}

func TestRestorePreviewMaximumUnion(t *testing.T) {
	s, _, base := fixture(t)
	site := makeSite(t, s)
	replace := func(prefix string) {
		t.Helper()
		r, err := s.checked(site.ID)
		if err != nil {
			t.Fatal(err)
		}
		data := map[string][]byte{}
		for i := 0; i < MaxFiles; i++ {
			data[fmt.Sprintf("%s%02d.txt", prefix, i)] = []byte("verified actual bytes")
		}
		files, err := fileCatalog(data)
		if err != nil {
			t.Fatal(err)
		}
		next := r
		next.Files = files
		next.Site.Revision++
		if err = s.change(r, next, data, "write", "local-operator"); err != nil {
			t.Fatal(err)
		}
		site = next.Site
	}
	replace("A")
	b, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, _ = s.Get(site.ID)
	replace("z")
	before := previewDisk(t, base)
	p, err := s.PreviewRestore(site.ID, RestoreInput{b.ID, site.Revision})
	if err != nil || len(p.Files) != 128 || p.Counts != (RestorePreviewCounts{Added: 64, Removed: 64}) {
		t.Fatal("bounded 128 union", err, len(p.Files), p.Counts)
	}
	for i, f := range p.Files {
		if i > 0 && p.Files[i-1].Path >= f.Path {
			t.Fatal("union not ASCII sorted")
		}
	}
	if !reflect.DeepEqual(before, previewDisk(t, base)) {
		t.Fatal("max union preview mutated fixture")
	}
}

func TestRestorePreviewRefusesCrossSnapshotCaseAliases(t *testing.T) {
	s, _, base := fixture(t)
	site := makeSite(t, s)
	b, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	// Two real transitions keep each catalog and Windows filesystem valid,
	// while the union of current INDEX.html and archived index.html aliases.
	for _, path := range []string{"intermediate.txt", "INDEX.html"} {
		r, err := s.checked(site.ID)
		if err != nil {
			t.Fatal(err)
		}
		data := map[string][]byte{path: []byte("actual bytes")}
		files, err := fileCatalog(data)
		if err != nil {
			t.Fatal(err)
		}
		next := r
		next.Files = files
		next.Site.Revision++
		if err = s.change(r, next, data, "write", "local-operator"); err != nil {
			t.Fatal(err)
		}
		site = next.Site
	}
	before := previewDisk(t, base)
	if _, err = s.PreviewRestore(site.ID, RestoreInput{b.ID, site.Revision}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("ambiguous portable union accepted", err)
	}
	if !reflect.DeepEqual(before, previewDisk(t, base)) {
		t.Fatal("case alias refusal mutated state")
	}
}
