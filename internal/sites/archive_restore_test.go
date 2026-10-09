package sites

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUploadedArchiveRestoreReadOnlyExactBytesAndReopen(t *testing.T) {
	s, j, base := fixture(t)
	site := makeSite(t, s)
	site = previewWrite(t, s, site, "index.html", "<h1>Archived</h1>")
	png := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0, 255, 128}
	var err error
	site, err = s.UploadFile(site.ID, UploadInput{Path: "pixel.png", Content: png, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := s.ExportBackup(site.ID, backup.ID)
	if err != nil {
		t.Fatal(err)
	}
	site, _ = s.Get(site.ID)
	site = previewWrite(t, s, site, "index.html", "current")
	site = previewWrite(t, s, site, "new.txt", "remove me")
	site, err = s.DeleteFile(site.ID, DeleteInput{Path: "pixel.png", ExpectedSHA256: sum(png), ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	schedule, err := s.SetBackupSchedule(site.ID, BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "daily", Enabled: &disabled}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	history, _ := s.Backups(site.ID)
	input := ArchiveRestoreInput{Archive: raw, ExpectedRevision: site.Revision, ExpectedArchiveSHA256: sum(raw)}
	before := previewDisk(t, base)
	preview, err := s.PreviewArchiveRestore(site.ID, input)
	if err != nil || preview.ArchiveSHA256 != sum(raw) || preview.CurrentRevision != site.Revision || preview.Counts != (RestorePreviewCounts{Added: 1, Modified: 1, Removed: 1}) {
		t.Fatalf("preview %+v %v", preview, err)
	}
	if !reflect.DeepEqual(before, previewDisk(t, base)) {
		t.Fatal("preview wrote content, state, schedule or signed trail")
	}
	for _, bad := range []ArchiveRestoreInput{{Archive: raw, ExpectedRevision: site.Revision - 1, ExpectedArchiveSHA256: sum(raw)}, {Archive: raw, ExpectedRevision: site.Revision, ExpectedArchiveSHA256: strings.Repeat("0", 64)}, {Archive: []byte("bad ZIP"), ExpectedRevision: site.Revision, ExpectedArchiveSHA256: sum([]byte("bad ZIP"))}} {
		if _, err := s.RestoreArchive(site.ID, bad, "local-operator"); err == nil {
			t.Fatal("invalid restore accepted")
		}
		if !reflect.DeepEqual(before, previewDisk(t, base)) {
			t.Fatal("refusal wrote state")
		}
	}
	restored, err := s.RestoreArchive(site.ID, input, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	identity := restored
	identity.Revision = site.Revision
	identity.UpdatedAt = site.UpdatedAt
	if !reflect.DeepEqual(identity, site) || restored.Revision != site.Revision+1 {
		t.Fatal("identity changed or incorrect revision")
	}
	gotSchedule, _ := s.BackupSchedule(site.ID)
	gotHistory, _ := s.Backups(site.ID)
	if !reflect.DeepEqual(&schedule, gotSchedule) || !reflect.DeepEqual(history, gotHistory) {
		t.Fatal("schedule/history changed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Join(base, "sites"), j)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for path, want := range map[string][]byte{"/index.html": []byte("<h1>Archived</h1>"), "/pixel.png": png} {
		got := served(reopened, site.Domain, path, "GET")
		if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), want) {
			t.Fatal("restored bytes not exact", path, got.Code)
		}
	}
	if served(reopened, site.PreviewHost, "/new.txt", "GET").Code != 404 {
		t.Fatal("newer file survived")
	}
}

func TestUploadedArchiveRestorePhysicalCollisionsRefuseBeforeChange(t *testing.T) {
	for _, tc := range []struct {
		name, current, target string
		folder                bool
	}{{"case", "Index.html", "index.html", false}, {"file-parent", "folder.html", "folder.html/index.html", false}, {"folder-file", "folder.html/child.txt", "folder.html", true}, {"empty-case", "Folder/child.txt", "folder/index.html", true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, base := fixture(t)
			site := makeSite(t, s)
			if tc.current != "Index.html" {
				site = previewWrite(t, s, site, tc.current, "current")
			} else {
				tc.current = "INDEX.txt"
				tc.target = "index.txt"
				site = previewWrite(t, s, site, tc.current, "current")
			}
			if tc.folder {
				f, _ := s.ReadFile(site.ID, tc.current)
				var err error
				site, err = s.DeleteFile(site.ID, DeleteInput{Path: tc.current, ExpectedSHA256: f.SHA256, ExpectedRevision: site.Revision}, "local-operator")
				if err != nil {
					t.Fatal(err)
				}
			}
			raw, err := buildArchive(record{Site: site}, strings.Repeat("a", 32), map[string][]byte{tc.target: []byte("replacement")})
			if err != nil {
				t.Fatal(err)
			}
			input := ArchiveRestoreInput{Archive: raw, ExpectedRevision: site.Revision, ExpectedArchiveSHA256: sum(raw)}
			before := previewDisk(t, base)
			if _, err = s.PreviewArchiveRestore(site.ID, input); err == nil {
				t.Fatal("collision preview admitted")
			}
			if _, err = s.RestoreArchive(site.ID, input, "local-operator"); err == nil {
				t.Fatal("collision restore admitted")
			}
			if !reflect.DeepEqual(before, previewDisk(t, base)) {
				t.Fatal("collision changed disk")
			}
		})
	}
}

func TestUploadedArchiveRestoreRetainedFolderBudget(t *testing.T) {
	s, _, base := fixture(t)
	site := makeSite(t, s)
	for i := 0; i < MaxFiles*9-1; i++ {
		if err := os.Mkdir(filepath.Join(base, "sites", "data", site.ID, "content", fmt.Sprintf("empty%d", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := buildArchive(record{Site: site}, strings.Repeat("b", 32), map[string][]byte{"new/index.html": []byte("new")})
	if err != nil {
		t.Fatal(err)
	}
	input := ArchiveRestoreInput{Archive: raw, ExpectedRevision: site.Revision, ExpectedArchiveSHA256: sum(raw)}
	before := previewDisk(t, base)
	if _, err = s.PreviewArchiveRestore(site.ID, input); !errors.Is(err, ErrInvalid) {
		t.Fatal("budget preview", err)
	}
	if _, err = s.RestoreArchive(site.ID, input, "local-operator"); !errors.Is(err, ErrInvalid) {
		t.Fatal("budget restore", err)
	}
	if !reflect.DeepEqual(before, previewDisk(t, base)) {
		t.Fatal("budget refusal wrote disk")
	}
}

func TestUploadedArchiveRestoreSourceIdentityAndDirectoryAliases(t *testing.T) {
	s, _, base := fixture(t)
	site := makeSite(t, s)
	source := site
	source.ID = strings.Repeat("f", 32)
	source.Revision = 99
	for _, bad := range []bool{true, false} {
		data := map[string][]byte{"Assets/one.txt": []byte("one"), "Assets/two.txt": []byte("two")}
		if bad {
			delete(data, "Assets/two.txt")
			data["assets/two.txt"] = []byte("two")
		}
		raw, err := buildArchive(record{Site: source}, strings.Repeat("e", 32), data)
		if err != nil {
			t.Fatal(err)
		}
		input := ArchiveRestoreInput{Archive: raw, ExpectedRevision: site.Revision, ExpectedArchiveSHA256: sum(raw)}
		before := previewDisk(t, base)
		p, err := s.PreviewArchiveRestore(site.ID, input)
		if !reflect.DeepEqual(before, previewDisk(t, base)) {
			t.Fatal("source preview mutated")
		}
		if bad {
			if err == nil {
				t.Fatal("new directory aliases admitted")
			}
			if _, err = s.RestoreArchive(site.ID, input, "local-operator"); err == nil {
				t.Fatal("alias restore admitted")
			}
			if !reflect.DeepEqual(before, previewDisk(t, base)) {
				t.Fatal("alias refusal mutated")
			}
			continue
		}
		if err != nil || p.BackupRevision != 99 || p.SiteID != site.ID {
			t.Fatal("independent source metadata", err)
		}
		got, err := s.RestoreArchive(site.ID, input, "local-operator")
		if err != nil || got.ID != site.ID || got.Domain != site.Domain {
			t.Fatal("source identity was applied", err)
		}
	}
}
