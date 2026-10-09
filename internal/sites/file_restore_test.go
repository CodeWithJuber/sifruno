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

func TestFileRestoreSelectedBytesPreservationAndReopen(t *testing.T) {
	s, j, base := fixture(t)
	site := makeSite(t, s)
	site = previewWrite(t, s, site, "index.html", "archived page")
	site = previewWrite(t, s, site, "other.txt", "archived other")
	png := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0, 255, 128}
	site, err := s.UploadFile(site.ID, UploadInput{Path: "pixel.png", Content: png, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, _ = s.Get(site.ID)
	site = previewWrite(t, s, site, "index.html", "current page")
	site = previewWrite(t, s, site, "other.txt", "current other")
	site = previewWrite(t, s, site, "new.txt", "keep new")
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
	for _, path := range []string{"index.html", "pixel.png"} {
		input := FileRestoreInput{backup.ID, backup.SHA256, site.Revision, path}
		before := previewDisk(t, base)
		p, err := s.PreviewFileRestore(site.ID, input)
		if err != nil || p.File.Path != path || p.File.After == nil || p.PreservedFiles != lenMustFiles(t, s, site.ID)-boolInt(p.File.Before != nil) {
			t.Fatalf("preview %+v %v", p, err)
		}
		if path == "index.html" && p.File.Kind != "modified" || path == "pixel.png" && (p.File.Kind != "added" || p.File.Before != nil) {
			t.Fatal("wrong one-file preview", p)
		}
		if !reflect.DeepEqual(before, previewDisk(t, base)) {
			t.Fatal("preview mutated disk")
		}
		if _, err = s.RestoreFile(site.ID, ConfirmFileRestoreInput{input, false}, "local-operator"); !errors.Is(err, ErrInvalid) {
			t.Fatal("missing confirmation accepted", err)
		}
		if !reflect.DeepEqual(before, previewDisk(t, base)) {
			t.Fatal("unconfirmed restore mutated disk")
		}
		next, err := s.RestoreFile(site.ID, ConfirmFileRestoreInput{input, true}, "local-operator")
		if err != nil {
			t.Fatal(err)
		}
		identity := next
		identity.Revision = site.Revision
		identity.UpdatedAt = site.UpdatedAt
		if !reflect.DeepEqual(identity, site) || next.Revision != site.Revision+1 {
			t.Fatal("identity/revision changed unexpectedly")
		}
		site = next
		if path == "index.html" && served(s, site.Domain, "/pixel.png", "GET").Code != 404 {
			t.Fatal("unselected archived file restored")
		}
		for path, want := range map[string]string{"other.txt": "current other", "new.txt": "keep new"} {
			got := served(s, site.Domain, "/"+path, "GET")
			if got.Code != 200 || got.Body.String() != want {
				t.Fatal("unrelated bytes changed", path)
			}
		}
	}
	gotSchedule, _ := s.BackupSchedule(site.ID)
	gotHistory, _ := s.Backups(site.ID)
	if !reflect.DeepEqual(&schedule, gotSchedule) || !reflect.DeepEqual(history, gotHistory) {
		t.Fatal("schedule or history changed")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Join(base, "sites"), j)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for path, want := range map[string][]byte{"index.html": []byte("archived page"), "pixel.png": png, "other.txt": []byte("current other"), "new.txt": []byte("keep new")} {
		got := served(reopened, site.Domain, "/"+path, "GET")
		if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), want) {
			t.Fatal("reopen bytes", path)
		}
	}
}

func TestFileRestoreRefusalsDoNotWrite(t *testing.T) {
	for _, mode := range []string{"stale", "hash", "missing", "foreign", "path", "alias", "corrupt", "tamper", "physical-folder", "case-folder", "count", "bytes", "nodes"} {
		t.Run(mode, func(t *testing.T) {
			s, _, base := fixture(t)
			site := makeSite(t, s)
			path := "saved.txt"
			if mode == "physical-folder" {
				path = "folder.html"
			}
			if mode == "case-folder" {
				path = "assets/saved.txt"
			}
			if mode == "nodes" {
				path = "new/saved.txt"
			}
			site = previewWrite(t, s, site, path, "archived")
			backup, err := s.Backup(site.ID, site.Revision, "local-operator")
			if err != nil {
				t.Fatal(err)
			}
			site, _ = s.Get(site.ID)
			f, _ := s.ReadFile(site.ID, path)
			site, err = s.DeleteFile(site.ID, DeleteInput{Path: path, ExpectedSHA256: f.SHA256, ExpectedRevision: site.Revision}, "local-operator")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "alias" {
				site = previewWrite(t, s, site, "SAVED.txt", "current")
			}
			if mode == "physical-folder" {
				if err = os.Mkdir(filepath.Join(base, "sites", "data", site.ID, "content", path), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "case-folder" { // remove the empty exact directory before introducing its physical alias
				if err = os.Remove(filepath.Join(base, "sites", "data", site.ID, "content", "assets")); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(filepath.Join(base, "sites", "data", site.ID, "content", "Assets"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "count" {
				for i := 1; i < MaxFiles; i++ {
					site = previewWrite(t, s, site, fmt.Sprintf("f%d.txt", i), "x")
				}
			}
			if mode == "bytes" { // use the ordinary change path with a valid full catalog at the site limit
				r, e := s.checked(site.ID)
				if e != nil {
					t.Fatal(e)
				}
				data := map[string][]byte{}
				for i := 0; i < MaxSiteBytes/MaxFileBytes; i++ {
					data[fmt.Sprintf("f%d.txt", i)] = bytes.Repeat([]byte("x"), MaxFileBytes)
				}
				next := r
				next.Files, e = fileCatalog(data)
				if e != nil {
					t.Fatal(e)
				}
				next.Site.Revision++
				if e = s.change(r, next, data, "write", "local-operator"); e != nil {
					t.Fatal(e)
				}
				site = next.Site
			}
			if mode == "nodes" {
				for i := 0; i < MaxFiles*9-2; i++ {
					if err = os.Mkdir(filepath.Join(base, "sites", "data", site.ID, "content", fmt.Sprintf("empty%d", i)), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			input := FileRestoreInput{backup.ID, backup.SHA256, site.Revision, path}
			id := site.ID
			switch mode {
			case "stale":
				input.ExpectedRevision--
			case "hash":
				input.ExpectedBackupSHA256 = strings.Repeat("0", 64)
			case "missing":
				input.Path = "absent.txt"
			case "path":
				input.Path = "../saved.txt"
			case "foreign":
				other, e := s.Create(CreateInput{Name: "Other", Domain: "other.test"}, "local-operator")
				if e != nil {
					t.Fatal(e)
				}
				id = other.ID
				input.ExpectedRevision = other.Revision
			case "corrupt":
				if err = os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "backups", backup.ID+".zip"), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "tamper":
				if err = os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "content", "index.html"), []byte("tamper"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := previewDisk(t, base)
			if _, err = s.PreviewFileRestore(id, input); err == nil {
				t.Fatal("refusal preview accepted")
			}
			if _, err = s.RestoreFile(id, ConfirmFileRestoreInput{input, true}, "local-operator"); err == nil {
				t.Fatal("refusal restore accepted")
			}
			if !reflect.DeepEqual(before, previewDisk(t, base)) {
				t.Fatal("refusal mutated disk")
			}
		})
	}
}

func lenMustFiles(t *testing.T, s *Store, id string) int {
	t.Helper()
	f, e := s.Files(id)
	if e != nil {
		t.Fatal(e)
	}
	return len(f)
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
