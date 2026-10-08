package sites

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUploadBinaryBackupDeleteRestoreReopen(t *testing.T) {
	s, j, base := fixture(t)
	site := makeSite(t, s)
	data := map[string][]byte{"assets/pixel.png": {0x89, 'P', 'N', 'G', 0, 255, 128, 10}, "fonts/font.woff2": {0, 255, 128, 42}, "docs/file.pdf": []byte("%PDF-1.7\n\x00\xff"), "notes.txt": []byte("Hello \u0645\u0631\u062d\u0628\u0627"), "empty.txt": {}}
	for path, raw := range data {
		next, err := s.UploadFile(site.ID, UploadInput{Path: path, Content: raw, ExpectedRevision: site.Revision}, "local-operator")
		if err != nil || next.Revision != site.Revision+1 {
			t.Fatal("upload", path, err)
		}
		site = next
		w := served(s, site.PreviewHost, "/"+path, "GET")
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), raw) {
			t.Fatal("served bytes", path, w.Code)
		}
	}
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	path := "assets/pixel.png"
	site, err = s.DeleteFile(site.ID, DeleteInput{Path: path, ExpectedSHA256: sum(data[path]), ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	if served(s, site.Domain, "/"+path, "GET").Code != 404 {
		t.Fatal("delete did not remove upload")
	}
	site, err = s.Restore(site.ID, RestoreInput{BackupID: backup.ID, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), j)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	got, err := again.Get(site.ID)
	if err != nil || got != site {
		t.Fatal("reopen revision", err)
	}
	for path, raw := range data {
		w := served(again, site.Domain, "/"+path, "GET")
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), raw) {
			t.Fatal("restored/reopened bytes", path, w.Code)
		}
	}
	if j.Verify() != nil {
		t.Fatal("signed history invalid")
	}
}

func TestUploadRefusalsDoNotMutate(t *testing.T) {
	s, j, _ := fixture(t)
	site := makeSite(t, s)
	var err error
	site, err = s.UploadFile(site.ID, UploadInput{Path: "empty.txt", Content: []byte{}, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := s.Files(site.ID)
	history, _ := j.List()
	cases := []struct {
		path     string
		data     []byte
		revision uint64
		want     error
	}{
		{"index.html", []byte("replace"), site.Revision, ErrConflict}, {"empty.txt", nil, site.Revision, ErrConflict},
		{"new.png", nil, site.Revision - 1, ErrConflict}, {"INDEX.html", nil, site.Revision, ErrInvalid},
		{"index.html/child.png", nil, site.Revision, ErrInvalid}, {"../escape.png", nil, site.Revision, ErrInvalid},
		{"secret.php", nil, site.Revision, ErrInvalid}, {"secrets.txt", nil, site.Revision, ErrInvalid},
		{"large.png", make([]byte, MaxFileBytes+1), site.Revision, ErrInvalid},
	}
	for _, tc := range cases {
		if _, err := s.UploadFile(site.ID, UploadInput{Path: tc.path, Content: tc.data, ExpectedRevision: tc.revision}, "local-operator"); !errors.Is(err, tc.want) {
			t.Fatal(tc.path, err)
		}
		got, _ := s.Get(site.ID)
		catalog, _ := s.Files(site.ID)
		events, _ := j.List()
		if got != site || !reflect.DeepEqual(files, catalog) || !reflect.DeepEqual(history, events) {
			t.Fatal("refusal mutated site or journal", tc.path)
		}
	}
}

func TestUploadAggregateLimits(t *testing.T) {
	for _, kind := range []string{"count", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			s, j, _ := fixture(t)
			data := map[string][]byte{}
			count, size := MaxFiles, 0
			if kind == "bytes" {
				count, size = MaxSiteBytes/MaxFileBytes, MaxFileBytes
			}
			for i := 0; i < count; i++ {
				data[fmt.Sprintf("asset%d.png", i)] = make([]byte, size)
			}
			site, err := s.create(CreateInput{Name: "Capacity", Domain: "capacity.test"}, data, "create", "local-operator")
			if err != nil {
				t.Fatal(err)
			}
			before, _ := s.Files(site.ID)
			history, _ := j.List()
			if _, err = s.UploadFile(site.ID, UploadInput{Path: "extra.png", Content: []byte{1}, ExpectedRevision: site.Revision}, "local-operator"); !errors.Is(err, ErrInvalid) {
				t.Fatal("limit accepted", err)
			}
			after, _ := s.Files(site.ID)
			got, _ := s.Get(site.ID)
			events, _ := j.List()
			if got != site || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(history, events) {
				t.Fatal("limit mutation")
			}
		})
	}
}

func TestUploadRefusesCatalogDrift(t *testing.T) {
	s, j, base := fixture(t)
	site := makeSite(t, s)
	history, _ := j.List()
	original := filepath.Join(base, "sites", "data", site.ID, "content", "index.html")
	if err := os.WriteFile(original, []byte("external change"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UploadFile(site.ID, UploadInput{Path: "new.png", Content: []byte{255}, ExpectedRevision: site.Revision}, "local-operator"); err == nil {
		t.Fatal("catalog drift accepted")
	}
	if _, err := os.Stat(filepath.Join(base, "sites", "data", site.ID, "content", "new.png")); !os.IsNotExist(err) {
		t.Fatal("upload was written")
	}
	raw, err := os.ReadFile(original)
	if err != nil || string(raw) != "external change" {
		t.Fatal("drift was changed", err)
	}
	events, _ := j.List()
	if !reflect.DeepEqual(history, events) {
		t.Fatal("drift changed history")
	}
}
