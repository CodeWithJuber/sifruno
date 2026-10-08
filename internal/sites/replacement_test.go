package sites

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReplaceBinaryRestoreReopen(t *testing.T) {
	s, j, base := fixture(t)
	site := makeSite(t, s)
	old := []byte{137, 80, 78, 71, 0, 255, 128}
	replacement := []byte{0, 128, 255, 10, 42}
	site, err := s.UploadFile(site.ID, UploadInput{Path: "assets/pixel.png", Content: old, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	before := served(s, site.Domain, "/index.html", "GET").Body.Bytes()
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.ReplaceFile(site.ID, ReplaceInput{Path: "assets/pixel.png", Content: replacement, ExpectedSHA256: sum(old), ExpectedRevision: site.Revision}, "local-operator")
	if err != nil || next.Revision != site.Revision+1 {
		t.Fatal("replace", err)
	}
	if w := served(s, site.PreviewHost, "/assets/pixel.png", "GET"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), replacement) {
		t.Fatal("replacement bytes", w.Code)
	}
	if !bytes.Equal(served(s, site.Domain, "/index.html", "GET").Body.Bytes(), before) {
		t.Fatal("other file changed")
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
	if err != nil || got != next {
		t.Fatal("reopen", err)
	}
	if !bytes.Equal(served(again, site.Domain, "/assets/pixel.png", "GET").Body.Bytes(), replacement) {
		t.Fatal("reopen bytes")
	}
	restored, err := again.Restore(site.ID, RestoreInput{BackupID: backup.ID, ExpectedRevision: next.Revision}, "local-operator")
	if err != nil || restored.Revision != next.Revision+1 {
		t.Fatal("restore", err)
	}
	if !bytes.Equal(served(again, site.Domain, "/assets/pixel.png", "GET").Body.Bytes(), old) {
		t.Fatal("restored original bytes")
	}
	if j.Verify() != nil {
		t.Fatal("history")
	}
}
func TestReplaceRefusalsDoNotMutate(t *testing.T) {
	s, j, _ := fixture(t)
	site := makeSite(t, s)
	files, _ := s.Files(site.ID)
	history, _ := j.List()
	original := served(s, site.Domain, "/index.html", "GET").Body.Bytes()
	hash := sum(original)
	base := ReplaceInput{Path: "index.html", Content: []byte{255, 0}, ExpectedSHA256: hash, ExpectedRevision: site.Revision}
	cases := []struct {
		name   string
		change func(*ReplaceInput)
		want   error
	}{
		{"missing hash", func(i *ReplaceInput) { i.ExpectedSHA256 = "" }, ErrInvalid},
		{"invalid hash", func(i *ReplaceInput) { i.ExpectedSHA256 = "bad" }, ErrInvalid},
		{"wrong hash", func(i *ReplaceInput) { i.ExpectedSHA256 = strings.Repeat("0", 64) }, ErrConflict},
		{"zero revision", func(i *ReplaceInput) { i.ExpectedRevision = 0 }, ErrInvalid},
		{"stale revision", func(i *ReplaceInput) { i.ExpectedRevision++ }, ErrConflict},
		{"case alias", func(i *ReplaceInput) { i.Path = "INDEX.html" }, ErrConflict},
		{"missing destination", func(i *ReplaceInput) { i.Path = "missing.png" }, ErrConflict},
		{"traversal", func(i *ReplaceInput) { i.Path = "../escape.png" }, ErrInvalid},
		{"directory", func(i *ReplaceInput) { i.Path = "assets" }, ErrInvalid},
		{"unsupported", func(i *ReplaceInput) { i.Path = "script.php" }, ErrInvalid},
		{"oversize", func(i *ReplaceInput) { i.Content = make([]byte, MaxFileBytes+1) }, ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := base
			tc.change(&input)
			if _, err := s.ReplaceFile(site.ID, input, "local-operator"); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			got, _ := s.Get(site.ID)
			catalog, _ := s.Files(site.ID)
			events, _ := j.List()
			if got != site || !reflect.DeepEqual(files, catalog) || !reflect.DeepEqual(history, events) || !bytes.Equal(served(s, site.Domain, "/index.html", "GET").Body.Bytes(), original) {
				t.Fatal("refusal mutated state")
			}
		})
	}
}

func TestReplaceAtCapacityAndGrowthRefusal(t *testing.T) {
	for _, kind := range []string{"count", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			s, j, _ := fixture(t)
			data := map[string][]byte{}
			count, size := MaxFiles, 1
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
			path := "asset0.png"
			site, err = s.ReplaceFile(site.ID, ReplaceInput{Path: path, Content: make([]byte, size), ExpectedSHA256: sum(data[path]), ExpectedRevision: site.Revision}, "local-operator")
			if err != nil {
				t.Fatal("same-size replacement at capacity", err)
			}
			site, err = s.ReplaceFile(site.ID, ReplaceInput{Path: path, Content: []byte{}, ExpectedSHA256: sum(data[path]), ExpectedRevision: site.Revision}, "local-operator")
			if err != nil {
				t.Fatal("smaller replacement at capacity", err)
			}
			if kind == "bytes" {
				// Leave one byte of aggregate capacity beyond the empty target, then
				// consume two bytes elsewhere before trying to refill the target.
				site, err = s.ReplaceFile(site.ID, ReplaceInput{Path: "asset1.png", Content: make([]byte, size-1), ExpectedSHA256: sum(data["asset1.png"]), ExpectedRevision: site.Revision}, "local-operator")
				if err != nil {
					t.Fatal(err)
				}
				site, err = s.UploadFile(site.ID, UploadInput{Path: "extra.png", Content: []byte{1, 2}, ExpectedRevision: site.Revision}, "local-operator")
				if err != nil {
					t.Fatal(err)
				}
				catalog, _ := s.Files(site.ID)
				history, _ := j.List()
				if _, err = s.ReplaceFile(site.ID, ReplaceInput{Path: path, Content: make([]byte, size), ExpectedSHA256: sum(nil), ExpectedRevision: site.Revision}, "local-operator"); !errors.Is(err, ErrInvalid) {
					t.Fatal("growth admitted", err)
				}
				got, _ := s.Get(site.ID)
				after, _ := s.Files(site.ID)
				events, _ := j.List()
				if got != site || !reflect.DeepEqual(catalog, after) || !reflect.DeepEqual(history, events) {
					t.Fatal("growth refusal mutated")
				}
			}
		})
	}
}
