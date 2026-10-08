package sites

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestRenameBytesHTTPReopenRestore(t *testing.T) {
	s, journal, base := fixture(t)
	site := makeSite(t, s)
	data := []byte{137, 80, 78, 71, 0, 255, 128}
	site, err := s.UploadFile(site.ID, UploadInput{Path: "assets/pixel.png", Content: data, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	index := append([]byte{}, served(s, site.Domain, "/index.html", "GET").Body.Bytes()...)
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.RenameFile(site.ID, RenameInput{"assets/pixel.png", "images/new/pixel.png", sum(data), site.Revision}, "local-operator")
	if err != nil || next.Revision != site.Revision+1 || next.ID != site.ID || next.Domain != site.Domain || next.PreviewHost != site.PreviewHost || next.State != site.State || next.Name != site.Name || !next.CreatedAt.Equal(site.CreatedAt) {
		t.Fatal("rename identity/revision", next, err)
	}
	for _, host := range []string{site.Domain, site.PreviewHost} {
		if w := served(s, host, "/assets/pixel.png", "GET"); w.Code != 404 {
			t.Fatal("old URL", w.Code)
		}
		if w := served(s, host, "/images/new/pixel.png", "GET"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) {
			t.Fatal("new URL bytes", w.Code)
		}
		if !bytes.Equal(served(s, host, "/index.html", "GET").Body.Bytes(), index) {
			t.Fatal("unrelated file changed")
		}
	}
	files, err := s.Files(site.ID)
	if err != nil || len(files) != 2 || files[0] != (FileInfo{"images/new/pixel.png", int64(len(data)), sum(data)}) {
		t.Fatal("catalog", files, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), journal)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if got, err := again.Get(site.ID); err != nil || got != next {
		t.Fatal("reopen", got, err)
	}
	if w := served(again, site.Domain, "/images/new/pixel.png", "GET"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatal("reopen bytes")
	}
	if _, err = again.Restore(site.ID, RestoreInput{BackupID: backup.ID, ExpectedRevision: next.Revision}, "local-operator"); err != nil {
		t.Fatal(err)
	}
	if w := served(again, site.Domain, "/assets/pixel.png", "GET"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatal("restore bytes")
	}
	if w := served(again, site.Domain, "/images/new/pixel.png", "GET"); w.Code != 404 {
		t.Fatal("restore new URL")
	}
	if journal.Verify() != nil {
		t.Fatal("journal")
	}
}

func TestRenameRefusalsPreserveState(t *testing.T) {
	s, journal, _ := fixture(t)
	site := makeSite(t, s)
	site, err := s.UploadFile(site.ID, UploadInput{"assets.png/other.txt", []byte("other"), site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := s.Files(site.ID)
	history, _ := journal.List()
	index := append([]byte{}, served(s, site.Domain, "/index.html", "GET").Body.Bytes()...)
	base := RenameInput{"index.html", "moved.html", sum(index), site.Revision}
	for _, row := range []struct {
		name string
		edit func(*RenameInput)
		want error
	}{
		{"no-op", func(v *RenameInput) { v.Destination = v.Path }, ErrInvalid},
		{"case-only", func(v *RenameInput) { v.Destination = "INDEX.html" }, ErrInvalid},
		{"collision", func(v *RenameInput) { v.Destination = "ASSETS.png/OTHER.txt" }, ErrConflict},
		{"file as folder", func(v *RenameInput) { v.Destination = "index.html/new.png" }, ErrConflict},
		{"folder as file", func(v *RenameInput) { v.Destination = "assets.png" }, ErrConflict},
		{"case alias parent", func(v *RenameInput) { v.Destination = "ASSETS.png/new.html" }, ErrConflict},
		{"missing", func(v *RenameInput) { v.Path = "missing.html" }, ErrNotFound},
		{"source alias", func(v *RenameInput) { v.Path = "INDEX.html" }, ErrNotFound},
		{"stale", func(v *RenameInput) { v.ExpectedRevision++ }, ErrConflict},
		{"wrong hash", func(v *RenameInput) { v.ExpectedSHA256 = strings.Repeat("0", 64) }, ErrConflict},
		{"missing hash", func(v *RenameInput) { v.ExpectedSHA256 = "" }, ErrInvalid},
		{"zero revision", func(v *RenameInput) { v.ExpectedRevision = 0 }, ErrInvalid},
		{"traversal", func(v *RenameInput) { v.Destination = "../escape.html" }, ErrInvalid},
		{"absolute", func(v *RenameInput) { v.Destination = "C:/escape.html" }, ErrInvalid},
		{"cross site", func(v *RenameInput) { v.Destination = "/api/v1/sites/other/file.html" }, ErrInvalid},
		{"reserved", func(v *RenameInput) { v.Destination = "credentials.txt" }, ErrInvalid},
		{"unsupported", func(v *RenameInput) { v.Destination = "index.php" }, ErrInvalid},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := base
			row.edit(&input)
			if got, err := s.RenameFile(site.ID, input, "local-operator"); got != (Site{}) || !errors.Is(err, row.want) {
				t.Fatal(got, err)
			}
			got, _ := s.Get(site.ID)
			catalog, _ := s.Files(site.ID)
			events, _ := journal.List()
			if got != site || !reflect.DeepEqual(catalog, files) || !reflect.DeepEqual(events, history) || !bytes.Equal(served(s, site.Domain, "/index.html", "GET").Body.Bytes(), index) {
				t.Fatal("refusal mutated state")
			}
		})
	}
	if _, err := s.RenameFile(site.ID, base, "other"); !errors.Is(err, ErrInvalid) {
		t.Fatal("actor", err)
	}
}

func TestRenameEmptyDestinationFolderRefusesBeforeMutation(t *testing.T) {
	s, journal, _ := fixture(t)
	site := makeSite(t, s)
	site, err := s.UploadFile(site.ID, UploadInput{"empty.png/file.txt", []byte("preserved"), site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.RenameFile(site.ID, RenameInput{"empty.png/file.txt", "elsewhere.txt", sum([]byte("preserved")), site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := s.Files(site.ID)
	history, _ := journal.List()
	file, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"empty.png", "EMPTY.png/new.html"} {
		if _, err := s.RenameFile(site.ID, RenameInput{file.Path, destination, file.SHA256, site.Revision}, "local-operator"); !errors.Is(err, ErrConflict) {
			t.Fatal(destination, err)
		}
		got, _ := s.Get(site.ID)
		catalog, _ := s.Files(site.ID)
		events, _ := journal.List()
		if got != site || !reflect.DeepEqual(catalog, files) || !reflect.DeepEqual(events, history) || served(s, site.Domain, "/index.html", "GET").Body.String() != file.Content {
			t.Fatal("folder refusal mutated state")
		}
	}
}

func TestRenameCompetingClientsCommitOnce(t *testing.T) {
	s, _, _ := fixture(t)
	site := makeSite(t, s)
	file, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, destination := range []string{"first.html", "second.html"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			_, err := s.RenameFile(site.ID, RenameInput{file.Path, path, file.SHA256, site.Revision}, "local-operator")
			results <- err
		}(destination)
	}
	wg.Wait()
	close(results)
	commits, conflicts := 0, 0
	for err := range results {
		if err == nil {
			commits++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if commits != 1 || conflicts != 1 {
		t.Fatal("competing outcomes", commits, conflicts)
	}
	got, _ := s.Get(site.ID)
	files, _ := s.Files(site.ID)
	if got.Revision != site.Revision+1 || len(files) != 1 || files[0].SHA256 != file.SHA256 {
		t.Fatal("multiple mutations")
	}
	if served(s, site.Domain, "/", "GET").Code != 404 {
		t.Fatal("renamed index root still served")
	}
}

func TestRenameAtFileCapacityWithEmptyFolder(t *testing.T) {
	s, journal, base := fixture(t)
	data := map[string][]byte{"index.html": []byte("capacity index"), "empty.png/file.txt": []byte("preserved at capacity")}
	for i := 0; i < MaxFiles-2; i++ {
		data[fmt.Sprintf("asset%02d.txt", i)] = []byte(fmt.Sprintf("asset %d", i))
	}
	site, err := s.create(CreateInput{Name: "Capacity", Domain: "capacity.test"}, data, "test", "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	// This move leaves 64 saved files plus an empty folder at the root.
	site, err = s.RenameFile(site.ID, RenameInput{"empty.png/file.txt", "moved.txt", sum(data["empty.png/file.txt"]), site.Revision}, "local-operator")
	if err != nil {
		t.Fatal("first move", err)
	}
	files, err := s.Files(site.ID)
	if err != nil || len(files) != MaxFiles {
		t.Fatal("valid catalog with empty folder", err, len(files))
	}
	next, err := s.RenameFile(site.ID, RenameInput{"asset00.txt", "renamed.txt", sum(data["asset00.txt"]), site.Revision}, "local-operator")
	if err != nil || next.Revision != site.Revision+1 {
		t.Fatal("rename with 65 directory entries", next, err)
	}
	if served(s, site.Domain, "/asset00.txt", "GET").Code != 404 {
		t.Fatal("old capacity URL")
	}
	if w := served(s, site.Domain, "/renamed.txt", "GET"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data["asset00.txt"]) {
		t.Fatal("new capacity bytes", w.Code)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), journal)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	files, err = again.Files(site.ID)
	if err != nil || len(files) != MaxFiles {
		t.Fatal("reopened capacity catalog", err, len(files))
	}
	if got, err := again.Get(site.ID); err != nil || got != next {
		t.Fatal("reopened capacity identity", got, err)
	}
}
