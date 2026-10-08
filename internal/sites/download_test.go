package sites

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDownloadFileSavedBytesAndReadOnlyState(t *testing.T) {
	s, journal, base := fixture(t)
	site := makeSite(t, s)
	assets := map[string][]byte{"assets/text.txt": []byte("Saved UTF-8: مرحبا\n"), "assets/image.png": {0x89, 'P', 'N', 'G', 0, 0xff, 0x80}, "empty.txt": {}, "limit.pdf": bytes.Repeat([]byte{0xff}, MaxFileBytes)}
	for path, content := range assets {
		var err error
		site, err = s.UploadFile(site.ID, UploadInput{Path: path, Content: content, ExpectedRevision: site.Revision}, "local-operator")
		if err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.load(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(base, "sites", "data", site.ID, "state.json")
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	history, err := journal.List()
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range assets {
		got, file, err := s.DownloadFile(site.ID, DownloadInput{Path: path, ExpectedSHA256: sum(content), ExpectedRevision: site.Revision})
		if err != nil || !bytes.Equal(got, content) || file.Path != path || file.SHA256 != sum(content) || file.Bytes != int64(len(content)) {
			t.Fatal("saved byte download mismatch", path, err)
		}
	}
	after, err := s.load(site.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("download changed catalog", err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(state, stateAfter) {
		t.Fatal("download changed signed state", err)
	}
	historyAfter, err := journal.List()
	if err != nil || !reflect.DeepEqual(history, historyAfter) || journal.Verify() != nil {
		t.Fatal("download changed history", err)
	}
}

func TestDownloadFileRefusals(t *testing.T) {
	s, _, _ := fixture(t)
	site := makeSite(t, s)
	file, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	valid := DownloadInput{Path: file.Path, ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}
	before, err := s.load(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name  string
		input DownloadInput
		want  error
	}{
		{"stale revision", DownloadInput{file.Path, file.SHA256, site.Revision + 1}, ErrConflict},
		{"wrong hash", DownloadInput{file.Path, strings.Repeat("0", 64), site.Revision}, ErrConflict},
		{"missing", DownloadInput{"missing.txt", file.SHA256, site.Revision}, ErrNotFound},
		{"missing hash", DownloadInput{file.Path, "", site.Revision}, ErrInvalid},
		{"zero revision", DownloadInput{file.Path, file.SHA256, 0}, ErrInvalid},
		{"traversal", DownloadInput{"../index.html", file.SHA256, site.Revision}, ErrInvalid},
		{"directory", DownloadInput{"assets", file.SHA256, site.Revision}, ErrInvalid},
		{"reserved", DownloadInput{"credentials.txt", file.SHA256, site.Revision}, ErrInvalid},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, info, err := s.DownloadFile(site.ID, row.input)
			if got != nil || info != (FileInfo{}) || !errors.Is(err, row.want) {
				t.Fatal("refusal", err)
			}
		})
	}
	if _, _, err := s.DownloadFile(strings.Repeat("a", 32), valid); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown website", err)
	}
	r, err := s.load(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, r) {
		t.Fatal("refusals changed catalog")
	}
	r.Pending = &pendingChange{Action: "interrupted", Checkpoints: []string{}}
	if err = s.save(r); err != nil {
		t.Fatal(err)
	}
	recovery := r
	if _, _, err = s.DownloadFile(site.ID, valid); !errors.Is(err, ErrUnavailable) {
		t.Fatal("recovery download accepted", err)
	}
	r, err = s.load(site.ID)
	if err != nil || !reflect.DeepEqual(recovery, r) {
		t.Fatal("download changed recovery record")
	}
}

func TestDownloadFileRefusesUnsafeOrCorruptStorage(t *testing.T) {
	for _, kind := range []string{"corrupt", "oversized", "missing", "directory", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			s, _, base := fixture(t)
			site := makeSite(t, s)
			file, err := s.ReadFile(site.ID, "index.html")
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(base, "sites", "data", site.ID, "content", file.Path)
			if err = os.Remove(p); err != nil {
				t.Fatal(err)
			}
			want := ErrUnavailable
			switch kind {
			case "corrupt":
				err = os.WriteFile(p, []byte("altered"), 0600)
			case "oversized":
				err = os.WriteFile(p, make([]byte, MaxFileBytes+1), 0600)
			case "directory":
				err = os.Mkdir(p, 0700)
			case "symlink", "hardlink":
				outside := filepath.Join(base, "outside.txt")
				if err = os.WriteFile(outside, []byte(file.Content), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(outside, p)
					if err != nil {
						t.Skip("symlink creation unavailable on this test host")
					}
				} else {
					err = os.Link(outside, p)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			got, info, err := s.DownloadFile(site.ID, DownloadInput{file.Path, file.SHA256, site.Revision})
			if got != nil || info != (FileInfo{}) || !errors.Is(err, want) {
				t.Fatal("unsafe download accepted", err)
			}
			if current, err := s.load(site.ID); err != nil || current.Site != site {
				t.Fatal("failed read changed revision", err)
			}
		})
	}
}
