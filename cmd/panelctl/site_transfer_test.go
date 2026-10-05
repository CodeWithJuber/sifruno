package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureTransferZIP(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, p := range []struct{ name, content string }{{"manifest.json", `{"version":1}`}, {"files/index.html", "<h1>ARCHIVE-SENSITIVE-FIXTURE</h1>"}} {
		f, e := z.Create(p.name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.WriteString(f, p.content); e != nil {
			t.Fatal(e)
		}
	}
	if z.Close() != nil {
		t.Fatal("fixture archive unavailable")
	}
	return b.Bytes()
}
func TestCLITransferRejectsUnsafeLocalFiles(t *testing.T) {
	dir := t.TempDir()
	raw := fixtureTransferZIP(t)
	source := filepath.Join(dir, "source.zip")
	if os.WriteFile(source, raw, 0600) != nil {
		t.Fatal("fixture unavailable")
	}
	if _, e := readTransferArchive(source); e != nil {
		t.Fatal(e)
	}
	hard := filepath.Join(dir, "hard.zip")
	if e := os.Link(source, hard); e != nil {
		t.Fatal("hardlink fixture unavailable")
	}
	for _, p := range []string{source, hard, dir} {
		if _, e := readTransferArchive(p); e == nil {
			t.Fatal("unsafe archive file accepted")
		}
	}
	if os.Remove(hard) != nil {
		t.Fatal("hardlink cleanup failed")
	}
	symlink := filepath.Join(dir, "link.zip")
	if os.Symlink(source, symlink) == nil {
		if _, e := readTransferArchive(symlink); e == nil {
			t.Fatal("archive symlink accepted")
		}
	}
	folder := filepath.Join(dir, "linked-folder")
	if os.Symlink(dir, folder) == nil {
		if _, e := readTransferArchive(filepath.Join(folder, "source.zip")); e == nil {
			t.Fatal("archive parent symlink accepted")
		}
	}
	empty := filepath.Join(dir, "empty.zip")
	os.WriteFile(empty, nil, 0600)
	if _, e := readTransferArchive(empty); e == nil {
		t.Fatal("empty archive accepted")
	}
	malformed := filepath.Join(dir, "malformed.zip")
	os.WriteFile(malformed, []byte("ARCHIVE-SENSITIVE-FIXTURE"), 0600)
	if _, e := readTransferArchive(malformed); e == nil || strings.Contains(e.Error(), "ARCHIVE-SENSITIVE") {
		t.Fatal("malformed archive accepted or echoed")
	}
	big := filepath.Join(dir, "big.zip")
	f, e := os.Create(big)
	if e != nil {
		t.Fatal(e)
	}
	e = f.Truncate(34<<20 + 1)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = readTransferArchive(big); e == nil {
		t.Fatal("oversize local archive accepted")
	}
}
func TestCLIExportExclusiveOutputAndBoundedResponses(t *testing.T) {
	raw := fixtureTransferZIP(t)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		success bool
	}{
		{"valid", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.Write(raw)
		}, true},
		{"wrong-type", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(raw)
		}, false},
		{"malformed", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			io.WriteString(w, "ARCHIVE-SENSITIVE-FIXTURE")
		}, false},
		{"overlength-header", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Length", fmt.Sprint(34<<20+1))
		}, false},
		{"truncated", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Length", fmt.Sprint(len(raw)+1))
			w.Write(raw)
		}, false},
		{"chunked-overlimit", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.(http.Flusher).Flush()
			chunk := bytes.Repeat([]byte{'x'}, 1<<20)
			for range 35 {
				if _, e := w.Write(chunk); e != nil {
					return
				}
			}
		}, false},
		{"error-archive", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(422)
			io.WriteString(w, "ARCHIVE-SENSITIVE-FIXTURE")
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			client, e := newSiteClient(server.URL)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "new.zip")
			var output bytes.Buffer
			e = client.exportSite("/export", path, &output)
			if (e == nil) != tc.success {
				t.Fatal("response admission mismatch", e)
			}
			if e != nil && strings.Contains(e.Error(), "ARCHIVE-SENSITIVE") {
				t.Fatal("archive diagnostic leaked")
			}
			got, readErr := os.ReadFile(path)
			if tc.success {
				if readErr != nil || !bytes.Equal(got, raw) {
					t.Fatal("export bytes mismatch")
				}
				if client.exportSite("/export", path, io.Discard) == nil {
					t.Fatal("existing output overwritten")
				}
				again, _ := os.ReadFile(path)
				if !bytes.Equal(again, raw) {
					t.Fatal("existing output changed")
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatal("failed transfer retained partial archive")
			}
		})
	}
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.zip")
	os.WriteFile(existing, raw, 0600)
	linked := filepath.Join(dir, "hard.zip")
	if os.Link(existing, linked) != nil {
		t.Fatal("hardlink fixture unavailable")
	}
	client, _ := newSiteClient("http://127.0.0.1:1")
	for _, p := range []string{existing, linked, dir} {
		if client.exportSite("/export", p, io.Discard) == nil {
			t.Fatal("unsafe output accepted")
		}
	}
	if !bytes.Equal(raw, mustReadTransferFile(t, existing)) {
		t.Fatal("refusal changed original")
	}
	symbolic := filepath.Join(dir, "symbolic.zip")
	if os.Symlink(existing, symbolic) == nil && client.exportSite("/export", symbolic, io.Discard) == nil {
		t.Fatal("output symlink accepted")
	}
}
func mustReadTransferFile(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("fixture output unavailable")
	}
	return b
}
func TestCLIImportResponseAndFlagDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.zip")
	os.WriteFile(path, fixtureTransferZIP(t), 0600)
	for _, response := range []struct{ kind, body string }{{"text/plain", "ARCHIVE-SENSITIVE-FIXTURE"}, {"application/json", `{"id":"ARCHIVE-SENSITIVE-FIXTURE"}`}, {"application/json", strings.Repeat("x", 16385)}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Origin") == "" || r.Header.Get("X-CSRF-Token") != "synthetic-csrf" || !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
				t.Error("missing multipart authentication headers")
			}
			w.Header().Set("Content-Type", response.kind)
			io.WriteString(w, response.body)
		}))
		client, _ := newSiteClient(server.URL)
		client.csrf = "synthetic-csrf"
		e := client.importSite("/api/v1/sites/import", "Fixture", "fixture.example", path, io.Discard)
		server.Close()
		if e == nil || strings.Contains(e.Error(), "ARCHIVE-SENSITIVE") {
			t.Fatal("unsafe import response diagnostic")
		}
	}
	var out, errs bytes.Buffer
	e := runSites([]string{"import", "--revision", "USER-SENSITIVE-VALUE"}, "", "http://127.0.0.1:1", &out, &errs)
	if e == nil || strings.Contains(e.Error()+errs.String(), "USER-SENSITIVE") {
		t.Fatal("invalid flags echoed input")
	}
	for _, args := range [][]string{{"export", "--id", "bad", "--backup", "bad", "--out", "secret"}, {"import", "--name", strings.Repeat("é", 41), "--domain", "fixture.example", "--from", "secret"}} {
		if runSites(args, "", "http://127.0.0.1:1", &out, &errs) == nil {
			t.Fatal("invalid transfer admitted")
		}
	}
}
