package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sifruno/internal/sites"
	"strconv"
	"testing"
)

func uploadedRestoreRequest(path string, parts []importPart, c *http.Cookie, csrf string) *http.Request {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, p := range parts {
		var w io.Writer
		if p.filename != "" {
			w, _ = mw.CreateFormFile(p.name, p.filename)
		} else {
			w, _ = mw.CreateFormField(p.name)
		}
		_, _ = io.WriteString(w, p.content)
	}
	_ = mw.Close()
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+path, &body)
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("X-CSRF-Token", csrf)
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func TestUploadedArchiveRestoreAPIAdmissionAndExactContract(t *testing.T) {
	f := websiteFixture(t)
	c, csrf := websiteSignIn(t, f)
	site := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Target", Domain: "target.example"}, c, csrf))
	backup, err := f.store.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := f.store.ExportBackup(site.ID, backup.ID)
	if err != nil {
		t.Fatal(err)
	}
	site, _ = f.store.Get(site.ID)
	base := "/api/v1/sites/" + site.ID + "/archive-restore"
	parts := []importPart{{name: "archive", filename: "native.zip", content: string(raw)}, {name: "expected_revision", content: strconv.FormatUint(site.Revision, 10)}}
	before := siteAdmissionSnapshot(t, f)
	for _, suffix := range []string{"-preview", ""} {
		valid := append([]importPart{}, parts...)
		if suffix == "" {
			valid = append(valid, importPart{name: "expected_archive_sha256", content: backup.SHA256})
		}
		for _, tc := range []string{"unauthenticated", "csrf", "origin", "extra", "duplicate", "oversized", "malformed"} {
			t.Run(suffix+tc, func(t *testing.T) {
				request := uploadedRestoreRequest(base+suffix, valid, c, csrf)
				want := 400
				switch tc {
				case "unauthenticated":
					request.Header.Del("Cookie")
					request.Body = panicReadBody{}
					want = 401
				case "csrf":
					request.Header.Del("X-CSRF-Token")
					request.Body = panicReadBody{}
					want = 403
				case "origin":
					request.Header.Set("Origin", "http://foreign.example")
					request.Body = panicReadBody{}
					want = 403
				case "extra":
					request = uploadedRestoreRequest(base+suffix, append(append([]importPart{}, valid...), importPart{name: "domain", content: "foreign.example"}), c, csrf)
				case "duplicate":
					request = uploadedRestoreRequest(base+suffix, append(append([]importPart{}, valid...), parts[1]), c, csrf)
				case "oversized":
					request.ContentLength = maxTransferBody + 1
					request.Body = panicReadBody{}
					want = 413
				case "malformed":
					bad := append([]importPart{}, valid...)
					bad[0].content = "bad ZIP"
					request = uploadedRestoreRequest(base+suffix, bad, c, csrf)
					want = 422
					if suffix == "" {
						want = 409
					}
				}
				w := httptest.NewRecorder()
				f.handler.ServeHTTP(w, request)
				if w.Code != want {
					t.Fatalf("got %d want %d", w.Code, want)
				}
				if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
					t.Fatal("refusal changed site or trail")
				}
			})
		}
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, uploadedRestoreRequest(base+"-preview", parts, c, csrf))
	var preview sites.ArchiveRestorePreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &preview) != nil || preview.ArchiveSHA256 != backup.SHA256 || preview.SiteID != site.ID {
		t.Fatal("preview response", w.Code)
	}
	if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
		t.Fatal("preview mutated")
	}
	confirm := append(append([]importPart{}, parts...), importPart{name: "expected_archive_sha256", content: preview.ArchiveSHA256})
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, uploadedRestoreRequest(base, confirm, c, csrf))
	got := siteResponse(t, w)
	if got.ID != site.ID || got.Revision != site.Revision+1 {
		t.Fatal("restore response")
	}
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, uploadedRestoreRequest(base, confirm, c, csrf))
	if w.Code != 409 {
		t.Fatal("stale restore", w.Code)
	}
}
