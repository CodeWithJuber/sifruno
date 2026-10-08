package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"sifruno/internal/sites"
)

func TestSiteFileDownloadPrivateRawAttachment(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Download", Domain: "download.test"}, cookie, csrf))
	content := []byte{0x89, 'P', 'N', 'G', 0, 0xff, 0x80}
	site = siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites/"+site.ID+"/upload", sites.UploadInput{Path: "assets/image.png", Content: content, ExpectedRevision: site.Revision}, cookie, csrf))
	files, err := f.store.Files(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		query := url.Values{"path": {file.Path}, "expected_revision": {strconv.FormatUint(site.Revision, 10)}, "expected_sha256": {file.SHA256}}
		endpoint := "/api/v1/sites/" + site.ID + "/files/download?" + query.Encode()
		if w := websiteRequest(f.handler, "GET", endpoint, nil, nil, ""); w.Code != 401 {
			t.Fatal("unauthenticated download accepted", w.Code)
		}
		w := websiteRequest(f.handler, "GET", endpoint, nil, cookie, "")
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/octet-stream" || w.Header().Get("Content-Length") != strconv.FormatInt(file.Bytes, 10) || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("raw download headers", w.Code)
		}
		if file.Path == "assets/image.png" && (!bytes.Equal(w.Body.Bytes(), content) || w.Header().Get("Content-Disposition") != `attachment; filename="image.png"`) {
			t.Fatal("binary bytes or attachment filename")
		}
		if file.Path == "index.html" && !strings.Contains(w.Body.String(), "Download") {
			t.Fatal("text bytes")
		}
		if w := websiteRequest(f.handler, "HEAD", endpoint, nil, cookie, ""); w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != strconv.FormatInt(file.Bytes, 10) {
			t.Fatal("HEAD did not preserve metadata", w.Code)
		}
		for _, test := range []struct {
			key, value string
			status     int
		}{{"expected_revision", "1", 409}, {"expected_sha256", strings.Repeat("0", 64), 409}, {"path", "missing.txt", 404}, {"path", "../index.html", 422}, {"path", "key.txt", 422}, {"expected_revision", "0", 422}, {"expected_revision", "01", 422}, {"expected_revision", "18446744073709551616", 422}, {"expected_sha256", "", 422}} {
			q := url.Values{"path": {file.Path}, "expected_revision": {strconv.FormatUint(site.Revision, 10)}, "expected_sha256": {file.SHA256}}
			q.Set(test.key, test.value)
			if w := websiteRequest(f.handler, "GET", "/api/v1/sites/"+site.ID+"/files/download?"+q.Encode(), nil, cookie, ""); w.Code != test.status || strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") {
				t.Fatal("download refusal", test.key, w.Code)
			}
		}
		for _, suffix := range []string{"&path=index.html", "&extra=true", "&bad=%zz"} {
			if w := websiteRequest(f.handler, "GET", endpoint+suffix, nil, cookie, ""); w.Code != 422 {
				t.Fatal("ambiguous query accepted", w.Code)
			}
		}
		r := httptest.NewRequest("GET", "http://download.test"+endpoint, nil)
		r.RemoteAddr = "203.0.113.2:14000"
		r.AddCookie(cookie)
		public := httptest.NewRecorder()
		f.handler.ServeHTTP(public, r)
		if public.Code != 403 {
			t.Fatal("public panel download accepted", public.Code)
		}
	}
	if current, err := f.store.Get(site.ID); err != nil || current != site || f.journal.Verify() != nil {
		t.Fatal("download changed site state", err)
	}
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	w := websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("invalid OpenAPI")
	}
	raw := string(spec.Paths["/api/v1/sites/{id}/files/download"])
	for _, expected := range []string{"download-site-file", "expected_revision", "expected_sha256", "application/octet-stream", "2097152"} {
		if !strings.Contains(raw, expected) {
			t.Fatal("download contract absent", expected)
		}
	}
}
