package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func archiveRequest(h http.Handler, body, contentType string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+migrationArchivePath, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", contentType)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The backup file upload needs the admin's session with CSRF, takes the
// file's bytes as a stream, and answers the migration source with what the
// file holds; a file the broker refuses is explained.
func TestUploadACPanelBackupFile(t *testing.T) {
	f, _, spy := migrationFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	if w := archiveRequest(f.handler, "cpmove bytes", "application/octet-stream", nil, ""); w.Code != 401 {
		t.Fatalf("without a session: %d", w.Code)
	}
	if w := archiveRequest(f.handler, "cpmove bytes", "application/octet-stream", cookie, ""); w.Code != 403 {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	if w := archiveRequest(f.handler, `{"file":"x"}`, "application/json", cookie, csrf); w.Code != 415 || spy.uploaded != "" {
		t.Fatalf("JSON: %d %s", w.Code, w.Body.String())
	}
	w := archiveRequest(f.handler, "cpmove bytes", "application/octet-stream", cookie, csrf)
	var opened struct {
		Source MigrationSource `json:"source"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &opened) != nil || opened.Source.Via != "archive" || opened.Source.Archive == nil || opened.Source.Archive.User != "shopone" || spy.uploaded != "cpmove bytes" {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	w = archiveRequest(f.handler, "not a backup", "application/octet-stream", cookie, csrf)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "The backup file could not be used") || !strings.Contains(w.Body.String(), "not a cPanel account backup") {
		t.Fatalf("a refused file: %d %s", w.Code, w.Body.String())
	}
}
