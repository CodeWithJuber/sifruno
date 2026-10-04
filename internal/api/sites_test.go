package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sifruno/internal/operator"
	"sifruno/internal/sites"
	"sifruno/internal/trail"
)

type siteFixture struct {
	handler http.Handler
	manager *operator.Manager
	store   *sites.Store
	journal *trail.Store
	key     string
}

func websiteFixture(t *testing.T) siteFixture {
	t.Helper()
	dir := realTempDir(t)
	m, err := operator.Open(filepath.Join(dir, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(m.AccessKeyPath())
	if err != nil {
		t.Fatal("fixture access key unavailable")
	}
	j, err := trail.Open(filepath.Join(dir, "trail"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := sites.Open(filepath.Join(dir, "sites"), j)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h := New(Options{Operator: m, Sites: s, Trail: j, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return siteFixture{h, m, s, j, strings.TrimSpace(string(b))}
}

func websiteRequest(h http.Handler, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	var text string
	if raw, ok := body.(string); ok {
		text = raw
	} else if body != nil {
		b, _ := json.Marshal(body)
		text = string(b)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(text))
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
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

func websiteSignIn(t *testing.T, f siteFixture) (*http.Cookie, string) {
	t.Helper()
	w := websiteRequest(f.handler, "POST", "/api/v1/session/login", map[string]string{"access_key": f.key}, nil, "")
	if w.Code != 200 {
		t.Fatalf("fixture sign in status %d", w.Code)
	}
	var s operator.Session
	if json.Unmarshal(w.Body.Bytes(), &s) != nil || !s.Authenticated || len(s.CSRFToken) != 43 {
		t.Fatal("invalid operator session DTO")
	}
	if strings.Contains(w.Body.String(), f.key) || len(w.Result().Cookies()) != 1 {
		t.Fatal("credential exposed or cookie missing")
	}
	return w.Result().Cookies()[0], s.CSRFToken
}

func siteResponse(t *testing.T, w *httptest.ResponseRecorder) sites.Site {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("website operation status %d: %s", w.Code, w.Body.String())
	}
	var s sites.Site
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil || len(s.ID) != 32 || s.Revision == 0 {
		t.Fatal("invalid website response")
	}
	return s
}

func TestWebsiteAuthenticationAndMutationBoundary(t *testing.T) {
	f := websiteFixture(t)
	id := strings.Repeat("a", 32)
	for _, path := range []string{"/api/v1/sites", "/api/v1/sites/" + id, "/api/v1/sites/" + id + "/files", "/api/v1/sites/" + id + "/file?path=index.html", "/api/v1/sites/" + id + "/backups"} {
		if w := websiteRequest(f.handler, "GET", path, nil, nil, ""); w.Code != 401 {
			t.Fatalf("unauthenticated website read %s status%d", path, w.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/sites", `{broken`, nil, ""); w.Code != 401 {
		t.Fatal("unauthenticated mutation parsed before admission")
	}
	c, csrf := websiteSignIn(t, f)
	for _, token := range []string{"", "wrong"} {
		if w := websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Denied", Domain: "denied.example"}, c, token); w.Code != 403 {
			t.Fatal("missing CSRF accepted")
		}
	}
	for _, origin := range []string{"", "http://foreign.invalid", "http://localhost:8080"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites", strings.NewReader(`{"name":"Denied","domain":"denied.example"}`))
		r.RemoteAddr = "127.0.0.1:14000"
		r.AddCookie(c)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("nonmatching Origin accepted")
		}
	}
	items, err := f.store.List()
	if err != nil || len(items) != 0 {
		t.Fatal("denied mutation changed storage")
	}
	for _, path := range []string{"/api/v1/budget", "/api/v1/trail", "/api/v1/status", "/api/v1/services", "/api/v1/server"} {
		if w := websiteRequest(f.handler, "POST", path, `{}`, c, csrf); w.Code != 405 {
			t.Fatal("unrelated API mutation enabled", path, w.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", "/json-api/createacct", `{}`, c, csrf); w.Code != 501 {
		t.Fatal("unimplemented cPanel route changed")
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/logout", `{}`, c, csrf); w.Code != 200 {
		t.Fatal("logout failed")
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/sites", nil, c, ""); w.Code != 401 {
		t.Fatal("logout replay exposed sites")
	}
}

func TestWebsiteActualCRUDBackupRestoreAndTrail(t *testing.T) {
	f := websiteFixture(t)
	c, csrf := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "GET", "/api/v1/sites", nil, c, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("empty site inventory not typed")
	}
	s := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Actual fixture", Domain: "fixture.example"}, c, csrf))
	if s.PreviewHost != "site-"+s.ID+".localhost" || s.State != "active" {
		t.Fatal("incorrect actual site metadata")
	}
	base := "/api/v1/sites/" + s.ID
	w = websiteRequest(f.handler, "GET", base+"/files", nil, c, "")
	var files siteFilesBody
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &files) != nil || len(files.Items) != 1 || files.Items[0].Path != "index.html" {
		t.Fatal("seed was not actually created")
	}
	w = websiteRequest(f.handler, "GET", base+"/file?path=index.html", nil, c, "")
	var seed sites.FileContent
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &seed) != nil || len(seed.SHA256) != 64 || seed.Content == "" || seed.Revision != s.Revision {
		t.Fatal("actual file read failed")
	}
	edit := sites.WriteInput{Path: "index.html", Content: "<h1>Actual saved fixture</h1>", ExpectedSHA256: seed.SHA256, ExpectedRevision: s.Revision}
	s = siteResponse(t, websiteRequest(f.handler, "PUT", base+"/file", edit, c, csrf))
	if w := websiteRequest(f.handler, "PUT", base+"/file", edit, c, csrf); w.Code != 409 {
		t.Fatal("stale revision did not conflict")
	}
	w = websiteRequest(f.handler, "POST", base+"/backups", backupBody{ExpectedRevision: s.Revision}, c, csrf)
	var backup sites.BackupInfo
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &backup) != nil || len(backup.ID) != 32 || len(backup.SHA256) != 64 || backup.Bytes <= 0 || backup.Files != 1 {
		t.Fatalf("actual backup failed status%d", w.Code)
	}
	// Refresh the actual current revision after backup; checkpoint bookkeeping
	// may legitimately advance the site revision.
	s = siteResponse(t, websiteRequest(f.handler, "GET", base, nil, c, ""))
	w = websiteRequest(f.handler, "GET", base+"/backups", nil, c, "")
	var backups siteBackupsBody
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &backups) != nil || len(backups.Items) != 1 || backups.Items[0].ID != backup.ID {
		t.Fatal("actual backup inventory missing")
	}
	s = siteResponse(t, websiteRequest(f.handler, "POST", base+"/state", sites.StateInput{State: "suspended", ExpectedRevision: s.Revision}, c, csrf))
	if s.State != "suspended" {
		t.Fatal("suspend not persisted")
	}
	s = siteResponse(t, websiteRequest(f.handler, "POST", base+"/state", sites.StateInput{State: "active", ExpectedRevision: s.Revision}, c, csrf))
	w = websiteRequest(f.handler, "GET", base+"/file?path=index.html", nil, c, "")
	var current sites.FileContent
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &current) != nil {
		t.Fatal("current file unavailable")
	}
	s = siteResponse(t, websiteRequest(f.handler, "PUT", base+"/file", sites.WriteInput{Path: "index.html", Content: "<h1>Second saved fixture</h1>", ExpectedSHA256: current.SHA256, ExpectedRevision: s.Revision}, c, csrf))
	s = siteResponse(t, websiteRequest(f.handler, "POST", base+"/restore", sites.RestoreInput{BackupID: backup.ID, ExpectedRevision: s.Revision}, c, csrf))
	w = websiteRequest(f.handler, "GET", base+"/file?path=index.html", nil, c, "")
	var restored sites.FileContent
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &restored) != nil || restored.Content != edit.Content || restored.Revision != s.Revision {
		t.Fatal("backup did not restore actual content")
	}
	entries, err := f.journal.List()
	if err != nil || len(entries) < 6 {
		t.Fatal("website changes lack actual scoped trail")
	}
}

func TestWebsiteSafeStrictRequestErrorsAndUnavailableStores(t *testing.T) {
	f := websiteFixture(t)
	c, csrf := websiteSignIn(t, f)
	secret := "SENSITIVE-FIXTURE-NOT-A-CREDENTIAL"
	for _, body := range []string{
		`{"name":"` + secret + `","domain":`,
		`{"name":"` + secret + `","domain":"fixture.example","unknown":true}`,
		`{"name":"` + secret + `","name":"duplicate","domain":"fixture.example"}`,
		`{"name":"` + secret + `","domain":"fixture.example"} {}`,
		`null`, ` `,
	} {
		w := websiteRequest(f.handler, "POST", "/api/v1/sites", body, c, csrf)
		if w.Code != 400 || strings.Contains(w.Body.String(), secret) || !strings.Contains(w.Body.String(), `"detail"`) {
			t.Fatal("malformed JSON did not fail safely", w.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/sites", strings.Repeat("a", 4097), c, csrf); w.Code != 413 {
		t.Fatal("create request bytes unbounded")
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites", strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:14000"
	r.AddCookie(c)
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal("non-JSON mutation accepted")
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Invalid", Domain: "http://bad.example/path"}, c, csrf); w.Code != 422 || strings.Contains(w.Body.String(), "http://bad.example/path") {
		t.Fatal("invalid domain echoed or accepted")
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/sites/"+strings.Repeat("a", 32), nil, c, ""); w.Code != 404 {
		t.Fatal("missing website not 404")
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/sites/"+strings.Repeat("a", 32)+"/file?path=..%2Faccess.key", nil, c, ""); w.Code != 404 && w.Code != 422 {
		t.Fatal("traversal request escaped validation")
	}
	if w := websiteRequest(New(Options{AllowedOrigins: []string{"http://127.0.0.1:8080"}}), "GET", "/api/v1/sites", nil, nil, ""); w.Code != 503 {
		t.Fatal("missing auth produced fake success")
	}
	h := New(Options{Operator: f.manager, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	if w := websiteRequest(h, "GET", "/api/v1/sites", nil, c, ""); w.Code != 503 {
		t.Fatal("missing storage produced fake success")
	}
	if w := websiteRequest(h, "GET", "/api/v1/sites", nil, nil, ""); w.Code != 401 {
		t.Fatal("missing storage bypassed auth")
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/sites/"+strings.Repeat("a", 32)+"/file?path="+strings.Repeat("x", 513), nil, c, ""); w.Code != 422 {
		t.Fatal("file query path unbounded")
	}
}
