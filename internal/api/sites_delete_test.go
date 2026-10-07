package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sifruno/internal/sites"
)

func TestWebsiteDeleteAuthenticationAndStrictBody(t *testing.T) {
	f := websiteFixture(t)
	site, err := f.store.Create(sites.CreateInput{Name: "Delete guards", Domain: "delete-guards.example"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	file, err := f.store.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/sites/" + site.ID + "/file"
	input := sites.DeleteInput{Path: file.Path, ExpectedSHA256: file.SHA256, ExpectedRevision: site.Revision}
	if w := websiteRequest(f.handler, "DELETE", path, `{broken`, nil, ""); w.Code != 401 {
		t.Fatal("unauthenticated deletion parsed before admission", w.Code)
	}
	cookie, csrf := websiteSignIn(t, f)
	for _, token := range []string{"", "wrong"} {
		if w := websiteRequest(f.handler, "DELETE", path, input, cookie, token); w.Code != 403 {
			t.Fatal("delete CSRF guard", w.Code)
		}
	}
	for _, origin := range []string{"", "http://foreign.invalid"} {
		body, _ := json.Marshal(input)
		r := httptest.NewRequest("DELETE", "http://127.0.0.1:8080"+path, strings.NewReader(string(body)))
		r.RemoteAddr = "127.0.0.1:14000"
		r.AddCookie(cookie)
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("delete Origin guard", w.Code)
		}
	}
	for _, body := range []string{`{broken`, `null`, `{"path":"index.html","content":"must not be accepted"}`, `{"path":"index.html","path":"duplicate.txt"}`, `{}`} {
		w := websiteRequest(f.handler, "DELETE", path, body, cookie, csrf)
		want := 400
		if body == `{}` {
			want = 422
		}
		if w.Code != want || strings.Contains(w.Body.String(), "must not be accepted") {
			t.Fatal("strict deletion body", w.Code)
		}
	}
	if w := websiteRequest(f.handler, "DELETE", path, strings.Repeat("x", 4097), cookie, csrf); w.Code != 413 {
		t.Fatal("delete body unbounded", w.Code)
	}
	badPath := input
	badPath.Path = "../index.html"
	if w := websiteRequest(f.handler, "DELETE", path, badPath, cookie, csrf); w.Code != 422 {
		t.Fatal("traversal deletion accepted", w.Code)
	}
	if w := websiteRequest(f.handler, "DELETE", "/api/v1/sites/"+site.ID+"/files", input, cookie, csrf); w.Code != 405 {
		t.Fatal("directory inventory deletion enabled", w.Code)
	}
	if actual, err := f.store.ReadFile(site.ID, file.Path); err != nil || actual != file {
		t.Fatal("refused deletion changed storage", err)
	}
}

func TestWebsiteDeleteCASServingAndBackupRestore(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Delete roundtrip", Domain: "delete-roundtrip.example"}, cookie, csrf))
	base := "/api/v1/sites/" + site.ID
	w := websiteRequest(f.handler, "GET", base+"/file?path=index.html", nil, cookie, "")
	var original sites.FileContent
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &original) != nil {
		t.Fatal("seed file read", w.Code)
	}
	w = websiteRequest(f.handler, "POST", base+"/backups", backupBody{ExpectedRevision: site.Revision}, cookie, csrf)
	var backup sites.BackupInfo
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &backup) != nil {
		t.Fatal("backup before deletion", w.Code)
	}
	site = siteResponse(t, websiteRequest(f.handler, "GET", base, nil, cookie, ""))
	site = siteResponse(t, websiteRequest(f.handler, "PUT", base+"/file", sites.WriteInput{Path: "assets/keep.txt", Content: "keep this file", ExpectedRevision: site.Revision}, cookie, csrf))
	input := sites.DeleteInput{Path: original.Path, ExpectedSHA256: original.SHA256, ExpectedRevision: site.Revision}
	for _, bad := range []sites.DeleteInput{
		{Path: original.Path, ExpectedSHA256: original.SHA256, ExpectedRevision: site.Revision - 1},
		{Path: original.Path, ExpectedSHA256: strings.Repeat("0", 64), ExpectedRevision: site.Revision},
	} {
		if w := websiteRequest(f.handler, "DELETE", base+"/file", bad, cookie, csrf); w.Code != 409 {
			t.Fatal("delete CAS guard", w.Code)
		}
	}
	before := site.Revision
	site = siteResponse(t, websiteRequest(f.handler, "DELETE", base+"/file", input, cookie, csrf))
	if site.Revision != before+1 {
		t.Fatal("delete response revision", site.Revision)
	}
	if w := websiteRequest(f.handler, "DELETE", base+"/file", input, cookie, csrf); w.Code != 409 {
		t.Fatal("stale delete replay accepted", w.Code)
	}
	if w := websiteRequest(f.handler, "GET", base+"/file?path=index.html", nil, cookie, ""); w.Code != 404 {
		t.Fatal("deleted file API read", w.Code)
	}
	w = websiteRequest(f.handler, "GET", base+"/files", nil, cookie, "")
	var files siteFilesBody
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &files) != nil || len(files.Items) != 1 || files.Items[0].Path != "assets/keep.txt" {
		t.Fatal("delete did not refresh actual catalog", w.Code)
	}
	serve := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = site.PreviewHost
		w := httptest.NewRecorder()
		f.store.Handler().ServeHTTP(w, r)
		return w
	}
	if w := serve("/"); w.Code != http.StatusNotFound {
		t.Fatal("deleted index still served", w.Code)
	}
	if w := serve("/assets/keep.txt"); w.Code != 200 || w.Body.String() != "keep this file" {
		t.Fatal("delete changed another served file", w.Code)
	}
	site = siteResponse(t, websiteRequest(f.handler, "POST", base+"/restore", sites.RestoreInput{BackupID: backup.ID, ExpectedRevision: site.Revision}, cookie, csrf))
	if w := serve("/"); w.Code != 200 || w.Body.String() != original.Content {
		t.Fatal("backup did not return actual served bytes", w.Code)
	}
	if f.journal.Verify() != nil {
		t.Fatal("signed delete/restore history invalid")
	}
}
