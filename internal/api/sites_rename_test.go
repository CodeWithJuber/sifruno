package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sifruno/internal/sites"
	"strings"
	"testing"
)

func TestSiteRenameStrictAdmissionAndHTTP(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site, err := f.store.Create(sites.CreateInput{Name: "Rename", Domain: "rename.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := f.store.Files(site.ID)
	input := sites.RenameInput{Path: "index.html", Destination: "pages/home.html", ExpectedSHA256: files[0].SHA256, ExpectedRevision: site.Revision}
	endpoint := "/api/v1/sites/" + site.ID + "/rename"
	before := siteAdmissionSnapshot(t, f)
	if w := websiteRequest(f.handler, "POST", endpoint, "{broken", nil, ""); w.Code != 401 {
		t.Fatal("auth", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", endpoint, input, cookie, ""); w.Code != 403 {
		t.Fatal("csrf", w.Code)
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+endpoint, strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:14000"
	r.AddCookie(cookie)
	r.Header.Set("Origin", "http://evil.test")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("origin", w.Code)
	}
	raw, _ := json.Marshal(input)
	for _, bad := range []string{`{}`, `null`, `[]`, `{"path":"index.html"}`, strings.Replace(string(raw), `"destination":`, `"Destination":`, 1), strings.Replace(string(raw), `"destination":"pages/home.html"`, `"destination":null`, 1), strings.Replace(string(raw), `"expected_revision":1`, `"expected_revision":null`, 1), strings.Replace(string(raw), `"expected_revision":1`, `"expected_revision":"1"`, 1), strings.Replace(string(raw), `"path":"index.html"`, `"path":"index.html","path":"other.html"`, 1), string(raw[:len(raw)-1]) + `,"site_id":"other"}`, string(raw) + ` {}`} {
		if w := websiteRequest(f.handler, "POST", endpoint, bad, cookie, csrf); w.Code != 400 {
			t.Fatal("strict admission", w.Code, bad)
		}
		if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
			t.Fatal("refusal mutated state")
		}
	}
	if w := websiteRequest(f.handler, "POST", endpoint, strings.Repeat(" ", 4097), cookie, csrf); w.Code != 413 {
		t.Fatal("limit", w.Code)
	}
	for _, kind := range []string{"stale", "hash", "noop", "traversal", "missing"} {
		bad := input
		want := 409
		switch kind {
		case "stale":
			bad.ExpectedRevision++
		case "hash":
			bad.ExpectedSHA256 = strings.Repeat("0", 64)
		case "noop":
			bad.Destination = bad.Path
			want = 422
		case "traversal":
			bad.Destination = "../escape.html"
			want = 422
		case "missing":
			bad.Path = "missing.html"
			want = 404
		}
		if w := websiteRequest(f.handler, "POST", endpoint, bad, cookie, csrf); w.Code != want {
			t.Fatal(kind, w.Code)
		}
		if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
			t.Fatal("refusal mutated state")
		}
	}
	file, _ := f.store.ReadFile(site.ID, input.Path)
	next := siteResponse(t, websiteRequest(f.handler, "POST", endpoint, input, cookie, csrf))
	if next.Revision != site.Revision+1 || next.ID != site.ID || next.Domain != site.Domain || next.State != site.State {
		t.Fatal("identity/revision")
	}
	for _, path := range []string{"/index.html", "/pages/home.html", "/"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = site.PreviewHost
		w := httptest.NewRecorder()
		f.store.Handler().ServeHTTP(w, r)
		if path == "/pages/home.html" {
			if w.Code != 200 || w.Body.String() != file.Content {
				t.Fatal("moved HTTP bytes", w.Code)
			}
		} else if w.Code != 404 {
			t.Fatal("old HTTP URL", path, w.Code)
		}
	}
	after := siteAdmissionSnapshot(t, f)
	if w := websiteRequest(f.handler, "POST", endpoint, input, cookie, csrf); w.Code != 409 {
		t.Fatal("replay", w.Code)
	}
	if !bytes.Equal(after, siteAdmissionSnapshot(t, f)) {
		t.Fatal("replay mutated state")
	}
	spec := httptest.NewRecorder()
	f.handler.ServeHTTP(spec, httptest.NewRequest("GET", "http://127.0.0.1:8080/openapi.json", nil))
	var doc map[string]any
	if json.Unmarshal(spec.Body.Bytes(), &doc) != nil || doc["paths"].(map[string]any)["/api/v1/sites/{id}/rename"] == nil {
		t.Fatal("schema")
	}
}

func TestSiteRenameRevokedDuringBody(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site, err := f.store.Create(sites.CreateInput{Name: "Rename", Domain: "rename.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := f.store.Files(site.ID)
	before := siteAdmissionSnapshot(t, f)
	body := &siteAdmissionBody{Reader: strings.NewReader(fmt.Sprintf(`{"path":"index.html","destination":"moved.html","expected_revision":%d,"expected_sha256":"%s"}`, site.Revision, files[0].SHA256)), entered: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites/"+site.ID+"/rename", body)
	r.RemoteAddr = "127.0.0.1:14000"
	r.AddCookie(cookie)
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); f.handler.ServeHTTP(w, r) }()
	<-body.entered
	if logout := websiteRequest(f.handler, "POST", "/api/v1/session/logout", `{}`, cookie, csrf); logout.Code != 200 {
		t.Fatal("logout", logout.Code)
	}
	close(body.release)
	<-done
	if w.Code != 401 {
		t.Fatal("late auth", w.Code)
	}
	if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
		t.Fatal("revocation mutated state")
	}
}
