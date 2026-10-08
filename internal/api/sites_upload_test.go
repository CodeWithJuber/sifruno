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

func TestSiteUploadStrictAdmissionAndBinary(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site, err := f.store.Create(sites.CreateInput{Name: "Upload", Domain: "upload.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "/api/v1/sites/" + site.ID + "/upload"
	input := sites.UploadInput{Path: "assets/pixel.png", Content: []byte{137, 80, 78, 71, 0, 255, 128}, ExpectedRevision: site.Revision}
	if w := websiteRequest(f.handler, "POST", endpoint, "{broken", nil, ""); w.Code != 401 {
		t.Fatal("auth", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", endpoint, input, cookie, ""); w.Code != 403 {
		t.Fatal("csrf", w.Code)
	}
	before := siteAdmissionSnapshot(t, f)
	for _, raw := range []string{`{}`, `null`, `[]`, `{"path":"x.png","content":"AA=="}`, `{"path":"x.png","content":null,"expected_revision":1}`, `{"path":"x.png","content":[0],"expected_revision":1}`, `{"path":"x.png","content":"!bad","expected_revision":1}`, `{"Path":"x.png","content":"AA==","expected_revision":1}`, `{"path":"x.png","path":"y.png","content":"AA==","expected_revision":1}`, `{"path":"x.png","content":"AA==","expected_revision":null}`, `{"path":"x.png","content":"AA==","expected_revision":1,"extra":true}`, `{"path":"x.png","content":"AA==","expected_revision":1} {}`} {
		if w := websiteRequest(f.handler, "POST", endpoint, raw, cookie, csrf); w.Code != 400 {
			t.Fatal("strict body", w.Code)
		}
		if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
			t.Fatal("bad body mutated store")
		}
	}
	if w := websiteRequest(f.handler, "POST", endpoint, strings.Repeat(" ", ((sites.MaxFileBytes+2)/3)*4+8193), cookie, csrf); w.Code != 413 {
		t.Fatal("body limit", w.Code)
	}
	tooBig := input
	tooBig.Content = make([]byte, sites.MaxFileBytes+1)
	if w := websiteRequest(f.handler, "POST", endpoint, tooBig, cookie, csrf); w.Code != 422 {
		t.Fatal("decoded file limit", w.Code)
	}
	if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
		t.Fatal("oversize mutated store")
	}
	next := siteResponse(t, websiteRequest(f.handler, "POST", endpoint, input, cookie, csrf))
	if next.Revision != site.Revision+1 {
		t.Fatal("revision")
	}
	r := httptest.NewRequest("GET", "/"+input.Path, nil)
	r.Host = site.PreviewHost
	w := httptest.NewRecorder()
	f.store.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), input.Content) {
		t.Fatal("binary HTTP bytes", w.Code)
	}
	input.ExpectedRevision = next.Revision
	if w := websiteRequest(f.handler, "POST", endpoint, input, cookie, csrf); w.Code != 409 {
		t.Fatal("overwrite", w.Code)
	}
	input.Path = "new.png"
	input.ExpectedRevision = site.Revision
	if w := websiteRequest(f.handler, "POST", endpoint, input, cookie, csrf); w.Code != 409 {
		t.Fatal("stale", w.Code)
	}
	got, _ := f.store.Get(site.ID)
	if got != next {
		t.Fatal("refusal revision changed")
	}
}

func TestSiteUploadRevokedDuringBody(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site, err := f.store.Create(sites.CreateInput{Name: "Upload", Domain: "upload.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	before := siteAdmissionSnapshot(t, f)
	body := &siteAdmissionBody{Reader: strings.NewReader(fmt.Sprintf(`{"path":"x.png","content":"AA==","expected_revision":%d}`, site.Revision)), entered: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites/"+site.ID+"/upload", body)
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
		t.Fatal("late auth accepted", w.Code)
	}
	if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
		t.Fatal("revoked request mutated store")
	}
}

func TestSiteUploadSchema(t *testing.T) {
	f := websiteFixture(t)
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080/openapi.json", nil)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	var doc map[string]any
	if json.Unmarshal(w.Body.Bytes(), &doc) != nil {
		t.Fatal("spec")
	}
	paths, _ := doc["paths"].(map[string]any)
	if paths["/api/v1/sites/{id}/upload"] == nil {
		t.Fatal("upload missing from contract")
	}
}
