package api

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"sifruno/internal/sites"
	"strings"
	"testing"
)

func TestSiteReplacementStrictAdmissionAndBinary(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site, err := f.store.Create(sites.CreateInput{Name: "Replace", Domain: "replace.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, err := f.store.Files(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "/api/v1/sites/" + site.ID + "/upload"
	input := sites.ReplaceInput{Path: "index.html", Content: []byte{0, 255, 128, 42}, ExpectedSHA256: files[0].SHA256, ExpectedRevision: site.Revision}
	if w := websiteRequest(f.handler, "PUT", endpoint, "{broken", nil, ""); w.Code != 401 {
		t.Fatal("auth", w.Code)
	}
	if w := websiteRequest(f.handler, "PUT", endpoint, input, cookie, ""); w.Code != 403 {
		t.Fatal("csrf", w.Code)
	}
	r := httptest.NewRequest("PUT", "http://127.0.0.1:8080"+endpoint, strings.NewReader(`{}`))
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
	before := siteAdmissionSnapshot(t, f)
	for _, raw := range []string{`{}`, `null`, `[]`, `{"path":"index.html","content":"AA==","expected_revision":1}`, `{"path":"index.html","content":[0],"expected_revision":1,"expected_sha256":"` + input.ExpectedSHA256 + `"}`, `{"path":"index.html","content":null,"expected_revision":1,"expected_sha256":"` + input.ExpectedSHA256 + `"}`, `{"path":"index.html","content":"AA==","expected_revision":1,"expected_sha256":null}`, `{"path":"index.html","content":"!bad","expected_revision":1,"expected_sha256":"` + input.ExpectedSHA256 + `"}`, `{"path":"index.html","path":"x.png","content":"AA==","expected_revision":1,"expected_sha256":"` + input.ExpectedSHA256 + `"}`, `{"path":"index.html","content":"AA==","expected_revision":1,"expected_sha256":"` + input.ExpectedSHA256 + `","extra":true}`} {
		if w := websiteRequest(f.handler, "PUT", endpoint, raw, cookie, csrf); w.Code != 400 {
			t.Fatal("strict", w.Code)
		}
		if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
			t.Fatal("strict mutation")
		}
	}
	for _, kind := range []string{"hash", "stale", "missing", "oversize"} {
		bad := input
		want := 409
		switch kind {
		case "hash":
			bad.ExpectedSHA256 = strings.Repeat("0", 64)
		case "stale":
			bad.ExpectedRevision++
		case "missing":
			bad.Path = "missing.png"
		case "oversize":
			bad.Content = make([]byte, sites.MaxFileBytes+1)
			want = 422
		}
		if w := websiteRequest(f.handler, "PUT", endpoint, bad, cookie, csrf); w.Code != want {
			t.Fatal(kind, w.Code)
		}
		if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
			t.Fatal("refusal mutation")
		}
	}
	next := siteResponse(t, websiteRequest(f.handler, "PUT", endpoint, input, cookie, csrf))
	if next.Revision != site.Revision+1 {
		t.Fatal("revision")
	}
	served := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/index.html", nil)
	request.Host = site.PreviewHost
	f.store.Handler().ServeHTTP(served, request)
	if served.Code != 200 || !bytes.Equal(served.Body.Bytes(), input.Content) {
		t.Fatal("binary serving", served.Code)
	}
	if w := websiteRequest(f.handler, "POST", endpoint, input, cookie, csrf); w.Code != 400 {
		t.Fatal("create accepted hash", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", endpoint, sites.UploadInput{Path: input.Path, Content: input.Content, ExpectedRevision: next.Revision}, cookie, csrf); w.Code != 409 {
		t.Fatal("create overwrote", w.Code)
	}
}
func TestSiteReplacementRevokedDuringBody(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site, err := f.store.Create(sites.CreateInput{Name: "Replace", Domain: "replace.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := f.store.Files(site.ID)
	before := siteAdmissionSnapshot(t, f)
	body := &siteAdmissionBody{Reader: strings.NewReader(fmt.Sprintf(`{"path":"index.html","content":"AA==","expected_revision":%d,"expected_sha256":"%s"}`, site.Revision, files[0].SHA256)), entered: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequest("PUT", "http://127.0.0.1:8080/api/v1/sites/"+site.ID+"/upload", body)
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
		t.Fatal("revoked mutation")
	}
}
