package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sifruno/internal/sites"
)

type importPart struct{ name, filename, content string }

func transferRequest(f siteFixture, c *http.Cookie, csrf string, parts []importPart) *httptest.ResponseRecorder {
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
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites/import", &body)
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("X-CSRF-Token", csrf)
	if c != nil {
		r.AddCookie(c)
	}
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, r)
	return out
}
func TestSiteTransferActualExportImport(t *testing.T) {
	f := websiteFixture(t)
	c, csrf := websiteSignIn(t, f)
	s := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Source", Domain: "source.example"}, c, csrf))
	file, err := f.store.ReadFile(s.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	s = siteResponse(t, websiteRequest(f.handler, "PUT", "/api/v1/sites/"+s.ID+"/file", sites.WriteInput{Path: "index.html", Content: "<h1>Transferred real content</h1>", ExpectedSHA256: file.SHA256, ExpectedRevision: s.Revision}, c, csrf))
	b, err := f.store.Backup(s.ID, s.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	// Export and import cross an actual loopback HTTP socket. Preserve the
	// admitted panel Host/Origin while dialing the isolated ephemeral fixture.
	server := httptest.NewServer(f.handler)
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	f.handler = http.HandlerFunc(func(out http.ResponseWriter, request *http.Request) {
		forward := request.Clone(request.Context())
		forward.URL.Scheme, forward.URL.Host = endpoint.Scheme, endpoint.Host
		forward.RequestURI = ""
		response, err := server.Client().Do(forward)
		if err != nil {
			t.Fatal("fixture HTTP transport failed")
		}
		defer response.Body.Close()
		for name, values := range response.Header {
			for _, value := range values {
				out.Header().Add(name, value)
			}
		}
		out.WriteHeader(response.StatusCode)
		_, _ = io.Copy(out, response.Body)
	})
	path := "/api/v1/sites/" + s.ID + "/backups/" + b.ID + "/download"
	if w := websiteRequest(f.handler, "GET", path, nil, nil, ""); w.Code != 401 {
		t.Fatal("export unauthenticated", w.Code)
	}
	w := websiteRequest(f.handler, "GET", path, nil, c, "")
	hash := sha256.Sum256(w.Body.Bytes())
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" || hex.EncodeToString(hash[:]) != b.SHA256 || w.Header().Get("Content-Disposition") != `attachment; filename="sifruno-site.zip"` {
		t.Fatal("export bytes or headers invalid", w.Code)
	}
	archive := w.Body.String()
	imported := siteResponse(t, transferRequest(f, c, csrf, []importPart{{name: "name", content: "Imported"}, {name: "domain", content: "imported.example"}, {name: "archive", filename: "native.zip", content: archive}}))
	got, err := f.store.ReadFile(imported.ID, "index.html")
	if err != nil || got.Content != "<h1>Transferred real content</h1>" || imported.ID == s.ID {
		t.Fatal("actual persisted content not imported")
	}
	items, err := f.store.List()
	if err != nil || len(items) != 2 {
		t.Fatal("import inventory not persisted")
	}
	w = websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	var spec map[string]any
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil || !strings.Contains(w.Body.String(), "multipart/form-data") || !strings.Contains(w.Body.String(), "download-site-backup") {
		t.Fatal("transfer spec absent")
	}
}

type panicReadBody struct{}

func (panicReadBody) Read([]byte) (int, error) { panic("body read before authorization") }
func (panicReadBody) Close() error             { return nil }
func TestSiteTransferAdmissionBeforeBodyRead(t *testing.T) {
	f := websiteFixture(t)
	c, csrf := websiteSignIn(t, f)
	cases := []struct {
		cookie        *http.Cookie
		token, origin string
		status        int
	}{{nil, csrf, "http://127.0.0.1:8080", 401}, {c, "", "http://127.0.0.1:8080", 403}, {c, csrf, "", 403}, {c, csrf, "http://foreign.invalid", 403}}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites/import", nil)
		r.Body = panicReadBody{}
		r.RemoteAddr = "127.0.0.1:14000"
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-CSRF-Token", tc.token)
		r.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		if tc.cookie != nil {
			r.AddCookie(tc.cookie)
		}
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal("admission status", w.Code)
		}
	}
}
func TestSiteTransferMaliciousMultipart(t *testing.T) {
	f := websiteFixture(t)
	c, csrf := websiteSignIn(t, f)
	normal := []importPart{{name: "name", content: "Fixture"}, {name: "domain", content: "fixture.example"}, {name: "archive", filename: "native.zip", content: "CORRUPT-SENSITIVE-FIXTURE"}}
	cases := []struct {
		parts  []importPart
		status int
	}{{normal, 422}, {normal[:2], 400}, {append(append([]importPart{}, normal...), normal[0]), 400}, {append(append([]importPart{}, normal...), importPart{name: "unknown", content: "secret"}), 400}, {[]importPart{{name: "name", filename: "bad", content: "Fixture"}, normal[1], normal[2]}, 400}, {[]importPart{normal[0], normal[1], {name: "archive", content: "bad"}}, 400}, {[]importPart{normal[0], normal[1], {name: "archive", filename: "native.zip"}}, 400}, {[]importPart{{name: "name", content: strings.Repeat("é", 41)}, normal[1], normal[2]}, 413}, {[]importPart{{name: "name", content: string([]byte{255})}, normal[1], normal[2]}, 400}, {[]importPart{normal[0], normal[1], {name: "archive", filename: "native.zip", content: strings.Repeat("x", maxTransferArchive+1)}}, 413}}
	for _, tc := range cases {
		w := transferRequest(f, c, csrf, tc.parts)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "CORRUPT-SENSITIVE-FIXTURE") {
			t.Fatal("unsafe multipart", w.Code, "wanted", tc.status)
		}
	}
	for _, ct := range []string{"application/json", "multipart/form-data", "multipart/form-data; boundary=x"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites/import", strings.NewReader("bad"))
		r.RemoteAddr = "127.0.0.1:14000"
		r.AddCookie(c)
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", ct)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 415 {
			t.Fatal("malformed admitted", w.Code)
		}
	}
	items, err := f.store.List()
	if err != nil || len(items) != 0 {
		t.Fatal("rejected archive mutated inventory")
	}
}

type blockingImportBody struct{ entered, release chan struct{} }

func (b *blockingImportBody) Read([]byte) (int, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return 0, io.EOF
}
func (b *blockingImportBody) Close() error { return nil }
func TestSiteTransferConcurrencyBound(t *testing.T) {
	f := websiteFixture(t)
	c, csrf := websiteSignIn(t, f)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	finished := make(chan int, 2)
	makeRequest := func(body io.ReadCloser) *http.Request {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites/import", nil)
		r.Body = body
		r.RemoteAddr = "127.0.0.1:14000"
		r.AddCookie(c)
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", "multipart/form-data; boundary=fixture")
		return r
	}
	for range 2 {
		go func() {
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, makeRequest(&blockingImportBody{entered, release}))
			finished <- w.Code
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("transfer did not begin")
		}
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, makeRequest(panicReadBody{}))
	if w.Code != 503 {
		close(release)
		t.Fatal("third transfer admitted", w.Code)
	}
	close(release)
	for range 2 {
		if code := <-finished; code != 400 {
			t.Fatal("truncated blocked request status", code)
		}
	}
}
