package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"sifruno/internal/sites"
)

func TestWebsiteDomainAuthenticationAndRequestGuards(t *testing.T) {
	f := websiteFixture(t)
	site, err := f.store.Create(sites.CreateInput{Name: "Domain guards", Domain: "domain-guards.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/sites/" + site.ID + "/domain"
	input := sites.DomainInput{Domain: "changed.test", ExpectedRevision: site.Revision}
	if w := websiteRequest(f.handler, "PUT", path, `{broken`, nil, ""); w.Code != 401 {
		t.Fatal("domain body parsed before authentication", w.Code)
	}
	cookie, csrf := websiteSignIn(t, f)
	for _, token := range []string{"", "wrong"} {
		if w := websiteRequest(f.handler, "PUT", path, input, cookie, token); w.Code != 403 {
			t.Fatal("domain CSRF guard", w.Code)
		}
	}
	for _, row := range []struct {
		origin, contentType string
		status              int
	}{
		{"", "application/json", 403},
		{"http://foreign.invalid", "application/json", 403},
		{"http://127.0.0.1:8080", "text/plain", 415},
	} {
		r := httptest.NewRequest("PUT", "http://127.0.0.1:8080"+path, strings.NewReader(`{"domain":"changed.test","expected_revision":1}`))
		r.RemoteAddr = "127.0.0.1:14000"
		r.AddCookie(cookie)
		r.Header.Set("Origin", row.origin)
		r.Header.Set("Content-Type", row.contentType)
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != row.status {
			t.Fatal("domain Origin/content-type guard", w.Code)
		}
	}
	for _, body := range []string{`{broken`, `null`, `{"domain":"changed.test","domain":"duplicate.test","expected_revision":1}`, `{"domain":"changed.test","expected_revision":1,"unknown":true}`} {
		if w := websiteRequest(f.handler, "PUT", path, body, cookie, csrf); w.Code != 400 {
			t.Fatal("domain body not strict", w.Code)
		}
	}
	if w := websiteRequest(f.handler, "PUT", path, strings.Repeat("x", 4097), cookie, csrf); w.Code != 413 {
		t.Fatal("domain body not bounded", w.Code)
	}
	if w := websiteRequest(f.handler, "PUT", path, sites.DomainInput{Domain: "http://bad.test/path", ExpectedRevision: site.Revision}, cookie, csrf); w.Code != 422 {
		t.Fatal("invalid domain accepted", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", path, input, cookie, csrf); w.Code != 405 {
		t.Fatal("domain mutation expanded to POST", w.Code)
	}
	if current, err := f.store.Get(site.ID); err != nil || current != site {
		t.Fatal("refused domain request changed storage", current, err)
	}
}

func TestWebsiteDomainCASNoOpAndActualRouting(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Domain routing", Domain: "old-domain.test"}, cookie, csrf))
	other := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Reserved", Domain: "reserved.test"}, cookie, csrf))
	path := "/api/v1/sites/" + site.ID + "/domain"
	for _, bad := range []sites.DomainInput{{Domain: "new-domain.test", ExpectedRevision: 0}, {Domain: strings.ToUpper(other.Domain), ExpectedRevision: site.Revision}} {
		if w := websiteRequest(f.handler, "PUT", path, bad, cookie, csrf); w.Code != 409 {
			t.Fatal("domain stale/duplicate guard", w.Code)
		}
	}
	if actual := siteResponse(t, websiteRequest(f.handler, "PUT", path, sites.DomainInput{Domain: strings.ToUpper(site.Domain), ExpectedRevision: site.Revision}, cookie, csrf)); actual != site {
		t.Fatal("same canonical domain was not a no-op", actual)
	}
	file, err := f.store.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	before := site
	site = siteResponse(t, websiteRequest(f.handler, "PUT", path, sites.DomainInput{Domain: "BÜCHER.test", ExpectedRevision: site.Revision}, cookie, csrf))
	if site.Domain != "xn--bcher-kva.test" || site.Revision != before.Revision+1 || site.ID != before.ID || site.PreviewHost != before.PreviewHost || site.State != before.State {
		t.Fatal("domain response contract", site)
	}
	if w := websiteRequest(f.handler, "PUT", path, sites.DomainInput{Domain: site.Domain, ExpectedRevision: before.Revision}, cookie, csrf); w.Code != 409 {
		t.Fatal("stale same-domain request accepted", w.Code)
	}
	for _, row := range []struct {
		host   string
		status int
	}{{before.Domain, 404}, {site.Domain, 200}, {site.PreviewHost, 200}} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = row.host
		w := httptest.NewRecorder()
		f.store.Handler().ServeHTTP(w, r)
		if w.Code != row.status || (row.status == 200 && w.Body.String() != file.Content) {
			t.Fatal("actual domain routing", row.host, w.Code)
		}
	}
}

// A domain another website uses answers 409 with its own error code, so the
// panel does not report it as a changed revision; a stale revision has none.
func TestWebsiteDomainTakenHasItsOwnErrorCode(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	code := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		var problem struct {
			Status int    `json:"status"`
			Error  string `json:"error"`
		}
		if w.Code != 409 || json.Unmarshal(w.Body.Bytes(), &problem) != nil || problem.Status != 409 {
			t.Fatalf("want a 409 problem, got %d: %s", w.Code, w.Body.String())
		}
		return problem.Error
	}
	first := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "First", Domain: "taken.test"}, cookie, csrf))
	if got := code(websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Second", Domain: "TAKEN.test"}, cookie, csrf)); got != "domain_taken" {
		t.Fatalf("duplicate create code %q", got)
	}
	second := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Second", Domain: "free.test"}, cookie, csrf))
	path := "/api/v1/sites/" + second.ID + "/domain"
	if got := code(websiteRequest(f.handler, "PUT", path, sites.DomainInput{Domain: first.Domain, ExpectedRevision: second.Revision}, cookie, csrf)); got != "domain_taken" {
		t.Fatalf("duplicate domain change code %q", got)
	}
	if got := code(websiteRequest(f.handler, "PUT", path, sites.DomainInput{Domain: "other.test", ExpectedRevision: second.Revision + 1}, cookie, csrf)); got != "" {
		t.Fatalf("stale revision carried code %q", got)
	}
}
