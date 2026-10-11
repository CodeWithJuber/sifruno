package api

import (
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"sifruno/internal/sites"
)

func TestWebsiteNameAuthenticationAndExactRequestGuards(t *testing.T) {
	f := websiteFixture(t)
	site, err := f.store.Create(sites.CreateInput{Name: "Name guards", Domain: "name-guards.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/sites/" + site.ID + "/name"
	input := sites.NameInput{Name: "Changed name", ExpectedRevision: site.Revision}
	if w := websiteRequest(f.handler, "PUT", path, `{broken`, nil, ""); w.Code != 401 {
		t.Fatal("name body parsed before authentication", w.Code)
	}
	cookie, csrf := websiteSignIn(t, f)
	for _, token := range []string{"", "wrong"} {
		if w := websiteRequest(f.handler, "PUT", path, input, cookie, token); w.Code != 403 {
			t.Fatal("name CSRF guard", w.Code)
		}
	}
	for _, row := range []struct {
		origin, contentType string
		status              int
	}{
		{"", "application/json", 403}, {"http://foreign.invalid", "application/json", 403}, {"http://127.0.0.1:8080", "text/plain", 415},
	} {
		r := httptest.NewRequest("PUT", "http://127.0.0.1:8080"+path, strings.NewReader(`{"name":"Changed name","expected_revision":1}`))
		r.RemoteAddr = "127.0.0.1:14000"
		r.AddCookie(cookie)
		r.Header.Set("Origin", row.origin)
		r.Header.Set("Content-Type", row.contentType)
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != row.status {
			t.Fatal("name Origin/content-type guard", w.Code)
		}
	}
	for _, body := range []string{
		`{broken`, `null`, `[]`, `{"name":"Changed name","name":"duplicate","expected_revision":1}`, `{"name":"Changed name","expected_revision":1,"unknown":true}`,
		`{"name":"Changed name"}`, `{"expected_revision":1}`, `{"name":null,"expected_revision":1}`, `{"name":"Changed name","expected_revision":null}`,
		`{"name":42,"expected_revision":1}`, `{"name":"Changed name","expected_revision":"1"}`, `{"name":"Changed name","expected_revision":1.5}`, `{"name":"Changed name","expected_revision":-1}`,
		`{"Name":"Changed name","expected_revision":1}`, `{"name":"Changed name","Expected_Revision":1}`, `{"name":"Changed name","expected_revision":1} {}`,
		"{\"name\":\"" + string([]byte{255}) + "\",\"expected_revision\":1}",
	} {
		if w := websiteRequest(f.handler, "PUT", path, body, cookie, csrf); w.Code != 400 {
			t.Fatal("name body not exact", w.Code)
		}
	}
	if w := websiteRequest(f.handler, "PUT", path, strings.Repeat("x", 4097), cookie, csrf); w.Code != 413 {
		t.Fatal("name body not bounded", w.Code)
	}
	for _, name := range []string{"", " leading", "trailing ", "bad\nname", "bad\x7fname", strings.Repeat("x", 81), strings.Repeat("名", 27)} {
		if w := websiteRequest(f.handler, "PUT", path, sites.NameInput{Name: name, ExpectedRevision: site.Revision}, cookie, csrf); w.Code != 422 {
			t.Fatal("invalid name accepted", w.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", path, input, cookie, csrf); w.Code != 405 {
		t.Fatal("name mutation expanded to POST", w.Code)
	}
	if current, err := f.store.Get(site.ID); err != nil || current != site {
		t.Fatal("refused name request changed storage", current, err)
	}
}

func TestWebsiteNameCASNoOpAndSessionReplay(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site := siteResponse(t, websiteRequest(f.handler, "POST", "/api/v1/sites", sites.CreateInput{Name: "Original name", Domain: "name-cas.test"}, cookie, csrf))
	path := "/api/v1/sites/" + site.ID + "/name"
	entries, err := f.journal.List()
	if err != nil {
		t.Fatal(err)
	}
	if actual := siteResponse(t, websiteRequest(f.handler, "PUT", path, sites.NameInput{Name: site.Name, ExpectedRevision: site.Revision}, cookie, csrf)); actual != site {
		t.Fatal("same name not no-op", actual)
	}
	if got, err := f.journal.List(); err != nil || !reflect.DeepEqual(got, entries) {
		t.Fatal("no-op wrote audit", err)
	}
	before := site
	site = siteResponse(t, websiteRequest(f.handler, "PUT", path, sites.NameInput{Name: strings.Repeat("名", 26) + "AB", ExpectedRevision: site.Revision}, cookie, csrf))
	expected := before
	expected.Name, expected.Revision, expected.UpdatedAt = site.Name, before.Revision+1, site.UpdatedAt
	if site != expected || !site.UpdatedAt.After(before.UpdatedAt) {
		t.Fatal("name response changed unrelated metadata", site)
	}
	for _, name := range []string{site.Name, "Stale replacement"} {
		if w := websiteRequest(f.handler, "PUT", path, sites.NameInput{Name: name, ExpectedRevision: before.Revision}, cookie, csrf); w.Code != 409 {
			t.Fatal("stale rename accepted", w.Code)
		}
	}
	if w := websiteRequest(f.handler, "PUT", "/api/v1/sites/"+strings.Repeat("a", 32)+"/name", sites.NameInput{Name: "Unknown", ExpectedRevision: 1}, cookie, csrf); w.Code != 404 {
		t.Fatal("unknown site accepted", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/logout", nil, cookie, csrf); w.Code != 200 {
		t.Fatal("fixture logout", w.Code)
	}
	if w := websiteRequest(f.handler, "PUT", path, sites.NameInput{Name: "Replay", ExpectedRevision: site.Revision}, cookie, csrf); w.Code != 401 {
		t.Fatal("logged-out session replay accepted", w.Code)
	}
	if got, err := f.store.Get(site.ID); err != nil || got != site {
		t.Fatal("refusal/replay changed name", got, err)
	}
}
