package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
)

// AdoptPublicHTML answers as the broker does: the revision must match and
// moves on, and the folder change is gone.
func (b *sitesBroker) AdoptPublicHTML(_ context.Context, id string, in hostaccounts.AdoptInput, actor string) (hostaccounts.Account, error) {
	return b.changed(fmt.Sprintf("folder %s rev=%d reason=%q actor=%s", id, in.ExpectedRevision, in.Reason, actor), id, in.ExpectedRevision, func(a *hostaccounts.Account) { a.SiteFolderChanged = false })
}

func TestWebsiteFolderChangeIsShownAndAdopted(t *testing.T) {
	f, _, broker, _, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	broker.change(site.AccountID, func(a *hostaccounts.Account) { a.SiteFolderChanged = true })
	one := decodeDetail(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID, nil, cookie, ""))
	if !one.SiteFolderChanged || one.State != "active" {
		t.Fatalf("site %+v", one)
	}
	if sites := decodeSites(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "").Body.Bytes()); len(sites) != 1 || !sites[0].SiteFolderChanged {
		t.Fatalf("listed %+v", sites)
	}

	got := decodeDetail(t, websiteRequest(f.handler, "POST", sitePath(site, "folder"), map[string]any{"expected_revision": site.Revision}, cookie, csrf))
	if got.SiteFolderChanged || got.Revision != site.Revision+1 || got.State != "active" || got.PHPVersion != "8.3" {
		t.Fatalf("after adopting %+v", got)
	}
	want := fmt.Sprintf(`folder %s rev=%d reason="Current public_html used on the website's page" actor=local-operator`, site.AccountID, site.Revision)
	if !slices.Equal(broker.changes, []string{want}) {
		t.Fatalf("broker changes %q", broker.changes)
	}

	for err, want := range map[error]struct {
		status int
		detail string
	}{
		hostaccounts.ErrConflict:    {409, websiteFolderRefused},
		hostaccounts.ErrRecovery:    {503, websiteFolderNeedsCheck},
		hostaccounts.ErrUnavailable: {503, websiteNoAnswer},
		hostaccounts.ErrNotFound:    {404, websiteNotFound},
	} {
		broker.changeErr = err
		w := websiteRequest(f.handler, "POST", sitePath(site, "folder"), map[string]any{"expected_revision": got.Revision}, cookie, csrf)
		if w.Code != want.status || problemDetail(t, w) != want.detail || !strings.HasPrefix(problemTechnical(t, w), "account service: ") {
			t.Fatalf("broker answered %v: %d %s", err, w.Code, w.Body.String())
		}
	}
	broker.changeErr = nil

	before := len(broker.changes)
	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		detail string
	}{
		"no revision":      {map[string]any{}, 422, websiteNoRevision},
		"a stale revision": {map[string]any{"expected_revision": site.Revision}, 409, websiteStale},
	} {
		w := websiteRequest(f.handler, "POST", sitePath(site, "folder"), tc.body, cookie, csrf)
		if w.Code != tc.status || problemDetail(t, w) != tc.detail {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if len(broker.changes) != before {
		t.Fatalf("a refused request reached the broker: %q", broker.changes[before:])
	}
}

func TestWebsiteFolderAdmission(t *testing.T) {
	f, _, broker, _, site := actionsFixture(t)
	body := fmt.Sprintf(`{"expected_revision":%d}`, site.Revision)
	path := sitePath(site, "folder")
	if w := websiteRequest(f.handler, "POST", path, body, nil, ""); w.Code != 401 {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	cookie, csrf := websiteSignIn(t, f)
	if w := websiteRequest(f.handler, "POST", path, body, cookie, ""); w.Code != 403 {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	for _, method := range []string{"PUT", "DELETE", "PATCH"} {
		if w := websiteRequest(f.handler, method, path, body, cookie, csrf); w.Code != 405 {
			t.Fatalf("%s: %d", method, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Origin", "http://other.example")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-origin: %d", w.Code)
	}
	for _, tc := range []struct {
		name, body string
		status     int
		detail     string
	}{
		{"unknown key", `{"reason":"x","expected_revision":2}`, 422, "Send only expected_revision."},
		{"another action's key", `{"state":"suspended","expected_revision":2}`, 422, "Send only expected_revision."},
		{"duplicate key", `{"expected_revision":1,"expected_revision":2}`, 422, "expected_revision more than once"},
		{"revision as text", `{"expected_revision":"2"}`, 422, "expected_revision must be a whole number."},
		{"array", `[]`, 400, ""},
		{"too large", `{"expected_revision":2` + strings.Repeat(" ", 4096) + `}`, 413, ""},
	} {
		w := websiteRequest(f.handler, "POST", path, tc.body, cookie, csrf)
		if w.Code != tc.status {
			t.Fatalf("%s: status %d want %d: %s", tc.name, w.Code, tc.status, w.Body.String())
		}
		if d := problemDetail(t, w); tc.detail != "" && !strings.Contains(d, tc.detail) {
			t.Fatalf("%s: detail %q", tc.name, d)
		}
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/sites/"+strings.Repeat("0", 32)+"/folder", body, cookie, csrf); w.Code != 404 {
		t.Fatalf("unknown site: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "POST", path+"/", body, cookie, csrf); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST %s/: %d", path, w.Code)
	}
	if len(broker.changes) != 0 {
		t.Fatalf("a refused request changed something: %q", broker.changes)
	}
}

// A second suspend of a suspended site is a change of its own: it installs
// the suspended site's web server settings again, with its own reason.
func TestWebsiteSuspensionAppliedAgain(t *testing.T) {
	f, _, broker, _, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	first := decodeDetail(t, websiteRequest(f.handler, "POST", sitePath(site, "state"), map[string]any{"state": "suspended", "expected_revision": site.Revision}, cookie, csrf))
	again := decodeDetail(t, websiteRequest(f.handler, "POST", sitePath(site, "state"), map[string]any{"state": "suspended", "expected_revision": first.Revision}, cookie, csrf))
	if again.State != "suspended" || again.Revision != first.Revision+1 {
		t.Fatalf("after applying the suspension again %+v", again)
	}
	want := []string{
		fmt.Sprintf(`state %s suspended rev=%d reason="Suspended on the website's page" actor=local-operator`, site.AccountID, site.Revision),
		fmt.Sprintf(`state %s suspended rev=%d reason="Suspension applied again on the website's page" actor=local-operator`, site.AccountID, first.Revision),
	}
	if !slices.Equal(broker.changes, want) {
		t.Fatalf("broker changes %q", broker.changes)
	}
	broker.changeErr = hostaccounts.ErrWebRejected
	w := websiteRequest(f.handler, "POST", sitePath(site, "state"), map[string]any{"state": "suspended", "expected_revision": again.Revision}, cookie, csrf)
	if w.Code != 422 || !strings.HasPrefix(problemDetail(t, w), "The web server's configuration test failed, so the suspension was not applied again and nothing changed. The site stays suspended.") {
		t.Fatalf("rejected %d: %s", w.Code, w.Body.String())
	}
}
