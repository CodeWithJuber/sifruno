package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/dbhost"
	"sifruno/internal/operator"
	"sifruno/internal/phpmyadmin"
)

// fakePhpMyAdmin stands in for internal/phpmyadmin's Service: it records
// what it was asked to open and every request the panel passed on.
type fakePhpMyAdmin struct {
	mu      sync.Mutex
	opened  []string
	passed  []*http.Request
	openErr error
}

func (f *fakePhpMyAdmin) Open(_ context.Context, owner string, databases []string) (phpmyadmin.Handoff, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.openErr != nil {
		return phpmyadmin.Handoff{}, f.openErr
	}
	f.opened = append(f.opened, owner+": "+strings.Join(databases, ","))
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	return phpmyadmin.Handoff{URL: phpmyadmin.BasePath + phpmyadmin.SignonScript + "?code=" + strings.Repeat("C", 43), CodeExpires: now.Add(time.Minute), LoginExpires: now.Add(time.Hour)}, nil
}

func (f *fakePhpMyAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.passed = append(f.passed, r)
	f.mu.Unlock()
	_, _ = w.Write([]byte("phpMyAdmin page"))
}

func phpMyAdminFixture(t *testing.T) (siteFixture, *fakeDatabases, *fakePhpMyAdmin) {
	t.Helper()
	f, db, broker := databasesFixture(t)
	pma := &fakePhpMyAdmin{}
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Databases: db, PhpMyAdmin: pma, PhpMyAdminProxy: pma, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return f, db, pma
}

const alphaPhpMyAdmin = alphaDatabases + "/phpmyadmin"

func TestOpenPhpMyAdminForOneWebsite(t *testing.T) {
	f, db, pma := phpMyAdminFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	db.seed("alpha", "alpha_shop")

	w := websiteRequest(f.handler, "POST", alphaPhpMyAdmin, map[string]string{}, cookie, csrf)
	var body map[string]json.RawMessage
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(withoutSchema(body)) != 3 {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	if string(body["url"]) != `"/api/v1/phpmyadmin/sifruno-signon.php?code=`+strings.Repeat("C", 43)+`"` || string(body["link_expires_at"]) != `"2026-11-24T10:01:00Z"` || string(body["login_expires_at"]) != `"2026-11-24T11:00:00Z"` {
		t.Fatalf("body %s", w.Body.String())
	}
	// Only alpha's databases: beta's, and beta's database that carries
	// alpha's prefix, are not given, even by a service that lists them all.
	if !slices.Equal(pma.opened, []string{"alpha: alpha_shop,alpha_wp"}) {
		t.Fatalf("opened %q", pma.opened)
	}
	db.leaky = true
	if w := websiteRequest(f.handler, "POST", alphaPhpMyAdmin, map[string]string{}, cookie, csrf); w.Code != 201 || pma.opened[1] != "alpha: alpha_shop,alpha_wp" {
		t.Fatalf("leaky list: %d %q", w.Code, pma.opened)
	}
	db.leaky = false

	// The admission every database change has: CSRF, Origin, an empty object.
	for _, tc := range []struct {
		name string
		csrf string
		body any
		set  func(*http.Request)
		code int
	}{
		{"no CSRF", "", map[string]string{}, nil, 403},
		{"a field", csrf, map[string]string{"user": "root"}, nil, 422},
		{"not JSON", csrf, "user=root", nil, 400},
	} {
		if w := websiteRequest(f.handler, "POST", alphaPhpMyAdmin, tc.body, cookie, tc.csrf); w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+alphaPhpMyAdmin, strings.NewReader("{}"))
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Origin", "http://evil.example")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Fatalf("another origin: %d", rec.Code)
	}
	if w := websiteRequest(f.handler, "POST", alphaPhpMyAdmin, map[string]string{}, nil, ""); w.Code != 401 {
		t.Fatalf("no session: %d", w.Code)
	}
	if len(pma.opened) != 2 {
		t.Fatalf("a refused request opened phpMyAdmin: %q", pma.opened)
	}

	// A website with no database, an unknown website, no phpMyAdmin.
	delete(db.databases, "alpha_wp")
	delete(db.databases, "alpha_shop")
	w = websiteRequest(f.handler, "POST", alphaPhpMyAdmin, map[string]string{}, cookie, csrf)
	if detail, _ := problemTexts(t, w); w.Code != 409 || !strings.Contains(detail, "Create a database first") {
		t.Fatalf("no database: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/sites/"+strings.Repeat("c", 32)+"/databases/phpmyadmin", map[string]string{}, cookie, csrf); w.Code != 404 {
		t.Fatalf("unknown website: %d", w.Code)
	}
	db.seed("alpha", "alpha_wp")
	for _, tc := range []struct {
		err    error
		status int
		text   string
	}{
		{phpmyadmin.ErrTooMany, 429, "Too many phpMyAdmin sign-ins"},
		{phpmyadmin.ErrNotRecorded, 500, "could not record"},
		{dbhost.ErrUnavailable, 503, "not answering"},
		{errors.New("ERROR 1045 (28000): Access denied near 'IDENTIFIED BY 'x''"), 502, "temporary user"},
	} {
		pma.openErr = tc.err
		w := websiteRequest(f.handler, "POST", alphaPhpMyAdmin, map[string]string{}, cookie, csrf)
		detail, technical := problemTexts(t, w)
		if w.Code != tc.status || !strings.Contains(detail, tc.text) || strings.Contains(strings.Join(technical, " "), "IDENTIFIED BY") {
			t.Fatalf("%v: %d %s %q", tc.err, w.Code, detail, technical)
		}
	}
	pma.openErr = nil

	// Without phpMyAdmin on the server, the answer says how to add it.
	_, _, broker := databasesFixture(t)
	off := New(Options{Operator: f.manager, Accounts: broker, Databases: db, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	w = websiteRequest(off, "POST", alphaPhpMyAdmin, map[string]string{}, cookie, csrf)
	if detail, _ := problemTexts(t, w); w.Code != 503 || !strings.Contains(detail, "install.sh") {
		t.Fatalf("not set up: %d %s", w.Code, w.Body.String())
	}
}

func TestPhpMyAdminIsForPeopleNotTokens(t *testing.T) {
	f, _, pma := phpMyAdminFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "POST", "/api/v1/session/tokens", map[string]any{"name": "WHMCS", "expires_in_days": 30}, cookie, csrf)
	var created operator.CreatedToken
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &created) != nil {
		t.Fatalf("create token: %d %s", w.Code, w.Body.String())
	}
	remote := operator.Remote(f.handler, []string{"panel.example.test"})
	for _, network := range []bool{false, true} {
		h := f.handler
		if network {
			h = remote
		}
		w := clientRequest(h, network, "POST", alphaPhpMyAdmin, created.Token, map[string]string{})
		if w.Code != 403 || problemError(t, w) != "token_not_allowed" {
			t.Fatalf("network=%v open with a token: %d %s", network, w.Code, w.Body.String())
		}
		for _, path := range []string{phpmyadmin.BasePath, phpmyadmin.BasePath + "index.php", phpmyadmin.BasePath + phpmyadmin.SignonScript + "?code=x"} {
			w := clientRequest(h, network, "GET", path, created.Token, nil)
			if w.Code != 403 || !strings.Contains(w.Body.String(), "API tokens cannot open phpMyAdmin.") {
				t.Fatalf("network=%v GET %s with a token: %d %s", network, path, w.Code, w.Body.String())
			}
		}
	}
	if len(pma.opened) != 0 || len(pma.passed) != 0 {
		t.Fatalf("a token reached phpMyAdmin: %q, %d requests", pma.opened, len(pma.passed))
	}
	// Other database routes stay open to tokens.
	if w := clientRequest(f.handler, false, "GET", alphaDatabases, created.Token, nil); w.Code != 200 {
		t.Fatalf("token list: %d", w.Code)
	}
}

func pmaRequest(h http.Handler, method, path string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader("token=t&sql_query=SELECT+1"))
	r.RemoteAddr = "127.0.0.1:14000"
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestThePanelServesPhpMyAdminToASignedInSessionOnly(t *testing.T) {
	f, _, pma := phpMyAdminFixture(t)
	page := phpmyadmin.BasePath + "index.php"

	// No session: a page that says what to do, nothing passed on.
	w := pmaRequest(f.handler, "GET", page, nil, "")
	if w.Code != 401 || !strings.Contains(w.Body.String(), "You are not signed in to the panel.") || !strings.Contains(w.Body.String(), "Next step:") || len(pma.passed) != 0 {
		t.Fatalf("no session: %d %s", w.Code, w.Body.String())
	}
	cookie, _ := websiteSignIn(t, f)
	// The session cookie is the one the proxy strips.
	if cookie.Name != phpmyadmin.PanelCookie || cookie.Path != "/api/v1" {
		t.Fatalf("the panel's session cookie is %s at %s; phpmyadmin.PanelCookie and BasePath must follow it", cookie.Name, cookie.Path)
	}
	w = pmaRequest(f.handler, "GET", page, cookie, "")
	if w.Code != 200 || w.Body.String() != "phpMyAdmin page" || len(pma.passed) != 1 {
		t.Fatalf("signed in: %d %s", w.Code, w.Body.String())
	}
	// phpMyAdmin's pages get phpMyAdmin's policy; the panel's routes keep theirs.
	if csp := w.Header().Get("Content-Security-Policy"); csp != phpMyAdminCSP || !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "object-src 'none'") {
		t.Fatalf("phpMyAdmin CSP %q", csp)
	}
	panel := websiteRequest(f.handler, "GET", alphaDatabases, nil, cookie, "")
	if csp := panel.Header().Get("Content-Security-Policy"); strings.Contains(csp, "unsafe") || !strings.Contains(csp, "script-src 'self';") || !strings.Contains(csp, "form-action 'none'") {
		t.Fatalf("the panel's own CSP changed: %q", csp)
	}

	// A POST needs the browser's Origin, which must be the panel's.
	if w := pmaRequest(f.handler, "POST", page, cookie, ""); w.Code != 403 || len(pma.passed) != 1 {
		t.Fatalf("POST without Origin: %d", w.Code)
	}
	if w := pmaRequest(f.handler, "POST", page, cookie, "http://evil.example"); w.Code != 403 || len(pma.passed) != 1 {
		t.Fatalf("POST from another origin: %d", w.Code)
	}
	if w := pmaRequest(f.handler, "POST", page, cookie, "http://127.0.0.1:8080"); w.Code != 200 || len(pma.passed) != 2 {
		t.Fatalf("POST from the panel: %d %s", w.Code, w.Body.String())
	}
	// No CSRF header was needed, and none was added.
	if pma.passed[1].Header.Get("X-CSRF-Token") != "" {
		t.Fatal("a CSRF header reached phpMyAdmin")
	}
	for _, method := range []string{"PUT", "DELETE", "PATCH"} {
		if w := pmaRequest(f.handler, method, page, cookie, "http://127.0.0.1:8080"); w.Code != 405 {
			t.Fatalf("%s: %d", method, w.Code)
		}
	}
	// Paths that only clean into another place are refused.
	for _, path := range []string{phpmyadmin.BasePath + "../session", phpmyadmin.BasePath + "./index.php", phpmyadmin.BasePath + "js//x.js"} {
		if w := pmaRequest(f.handler, "GET", path, cookie, ""); w.Code != 400 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if w := pmaRequest(f.handler, "GET", strings.TrimSuffix(phpmyadmin.BasePath, "/"), cookie, ""); w.Code != 301 || w.Header().Get("Location") != phpmyadmin.BasePath {
		t.Fatalf("base without slash: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := pmaRequest(f.handler, "GET", "/api/v1/phpmyadminx", cookie, ""); w.Code == 200 {
		t.Fatal("a neighbouring path reached phpMyAdmin")
	}
	if len(pma.passed) != 2 {
		t.Fatalf("refused requests were passed on: %d", len(pma.passed))
	}

	// Cross-site requests never arrive.
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080"+page, nil)
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	if rec.Code != 403 || len(pma.passed) != 2 {
		t.Fatalf("cross-site: %d", rec.Code)
	}

	// Over the network: an admin session only, as every API route.
	remote := operator.Remote(f.handler, []string{"panel.example.test"})
	if w := remoteRequest(remote, "GET", page, nil, cookie, ""); w.Code != 403 || !strings.Contains(w.Body.String(), "admin signed in with a password and a code") {
		t.Fatalf("access-key session over the network: %d %s", w.Code, w.Body.String())
	}
	if w := remoteRequest(remote, "GET", page, nil, nil, ""); w.Code != 401 {
		t.Fatalf("no session over the network: %d", w.Code)
	}
	if len(pma.passed) != 2 {
		t.Fatalf("network requests were passed on: %d", len(pma.passed))
	}

	// Not set up.
	off := New(Options{Operator: f.manager, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	if w := pmaRequest(off, "GET", page, cookie, ""); w.Code != 503 || !strings.Contains(w.Body.String(), "install.sh") {
		t.Fatalf("not set up: %d %s", w.Code, w.Body.String())
	}
}
