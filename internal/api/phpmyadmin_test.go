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

// phpMyAdminOrigin is phpMyAdmin's own origin in these tests: the panel's
// host name on another port.
const phpMyAdminOrigin = "https://panel.example.test:8444"

// fakePhpMyAdmin stands in for internal/phpmyadmin's Service: it records
// what it was asked to open.
type fakePhpMyAdmin struct {
	mu      sync.Mutex
	opened  []string
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
	return phpmyadmin.Handoff{Path: phpmyadmin.SignonPath + "?code=" + strings.Repeat("C", 43), CodeExpires: now.Add(time.Minute), LoginExpires: now.Add(time.Hour)}, nil
}

func (f *fakePhpMyAdmin) SignonURL(host string, h phpmyadmin.Handoff) string {
	return "https://" + host + ":8444" + h.Path
}

func phpMyAdminFixture(t *testing.T, panelHosts ...string) (siteFixture, *fakeDatabases, *fakePhpMyAdmin) {
	t.Helper()
	f, db, broker := databasesFixture(t)
	pma := &fakePhpMyAdmin{}
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Databases: db, PhpMyAdmin: pma, PanelHosts: panelHosts, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return f, db, pma
}

const alphaPhpMyAdmin = alphaDatabases + "/phpmyadmin"

func TestOpenPhpMyAdminForOneWebsite(t *testing.T) {
	f, db, pma := phpMyAdminFixture(t, "panel.example.test", "203.0.113.5")
	cookie, csrf := websiteSignIn(t, f)
	db.seed("alpha", "alpha_shop")

	w := websiteRequest(f.handler, "POST", alphaPhpMyAdmin, map[string]string{}, cookie, csrf)
	var body map[string]json.RawMessage
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(withoutSchema(body)) != 3 {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	// On loopback the link is on the first panel host name's phpMyAdmin port.
	if string(body["url"]) != `"https://panel.example.test:8444/sifruno-signon.php?code=`+strings.Repeat("C", 43)+`"` || string(body["link_expires_at"]) != `"2026-11-24T10:01:00Z"` || string(body["login_expires_at"]) != `"2026-11-24T11:00:00Z"` {
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
		code int
	}{
		{"no CSRF", "", map[string]string{}, 403},
		{"a field", csrf, map[string]string{"user": "root"}, 422},
		{"not JSON", csrf, "user=root", 400},
	} {
		if w := websiteRequest(f.handler, "POST", alphaPhpMyAdmin, tc.body, cookie, tc.csrf); w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body.String())
		}
	}
	for _, origin := range []string{"http://evil.example", phpMyAdminOrigin} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+alphaPhpMyAdmin, strings.NewReader("{}"))
		r.RemoteAddr = "127.0.0.1:14000"
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, r)
		if rec.Code != 403 {
			t.Fatalf("origin %s: %d", origin, rec.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", alphaPhpMyAdmin, map[string]string{}, nil, ""); w.Code != 401 {
		t.Fatalf("no session: %d", w.Code)
	}
	if len(pma.opened) != 2 {
		t.Fatalf("a refused request opened phpMyAdmin: %q", pma.opened)
	}

	// A website with no database, an unknown website, failures.
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

	// Without phpMyAdmin, or without a panel host name for its origin, the
	// answer says how to add it.
	_, _, broker := databasesFixture(t)
	for _, o := range []Options{
		{Operator: f.manager, Accounts: broker, Databases: db, PanelHosts: []string{"panel.example.test"}, AllowedOrigins: []string{"http://127.0.0.1:8080"}},
		{Operator: f.manager, Accounts: broker, Databases: db, PhpMyAdmin: pma, AllowedOrigins: []string{"http://127.0.0.1:8080"}},
	} {
		w = websiteRequest(New(o), "POST", alphaPhpMyAdmin, map[string]string{}, cookie, csrf)
		if detail, _ := problemTexts(t, w); w.Code != 503 || !strings.Contains(detail, "--panel-host") {
			t.Fatalf("not set up: %d %s", w.Code, w.Body.String())
		}
	}
}

// Over the network, the link is on the host name the admin used.
func TestOpenPhpMyAdminOverTheNetwork(t *testing.T) {
	f, _, _ := phpMyAdminFixture(t, "other.example.test", "panel.example.test")
	remote := operator.Remote(f.handler, []string{"other.example.test", "panel.example.test"})
	cookie, csrf := remoteAdminSignIn(t, f, remote)
	w := remoteRequest(remote, "POST", alphaPhpMyAdmin, map[string]string{}, cookie, csrf)
	var body siteDatabaseOpenBodyOut
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &body) != nil || !strings.HasPrefix(body.URL, phpMyAdminOrigin+phpmyadmin.SignonPath+"?code=") {
		t.Fatalf("open over the network: %d %s", w.Code, w.Body.String())
	}
}

func TestPhpMyAdminIsForPeopleNotTokens(t *testing.T) {
	f, _, pma := phpMyAdminFixture(t, "panel.example.test")
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
	}
	if len(pma.opened) != 0 {
		t.Fatalf("a token opened phpMyAdmin: %q", pma.opened)
	}
	// Other database routes stay open to tokens.
	if w := clientRequest(f.handler, false, "GET", alphaDatabases, created.Token, nil); w.Code != 200 {
		t.Fatalf("token list: %d", w.Code)
	}
}

// phpMyAdmin is never served on the panel's origin, and the panel's API
// refuses every request a phpMyAdmin page sends it.
func TestThePanelRefusesPhpMyAdminsOrigin(t *testing.T) {
	f, _, _ := phpMyAdminFixture(t, "panel.example.test")
	cookie, csrf := websiteSignIn(t, f)
	for _, path := range []string{"/api/v1/phpmyadmin/", "/api/v1/phpmyadmin/index.php", "/api/v1/phpmyadmin/sifruno-signon.php"} {
		if w := websiteRequest(f.handler, "GET", path, nil, cookie, ""); w.Code != 404 {
			t.Fatalf("GET %s on the panel: %d", path, w.Code)
		}
	}
	remote := operator.Remote(f.handler, []string{"panel.example.test"})
	adminCookie, adminCSRF := remoteAdminSignIn(t, f, remote)
	fromPhpMyAdmin := func(r *http.Request) {
		r.Header.Set("Origin", phpMyAdminOrigin)
		r.Header.Set("Sec-Fetch-Site", "same-site")
	}
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/v1/session"}, {"GET", "/api/v1/websites/sites"}, {"GET", alphaDatabases},
		{"POST", alphaPhpMyAdmin}, {"POST", "/api/v1/session/tokens"}, {"GET", "/openapi.json"},
	} {
		if w := remoteRequest(remote, route.method, route.path, map[string]string{}, adminCookie, adminCSRF, fromPhpMyAdmin); w.Code != 403 {
			t.Fatalf("%s %s from phpMyAdmin's origin over the network: %d", route.method, route.path, w.Code)
		}
		r := httptest.NewRequest(route.method, "http://127.0.0.1:8080"+route.path, strings.NewReader("{}"))
		r.RemoteAddr = "127.0.0.1:14000"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		fromPhpMyAdmin(r)
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, r)
		if rec.Code != 403 {
			t.Fatalf("%s %s from phpMyAdmin's origin on loopback: %d", route.method, route.path, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("the panel answered with CORS headers")
		}
	}
}

// remoteAdminSignIn makes the first admin on the server with the access key
// and signs it in over the HTTPS listener, as a person on another machine.
func remoteAdminSignIn(t *testing.T, f siteFixture, remote http.Handler) (*http.Cookie, string) {
	t.Helper()
	keyCookie, keyCSRF := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "POST", "/api/v1/session/setup/totp", map[string]string{"username": "admin"}, keyCookie, keyCSRF)
	var secret struct {
		Secret string `json:"secret"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &secret) != nil {
		t.Fatalf("begin setup: %d", w.Code)
	}
	// The previous step's code for the setup, so the current one is free for the sign-in.
	step := time.Now().Unix() / 30
	const password = "phpMyAdmin proof admin"
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/setup/admin", map[string]string{"username": "admin", "password": password, "totp_code": testCode(secret.Secret, step-1)}, keyCookie, keyCSRF); w.Code != 200 {
		t.Fatalf("finish setup: %d %s", w.Code, w.Body.String())
	}
	w = remoteRequest(remote, "POST", "/api/v1/session/login", map[string]string{"username": "admin", "password": password, "totp_code": testCode(secret.Secret, step)}, nil, "")
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || json.Unmarshal(w.Body.Bytes(), &session) != nil {
		t.Fatalf("admin sign-in over the network: %d %s", w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0], session.CSRF
}
