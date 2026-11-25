package api

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sifruno/internal/operator"
)

// clientRequest is a request as an API client such as the WHMCS module sends
// it: a bearer token, a JSON body, and no cookie, Origin or CSRF header. When
// network is true it arrives on the HTTPS listener from another machine.
func clientRequest(h http.Handler, network bool, method, path, token string, body any) *httptest.ResponseRecorder {
	base, peer := "http://127.0.0.1:8080", "127.0.0.1:14000"
	if network {
		base, peer = remoteOrigin, "198.51.100.7:51234"
	}
	var text string
	if body != nil {
		b, _ := json.Marshal(body)
		text = string(b)
	}
	r := httptest.NewRequest(method, base+path, strings.NewReader(text))
	r.RemoteAddr = peer
	if network {
		r.TLS = &tls.ConnectionState{}
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func problemError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(w.Body.Bytes(), &p) != nil {
		t.Fatalf("not a problem response: %s", w.Body.String())
	}
	return p.Error
}

func TestAPITokenThroughThePanelAPI(t *testing.T) {
	f := websiteFixture(t)
	remote := operator.Remote(f.handler, []string{"panel.example.test"})
	cookie, csrf := websiteSignIn(t, f)

	w := websiteRequest(f.handler, "POST", "/api/v1/session/tokens", map[string]any{"name": "WHMCS", "expires_in_days": 30}, cookie, csrf)
	var created operator.CreatedToken
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &created) != nil || !strings.HasPrefix(created.Token, "sfr_") || len(created.Token) != 47 {
		t.Fatalf("create token: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/tokens", map[string]string{"name": "No CSRF"}, cookie, ""); w.Code != 403 {
		t.Fatalf("create without CSRF: %d", w.Code)
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/session/tokens", nil, cookie, ""); w.Code != 200 || strings.Contains(w.Body.String(), created.Token) || !strings.Contains(w.Body.String(), created.Prefix) {
		t.Fatalf("list tokens: %d %s", w.Code, w.Body.String())
	}

	// On loopback and over the HTTPS listener the token reads and writes
	// like an admin session, without a cookie, Origin or CSRF header.
	for _, network := range []bool{false, true} {
		h := f.handler
		if network {
			h = remote
		}
		for _, path := range []string{"/api/v1/sites", "/api/v1/server", "/openapi.json"} {
			if w := clientRequest(h, network, "GET", path, created.Token, nil); w.Code != 200 {
				t.Fatalf("network=%v GET %s: %d %s", network, path, w.Code, w.Body.String())
			}
		}
		domain := "loopback.example"
		if network {
			domain = "network.example"
		}
		w := clientRequest(h, network, "POST", "/api/v1/sites", created.Token, map[string]string{"name": "Made by token", "domain": domain})
		if w.Code != 201 && w.Code != 200 {
			t.Fatalf("network=%v create site: %d %s", network, w.Code, w.Body.String())
		}
		// The fences: no session, sign-in, setup or token route.
		for _, route := range []struct{ method, path string }{
			{"GET", "/api/v1/session"}, {"GET", "/api/v1/session/sessions"}, {"POST", "/api/v1/session/login"},
			{"POST", "/api/v1/session/logout"}, {"POST", "/api/v1/session/revoke-others"}, {"POST", "/api/v1/session/setup/totp"},
			{"GET", "/api/v1/session/tokens"}, {"POST", "/api/v1/session/tokens"}, {"POST", "/api/v1/session/tokens/" + created.ID + "/revoke"},
			// Outside the allow list: the change trail, internal tools, any
			// later route, and a path that only cleans into an allowed one.
			{"GET", "/api/v1/trail"}, {"GET", "/api/v1/budget"}, {"GET", "/api/v1/platform"}, {"GET", "/api/v1/not-yet-written"},
			{"GET", "/api/v1/sites/../session"}, {"GET", "/api/v1/sitesx"},
			// Credential set-up inside an allowed area.
			{"GET", "/api/v1/websites/backup-storage"}, {"POST", "/api/v1/websites/backup-storage"},
			{"POST", "/api/v1/websites/backup-storage/password"}, {"POST", "/api/v1/websites/backup-storage/password-saved"},
			// An admin's abandon of an unfinished create.
			{"POST", "/api/v1/accounts/" + strings.Repeat("a", 32) + "/abandon-create"},
			// An admin's finish of an unfinished delete.
			{"POST", "/api/v1/accounts/" + strings.Repeat("a", 32) + "/finish-delete"},
			// An admin's change of an account's plan and limits.
			{"POST", "/api/v1/accounts/" + strings.Repeat("a", 32) + "/plan"},
			// A site's restore, which overwrites it, and its drill.
			{"POST", "/api/v1/websites/sites/" + strings.Repeat("a", 32) + "/backups/restore"},
			{"POST", "/api/v1/websites/sites/" + strings.Repeat("a", 32) + "/backups/drill"},
			{"GET", "/api/v1/websites/sites/" + strings.Repeat("a", 32) + "/backups/restore/x"},
			// The older ZIP backups: restores and their previews, removal,
			// and a download, which hands out the site's contents.
			{"POST", "/api/v1/sites/site-1/restore"}, {"POST", "/api/v1/sites/site-1/restore-preview"},
			{"POST", "/api/v1/sites/site-1/restore-file"}, {"POST", "/api/v1/sites/site-1/restore-file-preview"},
			{"POST", "/api/v1/sites/site-1/archive-restore"}, {"POST", "/api/v1/sites/site-1/remove-backup"},
			{"GET", "/api/v1/sites/site-1/backups/backup-1/download"},
		} {
			w := clientRequest(h, network, route.method, route.path, created.Token, map[string]string{})
			if w.Code != 403 || problemError(t, w) != "token_not_allowed" {
				t.Fatalf("network=%v %s %s with a token: %d %s", network, route.method, route.path, w.Code, w.Body.String())
			}
		}
		// Backing up now and the backup list stay open to a token: the
		// answer comes from the route (no backups on this fixture), not
		// from the token fence.
		for _, route := range []struct{ method, path string }{
			{"GET", "/api/v1/websites/sites/" + strings.Repeat("a", 32) + "/backups"},
			{"POST", "/api/v1/websites/sites/" + strings.Repeat("a", 32) + "/backups"},
		} {
			w := clientRequest(h, network, route.method, route.path, created.Token, map[string]string{})
			if w.Code == 403 || w.Code == 401 || strings.Contains(w.Body.String(), "token_not_allowed") {
				t.Fatalf("network=%v %s %s with a token: %d %s", network, route.method, route.path, w.Code, w.Body.String())
			}
		}
		if w := clientRequest(h, network, "GET", "/api/v1/sites", "sfr_"+strings.Repeat("Z", 43), nil); w.Code != 401 || problemError(t, w) != "invalid_token" {
			t.Fatalf("network=%v wrong token: %d", network, w.Code)
		}
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/sites", nil, cookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "loopback.example") || !strings.Contains(w.Body.String(), "network.example") {
		t.Fatalf("sites made with the token: %d %s", w.Code, w.Body.String())
	}

	// A token sent together with the session cookie is refused.
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/v1/sites", nil)
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Authorization", "Bearer "+created.Token)
	r.AddCookie(cookie)
	both := httptest.NewRecorder()
	f.handler.ServeHTTP(both, r)
	if both.Code != 400 || problemError(t, both) != "invalid_request" {
		t.Fatalf("token with cookie: %d %s", both.Code, both.Body.String())
	}

	// Revoked with the session, the token stops working everywhere.
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/tokens/"+created.ID+"/revoke", map[string]string{}, cookie, csrf); w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	for _, network := range []bool{false, true} {
		h := f.handler
		if network {
			h = remote
		}
		if w := clientRequest(h, network, "GET", "/api/v1/sites", created.Token, nil); w.Code != 401 || problemError(t, w) != "invalid_token" {
			t.Fatalf("network=%v revoked token: %d", network, w.Code)
		}
	}
	if w := clientRequest(f.handler, false, "GET", "/api/v1/sites", "", nil); w.Code != 401 {
		t.Fatalf("no credential: %d", w.Code)
	}
}

func TestOpenAPIDescribesAPITokens(t *testing.T) {
	f := websiteFixture(t)
	w := websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	var spec struct {
		Paths      map[string]map[string]json.RawMessage
		Components struct {
			SecuritySchemes map[string]struct{ Type, Scheme string }
			Schemas         map[string]struct {
				Properties map[string]map[string]any
			}
		}
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatalf("OpenAPI: %d", w.Code)
	}
	if s := spec.Components.SecuritySchemes["apiToken"]; s.Type != "http" || s.Scheme != "bearer" {
		t.Fatal("bearer token scheme not described")
	}
	for path, method := range map[string]string{"/api/v1/session/tokens": "post", "/api/v1/session/tokens/{id}/revoke": "post"} {
		if _, ok := spec.Paths[path][method]; !ok {
			t.Fatalf("%s %s not described", method, path)
		}
	}
	if _, ok := spec.Paths["/api/v1/session/tokens"]["get"]; !ok {
		t.Fatal("token list not described")
	}
	if spec.Components.Schemas["OperatorAPITokenCreated"].Properties["token"]["readOnly"] != true {
		t.Fatal("the token must be described as returned once")
	}
	if _, ok := spec.Components.Schemas["OperatorAPIToken"].Properties["token"]; ok {
		t.Fatal("the listed token must not carry the token")
	}
}
