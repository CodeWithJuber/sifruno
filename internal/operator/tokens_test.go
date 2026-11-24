package operator

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const tokensPath = "/api/v1/session/tokens"

// withProbe adds a route guarded by Authorize, standing in for the panel's
// API routes: GET is a read, any other method a mutation.
func withProbe(m *Manager, h http.Handler) http.Handler {
	h.(*http.ServeMux).HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if actor, ok := m.Authorize(w, r, r.Method != http.MethodGet); ok {
			writeJSON(w, map[string]string{"actor": actor})
		}
	})
	return h
}

// tokenFixture is a panel with a probe route, a clock the test controls and
// a signed-in session.
func tokenFixture(t *testing.T, clock *time.Time) (*Manager, http.Handler, *http.Cookie, Session) {
	t.Helper()
	m, h, key := fixture(t)
	m.now = func() time.Time { return *clock }
	h = withProbe(m, h)
	cookie, s := signIn(t, h, key, nil)
	return m, h, cookie, s
}

func createToken(t *testing.T, h http.Handler, cookie *http.Cookie, csrf, body string) CreatedToken {
	t.Helper()
	w := opRequest(h, "POST", tokensPath, body, cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("create token: %d %s", w.Code, w.Body.String())
	}
	return decodeBody[CreatedToken](t, w.Body.Bytes())
}

// bearer sends a request the way an API client does: no cookie, Origin or
// CSRF header. Each change can rewrite the request.
func bearer(h http.Handler, method, path, token string, changes ...func(*http.Request) *http.Request) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader("{}"))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for _, change := range changes {
		r = change(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// fromNetwork makes the request arrive on the HTTPS listener from addr.
func fromNetwork(addr string) func(*http.Request) *http.Request {
	return func(r *http.Request) *http.Request {
		r.Host = "panel.example.test"
		r.RemoteAddr = addr
		r.TLS = &tls.ConnectionState{}
		return r
	}
}

func tokenList(t *testing.T, h http.Handler, cookie *http.Cookie) (TokenList, string) {
	t.Helper()
	w := opRequest(h, "GET", tokensPath, "", cookie, "")
	if w.Code != 200 {
		t.Fatalf("list tokens: %d %s", w.Code, w.Body.String())
	}
	return decodeBody[TokenList](t, w.Body.Bytes()), w.Body.String()
}

func TestAPITokenCreateUseAndRevoke(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m, h, cookie, s := tokenFixture(t, &now)
	unknown := bearer(h, "GET", "/probe", tokenPrefix+strings.Repeat("A", 43))
	if unknown.Code != 401 || problemCode(t, unknown.Body.Bytes()) != "invalid_token" || unknown.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("unknown token: %d %s", unknown.Code, unknown.Body.String())
	}

	created := createToken(t, h, cookie, s.CSRFToken, `{"name":"WHMCS"}`)
	if !validAPIToken(created.Token) || !strings.HasPrefix(created.Token, created.Prefix) || len(created.Prefix) != 10 || !shownPrefixPattern.MatchString(created.Prefix) {
		t.Fatalf("token or prefix malformed: prefix %q", created.Prefix)
	}
	if !validManagementID(created.ID) || created.Name != "WHMCS" || !created.CreatedAt.Equal(now) || !created.ExpiresAt.Equal(now.Add(90*24*time.Hour)) || created.LastUsedAt != nil || created.Expired {
		t.Fatalf("created token record: %+v", created.APIToken)
	}

	// The file holds a keyed hash, never the token or any part of its secret
	// beyond the shown prefix.
	raw, err := os.ReadFile(filepath.Join(m.dir, tokensFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), created.Token) || strings.Contains(string(raw), created.Token[len(tokenPrefix):]) || strings.Contains(string(raw), created.Token[len(created.Prefix):]) {
		t.Fatal("the token file holds the secret")
	}
	unkeyed := sha256.Sum256([]byte(created.Token))
	mac := hmac.New(sha256.New, m.tokenKey[:])
	mac.Write([]byte(created.Token))
	if strings.Contains(string(raw), base64.RawStdEncoding.EncodeToString(unkeyed[:])) || !strings.Contains(string(raw), base64.RawStdEncoding.EncodeToString(mac.Sum(nil))) {
		t.Fatal("the token file must hold the HMAC under tokens.key, not a plain hash")
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{tokensFile, tokensKeyFile} {
			if st, err := os.Stat(filepath.Join(m.dir, name)); err != nil || st.Mode().Perm() != 0600 {
				t.Fatalf("%s must be 0600", name)
			}
		}
	}

	// A token reads and changes without a cookie, Origin or CSRF token.
	if w := bearer(h, "GET", "/probe", created.Token); w.Code != 200 || !strings.Contains(w.Body.String(), `"local-operator"`) {
		t.Fatalf("token read: %d %s", w.Code, w.Body.String())
	}
	if w := bearer(h, "POST", "/probe", created.Token); w.Code != 200 {
		t.Fatalf("token mutation: %d %s", w.Code, w.Body.String())
	}
	if w := bearer(h, "GET", "/probe", created.Token, func(r *http.Request) *http.Request { r.Header.Set("Authorization", "bearer "+created.Token); return r }); w.Code != 200 {
		t.Fatalf("the scheme name is case-insensitive: %d", w.Code)
	}

	list, body := tokenList(t, h, cookie)
	if len(list.Items) != 1 || list.Capacity != 32 || list.Items[0].LastUsedAt == nil || !list.Items[0].LastUsedAt.Equal(now) || list.Items[0].Prefix != created.Prefix {
		t.Fatalf("list after use: %s", body)
	}
	if strings.Contains(body, created.Token[len(created.Prefix):]) || strings.Contains(body, `"hash"`) || strings.Contains(body, `"token"`) {
		t.Fatal("the list exposes the token or its hash")
	}

	// Revoking needs the session's CSRF token, then the token stops at once
	// with the same answer as a token that never existed.
	revoke := tokensPath + "/" + created.ID + "/revoke"
	if w := opRequest(h, "POST", revoke, "{}", cookie, ""); w.Code != 403 {
		t.Fatalf("revoke without CSRF: %d", w.Code)
	}
	w := opRequest(h, "POST", revoke, "{}", cookie, s.CSRFToken)
	if w.Code != 200 || decodeBody[APIToken](t, w.Body.Bytes()).Name != "WHMCS" || strings.Contains(w.Body.String(), created.Token) {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	revoked := bearer(h, "GET", "/probe", created.Token)
	if revoked.Code != 401 || revoked.Body.String() != unknown.Body.String() {
		t.Fatalf("revoked token: %d %s", revoked.Code, revoked.Body.String())
	}
	if w := opRequest(h, "POST", revoke, "{}", cookie, s.CSRFToken); w.Code != 404 || problemCode(t, w.Body.Bytes()) != "token_not_found" {
		t.Fatalf("revoke twice: %d", w.Code)
	}
	if w := opRequest(h, "POST", tokensPath+"/not-an-id/revoke", "{}", cookie, s.CSRFToken); w.Code != 400 {
		t.Fatalf("revoke with a malformed ID: %d", w.Code)
	}
	if list, _ := tokenList(t, h, cookie); len(list.Items) != 0 {
		t.Fatal("a revoked token is still listed")
	}
	raw, _ = os.ReadFile(filepath.Join(m.dir, tokensFile))
	if strings.Contains(string(raw), created.ID) {
		t.Fatal("a revoked token is still stored")
	}
}

func TestAPITokenExpiryAndInputRules(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	_, h, cookie, s := tokenFixture(t, &now)
	unknown := bearer(h, "GET", "/probe", tokenPrefix+strings.Repeat("B", 43))
	day := createToken(t, h, cookie, s.CSRFToken, `{"name":"Nightly script","expires_in_days":1}`)
	year := createToken(t, h, cookie, s.CSRFToken, `{"name":"Backup job","expires_in_days":365}`)
	if !day.ExpiresAt.Equal(now.Add(24*time.Hour)) || !year.ExpiresAt.Equal(now.Add(365*24*time.Hour)) {
		t.Fatal("expiry not applied")
	}
	for _, body := range []string{`{"name":"a","expires_in_days":0}`, `{"name":"b","expires_in_days":366}`, `{"name":"c","expires_in_days":-5}`} {
		if w := opRequest(h, "POST", tokensPath, body, cookie, s.CSRFToken); w.Code != 422 || problemCode(t, w.Body.Bytes()) != "invalid_expiry" {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
	for _, name := range []string{"", "   ", " WHMCS", "WHMCS ", strings.Repeat("x", 65), "line\nbreak", "tab\there", "right‮left"} {
		body := fmt.Sprintf(`{"name":%q}`, name)
		if w := opRequest(h, "POST", tokensPath, body, cookie, s.CSRFToken); w.Code != 422 || problemCode(t, w.Body.Bytes()) != "invalid_token_name" {
			t.Fatalf("name %q: %d", name, w.Code)
		}
	}
	if w := opRequest(h, "POST", tokensPath, `{"name":"NIGHTLY SCRIPT"}`, cookie, s.CSRFToken); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "token_name_taken" {
		t.Fatalf("duplicate name: %d", w.Code)
	}
	for _, body := range []string{`{"name":"x","token":"sfr_x"}`, `{"name":"x","expires_in_days":"90"}`, `{"name":"x","expires_in_days":1.5}`, `[]`} {
		if w := opRequest(h, "POST", tokensPath, body, cookie, s.CSRFToken); w.Code != 400 {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}

	// Valid until the last second, then refused like an unknown token. The
	// session (15 minutes) is long gone by then; the token does not need it.
	now = now.Add(24*time.Hour - time.Second)
	if w := bearer(h, "GET", "/probe", day.Token); w.Code != 200 {
		t.Fatalf("token before expiry: %d", w.Code)
	}
	now = now.Add(time.Second)
	if w := bearer(h, "GET", "/probe", day.Token); w.Code != 401 || w.Body.String() != unknown.Body.String() {
		t.Fatalf("expired token: %d %s", w.Code, w.Body.String())
	}
	if w := bearer(h, "GET", "/probe", year.Token); w.Code != 200 {
		t.Fatalf("other token: %d", w.Code)
	}
}

func TestAPITokenNeverReachesSessionRoutes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	_, h, cookie, s := tokenFixture(t, &now)
	created := createToken(t, h, cookie, s.CSRFToken, `{"name":"WHMCS"}`)
	routes := []struct{ method, path string }{
		{"GET", "/api/v1/session"}, {"POST", "/api/v1/session/login"}, {"POST", "/api/v1/session/logout"},
		{"GET", "/api/v1/session/sessions"}, {"POST", "/api/v1/session/sessions/" + strings.Repeat("a", 32) + "/revoke"}, {"POST", "/api/v1/session/revoke-others"},
		{"GET", "/api/v1/session/setup"}, {"POST", "/api/v1/session/setup/totp"}, {"POST", "/api/v1/session/setup/admin"},
		{"GET", tokensPath}, {"POST", tokensPath}, {"POST", tokensPath + "/" + created.ID + "/revoke"},
	}
	for _, route := range routes {
		// Alone, as an API client sends it, and together with a valid session.
		alone := bearer(h, route.method, route.path, created.Token)
		withSession := bearer(h, route.method, route.path, created.Token, func(r *http.Request) *http.Request {
			r.AddCookie(cookie)
			r.Header.Set("Origin", "http://127.0.0.1:8080")
			r.Header.Set("X-CSRF-Token", s.CSRFToken)
			return r
		})
		for _, w := range []*httptest.ResponseRecorder{alone, withSession} {
			if w.Code != 403 || problemCode(t, w.Body.Bytes()) != "token_not_allowed" {
				t.Fatalf("%s %s with a token: %d %s", route.method, route.path, w.Code, w.Body.String())
			}
		}
	}
	if list, _ := tokenList(t, h, cookie); len(list.Items) != 1 {
		t.Fatal("a token changed the token list")
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", cookie, ""); w.Code != 200 {
		t.Fatal("a token ended the session")
	}

	// A token is not a session: sent with the session cookie it is refused,
	// on reads and changes alike, and the cookie alone still works.
	for _, method := range []string{"GET", "POST"} {
		w := bearer(h, method, "/probe", created.Token, func(r *http.Request) *http.Request { r.AddCookie(cookie); return r })
		if w.Code != 400 || problemCode(t, w.Body.Bytes()) != "invalid_request" {
			t.Fatalf("%s token with cookie: %d", method, w.Code)
		}
	}
	if w := opRequest(h, "GET", "/probe", "", cookie, ""); w.Code != 200 {
		t.Fatal("session alone no longer works")
	}
	// Over a plain-HTTP connection that is not loopback the token is refused,
	// should such a listener ever mark requests remote.
	w := bearer(h, "GET", "/probe", created.Token, func(r *http.Request) *http.Request {
		r.Host, r.RemoteAddr = "panel.example.test", "198.51.100.7:51234"
		return r.WithContext(context.WithValue(r.Context(), remoteKey{}, true))
	})
	if w.Code != 403 || problemCode(t, w.Body.Bytes()) != "https_required" {
		t.Fatalf("token over plain HTTP: %d", w.Code)
	}
}

func TestAPITokenFailuresAreRateLimited(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m, h, cookie, s := tokenFixture(t, &now)
	created := createToken(t, h, cookie, s.CSRFToken, `{"name":"WHMCS"}`)
	remote := Remote(h, []string{"panel.example.test"})

	// Malformed headers count as failures and get the same answer.
	malformed := []func(*http.Request) *http.Request{
		func(r *http.Request) *http.Request { r.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4="); return r },
		func(r *http.Request) *http.Request { r.Header.Set("Authorization", "Bearer"); return r },
		func(r *http.Request) *http.Request { r.Header.Set("Authorization", "Bearer sfr_short"); return r },
		func(r *http.Request) *http.Request { r.Header.Set("Authorization", "Bearer  "+created.Token); return r },
		func(r *http.Request) *http.Request {
			r.Header.Add("Authorization", "Bearer "+created.Token)
			r.Header.Add("Authorization", "Bearer "+created.Token)
			return r
		},
	}
	for i := 0; i < 20; i++ {
		var w *httptest.ResponseRecorder
		if i < len(malformed) {
			w = bearer(h, "GET", "/probe", "", malformed[i])
		} else {
			w = bearer(h, "GET", "/probe", tokenPrefix+strings.Repeat("C", 43))
		}
		if w.Code != 401 || problemCode(t, w.Body.Bytes()) != "invalid_token" {
			t.Fatalf("failure %d: %d", i, w.Code)
		}
	}
	// The 21st failure is refused before any check, and while the limit is
	// used up a valid token waits too.
	for _, token := range []string{tokenPrefix + strings.Repeat("C", 43), created.Token} {
		if w := bearer(h, "GET", "/probe", token); w.Code != 429 || w.Header().Get("Retry-After") != "3" {
			t.Fatalf("over the limit: %d", w.Code)
		}
	}
	// Sign-in has its own limits, and the network has its own buckets.
	if w := opRequest(h, "GET", "/api/v1/session", "", cookie, ""); w.Code != 200 {
		t.Fatal("bearer failures affected the session")
	}
	key, err := os.ReadFile(m.AccessKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	signIn(t, h, strings.TrimSpace(string(key)), nil)
	if w := bearer(remote, "GET", "/probe", created.Token, fromNetwork("198.51.100.7:51234")); w.Code != 200 {
		t.Fatalf("network token while loopback is limited: %d %s", w.Code, w.Body.String())
	}

	// One address over the network: 5 failures, then 429 for a minute; another
	// address is not affected.
	for i := 0; i < 5; i++ {
		if w := bearer(remote, "GET", "/probe", tokenPrefix+strings.Repeat("D", 43), fromNetwork("198.51.100.7:51234")); w.Code != 401 {
			t.Fatalf("network failure %d: %d", i, w.Code)
		}
	}
	if w := bearer(remote, "GET", "/probe", created.Token, fromNetwork("198.51.100.7:51234")); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("network address over its limit: %d", w.Code)
	}
	if w := bearer(remote, "GET", "/probe", created.Token, fromNetwork("203.0.113.9:40000")); w.Code != 200 {
		t.Fatalf("another network address: %d", w.Code)
	}
}

func TestAPITokensPersistAndAreBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m, h, cookie, s := tokenFixture(t, &now)
	created := createToken(t, h, cookie, s.CSRFToken, `{"name":"WHMCS"}`)
	if w := bearer(h, "GET", "/probe", created.Token); w.Code != 200 {
		t.Fatal("token unusable")
	}

	// A restart keeps the token, its hash key and its last use.
	m2, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	m2.now = m.now
	mux2 := http.NewServeMux()
	m2.Register(mux2)
	h2 := withProbe(m2, mux2)
	if w := bearer(h2, "GET", "/probe", created.Token); w.Code != 200 {
		t.Fatalf("token after restart: %d", w.Code)
	}
	if len(m2.tokens.Tokens) != 1 || m2.tokens.Tokens[0].LastUsedAt == nil || !m2.tokens.Tokens[0].LastUsedAt.Equal(now) {
		t.Fatal("last use not saved")
	}

	// The last-used time is written at most once a minute.
	before, _ := os.ReadFile(filepath.Join(m.dir, tokensFile))
	now = now.Add(30 * time.Second)
	bearer(h2, "GET", "/probe", created.Token)
	if after, _ := os.ReadFile(filepath.Join(m.dir, tokensFile)); string(after) != string(before) {
		t.Fatal("last use written more than once a minute")
	}
	now = now.Add(30 * time.Second)
	bearer(h2, "GET", "/probe", created.Token)
	if after, _ := os.ReadFile(filepath.Join(m.dir, tokensFile)); string(after) == string(before) {
		t.Fatal("last use not updated after a minute")
	}

	// At most 32 tokens.
	for i := 1; i < maxTokens; i++ {
		createToken(t, h, cookie, s.CSRFToken, fmt.Sprintf(`{"name":"Token %d"}`, i))
	}
	if w := opRequest(h, "POST", tokensPath, `{"name":"One too many"}`, cookie, s.CSRFToken); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "token_limit" {
		t.Fatalf("over the limit: %d", w.Code)
	}

	// An edited file that fails its checks stops the panel instead of being
	// trusted.
	raw, _ := os.ReadFile(filepath.Join(m.dir, tokensFile))
	if err := os.WriteFile(filepath.Join(m.dir, tokensFile), []byte(strings.Replace(string(raw), `"version": 1`, `"version": 2`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(m.dir); err == nil {
		t.Fatal("an invalid token file was accepted")
	}
}
