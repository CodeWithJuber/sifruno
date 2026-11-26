package operator

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Manager, http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		var err error
		dir, err = filepath.EvalSymlinks(dir)
		if err != nil {
			t.Fatal(err)
		}
	}
	m, err := Open(filepath.Join(dir, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(m.AccessKeyPath())
	if err != nil {
		t.Fatal("fixture credential unreadable")
	}
	mux := http.NewServeMux()
	m.Register(mux)
	return m, mux, strings.TrimSpace(string(b))
}

func opRequest(h http.Handler, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func signIn(t *testing.T, h http.Handler, key string, old *http.Cookie) (*http.Cookie, Session) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"access_key": key})
	w := opRequest(h, "POST", "/api/v1/session/login", string(b), old, "")
	if w.Code != 200 {
		t.Fatalf("fixture login status %d", w.Code)
	}
	var s Session
	if json.Unmarshal(w.Body.Bytes(), &s) != nil || !s.Authenticated || !validToken(s.CSRFToken) {
		t.Fatal("invalid session DTO")
	}
	cs := w.Result().Cookies()
	if len(cs) != 1 {
		t.Fatal("missing session cookie")
	}
	return cs[0], s
}

func TestCredentialPersistencePrivateBoundsAndCookie(t *testing.T) {
	m, h, key := fixture(t)
	if len(key) != 43 || !validToken(key) {
		t.Fatal("incorrect credential format")
	}
	m2, err := Open(filepath.Dir(m.AccessKeyPath()))
	if err != nil {
		t.Fatal(err)
	}
	if m.keyHash != m2.keyHash {
		t.Fatal("credential rotated on reopen")
	}
	c, s := signIn(t, h, key, nil)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/api/v1" || c.MaxAge != 0 || !c.Expires.IsZero() || c.Secure {
		t.Fatal("incorrect local cookie policy")
	}
	if strings.Contains(c.Value, key) || strings.Contains(c.Value, s.CSRFToken) {
		t.Fatal("cookie payload was not encrypted")
	}
	if d := time.Until(s.ExpiresAt); d <= sessionMax-time.Minute || d > sessionMax {
		t.Fatal("incorrect session hard limit")
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", c, ""); w.Code != 200 {
		t.Fatal("active session unavailable")
	}
	// A newly opened manager shares persistent crypto keys but never resurrects
	// an access-key session: only password sessions are saved, and the saved
	// sessions are written when the panel stops.
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m2, err = Open(filepath.Dir(m.AccessKeyPath()))
	if err != nil {
		t.Fatal(err)
	}
	mux2 := http.NewServeMux()
	m2.Register(mux2)
	if w := opRequest(mux2, "GET", "/api/v1/session", "", c, ""); w.Code != 401 {
		t.Fatal("restart resurrected session")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(m.AccessKeyPath())
		if st.Mode().Perm() != 0600 {
			t.Fatal("credential mode not private")
		}
	}
}

func TestCookieForgeryRotationLogoutReplayAndExpiry(t *testing.T) {
	m, h, key := fixture(t)
	c, s := signIn(t, h, key, nil)
	forged := *c
	forged.Value = c.Value[:len(c.Value)-1] + "!"
	if w := opRequest(h, "GET", "/api/v1/session", "", &forged, ""); w.Code != 401 {
		t.Fatal("forged cookie accepted")
	}
	next, ns := signIn(t, h, key, c)
	if ns.CSRFToken == s.CSRFToken {
		t.Fatal("login did not rotate CSRF")
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", c, ""); w.Code != 401 {
		t.Fatal("rotated cookie still active")
	}
	if w := opRequest(h, "POST", "/api/v1/session/logout", "{}", next, s.CSRFToken); w.Code != 403 {
		t.Fatal("stale CSRF accepted")
	}
	if w := opRequest(h, "POST", "/api/v1/session/logout", "{}", next, ns.CSRFToken); w.Code != 200 || !strings.Contains(w.Body.String(), `"authenticated":false`) {
		t.Fatal("logout failed")
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", next, ""); w.Code != 401 {
		t.Fatal("logged-out cookie replay accepted")
	}
	c, _ = signIn(t, h, key, nil)
	current := m.now()
	m.now = func() time.Time { return current.Add(sessionIdle + time.Second) }
	if w := opRequest(h, "GET", "/api/v1/session", "", c, ""); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
}

func TestAdmissionOriginRemoteAndSensitiveMalformedInput(t *testing.T) {
	_, h, key := fixture(t)
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"access_key":"bad"}`, 401}, {`{"access_key":"` + key + `","unknown":true}`, 400},
		{`{"access_key":"` + key + `","access_key":"duplicate"}`, 400},
		{"{\"access_key\":\"\xff\"}", 400},
		{`{"access_key":`, 400}, {` `, 400}, {`null`, 400}, {`{"access_key":"` + key + `"} {}`, 400},
		{strings.Repeat("a", maxLoginBytes+1), 413},
	} {
		w := opRequest(h, "POST", "/api/v1/session/login", test.body, nil, "")
		if w.Code != test.status {
			t.Fatalf("unexpected malformed login status %d wanted %d", w.Code, test.status)
		}
		if strings.Contains(w.Body.String(), key) || (len(strings.TrimSpace(test.body)) > 8 && strings.Contains(w.Body.String(), test.body)) {
			t.Fatal("input echoed in problem details")
		}
	}
	for _, test := range []struct{ origin, remote string }{{"", "127.0.0.1:1000"}, {"http://foreign.invalid", "127.0.0.1:1000"}, {"http://127.0.0.1:8080", "192.0.2.1:1000"}} {
		b, _ := json.Marshal(map[string]string{"access_key": key})
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/session/login", strings.NewReader(string(b)))
		r.RemoteAddr = test.remote
		r.Header.Set("Origin", test.origin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("nonlocal or foreign origin login accepted")
		}
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", nil, ""); w.Code != 401 {
		t.Fatal("unauthenticated session accepted")
	}
	if w := opRequest(h, "POST", "/api/v1/session/logout", "{}", nil, ""); w.Code != 401 {
		t.Fatal("unauthenticated logout accepted")
	}
}

func TestLoginRateAndActiveSessionBounds(t *testing.T) {
	m, h, _ := fixture(t)
	for i := 0; i < 20; i++ {
		if w := opRequest(h, "POST", "/api/v1/session/login", `{"access_key":"wrong"}`, nil, ""); w.Code != 401 {
			t.Fatalf("attempt %d status %d", i, w.Code)
		}
	}
	if w := opRequest(h, "POST", "/api/v1/session/login", `{"access_key":"wrong"}`, nil, ""); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("login limiter not bounded")
	}
	if len(m.active) != 0 {
		t.Fatal("failed login created active session")
	}
	// Deliberately prefill only fixture bookkeeping to exercise the independent
	// active-session cap, not a second costly brute-force loop.
	m, h, key := fixture(t)
	for i := 0; i < maxSessions; i++ {
		id, err := randomToken()
		if err != nil {
			t.Fatal(err)
		}
		// The idle limit counts from creation until the first request.
		m.active[id] = activeSession{created: time.Now(), expires: time.Now().Add(time.Minute)}
	}
	b, _ := json.Marshal(map[string]string{"access_key": key})
	if w := opRequest(h, "POST", "/api/v1/session/login", string(b), nil, ""); w.Code != 429 {
		t.Fatal("active session cap not enforced")
	}
}

func TestTLSCookieAndMalformedPrivateStateFailClosed(t *testing.T) {
	m, h, key := fixture(t)
	b, _ := json.Marshal(map[string]string{"access_key": key})
	r := httptest.NewRequest("POST", "https://127.0.0.1:8080/api/v1/session/login", strings.NewReader(string(b)))
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "127.0.0.1:1000"
	r.Header.Set("Origin", "https://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || !w.Result().Cookies()[0].Secure {
		t.Fatal("TLS did not set secure cookie")
	}
	if err := os.WriteFile(m.AccessKeyPath(), []byte("broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Dir(m.AccessKeyPath())); err == nil || strings.Contains(err.Error(), m.AccessKeyPath()) {
		t.Fatal("malformed private credential did not fail safely")
	}
}

func TestPrivateCredentialHardlinkAndSessionKeyBounds(t *testing.T) {
	m, _, _ := fixture(t)
	alias := filepath.Join(filepath.Dir(m.AccessKeyPath()), "fixture-key-link")
	if err := os.Link(m.AccessKeyPath(), alias); err != nil {
		t.Skip("fixture filesystem does not support hardlinks")
	}
	if _, err := Open(filepath.Dir(m.AccessKeyPath())); err == nil {
		t.Fatal("credential hardlink accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal("fixture hardlink cleanup failed")
	}
	if _, err := Open(filepath.Dir(m.AccessKeyPath())); err != nil {
		t.Fatal("intact private state could not reopen")
	}
	keys := filepath.Join(filepath.Dir(m.AccessKeyPath()), "session.keys")
	f, err := os.OpenFile(keys, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal("fixture session key unavailable")
	}
	_, err = f.Write([]byte{1})
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("fixture session key append failed")
	}
	if _, err := Open(filepath.Dir(m.AccessKeyPath())); err == nil {
		t.Fatal("oversized session key accepted or silently rotated")
	}
}
