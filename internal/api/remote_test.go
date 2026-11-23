package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sifruno/internal/operator"
)

const remoteOrigin = "https://panel.example.test:2083"

// remoteRequest is a request as it arrives on the HTTPS listener from
// another machine.
func remoteRequest(h http.Handler, method, path string, body any, cookie *http.Cookie, csrf string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	var text string
	if raw, ok := body.(string); ok {
		text = raw
	} else if body != nil {
		b, _ := json.Marshal(body)
		text = string(b)
	}
	r := httptest.NewRequest(method, remoteOrigin+path, strings.NewReader(text))
	r.RemoteAddr = "198.51.100.7:51234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", remoteOrigin)
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	for _, m := range mutate {
		m(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func testCode(secret string, step int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	o := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[o:o+4])&0x7fffffff)%1000000)
}

func TestRemoteListenerAdminOnly(t *testing.T) {
	f := websiteFixture(t)
	remote := operator.Remote(f.handler, []string{"panel.example.test"})

	// Wrong host name, or plain HTTP, never reaches the API.
	if w := remoteRequest(remote, "GET", "/api/v1/server", nil, nil, "", func(r *http.Request) { r.Host = "other.test:2083" }); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign host: %d", w.Code)
	}
	if w := remoteRequest(remote, "GET", "/api/v1/server", nil, nil, "", func(r *http.Request) { r.TLS = nil }); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("plain HTTP: %d", w.Code)
	}
	// Readings that loopback serves openly need a session over the network.
	for _, path := range []string{"/api/v1/server", "/api/v1/services", "/api/v1/platform", "/api/v1/trail", "/openapi.json", "/api/v1/sites"} {
		if w := remoteRequest(remote, "GET", path, nil, nil, ""); w.Code != 401 {
			t.Fatalf("%s without a session: %d", path, w.Code)
		}
	}
	if w := remoteRequest(remote, "GET", "/json-api/listaccts", nil, nil, ""); w.Code != 404 {
		t.Fatalf("WHM transport on the panel listener: %d", w.Code)
	}
	if w := remoteRequest(remote, "POST", "/api/v1/session/login", map[string]string{"access_key": f.key}, nil, ""); w.Code != 403 || strings.Contains(w.Body.String(), f.key) {
		t.Fatalf("access key over the network: %d", w.Code)
	}
	if w := remoteRequest(remote, "GET", "/api/v1/session/setup", nil, nil, ""); w.Code != 200 {
		t.Fatalf("setup status: %d", w.Code)
	}

	// A key session made on the server is not accepted over the network,
	// and setup cannot be started from there.
	keyCookie, keyCSRF := websiteSignIn(t, f)
	if w := remoteRequest(remote, "GET", "/api/v1/sites", nil, keyCookie, ""); w.Code != 403 || !strings.Contains(w.Body.String(), "admin_sign_in_required") {
		t.Fatalf("key session over the network: %d %s", w.Code, w.Body.String())
	}
	if w := remoteRequest(remote, "POST", "/api/v1/session/setup/totp", map[string]string{"username": "admin"}, keyCookie, keyCSRF); w.Code != 403 {
		t.Fatalf("setup over the network: %d", w.Code)
	}

	// Create the admin on the server. Use the previous step's code (inside the
	// accepted window) so the current step is still free for the remote login.
	w := websiteRequest(f.handler, "POST", "/api/v1/session/setup/totp", map[string]string{"username": "admin"}, keyCookie, keyCSRF)
	var secret struct {
		Secret string `json:"secret"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &secret) != nil {
		t.Fatalf("begin setup: %d", w.Code)
	}
	step := time.Now().Unix() / 30
	w = websiteRequest(f.handler, "POST", "/api/v1/session/setup/admin", map[string]string{"username": "admin", "password": "a long enough password", "totp_code": testCode(secret.Secret, step-1)}, keyCookie, keyCSRF)
	if w.Code != 200 {
		t.Fatalf("finish setup: %d %s", w.Code, w.Body.String())
	}

	w = remoteRequest(remote, "POST", "/api/v1/session/login", map[string]string{"username": "admin", "password": "a long enough password", "totp_code": testCode(secret.Secret, step)}, nil, "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("admin login over the network: %d %s", w.Code, w.Body.String())
	}
	adminCookie := w.Result().Cookies()[0]
	if !adminCookie.Secure || !adminCookie.HttpOnly || adminCookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("the session cookie must be Secure, HttpOnly and SameSite=Strict over HTTPS")
	}
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &session)
	for _, path := range []string{"/api/v1/server", "/api/v1/sites", "/openapi.json"} {
		if w := remoteRequest(remote, "GET", path, nil, adminCookie, ""); w.Code != 200 {
			t.Fatalf("%s with an admin session: %d", path, w.Code)
		}
	}
	if w := remoteRequest(remote, "POST", "/api/v1/sites", map[string]string{"name": "Remote", "domain": "remote.test"}, adminCookie, ""); w.Code != 403 {
		t.Fatalf("write without CSRF: %d", w.Code)
	}
	if w := remoteRequest(remote, "POST", "/api/v1/sites", map[string]string{"name": "Remote", "domain": "remote.test"}, adminCookie, session.CSRF, func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }); w.Code != 403 {
		t.Fatalf("foreign origin: %d", w.Code)
	}
	if w := remoteRequest(remote, "POST", "/api/v1/sites", map[string]string{"name": "Remote", "domain": "remote.test"}, adminCookie, session.CSRF); w.Code != 201 && w.Code != 200 {
		t.Fatalf("admin write over the network: %d %s", w.Code, w.Body.String())
	}
	// The loopback listener still works as before, with no remote marking.
	if w := websiteRequest(f.handler, "GET", "/api/v1/server", nil, nil, ""); w.Code != 200 {
		t.Fatalf("loopback reading: %d", w.Code)
	}
}

// Failed sign-ins from the network must not use up the server's own limits,
// and one outside address must not lock the admin out of another.
func TestRemoteSignInLimitsAreSeparate(t *testing.T) {
	f := websiteFixture(t)
	remote := operator.Remote(f.handler, []string{"panel.example.test"})
	keyCookie, keyCSRF := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "POST", "/api/v1/session/setup/totp", map[string]string{"username": "admin"}, keyCookie, keyCSRF)
	var secret struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &secret)
	step := time.Now().Unix() / 30
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/setup/admin", map[string]string{"username": "admin", "password": "a long enough password", "totp_code": testCode(secret.Secret, step-1)}, keyCookie, keyCSRF); w.Code != 200 {
		t.Fatalf("setup: %d", w.Code)
	}

	from := func(ip string) func(*http.Request) { return func(r *http.Request) { r.RemoteAddr = ip + ":40000" } }
	limited := 0
	for i := 0; i < 25; i++ {
		w := remoteRequest(remote, "POST", "/api/v1/session/login", map[string]string{"username": "admin", "password": "wrong password here", "totp_code": "123456"}, nil, "", from("203.0.113.9"))
		if w.Code == 429 {
			limited++
		} else if w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if limited == 0 {
		t.Fatal("25 failures from one address were never limited")
	}
	// The server's own access-key login is untouched.
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/login", map[string]string{"access_key": f.key}, nil, ""); w.Code != 200 {
		t.Fatalf("loopback key login after network failures: %d", w.Code)
	}
	// The same username from another address has its own five tries; the
	// network-wide limit refills one try every 3 seconds.
	time.Sleep(3100 * time.Millisecond)
	w = remoteRequest(remote, "POST", "/api/v1/session/login", map[string]string{"username": "admin", "password": "a long enough password", "totp_code": testCode(secret.Secret, step)}, nil, "", from("198.51.100.20"))
	if w.Code != 200 {
		t.Fatalf("admin from another address: %d %s", w.Code, w.Body.String())
	}
}
