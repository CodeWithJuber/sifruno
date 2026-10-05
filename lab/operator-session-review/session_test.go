package operator_session_review_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"sifruno/internal/api"
	"sifruno/internal/operator"
)

const origin = "http://127.0.0.1:8181"

type fixture struct {
	manager  *operator.Manager
	handler  http.Handler
	key, dir string
}
type admission struct {
	cookie      *http.Cookie
	csrf, rawID string
}
type inventory struct {
	Items []struct {
		ID      string    `json:"id"`
		Created time.Time `json:"created_at"`
		Expires time.Time `json:"expires_at"`
		Current bool      `json:"current"`
	} `json:"items"`
	Capacity int `json:"capacity"`
	Lifetime int `json:"lifetime_seconds"`
}

func isolated(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	m, err := operator.Open(filepath.Join(dir, "operator"))
	if err != nil {
		t.Fatal("isolated manager unavailable")
	}
	b, err := os.ReadFile(m.AccessKeyPath())
	if err != nil {
		t.Fatal("isolated key unavailable")
	}
	return fixture{m, api.New(api.Options{Operator: m, AllowedOrigins: []string{origin}}), strings.TrimSpace(string(b)), dir}
}
func request(h http.Handler, method, path, body string, a admission, adjust func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, origin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:52221"
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	if a.cookie != nil {
		r.AddCookie(a.cookie)
	}
	if a.csrf != "" {
		r.Header.Set("X-CSRF-Token", a.csrf)
	}
	if adjust != nil {
		adjust(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func expect(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP status got %d, want %d (body withheld)", w.Code, status)
	}
}
func decode(t *testing.T, w *httptest.ResponseRecorder, dst any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(w.Body.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(&struct{}{}) != io.EOF {
		t.Fatal("response violates exact DTO")
	}
}

func exactKeys(t *testing.T, raw []byte, keys ...string) map[string]json.RawMessage {
	t.Helper()
	var v map[string]json.RawMessage
	if json.Unmarshal(raw, &v) != nil || len(v) != len(keys) {
		t.Fatal("response key inventory differs")
	}
	for _, key := range keys {
		if _, ok := v[key]; !ok {
			t.Fatal("response contains a field alias or omitted field")
		}
	}
	return v
}
func login(t *testing.T, f fixture, old admission) admission {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"access_key": f.key})
	w := request(f.handler, "POST", "/api/v1/session/login", string(b), old, nil)
	expect(t, w, 200)
	var dto operator.Session
	decode(t, w, &dto)
	if !dto.Authenticated || dto.CSRFToken == "" {
		t.Fatal("legacy session DTO unavailable")
	}
	cs := w.Result().Cookies()
	if len(cs) != 1 || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteStrictMode || cs[0].Path != "/api/v1" || cs[0].MaxAge != 900 {
		t.Fatal("legacy cookie policy changed")
	}
	keys, err := os.ReadFile(filepath.Join(filepath.Dir(f.manager.AccessKeyPath()), "session.keys"))
	if err != nil || len(keys) != 64 {
		t.Fatal("isolated cookie decoder unavailable")
	}
	r := httptest.NewRequest("GET", origin+"/api/v1/session", nil)
	r.AddCookie(cs[0])
	s, err := sessions.NewCookieStore(keys[:32], keys[32:]).New(r, "sifruno_operator")
	if err != nil {
		t.Fatal("isolated cookie decode failed")
	}
	id, ok := s.Values["id"].(string)
	if !ok {
		t.Fatal("isolated cookie ID unavailable")
	}
	return admission{cs[0], dto.CSRFToken, id}
}
func list(t *testing.T, f fixture, a admission, forbidden ...admission) inventory {
	t.Helper()
	w := request(f.handler, "GET", "/api/v1/session/sessions", "", a, nil)
	expect(t, w, 200)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" || len(w.Result().Cookies()) != 0 {
		t.Fatal("inventory cache/content/cookie contract changed")
	}
	var v inventory
	decode(t, w, &v)
	fields := exactKeys(t, w.Body.Bytes(), "items", "capacity", "lifetime_seconds")
	var rawItems []json.RawMessage
	if json.Unmarshal(fields["items"], &rawItems) != nil {
		t.Fatal("inventory items unavailable")
	}
	for _, raw := range rawItems {
		exactKeys(t, raw, "id", "created_at", "expires_at", "current")
	}
	if v.Capacity != 128 || v.Lifetime != 900 || v.Items == nil || len(v.Items) > 128 {
		t.Fatal("inventory bounds invalid")
	}
	seen := map[string]bool{}
	currents := 0
	for _, x := range v.Items {
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(x.ID) || seen[x.ID] || x.Created.IsZero() || x.Expires.Sub(x.Created) != 900*time.Second || x.Created.After(time.Now().Add(time.Second)) || !x.Expires.After(time.Now()) {
			t.Fatal("metadata invariants invalid")
		}
		seen[x.ID] = true
		if x.Current {
			currents++
		}
	}
	if currents != 1 {
		t.Fatal("inventory lacks exactly one authorizer")
	}
	secrets := []string{f.key, a.csrf, a.rawID, a.cookie.Value}
	for _, x := range forbidden {
		secrets = append(secrets, x.csrf, x.rawID, x.cookie.Value)
	}
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(w.Body.Bytes(), []byte(secret)) {
			t.Fatal("inventory exposed an isolated credential")
		}
	}
	return v
}
func current(v inventory) string {
	for _, x := range v.Items {
		if x.Current {
			return x.ID
		}
	}
	return ""
}
func count(t *testing.T, w *httptest.ResponseRecorder, n int) {
	t.Helper()
	expect(t, w, 200)
	var v struct {
		N int `json:"revoked_count"`
	}
	decode(t, w, &v)
	if v.N != n {
		t.Fatal("revocation count differs")
	}
}

func TestIndependentInventoryAndRevocationFlow(t *testing.T) {
	f := isolated(t)
	a := login(t, f, admission{})
	b := login(t, f, admission{})
	c := login(t, f, admission{})
	av := list(t, f, a, b, c)
	bv := list(t, f, b, a, c)
	cv := list(t, f, c, a, b)
	if len(av.Items) != 3 || current(av) == current(bv) || current(av) == current(cv) || current(bv) == current(cv) {
		t.Fatal("current metadata or unique IDs invalid")
	}
	before, _ := json.Marshal(av)
	after, _ := json.Marshal(list(t, f, a, b, c))
	if !bytes.Equal(before, after) {
		t.Fatal("inventory changes without mutation")
	}
	expect(t, request(f.handler, "POST", "/api/v1/session/sessions/"+current(av)+"/revoke", "{}", a, nil), 409)
	unknown := strings.Repeat("f", 32)
	for _, x := range av.Items {
		if x.ID == unknown {
			unknown = strings.Repeat("e", 32)
		}
	}
	expect(t, request(f.handler, "POST", "/api/v1/session/sessions/"+unknown+"/revoke", "{}", a, nil), 404)
	count(t, request(f.handler, "POST", "/api/v1/session/sessions/"+current(bv)+"/revoke", "{}", a, nil), 1)
	expect(t, request(f.handler, "GET", "/api/v1/session", "", b, nil), 401)
	count(t, request(f.handler, "POST", "/api/v1/session/revoke-others", "{}", a, nil), 1)
	expect(t, request(f.handler, "GET", "/api/v1/session", "", c, nil), 401)
	if len(list(t, f, a).Items) != 1 {
		t.Fatal("revoke-others did not retain only current")
	}
	count(t, request(f.handler, "POST", "/api/v1/session/revoke-others", "{}", a, nil), 0)
	expect(t, request(f.handler, "GET", "/api/v1/session", "", a, nil), 200)
	rotated := login(t, f, a)
	expect(t, request(f.handler, "GET", "/api/v1/session", "", a, nil), 401)
	if len(list(t, f, rotated).Items) != 1 || current(list(t, f, rotated)) == current(av) {
		t.Fatal("login rotation retained old metadata")
	}
}

func TestIndependentStrictMutationAndAdmission(t *testing.T) {
	f := isolated(t)
	a := login(t, f, admission{})
	b := login(t, f, admission{})
	target := current(list(t, f, b, a))
	for _, path := range []string{"/api/v1/session/revoke-others", "/api/v1/session/sessions/" + target + "/revoke"} {
		for _, tc := range []struct {
			name, body string
			status     int
		}{
			{"empty", "", 400}, {"null", "null", 400}, {"array", "[]", 400}, {"unknown", `{"credential":"REVIEW_SENTINEL"}`, 400}, {"alias", `{"ID":"REVIEW_SENTINEL"}`, 400}, {"duplicate", `{"x":1,"x":2}`, 400}, {"trailing", "{} {}", 400}, {"invalid_utf8", "{\"x\":\"\xff\"}", 400}, {"oversize", strings.Repeat(" ", 2049), 413},
		} {
			t.Run(strings.TrimPrefix(path, "/api/v1/session/")+"/"+tc.name, func(t *testing.T) {
				w := request(f.handler, "POST", path, tc.body, a, nil)
				expect(t, w, tc.status)
				if bytes.Contains(w.Body.Bytes(), []byte("REVIEW_SENTINEL")) {
					t.Fatal("fixed error reflected input")
				}
			})
		}
		for _, tc := range []struct {
			name   string
			status int
			adjust func(*http.Request)
		}{
			{"content_type", 415, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
			{"charset", 415, func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }},
			{"origin_missing", 403, func(r *http.Request) { r.Header.Del("Origin") }},
			{"origin_port", 403, func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:8182") }},
			{"csrf_missing", 403, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }},
			{"csrf_other_session", 403, func(r *http.Request) { r.Header.Set("X-CSRF-Token", b.csrf) }},
			{"cross_site", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
			{"foreign_peer_forwarded", 403, func(r *http.Request) { r.RemoteAddr = "192.0.2.1:52221"; r.Header.Set("X-Forwarded-For", "127.0.0.1") }},
			{"foreign_host", 403, func(r *http.Request) { r.Host = "example.invalid" }},
		} {
			t.Run(strings.TrimPrefix(path, "/api/v1/session/")+"/"+tc.name, func(t *testing.T) { expect(t, request(f.handler, "POST", path, "{}", a, tc.adjust), tc.status) })
		}
	}
	for _, bad := range []string{"short", strings.Repeat("0", 33), "ABCDEF0123456789ABCDEF0123456789", "0000000000000000000000000000000g"} {
		w := request(f.handler, "POST", "/api/v1/session/sessions/"+bad+"/revoke", "{}", a, nil)
		if w.Code != 400 && w.Code != 422 {
			t.Fatalf("invalid public ID returned %d", w.Code)
		}
	}
	expect(t, request(f.handler, "GET", "/api/v1/session/sessions", "", admission{}, nil), 401)
	if len(list(t, f, a, b).Items) != 2 {
		t.Fatal("rejected mutation changed inventory")
	}
	expect(t, request(f.handler, "GET", "/api/v1/session", "", b, nil), 200)
}

type gatedBody struct {
	io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}
func (b *gatedBody) Close() error { return nil }

func TestIndependentRevokedAuthorizerCannotMutate(t *testing.T) {
	for _, action := range []string{"revoke-others", "revoke-target"} {
		t.Run(action, func(t *testing.T) {
			f := isolated(t)
			a := login(t, f, admission{})
			b := login(t, f, admission{})
			c := login(t, f, admission{})
			aID := current(list(t, f, a, b, c))
			cID := current(list(t, f, c, a, b))
			path := "/api/v1/session/revoke-others"
			if action == "revoke-target" {
				path = "/api/v1/session/sessions/" + cID + "/revoke"
			}
			body := &gatedBody{Reader: strings.NewReader("{}"), entered: make(chan struct{}), release: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(body.release) }) }
			defer release()
			r := httptest.NewRequest("POST", origin+path, body)
			r.RemoteAddr = "127.0.0.1:52221"
			r.AddCookie(a.cookie)
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", a.csrf)
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { f.handler.ServeHTTP(w, r); close(done) }()
			select {
			case <-body.entered:
			case <-time.After(3 * time.Second):
				release()
				t.Fatal("pending request did not reach bounded body read")
			}
			count(t, request(f.handler, "POST", "/api/v1/session/sessions/"+aID+"/revoke", "{}", b, nil), 1)
			release()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("pending request did not finish")
			}
			expect(t, w, 401)
			if len(list(t, f, b, c).Items) != 2 {
				t.Fatal("revoked authorizer deleted another admission")
			}
			expect(t, request(f.handler, "GET", "/api/v1/session", "", c, nil), 200)
		})
	}
}

func TestIndependentRestartAndLegacyLogout(t *testing.T) {
	f := isolated(t)
	a := login(t, f, admission{})
	m, err := operator.Open(filepath.Dir(f.manager.AccessKeyPath()))
	if err != nil {
		t.Fatal("isolated reopened manager unavailable")
	}
	h := api.New(api.Options{Operator: m, AllowedOrigins: []string{origin}})
	expect(t, request(h, "GET", "/api/v1/session/sessions", "", a, nil), 401)
	expect(t, request(h, "POST", "/api/v1/session/revoke-others", "{}", a, nil), 401)
	expect(t, request(f.handler, "POST", "/api/v1/session/logout", "{}", a, nil), 200)
	expect(t, request(f.handler, "GET", "/api/v1/session/sessions", "", a, nil), 401)
}
