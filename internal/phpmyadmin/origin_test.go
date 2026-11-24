package phpmyadmin

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const pmaOrigin = "https://panel.example.test:8444"

// fakeScript stands in for the listener behind the proxy: the sign-in
// script redeems a code and redirects as the shipped one does, and every
// other page answers with its path. It records what reached it.
type fakeScript struct {
	mu     sync.Mutex
	svc    *Service
	passed []*http.Request
}

func (f *fakeScript) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.passed = append(f.passed, r.Clone(context.Background()))
	f.mu.Unlock()
	if r.URL.Path == SignonPath && r.URL.Query().Get("code") != "" {
		if _, err := f.svc.Redeem(r.URL.Query().Get("code")); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Add("Set-Cookie", "SifrunoPhpMyAdminSignon=s; path=/; secure; HttpOnly; SameSite=Strict")
		w.Header().Set("Location", "/index.php")
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	_, _ = w.Write([]byte("phpMyAdmin " + r.URL.Path))
}

func originFixture(t *testing.T) (*Origin, *Service, *fakeScript, *clock) {
	t.Helper()
	db := newFakeDatabase()
	c := &clock{now: time.Now()}
	s, _ := newTestService(t, db, c)
	script := &fakeScript{svc: s}
	return NewOrigin(s, script, []string{"Panel.Example.Test"}), s, script, c
}

func originRequest(h http.Handler, method, path string, cookies []*http.Cookie, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, pmaOrigin+path, strings.NewReader("token=t"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	for _, m := range mutate {
		m(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func admission(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == AdmissionCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestACodeLetsTheBrowserInUntilItsLoginEnds(t *testing.T) {
	o, s, script, c := originFixture(t)
	h, err := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing gets in without a code or a cookie, and nothing is passed on.
	for _, path := range []string{"/", "/index.php", SignonPath} {
		w := originRequest(o, "GET", path, nil)
		if w.Code != 401 || !strings.Contains(w.Body.String(), "phpMyAdmin needs a new sign-in.") {
			t.Fatalf("GET %s with no admission: %d %s", path, w.Code, w.Body.String())
		}
	}
	if len(script.passed) != 0 {
		t.Fatalf("%d requests reached phpMyAdmin", len(script.passed))
	}

	w := originRequest(o, "GET", h.Path, nil)
	cookie := admission(t, w)
	if w.Code != http.StatusSeeOther || cookie == nil {
		t.Fatalf("sign-in: %d %v", w.Code, w.Result().Cookies())
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge < 3500 || cookie.MaxAge > 3600 {
		t.Fatalf("admission cookie %+v", cookie)
	}
	if !strings.Contains(strings.Join(w.Result().Header.Values("Set-Cookie"), "\n"), "SifrunoPhpMyAdminSignon=") {
		t.Fatal("the script's own cookie was lost")
	}
	if got := w.Header().Get("Content-Security-Policy"); got != CSP {
		t.Fatalf("CSP %q", got)
	}

	// The cookie alone lets the browser in, and never reaches phpMyAdmin.
	w = originRequest(o, "GET", "/index.php", []*http.Cookie{cookie})
	if w.Code != 200 || w.Body.String() != "phpMyAdmin /index.php" {
		t.Fatalf("admitted: %d %s", w.Code, w.Body.String())
	}
	if last := script.passed[len(script.passed)-1]; strings.Contains(last.Header.Get("Cookie"), AdmissionCookie) {
		t.Fatal("the admission cookie reached phpMyAdmin")
	}

	// The same code again: refused here, before phpMyAdmin, and no cookie.
	before := len(script.passed)
	w = originRequest(o, "GET", h.Path, nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "This phpMyAdmin link no longer works.") || admission(t, w) != nil || len(script.passed) != before {
		t.Fatalf("reused code: %d %s", w.Code, w.Body.String())
	}
	// Two codes, a code array or a query Go cannot read: refused before
	// phpMyAdmin, so Go and PHP never read different codes.
	h2, err := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{h2.Path + "&code=" + strings.Repeat("A", 43), SignonPath + "?code=" + strings.Repeat("A", 43) + "&" + strings.TrimPrefix(h2.Path, SignonPath+"?"),
		h2.Path + "&code[]=x", h2.Path + ";code=x"} {
		if w := originRequest(o, "GET", query, nil); w.Code != 400 || admission(t, w) != nil || len(script.passed) != before {
			t.Fatalf("%s: %d", query, w.Code)
		}
	}
	if _, ok := s.Peek(strings.TrimPrefix(h2.Path, SignonPath+"?code=")); !ok {
		t.Fatal("a refused request used up the code")
	}

	// A forged cookie is refused and cleared.
	w = originRequest(o, "GET", "/index.php", []*http.Cookie{{Name: AdmissionCookie, Value: strings.Repeat("A", 43)}})
	if w.Code != 401 || !strings.Contains(w.Header().Get("Set-Cookie"), AdmissionCookie+"=;") {
		t.Fatalf("forged cookie: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}

	// The temporary user expires: the cookie stops working with it.
	c.Add(time.Hour)
	w = originRequest(o, "GET", "/index.php", []*http.Cookie{cookie})
	if w.Code != 401 || len(script.passed) != before {
		t.Fatalf("after the login expired: %d", w.Code)
	}
}

func TestSigningOutEndsTheAdmission(t *testing.T) {
	o, s, _, _ := originFixture(t)
	h, _ := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	cookie := admission(t, originRequest(o, "GET", h.Path, nil))
	if cookie == nil {
		t.Fatal("no admission")
	}
	w := originRequest(o, "GET", SignonPath+"?signed_out=1", []*http.Cookie{cookie})
	if w.Code != 200 || !strings.Contains(strings.Join(w.Result().Header.Values("Set-Cookie"), "\n"), AdmissionCookie+"=;") {
		t.Fatalf("sign-out: %d %q", w.Code, w.Result().Header.Values("Set-Cookie"))
	}
	if w := originRequest(o, "GET", "/index.php", []*http.Cookie{cookie}); w.Code != 401 {
		t.Fatalf("after sign-out: %d", w.Code)
	}
}

func TestTheOriginServesPhpMyAdminOnly(t *testing.T) {
	o, s, script, _ := originFixture(t)
	h, _ := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	cookie := admission(t, originRequest(o, "GET", h.Path, nil))
	admitted := []*http.Cookie{cookie, {Name: PanelCookie, Value: "panel-session"}}
	before := len(script.passed)

	// The panel's API path: its cookie would be sent here, so nothing is served.
	for _, path := range []string{"/api", "/api/v1/session", "/API/v1/sites", "/api/v1/phpmyadmin/"} {
		w := originRequest(o, "GET", path, admitted)
		if w.Code != 404 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("GET %s: %d", path, w.Code)
		}
	}
	// Another host name, or plain HTTP.
	if w := originRequest(o, "GET", "/index.php", admitted, func(r *http.Request) { r.Host = "evil.example:8444" }); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign host: %d", w.Code)
	}
	if w := originRequest(o, "GET", "/index.php", admitted, func(r *http.Request) { r.TLS = nil }); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("plain HTTP: %d", w.Code)
	}
	// An API token, an unclean path, another method, a cross-site request,
	// a POST from another origin or with none.
	for name, tc := range map[string]struct {
		method, path string
		mutate       func(*http.Request)
		code         int
	}{
		"token":        {"GET", "/index.php", func(r *http.Request) { r.Header.Set("Authorization", "Bearer sfr_x") }, 403},
		"dot dot":      {"GET", "/js/../index.php", nil, 400},
		"double slash": {"GET", "/js//x.js", nil, 400},
		"PUT":          {"PUT", "/index.php", nil, 405},
		"cross-site":   {"GET", "/index.php", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		"panel origin": {"POST", "/index.php", func(r *http.Request) { r.Header.Set("Origin", "https://panel.example.test:8443") }, 403},
		"no origin":    {"POST", "/index.php", nil, 403},
	} {
		mutate := tc.mutate
		if mutate == nil {
			mutate = func(*http.Request) {}
		}
		if w := originRequest(o, tc.method, tc.path, admitted, mutate); w.Code != tc.code {
			t.Fatalf("%s: %d, want %d", name, w.Code, tc.code)
		}
	}
	if len(script.passed) != before {
		t.Fatalf("refused requests reached phpMyAdmin: %d", len(script.passed)-before)
	}
	// phpMyAdmin's own POST, with the panel's cookie stripped.
	w := originRequest(o, "POST", "/index.php", admitted, func(r *http.Request) { r.Header.Set("Origin", pmaOrigin) })
	if w.Code != 200 || len(script.passed) != before+1 {
		t.Fatalf("phpMyAdmin's POST: %d", w.Code)
	}
}

// The origin with the real proxy: a TLS request gets X-Forwarded-Proto and
// no admission or panel cookie reaches the listener.
func TestTheOriginWithTheProxy(t *testing.T) {
	var got *http.Request
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Clone(context.Background()) }))
	defer listener.Close()
	proxy, err := NewProxy(strings.TrimPrefix(listener.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newTestService(t, newFakeDatabase(), &clock{now: time.Now()})
	o := NewOrigin(s, proxy, []string{"panel.example.test"})
	h, _ := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	w := originRequest(o, "GET", h.Path, []*http.Cookie{{Name: PanelCookie, Value: "p"}}, func(r *http.Request) { r.TLS = &tls.ConnectionState{} })
	if w.Code != 200 || got == nil || got.Header.Get("X-Forwarded-Proto") != "https" || strings.Contains(got.Header.Get("Cookie"), PanelCookie) {
		t.Fatalf("%d %v", w.Code, got)
	}
}
