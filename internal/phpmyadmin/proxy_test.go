package phpmyadmin

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// upstreamFixture is phpMyAdmin's listener: it records what it was sent and
// answers with the headers a test gives it.
func upstreamFixture(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) (*Proxy, *http.Request, func() *http.Request) {
	t.Helper()
	var seen *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = r.Clone(r.Context())
		seen.Body = io.NopCloser(strings.NewReader(string(body)))
		answer(w, r)
	}))
	t.Cleanup(server.Close)
	s, err := NewProxy(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return s, seen, func() *http.Request { return seen }
}

func TestTheProxyStripsThePanelsCredentials(t *testing.T) {
	s, _, seen := upstreamFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "phpMyAdmin") })
	for _, https := range []bool{false, true} {
		// httptest gives an https:// request a TLS state, as the HTTPS listener does.
		origin := "http://127.0.0.1:8080"
		if https {
			origin = "https://panel.example.test:8443"
		}
		r := httptest.NewRequest("POST", origin+"/index.php?route=/sql", strings.NewReader("sql_query=SELECT+1"))
		r.Header.Set("Cookie", PanelCookie+"=panel-session; phpMyAdmin=pma-session; pma_lang=en; "+AdmissionCookie+"=admitted")
		r.Header.Add("Cookie", "SifrunoPhpMyAdminSignon=signon; "+PanelCookie+"=second")
		r.Header.Set("Authorization", "Bearer sfr_token")
		r.Header.Set("Proxy-Authorization", "Basic eA==")
		r.Header.Set("X-CSRF-Token", "csrf")
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Forwarded-Host", "evil.example")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Forwarded", "for=203.0.113.9;proto=https")
		r.Header.Set("X-Real-IP", "203.0.113.9")
		r.Header.Set("Proxy", "http://203.0.113.9:3128")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != "phpMyAdmin" {
			t.Fatalf("https=%v: %d %s", https, w.Code, w.Body.String())
		}
		got := seen()
		if got.URL.Path != "/index.php" || got.URL.RawQuery != "route=/sql" || got.Method != "POST" {
			t.Fatalf("forwarded %s %s?%s", got.Method, got.URL.Path, got.URL.RawQuery)
		}
		if body, _ := io.ReadAll(got.Body); string(body) != "sql_query=SELECT+1" {
			t.Fatalf("body %q", body)
		}
		if cookies := got.Header.Values("Cookie"); !slices.Equal(cookies, []string{"phpMyAdmin=pma-session; pma_lang=en; SifrunoPhpMyAdminSignon=signon"}) {
			t.Fatalf("cookies %q", cookies)
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "X-Csrf-Token", "X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "X-Real-Ip", "Proxy"} {
			if v := got.Header.Values(name); len(v) != 0 {
				t.Fatalf("https=%v: %s reached phpMyAdmin: %q", https, name, v)
			}
		}
		want := ""
		if https {
			want = "https"
		}
		// What the client sent is never passed on; the panel's own mark is.
		if v := got.Header.Values("X-Forwarded-Proto"); strings.Join(v, ",") != want {
			t.Fatalf("https=%v: X-Forwarded-Proto %q", https, v)
		}
		if strings.Contains(got.Host, "panel.example.test") || strings.Contains(got.Host, "evil") {
			t.Fatalf("Host %q", got.Host)
		}
	}

	// Only the panel's cookie: no Cookie header at all.
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080/", nil)
	r.Header.Set("Cookie", PanelCookie+"=panel-session; "+AdmissionCookie+"=admitted")
	s.ServeHTTP(httptest.NewRecorder(), r)
	if v := seen().Header.Values("Cookie"); len(v) != 0 {
		t.Fatalf("cookies %q", v)
	}
}

func TestTheProxyFiltersWhatPhpMyAdminAnswers(t *testing.T) {
	s, _, _ := upstreamFixture(t, func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for _, line := range []string{
			"phpMyAdmin=abc; path=/; HttpOnly; SameSite=Strict",
			"pma_lang=en; domain=example.test",
			PanelCookie + "=stolen; path=/api/v1; HttpOnly",
			AdmissionCookie + "=forged; path=/; Secure",
			"__Host-x=1; path=/; Secure",
			"tossed=1; path=/api/v1",
			"tossed2=1; path=/API",
			"pmaUser-1=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; path=/",
			"not a cookie",
		} {
			h.Add("Set-Cookie", line)
		}
		h.Set("Content-Security-Policy", "default-src *")
		h.Set("X-Content-Security-Policy", "default-src *")
		h.Set("X-WebKit-CSP", "default-src *")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Clear-Site-Data", `"cookies"`)
		h.Set("Referrer-Policy", "unsafe-url")
		h.Set("Server", "LiteSpeed")
		h.Set("X-Powered-By", "PHP/8.3")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Location", "http://"+r.Host+"/index.php?route=/")
		w.WriteHeader(http.StatusFound)
	})
	for _, https := range []bool{false, true} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:8080"+SignonPath, nil)
		if https {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		h := w.Result().Header
		cookies := h.Values("Set-Cookie")
		secure := ""
		if https {
			secure = "; Secure"
		}
		want := []string{
			"phpMyAdmin=abc; Path=/; HttpOnly" + secure + "; SameSite=Strict",
			"pma_lang=en; Path=/" + secure,
			"pmaUser-1=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0" + secure,
		}
		if !slices.Equal(cookies, want) {
			t.Fatalf("https=%v cookies\n%q\nwant\n%q", https, cookies, want)
		}
		for _, name := range strippedResponse {
			if v := h.Values(name); len(v) != 0 {
				t.Fatalf("%s passed on: %q", name, v)
			}
		}
		if h.Get("X-Frame-Options") != "DENY" {
			t.Fatal("phpMyAdmin's own X-Frame-Options was dropped")
		}
		if w.Code != http.StatusFound || h.Get("Location") != "/index.php?route=/" {
			t.Fatalf("redirect %d %q", w.Code, h.Get("Location"))
		}
	}
}

func TestTheProxyExplainsAFailure(t *testing.T) {
	// A listener that is gone.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	s, err := NewProxy(addr)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:8080/", nil))
	body := w.Body.String()
	if w.Code != http.StatusBadGateway || !strings.Contains(body, "phpMyAdmin did not answer.") || !strings.Contains(body, "Next step:") || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("%d %s", w.Code, body)
	}

	// An upload over the limit is refused before it is sent.
	s, _, seen := upstreamFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/index.php", strings.NewReader("x"))
	r.ContentLength = MaxRequestBytes + 1
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || seen() != nil {
		t.Fatalf("large upload: %d, sent %v", w.Code, seen() != nil)
	}
}

func TestWritePageEscapes(t *testing.T) {
	w := httptest.NewRecorder()
	WritePage(w, 403, "A <b>", "B & C", `D "E"`)
	body := w.Body.String()
	if w.Code != 403 || strings.Contains(body, "<b>") || !strings.Contains(body, "A &lt;b&gt;") || !strings.Contains(body, "B &amp; C") || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("%d %s", w.Code, body)
	}
}

func TestTheProxyGoesToLoopbackOnly(t *testing.T) {
	for _, upstream := range []string{"", "8090", "10.0.0.5:8090", "localhost:8090", "0.0.0.0:8090", "127.0.0.1:0", "127.0.0.1:x", "[::1]:8090x"} {
		if _, err := NewProxy(upstream); err == nil {
			t.Fatalf("upstream %q was accepted", upstream)
		}
	}
	for _, upstream := range []string{"127.0.0.1:8090", "[::1]:8090", "127.0.0.2:1"} {
		if _, err := NewProxy(upstream); err != nil {
			t.Fatalf("upstream %q: %v", upstream, err)
		}
	}
}
