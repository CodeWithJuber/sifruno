package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPreviewBoundary(t *testing.T) {
	expectedHost := ""
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != expectedHost {
			t.Error("unexpected upstream host")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("client credential/proxy headers reached upstream")
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<html><head></head><body>panel</body></html>")
		} else {
			io.WriteString(w, "{}")
		}
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	expectedHost = u.Host
	h := preview(u, "", "192.0.2.1:8081")
	for _, tc := range []struct {
		method, path, host, origin string
		want                       int
	}{
		{"GET", "/", "192.0.2.1:8081", "", 200}, {"GET", "/api/v1/server", "192.0.2.1:8081", "http://192.0.2.1:8081", 200},
		{"GET", "/", "attacker.invalid", "", 403}, {"GET", "/", "192.0.2.1:8081", "https://attacker.invalid", 403},
		{"POST", "/api/v1/server", "192.0.2.1:8081", "", 405}, {"GET", "/api/v1/trail", "192.0.2.1:8081", "", 403},
		{"GET", "/api/v1/budget", "192.0.2.1:8081", "", 403}, {"GET", "/.state/key", "192.0.2.1:8081", "", 404},
		{"GET", "/assets/../private", "192.0.2.1:8081", "", 404}, {"GET", "/json-api/createacct", "192.0.2.1:8081", "", 404},
		{"GET", "/api/v1/sites", "192.0.2.1:8081", "", 404}, {"GET", "/api/v1/sites/private-id/backups", "192.0.2.1:8081", "", 404},
		{"GET", "/api/v1/session", "192.0.2.1:8081", "", 404}, {"POST", "/api/v1/session/login", "192.0.2.1:8081", "", 405},
		{"POST", "/api/v1/sites", "192.0.2.1:8081", "", 405},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Host = tc.host
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Authorization", "Bearer non-secret-canary")
		r.Header.Set("Cookie", "canary=test")
		r.Header.Set("X-Forwarded-For", "192.0.2.99")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s: got%d want%d", tc.method, tc.path, w.Code, tc.want)
		}
		if tc.path == "/" && tc.want == 200 && !strings.Contains(w.Body.String(), `name="sifruno-public-preview"`) {
			t.Error("public view declaration missing")
		}
	}
}

func TestExactExternalHTTPSOrigin(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "http://"+r.Host {
			t.Error("accepted origin was not normalized to loopback upstream")
		}
		io.WriteString(w, "{}")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	origin := "https://mobile-example.trycloudflare.com"
	h := preview(u, origin, "192.0.2.1:8081")
	for _, tc := range []struct {
		origin, host string
		want         int
	}{
		{origin, "192.0.2.1:8081", 200},
		{"https://other.trycloudflare.com", "192.0.2.1:8081", 403},
		{"http://mobile-example.trycloudflare.com", "192.0.2.1:8081", 403},
		{origin + "/", "192.0.2.1:8081", 403},
		{origin + "?", "192.0.2.1:8081", 403},
		{origin + "#", "192.0.2.1:8081", 403},
		{origin + ":443", "192.0.2.1:8081", 403},
		{origin, "mobile-example.trycloudflare.com", 403},
	} {
		r := httptest.NewRequest("GET", "/api/v1/server", nil)
		r.Host = tc.host
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("origin=%q host=%q: got %d want %d", tc.origin, tc.host, w.Code, tc.want)
		}
	}
	for _, p := range []string{"/api/v1/trail", "/api/v1/budget"} {
		r := httptest.NewRequest("GET", p, nil)
		r.Host = "192.0.2.1:8081"
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("external origin exposed private tools")
		}
	}
}

func TestExternalOriginValidation(t *testing.T) {
	for _, s := range []string{"", "https://mobile-example.trycloudflare.com", "https://example.com:8443"} {
		if err := validateExternalOrigin(s); err != nil {
			t.Fatal("valid exact origin rejected", s)
		}
	}
	for _, s := range []string{"http://example.com", "https://user:password@example.com", "https://example.com/", "https://example.com/path", "https://example.com?", "https://example.com?key=value", "https://example.com#", "https://example.com#fragment", "https://example.com:", "https://example.com:0", "https://example.com:65536", "https:///example.com", "https:example.com", " https://example.com", "https://example.com\\path"} {
		if err := validateExternalOrigin(s); err == nil {
			t.Fatal("malformed external origin accepted", s)
		}
	}
}

func TestCrossSiteDocumentNavigation(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Site") != "same-origin" {
			http.Error(w, "Upstream cross-site access denied", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html><head></head><body>panel</body></html>")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	h := preview(u, "", "192.0.2.1:8081")
	for _, tc := range []struct {
		path, mode, dest, origin string
		want                     int
	}{
		{"/", "navigate", "document", "", 200},
		{"/services", "navigate", "document", "", 200},
		{"/", "navigate", "iframe", "", 403},
		{"/", "cors", "empty", "", 403},
		{"/api/v1/server", "navigate", "document", "", 403},
		{"/api/v1/trail", "navigate", "document", "", 403},
		{"/assets/main.js", "navigate", "document", "", 403},
		{"/", "navigate", "document", "https://foreign.invalid", 403},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = "192.0.2.1:8081"
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Sec-Fetch-Mode", tc.mode)
		r.Header.Set("Sec-Fetch-Dest", tc.dest)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s %s: got %d want %d", tc.path, tc.mode, tc.dest, w.Code, tc.want)
		}
	}
}
