package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
)

type webPreviewSpy struct {
	calls int
	fn    func(context.Context) (hostaccounts.WebPreview, error)
}

func (s *webPreviewSpy) Preview(ctx context.Context) (hostaccounts.WebPreview, error) {
	s.calls++
	return s.fn(ctx)
}

func webPreviewFixtureValue() hostaccounts.WebPreview {
	return hostaccounts.WebPreview{Profile: "restricted-chroot-v1", ProfileSHA256: strings.Repeat("1", 64), SnapshotSHA256: strings.Repeat("2", 64), BundleSHA256: strings.Repeat("3", 64), Files: []hostaccounts.WebPreviewFile{{Path: "apache/front.conf", Mode: 0600, Bytes: 99, SHA256: strings.Repeat("4", 64)}}}
}

func TestWebPreviewAdmissionAndMetadata(t *testing.T) {
	f := websiteFixture(t)
	s := &webPreviewSpy{fn: func(context.Context) (hostaccounts.WebPreview, error) { return webPreviewFixtureValue(), nil }}
	f.handler = New(Options{Operator: f.manager, WebPreview: s, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	if w := websiteRequest(f.handler, "GET", webPreviewPath, nil, nil, ""); w.Code != 401 || s.calls != 0 {
		t.Fatal("unauthorized preview contacted broker")
	}
	cookie, _ := websiteSignIn(t, f)
	for _, tc := range []struct {
		name, method, path string
		body               any
		code               int
	}{
		{"query", "GET", webPreviewPath + "?profile=attacker", nil, 400},
		{"empty-query", "GET", webPreviewPath + "?", nil, 400},
		{"encoded-path", "GET", "/api/v1/accounts/%77eb-preview", nil, 400},
		{"body", "GET", webPreviewPath, `{}`, 400},
		{"head", "HEAD", webPreviewPath, nil, 405},
		{"post", "POST", webPreviewPath, nil, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := websiteRequest(f.handler, tc.method, tc.path, tc.body, cookie, "")
			if w.Code != tc.code || s.calls != 0 {
				t.Fatalf("status=%d calls=%d", w.Code, s.calls)
			}
		})
	}
	for _, name := range []string{"remote", "origin", "cross-site", "unknown-length", "hidden-body", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://127.0.0.1:8080"+webPreviewPath, nil)
			r.RemoteAddr = "127.0.0.1:9000"
			r.AddCookie(cookie)
			code := 400
			switch name {
			case "remote":
				r.RemoteAddr = "192.0.2.5:9000"
				code = 403
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
				code = 403
			case "cross-site":
				r.Header.Set("Sec-Fetch-Site", "cross-site")
				code = 403
			case "unknown-length":
				r.ContentLength = -1
			case "hidden-body":
				r.Body = http.NoBody
				r2 := httptest.NewRequest("GET", "http://127.0.0.1:8080", strings.NewReader("x"))
				r.Body = r2.Body
				r.ContentLength = 0
			case "cancelled":
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
				code = 503
			}
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, r)
			if w.Code != code || s.calls != 0 {
				t.Fatalf("status=%d calls=%d", w.Code, s.calls)
			}
		})
	}
	w := websiteRequest(f.handler, "GET", webPreviewPath, nil, cookie, "")
	if w.Code != 200 || s.calls != 1 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d calls=%d", w.Code, s.calls)
	}
	var result hostaccounts.WebPreview
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.BundleSHA256 != strings.Repeat("3", 64) || len(result.Files) != 1 {
		t.Fatal("metadata lost")
	}
	for _, secret := range []string{f.key, "csrf_token", "\"data\"", "\"ready\"", "\"apply\""} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("unexpected credential/config/activation output")
		}
	}
}

func TestWebPreviewWithholdsRevokedCancelledAndFailedResults(t *testing.T) {
	for _, name := range []string{"logout", "cancelled", "recovery", "conflict", "internal-error", "disabled"} {
		t.Run(name, func(t *testing.T) {
			f := websiteFixture(t)
			var cookie *http.Cookie
			var csrf string
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &webPreviewSpy{fn: func(context.Context) (hostaccounts.WebPreview, error) {
				err := error(nil)
				switch name {
				case "logout":
					if w := websiteRequest(f.handler, "POST", "/api/v1/session/logout", `{}`, cookie, csrf); w.Code != 200 {
						t.Fatal("logout failed")
					}
				case "cancelled":
					cancel()
				case "recovery":
					err = hostaccounts.ErrRecovery
				case "conflict":
					err = hostaccounts.ErrConflict
				case "internal-error":
					err = errors.New("private-root-path-do-not-expose")
				}
				return webPreviewFixtureValue(), err
			}}
			var service hostaccounts.WebPreviewService = s
			if name == "disabled" {
				service = nil
			}
			f.handler = New(Options{Operator: f.manager, WebPreview: service, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
			cookie, csrf = websiteSignIn(t, f)
			r := httptest.NewRequest("GET", "http://127.0.0.1:8080"+webPreviewPath, nil).WithContext(ctx)
			r.RemoteAddr = "127.0.0.1:9000"
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, r)
			want := 503
			if name == "logout" {
				want = 401
			}
			if name == "conflict" {
				want = 409
			}
			if w.Code != want || strings.Contains(w.Body.String(), "bundle_sha256") || strings.Contains(w.Body.String(), "private-root-path") {
				t.Fatalf("unexpected failed preview: status=%d", w.Code)
			}
		})
	}
}

func TestWebPreviewOpenAPI(t *testing.T) {
	w := websiteRequest(New(Options{}), "GET", "/openapi.json", nil, nil, "")
	var spec struct {
		Paths map[string]map[string]struct {
			Security    []map[string][]string
			Description string
			Responses   map[string]json.RawMessage
			RequestBody json.RawMessage
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("invalid spec")
	}
	op := spec.Paths[webPreviewPath]["get"]
	if len(op.Security) != 1 || len(op.Security[0]) != 1 || op.Responses["200"] == nil || op.RequestBody != nil {
		t.Fatal("missing read-only auth contract")
	}
	if _, ok := op.Security[0]["operatorSession"]; !ok {
		t.Fatal("missing operator session")
	}
	for _, phrase := range []string{"no query or body", "rechecked before output", "recovery bookkeeping", "not current serving status"} {
		if !strings.Contains(op.Description, phrase) {
			t.Fatalf("missing documented limit %s", phrase)
		}
	}
}
