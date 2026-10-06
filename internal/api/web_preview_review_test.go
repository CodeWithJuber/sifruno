package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/operator"
	"strings"
	"testing"
)

func TestIndependentPreviewSessionTransitions(t *testing.T) {
	for _, change := range []string{"rotation", "revoke-caller", "revoke-other"} {
		t.Run(change, func(t *testing.T) {
			f := websiteFixture(t)
			var cookie, other *http.Cookie
			var csrf, otherCSRF, target string
			spy := &webPreviewSpy{fn: func(context.Context) (hostaccounts.WebPreview, error) {
				var w *httptest.ResponseRecorder
				switch change {
				case "rotation":
					w = websiteRequest(f.handler, "POST", "/api/v1/session/login", map[string]string{"access_key": f.key}, cookie, "")
				case "revoke-caller":
					w = websiteRequest(f.handler, "POST", "/api/v1/session/sessions/"+target+"/revoke", `{}`, other, otherCSRF)
				case "revoke-other":
					w = websiteRequest(f.handler, "POST", "/api/v1/session/sessions/"+target+"/revoke", `{}`, cookie, csrf)
				}
				if w.Code != 200 {
					t.Fatalf("transition%d", w.Code)
				}
				return webPreviewFixtureValue(), nil
			}}
			f.handler = New(Options{Operator: f.manager, WebPreview: spy, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
			cookie, csrf = websiteSignIn(t, f)
			other, otherCSRF = websiteSignIn(t, f)
			inventoryCookie := cookie
			if change == "revoke-other" {
				inventoryCookie = other
			}
			w := websiteRequest(f.handler, "GET", "/api/v1/session/sessions", nil, inventoryCookie, "")
			var inv operator.Inventory
			if json.Unmarshal(w.Body.Bytes(), &inv) != nil {
				t.Fatal("inventory")
			}
			for _, s := range inv.Items {
				if s.Current {
					target = s.ID
				}
			}
			w = websiteRequest(f.handler, "GET", webPreviewPath, nil, cookie, "")
			want := 401
			if change == "revoke-other" {
				want = 200
			}
			if w.Code != want || spy.calls != 1 {
				t.Fatalf("status%d calls%d", w.Code, spy.calls)
			}
			if want == 401 && strings.Contains(w.Body.String(), "bundle_sha256") {
				t.Fatal("revoked result disclosed")
			}
		})
	}
}
