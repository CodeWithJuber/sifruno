package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/operator"
)

// Admission only: the service spy never provisions native accounts.
type accountAdmissionBody struct {
	*strings.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *accountAdmissionBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}
func (b *accountAdmissionBody) Close() error { return nil }

func TestAccountSessionAdmissionAfterBody(t *testing.T) {
	for _, op := range []struct{ name, path, body string }{
		{"create", "/api/v1/accounts", `{"username":"nativeuser","domain":"native.example.test","reason":"fixture"}`},
		{"state", "/api/v1/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/state", `{"state":"suspended","expected_revision":7,"reason":"fixture"}`},
	} {
		for _, change := range []string{"logout", "targeted-revoke", "revoke-others", "active", "invalid-csrf", "malformed-after-logout"} {
			t.Run(op.name+"/"+change, func(t *testing.T) {
				f := websiteFixture(t)
				spy := &accountSpy{}
				f.handler = New(Options{Operator: f.manager, Accounts: spy, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
				cookie, csrf := websiteSignIn(t, f)
				other, otherCSRF := websiteSignIn(t, f)
				target := ""
				inventory := websiteRequest(f.handler, "GET", "/api/v1/session/sessions", nil, cookie, "")
				var sessions operator.Inventory
				if inventory.Code != 200 || json.Unmarshal(inventory.Body.Bytes(), &sessions) != nil {
					t.Fatal("inventory unavailable")
				}
				for _, s := range sessions.Items {
					if s.Current {
						target = s.ID
					}
				}
				if target == "" {
					t.Fatal("current management handle missing")
				}
				payload := op.body
				if change == "malformed-after-logout" {
					payload = `{"unknown":true}`
				}
				body := &accountAdmissionBody{Reader: strings.NewReader(payload), entered: make(chan struct{}), release: make(chan struct{})}
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(body.release) }) }
				defer release()
				r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080"+op.path, nil)
				r.Body = body
				r.RemoteAddr = "127.0.0.1:14000"
				r.Header.Set("Origin", "http://127.0.0.1:8080")
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(cookie)
				if change != "invalid-csrf" {
					r.Header.Set("X-CSRF-Token", csrf)
				}
				w := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { defer close(done); f.handler.ServeHTTP(w, r) }()
				await := func(c <-chan struct{}) {
					t.Helper()
					select {
					case <-c:
					case <-time.After(5 * time.Second):
						t.Fatal("bounded admission test timed out")
					}
				}
				if change == "invalid-csrf" {
					await(done)
					select {
					case <-body.entered:
						t.Fatal("initial CSRF rejection read body")
					default:
					}
					if w.Code != 403 || spy.calls != 0 {
						t.Fatal("initial CSRF guard changed")
					}
					return
				}
				await(body.entered)
				var revocation *httptest.ResponseRecorder
				switch change {
				case "logout", "malformed-after-logout":
					revocation = websiteRequest(f.handler, "POST", "/api/v1/session/logout", `{}`, cookie, csrf)
				case "targeted-revoke":
					revocation = websiteRequest(f.handler, "POST", "/api/v1/session/sessions/"+target+"/revoke", `{}`, other, otherCSRF)
				case "revoke-others":
					revocation = websiteRequest(f.handler, "POST", "/api/v1/session/revoke-others", `{}`, other, otherCSRF)
				}
				if revocation != nil && revocation.Code != 200 {
					t.Fatalf("revocation status %d", revocation.Code)
				}
				release()
				await(done)
				want := 401
				if change == "active" {
					want = 200
				} else if change == "malformed-after-logout" {
					want = 400
				}
				if w.Code != want {
					t.Fatalf("status %d want %d; backend calls %d", w.Code, want, spy.calls)
				}
				if change != "active" {
					if spy.calls != 0 {
						t.Fatal("denied request reached backend")
					}
					return
				}
				if spy.calls != 1 || spy.actor != "local-operator" {
					t.Fatal("active request dispatch/actor changed")
				}
				if op.name == "create" && (spy.created.Username != "nativeuser" || spy.created.Domain != "native.example.test" || spy.created.Reason != "fixture") {
					t.Fatal("create payload changed")
				}
				if op.name == "state" && (spy.changed.State != "suspended" || spy.changed.ExpectedRevision != 7 || spy.changed.Reason != "fixture") {
					t.Fatal("state payload changed")
				}
			})
		}
	}
}
