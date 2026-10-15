package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
)

// This spy tests HTTP admission only; it is not Linux provisioning evidence.
type accountSpy struct {
	calls   int
	actor   string
	err     error
	created hostaccounts.CreateInput
	changed hostaccounts.StateInput
}

func (s *accountSpy) Capability(context.Context) (hostaccounts.Capability, error) {
	s.calls++
	return hostaccounts.Capability{Available: false, Reason: "No broker configured", Backend: "none", Restrictions: []string{}}, nil
}
func (s *accountSpy) List(context.Context) ([]hostaccounts.Account, error) {
	s.calls++
	return nil, s.err
}
func (s *accountSpy) Create(_ context.Context, in hostaccounts.CreateInput, actor string) (hostaccounts.Account, error) {
	s.calls++
	s.created = in
	s.actor = actor
	return hostaccounts.Account{ID: "a", Username: in.Username, Domain: in.Domain, Revision: 1, CreatedAt: time.Now().UTC()}, s.err
}
func (s *accountSpy) SetState(_ context.Context, _ string, in hostaccounts.StateInput, actor string) (hostaccounts.Account, error) {
	s.calls++
	s.changed = in
	s.actor = actor
	return hostaccounts.Account{}, s.err
}
func (s *accountSpy) SetPlan(_ context.Context, _ string, _ hostaccounts.PlanInput, actor string) (hostaccounts.Account, error) {
	s.calls++
	s.actor = actor
	return hostaccounts.Account{}, s.err
}
func (s *accountSpy) Delete(_ context.Context, _ string, _ hostaccounts.DeleteInput, actor string) (hostaccounts.Account, error) {
	s.calls++
	s.actor = actor
	return hostaccounts.Account{}, s.err
}

func TestAccountHTTPAdmission(t *testing.T) {
	f := websiteFixture(t)
	s := &accountSpy{}
	f.handler = New(Options{Operator: f.manager, Accounts: s, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	for _, path := range []string{"/api/v1/accounts", "/api/v1/accounts/capability", "/api/v1/accounts/a/state"} {
		method := "GET"
		if strings.HasSuffix(path, "/state") {
			method = "POST"
		}
		if w := websiteRequest(f.handler, method, path, `{"username":"secret-invalid"}`, nil, ""); w.Code != 401 {
			t.Fatalf("unauthenticated status %d", w.Code)
		}
	}
	if s.calls != 0 {
		t.Fatal("unauthenticated broker contact")
	}
	cookie, csrf := websiteSignIn(t, f)
	for _, tc := range []struct {
		body   string
		csrf   string
		status int
	}{
		{`{"username":"hello"}`, "", 403},
		{`{"username":"one","username":"two"}`, csrf, 400},
		{`{"username":"one","USERNAME":"two"}`, csrf, 400},
		{`{"Username":"one"}`, csrf, 400},
		{`{"unknown":"sensitive"}`, csrf, 400},
		{`null`, csrf, 400},
		{`{"reason":"` + strings.Repeat("x", 4096) + `"}`, csrf, 413},
	} {
		w := websiteRequest(f.handler, "POST", "/api/v1/accounts", tc.body, cookie, tc.csrf)
		if w.Code != tc.status {
			t.Fatalf("admission status %d want %d", w.Code, tc.status)
		}
		if strings.Contains(w.Body.String(), "sensitive") {
			t.Fatal("invalid body echoed")
		}
	}
	if s.calls != 0 {
		t.Fatal("invalid write reached broker")
	}
	w := websiteRequest(f.handler, "GET", "/api/v1/accounts/capability", nil, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"available":false`) {
		t.Fatal("capability unavailable not represented")
	}
	w = websiteRequest(f.handler, "GET", "/api/v1/accounts", nil, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("empty list is not an array")
	}
	w = websiteRequest(f.handler, "POST", "/api/v1/accounts", `{"username":"nativeuser","domain":"native.example.test","reason":"operator fixture"}`, cookie, csrf)
	if w.Code != 200 || s.actor == "" || s.created.Username != "nativeuser" {
		t.Fatal("typed request/actor not delivered")
	}
	for _, tc := range []struct {
		err  error
		want int
	}{{hostaccounts.ErrInvalid, 422}, {hostaccounts.ErrConflict, 409}, {hostaccounts.ErrNotFound, 404}, {hostaccounts.ErrRecovery, 503}, {errors.New("private-path-secret"), 503}} {
		s.err = tc.err
		w = websiteRequest(f.handler, "POST", "/api/v1/accounts/a/state", `{"state":"suspended","expected_revision":1,"reason":"fixture"}`, cookie, csrf)
		if w.Code != tc.want || strings.Contains(w.Body.String(), "private-path-secret") {
			t.Fatal("unsafe broker error mapping")
		}
	}
	if s.changed.ExpectedRevision != 1 {
		t.Fatal("revision discarded")
	}
	w = websiteRequest(f.handler, "POST", "/api/v1/accounts/arbitrary", `{}`, cookie, csrf)
	if w.Code != 405 {
		t.Fatal("unknown mutation enabled")
	}
	// The spec must describe both independently required credentials.
	w = websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	var spec map[string]any
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("invalid OpenAPI")
	}
	paths := spec["paths"].(map[string]any)
	write := paths["/api/v1/accounts"].(map[string]any)["post"].(map[string]any)
	security := write["security"].([]any)[0].(map[string]any)
	if _, ok := security["operatorSession"]; !ok {
		t.Fatal("cookie missing from spec")
	}
	if _, ok := security["sessionCSRF"]; !ok {
		t.Fatal("CSRF missing from spec")
	}
}
