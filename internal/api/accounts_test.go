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
	calls     int
	actor     string
	err       error
	created   hostaccounts.CreateInput
	changed   hostaccounts.StateInput
	abandoned hostaccounts.AbandonCreateInput
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
func (s *accountSpy) AbandonCreate(_ context.Context, id string, in hostaccounts.AbandonCreateInput, actor string) (hostaccounts.Account, error) {
	s.calls++
	s.actor = actor
	s.abandoned = in
	return hostaccounts.Account{ID: id, State: "recovery_required"}, s.err
}

// An admin abandons an unfinished create with a reason only; a refusal says
// why nothing was removed, and other broker answers map as for any account
// change.
func TestAccountAbandonCreate(t *testing.T) {
	f := websiteFixture(t)
	s := &accountSpy{}
	f.handler = New(Options{Operator: f.manager, Accounts: s, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	path := "/api/v1/accounts/" + strings.Repeat("a", 32) + "/abandon-create"
	if w := websiteRequest(f.handler, "POST", path, `{"reason":"Leftover"}`, nil, ""); w.Code != 401 {
		t.Fatalf("unauthenticated status %d", w.Code)
	}
	cookie, csrf := websiteSignIn(t, f)
	for _, body := range []string{`{"reason":"Leftover","state":"active"}`, `{"reason":"Leftover","expected_revision":1}`, `{"Reason":"Leftover"}`, `null`} {
		if w := websiteRequest(f.handler, "POST", path, body, cookie, csrf); w.Code != 400 {
			t.Fatalf("%s: status %d", body, w.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", path, `{"reason":"Leftover"}`, cookie, ""); w.Code != 403 {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	if s.calls != 0 {
		t.Fatal("an invalid request reached the broker")
	}
	w := websiteRequest(f.handler, "POST", path, `{"reason":"Leftover of a killed useradd"}`, cookie, csrf)
	if w.Code != 200 || s.abandoned.Reason != "Leftover of a killed useradd" || s.actor == "" {
		t.Fatalf("abandon: %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		err  error
		want int
		says string
	}{
		{&hostaccounts.AbandonRefusedError{Reason: hostaccounts.AbandonHomeNotEmpty}, 409, "holds files this create did not make"},
		{&hostaccounts.AbandonRefusedError{Reason: hostaccounts.AbandonNoCreate}, 409, "no unfinished create"},
		{hostaccounts.ErrNotFound, 404, ""},
		{hostaccounts.ErrRecovery, 503, ""},
	} {
		s.err = tc.err
		w := websiteRequest(f.handler, "POST", path, `{"reason":"Leftover"}`, cookie, csrf)
		if w.Code != tc.want || !strings.Contains(w.Body.String(), tc.says) {
			t.Fatalf("%v: %d %s", tc.err, w.Code, w.Body.String())
		}
	}
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
