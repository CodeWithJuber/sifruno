package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/wizard"
)

// These spies test HTTP admission and the JSON shapes only; they provision
// nothing.
type wizardBrokerSpy struct {
	mu       sync.Mutex
	calls    int
	accounts []hostaccounts.Account
}

func (s *wizardBrokerSpy) List(context.Context) ([]hostaccounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return slices.Clone(s.accounts), nil
}
func (s *wizardBrokerSpy) Create(_ context.Context, in hostaccounts.CreateInput, _ string) (hostaccounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	a := hostaccounts.Account{ID: strings.Repeat("d", 32), Username: in.Username, Domain: in.Domain, Revision: 1}
	s.accounts = append(s.accounts, a)
	return a, nil
}
func (s *wizardBrokerSpy) Delete(context.Context, string, hostaccounts.DeleteInput, string) (hostaccounts.Account, error) {
	return hostaccounts.Account{}, nil
}
func (s *wizardBrokerSpy) SetState(context.Context, string, hostaccounts.StateInput, string) (hostaccounts.Account, error) {
	return hostaccounts.Account{}, nil
}
func (s *wizardBrokerSpy) SetWeb(_ context.Context, id string, in hostaccounts.WebInput, _ string) (hostaccounts.WebResult, error) {
	return hostaccounts.WebResult{Account: hostaccounts.Account{ID: id, Revision: in.ExpectedRevision + 1}}, nil
}
func (s *wizardBrokerSpy) InstallWordPress(context.Context, string, hostaccounts.WordPressInput, string) (hostaccounts.WordPressResult, error) {
	return hostaccounts.WordPressResult{Version: "7.1.5"}, nil
}

type wizardDatabaseSpy struct{}

func (wizardDatabaseSpy) Probe(context.Context) (string, error) { return "10.11", nil }
func (wizardDatabaseSpy) AllDatabases(context.Context) ([]dbhost.Database, error) {
	return nil, nil
}
func (wizardDatabaseSpy) AllUsers(context.Context) ([]dbhost.User, error) { return nil, nil }
func (wizardDatabaseSpy) ServerHas(context.Context, string, string) (bool, error) {
	return false, nil
}
func (wizardDatabaseSpy) CreateDatabaseStrict(context.Context, string, string) error { return nil }
func (wizardDatabaseSpy) CreateUserStrict(context.Context, string, string, string) error {
	return nil
}
func (wizardDatabaseSpy) SetPrivileges(context.Context, string, string, string, []string) error {
	return nil
}
func (wizardDatabaseSpy) DropDatabase(context.Context, string, string) error { return nil }
func (wizardDatabaseSpy) DropUser(context.Context, string, string) error     { return nil }

const wizardPassword = "Correct-Horse-Battery-9"

func wizardBody(change func(map[string]any)) string {
	body := map[string]any{"domain": "example.com", "title": "My site", "admin_user": "siteadmin", "admin_email": "me@example.com", "admin_password": wizardPassword, "php_version": "8.3"}
	if change != nil {
		change(body)
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func wizardFixture(t *testing.T) (siteFixture, *wizard.Runner, *wizardBrokerSpy) {
	t.Helper()
	f := websiteFixture(t)
	store, err := wizard.OpenStore(filepath.Join(realTempDir(t), "wizard"))
	if err != nil {
		t.Fatal(err)
	}
	spy := &wizardBrokerSpy{}
	runner := wizard.New(spy, wizardDatabaseSpy{}, store, nil)
	t.Cleanup(runner.Wait) // before the store's directory is removed
	f.handler = New(Options{Operator: f.manager, Wizard: runner, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return f, runner, spy
}

func problemDetail(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Status != w.Code || p.Title == "" || p.Detail == "" {
		t.Fatalf("not problem JSON (%d): %s", w.Code, w.Body.String())
	}
	return p.Detail
}

// withoutSchema drops the "$schema" link Huma adds to every panel response.
func withoutSchema(body map[string]json.RawMessage) map[string]json.RawMessage {
	delete(body, "$schema")
	return body
}

// checkJobShape compares a job's keys with the contract, exactly.
func checkJobShape(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var job map[string]json.RawMessage
	if err := json.Unmarshal(raw, &job); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range job {
			if !yield(k) {
				return
			}
		}
	})
	want := []string{"actor", "created_at", "domain", "error", "id", "kind", "php_version", "result", "state", "steps", "updated_at", "username"}
	if !slices.Equal(keys, want) {
		t.Fatalf("job keys %q", keys)
	}
	var steps []map[string]any
	if err := json.Unmarshal(job["steps"], &steps); err != nil || len(steps) != 5 {
		t.Fatalf("steps %s", job["steps"])
	}
	names := []string{"account", "web", "ssl", "database", "wordpress"}
	titles := []string{"Create the hosting account", "Put the site live with PHP", "Turn on https", "Create the database", "Install WordPress"}
	for i, s := range steps {
		if len(s) != 6 || s["name"] != names[i] || s["title"] != titles[i] {
			t.Fatalf("step %d: %v", i, s)
		}
		for _, k := range []string{"state", "message", "started_at", "finished_at"} {
			if _, ok := s[k].(string); !ok {
				t.Fatalf("step %d %s is not a string: %v", i, k, s)
			}
		}
	}
}

func TestWordPressWizardAdmission(t *testing.T) {
	f, runner, spy := wizardFixture(t)
	for _, path := range []string{"/api/v1/websites/wordpress", "/api/v1/websites/jobs", "/api/v1/websites/jobs/" + strings.Repeat("a", 32)} {
		method := "GET"
		if strings.HasSuffix(path, "/wordpress") {
			method = "POST"
		}
		if w := websiteRequest(f.handler, method, path, wizardBody(nil), nil, ""); w.Code != 401 {
			t.Fatalf("%s %s unauthenticated status %d", method, path, w.Code)
		}
	}
	cookie, csrf := websiteSignIn(t, f)
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/wordpress", wizardBody(nil), cookie, ""); w.Code != 403 {
		t.Fatalf("missing CSRF status %d", w.Code)
	}
	if w := websiteRequest(f.handler, "PUT", "/api/v1/websites/wordpress", wizardBody(nil), cookie, csrf); w.Code != 405 {
		t.Fatalf("PUT status %d", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/jobs", `{}`, cookie, csrf); w.Code != 405 {
		t.Fatalf("POST to the job list status %d", w.Code)
	}
	full := wizardBody(nil)
	for _, tc := range []struct {
		name, body string
		status     int
		detail     string
	}{
		{"duplicate key", strings.Replace(full, `{`, `{"domain":"other.example",`, 1), 422, "domain more than once"},
		{"case alias", strings.Replace(full, `"domain"`, `"Domain"`, 1), 422, "Send only domain"},
		{"unknown key", strings.Replace(full, `{`, `{"sensitive-key":"x",`, 1), 422, "Send only domain"},
		{"number", strings.Replace(full, `"8.3"`, `8.3`, 1), 422, "php_version must be text"},
		{"null field", strings.Replace(full, `"My site"`, `null`, 1), 422, "title must be text"},
		{"null body", `null`, 400, ""},
		{"array", `[]`, 400, ""},
		{"trailing data", full + `{}`, 400, ""},
		{"too large", strings.Replace(full, `"My site"`, `"`+strings.Repeat("x", 4096)+`"`, 1), 413, ""},
	} {
		w := websiteRequest(f.handler, "POST", "/api/v1/websites/wordpress", tc.body, cookie, csrf)
		if w.Code != tc.status {
			t.Fatalf("%s: status %d want %d: %s", tc.name, w.Code, tc.status, w.Body.String())
		}
		if d := problemDetail(t, w); tc.detail != "" && !strings.Contains(d, tc.detail) {
			t.Fatalf("%s: detail %q", tc.name, d)
		}
		if strings.Contains(w.Body.String(), "sensitive-key") || strings.Contains(w.Body.String(), wizardPassword) {
			t.Fatalf("%s: request echoed", tc.name)
		}
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/websites/wordpress", strings.NewReader(full))
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatalf("text body status %d", w.Code)
	}
	for field, value := range map[string]any{
		"domain":         "Example.com",
		"title":          " ",
		"admin_user":     "-admin",
		"admin_email":    "Me <me@example.com>",
		"admin_password": "short",
		"php_version":    "7.4",
	} {
		w := websiteRequest(f.handler, "POST", "/api/v1/websites/wordpress", wizardBody(func(b map[string]any) { b[field] = value }), cookie, csrf)
		if w.Code != 422 || !strings.HasPrefix(problemDetail(t, w), field+" ") {
			t.Fatalf("%s: status %d %s", field, w.Code, w.Body.String())
		}
	}
	missing := wizardBody(func(b map[string]any) { delete(b, "admin_email") })
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/wordpress", missing, cookie, csrf); w.Code != 422 || !strings.HasPrefix(problemDetail(t, w), "admin_email ") {
		t.Fatalf("missing field status %d", w.Code)
	}
	if spy.calls != 0 || len(runner.List()) != 0 {
		t.Fatal("a refused request reached the broker or the job store")
	}
}

func TestWordPressWizardJobShapes(t *testing.T) {
	f, runner, spy := wizardFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "POST", "/api/v1/websites/wordpress", wizardBody(nil), cookie, csrf)
	if w.Code != 202 {
		t.Fatalf("start status %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), wizardPassword) {
		t.Fatal("password in the response")
	}
	var started map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil || len(withoutSchema(started)) != 1 || started["job"] == nil {
		t.Fatalf("202 body %s", w.Body.String())
	}
	checkJobShape(t, started["job"])
	var job wizard.Job
	if err := json.Unmarshal(started["job"], &job); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(job.ID) || job.Kind != "wordpress" || job.Domain != "example.com" || job.PHPVersion != "8.3" || job.State != "running" || job.Actor == "" || job.CreatedAt == "" || job.Error != nil || job.Result != nil {
		t.Fatalf("started job %+v", job)
	}
	if !strings.Contains(string(started["job"]), `"error":null`) || !strings.Contains(string(started["job"]), `"result":null`) {
		t.Fatal("error and result are not null while running")
	}
	runner.Wait()

	w = websiteRequest(f.handler, "GET", "/api/v1/websites/jobs/"+job.ID, nil, cookie, "")
	var one map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &one) != nil || len(withoutSchema(one)) != 1 {
		t.Fatalf("GET job %d: %s", w.Code, w.Body.String())
	}
	checkJobShape(t, one["job"])
	var done wizard.Job
	if err := json.Unmarshal(one["job"], &done); err != nil {
		t.Fatal(err)
	}
	if done.State != "succeeded" || done.Username != "example" || done.Result == nil || done.Result.URL != "http://example.com/" || done.Result.AdminURL != "http://example.com/wp-admin/" || done.Result.WordPressVersion != "7.1.5" || done.Result.AccountID != strings.Repeat("d", 32) {
		t.Fatalf("finished job %+v %+v", done, done.Result)
	}

	// The domain now belongs to an account: a second start is refused.
	w = websiteRequest(f.handler, "POST", "/api/v1/websites/wordpress", wizardBody(nil), cookie, csrf)
	if w.Code != 409 || !strings.Contains(problemDetail(t, w), "already belongs") {
		t.Fatalf("taken domain status %d", w.Code)
	}
	spy.mu.Lock()
	spy.accounts = nil
	spy.mu.Unlock()
	if w = websiteRequest(f.handler, "POST", "/api/v1/websites/wordpress", wizardBody(func(b map[string]any) { b["domain"] = "second.example" }), cookie, csrf); w.Code != 202 {
		t.Fatalf("second start %d", w.Code)
	}
	runner.Wait()

	w = websiteRequest(f.handler, "GET", "/api/v1/websites/jobs", nil, cookie, "")
	var list map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(withoutSchema(list)) != 1 {
		t.Fatalf("GET jobs %d: %s", w.Code, w.Body.String())
	}
	var jobs []json.RawMessage
	if err := json.Unmarshal(list["jobs"], &jobs); err != nil || len(jobs) != 2 {
		t.Fatalf("jobs %s", list["jobs"])
	}
	for _, raw := range jobs {
		checkJobShape(t, raw)
	}
	var newest wizard.Job
	if err := json.Unmarshal(jobs[0], &newest); err != nil || newest.Domain != "second.example" {
		t.Fatal("jobs are not newest first")
	}

	for _, id := range []string{strings.Repeat("0", 32), "not-an-id", strings.ToUpper(job.ID)} {
		w = websiteRequest(f.handler, "GET", "/api/v1/websites/jobs/"+id, nil, cookie, "")
		if w.Code != 404 {
			t.Fatalf("GET %s status %d", id, w.Code)
		}
		problemDetail(t, w)
	}
}

func TestWordPressWizardNotSetUp(t *testing.T) {
	f := websiteFixture(t)
	f.handler = New(Options{Operator: f.manager, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	cookie, csrf := websiteSignIn(t, f)
	for _, tc := range []struct{ method, path, body, csrf string }{
		{"POST", "/api/v1/websites/wordpress", wizardBody(nil), csrf},
		{"GET", "/api/v1/websites/jobs", "", ""},
		{"GET", "/api/v1/websites/jobs/" + strings.Repeat("a", 32), "", ""},
	} {
		w := websiteRequest(f.handler, tc.method, tc.path, tc.body, cookie, tc.csrf)
		if w.Code != 503 || problemDetail(t, w) != "Website creation is not set up on this server" {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	// The spec describes the session and CSRF the POST needs.
	w := websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	var spec map[string]any
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("invalid OpenAPI")
	}
	post := spec["paths"].(map[string]any)["/api/v1/websites/wordpress"].(map[string]any)["post"].(map[string]any)
	security := fmt.Sprint(post["security"])
	if !strings.Contains(security, "operatorSession") || !strings.Contains(security, "sessionCSRF") {
		t.Fatalf("POST security %s", security)
	}
}
