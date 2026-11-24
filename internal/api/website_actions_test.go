package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/wizard"
)

// sitesDatabases keeps a registry, as dbhost does, so a delete has
// something that is the site's to drop. It reaches no database server.
type sitesDatabases struct {
	wizardDatabaseSpy
	mu        sync.Mutex
	databases []dbhost.Database
	users     []dbhost.User
	drops     []string
	dropErr   error
}

func (d *sitesDatabases) AllDatabases(context.Context) ([]dbhost.Database, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.databases), nil
}
func (d *sitesDatabases) AllUsers(context.Context) ([]dbhost.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.users), nil
}
func (d *sitesDatabases) CreateDatabaseStrict(_ context.Context, owner, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.databases = append(d.databases, dbhost.Database{Name: name, Owner: owner})
	return nil
}
func (d *sitesDatabases) CreateUserStrict(_ context.Context, owner, name, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users = append(d.users, dbhost.User{Name: name, Owner: owner})
	return nil
}
func (d *sitesDatabases) DropDatabase(_ context.Context, owner, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drops = append(d.drops, "database "+owner+" "+name)
	if d.dropErr != nil {
		return d.dropErr
	}
	d.databases = slices.DeleteFunc(d.databases, func(x dbhost.Database) bool { return x.Name == name })
	return nil
}
func (d *sitesDatabases) DropUser(_ context.Context, owner, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drops = append(d.drops, "user "+owner+" "+name)
	d.users = slices.DeleteFunc(d.users, func(x dbhost.User) bool { return x.Name == name })
	return nil
}

// actionsFixture is a panel with one site, example.com on PHP 8.3, on a
// server that has PHP 8.2 and 8.3 installed.
func actionsFixture(t *testing.T) (siteFixture, *wizard.Runner, *sitesBroker, *sitesDatabases, Website) {
	t.Helper()
	f := websiteFixture(t)
	dir := realTempDir(t)
	store, err := wizard.OpenStore(filepath.Join(dir, "wizard"))
	if err != nil {
		t.Fatal(err)
	}
	old := phpRoot
	phpRoot = filepath.Join(dir, "lsws")
	t.Cleanup(func() { phpRoot = old })
	for _, version := range []string{"82", "83"} {
		bin := filepath.Join(phpRoot, "lsphp"+version, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "lsphp"), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A directory where the binary should be is not an installed PHP.
	if err := os.MkdirAll(filepath.Join(phpRoot, "lsphp84", "bin", "lsphp"), 0o755); err != nil {
		t.Fatal(err)
	}
	broker, databases := &sitesBroker{}, &sitesDatabases{}
	runner := wizard.New(broker, databases, store, nil)
	t.Cleanup(runner.Wait)
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Wizard: runner, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	job := makeSite(t, runner, "example.com", "8.3")
	broker.mu.Lock()
	broker.changes = nil
	account := broker.accounts[0]
	broker.mu.Unlock()
	return f, runner, broker, databases, website(account, job)
}

func sitePath(site Website, action string) string {
	return "/api/v1/websites/sites/" + site.AccountID + "/" + action
}

func decodeDetail(t *testing.T, w *httptest.ResponseRecorder) WebsiteDetail {
	t.Helper()
	var raw map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &raw) != nil {
		t.Fatalf("site answer %d: %s", w.Code, w.Body.String())
	}
	checkWebsiteShape(t, raw, "php_versions")
	var got WebsiteDetail
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// problemTechnical is the first entry of the problem's errors, where a site
// action puts the text for "Technical details".
func problemTechnical(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Errors) == 0 {
		return ""
	}
	return p.Errors[0].Message
}

func TestWebsitePHPChangeKeepsTheQuota(t *testing.T) {
	f, runner, broker, _, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	one := decodeDetail(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID, nil, cookie, ""))
	if one.Website != site || !slices.Equal(one.PHPVersions, []string{"8.2", "8.3"}) || one.PHPVersion != "8.3" || one.Revision != 2 {
		t.Fatalf("site %+v", one)
	}

	got := decodeDetail(t, websiteRequest(f.handler, "POST", sitePath(site, "php"), map[string]any{"php_version": "8.2", "expected_revision": site.Revision}, cookie, csrf))
	if got.PHPVersion != "8.2" || got.Revision != site.Revision+1 || got.State != "active" || !slices.Equal(got.PHPVersions, []string{"8.2", "8.3"}) {
		t.Fatalf("after the change %+v", got)
	}
	want := fmt.Sprintf(`web %s php=8.2 quota=1024 rev=%d reason="PHP version changed on the website's page" actor=local-operator`, site.AccountID, site.Revision)
	if !slices.Equal(broker.changes, []string{want}) {
		t.Fatalf("broker changes %q", broker.changes)
	}
	// The list shows the broker's version, not the one the job was made with.
	sites := decodeSites(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "").Body.Bytes())
	if job := runner.Succeeded()[0]; len(sites) != 1 || sites[0].PHPVersion != "8.2" || job.PHPVersion != "8.3" || sites[0].Revision != got.Revision {
		t.Fatalf("listed %+v, job PHP %s", sites, job.PHPVersion)
	}
	site = got.Website

	// The broker's config test is the judge of a version: its refusal is a
	// plain error, and nothing changed.
	broker.changeErr = hostaccounts.ErrWebRejected
	w := websiteRequest(f.handler, "POST", sitePath(site, "php"), map[string]any{"php_version": "8.4", "expected_revision": site.Revision}, cookie, csrf)
	if w.Code != 422 || problemDetail(t, w) != "The web server's configuration test failed with PHP 8.4, so the site kept PHP 8.2. PHP 8.4 may not be installed on this server." || problemTechnical(t, w) != "account service: web configuration rejected" {
		t.Fatalf("rejected version %d: %s", w.Code, w.Body.String())
	}
	for err, want := range map[error]struct {
		status int
		detail string
	}{
		hostaccounts.ErrConflict:    {409, websiteBusy},
		hostaccounts.ErrRecovery:    {503, websiteRecovery},
		hostaccounts.ErrUnavailable: {503, websiteNoAnswer},
		hostaccounts.ErrInvalid:     {422, websiteRefused},
		hostaccounts.ErrNotFound:    {404, websiteNotFound},
	} {
		broker.changeErr = err
		w := websiteRequest(f.handler, "POST", sitePath(site, "php"), map[string]any{"php_version": "8.3", "expected_revision": site.Revision}, cookie, csrf)
		if w.Code != want.status || problemDetail(t, w) != want.detail || !strings.HasPrefix(problemTechnical(t, w), "account service: ") {
			t.Fatalf("broker answered %v: %d %s", err, w.Code, w.Body.String())
		}
	}
	broker.changeErr = nil

	// Refused by the panel, before the broker is asked to change anything.
	before := len(broker.changes)
	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		detail string
	}{
		"a version that does not exist": {map[string]any{"php_version": "7.4", "expected_revision": site.Revision}, 422, "php_version must be 8.1, 8.2, 8.3 or 8.4."},
		"no version":                    {map[string]any{"expected_revision": site.Revision}, 422, "php_version must be 8.1, 8.2, 8.3 or 8.4."},
		"no revision":                   {map[string]any{"php_version": "8.3"}, 422, websiteNoRevision},
		"a stale revision":              {map[string]any{"php_version": "8.3", "expected_revision": site.Revision - 1}, 409, websiteStale},
	} {
		w := websiteRequest(f.handler, "POST", sitePath(site, "php"), tc.body, cookie, csrf)
		if w.Code != tc.status || problemDetail(t, w) != tc.detail {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	broker.change(site.AccountID, func(a *hostaccounts.Account) { a.State = "suspended" })
	if w := websiteRequest(f.handler, "POST", sitePath(site, "php"), map[string]any{"php_version": "8.3", "expected_revision": site.Revision}, cookie, csrf); w.Code != 409 || problemDetail(t, w) != websiteNotActive {
		t.Fatalf("suspended site: %d %s", w.Code, w.Body.String())
	}
	broker.change(site.AccountID, func(a *hostaccounts.Account) { a.State = "recovery_required" })
	if w := websiteRequest(f.handler, "POST", sitePath(site, "php"), map[string]any{"php_version": "8.3", "expected_revision": site.Revision}, cookie, csrf); w.Code != 503 || problemDetail(t, w) != websiteRecovery {
		t.Fatalf("account awaiting recovery: %d %s", w.Code, w.Body.String())
	}
	// A broker from before it reported the settings: the quota is unknown.
	broker.change(site.AccountID, func(a *hostaccounts.Account) { a.State, a.Web = "active", hostaccounts.WebState{} })
	if w := websiteRequest(f.handler, "POST", sitePath(site, "php"), map[string]any{"php_version": "8.3", "expected_revision": site.Revision}, cookie, csrf); w.Code != 503 || problemDetail(t, w) != websiteNoQuota {
		t.Fatalf("no quota reported: %d %s", w.Code, w.Body.String())
	}
	if len(broker.changes) != before {
		t.Fatalf("a refused request reached the broker: %q", broker.changes[before:])
	}
}

func TestWebsiteSuspendAndResume(t *testing.T) {
	f, _, broker, _, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	got := decodeDetail(t, websiteRequest(f.handler, "POST", sitePath(site, "state"), map[string]any{"state": "suspended", "expected_revision": site.Revision}, cookie, csrf))
	if got.State != "suspended" || got.Revision != site.Revision+1 || got.PHPVersion != "8.3" {
		t.Fatalf("after suspend %+v", got)
	}
	if one := decodeDetail(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID, nil, cookie, "")); one.State != "suspended" || one.Revision != got.Revision {
		t.Fatalf("read after suspend %+v", one)
	}
	resumed := decodeDetail(t, websiteRequest(f.handler, "POST", sitePath(site, "state"), map[string]any{"state": "active", "expected_revision": got.Revision}, cookie, csrf))
	if resumed.State != "active" || resumed.Revision != got.Revision+1 {
		t.Fatalf("after resume %+v", resumed)
	}
	want := []string{
		fmt.Sprintf(`state %s suspended rev=%d reason="Suspended on the website's page" actor=local-operator`, site.AccountID, site.Revision),
		fmt.Sprintf(`state %s active rev=%d reason="Resumed on the website's page" actor=local-operator`, site.AccountID, got.Revision),
	}
	if !slices.Equal(broker.changes, want) {
		t.Fatalf("broker changes %q", broker.changes)
	}

	broker.changeErr = hostaccounts.ErrWebRejected
	w := websiteRequest(f.handler, "POST", sitePath(site, "state"), map[string]any{"state": "suspended", "expected_revision": resumed.Revision}, cookie, csrf)
	if w.Code != 422 || !strings.HasPrefix(problemDetail(t, w), "The web server's configuration test failed with the site suspended, so the site was not suspended and nothing changed.") {
		t.Fatalf("rejected suspend %d: %s", w.Code, w.Body.String())
	}
	broker.changeErr = nil
	before := len(broker.changes)
	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		detail string
	}{
		"another state":    {map[string]any{"state": "recovery_required", "expected_revision": resumed.Revision}, 422, "state must be active or suspended."},
		"no revision":      {map[string]any{"state": "suspended"}, 422, websiteNoRevision},
		"a stale revision": {map[string]any{"state": "suspended", "expected_revision": site.Revision}, 409, websiteStale},
	} {
		w := websiteRequest(f.handler, "POST", sitePath(site, "state"), tc.body, cookie, csrf)
		if w.Code != tc.status || problemDetail(t, w) != tc.detail {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if len(broker.changes) != before {
		t.Fatalf("a refused request reached the broker: %q", broker.changes[before:])
	}
}

func TestWebsiteDelete(t *testing.T) {
	f, runner, broker, databases, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	del := func(domain string, revision uint64) *httptest.ResponseRecorder {
		return websiteRequest(f.handler, "POST", sitePath(site, "delete"), map[string]any{"confirm_domain": domain, "expected_revision": revision}, cookie, csrf)
	}
	// The typed domain must be the site's, and the revision current.
	for name, tc := range map[string]struct {
		domain   string
		revision uint64
		status   int
		detail   string
	}{
		"another domain":   {"example.org", site.Revision, 422, "The domain you typed is not this website's domain, example.com. Nothing was removed."},
		"no domain":        {"", site.Revision, 422, "confirm_domain must be the website's domain."},
		"no revision":      {"example.com", 0, 422, websiteNoRevision},
		"a stale revision": {"example.com", site.Revision - 1, 409, "This website changed after the page loaded it. Nothing was removed."},
	} {
		if w := del(tc.domain, tc.revision); w.Code != tc.status || problemDetail(t, w) != tc.detail {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if len(databases.drops) != 0 || len(broker.changes) != 0 {
		t.Fatalf("a refused delete removed something: %q %q", databases.drops, broker.changes)
	}

	// The account goes first; then the database will not go: the delete
	// stops and says what is left.
	databases.dropErr = errors.New("ERROR 1010: database directory not empty")
	w := del("example.com", site.Revision)
	left := "The database server did not remove the database example_wp. Removed before that: the hosting account example with its files and its site on the web server, the database user example_wp. Still on the server: the database example_wp. " +
		"The hosting account is gone, so Websites lists this website as partly deleted. Delete it again to remove the rest."
	want := fmt.Sprintf(`delete %s rev=%d reason="Deleted from the website's page" actor=local-operator`, site.AccountID, site.Revision)
	if w.Code != 503 || problemDetail(t, w) != left || problemTechnical(t, w) != "ERROR 1010: database directory not empty" || !slices.Equal(broker.changes, []string{want}) {
		t.Fatalf("stopped delete %d: %s", w.Code, w.Body.String())
	}
	databases.dropErr = nil

	// The site stays listed, partly deleted, with the revision its delete
	// was asked at; nothing else can change it.
	partly := decodeDetail(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID, nil, cookie, ""))
	if partly.State != "partly_deleted" || partly.Revision != site.Revision || partly.Domain != "example.com" || partly.Username != "example" || partly.PHPVersion != "" || partly.HTTPS.On {
		t.Fatalf("partly deleted site %+v", partly)
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"partly_deleted"`) {
		t.Fatalf("list with a partly deleted site %d: %s", w.Code, w.Body.String())
	}
	for action, body := range map[string]map[string]any{
		"php":   {"php_version": "8.2", "expected_revision": site.Revision},
		"state": {"state": "suspended", "expected_revision": site.Revision},
	} {
		if w := websiteRequest(f.handler, "POST", sitePath(site, action), body, cookie, csrf); w.Code != 409 || problemDetail(t, w) != websitePartly {
			t.Fatalf("%s of a partly deleted site %d: %s", action, w.Code, w.Body.String())
		}
	}

	// Asked again, it carries on and finishes.
	w = del("example.com", site.Revision)
	var raw map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &raw) != nil || len(withoutSchema(raw)) != 3 {
		t.Fatalf("delete %d: %s", w.Code, w.Body.String())
	}
	var done WebsiteDeleted
	if err := json.Unmarshal(w.Body.Bytes(), &done); err != nil {
		t.Fatal(err)
	}
	if done.Domain != "example.com" || !slices.Equal(done.Removed, []string{"the database example_wp"}) || done.Kept == nil || len(done.Kept) != 0 {
		t.Fatalf("deleted %+v", done)
	}
	if !slices.Equal(databases.drops, []string{"user example example_wp", "database example example_wp", "database example example_wp"}) {
		t.Fatalf("drops %q", databases.drops)
	}
	if !slices.Equal(broker.changes, []string{want}) {
		t.Fatalf("broker changes %q", broker.changes)
	}
	// The site is gone from Websites, and its job is kept as a record.
	if w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"sites":[]`) {
		t.Fatalf("list after the delete %d: %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID, nil, cookie, ""); w.Code != 404 {
		t.Fatalf("read after the delete %d", w.Code)
	}
	if jobs := runner.List(); len(jobs) != 1 || jobs[0].RemovedAt == "" || len(runner.Succeeded()) != 0 {
		t.Fatalf("jobs after the delete %+v", jobs)
	}
	if w := del("example.com", site.Revision); w.Code != 404 {
		t.Fatalf("second delete %d: %s", w.Code, w.Body.String())
	}
}

// A delete the account service refused because the site's processes kept
// running answers 409 with that reason and what to do next, and the broker's
// own word under "Technical details".
func TestWebsiteDeleteRefusedAsBusy(t *testing.T) {
	f, _, broker, databases, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	broker.change(site.AccountID, func(a *hostaccounts.Account) { a.State = "suspended" })
	broker.mu.Lock()
	broker.busyDeletes = 1
	broker.mu.Unlock()
	w := websiteRequest(f.handler, "POST", sitePath(site, "delete"), map[string]any{"confirm_domain": "example.com", "expected_revision": site.Revision}, cookie, csrf)
	want := "The account still had running processes after 3 attempts, so nothing was removed. Suspend the site first (that stops its processes and keeps the site off), then delete it again."
	if w.Code != 409 || problemDetail(t, w) != want || problemTechnical(t, w) != hostaccounts.ErrDeleteBusy.Error() {
		t.Fatalf("busy delete %d: %s", w.Code, w.Body.String())
	}
	if len(databases.drops) != 0 || len(broker.changes) != 1 {
		t.Fatalf("a refused delete went on: %q %q", databases.drops, broker.changes)
	}
}

func TestWebsiteActionAdmission(t *testing.T) {
	f, _, broker, databases, site := actionsFixture(t)
	bodies := map[string]string{
		"php":    fmt.Sprintf(`{"php_version":"8.2","expected_revision":%d}`, site.Revision),
		"state":  fmt.Sprintf(`{"state":"suspended","expected_revision":%d}`, site.Revision),
		"delete": fmt.Sprintf(`{"confirm_domain":"example.com","expected_revision":%d}`, site.Revision),
	}
	for action, body := range bodies {
		if w := websiteRequest(f.handler, "POST", sitePath(site, action), body, nil, ""); w.Code != 401 {
			t.Fatalf("%s unauthenticated: %d", action, w.Code)
		}
	}
	cookie, csrf := websiteSignIn(t, f)
	first := map[string]string{"php": "php_version", "state": "state", "delete": "confirm_domain"}
	for action, body := range bodies {
		path := sitePath(site, action)
		if w := websiteRequest(f.handler, "POST", path, body, cookie, ""); w.Code != 403 {
			t.Fatalf("%s without CSRF: %d", action, w.Code)
		}
		for _, method := range []string{"PUT", "DELETE", "PATCH"} {
			if w := websiteRequest(f.handler, method, path, body, cookie, csrf); w.Code != 405 {
				t.Fatalf("%s %s: %d", method, action, w.Code)
			}
		}
		// A page on another origin cannot ask, even with the cookie and token.
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:14000"
		r.Header.Set("Origin", "http://other.example")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s cross-origin: %d", action, w.Code)
		}
		only := "Send only " + first[action] + " and expected_revision."
		for _, tc := range []struct {
			name, body string
			status     int
			detail     string
		}{
			{"unknown key", strings.Replace(body, `{`, `{"reason":"x",`, 1), 422, only},
			{"case alias", strings.Replace(body, `"expected_revision"`, `"Expected_Revision"`, 1), 422, only},
			{"another action's key", strings.Replace(body, `{`, `{"domain":"example.com",`, 1), 422, only},
			{"duplicate key", strings.Replace(body, `{`, `{"expected_revision":1,`, 1), 422, "expected_revision more than once"},
			{"revision as text", strings.Replace(body, fmt.Sprintf(`:%d}`, site.Revision), fmt.Sprintf(`:"%d"}`, site.Revision), 1), 422, "expected_revision must be a whole number."},
			{"negative revision", strings.Replace(body, fmt.Sprintf(`:%d}`, site.Revision), `:-1}`, 1), 422, "expected_revision must be a whole number."},
			{"fraction revision", strings.Replace(body, fmt.Sprintf(`:%d}`, site.Revision), `:2.0}`, 1), 422, "expected_revision must be a whole number."},
			{"text as a number", fmt.Sprintf(`{%q:1,"expected_revision":%d}`, first[action], site.Revision), 422, first[action] + " must be text."},
			{"array", `[]`, 400, ""},
			{"trailing data", body + `{}`, 400, ""},
			{"too large", strings.Replace(body, `{`, `{"`+first[action]+`":"`+strings.Repeat("x", 4096)+`",`, 1), 413, ""},
		} {
			w := websiteRequest(f.handler, "POST", path, tc.body, cookie, csrf)
			if w.Code != tc.status {
				t.Fatalf("%s %s: status %d want %d: %s", action, tc.name, w.Code, tc.status, w.Body.String())
			}
			if d := problemDetail(t, w); tc.detail != "" && !strings.Contains(d, tc.detail) {
				t.Fatalf("%s %s: detail %q", action, tc.name, d)
			}
		}
		// Not a listed website: 404, whatever the action.
		for _, id := range []string{strings.Repeat("0", 32)} {
			if w := websiteRequest(f.handler, "POST", "/api/v1/websites/sites/"+id+"/"+action, body, cookie, csrf); w.Code != 404 {
				t.Fatalf("%s on an unknown site: %d %s", action, w.Code, w.Body.String())
			}
		}
	}
	// Only these three actions take a POST.
	for _, path := range []string{sitePath(site, "restart"), "/api/v1/websites/sites/" + site.AccountID, "/api/v1/websites/sites/not-an-id/delete", sitePath(site, "delete") + "/"} {
		if w := websiteRequest(f.handler, "POST", path, bodies["delete"], cookie, csrf); w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s: %d", path, w.Code)
		}
	}
	if len(broker.changes) != 0 || len(databases.drops) != 0 {
		t.Fatalf("a refused request changed something: %q %q", broker.changes, databases.drops)
	}
}

func TestWebsiteActionsNotSetUp(t *testing.T) {
	f, runner, broker, _, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	bodies := map[string]map[string]any{
		"php":    {"php_version": "8.2", "expected_revision": site.Revision},
		"state":  {"state": "suspended", "expected_revision": site.Revision},
		"delete": {"confirm_domain": "example.com", "expected_revision": site.Revision},
	}
	for name, options := range map[string]Options{
		"no wizard": {Operator: f.manager, Accounts: broker},
		"no broker": {Operator: f.manager, Wizard: runner},
	} {
		h := New(Options{Operator: options.Operator, Accounts: options.Accounts, Wizard: options.Wizard, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
		for action, body := range bodies {
			w := websiteRequest(h, "POST", sitePath(site, action), body, cookie, csrf)
			if w.Code != 503 || problemDetail(t, w) != websitesNotSetUp {
				t.Fatalf("%s %s: %d %s", name, action, w.Code, w.Body.String())
			}
		}
	}
}
