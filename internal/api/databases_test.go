package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
)

// fakeDatabases stands in for dbhost.LocalService. It checks no ownership
// itself and does whatever it is asked, so these tests show the panel's own
// fence: a call that should not happen is in calls, and a database that
// should be untouched is gone. With leaky set, the list calls answer every
// owner's entries.
type fakeDatabases struct {
	mu        sync.Mutex
	databases map[string]dbhost.Database
	users     map[string]dbhost.User
	passwords map[string]string
	calls     []string
	leaky     bool
	// fail answers an error for one operation; it is given the password, as
	// MariaDB can echo the statement.
	fail map[string]func(password string) error
}

func newFakeDatabases() *fakeDatabases {
	return &fakeDatabases{databases: map[string]dbhost.Database{}, users: map[string]dbhost.User{}, passwords: map[string]string{}, fail: map[string]func(string) error{}}
}

func (f *fakeDatabases) seed(owner, database string, users ...string) {
	f.databases[database] = dbhost.Database{Name: database, Owner: owner, Users: users}
	for _, u := range users {
		f.users[u] = dbhost.User{Name: u, Owner: owner, Hosts: []string{"localhost"}}
	}
}

// begin records a call (never a password) and answers its planned failure.
func (f *fakeDatabases) begin(op, owner, name, password string) error {
	f.calls = append(f.calls, op+" "+owner+" "+name)
	if fail := f.fail[op]; fail != nil {
		return fail(password)
	}
	return nil
}

func (f *fakeDatabases) ListDatabases(_ context.Context, owner string) ([]dbhost.Database, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fail := f.fail["list"]; fail != nil {
		return nil, fail("")
	}
	out := []dbhost.Database{}
	for _, d := range f.databases {
		if f.leaky || d.Owner == owner {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b dbhost.Database) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (f *fakeDatabases) ListUsers(_ context.Context, owner string) ([]dbhost.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []dbhost.User{}
	for _, u := range f.users {
		if f.leaky || u.Owner == owner {
			out = append(out, u)
		}
	}
	slices.SortFunc(out, func(a, b dbhost.User) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (f *fakeDatabases) CreateDatabaseStrict(_ context.Context, owner, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("create-database", owner, name, ""); err != nil {
		if errors.Is(err, dbhost.ErrNotRegistered) {
			f.databases[name] = dbhost.Database{Name: name, Owner: owner}
		}
		return err
	}
	if _, ok := f.databases[name]; ok {
		return fmt.Errorf("%w: the registry already lists the database %s", dbhost.ErrExists, name)
	}
	f.databases[name] = dbhost.Database{Name: name, Owner: owner}
	return nil
}

func (f *fakeDatabases) CreateUserStrict(_ context.Context, owner, name, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("create-user", owner, name, password); err != nil {
		return err
	}
	if _, ok := f.users[name]; ok {
		return fmt.Errorf("%w: the registry already lists the user %s", dbhost.ErrExists, name)
	}
	f.users[name] = dbhost.User{Name: name, Owner: owner, Hosts: []string{"localhost"}}
	f.passwords[name] = password
	return nil
}

func (f *fakeDatabases) SetPrivileges(_ context.Context, owner, user, db string, privs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("grant", owner, user+" on "+db+" "+strings.Join(privs, ","), f.passwords[user]); err != nil {
		return err
	}
	d := f.databases[db]
	d.Users = append(d.Users, user)
	f.databases[db] = d
	return nil
}

func (f *fakeDatabases) SetPassword(_ context.Context, owner, name, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("set-password", owner, name, password); err != nil {
		return err
	}
	f.passwords[name] = password
	return nil
}

func (f *fakeDatabases) DropDatabase(_ context.Context, owner, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("drop-database", owner, name, ""); err != nil {
		return err
	}
	delete(f.databases, name)
	return nil
}

func (f *fakeDatabases) DropUser(_ context.Context, owner, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("drop-user", owner, name, ""); err != nil {
		return err
	}
	delete(f.users, name)
	delete(f.passwords, name)
	return nil
}

var (
	alphaID = strings.Repeat("a", 32)
	betaID  = strings.Repeat("b", 32)
)

const (
	databasePassword = "correct horse battery staple"
	alphaDatabases   = "/api/v1/websites/sites/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/databases"
)

// databasesFixture is two websites, alpha and beta, each with the wizard's
// database and user, and one database in beta's name that carries alpha's
// prefix.
func databasesFixture(t *testing.T) (siteFixture, *fakeDatabases, *sitesBroker) {
	t.Helper()
	f := websiteFixture(t)
	broker := &sitesBroker{accounts: []hostaccounts.Account{
		{ID: alphaID, Username: "alpha", Domain: "alpha.example", State: "active", Revision: 1},
		{ID: betaID, Username: "beta", Domain: "beta.example", State: "active", Revision: 1},
	}}
	db := newFakeDatabases()
	db.seed("alpha", "alpha_wp", "alpha_wp")
	db.seed("beta", "beta_wp", "beta_wp")
	db.seed("beta", "alpha_stolen", "alpha_thief")
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Databases: db, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return f, db, broker
}

// problemTexts is every text a problem answer carries: the detail and the
// technical lines.
func problemTexts(t *testing.T, w *httptest.ResponseRecorder) (detail string, technical []string) {
	t.Helper()
	var p struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Status != w.Code || p.Detail == "" {
		t.Fatalf("not problem JSON (%d): %s", w.Code, w.Body.String())
	}
	for _, e := range p.Errors {
		technical = append(technical, e.Message)
	}
	return p.Detail, technical
}

func databaseList(t *testing.T, h http.Handler, id string, cookie *http.Cookie) siteDatabasesBody {
	t.Helper()
	w := websiteRequest(h, "GET", "/api/v1/websites/sites/"+id+"/databases", nil, cookie, "")
	if w.Code != 200 {
		t.Fatalf("list status %d: %s", w.Code, w.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil || len(withoutSchema(raw)) != 2 || raw["databases"] == nil || raw["users"] == nil {
		t.Fatalf("list body %s", w.Body.String())
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw["databases"], &items); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if len(item) != 2 || item["name"] == nil || !strings.HasPrefix(string(item["users"]), "[") {
			t.Fatalf("database entry %v", item)
		}
	}
	var users []map[string]json.RawMessage
	if err := json.Unmarshal(raw["users"], &users); err != nil {
		t.Fatal(err)
	}
	for _, item := range users {
		if len(item) != 1 || item["name"] == nil {
			t.Fatalf("user entry %v", item)
		}
	}
	var body siteDatabasesBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestSiteDatabasesCreateListAndDelete(t *testing.T) {
	f, db, _ := databasesFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	post := func(path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		w := websiteRequest(f.handler, "POST", alphaDatabases+path, body, cookie, csrf)
		if strings.Contains(w.Body.String(), databasePassword) {
			t.Fatalf("POST %s echoed the password: %s", path, w.Body.String())
		}
		return w
	}
	named := func(w *httptest.ResponseRecorder, status int, name string) {
		t.Helper()
		var body map[string]json.RawMessage
		if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(withoutSchema(body)) != 1 || string(body["name"]) != `"`+name+`"` {
			t.Fatalf("status %d, want %d naming %s: %s", w.Code, status, name, w.Body.String())
		}
	}

	if got := databaseList(t, f.handler, alphaID, cookie); len(got.Databases) != 1 || got.Databases[0].Name != "alpha_wp" || !slices.Equal(got.Databases[0].Users, []string{"alpha_wp"}) || len(got.Users) != 1 || got.Users[0].Name != "alpha_wp" {
		t.Fatalf("first list %+v", got)
	}

	named(post("", map[string]string{"name_suffix": "shop"}), 201, "alpha_shop")
	// A suffix that spells another website's name is still only a suffix.
	named(post("", map[string]string{"name_suffix": "beta_wp"}), 201, "alpha_beta_wp")
	named(post("/users", map[string]string{"name_suffix": "app", "password": databasePassword, "database": "alpha_shop"}), 201, "alpha_app")
	if db.passwords["alpha_app"] != databasePassword || db.users["alpha_app"].Owner != "alpha" || db.databases["alpha_shop"].Owner != "alpha" {
		t.Fatalf("created %+v %+v", db.users["alpha_app"], db.databases["alpha_shop"])
	}
	if !slices.Contains(db.calls, "grant alpha alpha_app on alpha_shop ALL PRIVILEGES") {
		t.Fatalf("no grant of every privilege: %q", db.calls)
	}

	got := databaseList(t, f.handler, alphaID, cookie)
	if len(got.Databases) != 3 || got.Databases[1].Name != "alpha_shop" || !slices.Equal(got.Databases[1].Users, []string{"alpha_app"}) || len(got.Databases[0].Users) != 0 || len(got.Users) != 2 {
		t.Fatalf("list after creates %+v", got)
	}
	w := websiteRequest(f.handler, "GET", alphaDatabases, nil, cookie, "")
	if !strings.Contains(w.Body.String(), `{"name":"alpha_beta_wp","users":[]}`) || strings.Contains(w.Body.String(), databasePassword) {
		t.Fatalf("list body %s", w.Body.String())
	}

	const newPassword = "another long passphrase 42"
	w = websiteRequest(f.handler, "POST", alphaDatabases+"/users/alpha_app/password", map[string]string{"password": newPassword}, cookie, csrf)
	named(w, 200, "alpha_app")
	if db.passwords["alpha_app"] != newPassword || strings.Contains(w.Body.String(), newPassword) {
		t.Fatal("the new password did not reach the service, or was echoed")
	}

	// Deleting the database leaves its user, and deletes nothing else.
	before := len(db.calls)
	named(post("/alpha_shop/delete", map[string]string{"confirm_name": "alpha_shop"}), 200, "alpha_shop")
	if !slices.Equal(db.calls[before:], []string{"drop-database alpha alpha_shop"}) {
		t.Fatalf("delete database did %q", db.calls[before:])
	}
	if _, ok := db.users["alpha_app"]; !ok {
		t.Fatal("deleting the database removed its user")
	}
	before = len(db.calls)
	named(post("/users/alpha_app/delete", map[string]string{"confirm_name": "alpha_app"}), 200, "alpha_app")
	if !slices.Equal(db.calls[before:], []string{"drop-user alpha alpha_app"}) {
		t.Fatalf("delete user did %q", db.calls[before:])
	}
	if got = databaseList(t, f.handler, alphaID, cookie); len(got.Databases) != 2 || len(got.Users) != 1 {
		t.Fatalf("list after deletes %+v", got)
	}

	// A website with nothing: two empty lists, not null.
	delete(db.databases, "beta_wp")
	delete(db.databases, "alpha_stolen")
	delete(db.users, "beta_wp")
	delete(db.users, "alpha_thief")
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+betaID+"/databases", nil, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"databases":[]`) || !strings.Contains(w.Body.String(), `"users":[]`) {
		t.Fatalf("empty list %d: %s", w.Code, w.Body.String())
	}
}

// A request for alpha can never read, change or delete what belongs to beta,
// whatever name it carries and even if the service would allow it.
func TestSiteDatabasesOwnerIsolation(t *testing.T) {
	for _, leaky := range []bool{false, true} {
		f, db, broker := databasesFixture(t)
		db.leaky = leaky
		cookie, csrf := websiteSignIn(t, f)

		got := databaseList(t, f.handler, alphaID, cookie)
		if len(got.Databases) != 1 || got.Databases[0].Name != "alpha_wp" || len(got.Users) != 1 || got.Users[0].Name != "alpha_wp" {
			t.Fatalf("leaky=%v: alpha's list shows another website's entries: %+v", leaky, got)
		}

		for _, tc := range []struct {
			name, path string
			body       any
			status     int
			detail     string
		}{
			{"delete beta's database", "/beta_wp/delete", map[string]string{"confirm_name": "beta_wp"}, 404, databaseNotFound},
			{"delete beta's database that has alpha's prefix", "/alpha_stolen/delete", map[string]string{"confirm_name": "alpha_stolen"}, 404, databaseNotFound},
			{"delete a database nobody has", "/alpha_none/delete", map[string]string{"confirm_name": "alpha_none"}, 404, databaseNotFound},
			{"delete beta's user", "/users/beta_wp/delete", map[string]string{"confirm_name": "beta_wp"}, 404, databaseUserNotFound},
			{"delete beta's user that has alpha's prefix", "/users/alpha_thief/delete", map[string]string{"confirm_name": "alpha_thief"}, 404, databaseUserNotFound},
			{"change beta's password", "/users/beta_wp/password", map[string]string{"password": databasePassword}, 404, databaseUserNotFound},
			{"change the password of beta's user with alpha's prefix", "/users/alpha_thief/password", map[string]string{"password": databasePassword}, 404, databaseUserNotFound},
			{"grant on beta's database", "/users", map[string]string{"name_suffix": "spy", "password": databasePassword, "database": "beta_wp"}, 404, databaseNotFound},
			{"grant on beta's database with alpha's prefix", "/users", map[string]string{"name_suffix": "spy", "password": databasePassword, "database": "alpha_stolen"}, 404, databaseNotFound},
			{"a user name as a database", "/alpha_thief/delete", map[string]string{"confirm_name": "alpha_thief"}, 404, databaseNotFound},
			{"a name in another case", "/BETA_WP/delete", map[string]string{"confirm_name": "BETA_WP"}, 404, databaseNotFound},
			{"a quoted name", "/alpha_wp%60/delete", map[string]string{"confirm_name": "alpha_wp`"}, 404, databaseNotFound},
			{"a name with a statement", "/alpha_wp%3BDROP%20DATABASE%20beta_wp/delete", map[string]string{"confirm_name": "alpha_wp;DROP DATABASE beta_wp"}, 404, databaseNotFound},
			{"a suffix that climbs out", "", map[string]string{"name_suffix": "../beta_wp"}, 422, databaseSuffixRule},
			{"a suffix with a statement", "", map[string]string{"name_suffix": "x`; DROP DATABASE beta_wp"}, 422, databaseSuffixRule},
			{"a user suffix with a quote", "/users", map[string]string{"name_suffix": "x'@'%", "password": databasePassword, "database": "alpha_wp"}, 422, databaseSuffixRule},
			{"a username in the body", "", `{"name_suffix":"x","username":"beta"}`, 422, "Send only name_suffix."},
			{"an owner in the body", "/beta_wp/delete", `{"confirm_name":"beta_wp","owner":"beta"}`, 422, "Send only confirm_name."},
		} {
			w := websiteRequest(f.handler, "POST", alphaDatabases+tc.path, tc.body, cookie, csrf)
			if d := problemDetail(t, w); w.Code != tc.status || !strings.Contains(d, tc.detail) {
				t.Fatalf("leaky=%v %s: %d %q", leaky, tc.name, w.Code, d)
			}
			if strings.Contains(w.Body.String(), "beta") || strings.Contains(w.Body.String(), databasePassword) {
				t.Fatalf("leaky=%v %s: the answer names the other website or the password: %s", leaky, tc.name, w.Body.String())
			}
		}
		// Encoded slashes and dot segments never reach a handler.
		for _, path := range []string{"/alpha_wp%2F..%2Fbeta_wp/delete", "/..%2F..%2F" + betaID + "%2Fdatabases%2Fbeta_wp/delete", "/users/alpha_wp%2F..%2Fbeta_wp/password", "/../../" + betaID + "/databases/beta_wp/delete"} {
			body := map[string]string{"confirm_name": "beta_wp", "password": databasePassword}
			if strings.HasSuffix(path, "/delete") {
				delete(body, "password")
			} else {
				delete(body, "confirm_name")
			}
			before := len(db.calls)
			if w := websiteRequest(f.handler, "POST", alphaDatabases+path, body, cookie, csrf); w.Code < 300 || len(db.calls) != before {
				t.Fatalf("leaky=%v crafted path %s: status %d, calls %q", leaky, path, w.Code, db.calls[before:])
			}
		}

		if len(db.calls) != 0 {
			t.Fatalf("leaky=%v: a refused request reached the database service: %q", leaky, db.calls)
		}
		if d := db.databases["beta_wp"]; d.Owner != "beta" || !slices.Equal(d.Users, []string{"beta_wp"}) || db.databases["alpha_stolen"].Owner != "beta" || db.users["beta_wp"].Owner != "beta" || db.users["alpha_thief"].Owner != "beta" || len(db.passwords) != 0 {
			t.Fatalf("leaky=%v: beta's databases changed: %+v %+v", leaky, db.databases, db.users)
		}

		// The owner is the broker's username, whatever the address or body says.
		for _, id := range []string{strings.Repeat("0", 32), strings.ToUpper(alphaID), "alpha", "beta"} {
			if w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+id+"/databases", nil, cookie, ""); w.Code != 404 || problemDetail(t, w) != databaseSiteNotFound {
				t.Fatalf("GET for %s: %d %s", id, w.Code, w.Body.String())
			}
			if w := websiteRequest(f.handler, "POST", "/api/v1/websites/sites/"+id+"/databases", map[string]string{"name_suffix": "x"}, cookie, csrf); w.Code != 404 {
				t.Fatalf("POST for %s: %d %s", id, w.Code, w.Body.String())
			}
		}
		// dbhost reads an empty owner as every account: an account the broker
		// names badly gets nothing.
		for _, username := range []string{"", "Alpha", "al", "alpha_wp`"} {
			broker.change(alphaID, func(a *hostaccounts.Account) { a.Username = username })
			for _, method := range []string{"GET", "POST"} {
				if w := websiteRequest(f.handler, method, alphaDatabases, map[string]string{"name_suffix": "x"}, cookie, csrf); w.Code != 503 || problemDetail(t, w) != databaseOwnerUnknown {
					t.Fatalf("username %q %s: %d %s", username, method, w.Code, w.Body.String())
				}
			}
		}
		if len(db.calls) != 0 {
			t.Fatalf("leaky=%v: a request without a usable owner reached the database service: %q", leaky, db.calls)
		}
	}
}

func TestSiteDatabasesAdmissionAndStrictKeys(t *testing.T) {
	f, db, _ := databasesFixture(t)
	posts := map[string]string{
		"":                         `{"name_suffix":"shop"}`,
		"/users":                   `{"name_suffix":"app","password":"` + databasePassword + `","database":"alpha_wp"}`,
		"/users/alpha_wp/password": `{"password":"` + databasePassword + `"}`,
		"/alpha_wp/delete":         `{"confirm_name":"alpha_wp"}`,
		"/users/alpha_wp/delete":   `{"confirm_name":"alpha_wp"}`,
	}
	if w := websiteRequest(f.handler, "GET", alphaDatabases, nil, nil, ""); w.Code != 401 {
		t.Fatalf("unauthenticated GET status %d", w.Code)
	}
	cookie, csrf := websiteSignIn(t, f)
	for path, body := range posts {
		if w := websiteRequest(f.handler, "POST", alphaDatabases+path, body, nil, ""); w.Code != 401 {
			t.Fatalf("unauthenticated POST %s status %d", path, w.Code)
		}
		if w := websiteRequest(f.handler, "POST", alphaDatabases+path, body, cookie, ""); w.Code != 403 {
			t.Fatalf("POST %s without CSRF status %d", path, w.Code)
		}
		for _, method := range []string{"PUT", "PATCH", "DELETE"} {
			if w := websiteRequest(f.handler, method, alphaDatabases+path, body, cookie, csrf); w.Code != 405 {
				t.Fatalf("%s %s status %d", method, path, w.Code)
			}
		}
		// A page on another origin cannot post, even with the cookie and token.
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+alphaDatabases+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:14000"
		r.Header.Set("Origin", "http://other.example")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("cross-origin POST %s status %d", path, w.Code)
		}
		r = httptest.NewRequest("POST", "http://127.0.0.1:8080"+alphaDatabases+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:14000"
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("Content-Type", "text/plain")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != 415 {
			t.Fatalf("text body POST %s status %d", path, w.Code)
		}

		first := body[2:strings.Index(body, `":`)]
		for _, tc := range []struct {
			name, body string
			status     int
			detail     string
		}{
			{"duplicate key", strings.Replace(body, `{`, `{"`+first+`":"other",`, 1), 422, first + " more than once"},
			{"case alias", strings.Replace(body, `"`+first+`"`, `"`+strings.ToUpper(first)+`"`, 1), 422, "Send only "},
			{"unknown key", strings.Replace(body, `{`, `{"sensitive-key":"x",`, 1), 422, "Send only "},
			{"number", strings.Replace(body, `{"`+first+`":"`, `{"`+first+`":1,"x":"`, 1), 422, first + " must be text"},
			{"null field", `{"` + first + `":null}`, 422, first + " must be text"},
			{"null body", `null`, 400, ""},
			{"array", `[]`, 400, ""},
			{"trailing data", body + `{}`, 400, ""},
			{"too large", strings.Replace(body, `{`, `{"`+first+`":"`+strings.Repeat("x", 4096)+`",`, 1), 413, ""},
		} {
			w := websiteRequest(f.handler, "POST", alphaDatabases+path, tc.body, cookie, csrf)
			if w.Code != tc.status {
				t.Fatalf("%s %s: status %d want %d: %s", path, tc.name, w.Code, tc.status, w.Body.String())
			}
			if d := problemDetail(t, w); tc.detail != "" && !strings.Contains(d, tc.detail) {
				t.Fatalf("%s %s: detail %q", path, tc.name, d)
			}
			if strings.Contains(w.Body.String(), "sensitive-key") || strings.Contains(w.Body.String(), databasePassword) {
				t.Fatalf("%s %s: request echoed", path, tc.name)
			}
		}
	}
	// Each route names its own keys.
	for path, only := range map[string]string{"": "Send only name_suffix.", "/users": "Send only name_suffix, password and database.", "/users/alpha_wp/password": "Send only password.", "/alpha_wp/delete": "Send only confirm_name.", "/users/alpha_wp/delete": "Send only confirm_name."} {
		w := websiteRequest(f.handler, "POST", alphaDatabases+path, `{"other":"x"}`, cookie, csrf)
		if w.Code != 422 || !strings.HasSuffix(problemDetail(t, w), only) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	// Nothing else under a site becomes a mutation.
	for _, path := range []string{"/users/alpha_wp", "/users/alpha_wp/grant", "/alpha_wp", "/alpha_wp/rename", "/alpha_wp/delete/", "/users/alpha_wp/password/again", "//delete"} {
		if w := websiteRequest(f.handler, "POST", alphaDatabases+path, `{"confirm_name":"alpha_wp"}`, cookie, csrf); w.Code != 405 {
			t.Fatalf("POST %s status %d", path, w.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/sites/"+alphaID, `{}`, cookie, csrf); w.Code != 405 {
		t.Fatalf("POST to the site status %d", w.Code)
	}
	if len(db.calls) != 0 || len(db.databases) != 3 {
		t.Fatalf("a refused request reached the database service: %q", db.calls)
	}

	// The spec describes the session and CSRF each POST needs.
	w := websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	var spec map[string]any
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("invalid OpenAPI")
	}
	paths := spec["paths"].(map[string]any)
	const base = "/api/v1/websites/sites/{account_id}/databases"
	for _, path := range []string{"", "/users", "/users/{user}/password", "/{name}/delete", "/users/{user}/delete"} {
		post, ok := paths[base+path].(map[string]any)["post"].(map[string]any)
		if !ok {
			t.Fatalf("no POST %s in the spec", path)
		}
		if security := fmt.Sprint(post["security"]); !strings.Contains(security, "operatorSession") || !strings.Contains(security, "sessionCSRF") || !strings.Contains(fmt.Sprint(post["description"]), "never a name from the request") {
			t.Fatalf("POST %s: security %s", path, security)
		}
	}
	if get := paths[base].(map[string]any)["get"].(map[string]any); strings.Contains(fmt.Sprint(get["security"]), "sessionCSRF") || !strings.Contains(fmt.Sprint(get["security"]), "operatorSession") {
		t.Fatalf("GET security %v", get["security"])
	}
}

func TestSiteDatabasesValidation(t *testing.T) {
	f, db, broker := databasesFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	refused := func(name, path string, body any, detail string) {
		t.Helper()
		w := websiteRequest(f.handler, "POST", alphaDatabases+path, body, cookie, csrf)
		if d := problemDetail(t, w); w.Code != 422 || !strings.Contains(d, detail) {
			t.Fatalf("%s: %d %q", name, w.Code, d)
		}
		if strings.Contains(w.Body.String(), databasePassword) {
			t.Fatalf("%s: password echoed", name)
		}
	}
	user := func(change func(map[string]string)) map[string]string {
		body := map[string]string{"name_suffix": "app", "password": databasePassword, "database": "alpha_wp"}
		change(body)
		return body
	}
	for _, suffix := range []string{"", "Shop", "my-shop", "my shop", "shöp", "a.b", strings.Repeat("a", 17), "wp\n"} {
		refused("database suffix "+suffix, "", map[string]string{"name_suffix": suffix}, databaseSuffixRule)
		refused("user suffix "+suffix, "/users", user(func(b map[string]string) { b["name_suffix"] = suffix }), databaseSuffixRule)
	}
	refused("missing suffix", "", `{}`, databaseSuffixRule)
	for name, password := range map[string]string{
		"short":         "elevenchars",
		"long":          strings.Repeat("p", 129),
		"leading space": " " + databasePassword,
		"closing space": databasePassword + " ",
		"line break":    "correct horse\nbattery",
		"tab":           "correct horse\tbattery",
		"delete":        "correct horse\x7fbattery",
		"control":       "correct horse\u0085battery",
		"empty":         "",
	} {
		refused("new user password "+name, "/users", user(func(b map[string]string) { b["password"] = password }), databasePasswordRule)
		refused("changed password "+name, "/users/alpha_wp/password", map[string]string{"password": password}, databasePasswordRule)
	}
	refused("missing password", "/users/alpha_wp/password", `{}`, databasePasswordRule)
	refused("missing database", "/users", `{"name_suffix":"app","password":"`+databasePassword+`"}`, "database must name one of this website's databases.")
	for _, confirm := range []string{"", "alpha", "ALPHA_WP", "alpha_wp ", "beta_wp"} {
		refused("database confirm "+confirm, "/alpha_wp/delete", map[string]string{"confirm_name": confirm}, "confirm_name must be the database's name")
		refused("user confirm "+confirm, "/users/alpha_wp/delete", map[string]string{"confirm_name": confirm}, "confirm_name must be the user's name")
	}
	if len(db.calls) != 0 {
		t.Fatalf("a refused request reached the database service: %q", db.calls)
	}

	// The limits are dbhost's: 64 characters for a database, 47 for a user.
	long := "a" + strings.Repeat("b", 31)
	broker.change(alphaID, func(a *hostaccounts.Account) { a.Username = long })
	suffix := strings.Repeat("s", 16)
	if w := websiteRequest(f.handler, "POST", alphaDatabases, map[string]string{"name_suffix": suffix}, cookie, csrf); w.Code != 201 || db.databases[long+"_"+suffix].Owner != long {
		t.Fatalf("49-character database name: %d %s", w.Code, w.Body.String())
	}
	body := map[string]string{"name_suffix": suffix, "password": databasePassword, "database": long + "_" + suffix}
	w := websiteRequest(f.handler, "POST", alphaDatabases+"/users", body, cookie, csrf)
	if d := problemDetail(t, w); w.Code != 422 || !strings.Contains(d, "at most 47 characters") {
		t.Fatalf("49-character user name: %d %q", w.Code, d)
	}
	body["name_suffix"] = strings.Repeat("s", 14)
	if w = websiteRequest(f.handler, "POST", alphaDatabases+"/users", body, cookie, csrf); w.Code != 201 || len(long+"_"+body["name_suffix"]) != dbhost.MaxUserLen {
		t.Fatalf("47-character user name: %d %s", w.Code, w.Body.String())
	}
	// 128 bytes and inner spaces are accepted.
	body = map[string]string{"name_suffix": "edge", "password": "p " + strings.Repeat("ü", 63), "database": long + "_" + suffix}
	if w = websiteRequest(f.handler, "POST", alphaDatabases+"/users", body, cookie, csrf); w.Code != 201 || db.passwords[long+"_edge"] != body["password"] {
		t.Fatalf("128-byte password: %d %s", w.Code, w.Body.String())
	}
}

// MariaDB can echo the statement, and the statement holds the password.
func TestSiteDatabasesScrubPasswords(t *testing.T) {
	const quoted = `it's a "long" pass\word <here>`
	echoes := map[string]func(string) error{
		"statement echo": func(p string) error {
			return fmt.Errorf("ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual for the right syntax to use near '%s'' at line 1", p[len(p)/2:])
		},
		"as typed": func(p string) error {
			return fmt.Errorf("ERROR 1819 (HY000) at line 1: the password %s is not allowed\nfor\tthis \x00user\x1b[0m", p)
		},
		"as escaped": func(p string) error {
			return fmt.Errorf("ERROR 1819 (HY000) at line 1: IDENTIFIED BY '%s' refused", strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(p))
		},
		"long": func(p string) error { return errors.New(strings.Repeat("x", 600) + p) },
	}
	f, db, _ := databasesFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	for _, password := range []string{databasePassword, quoted} {
		for name, echo := range echoes {
			for _, tc := range []struct{ op, path string }{
				{"create-user", "/users"},
				{"grant", "/users"},
				{"set-password", "/users/alpha_wp/password"},
			} {
				db.fail = map[string]func(string) error{tc.op: echo}
				body := map[string]string{"password": password}
				if tc.path == "/users" {
					body["name_suffix"], body["database"] = "app", "alpha_wp"
				}
				w := websiteRequest(f.handler, "POST", alphaDatabases+tc.path, body, cookie, csrf)
				detail, technical := problemTexts(t, w)
				if w.Code != 502 || len(technical) != 1 || technical[0] == "" {
					t.Fatalf("%s %s: %d %s", tc.op, name, w.Code, w.Body.String())
				}
				escaped := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(password)
				for _, text := range append(technical, detail, w.Body.String()) {
					if strings.Contains(text, password) || strings.Contains(text, escaped) || strings.Contains(text, password[len(password)/2:]) {
						t.Fatalf("%s %s: the answer holds the password: %s", tc.op, name, text)
					}
				}
				if len(technical[0]) > 512 || strings.ContainsFunc(technical[0], func(r rune) bool { return r < 0x20 || r >= 0x7f }) {
					t.Fatalf("%s %s: technical text is not short printable ASCII: %q", tc.op, name, technical[0])
				}
				if name == "statement echo" && !strings.HasSuffix(technical[0], "near [statement removed]") {
					t.Fatalf("%s: statement echo kept: %q", tc.op, technical[0])
				}
				if name == "as typed" && technical[0] != "ERROR 1819 (HY000) at line 1: the password [secret] is not allowed for this user[0m" {
					t.Fatalf("%s: %q", tc.op, technical[0])
				}
				// A user that could not be given its access is removed again.
				if _, kept := db.users["alpha_app"]; kept {
					t.Fatalf("%s %s: the user was kept", tc.op, name)
				}
				if tc.op == "grant" && (db.calls[len(db.calls)-1] != "drop-user alpha alpha_app" || !strings.Contains(detail, "so the panel removed it again")) {
					t.Fatalf("grant failure: %q %q", db.calls, detail)
				}
			}
		}
	}

	// The grant failed and so did the removal: the answer says what is left.
	db.fail = map[string]func(string) error{
		"grant":     func(string) error { return errors.New("ERROR 1044 (42000) at line 1: Access denied") },
		"drop-user": func(string) error { return dbhost.ErrUnavailable },
	}
	w := websiteRequest(f.handler, "POST", alphaDatabases+"/users", map[string]string{"name_suffix": "app", "password": databasePassword, "database": "alpha_wp"}, cookie, csrf)
	if d := problemDetail(t, w); w.Code != 502 || !strings.Contains(d, "could not remove it again. Delete it here if it is listed") {
		t.Fatalf("failed undo: %d %q", w.Code, d)
	}
}

func TestSiteDatabasesConflictAndUnavailable(t *testing.T) {
	f, db, broker := databasesFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	user := func(suffix string) map[string]string {
		return map[string]string{"name_suffix": suffix, "password": databasePassword, "database": "alpha_wp"}
	}

	// 409, in plain words, whoever has the name.
	db.seed("beta", "alpha_taken", "alpha_takenuser")
	for _, tc := range []struct {
		path string
		body any
		want string
	}{
		{"", map[string]string{"name_suffix": "wp"}, "A database named alpha_wp already exists on this server. Choose another name."},
		{"", map[string]string{"name_suffix": "taken"}, "A database named alpha_taken already exists on this server. Choose another name."},
		{"/users", user("wp"), "A database user named alpha_wp already exists on this server. Choose another name."},
		{"/users", user("takenuser"), "A database user named alpha_takenuser already exists on this server. Choose another name."},
	} {
		w := websiteRequest(f.handler, "POST", alphaDatabases+tc.path, tc.body, cookie, csrf)
		if detail, technical := problemTexts(t, w); w.Code != 409 || detail != tc.want || len(technical) != 0 || strings.Contains(w.Body.String(), "beta") {
			t.Fatalf("POST %s %v: %d %s", tc.path, tc.body, w.Code, w.Body.String())
		}
	}
	if db.databases["alpha_taken"].Owner != "beta" || db.users["alpha_takenuser"].Owner != "beta" || db.users["alpha_wp"].Owner != "alpha" || len(db.passwords) != 0 {
		t.Fatal("a refused create changed an existing database or user")
	}
	for _, call := range db.calls {
		if strings.HasPrefix(call, "drop-") || strings.HasPrefix(call, "grant") {
			t.Fatalf("a 409 was followed by %q", call)
		}
	}

	// Made on the server but not recorded: removed again, and said so.
	db.fail["create-database"] = func(string) error { return fmt.Errorf("%w: database alpha_lost: disk full", dbhost.ErrNotRegistered) }
	w := websiteRequest(f.handler, "POST", alphaDatabases, map[string]string{"name_suffix": "lost"}, cookie, csrf)
	if d, technical := problemTexts(t, w); w.Code != 500 || !strings.Contains(d, "so the panel removed it again") || len(technical) != 1 || db.calls[len(db.calls)-1] != "drop-database alpha alpha_lost" {
		t.Fatalf("unrecorded database: %d %s %q", w.Code, w.Body.String(), db.calls)
	}
	if _, kept := db.databases["alpha_lost"]; kept {
		t.Fatal("the unrecorded database was kept")
	}
	delete(db.fail, "create-database")

	// 503 when the database server is down.
	requests := []struct {
		method, path string
		body         any
	}{
		{"GET", "", nil},
		{"POST", "", map[string]string{"name_suffix": "shop"}},
		{"POST", "/users", user("app")},
		{"POST", "/users/alpha_wp/password", map[string]string{"password": databasePassword}},
		{"POST", "/alpha_wp/delete", map[string]string{"confirm_name": "alpha_wp"}},
		{"POST", "/users/alpha_wp/delete", map[string]string{"confirm_name": "alpha_wp"}},
	}
	for _, op := range []string{"create-database", "create-user", "set-password", "drop-database", "drop-user", "list"} {
		db.fail[op] = func(string) error { return dbhost.ErrUnavailable }
	}
	for _, tc := range requests {
		w := websiteRequest(f.handler, tc.method, alphaDatabases+tc.path, tc.body, cookie, csrf)
		if w.Code != 503 || problemDetail(t, w) != databaseServerDown || strings.Contains(w.Body.String(), databasePassword) {
			t.Fatalf("database server down, %s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	db.fail = map[string]func(string) error{}
	calls := len(db.calls)

	// 503 when the broker does not answer: without it there is no owner.
	broker.mu.Lock()
	broker.listErr = hostaccounts.ErrUnavailable
	broker.mu.Unlock()
	for _, tc := range requests {
		w := websiteRequest(f.handler, tc.method, alphaDatabases+tc.path, tc.body, cookie, csrf)
		if w.Code != 503 || problemDetail(t, w) != databasesNoBroker {
			t.Fatalf("broker down, %s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	// 503 when the database service or the account service is not set up.
	for name, options := range map[string]Options{
		"no database service": {Operator: f.manager, Accounts: broker},
		"no account service":  {Operator: f.manager, Databases: db},
	} {
		h := New(Options{Operator: options.Operator, Accounts: options.Accounts, Databases: options.Databases, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
		for _, tc := range requests {
			w := websiteRequest(h, tc.method, alphaDatabases+tc.path, tc.body, cookie, csrf)
			if w.Code != 503 || problemDetail(t, w) != databasesNotSetUp {
				t.Fatalf("%s, %s %s: %d %s", name, tc.method, tc.path, w.Code, w.Body.String())
			}
		}
	}
	if len(db.calls) != calls {
		t.Fatalf("a request without an owner reached the database service: %q", db.calls[calls:])
	}
}

// sqlRecorder is a dbhost.Runner: it keeps each statement and answers one
// row, which is all the service's probe needs.
type sqlRecorder struct {
	mu         sync.Mutex
	statements []string
}

func (r *sqlRecorder) Run(_ context.Context, sql string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sql != "SELECT VERSION()" {
		r.statements = append(r.statements, sql)
	}
	return []string{"10.11.9-MariaDB"}, nil
}

func (r *sqlRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.statements
	r.statements = nil
	return out
}

// The page's routes over dbhost's own service and registry, with only the
// mysql client replaced: the statements are the ones MariaDB would run.
func TestSiteDatabasesOverTheRegistry(t *testing.T) {
	f, _, broker := databasesFixture(t)
	registry, err := dbhost.OpenRegistry(filepath.Join(realTempDir(t), "dbmap.json"))
	if err != nil {
		t.Fatal(err)
	}
	sql := &sqlRecorder{}
	service := &dbhost.LocalService{Run: sql, Registry: registry}
	ctx := context.Background()
	if err = errors.Join(service.CreateDatabaseStrict(ctx, "beta", "beta_wp"), service.CreateUserStrict(ctx, "beta", "beta_wp", "beta's own passphrase"), service.SetPrivileges(ctx, "beta", "beta_wp", "beta_wp", []string{"ALL PRIVILEGES"})); err != nil {
		t.Fatal(err)
	}
	sql.take()
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Databases: service, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	cookie, csrf := websiteSignIn(t, f)
	post := func(status int, path string, body map[string]string, want ...string) {
		t.Helper()
		w := websiteRequest(f.handler, "POST", alphaDatabases+path, body, cookie, csrf)
		if got := sql.take(); w.Code != status || !slices.Equal(got, want) || strings.Contains(w.Body.String(), databasePassword) {
			t.Fatalf("POST %s: %d %s\nstatements %q\nwant       %q", path, w.Code, w.Body.String(), got, want)
		}
	}
	const utf8mb4 = " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
	user := map[string]string{"name_suffix": "app", "password": databasePassword, "database": "alpha_shop"}
	post(201, "", map[string]string{"name_suffix": "shop"}, "CREATE DATABASE `alpha_shop`"+utf8mb4)
	post(409, "", map[string]string{"name_suffix": "shop"})
	post(201, "/users", user,
		"CREATE USER 'alpha_app'@'localhost' IDENTIFIED BY '"+databasePassword+"'",
		"REVOKE ALL PRIVILEGES ON `alpha_shop`.* FROM 'alpha_app'@'localhost'",
		"GRANT ALL PRIVILEGES ON `alpha_shop`.* TO 'alpha_app'@'localhost'")
	post(409, "/users", user)
	post(200, "/users/alpha_app/password", map[string]string{"password": "it's a new pass\\phrase"}, `ALTER USER 'alpha_app'@'localhost' IDENTIFIED BY 'it\'s a new pass\\phrase'`)
	if got := databaseList(t, f.handler, alphaID, cookie); len(got.Databases) != 1 || got.Databases[0].Name != "alpha_shop" || !slices.Equal(got.Databases[0].Users, []string{"alpha_app"}) || len(got.Users) != 1 || got.Users[0].Name != "alpha_app" {
		t.Fatalf("alpha's list %+v", got)
	}

	// Beta's database and user are out of alpha's reach: no statement runs.
	post(404, "/beta_wp/delete", map[string]string{"confirm_name": "beta_wp"})
	post(404, "/users/beta_wp/delete", map[string]string{"confirm_name": "beta_wp"})
	post(404, "/users/beta_wp/password", map[string]string{"password": databasePassword})
	post(404, "/users", map[string]string{"name_suffix": "spy", "password": databasePassword, "database": "beta_wp"})

	// Deleting the database runs one statement, and its user stays.
	post(200, "/alpha_shop/delete", map[string]string{"confirm_name": "alpha_shop"}, "DROP DATABASE IF EXISTS `alpha_shop`")
	if got := databaseList(t, f.handler, alphaID, cookie); len(got.Databases) != 0 || len(got.Users) != 1 {
		t.Fatalf("alpha's list after deleting the database %+v", got)
	}
	post(200, "/users/alpha_app/delete", map[string]string{"confirm_name": "alpha_app"}, "DROP USER IF EXISTS 'alpha_app'@'localhost'")
	if got := databaseList(t, f.handler, betaID, cookie); len(got.Databases) != 1 || got.Databases[0].Name != "beta_wp" || !slices.Equal(got.Databases[0].Users, []string{"beta_wp"}) || len(got.Users) != 1 {
		t.Fatalf("beta's list %+v", got)
	}
}
