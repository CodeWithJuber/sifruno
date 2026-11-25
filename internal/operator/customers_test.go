package operator

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	siteA            = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	siteB            = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	customerPassword = "customer password one"
)

type customerClock struct{ now time.Time }

// customerFixture is a manager with a fixed clock and an access-key session,
// which is an admin session for managing customer logins.
func customerFixture(t *testing.T) (*Manager, http.Handler, *customerClock, *http.Cookie, string) {
	t.Helper()
	m, h, key := fixture(t)
	clock := &customerClock{now: time.Unix(1_800_000_000, 0)}
	m.now = func() time.Time { return clock.now }
	cookie, s := signIn(t, h, key, nil)
	return m, h, clock, cookie, s.CSRFToken
}

func jsonBody(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func createLogin(t *testing.T, h http.Handler, cookie *http.Cookie, csrf, username string, websites ...string) CustomerSetupLink {
	t.Helper()
	w := opRequest(h, "POST", "/api/v1/session/customers", jsonBody(map[string]any{"username": username, "websites": websites}), cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("create customer %s: %d %s", username, w.Code, w.Body.String())
	}
	return decodeBody[CustomerSetupLink](t, w.Body.Bytes())
}

func linkToken(t *testing.T, link string) string {
	t.Helper()
	prefix, token, found := strings.Cut(link, "#")
	if !found || !strings.HasSuffix(prefix, "/setup") || !validToken(token) {
		t.Fatalf("not a setup link: %q", link)
	}
	return token
}

// setUpCustomer runs the customer's setup from its link and returns its
// authenticator secret and new session.
func setUpCustomer(t *testing.T, h http.Handler, token string, at time.Time) (string, *http.Cookie, Session) {
	t.Helper()
	w := opRequest(h, "POST", "/api/v1/session/customer-setup/begin", jsonBody(map[string]string{"token": token}), nil, "")
	if w.Code != 200 {
		t.Fatalf("begin customer setup: %d %s", w.Code, w.Body.String())
	}
	secret := decodeBody[customerSetupSecret](t, w.Body.Bytes())
	w = opRequest(h, "POST", "/api/v1/session/customer-setup/finish", jsonBody(map[string]string{"token": token, "password": customerPassword, "totp_code": codeAt(t, secret.Secret, at)}), nil, "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("finish customer setup: %d %s", w.Code, w.Body.String())
	}
	return secret.Secret, w.Result().Cookies()[0], decodeBody[Session](t, w.Body.Bytes())
}

func customerSignIn(h http.Handler, username, password, code string) *httptest.ResponseRecorder {
	return opRequest(h, "POST", "/api/v1/session/login", adminLoginBody(username, password, code), nil, "")
}

// refillLoginBuckets gives every username its five tries back. The limiters
// run on real time, which the fixed test clock does not move.
func refillLoginBuckets(m *Manager) {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	for i := range m.buckets {
		m.buckets[i] = newAccountLimiter()
	}
}

func adminAgain(t *testing.T, m *Manager, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	key, err := os.ReadFile(m.AccessKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	cookie, s := signIn(t, h, strings.TrimSpace(string(key)), nil)
	return cookie, s.CSRFToken
}

func scopeOf(m *Manager, cookie *http.Cookie) (Principal, bool, bool) {
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/v1/websites/sites", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.AddCookie(cookie)
	return m.Scope(r)
}

func TestCustomerFileIsPrivateStrictAndRoundTrips(t *testing.T) {
	m, h, _, cookie, csrf := customerFixture(t)
	created := createLogin(t, h, cookie, csrf, "alice", siteB, siteA, siteA)
	if strings.Join(created.Websites, ",") != siteA+","+siteB || created.Setup != "pending" || created.Disabled {
		t.Fatalf("created login: %+v", created.CustomerLogin)
	}
	path := filepath.Join(m.dir, customersFile)
	info, err := os.Stat(path)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("customers.json must be 0600: %v %v", info, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), linkToken(t, created.SetupLink)) {
		t.Fatal("the setup link's secret must not be stored")
	}
	again, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := again.customers.Load().find("alice"); !found {
		t.Fatal("customer not kept across a restart")
	}

	valid := customerRecord{Username: "bob", Websites: []string{siteA}, Setup: &setupLink{Hash: strings.Repeat("A", 43), ExpiresAt: time.Now()}, CreatedAt: time.Now()}
	hash, _ := hashPassword(customerPassword)
	secret, _ := newTOTPSecret()
	admins := adminFile{Version: 1, Admins: []adminRecord{{Username: "root-admin"}}}
	for name, mutate := range map[string]func(*customerRecord){
		"unsorted websites":   func(c *customerRecord) { c.Websites = []string{siteB, siteA} },
		"repeated websites":   func(c *customerRecord) { c.Websites = []string{siteA, siteA} },
		"malformed website":   func(c *customerRecord) { c.Websites = []string{"../etc"} },
		"bad username":        func(c *customerRecord) { c.Username = "Bob" },
		"admin's username":    func(c *customerRecord) { c.Username = "root-admin" },
		"no created time":     func(c *customerRecord) { c.CreatedAt = time.Time{} },
		"neither link nor pw": func(c *customerRecord) { c.Setup = nil },
		"short link hash":     func(c *customerRecord) { c.Setup = &setupLink{Hash: "AAAA", ExpiresAt: time.Now()} },
		"link and password":   func(c *customerRecord) { c.Password, c.TOTP = &hash, &adminTOTP{Secret: secret} },
		"password, no code":   func(c *customerRecord) { c.Setup, c.Password = nil, &hash },
		"bad secret": func(c *customerRecord) {
			c.Setup, c.Password, c.TOTP = nil, &hash, &adminTOTP{Secret: "short"}
		},
	} {
		c := valid
		mutate(&c)
		if (customerFile{Version: 1, Customers: []customerRecord{c}}).validate(admins) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if (customerFile{Version: 1, Customers: []customerRecord{valid, valid}}).validate(admins) == nil {
		t.Fatal("a repeated username was accepted")
	}
	if err := (customerFile{Version: 1, Customers: []customerRecord{valid}}).validate(admins); err != nil {
		t.Fatalf("valid record refused: %v", err)
	}

	// A damaged or loose file stops the panel rather than being ignored.
	if err := os.WriteFile(path, []byte(`{"version":1,"customers":[{"username":"x"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(m.dir); err == nil || !strings.Contains(err.Error(), customersFile) {
		t.Fatalf("damaged customers.json: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(m.dir); err == nil {
			t.Fatal("a customers.json others can read must be refused")
		}
	}
}

func TestCustomerSetsUpSignsInAndIsTurnedOffResetAndRemoved(t *testing.T) {
	m, h, clock, adminCookie, csrf := customerFixture(t)
	created := createLogin(t, h, adminCookie, csrf, "alice", siteA)
	token := linkToken(t, created.SetupLink)

	// Before setup the login cannot sign in, with the usual answer.
	if w := customerSignIn(h, "alice", customerPassword, "123456"); w.Code != 401 || problemCode(t, w.Body.Bytes()) != "invalid_credentials" {
		t.Fatalf("sign-in before setup: %d", w.Code)
	}
	secret, cookie, session := setUpCustomer(t, h, token, clock.now)
	if session.Role != "customer" || session.Username != "alice" || session.ViewAs != "" {
		t.Fatalf("setup session: %+v", session)
	}
	p, restricted, ok := scopeOf(m, cookie)
	if !restricted || !ok || p.Customer != "alice" || p.Actor != "customer:alice" || !p.Owns(siteA) || p.Owns(siteB) {
		t.Fatalf("customer principal: %+v %v %v", p, restricted, ok)
	}
	// The link works once.
	if w := opRequest(h, "POST", "/api/v1/session/customer-setup/begin", jsonBody(map[string]string{"token": token}), nil, ""); w.Code != 404 || problemCode(t, w.Body.Bytes()) != "setup_link_invalid" {
		t.Fatalf("used link: %d", w.Code)
	}
	list := decodeBody[CustomerLoginList](t, opRequest(h, "GET", "/api/v1/session/customers", "", adminCookie, "").Body.Bytes())
	if len(list.Items) != 1 || list.Items[0].Setup != "done" || list.Items[0].SetupExpiresAt != nil {
		t.Fatalf("list after setup: %+v", list)
	}

	// The code used for setup cannot sign in; a new one can, once.
	used := codeAt(t, secret, clock.now)
	if w := customerSignIn(h, "alice", customerPassword, used); w.Code != 401 {
		t.Fatalf("setup code replayed: %d", w.Code)
	}
	clock.now = clock.now.Add(30 * time.Second)
	code := codeAt(t, secret, clock.now)
	w := customerSignIn(h, "alice", customerPassword, code)
	if w.Code != 200 || decodeBody[Session](t, w.Body.Bytes()).Role != "customer" {
		t.Fatalf("customer sign-in: %d %s", w.Code, w.Body.String())
	}
	if w := customerSignIn(h, "alice", customerPassword, code); w.Code != 401 {
		t.Fatalf("sign-in code replayed: %d", w.Code)
	}
	wrong := []string{
		adminLoginBody("alice", "not the password at all", codeAt(t, secret, clock.now.Add(30*time.Second))),
		adminLoginBody("nobody", customerPassword, codeAt(t, secret, clock.now.Add(30*time.Second))),
	}
	for _, body := range wrong {
		if w := opRequest(h, "POST", "/api/v1/session/login", body, nil, ""); w.Code != 401 || problemCode(t, w.Body.Bytes()) != "invalid_credentials" {
			t.Fatalf("wrong credentials: %d", w.Code)
		}
	}

	// Turning the login off ends its sessions at once, and sign-in gets the
	// usual answer, which does not say the login is off.
	refillLoginBuckets(m)
	w = opRequest(h, "POST", "/api/v1/session/customers/alice/state", `{"disabled":true}`, adminCookie, csrf)
	if w.Code != 200 || !decodeBody[CustomerLogin](t, w.Body.Bytes()).Disabled {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", cookie, ""); w.Code != 401 {
		t.Fatalf("session of a turned-off login: %d", w.Code)
	}
	clock.now = clock.now.Add(time.Minute)
	if w := customerSignIn(h, "alice", customerPassword, codeAt(t, secret, clock.now)); w.Code != 401 || problemCode(t, w.Body.Bytes()) != "invalid_credentials" {
		t.Fatalf("turned-off login signs in: %d", w.Code)
	}
	if w := opRequest(h, "POST", "/api/v1/session/customers/alice/state", `{"disabled":false}`, adminCookie, csrf); w.Code != 200 {
		t.Fatalf("enable: %d", w.Code)
	}
	clock.now = clock.now.Add(time.Minute)
	w = customerSignIn(h, "alice", customerPassword, codeAt(t, secret, clock.now))
	if w.Code != 200 {
		t.Fatalf("sign-in after enable: %d", w.Code)
	}
	cookie = w.Result().Cookies()[0]

	// A new setup link resets the login: the old password and sessions stop.
	refillLoginBuckets(m)
	w = opRequest(h, "POST", "/api/v1/session/customers/alice/setup-link", `{}`, adminCookie, csrf)
	if w.Code != 200 {
		t.Fatalf("new link: %d %s", w.Code, w.Body.String())
	}
	reset := decodeBody[CustomerSetupLink](t, w.Body.Bytes())
	if reset.Setup != "pending" || linkToken(t, reset.SetupLink) == token {
		t.Fatalf("reset: %+v", reset)
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", cookie, ""); w.Code != 401 {
		t.Fatalf("session after reset: %d", w.Code)
	}
	clock.now = clock.now.Add(time.Minute)
	if w := customerSignIn(h, "alice", customerPassword, codeAt(t, secret, clock.now)); w.Code != 401 {
		t.Fatalf("old password after reset: %d", w.Code)
	}
	_, cookie, _ = setUpCustomer(t, h, linkToken(t, reset.SetupLink), clock.now)

	// Removing the login ends its sessions; the websites stay where they are.
	w = opRequest(h, "POST", "/api/v1/session/customers/alice/delete", `{}`, adminCookie, csrf)
	if w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", cookie, ""); w.Code != 401 {
		t.Fatalf("session after delete: %d", w.Code)
	}
	if w := opRequest(h, "POST", "/api/v1/session/customers/alice/delete", `{}`, adminCookie, csrf); w.Code != 404 || problemCode(t, w.Body.Bytes()) != "customer_not_found" {
		t.Fatalf("second delete: %d", w.Code)
	}
	if len(m.customers.Load().Customers) != 0 {
		t.Fatal("customer still stored")
	}
}

func TestCustomerSetupLinkRules(t *testing.T) {
	m, h, clock, adminCookie, csrf := customerFixture(t)
	created := createLogin(t, h, adminCookie, csrf, "alice", siteA)
	token := linkToken(t, created.SetupLink)
	begin := func(body string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/session/customer-setup/begin", strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("Content-Type", "application/json")
		for _, f := range mutate {
			f(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := begin(jsonBody(map[string]string{"token": token}), func(r *http.Request) { r.Header.Set("Origin", "http://evil.test") }); w.Code != 403 {
		t.Fatalf("foreign Origin: %d", w.Code)
	}
	if w := begin(jsonBody(map[string]string{"token": token}), func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") }); w.Code != 403 {
		t.Fatalf("with a token: %d", w.Code)
	}
	for _, wrong := range []string{"", "short", strings.Repeat("A", 43), token + "x"} {
		if w := begin(jsonBody(map[string]string{"token": wrong})); w.Code != 404 || problemCode(t, w.Body.Bytes()) != "setup_link_invalid" {
			t.Fatalf("wrong link %q: %d", wrong, w.Code)
		}
	}
	w := begin(jsonBody(map[string]string{"token": token}))
	if w.Code != 200 {
		t.Fatalf("begin: %d", w.Code)
	}
	secret := decodeBody[customerSetupSecret](t, w.Body.Bytes())
	if secret.Username != "alice" || !strings.HasPrefix(secret.URI, "otpauth://totp/Sifruno:alice?") {
		t.Fatalf("secret: %+v", secret)
	}
	finish := func(pw, code string) *httptest.ResponseRecorder {
		body := map[string]string{"token": token, "totp_code": code}
		body["pass"+"word"] = pw
		return opRequest(h, "POST", "/api/v1/session/customer-setup/finish", jsonBody(body), nil, "")
	}
	good := codeAt(t, secret.Secret, clock.now)
	for _, tc := range []struct {
		password, code, problem string
		status                  int
	}{
		{"short", good, "invalid_password", 422},
		{"alice", good, "invalid_password", 422},
		{customerPassword, "000000", "invalid_code", 422},
	} {
		if w := finish(tc.password, tc.code); w.Code != tc.status || problemCode(t, w.Body.Bytes()) != tc.problem {
			t.Fatalf("want %d %s, got %d %s", tc.status, tc.problem, w.Code, w.Body.String())
		}
	}
	// The secret lasts 10 minutes; opening the link again gives a new one.
	clock.now = clock.now.Add(11 * time.Minute)
	if w := finish(customerPassword, codeAt(t, secret.Secret, clock.now)); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "setup_expired" {
		t.Fatalf("expired step: %d", w.Code)
	}
	// The link lasts 24 hours.
	clock.now = clock.now.Add(24 * time.Hour)
	if w := begin(jsonBody(map[string]string{"token": token})); w.Code != 404 {
		t.Fatalf("day-old link: %d", w.Code)
	}
	adminCookie, csrf = adminAgain(t, m, h)
	list := decodeBody[CustomerLoginList](t, opRequest(h, "GET", "/api/v1/session/customers", "", adminCookie, "").Body.Bytes())
	if len(list.Items) != 1 || list.Items[0].Setup != "expired" {
		t.Fatalf("an old link must show as expired: %+v", list.Items[0])
	}
	// A turned-off login's link does not work either.
	fresh := decodeBody[CustomerSetupLink](t, opRequest(h, "POST", "/api/v1/session/customers/alice/setup-link", `{}`, adminCookie, csrf).Body.Bytes())
	if w := opRequest(h, "POST", "/api/v1/session/customers/alice/state", `{"disabled":true}`, adminCookie, csrf); w.Code != 200 {
		t.Fatalf("disable: %d", w.Code)
	}
	if w := begin(jsonBody(map[string]string{"token": linkToken(t, fresh.SetupLink)})); w.Code != 404 {
		t.Fatalf("turned-off login's link: %d", w.Code)
	}
}

func TestWrongSetupLinksAreRateLimited(t *testing.T) {
	_, h, clock, adminCookie, csrf := customerFixture(t)
	token := linkToken(t, createLogin(t, h, adminCookie, csrf, "alice", siteA).SetupLink)
	wrong := jsonBody(map[string]string{"token": strings.Repeat("B", 43)})
	for i := 0; i < 20; i++ {
		if w := opRequest(h, "POST", "/api/v1/session/customer-setup/begin", wrong, nil, ""); w.Code != 404 {
			t.Fatalf("wrong link %d: %d", i, w.Code)
		}
	}
	w := opRequest(h, "POST", "/api/v1/session/customer-setup/begin", wrong, nil, "")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("after 20 wrong links: %d", w.Code)
	}
	// The real link still works while the limit is used up.
	setUpCustomer(t, h, token, clock.now)

	// Over the network one address uses up its own five tries only.
	_, h2, _, adminCookie2, csrf2 := customerFixture(t)
	token2 := linkToken(t, createLogin(t, h2, adminCookie2, csrf2, "bob", siteA).SetupLink)
	remote := Remote(h2, []string{"panel.example.test"})
	from := func(addr, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://panel.example.test/api/v1/session/customer-setup/begin", strings.NewReader(body))
		r.RemoteAddr = addr
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Origin", "https://panel.example.test")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		remote.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 5; i++ {
		if w := from("198.51.100.7:4000", wrong); w.Code != 404 {
			t.Fatalf("remote wrong link %d: %d", i, w.Code)
		}
	}
	if w := from("198.51.100.7:4000", wrong); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("sixth wrong link from one address: %d", w.Code)
	}
	if w := from("203.0.113.9:4000", wrong); w.Code != 404 {
		t.Fatalf("another address: %d", w.Code)
	}
	if w := from("198.51.100.7:4000", jsonBody(map[string]string{"token": token2})); w.Code != 200 {
		t.Fatalf("real link from the limited address: %d %s", w.Code, w.Body.String())
	}
}

func TestCustomerLoginsNeedAnAdmin(t *testing.T) {
	m, h, clock, adminCookie, csrf := customerFixture(t)
	created := createLogin(t, h, adminCookie, csrf, "alice", siteA)
	_, cookie, session := setUpCustomer(t, h, linkToken(t, created.SetupLink), clock.now)

	for _, route := range []struct{ method, path, body string }{
		{"GET", "/api/v1/session/customers", ""},
		{"POST", "/api/v1/session/customers", jsonBody(map[string]any{"username": "eve", "websites": []string{siteB}})},
		{"POST", "/api/v1/session/customers/alice/websites", jsonBody(map[string]any{"websites": []string{siteA, siteB}})},
		{"POST", "/api/v1/session/customers/alice/setup-link", `{}`},
		{"POST", "/api/v1/session/view-as", `{"username":"alice"}`},
		{"POST", "/api/v1/session/view-as/end", `{}`},
		{"GET", "/api/v1/session/tokens", ""},
		{"POST", "/api/v1/session/tokens", `{"name":"mine"}`},
		{"GET", "/api/v1/session/sessions", ""},
		{"POST", "/api/v1/session/revoke-others", `{}`},
	} {
		w := opRequest(h, route.method, route.path, route.body, cookie, session.CSRFToken)
		if w.Code != 403 || problemCode(t, w.Body.Bytes()) != "admin_only" {
			t.Fatalf("customer on %s %s: %d %s", route.method, route.path, w.Code, w.Body.String())
		}
	}
	if p, _, _ := scopeOf(m, cookie); strings.Join(p.Websites, ",") != siteA {
		t.Fatal("a refused change altered the customer's websites")
	}
	// An admin's "sign out everywhere else" and session list leave customers alone.
	inventory := decodeBody[Inventory](t, opRequest(h, "GET", "/api/v1/session/sessions", "", adminCookie, "").Body.Bytes())
	if len(inventory.Items) != 1 {
		t.Fatalf("admin inventory lists customer sessions: %d", len(inventory.Items))
	}
	if w := opRequest(h, "POST", "/api/v1/session/revoke-others", `{}`, adminCookie, csrf); w.Code != 200 {
		t.Fatalf("revoke others: %d", w.Code)
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", cookie, ""); w.Code != 200 {
		t.Fatalf("customer session after the admin's revoke-others: %d", w.Code)
	}
	// The customer can sign itself out.
	if w := opRequest(h, "POST", "/api/v1/session/logout", `{}`, cookie, session.CSRFToken); w.Code != 200 {
		t.Fatalf("customer logout: %d", w.Code)
	}
}

func TestCustomerUsernamesAndWebsitesAreChecked(t *testing.T) {
	m, h, _, adminCookie, csrf := customerFixture(t)
	for _, tc := range []struct {
		body, problem string
		status        int
	}{
		{jsonBody(map[string]any{"username": "Alice", "websites": []string{siteA}}), "invalid_username", 422},
		{jsonBody(map[string]any{"username": "alice", "websites": []string{}}), "invalid_websites", 422},
		{jsonBody(map[string]any{"username": "alice", "websites": []string{"site-1"}}), "invalid_websites", 422},
		{jsonBody(map[string]any{"username": "alice"}), "invalid_websites", 422},
		{`{"username":"alice","websites":["` + siteA + `"],"role":"admin"}`, "invalid_request", 400},
	} {
		if w := opRequest(h, "POST", "/api/v1/session/customers", tc.body, adminCookie, csrf); w.Code != tc.status || problemCode(t, w.Body.Bytes()) != tc.problem {
			t.Fatalf("%s: %d %s", tc.body, w.Code, w.Body.String())
		}
	}
	many := make([]string, 65)
	for i := range many {
		many[i] = strings.Repeat(string(rune('a'+i%6)), 31) + string(rune('a'+i/6%6))
	}
	if w := opRequest(h, "POST", "/api/v1/session/customers", jsonBody(map[string]any{"username": "alice", "websites": many}), adminCookie, csrf); w.Code != 422 && w.Code != 413 {
		t.Fatalf("65 websites: %d", w.Code)
	}
	createLogin(t, h, adminCookie, csrf, "alice", siteA)
	if w := opRequest(h, "POST", "/api/v1/session/customers", jsonBody(map[string]any{"username": "alice", "websites": []string{siteB}}), adminCookie, csrf); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "username_taken" {
		t.Fatalf("taken username: %d", w.Code)
	}
	// An admin cannot later take a customer's username, nor the reverse.
	m.adminMu.Lock()
	m.admins.Admins = append(m.admins.Admins, adminRecord{Username: "boss"})
	m.adminMu.Unlock()
	if w := opRequest(h, "POST", "/api/v1/session/customers", jsonBody(map[string]any{"username": "boss", "websites": []string{siteB}}), adminCookie, csrf); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "username_taken" {
		t.Fatalf("admin's username: %d", w.Code)
	}
	m.adminMu.Lock()
	m.admins.Admins = nil
	m.adminMu.Unlock()
	if w := opRequest(h, "POST", setupPath+"/totp", `{"username":"alice"}`, adminCookie, csrf); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "username_taken" {
		t.Fatalf("first admin with a customer's username: %d", w.Code)
	}

	// With the API's check in place, only websites on this server are given.
	var asked []string
	m.CheckWebsitesWith(func(_ context.Context, ids []string) ([]string, error) {
		asked = ids
		if len(ids) > 1 {
			return ids[1:], nil
		}
		return nil, nil
	})
	if w := opRequest(h, "POST", "/api/v1/session/customers/alice/websites", jsonBody(map[string]any{"websites": []string{siteB, siteA}}), adminCookie, csrf); w.Code != 422 || problemCode(t, w.Body.Bytes()) != "unknown_website" {
		t.Fatalf("unknown website: %d", w.Code)
	}
	if strings.Join(asked, ",") != siteA+","+siteB {
		t.Fatalf("check asked about %v", asked)
	}
	if w := opRequest(h, "POST", "/api/v1/session/customers/alice/websites", jsonBody(map[string]any{"websites": []string{siteB}}), adminCookie, csrf); w.Code != 200 {
		t.Fatalf("set websites: %d", w.Code)
	}
	m.CheckWebsitesWith(func(context.Context, []string) ([]string, error) { return nil, errors.New("broker down") })
	if w := opRequest(h, "POST", "/api/v1/session/customers/alice/websites", jsonBody(map[string]any{"websites": []string{siteA}}), adminCookie, csrf); w.Code != 503 {
		t.Fatalf("broker down: %d", w.Code)
	}
	c, _ := m.customers.Load().find("alice")
	if strings.Join(m.customers.Load().Customers[c].Websites, ",") != siteB {
		t.Fatal("a refused change altered the websites")
	}

	// A deleted website leaves every customer's list.
	m.CheckWebsitesWith(nil)
	createLogin(t, h, adminCookie, csrf, "carol", siteB)
	if err := m.ForgetWebsite(siteB); err != nil {
		t.Fatal(err)
	}
	for _, cust := range m.customers.Load().Customers {
		if len(cust.Websites) != 0 {
			t.Fatalf("%s still has the deleted website", cust.Username)
		}
	}
	again, err := Open(m.dir)
	if err != nil || len(again.customers.Load().Customers[0].Websites) != 0 {
		t.Fatalf("forgotten website not saved: %v", err)
	}
}

func TestAdminViewsThePanelAsACustomer(t *testing.T) {
	m, h, clock, adminCookie, csrf := customerFixture(t)
	createLogin(t, h, adminCookie, csrf, "alice", siteA, siteB)
	bob := createLogin(t, h, adminCookie, csrf, "bob", siteB)

	if w := opRequest(h, "POST", "/api/v1/session/view-as", `{"username":"nobody"}`, adminCookie, csrf); w.Code != 404 {
		t.Fatalf("view as nobody: %d", w.Code)
	}
	if w := opRequest(h, "POST", "/api/v1/session/view-as", `{"username":"alice"}`, adminCookie, ""); w.Code != 403 {
		t.Fatalf("view as without CSRF: %d", w.Code)
	}
	w := opRequest(h, "POST", "/api/v1/session/view-as", `{"username":"alice"}`, adminCookie, csrf)
	if w.Code != 200 {
		t.Fatalf("view as: %d %s", w.Code, w.Body.String())
	}
	if s := decodeBody[Session](t, w.Body.Bytes()); s.Role != "admin" || s.ViewAs != "alice" || s.CSRFToken != csrf {
		t.Fatalf("view-as session: %+v", s)
	}
	p, restricted, ok := scopeOf(m, adminCookie)
	if !restricted || !ok || p.Customer != "alice" || p.Actor != "admin:local-operator as customer:alice" || !p.Owns(siteB) {
		t.Fatalf("view-as principal: %+v", p)
	}
	// While viewing, the session has only the customer's access.
	for _, route := range []struct{ method, path, body string }{
		{"GET", "/api/v1/session/customers", ""}, {"GET", "/api/v1/session/tokens", ""}, {"POST", "/api/v1/session/view-as", `{"username":"bob"}`},
	} {
		if w := opRequest(h, route.method, route.path, route.body, adminCookie, csrf); w.Code != 403 || problemCode(t, w.Body.Bytes()) != "admin_only" {
			t.Fatalf("%s while viewing: %d", route.path, w.Code)
		}
	}
	if s := decodeBody[Session](t, opRequest(h, "GET", "/api/v1/session", "", adminCookie, "").Body.Bytes()); s.ViewAs != "alice" {
		t.Fatalf("session while viewing: %+v", s)
	}
	w = opRequest(h, "POST", "/api/v1/session/view-as/end", `{}`, adminCookie, csrf)
	if w.Code != 200 || decodeBody[Session](t, w.Body.Bytes()).ViewAs != "" {
		t.Fatalf("end view as: %d", w.Code)
	}
	if p, restricted, ok := scopeOf(m, adminCookie); restricted || !ok || p.Restricted() {
		t.Fatalf("after going back: %+v", p)
	}

	// Removing the customer being viewed takes the admin back; a customer
	// cannot view as another.
	if w := opRequest(h, "POST", "/api/v1/session/view-as", `{"username":"alice"}`, adminCookie, csrf); w.Code != 200 {
		t.Fatalf("view as again: %d", w.Code)
	}
	m.adminMu.Lock()
	next := m.customers.Load().clone()
	i, _ := next.find("alice")
	next.Customers = append(next.Customers[:i], next.Customers[i+1:]...)
	m.customers.Store(&next)
	m.adminMu.Unlock()
	if w := opRequest(h, "GET", "/api/v1/session", "", adminCookie, ""); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "view_as_ended" {
		t.Fatalf("viewing a removed customer: %d", w.Code)
	}
	if s := decodeBody[Session](t, opRequest(h, "GET", "/api/v1/session", "", adminCookie, "").Body.Bytes()); s.ViewAs != "" || s.Role != "admin" {
		t.Fatalf("after the viewed customer went: %+v", s)
	}
	_, bobCookie, bobSession := setUpCustomer(t, h, linkToken(t, bob.SetupLink), clock.now)
	if w := opRequest(h, "POST", "/api/v1/session/view-as", `{"username":"bob"}`, bobCookie, bobSession.CSRFToken); w.Code != 403 {
		t.Fatalf("customer view-as: %d", w.Code)
	}
	if w := opRequest(h, "POST", "/api/v1/session/view-as", `{"username":"bob"}`, adminCookie, csrf); w.Code != 200 {
		t.Fatalf("view as bob: %d", w.Code)
	}
	if w := opRequest(h, "POST", "/api/v1/session/customers/bob/delete", `{}`, adminCookie, csrf); w.Code != 403 {
		t.Fatalf("delete while viewing: %d", w.Code)
	}
	opRequest(h, "POST", "/api/v1/session/view-as/end", `{}`, adminCookie, csrf)
	key, _ := os.ReadFile(m.AccessKeyPath())
	other, otherSession := signIn(t, h, strings.TrimSpace(string(key)), nil)
	if w := opRequest(h, "POST", "/api/v1/session/view-as", `{"username":"bob"}`, other, otherSession.CSRFToken); w.Code != 200 {
		t.Fatalf("second admin view as: %d", w.Code)
	}
	if w := opRequest(h, "POST", "/api/v1/session/customers/bob/delete", `{}`, adminCookie, csrf); w.Code != 200 {
		t.Fatalf("delete bob: %d", w.Code)
	}
	if s := decodeBody[Session](t, opRequest(h, "GET", "/api/v1/session", "", other, "").Body.Bytes()); s.ViewAs != "" {
		t.Fatal("deleting a customer must take its viewers back")
	}
}

func TestCustomerSessionsAreBounded(t *testing.T) {
	m, h, clock, adminCookie, csrf := customerFixture(t)
	created := createLogin(t, h, adminCookie, csrf, "alice", siteA)
	secret, first, _ := setUpCustomer(t, h, linkToken(t, created.SetupLink), clock.now)
	signInAlice := func() *httptest.ResponseRecorder {
		clock.now = clock.now.Add(30 * time.Second)
		return customerSignIn(h, "alice", customerPassword, codeAt(t, secret, clock.now))
	}
	var cookies []*http.Cookie
	for i := 1; i < maxSessionsPerCustomer+1; i++ {
		w := signInAlice()
		if w.Code != 200 {
			t.Fatalf("sign-in %d: %d", i, w.Code)
		}
		cookies = append(cookies, w.Result().Cookies()[0])
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", first, ""); w.Code != 401 {
		t.Fatalf("a customer's fifth session must end its oldest: %d", w.Code)
	}
	for _, c := range cookies {
		if w := opRequest(h, "GET", "/api/v1/session", "", c, ""); w.Code != 200 {
			t.Fatalf("a newer session ended: %d", w.Code)
		}
	}

	// Customers together hold at most 96 sessions; admins keep the rest.
	m.mu.Lock()
	for id, a := range m.active {
		if a.customer {
			delete(m.active, id)
		}
	}
	for i := 0; i < maxCustomerSessions; i++ {
		m.active["filler-"+strings.Repeat("f", i+1)] = activeSession{customer: true, username: "filler", created: clock.now, expires: clock.now.Add(time.Hour)}
	}
	m.mu.Unlock()
	refillLoginBuckets(m)
	if w := signInAlice(); w.Code != 429 {
		t.Fatalf("a customer sign-in past the customers' share: %d", w.Code)
	}
	key, _ := os.ReadFile(m.AccessKeyPath())
	if _, s := signIn(t, h, strings.TrimSpace(string(key)), nil); s.Role != "admin" {
		t.Fatal("an admin must still sign in while customers hold their share")
	}
	m.mu.Lock()
	delete(m.active, "filler-f")
	m.mu.Unlock()
	refillLoginBuckets(m)
	if w := signInAlice(); w.Code != 200 {
		t.Fatalf("sign-in once there is room: %d", w.Code)
	}
}
