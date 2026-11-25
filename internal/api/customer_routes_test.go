package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"sifruno/internal/operator"
)

const customerTestPassword = "customer password one"

// customerSession gives a customer a login for the websites through the
// panel's routes, as an admin does, and finishes its setup from the link as
// the customer does. h is where the customer's requests go (loopback or the
// HTTPS listener); request sends them there.
func customerSession(t *testing.T, f siteFixture, adminCookie *http.Cookie, adminCSRF, username string, request func(method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder, websites ...string) (*http.Cookie, string) {
	t.Helper()
	w := websiteRequest(f.handler, "POST", "/api/v1/session/customers", map[string]any{"username": username, "websites": websites}, adminCookie, adminCSRF)
	if w.Code != 200 {
		t.Fatalf("create customer: %d %s", w.Code, w.Body.String())
	}
	var created operator.CustomerSetupLink
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	_, token, _ := strings.Cut(created.SetupLink, "#")
	w = request("POST", "/api/v1/session/customer-setup/begin", map[string]string{"token": token}, nil, "")
	var secret struct {
		Secret string `json:"secret"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &secret) != nil {
		t.Fatalf("begin customer setup: %d %s", w.Code, w.Body.String())
	}
	body := map[string]string{"token": token, "totp_code": testCode(secret.Secret, time.Now().Unix()/30)}
	body["pass"+"word"] = customerTestPassword
	w = request("POST", "/api/v1/session/customer-setup/finish", body, nil, "")
	var session operator.Session
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &session) != nil || session.Role != "customer" || len(w.Result().Cookies()) != 1 {
		t.Fatalf("finish customer setup: %d %s", w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0], session.CSRFToken
}

func loopback(f siteFixture) func(string, string, any, *http.Cookie, string) *httptest.ResponseRecorder {
	return func(method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		return websiteRequest(f.handler, method, path, body, cookie, csrf)
	}
}

func problem(w *httptest.ResponseRecorder) string {
	var p struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	return p.Error
}

// Every route the panel registers has a decision in the customer table, and
// the table names no route that is not registered. Adding a route without
// deciding what a customer may do there fails here.
func TestCustomerRouteTableCoversEveryRoute(t *testing.T) {
	f := websiteFixture(t)
	_, mux := build(Options{Operator: f.manager})
	registered := map[string]bool{}
	for _, pattern := range mux.patterns {
		registered[pattern] = true
		if _, ok := customerRoutes[pattern]; !ok {
			t.Errorf("route %q has no entry in customerRoutes (internal/api/customer_routes.go): decide what a customer may do there", pattern)
		}
	}
	for pattern, access := range customerRoutes {
		if !registered[pattern] {
			t.Errorf("customerRoutes names %q, which is not a registered route", pattern)
		}
		hasSite := strings.Contains(pattern, "{"+websiteID+"}")
		if (access == ownWebsite) != hasSite && access != adminOnly {
			t.Errorf("%q: a route naming a website must be ownWebsite or adminOnly, and only such a route may be ownWebsite", pattern)
		}
		if strings.Contains(pattern, "...}") {
			t.Errorf("%q: a {name...} wildcard cannot be read by patternValue", pattern)
		}
	}
	if len(mux.patterns) < 100 {
		t.Fatalf("only %d routes recorded; the recorder misses registrations", len(mux.patterns))
	}
}

var updateCustomerRoutes = flag.Bool("update", false, "rewrite "+customerRoutesFile+" from customerRoutes")

const customerRoutesFile = "../../web/src/lib/customer-routes.json"

// The panel's own tests read the table from web/src/lib/customer-routes.json
// (customer-routes.test.mjs fails when the customer's menu or a website tab
// needs a route customers are refused). This keeps that file equal to the
// table. After changing the table, run
// go test ./internal/api -run TestCustomerRoutesFileMatchesTable -update
// and commit the file with the change.
func TestCustomerRoutesFileMatchesTable(t *testing.T) {
	names := map[customerAccess]string{adminOnly: "adminOnly", customerOpen: "customerOpen", ownWebsite: "ownWebsite", ownWebsites: "ownWebsites"}
	table := map[string]string{}
	for pattern, access := range customerRoutes {
		name, ok := names[access]
		if !ok {
			t.Fatalf("%q: access %d has no name here", pattern, access)
		}
		table[pattern] = name
	}
	want, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if *updateCustomerRoutes {
		if err := os.WriteFile(customerRoutesFile, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(customerRoutesFile)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s does not match customerRoutes (%v). Run go test ./internal/api -run TestCustomerRoutesFileMatchesTable -update and commit the file", customerRoutesFile, err)
	}
}

// A restricted session's answers name the routes it may use, which are the
// table's: a customer's sign-in and its session, and an admin's while it
// views as the customer. An admin's own session names none: it may use all.
func TestRestrictedSessionsNameTheirRoutes(t *testing.T) {
	f, _, _, site, _ := domainsFixture(t)
	adminCookie, adminCSRF := websiteSignIn(t, f)
	allowed := customerAllowedRoutes()
	if len(allowed) < 30 || slices.Contains(allowed, "POST /api/v1/websites/sites/{account_id}/state") || !slices.Contains(allowed, "GET /api/v1/websites/sites/{account_id}/backups") {
		t.Fatalf("allowed routes: %v", allowed)
	}
	routesOf := func(w *httptest.ResponseRecorder) []string {
		t.Helper()
		var s operator.Session
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &s) != nil || !s.Authenticated {
			t.Fatalf("session answer: %d %s", w.Code, w.Body.String())
		}
		return s.Routes
	}
	if got := routesOf(websiteRequest(f.handler, "GET", "/api/v1/session", nil, adminCookie, "")); got != nil {
		t.Fatalf("an admin's session names routes: %v", got)
	}
	cookie, _ := customerSession(t, f, adminCookie, adminCSRF, "alice", loopback(f), site.AccountID)
	if got := routesOf(websiteRequest(f.handler, "GET", "/api/v1/session", nil, cookie, "")); !slices.Equal(got, allowed) {
		t.Fatalf("a customer's session names %v", got)
	}
	if got := routesOf(websiteRequest(f.handler, "POST", "/api/v1/session/view-as", map[string]string{"username": "alice"}, adminCookie, adminCSRF)); !slices.Equal(got, allowed) {
		t.Fatalf("viewing as names %v", got)
	}
	if got := routesOf(websiteRequest(f.handler, "GET", "/api/v1/session", nil, adminCookie, "")); !slices.Equal(got, allowed) {
		t.Fatalf("a viewing session names %v", got)
	}
	if got := routesOf(websiteRequest(f.handler, "POST", "/api/v1/session/view-as/end", map[string]string{}, adminCookie, adminCSRF)); got != nil {
		t.Fatalf("back to the admin view names %v", got)
	}
}

// A customer reaches its own password and authenticator routes through the
// panel's gate, on the server and over HTTPS; an API token does not.
func TestCustomerReachesItsCredentialRoutes(t *testing.T) {
	f, _, _, site, _ := domainsFixture(t)
	remote := operator.Remote(f.handler, []string{"panel.example.test"})
	adminCookie, adminCSRF := websiteSignIn(t, f)
	request := func(method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		return remoteRequest(remote, method, path, body, cookie, csrf)
	}
	cookie, csrf := customerSession(t, f, adminCookie, adminCSRF, "alice", request, site.AccountID)
	wrong := map[string]string{"current_password": "not the right one at all", "totp_code": "000000"}
	for _, path := range []string{"/api/v1/session/password", "/api/v1/session/authenticator/begin"} {
		body := map[string]string{"current_password": wrong["current_password"], "totp_code": wrong["totp_code"]}
		if path == "/api/v1/session/password" {
			body["new_"+"pass"+"word"] = "a brand new long one"
		}
		if w := request("POST", path, body, cookie, csrf); w.Code != 422 || problem(w) != "invalid_credentials" {
			t.Fatalf("%s over HTTPS: %d %s", path, w.Code, w.Body.String())
		}
		if w := clientRequest(f.handler, false, "POST", path, "sfr_"+strings.Repeat("A", 43), body); w.Code != 403 {
			t.Fatalf("%s with an API token: %d", path, w.Code)
		}
	}
	if w := request("POST", "/api/v1/session/authenticator/finish", map[string]string{"totp_code": "000000"}, cookie, csrf); w.Code != 409 || problem(w) != "authenticator_change_expired" {
		t.Fatalf("finish over HTTPS: %d %s", w.Code, w.Body.String())
	}
}

// customerRouteRequest turns a pattern into a request path, with the given
// website in {account_id}.
func customerRouteRequest(pattern, site string) (method, path string) {
	method, path, found := strings.Cut(pattern, " ")
	if !found {
		method, path = "GET", pattern
	}
	if path == "/" {
		path = "/websites"
	}
	if strings.HasSuffix(path, "/") {
		path += "x"
	}
	return method, strings.NewReplacer("{account_id}", site, "{id}", strings.Repeat("e", 32), "{username}", "alice", "{name}", "alice_db", "{user}", "alice_u", "{kind}", "access", "{backupID}", "b1").Replace(path)
}

// A customer's session, on every registered route: refused where the table
// says adminOnly, refused with one answer for a website that is not its own
// (another customer's and one that does not exist look the same), and
// through to the handler for its own website and the open routes.
func TestEveryRouteHoldsACustomerToTheTable(t *testing.T) {
	f, _, _, site, other := domainsFixture(t)
	adminCookie, adminCSRF := websiteSignIn(t, f)
	cookie, csrf := customerSession(t, f, adminCookie, adminCSRF, "alice", loopback(f), site.AccountID)
	_, mux := build(Options{Operator: f.manager})
	missing := strings.Repeat("d", 32)
	for _, pattern := range mux.patterns {
		access := customerRoutes[pattern]
		if pattern == "POST /api/v1/session/logout" {
			continue // ends the session; checked last
		}
		send := func(id string) *httptest.ResponseRecorder {
			method, path := customerRouteRequest(pattern, id)
			body := any(nil)
			if method != "GET" {
				body = map[string]any{}
			}
			return websiteRequest(f.handler, method, path, body, cookie, csrf)
		}
		switch access {
		case adminOnly:
			if w := send(site.AccountID); w.Code != 403 || problem(w) != "customer_not_allowed" {
				t.Errorf("%s: a customer must be refused, got %d %s", pattern, w.Code, w.Body.String())
			}
		case customerOpen, ownWebsites:
			if w := send(site.AccountID); w.Code == 403 && problem(w) == "customer_not_allowed" {
				t.Errorf("%s: open to customers but refused", pattern)
			}
		case ownWebsite:
			own := send(site.AccountID)
			if (own.Code == 403 && problem(own) == "customer_not_allowed") || (own.Code == 404 && problem(own) == "website_not_found") {
				t.Errorf("%s: the customer's own website was refused: %d %s", pattern, own.Code, own.Body.String())
			}
			theirs, nobody := send(other.AccountID), send(missing)
			if theirs.Code != 404 || problem(theirs) != "website_not_found" {
				t.Errorf("%s: another customer's website: %d %s", pattern, theirs.Code, theirs.Body.String())
			}
			if theirs.Code != nobody.Code || theirs.Body.String() != nobody.Body.String() {
				t.Errorf("%s: another's website and a missing one must get the same answer", pattern)
			}
		}
	}
	// Paths the mux would rewrite, and escaped paths, never reach a handler.
	for _, path := range []string{"/api/v1/websites/sites/" + site.AccountID + "/../" + other.AccountID, "/api/v1/websites/sites//" + other.AccountID, "/api/v1/websites/sites/" + site.AccountID + "/"} {
		if w := websiteRequest(f.handler, "GET", path, nil, cookie, ""); w.Code != 403 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/v1/websites/sites/"+site.AccountID+"%2Fx", nil)
	r.RemoteAddr = "127.0.0.1:14000"
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("escaped path: %d", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/logout", map[string]any{}, cookie, csrf); w.Code != 200 {
		t.Errorf("customer logout: %d", w.Code)
	}
}

// Over the HTTPS listener, as from the customer's own computer: setup from
// the link, sign-in, only its own website in the list, and a direct address
// or API call to another website refused like one that does not exist.
func TestCustomerSeesOnlyItsOwnWebsitesOverHTTPS(t *testing.T) {
	f, _, _, site, other := domainsFixture(t)
	remote := operator.Remote(f.handler, []string{"panel.example.test"})
	adminCookie, adminCSRF := websiteSignIn(t, f)
	request := func(method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		return remoteRequest(remote, method, path, body, cookie, csrf)
	}
	cookie, csrf := customerSession(t, f, adminCookie, adminCSRF, "alice", request, site.AccountID)
	if !cookie.Secure || !cookie.HttpOnly {
		t.Fatal("a customer's cookie over HTTPS must be Secure and HttpOnly")
	}
	w := request("GET", "/api/v1/websites/sites", nil, cookie, "")
	if w.Code != 200 {
		t.Fatalf("customer list: %d %s", w.Code, w.Body.String())
	}
	if got := decodeSites(t, w.Body.Bytes()); len(got) != 1 || got[0].AccountID != site.AccountID {
		t.Fatalf("customer sees %+v", got)
	}
	if got := decodeSites(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, adminCookie, "").Body.Bytes()); len(got) != 2 {
		t.Fatalf("the admin's list must keep every website: %d", len(got))
	}
	if w := request("GET", "/api/v1/websites/sites/"+site.AccountID, nil, cookie, ""); w.Code != 200 {
		t.Fatalf("own website: %d %s", w.Code, w.Body.String())
	}
	theirs := request("GET", "/api/v1/websites/sites/"+other.AccountID, nil, cookie, "")
	nobody := request("GET", "/api/v1/websites/sites/"+strings.Repeat("d", 32), nil, cookie, "")
	if theirs.Code != 404 || theirs.Body.String() != nobody.Body.String() {
		t.Fatalf("another website over HTTPS: %d %s", theirs.Code, theirs.Body.String())
	}
	if w := request("POST", "/api/v1/websites/sites/"+other.AccountID+"/domain-add", map[string]any{"domain": "grab.example", "expected_revision": other.Revision}, cookie, csrf); w.Code != 404 {
		t.Fatalf("change to another website: %d", w.Code)
	}
	for _, path := range []string{"/api/v1/server", "/api/v1/accounts", "/api/v1/websites/jobs", "/api/v1/session/customers", "/api/v1/session/tokens", "/openapi.json"} {
		if w := request("GET", path, nil, cookie, ""); w.Code != 403 {
			t.Fatalf("%s for a customer over HTTPS: %d", path, w.Code)
		}
	}
	if w := request("GET", "/api/v1/session", nil, cookie, ""); w.Code != 200 {
		t.Fatalf("own session: %d", w.Code)
	}
	// The access key still works only on the server.
	if w := request("POST", "/api/v1/session/login", map[string]string{"access_key": f.key}, nil, ""); w.Code != 403 {
		t.Fatalf("access key over HTTPS: %d", w.Code)
	}
	// On loopback too, a customer's cookie cannot read what loopback serves
	// without a session.
	if w := websiteRequest(f.handler, "GET", "/api/v1/server", nil, cookie, ""); w.Code != 403 {
		t.Fatalf("customer cookie on a loopback reading: %d", w.Code)
	}
}

// A customer's changes are its own in the broker; an admin's while viewing
// as the customer are the admin's, and reach only what the customer could.
func TestViewAsIsAttributedToTheAdmin(t *testing.T) {
	f, broker, _, site, other := domainsFixture(t)
	keyCookie, keyCSRF := websiteSignIn(t, f)
	// A named admin, as on a real panel.
	w := websiteRequest(f.handler, "POST", "/api/v1/session/setup/totp", map[string]string{"username": "admin"}, keyCookie, keyCSRF)
	var secret struct {
		Secret string `json:"secret"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &secret) != nil {
		t.Fatalf("begin admin setup: %d", w.Code)
	}
	body := map[string]string{"username": "admin", "totp_code": testCode(secret.Secret, time.Now().Unix()/30)}
	body["pass"+"word"] = "admin password long"
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/setup/admin", body, keyCookie, keyCSRF); w.Code != 200 {
		t.Fatalf("finish admin setup: %d %s", w.Code, w.Body.String())
	}
	adminCookie, adminCSRF := keyCookie, keyCSRF
	cookie, csrf := customerSession(t, f, adminCookie, adminCSRF, "alice", loopback(f), site.AccountID)

	add := func(c *http.Cookie, token, domain string, target Website) *httptest.ResponseRecorder {
		t.Helper()
		accounts, _ := broker.List(t.Context())
		revision := uint64(0)
		for _, a := range accounts {
			if a.ID == target.AccountID {
				revision = a.Revision
			}
		}
		return websiteRequest(f.handler, "POST", sitePath(target, "domain-add"), map[string]any{"domain": domain, "expected_revision": revision}, c, token)
	}
	lastActor := func() string {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		last := broker.changes[len(broker.changes)-1]
		return last[strings.LastIndex(last, "actor=")+len("actor="):]
	}
	if w := add(cookie, csrf, "shop.example.com", site); w.Code != 200 {
		t.Fatalf("customer adds a domain: %d %s", w.Code, w.Body.String())
	}
	if got := lastActor(); got != "customer:alice" {
		t.Fatalf("customer's change recorded as %q", got)
	}

	w = websiteRequest(f.handler, "POST", "/api/v1/session/view-as", map[string]string{"username": "alice"}, adminCookie, adminCSRF)
	if w.Code != 200 {
		t.Fatalf("view as: %d %s", w.Code, w.Body.String())
	}
	if w := add(adminCookie, adminCSRF, "blog.example.com", site); w.Code != 200 {
		t.Fatalf("admin viewing as adds a domain: %d %s", w.Code, w.Body.String())
	}
	if got := lastActor(); got != "admin:admin as customer:alice" {
		t.Fatalf("change while viewing recorded as %q", got)
	}
	if got := decodeSites(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, adminCookie, "").Body.Bytes()); len(got) != 1 {
		t.Fatalf("viewing as alice lists %d websites", len(got))
	}
	if w := add(adminCookie, adminCSRF, "grab.example.com", other); w.Code != 404 {
		t.Fatalf("viewing as alice reaches another website: %d", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", sitePath(site, "state"), map[string]any{"state": "suspended", "expected_revision": 1}, adminCookie, adminCSRF); w.Code != 403 {
		t.Fatalf("viewing as alice suspends: %d", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/view-as/end", map[string]string{}, adminCookie, adminCSRF); w.Code != 200 {
		t.Fatalf("end view as: %d", w.Code)
	}
	if w := add(adminCookie, adminCSRF, "news.other.example", other); w.Code != 200 {
		t.Fatalf("admin after going back: %d %s", w.Code, w.Body.String())
	}
	if got := lastActor(); got != "local-operator" {
		t.Fatalf("admin's own change recorded as %q", got)
	}

	// Deleting a website takes it off the customer's list.
	current := decodeDetail(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID, nil, adminCookie, ""))
	if w := websiteRequest(f.handler, "POST", "/api/v1/accounts/"+site.AccountID+"/delete", map[string]any{"expected_revision": current.Revision, "reason": "customer left"}, adminCookie, adminCSRF); w.Code != 200 {
		t.Fatalf("delete account: %d %s", w.Code, w.Body.String())
	}
	var list operator.CustomerLoginList
	_ = json.Unmarshal(websiteRequest(f.handler, "GET", "/api/v1/session/customers", nil, adminCookie, "").Body.Bytes(), &list)
	if len(list.Items) != 1 || slices.Contains(list.Items[0].Websites, site.AccountID) {
		t.Fatalf("deleted website still given: %+v", list.Items)
	}
	if got := decodeSites(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "").Body.Bytes()); len(got) != 0 {
		t.Fatalf("customer still lists %d websites", len(got))
	}
}

// The admin's Customers page checks the websites it gives against the
// account service.
func TestCustomerWebsitesMustExist(t *testing.T) {
	f, _, _, site, _ := domainsFixture(t)
	adminCookie, adminCSRF := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "POST", "/api/v1/session/customers", map[string]any{"username": "alice", "websites": []string{site.AccountID, strings.Repeat("d", 32)}}, adminCookie, adminCSRF)
	if w.Code != 422 || problem(w) != "unknown_website" {
		t.Fatalf("unknown website: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/customers", map[string]any{"username": "alice", "websites": []string{site.AccountID}}, adminCookie, adminCSRF); w.Code != 200 {
		t.Fatalf("known website: %d %s", w.Code, w.Body.String())
	}
	if w := clientRequest(f.handler, false, "GET", "/api/v1/session/customers", "sfr_"+strings.Repeat("A", 43), nil); w.Code != 403 {
		t.Fatalf("API token on customer logins: %d", w.Code)
	}

}
