package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/wizard"
)

// sitesBroker is one fake broker for both sides of the join: the wizard
// creates accounts through it, and the panel lists them. It provisions
// nothing.
type sitesBroker struct {
	mu       sync.Mutex
	next     int
	accounts []hostaccounts.Account
	listErr  error
	lists    int
	// changes records every SetWeb, SetState and Delete; changeErr, when
	// set, is their answer, and nothing changes. busyDeletes is how many
	// deletes, in turn, the broker refuses as busy, changing nothing.
	changes     []string
	changeErr   error
	busyDeletes int
}

// changed applies one change to an account at its revision, as the broker
// does: the revision must match and moves on.
func (b *sitesBroker) changed(call, id string, revision uint64, edit func(*hostaccounts.Account)) (hostaccounts.Account, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.changes = append(b.changes, call)
	if b.changeErr != nil {
		return hostaccounts.Account{}, b.changeErr
	}
	i := slices.IndexFunc(b.accounts, func(a hostaccounts.Account) bool { return a.ID == id })
	if i < 0 {
		return hostaccounts.Account{}, hostaccounts.ErrNotFound
	}
	if b.accounts[i].Revision != revision {
		return hostaccounts.Account{}, hostaccounts.ErrConflict
	}
	edit(&b.accounts[i])
	b.accounts[i].Revision++
	return b.accounts[i], nil
}

func (b *sitesBroker) List(context.Context) ([]hostaccounts.Account, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lists++
	if b.listErr != nil {
		return nil, b.listErr
	}
	return slices.Clone(b.accounts), nil
}
func (b *sitesBroker) Create(_ context.Context, in hostaccounts.CreateInput, _ string) (hostaccounts.Account, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	a := hostaccounts.Account{ID: fmt.Sprintf("acc%029x", b.next), Username: in.Username, Domain: in.Domain, State: "active", Revision: 1}
	b.accounts = append(b.accounts, a)
	return a, nil
}
func (b *sitesBroker) Delete(_ context.Context, id string, in hostaccounts.DeleteInput, actor string) (hostaccounts.Account, error) {
	call := fmt.Sprintf("delete %s rev=%d reason=%q actor=%s", id, in.ExpectedRevision, in.Reason, actor)
	b.mu.Lock()
	if b.busyDeletes > 0 {
		b.busyDeletes--
		b.changes = append(b.changes, call)
		b.mu.Unlock()
		return hostaccounts.Account{}, hostaccounts.ErrDeleteBusy
	}
	b.mu.Unlock()
	a, err := b.changed(call, id, in.ExpectedRevision, func(*hostaccounts.Account) {})
	if err != nil {
		return hostaccounts.Account{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.accounts = slices.DeleteFunc(b.accounts, func(x hostaccounts.Account) bool { return x.ID == id })
	return a, nil
}

// SetWeb keeps the settings on the account, where the list reports them.
func (b *sitesBroker) SetWeb(_ context.Context, id string, in hostaccounts.WebInput, actor string) (hostaccounts.WebResult, error) {
	web := hostaccounts.WebState{PHPVersion: in.PHPVersion, QuotaMiB: in.QuotaMiB}
	a, err := b.changed(fmt.Sprintf("web %s php=%s quota=%d rev=%d reason=%q actor=%s", id, in.PHPVersion, in.QuotaMiB, in.ExpectedRevision, in.Reason, actor), id, in.ExpectedRevision, func(a *hostaccounts.Account) { a.Web = web })
	if err != nil {
		return hostaccounts.WebResult{}, err
	}
	return hostaccounts.WebResult{Account: a, Web: web}, nil
}
func (b *sitesBroker) InstallWordPress(context.Context, string, hostaccounts.WordPressInput, string) (hostaccounts.WordPressResult, error) {
	return hostaccounts.WordPressResult{Version: "7.1.5"}, nil
}
func (b *sitesBroker) Capability(context.Context) (hostaccounts.Capability, error) {
	return hostaccounts.Capability{Available: true}, nil
}
func (b *sitesBroker) SetState(_ context.Context, id string, in hostaccounts.StateInput, actor string) (hostaccounts.Account, error) {
	return b.changed(fmt.Sprintf("state %s %s rev=%d reason=%q actor=%s", id, in.State, in.ExpectedRevision, in.Reason, actor), id, in.ExpectedRevision, func(a *hostaccounts.Account) { a.State = in.State })
}
func (b *sitesBroker) SetPlan(context.Context, string, hostaccounts.PlanInput, string) (hostaccounts.Account, error) {
	return hostaccounts.Account{}, errors.New("not used")
}

// change edits the broker's record of one account, as a later operation
// (suspension, a certificate) would.
func (b *sitesBroker) change(id string, edit func(*hostaccounts.Account)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.accounts {
		if b.accounts[i].ID == id {
			edit(&b.accounts[i])
		}
	}
}

func sitesFixture(t *testing.T) (siteFixture, *wizard.Runner, *sitesBroker) {
	t.Helper()
	f := websiteFixture(t)
	store, err := wizard.OpenStore(filepath.Join(realTempDir(t), "wizard"))
	if err != nil {
		t.Fatal(err)
	}
	broker := &sitesBroker{}
	runner := wizard.New(broker, wizardDatabaseSpy{}, store, nil)
	t.Cleanup(runner.Wait)
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Wizard: runner, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return f, runner, broker
}

func makeSite(t *testing.T, runner *wizard.Runner, domain, php string) wizard.Job {
	t.Helper()
	job, err := runner.Start(context.Background(), wizard.Input{Domain: domain, Title: "My site", AdminUser: "siteadmin", AdminEmail: "me@example.com", AdminPassword: wizardPassword, PHPVersion: php}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	runner.Wait()
	done, ok := runner.Get(job.ID)
	if !ok || done.State != wizard.StateSucceeded {
		t.Fatalf("job for %s: %+v", domain, done)
	}
	return done
}

func decodeSites(t *testing.T, body []byte) []Website {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || len(withoutSchema(raw)) != 1 || raw["sites"] == nil {
		t.Fatalf("list body %s", body)
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw["sites"], &items); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		checkWebsiteShape(t, item)
	}
	var sites []Website
	if err := json.Unmarshal(raw["sites"], &sites); err != nil {
		t.Fatal(err)
	}
	return sites
}

// checkWebsiteShape compares one entry's keys with the contract, exactly:
// the list's entry, plus more for the one-site read (php_versions).
func checkWebsiteShape(t *testing.T, item map[string]json.RawMessage, more ...string) {
	t.Helper()
	delete(item, "$schema")
	// usage is there in the list when the account service reports it, with
	// exactly its five keys.
	if raw, ok := item["usage"]; ok {
		var usage map[string]json.RawMessage
		if json.Unmarshal(raw, &usage) != nil || len(usage) != 5 || usage["disk_used_bytes"] == nil || usage["disk_limit_bytes"] == nil || usage["traffic_month"] == nil || usage["traffic_bytes"] == nil || usage["traffic_complete"] == nil {
			t.Fatalf("usage %s", raw)
		}
		delete(item, "usage")
	}
	// limits are there when the account service reports them, with exactly
	// their three whole numbers.
	if raw, ok := item["limits"]; ok {
		var limits map[string]json.Number
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if dec.Decode(&limits) != nil || len(limits) != 3 {
			t.Fatalf("limits %s", raw)
		}
		for _, key := range []string{"processes", "memory_mib", "cpu_percent"} {
			if _, err := limits[key].Int64(); err != nil {
				t.Fatalf("limits.%s %s", key, raw)
			}
		}
		delete(item, "limits")
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range item {
			if !yield(k) {
				return
			}
		}
	})
	// The one-site read also lists the site's redirects.
	if slices.Contains(more, "php_versions") {
		more = append(more, "redirects")
	}
	want := slices.Sorted(slices.Values(append([]string{"account_id", "admin_url", "aliases", "created_at", "domain", "https", "kind", "php_version", "redirect_count", "revision", "site_folder_changed", "state", "url", "username", "wordpress_version"}, more...)))
	if !slices.Equal(keys, want) {
		t.Fatalf("website keys %q", keys)
	}
	var https map[string]any
	if err := json.Unmarshal(item["https"], &https); err != nil || len(https) != 2 {
		t.Fatalf("https %s", item["https"])
	}
	if _, ok := https["on"].(bool); !ok {
		t.Fatalf("https.on %s", item["https"])
	}
	if _, ok := https["not_after"].(string); !ok {
		t.Fatalf("https.not_after %s", item["https"])
	}
}

func TestWebsitesListJoinsBrokerAndJobs(t *testing.T) {
	f, runner, broker := sitesFixture(t)
	first := makeSite(t, runner, "first.example", "8.2")
	second := makeSite(t, runner, "second.example", "8.3")
	third := makeSite(t, runner, "third.example", "8.4")
	// An account the wizard did not make is not a website here.
	broker.mu.Lock()
	broker.accounts = append(broker.accounts, hostaccounts.Account{ID: strings.Repeat("e", 32), Username: "manual", Domain: "manual.example", State: "active", Revision: 1})
	broker.mu.Unlock()
	// The broker is the authority for state, certificate and domain.
	notAfter := time.Date(2027, 2, 21, 12, 30, 0, 0, time.UTC)
	broker.change(second.Result.AccountID, func(a *hostaccounts.Account) {
		a.Certificate = hostaccounts.CertificateState{NotAfter: notAfter.Unix(), Fingerprint: strings.Repeat("f", 64)}
	})
	broker.change(first.Result.AccountID, func(a *hostaccounts.Account) { a.State = "suspended" })
	// Deleted on the broker: gone from the list.
	broker.mu.Lock()
	broker.accounts = slices.DeleteFunc(broker.accounts, func(a hostaccounts.Account) bool { return a.ID == third.Result.AccountID })
	broker.mu.Unlock()

	cookie, _ := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "")
	if w.Code != 200 {
		t.Fatalf("list status %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), wizardPassword) {
		t.Fatal("password in the list")
	}
	sites := decodeSites(t, w.Body.Bytes())
	if len(sites) != 2 || sites[0].AccountID != second.Result.AccountID || sites[1].AccountID != first.Result.AccountID {
		t.Fatalf("sites %+v", sites)
	}
	want := Website{AccountID: second.Result.AccountID, Username: "second", Domain: "second.example", Kind: "wordpress", State: "active",
		HTTPS: WebsiteHTTPS{On: true, NotAfter: "2027-02-21T12:30:00Z"}, PHPVersion: "8.3", WordPressVersion: "7.1.5",
		URL: "http://second.example/", AdminURL: "http://second.example/wp-admin/", CreatedAt: second.CreatedAt, Revision: 2, Aliases: []WebsiteDomain{}}
	if !reflect.DeepEqual(sites[0], want) {
		t.Fatalf("second site %+v\nwant %+v", sites[0], want)
	}
	if s := sites[1]; s.State != "suspended" || s.HTTPS != (WebsiteHTTPS{}) || s.PHPVersion != "8.2" || s.Username != "first" {
		t.Fatalf("first site %+v", s)
	}
	if !strings.Contains(w.Body.String(), `"https":{"on":false,"not_after":""}`) {
		t.Fatalf("http site's https is not off and empty: %s", w.Body.String())
	}

	// One site, the same entry.
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+second.Result.AccountID, nil, cookie, "")
	var one map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &one) != nil {
		t.Fatalf("one site %d: %s", w.Code, w.Body.String())
	}
	checkWebsiteShape(t, one, "php_versions")
	var got Website
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("one site %+v", got)
	}
	// Deleted, not made by the wizard, unknown, or not an ID: 404.
	for _, id := range []string{third.Result.AccountID, strings.Repeat("e", 32), strings.Repeat("0", 32), "not-an-id", strings.ToUpper(second.Result.AccountID)} {
		w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+id, nil, cookie, "")
		if w.Code != 404 || !strings.HasPrefix(problemDetail(t, w), "That website was not found.") {
			t.Fatalf("GET %s: %d %s", id, w.Code, w.Body.String())
		}
	}
}

func TestWebsitesListIsEmptyWithoutSites(t *testing.T) {
	f, _, _ := sitesFixture(t)
	cookie, _ := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"sites":[]`) {
		t.Fatalf("empty list %d: %s", w.Code, w.Body.String())
	}
}

func TestWebsitesListAdmission(t *testing.T) {
	f, runner, broker := sitesFixture(t)
	site := makeSite(t, runner, "example.com", "8.3")
	before := broker.lists
	for _, path := range []string{"/api/v1/websites/sites", "/api/v1/websites/sites/" + site.Result.AccountID} {
		if w := websiteRequest(f.handler, "GET", path, nil, nil, ""); w.Code != 401 {
			t.Fatalf("unauthenticated %s: %d", path, w.Code)
		}
	}
	if broker.lists != before {
		t.Fatal("an unauthenticated read reached the broker")
	}
	cookie, csrf := websiteSignIn(t, f)
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		if w := websiteRequest(f.handler, method, "/api/v1/websites/sites", `{}`, cookie, csrf); w.Code != 405 {
			t.Fatalf("%s status %d", method, w.Code)
		}
	}
	// A page on another origin cannot read the list, even with the cookie.
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/v1/websites/sites", nil)
	r.RemoteAddr = "127.0.0.1:14000"
	r.Header.Set("Origin", "http://other.example")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 403 || strings.Contains(w.Body.String(), "example.com") {
		t.Fatalf("cross-origin read %d: %s", w.Code, w.Body.String())
	}
	if w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, ""); w.Code != 200 {
		t.Fatalf("same-origin read %d", w.Code)
	}
}

func TestWebsitesListNotAvailable(t *testing.T) {
	f, runner, broker := sitesFixture(t)
	site := makeSite(t, runner, "example.com", "8.3")
	cookie, _ := websiteSignIn(t, f)
	paths := []string{"/api/v1/websites/sites", "/api/v1/websites/sites/" + site.Result.AccountID}

	broker.mu.Lock()
	broker.listErr = hostaccounts.ErrUnavailable
	broker.mu.Unlock()
	for _, path := range paths {
		w := websiteRequest(f.handler, "GET", path, nil, cookie, "")
		if w.Code != 503 || problemDetail(t, w) != websitesNoBroker {
			t.Fatalf("broker down %s: %d %s", path, w.Code, w.Body.String())
		}
	}

	for name, options := range map[string]Options{
		"no wizard": {Operator: f.manager, Accounts: broker},
		"no broker": {Operator: f.manager, Wizard: runner},
	} {
		h := New(Options{Operator: options.Operator, Accounts: options.Accounts, Wizard: options.Wizard, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
		for _, path := range paths {
			w := websiteRequest(h, "GET", path, nil, cookie, "")
			if w.Code != 503 || problemDetail(t, w) != websitesNotSetUp {
				t.Fatalf("%s %s: %d %s", name, path, w.Code, w.Body.String())
			}
		}
	}
}

// A site shows its hosting account's limits as the broker reports them,
// read only; without them (a broker before limits) the key is left out.
func TestWebsiteShowsAccountLimits(t *testing.T) {
	f, runner, broker := sitesFixture(t)
	limited := makeSite(t, runner, "limited.example", "8.3")
	plain := makeSite(t, runner, "plain.example", "8.3")
	broker.change(limited.Result.AccountID, func(a *hostaccounts.Account) {
		a.Limits = hostaccounts.AccountLimits{Processes: 100, MemoryMiB: 1024, CPUPercent: 100}
	})
	cookie, _ := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+limited.Result.AccountID, nil, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"limits":{"processes":100,"memory_mib":1024,"cpu_percent":100}`) {
		t.Fatalf("site with limits %d: %s", w.Code, w.Body.String())
	}
	var got Website
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Limits == nil || *got.Limits != (WebsiteLimits{Processes: 100, MemoryMiB: 1024, CPUPercent: 100}) {
		t.Fatalf("decoded %+v", got)
	}
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+plain.Result.AccountID, nil, cookie, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), `"limits"`) {
		t.Fatalf("site without limits %d: %s", w.Code, w.Body.String())
	}
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "")
	if sites := decodeSites(t, w.Body.Bytes()); len(sites) != 2 {
		t.Fatalf("list %+v", sites)
	}
}
