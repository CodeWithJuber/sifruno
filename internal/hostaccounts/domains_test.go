package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"sifruno/internal/olsweb"
)

func domainsInput(r record, aliases []string, redirects ...SiteRedirect) SiteDomainsInput {
	if aliases == nil {
		aliases = []string{}
	}
	if redirects == nil {
		redirects = []SiteRedirect{}
	}
	return SiteDomainsInput{Aliases: aliases, Redirects: redirects, ExpectedRevision: r.Account.Revision, Reason: "Domains changed on the website's page"}
}

// renderUnderHome renders an installed site list as olsweb does on a host,
// with each document root moved from the test's temporary homes to /home.
func renderUnderHome(sites []olsweb.Site) (map[string][]byte, error) {
	moved := make([]olsweb.Site, 0, len(sites))
	for _, site := range sites {
		site.DocRoot = "/home/" + site.Username + "/public_html"
		moved = append(moved, site)
	}
	return olsweb.Render(webServer(moved))
}

func TestSiteDomainsGoLiveAndJournal(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	in := domainsInput(live, []string{"www.fixture.test", "shop.fixture.test", "fixture.example"},
		SiteRedirect{Path: "/old-page", Target: "https://fixture.test/new-page", Status: 301},
		SiteRedirect{Domain: "www.fixture.test", Target: "https://fixture.test", Status: 301},
	)
	got, err := s.setSiteDomains(ctx, live.Account.ID, in, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	// The broker's order: aliases sorted, domain redirects before paths.
	if strings.Join(got.Domains.Aliases, ",") != "fixture.example,shop.fixture.test,www.fixture.test" || got.Domains.Redirects[0].Domain != "www.fixture.test" || got.Domains.Redirects[1].Path != "/old-page" {
		t.Fatalf("answer %+v", got.Domains)
	}
	if got.Account.Revision != live.Account.Revision+1 || got.Account.SiteDomains == nil || len(got.Account.SiteDomains.Aliases) != 3 || got.Account.SiteDomains.Redirects != 2 {
		t.Fatalf("account %+v", got.Account)
	}
	if h := historyActions(t, s, live.Account.ID); strings.Join(h[len(h)-2:], " ") != "domains:intended domains:succeeded" {
		t.Fatalf("journal %v", h)
	}
	r := recordFor(t, s, live.Account.ID)
	if r.Pending != nil || r.DomainsNext != "" || r.Domains != encodeSiteDomains(got.Domains) || r.Account.SiteDomains != nil {
		t.Fatalf("record %+v", r)
	}
	// The site list carries them: the account's own domain first.
	site := siteOf(t, f.sites, live.Account.ID)
	if strings.Join(site.Domains, ",") != "fixture.test,fixture.example,shop.fixture.test,www.fixture.test" || len(site.Redirects) != 2 {
		t.Fatalf("site %+v", site)
	}
	files, err := renderUnderHome(f.sites)
	if err != nil {
		t.Fatal(err)
	}
	vh := string(files[olsweb.VhostConfigPath(site.Name)])
	if !strings.Contains(vh, "RewriteRule ^/?old-page/?$ https://fixture.test/new-page [R=301,L]\n") || !strings.Contains(vh, "RewriteRule ^/?(.*)$ https://fixture.test/$1 [R=301,L]\n") {
		t.Fatalf("vhost rules:\n%s", vh)
	}
	if !strings.Contains(string(files[olsweb.ServerConfigPath]), "map                     sifruno-"+site.Name+" fixture.test, fixture.example, shop.fixture.test, www.fixture.test\n") {
		t.Fatalf("listener map:\n%s", files[olsweb.ServerConfigPath])
	}

	// The list shows the aliases and how many redirects; the read shows all.
	items, err := s.list(ctx)
	if err != nil || items[0].SiteDomains == nil || strings.Join(items[0].SiteDomains.Aliases, ",") != "fixture.example,shop.fixture.test,www.fixture.test" || items[0].SiteDomains.Redirects != 2 {
		t.Fatalf("list %v %+v", err, items)
	}
	read, err := s.siteDomains(ctx, live.Account.ID)
	if err != nil || len(read.Domains.Redirects) != 2 || read.Account.Revision != got.Account.Revision {
		t.Fatalf("read %v %+v", err, read)
	}

	// The same set again changes nothing.
	again := in
	again.ExpectedRevision = got.Account.Revision
	if same, err := s.setSiteDomains(ctx, live.Account.ID, again, "test operator"); err != nil || same.Account.Revision != got.Account.Revision {
		t.Fatalf("unchanged set: %v %+v", err, same.Account)
	}
	// Removing them all is a change like any other.
	cleared, err := s.setSiteDomains(ctx, live.Account.ID, SiteDomainsInput{Aliases: []string{}, Redirects: []SiteRedirect{}, ExpectedRevision: got.Account.Revision, Reason: "Domains removed"}, "test operator")
	if err != nil || cleared.Account.SiteDomains != nil || len(siteOf(t, f.sites, live.Account.ID).Domains) != 1 || recordFor(t, s, live.Account.ID).Domains != "" {
		t.Fatalf("clear: %v %+v", err, cleared)
	}
}

func TestSiteDomainsRefusalsJournalNothing(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	before := recordFor(t, s, live.Account.ID)
	applies := f.siteApplies
	tooMany := []string{}
	for i := 0; i <= MaxSiteAliases; i++ {
		tooMany = append(tooMany, fmt.Sprintf("a%d.fixture.test", i))
	}
	manyRedirects := []SiteRedirect{}
	for i := 0; i <= MaxSiteRedirects; i++ {
		manyRedirects = append(manyRedirects, SiteRedirect{Path: fmt.Sprintf("/p%d", i), Target: "https://example.org/", Status: 301})
	}
	path := func(p, target string) SiteRedirect { return SiteRedirect{Path: p, Target: target, Status: 301} }
	cases := []struct {
		name string
		in   SiteDomainsInput
	}{
		{"the account's own domain", domainsInput(live, []string{"fixture.test"})},
		{"an alias twice", domainsInput(live, []string{"www.fixture.test", "www.fixture.test"})},
		{"an uppercase alias", domainsInput(live, []string{"Shop.fixture.test"})},
		{"an alias with a newline", domainsInput(live, []string{"shop.fixture.test\nlistener x {"})},
		{"an alias with a space", domainsInput(live, []string{"shop.fixture.test evil.test"})},
		{"a wildcard alias", domainsInput(live, []string{"*.fixture.test"})},
		{"an IP alias", domainsInput(live, []string{"192.0.2.1"})},
		{"a single label alias", domainsInput(live, []string{"localhost"})},
		{"www.www alias", domainsInput(live, []string{"www.www.fixture.test"})},
		{"www.tld alias", domainsInput(live, []string{"www.test"})},
		{"too many aliases", domainsInput(live, tooMany)},
		{"too many redirects", domainsInput(live, nil, manyRedirects...)},
		{"a target with a newline", domainsInput(live, nil, path("/a", "https://fixture.test/\nRewriteRule .* - [F]"))},
		{"a target with flags", domainsInput(live, nil, path("/a", "https://fixture.test/ [R=302,L]"))},
		{"a target with a back-reference", domainsInput(live, nil, path("/a", "https://fixture.test/$1"))},
		{"a target with a variable", domainsInput(live, nil, path("/a", "https://fixture.test/%{HTTP_COOKIE}"))},
		{"a target that ends the rules", domainsInput(live, nil, path("/a", "https://fixture.test/\n  END_rules\n}"))},
		{"a javascript target", domainsInput(live, nil, path("/a", "javascript:alert(1)"))},
		{"a relative target", domainsInput(live, nil, path("/a", "/b"))},
		{"a path pattern", domainsInput(live, nil, path("/a.*", "https://example.org/"))},
		{"the challenge path", domainsInput(live, nil, path("/.well-known/acme-challenge/x", "https://example.org/"))},
		{"a path to itself", domainsInput(live, nil, path("/a", "https://fixture.test/a"))},
		{"status 307", domainsInput(live, nil, SiteRedirect{Path: "/a", Target: "https://example.org/", Status: 307})},
		{"a domain that is not the site's", domainsInput(live, nil, SiteRedirect{Domain: "other.test", Target: "https://fixture.test", Status: 301})},
		{"a domain redirect with a path", domainsInput(live, []string{"www.fixture.test"}, SiteRedirect{Domain: "www.fixture.test", Target: "https://fixture.test/", Status: 301})},
		{"a domain redirect loop", domainsInput(live, []string{"www.fixture.test"}, SiteRedirect{Domain: "www.fixture.test", Target: "https://fixture.test", Status: 301}, SiteRedirect{Domain: "fixture.test", Target: "https://www.fixture.test", Status: 301})},
		{"no aliases list", SiteDomainsInput{Redirects: []SiteRedirect{}, ExpectedRevision: live.Account.Revision, Reason: "x"}},
		{"no reason", SiteDomainsInput{Aliases: []string{}, Redirects: []SiteRedirect{}, ExpectedRevision: live.Account.Revision}},
	}
	for _, c := range cases {
		if _, err := s.setSiteDomains(ctx, live.Account.ID, c.in, "test operator"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	stale := domainsInput(live, []string{"www.fixture.test"})
	stale.ExpectedRevision++
	if _, err := s.setSiteDomains(ctx, live.Account.ID, stale, "test operator"); !errors.Is(err, ErrConflict) {
		t.Errorf("stale revision: %v", err)
	}
	if after := recordFor(t, s, live.Account.ID); after != before || f.siteApplies != applies {
		t.Fatalf("a refusal changed the record or the config: %+v, %d applies", after, f.siteApplies-applies)
	}
	// Without the web operation, and for an account with no live site.
	plain := createFixtureNamed(t, s, "plainacct", "plain.test")
	if _, err := s.setSiteDomains(ctx, plain.ID, SiteDomainsInput{Aliases: []string{"www.plain.test"}, Redirects: []SiteRedirect{}, ExpectedRevision: plain.Revision, Reason: "x"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Errorf("no live site: %v", err)
	}
	s.web = nil
	if _, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(live, []string{"www.fixture.test"}), "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("web operation off: %v", err)
	}
}

// TestSiteDomainsClashAcrossAccounts: a domain belongs to one account. Its
// www. form counts as the same name, because OpenLiteSpeed maps it so.
func TestSiteDomainsClashAcrossAccounts(t *testing.T) {
	s, _ := webStore(t)
	ctx := context.Background()
	live := liveFixture(t, s)
	other := createFixtureNamed(t, s, "otheracct", "other.test")
	if _, err := s.setWeb(ctx, other.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: other.Revision, Reason: "Go live"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	otherRecord := recordFor(t, s, other.ID)
	if _, err := s.setSiteDomains(ctx, other.ID, domainsInput(otherRecord, []string{"alias.other.test"}), "test operator"); err != nil {
		t.Fatal(err)
	}
	for _, taken := range []string{"other.test", "www.other.test", "alias.other.test", "www.alias.other.test"} {
		if _, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(live, []string{taken}), "test operator"); !errors.Is(err, ErrDomainTaken) || !errors.Is(err, ErrConflict) {
			t.Errorf("%s: %v", taken, err)
		}
	}
	// A new account cannot take another's alias or its www. form either.
	for _, domain := range []string{"alias.other.test", "www.other.test"} {
		if _, err := s.create(ctx, CreateInput{Username: "thirdacct", Domain: domain, Reason: "x"}, "test operator"); !errors.Is(err, ErrConflict) {
			t.Errorf("create %s: %v", domain, err)
		}
	}
	// Once the other account lets the alias go, it can move.
	otherRecord = recordFor(t, s, other.ID)
	if _, err := s.setSiteDomains(ctx, other.ID, domainsInput(otherRecord, nil), "test operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(live, []string{"alias.other.test"}), "test operator"); err != nil {
		t.Fatalf("freed alias: %v", err)
	}
}

func TestSiteDomainsRejectedConfigChangesNothing(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	f.failure = "sites-reject"
	if _, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(live, []string{"www.fixture.test"}), "test operator"); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("rejected config: %v", err)
	}
	r := recordFor(t, s, live.Account.ID)
	if r.Pending != nil || r.Domains != "" || r.DomainsNext != "" || r.Account != live.Account {
		t.Fatalf("a rejected change left %+v", r)
	}
	if h := historyActions(t, s, live.Account.ID); h[len(h)-1] != "domains:rejected" {
		t.Fatalf("journal %v", h)
	}
	// The next change works: nothing was left pending.
	f.failure = ""
	if _, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(r, []string{"www.fixture.test"}), "test operator"); err != nil {
		t.Fatal(err)
	}
}

func TestSiteDomainsInterruptedApplyIsFinishedByRefresh(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	f.failure = "sites"
	if _, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(live, []string{"www.fixture.test"}), "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	r := recordFor(t, s, live.Account.ID)
	if r.Pending == nil || r.Pending.Action != "domains" || r.DomainsNext == "" || r.Domains != "" {
		t.Fatalf("pending domains op not durable: %+v", r)
	}
	// Every other mutation waits for it.
	if _, err := s.setWeb(ctx, live.Account.ID, WebInput{PHPVersion: "8.4", QuotaMiB: 200, ExpectedRevision: r.Account.Revision, Reason: "x"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("a mutation during a pending domains op: %v", err)
	}
	f.failure = ""
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r = recordFor(t, s, live.Account.ID)
	if r.Pending != nil || r.DomainsNext != "" || r.Account.Revision != live.Account.Revision+1 {
		t.Fatalf("refresh did not finish the domains op: %+v", r)
	}
	if d, _ := decodeSiteDomains(r.Domains); strings.Join(d.Aliases, ",") != "www.fixture.test" {
		t.Fatalf("finished set %q", r.Domains)
	}
	if h := historyActions(t, s, live.Account.ID); h[len(h)-1] != "domains:reconciled" {
		t.Fatalf("journal %v", h)
	}
	if site := siteOf(t, f.sites, live.Account.ID); strings.Join(site.Domains, ",") != "fixture.test,www.fixture.test" {
		t.Fatalf("site %+v", site)
	}
}

func TestSiteDomainsRecoveryCanEndRejected(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	f.failure = "sites"
	if _, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(live, []string{"www.fixture.test"}), "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	f.failure = "sites-reject"
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r := recordFor(t, s, live.Account.ID)
	if r.Pending != nil || r.Domains != "" || r.DomainsNext != "" || r.Account.Revision != live.Account.Revision {
		t.Fatalf("a recovery that failed its test must end rejected and unchanged: %+v", r)
	}
}

// TestSiteDomainsSuspendedSiteServesNothing: a suspended site keeps its
// suspended rendering, so its aliases answer 403 and it redirects nothing.
func TestSiteDomainsSuspendedSiteServesNothing(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	got, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(live, []string{"www.fixture.test"}, SiteRedirect{Path: "/a", Target: "https://example.org/b", Status: 302}), "test operator")
	if err != nil {
		t.Fatal(err)
	}
	suspended, err := s.setState(ctx, live.Account.ID, StateInput{State: "suspended", ExpectedRevision: got.Account.Revision, Reason: "Suspend"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	files, err := renderUnderHome(f.sites)
	if err != nil {
		t.Fatal(err)
	}
	vh := string(files[olsweb.VhostConfigPath(siteName(live.Account.ID))])
	if strings.Contains(vh, "R=302") || !strings.Contains(vh, "RewriteRule .* - [F,L]") || strings.Contains(vh, live.Account.PublicHTML) {
		t.Fatalf("suspended vhost:\n%s", vh)
	}
	// A suspended site's domains do not change.
	if _, err := s.setSiteDomains(ctx, live.Account.ID, SiteDomainsInput{Aliases: []string{}, Redirects: []SiteRedirect{}, ExpectedRevision: suspended.Revision, Reason: "x"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("change of a suspended site: %v", err)
	}
}

func TestSiteDomainsStoredFormIsChecked(t *testing.T) {
	s, _ := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	if _, err := s.setSiteDomains(ctx, live.Account.ID, domainsInput(live, []string{"www.fixture.test"}), "test operator"); err != nil {
		t.Fatal(err)
	}
	good := recordFor(t, s, live.Account.ID)
	for name, edit := range map[string]func(*record){
		"not canonical":    func(r *record) { r.Domains = `{"redirects":[],"aliases":["www.fixture.test"]}` },
		"an invalid alias": func(r *record) { r.Domains = `{"aliases":["bad domain"],"redirects":[]}` },
		"an injected target": func(r *record) {
			r.Domains = `{"aliases":[],"redirects":[{"path":"/a","target":"https://x.test/ [L]","status":301}]}`
		},
		"a next set without op":   func(r *record) { r.DomainsNext = good.Domains },
		"a listed summary stored": func(r *record) { r.Account.SiteDomains = &SiteDomainsSummary{Aliases: []string{}} },
	} {
		r := good
		edit(&r)
		if err := s.save(r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.list(ctx); !errors.Is(err, ErrRecovery) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.save(good); err != nil {
		t.Fatal(err)
	}
	if _, err := s.list(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestSiteDomainsLargestSetFitsTheRecord: the most aliases and redirects of
// the longest kind still make a record the store reads back.
func TestSiteDomainsLargestSetFitsTheRecord(t *testing.T) {
	label := strings.Repeat("a", 60)
	aliases := []string{}
	for i := 0; i < MaxSiteAliases; i++ {
		aliases = append(aliases, fmt.Sprintf("%s.%s.%s.%s%02d.test", label, label, label, label[:50], i))
	}
	redirects := []SiteRedirect{}
	target := "https://" + label + ".test/" + strings.Repeat("&", olsweb.MaxRedirectTargetBytes-len("https://"+label+".test/"))
	for i := 0; i < MaxSiteRedirects; i++ {
		p := fmt.Sprintf("/%03d", i) + strings.Repeat("p", olsweb.MaxRedirectPathBytes-4)
		redirects = append(redirects, SiteRedirect{Path: p, Target: target, Status: 301})
	}
	d := normalizeSiteDomains(SiteDomains{Aliases: aliases, Redirects: redirects})
	if !validSiteDomains("fixture.test", d) {
		t.Fatal("the largest set is not valid")
	}
	// Ampersands are the worst case: the record's JSON escapes each one.
	if encoded := encodeSiteDomains(d); siteDomainsSized(encoded) {
		t.Fatalf("a set of %d bytes in the record is accepted", len(encoded))
	}
	plain := strings.ReplaceAll(target, "&", "a")
	for i := range d.Redirects {
		d.Redirects[i].Target = plain
	}
	encoded := encodeSiteDomains(d)
	if !siteDomainsSized(encoded) {
		t.Fatalf("the largest plain set (%d bytes) does not fit", len(encoded))
	}
	r := record{Domains: encoded, DomainsNext: encoded, SSHKeys: strings.Repeat("k", MaxSSHKeys*maxSSHKeyLine)}
	if raw, _ := json.Marshal(r); len(raw) > maxRecordBytes {
		t.Fatalf("a record with two sets is %d bytes, more than %d", len(raw), maxRecordBytes)
	}
}

func TestSiteDomainsHTTP(t *testing.T) {
	s, _ := webStore(t)
	live := liveFixture(t, s)
	post := func(body string) (int, string) {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+live.Account.ID+"/domains", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(s).ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	rev := live.Account.Revision
	wrap := func(input string) string {
		return `{"input":` + input + `,"actor":"test operator"}`
	}
	for name, body := range map[string]string{
		"aliases left out":         wrap(fmt.Sprintf(`{"redirects":[],"expected_revision":%d,"reason":"x"}`, rev)),
		"redirects left out":       wrap(fmt.Sprintf(`{"aliases":[],"expected_revision":%d,"reason":"x"}`, rev)),
		"aliases null":             wrap(fmt.Sprintf(`{"aliases":null,"redirects":[],"expected_revision":%d,"reason":"x"}`, rev)),
		"an unknown redirect key":  wrap(fmt.Sprintf(`{"aliases":[],"redirects":[{"path":"/a","target":"https://x.test/","status":301,"flags":"L"}],"expected_revision":%d,"reason":"x"}`, rev)),
		"a redirect key twice":     wrap(fmt.Sprintf(`{"aliases":[],"redirects":[{"path":"/a","path":"/b","target":"https://x.test/","status":301}],"expected_revision":%d,"reason":"x"}`, rev)),
		"a redirect key in case":   wrap(fmt.Sprintf(`{"aliases":[],"redirects":[{"Path":"/a","target":"https://x.test/","status":301}],"expected_revision":%d,"reason":"x"}`, rev)),
		"a status as text":         wrap(fmt.Sprintf(`{"aliases":[],"redirects":[{"path":"/a","target":"https://x.test/","status":"301"}],"expected_revision":%d,"reason":"x"}`, rev)),
		"a null redirect":          wrap(fmt.Sprintf(`{"aliases":[],"redirects":[null],"expected_revision":%d,"reason":"x"}`, rev)),
		"an injected target":       wrap(fmt.Sprintf(`{"aliases":[],"redirects":[{"path":"/a","target":"https://x.test/\nRewriteRule .* - [F]","status":301}],"expected_revision":%d,"reason":"x"}`, rev)),
		"an unknown input key":     wrap(fmt.Sprintf(`{"aliases":[],"redirects":[],"rules":"x","expected_revision":%d,"reason":"x"}`, rev)),
		"an alias that is invalid": wrap(fmt.Sprintf(`{"aliases":["bad domain"],"redirects":[],"expected_revision":%d,"reason":"x"}`, rev)),
	} {
		if code, out := post(body); code != 400 || !strings.Contains(out, `"invalid"`) {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	other := createFixtureNamed(t, s, "otheracct", "other.test")
	_ = other
	if code, out := post(wrap(fmt.Sprintf(`{"aliases":["www.other.test"],"redirects":[],"expected_revision":%d,"reason":"x"}`, rev))); code != 409 || !strings.Contains(out, `"domain_taken"`) {
		t.Fatalf("taken: %d %s", code, out)
	}
	code, out := post(wrap(fmt.Sprintf(`{"aliases":["www.fixture.test"],"redirects":[{"domain":"www.fixture.test","target":"https://fixture.test","status":301}],"expected_revision":%d,"reason":"x"}`, rev)))
	if code != 200 || !strings.Contains(out, `"aliases":["www.fixture.test"]`) {
		t.Fatalf("good: %d %s", code, out)
	}
	req := httptest.NewRequest("GET", "http://unix/v1/accounts/"+live.Account.ID+"/domains", nil)
	w := httptest.NewRecorder()
	handler(s).ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"redirects":[{"domain":"www.fixture.test","target":"https://fixture.test","status":301}]`) {
		t.Fatalf("read: %d %s", w.Code, w.Body.String())
	}
}
