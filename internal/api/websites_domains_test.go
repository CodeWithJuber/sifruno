package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/acme"
	"sifruno/internal/hostaccounts"
)

// domainsBroker adds the domains operation to sitesBroker, keeping each
// account's set as the broker would and its summary on the listed account.
type domainsBroker struct {
	*sitesBroker
	mu   sync.Mutex
	sets map[string]hostaccounts.SiteDomains
	// readErr fails the read of a site's set.
	readErr error
}

func (b *domainsBroker) SiteDomains(_ context.Context, id string) (hostaccounts.SiteDomainsResult, error) {
	if b.readErr != nil {
		return hostaccounts.SiteDomainsResult{}, b.readErr
	}
	accounts, _ := b.List(context.Background())
	for _, a := range accounts {
		if a.ID == id {
			b.mu.Lock()
			defer b.mu.Unlock()
			set, ok := b.sets[id]
			if !ok {
				set = hostaccounts.SiteDomains{Aliases: []string{}, Redirects: []hostaccounts.SiteRedirect{}}
			}
			return hostaccounts.SiteDomainsResult{Account: a, Domains: set}, nil
		}
	}
	return hostaccounts.SiteDomainsResult{}, hostaccounts.ErrNotFound
}

func (b *domainsBroker) SetSiteDomains(_ context.Context, id string, in hostaccounts.SiteDomainsInput, actor string) (hostaccounts.SiteDomainsResult, error) {
	accounts, _ := b.List(context.Background())
	for _, a := range accounts {
		for _, alias := range in.Aliases {
			if a.ID != id && sameHost(a, alias) {
				return hostaccounts.SiteDomainsResult{}, hostaccounts.ErrDomainTaken
			}
		}
	}
	set := hostaccounts.SiteDomains{Aliases: slices.Sorted(slices.Values(in.Aliases)), Redirects: slices.Clone(in.Redirects)}
	routes := []string{}
	for _, r := range set.Redirects {
		routes = append(routes, fmt.Sprintf("%s%s>%s:%d", r.Domain, r.Path, r.Target, r.Status))
	}
	call := fmt.Sprintf("domains %s aliases=%s redirects=%s rev=%d reason=%q actor=%s", id, strings.Join(set.Aliases, ","), strings.Join(routes, ","), in.ExpectedRevision, in.Reason, actor)
	a, err := b.changed(call, id, in.ExpectedRevision, func(a *hostaccounts.Account) {
		a.SiteDomains = &hostaccounts.SiteDomainsSummary{Aliases: set.Aliases, Redirects: len(set.Redirects)}
	})
	if err != nil {
		return hostaccounts.SiteDomainsResult{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sets == nil {
		b.sets = map[string]hostaccounts.SiteDomains{}
	}
	b.sets[id] = set
	return hostaccounts.SiteDomainsResult{Account: a, Domains: set}, nil
}

type certificatesFake struct {
	mu        sync.Mutex
	refreshed []acme.Site
	waiting   map[string][]string
	done      chan struct{}
}

func (c *certificatesFake) Refresh(_ context.Context, s acme.Site) error {
	c.mu.Lock()
	c.refreshed = append(c.refreshed, s)
	c.mu.Unlock()
	c.done <- struct{}{}
	return nil
}

func (c *certificatesFake) Waiting(id string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.waiting[id]
}

func (c *certificatesFake) last(t *testing.T) acme.Site {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("no certificate refresh after a domain change")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshed[len(c.refreshed)-1]
}

func domainsFixture(t *testing.T) (siteFixture, *domainsBroker, *certificatesFake, Website, Website) {
	t.Helper()
	f, runner, broker, _, site := actionsFixture(t)
	other := makeSite(t, runner, "other.example", "8.3")
	d := &domainsBroker{sitesBroker: broker}
	certs := &certificatesFake{waiting: map[string][]string{}, done: make(chan struct{}, 10)}
	f.handler = New(Options{Operator: f.manager, Accounts: d, Wizard: runner, Certificates: certs, PanelHosts: []string{"panel.example.org"}, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	broker.mu.Lock()
	broker.changes = nil
	otherAccount := broker.accounts[1]
	broker.mu.Unlock()
	return f, d, certs, site, website(otherAccount, other, nil)
}

func TestWebsiteDomainAddAndRemove(t *testing.T) {
	f, broker, certs, site, other := domainsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	post := func(action string, body map[string]any) WebsiteDetail {
		t.Helper()
		return decodeDetail(t, websiteRequest(f.handler, "POST", sitePath(site, action), body, cookie, csrf))
	}
	got := post("domain-add", map[string]any{"domain": " WWW.Example.com ", "expected_revision": site.Revision})
	if len(got.Aliases) != 1 || got.Aliases[0] != (WebsiteDomain{Name: "www.example.com", HTTPS: "pending"}) || got.Revision != site.Revision+1 || len(got.Redirects) != 0 {
		t.Fatalf("after adding %+v", got)
	}
	want := fmt.Sprintf(`domains %s aliases=www.example.com redirects= rev=%d reason="Domain www.example.com added on the website's page" actor=local-operator`, site.AccountID, site.Revision)
	if !slices.Equal(broker.changes, []string{want}) {
		t.Fatalf("broker changes %q", broker.changes)
	}
	// HTTPS for the new set is asked for in the background.
	if s := certs.last(t); s.AccountID != site.AccountID || s.Domain != "example.com" || !slices.Equal(s.Aliases, []string{"www.example.com"}) || s.Revision != got.Revision || !s.Active {
		t.Fatalf("refresh %+v", s)
	}
	site = got.Website

	// The list and the read show the aliases, with what covers each.
	broker.change(site.AccountID, func(a *hostaccounts.Account) {
		a.Certificate = hostaccounts.CertificateState{NotAfter: 1803311049, Fingerprint: strings.Repeat("ab", 32), Names: "example.com,www.example.com"}
	})
	got = post("domain-add", map[string]any{"domain": "nodns.example.com", "expected_revision": site.Revision})
	certs.last(t)
	certs.mu.Lock()
	certs.waiting[site.AccountID] = []string{"nodns.example.com"}
	certs.mu.Unlock()
	sites := decodeSites(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "").Body.Bytes())
	i := slices.IndexFunc(sites, func(s Website) bool { return s.AccountID == site.AccountID })
	if i < 0 || !slices.Equal(sites[i].Aliases, []WebsiteDomain{{Name: "nodns.example.com", HTTPS: "waiting_for_dns"}, {Name: "www.example.com", HTTPS: "on"}}) || sites[i].RedirectCount != 0 {
		t.Fatalf("listed %+v", sites)
	}
	site = got.Website

	// Refused by the panel, before the broker is asked to change anything.
	before := len(broker.changes)
	for name, tc := range map[string]struct {
		domain string
		status int
		detail string
	}{
		"not a domain":        {"not a domain", 422, domainForm},
		"one label":           {"localhost", 422, domainForm},
		"an IP address":       {"192.0.2.1", 422, domainForm},
		"a wildcard":          {"*.example.com", 422, domainForm},
		"www.www":             {"www.www.example.com", 422, domainForm},
		"a newline":           {"shop.example.com\nlistener x {", 422, domainForm},
		"the main domain":     {"example.com", 422, "example.com is already this website's main domain."},
		"already an alias":    {"www.example.com", 422, "www.example.com is already a domain of this website."},
		"the panel's address": {"panel.example.org", 422, panelHostTaken},
		"the panel's www":     {"www.panel.example.org", 422, panelHostTaken},
	} {
		w := websiteRequest(f.handler, "POST", sitePath(site, "domain-add"), map[string]any{"domain": tc.domain, "expected_revision": site.Revision}, cookie, csrf)
		if w.Code != tc.status || problemDetail(t, w) != tc.detail {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if len(broker.changes) != before {
		t.Fatalf("a refusal reached the broker: %q", broker.changes[before:])
	}
	// Another website's domain, or its www. form: the broker refuses, and
	// the panel names the site that has it.
	for taken, detail := range map[string]string{
		"other.example":     "other.example already belongs to another website on this server. A domain can belong to one website only: remove it there first.",
		"www.other.example": "www.other.example already belongs to another website on this server, other.example. A domain can belong to one website only: remove it there first.",
	} {
		w := websiteRequest(f.handler, "POST", sitePath(site, "domain-add"), map[string]any{"domain": taken, "expected_revision": site.Revision}, cookie, csrf)
		if w.Code != 409 || problemDetail(t, w) != detail || !strings.HasPrefix(problemTechnical(t, w), "account service: ") {
			t.Errorf("%s: %d %s", taken, w.Code, w.Body.String())
		}
	}
	_ = other
	// A stale page changes nothing.
	w := websiteRequest(f.handler, "POST", sitePath(site, "domain-add"), map[string]any{"domain": "shop.example.com", "expected_revision": site.Revision - 1}, cookie, csrf)
	if w.Code != 409 || problemDetail(t, w) != websiteStale {
		t.Fatalf("stale: %d %s", w.Code, w.Body.String())
	}

	// Removing a domain takes its whole-domain redirect with it.
	got = post("redirect-add", map[string]any{"from": "www.example.com", "to": "https://example.com/", "status": 301, "expected_revision": site.Revision})
	if !slices.Equal(got.Redirects, []WebsiteRedirect{{From: "www.example.com", To: "https://example.com", Status: 301}}) || got.RedirectCount != 1 {
		t.Fatalf("domain redirect %+v", got.Redirects)
	}
	site = got.Website
	got = post("domain-remove", map[string]any{"domain": "www.example.com", "expected_revision": site.Revision})
	if !slices.Equal(got.Aliases, []WebsiteDomain{{Name: "nodns.example.com", HTTPS: "waiting_for_dns"}}) || len(got.Redirects) != 0 || got.RedirectCount != 0 {
		t.Fatalf("after removing %+v", got)
	}
	certs.last(t)
	site = got.Website
	for name, tc := range map[string]struct {
		domain string
		status int
	}{
		"the main domain":    {"example.com", 422},
		"not a domain of it": {"www.example.com", 409},
		"another's domain":   {"other.example", 409},
	} {
		w := websiteRequest(f.handler, "POST", sitePath(site, "domain-remove"), map[string]any{"domain": tc.domain, "expected_revision": site.Revision}, cookie, csrf)
		if w.Code != tc.status {
			t.Errorf("remove %s: %d %s", name, w.Code, w.Body.String())
		}
	}
}

func TestWebsiteRedirects(t *testing.T) {
	f, broker, certs, site, _ := domainsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	post := func(action string, body map[string]any) WebsiteDetail {
		t.Helper()
		return decodeDetail(t, websiteRequest(f.handler, "POST", sitePath(site, action), body, cookie, csrf))
	}
	got := post("domain-add", map[string]any{"domain": "www.example.com", "expected_revision": site.Revision})
	certs.last(t)
	site = got.Website
	got = post("redirect-add", map[string]any{"from": "/old-page", "to": "https://example.com/new-page?from=old&x=1", "status": 301, "expected_revision": site.Revision})
	if !slices.Equal(got.Redirects, []WebsiteRedirect{{From: "/old-page", To: "https://example.com/new-page?from=old&x=1", Status: 301}}) {
		t.Fatalf("path redirect %+v", got.Redirects)
	}
	site = got.Website
	// A redirect needs no new certificate.
	select {
	case <-certs.done:
		t.Fatal("a redirect asked for a certificate")
	default:
	}
	got = post("redirect-add", map[string]any{"from": "www.example.com", "to": "https://example.com", "status": 302, "expected_revision": site.Revision})
	site = got.Website
	if len(got.Redirects) != 2 {
		t.Fatalf("redirects %+v", got.Redirects)
	}
	// The site's read lists them; the list counts them.
	one := decodeDetail(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID, nil, cookie, ""))
	if len(one.Redirects) != 2 || one.RedirectCount != 2 {
		t.Fatalf("read %+v", one)
	}
	broker.readErr = hostaccounts.ErrUnavailable
	one = decodeDetail(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID, nil, cookie, ""))
	if len(one.Redirects) != 0 || one.RedirectCount != 2 {
		t.Fatalf("read without the broker's redirects %+v", one)
	}
	broker.readErr = nil

	before := len(broker.changes)
	for name, tc := range map[string]struct {
		from, to string
		status   any
		code     int
		detail   string
	}{
		"a newline in the address": {"/a", "https://example.com/\nRewriteRule .* - [F]", 301, 422, redirectTargetForm},
		"flags in the address":     {"/a", "https://example.com/ [R=302,L]", 301, 422, redirectTargetForm},
		"a back-reference":         {"/a", "https://example.com/$1", 301, 422, redirectTargetForm},
		"a server variable":        {"/a", "https://example.com/%{HTTP_COOKIE}", 301, 422, redirectTargetForm},
		"the end of the rules":     {"/a", "https://example.com/\n  END_rules\n}", 301, 422, redirectTargetForm},
		"a javascript address":     {"/a", "javascript:alert(1)", 301, 422, redirectTargetForm},
		"a relative address":       {"/a", "/b", 301, 422, redirectTargetForm},
		"a quote":                  {"/a", `https://example.com/"x`, 301, 422, redirectTargetForm},
		"a pattern as the path":    {"/a.*", "https://example.org/", 301, 422, redirectPathForm},
		"a space in the path":      {"/a b", "https://example.org/", 301, 422, redirectPathForm},
		"the challenge path":       {"/.well-known/acme-challenge/x", "https://example.org/", 301, 422, redirectPathForm},
		"a newline in the path":    {"/a\nRewriteRule", "https://example.org/", 301, 422, redirectPathForm},
		"a path twice":             {"/old-page", "https://example.org/", 301, 422, "There is already a redirect from /old-page. Remove it first to change where it goes."},
		"a domain with a path":     {"example.com", "https://example.org/start", 301, 422, redirectDomainTo},
		"a domain twice":           {"www.example.com", "https://example.org", 301, 422, "www.example.com is already redirected. Remove that redirect first to change where it goes."},
		"a domain not of the site": {"other.example", "https://example.org", 301, 422, "other.example is not a path or a domain of this website. A path starts with /; to redirect another domain, add it to the website first."},
		"a loop":                   {"example.com", "https://www.example.com", 301, 422, redirectLoop},
		"to the same path":         {"/a", "https://www.example.com/a", 301, 422, redirectLoop},
		"status 307":               {"/a", "https://example.org/", 307, 422, "status must be 301 (moved for good) or 302 (moved for now)."},
		"status as text":           {"/a", "https://example.org/", "301", 422, "status must be a whole number."},
	} {
		w := websiteRequest(f.handler, "POST", sitePath(site, "redirect-add"), map[string]any{"from": tc.from, "to": tc.to, "status": tc.status, "expected_revision": site.Revision}, cookie, csrf)
		if w.Code != tc.code || problemDetail(t, w) != tc.detail {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	// Keys the form does not use are refused before anything is read.
	w := websiteRequest(f.handler, "POST", sitePath(site, "redirect-add"), map[string]any{"from": "/a", "to": "https://example.org/", "status": 301, "flags": "L", "expected_revision": site.Revision}, cookie, csrf)
	if w.Code != 422 || !strings.Contains(problemDetail(t, w), "Send only from, to, status and expected_revision") {
		t.Fatalf("extra key: %d %s", w.Code, w.Body.String())
	}
	if len(broker.changes) != before {
		t.Fatalf("a refusal reached the broker: %q", broker.changes[before:])
	}

	got = post("redirect-remove", map[string]any{"from": "/old-page", "expected_revision": site.Revision})
	if !slices.Equal(got.Redirects, []WebsiteRedirect{{From: "www.example.com", To: "https://example.com", Status: 302}}) {
		t.Fatalf("after removing %+v", got.Redirects)
	}
	site = got.Website
	w = websiteRequest(f.handler, "POST", sitePath(site, "redirect-remove"), map[string]any{"from": "/old-page", "expected_revision": site.Revision}, cookie, csrf)
	if w.Code != 409 || problemDetail(t, w) != "This website has no redirect from /old-page. Reload the page to see its redirects." {
		t.Fatalf("removing twice: %d %s", w.Code, w.Body.String())
	}

	// A suspended site keeps its domains and redirects as they are.
	broker.change(site.AccountID, func(a *hostaccounts.Account) { a.State = "suspended" })
	w = websiteRequest(f.handler, "POST", sitePath(site, "redirect-add"), map[string]any{"from": "/b", "to": "https://example.org/", "status": 301, "expected_revision": site.Revision}, cookie, csrf)
	if w.Code != 409 || problemDetail(t, w) != domainsNotActive {
		t.Fatalf("suspended: %d %s", w.Code, w.Body.String())
	}
	// The broker's config test is the judge: a refusal is a plain error.
	broker.change(site.AccountID, func(a *hostaccounts.Account) { a.State = "active" })
	broker.changeErr = hostaccounts.ErrWebRejected
	w = websiteRequest(f.handler, "POST", sitePath(site, "redirect-add"), map[string]any{"from": "/b", "to": "https://example.org/", "status": 301, "expected_revision": site.Revision}, cookie, csrf)
	if w.Code != 422 || !strings.HasPrefix(problemDetail(t, w), "The web server's configuration test failed with this change, so nothing changed.") {
		t.Fatalf("rejected: %d %s", w.Code, w.Body.String())
	}
}

// Without the domains operation the routes say so, and change nothing.
func TestWebsiteDomainsNeedTheOperation(t *testing.T) {
	f, _, broker, _, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "POST", sitePath(site, "domain-add"), map[string]any{"domain": "www.example.com", "expected_revision": site.Revision}, cookie, csrf)
	if w.Code != 503 || problemDetail(t, w) != domainsNotSetUp || len(broker.changes) != 0 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Without a session nothing is read.
	w = websiteRequest(f.handler, "POST", sitePath(site, "domain-add"), map[string]any{"domain": "www.example.com", "expected_revision": site.Revision}, nil, "")
	if w.Code != 401 {
		t.Fatalf("no session: %d", w.Code)
	}
}
