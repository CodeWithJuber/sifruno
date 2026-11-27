package api

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/acme"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/olsweb"
)

// A website's other domains (aliases, which serve the same site), its
// redirects and its "Always use HTTPS". The account broker records and
// renders them; the panel checks the request, names the reason in plain
// words, and after a domain change asks for a certificate that covers the
// new set.

// SiteCertificates gets the websites' certificates; nil in Options when
// they are not set up. *acme.Manager is the real one.
type SiteCertificates interface {
	// Refresh asks for a certificate naming the site's domain and those of
	// its aliases that reach this server, when that changes what it names.
	Refresh(ctx context.Context, s acme.Site) error
	// Waiting names the aliases the last request left out because they did
	// not reach this server.
	Waiting(accountID string) []string
	// CopiedUntil answers the expiry of the certificate copied from the
	// site's old server when it moved here, while it is the one installed.
	CopiedUntil(accountID string) (time.Time, bool)
}

// WebsiteDomain is one of a website's other domains.
type WebsiteDomain struct {
	Name  string `json:"name"`
	HTTPS string `json:"https" enum:"on,waiting_for_dns,pending,off" doc:"on: the site's certificate covers it. waiting_for_dns: the last certificate request left it out because it does not reach this server yet; it needs the same DNS record as the site's domain. pending: no certificate covers it yet; the panel asks for one after a change and when its renewal check runs. off: website certificates are not set up on this server."`
}

// WebsiteRedirect is one redirect of a website.
type WebsiteRedirect struct {
	From   string `json:"from" doc:"A path such as /old-page, redirected on every domain of the site; or one of the site's domains, redirected whole with its path and query kept."`
	To     string `json:"to" doc:"Where visitors go: http:// or https:// and a domain, then for a path an optional path and query."`
	Status int    `json:"status" enum:"301,302" doc:"301 moved for good (browsers and search engines remember it), 302 moved for now."`
}

type websiteDomainBody struct {
	Domain           string `json:"domain" maxLength:"253" doc:"The domain, such as www.example.com or example.net."`
	ExpectedRevision uint64 `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}
type websiteRedirectBody struct {
	From             string `json:"from" maxLength:"253" doc:"A path that starts with /, or one of the site's domains."`
	To               string `json:"to" maxLength:"256" doc:"Where visitors go, starting with http:// or https://."`
	Status           int    `json:"status" enum:"301,302" doc:"301 or 302."`
	ExpectedRevision uint64 `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}
type websiteRedirectRemoveBody struct {
	From             string `json:"from" maxLength:"253" doc:"The path or domain of the redirect to remove."`
	ExpectedRevision uint64 `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}
type websiteDomainInput struct {
	AccountID string `path:"account_id"`
	Body      websiteDomainBody
}
type websiteRedirectInput struct {
	AccountID string `path:"account_id"`
	Body      websiteRedirectBody
}
type websiteRedirectRemoveInput struct {
	AccountID string `path:"account_id"`
	Body      websiteRedirectRemoveBody
}

// websiteAlwaysHTTPSBody turns the site's "Always use HTTPS" on or off. The
// setting is a pointer so a body that leaves it out is refused, not read
// as off.
type websiteAlwaysHTTPSBody struct {
	AlwaysHTTPS      *bool  `json:"always_https" doc:"true: while the site is live with a certificate that has not expired, plain http for each domain the certificate covers answers 301 to the same address on https. false: plain http serves the site too. Kept with or without a certificate."`
	ExpectedRevision uint64 `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}
type websiteAlwaysHTTPSInput struct {
	AccountID string `path:"account_id"`
	Body      websiteAlwaysHTTPSBody
}

const (
	certificateRefreshLimit = 10 * time.Minute // issue (3 minutes) and install (up to 6)

	domainsNotSetUp    = "This server's account service cannot change a website's domains. Update and restart the account service, then try again."
	domainsNotActive   = "Only a live website can change its domains and redirects. Resume the website first."
	domainsUnreadable  = "The account service did not answer with this website's domains and redirects, so nothing changed. Reload the page and try again."
	domainForm         = "Enter a domain such as www.example.com or example.net: lowercase letters, digits and hyphens, in two or more parts separated by dots."
	redirectPathForm   = "The path to redirect must start with / and use only letters, digits and - . _ ~ /, at most 128 characters, with no part that starts with a dot. For example /old-page."
	redirectTargetForm = "The address must start with http:// or https://, then a domain name, and may go on with a path. It can use letters, digits and - . _ ~ / ? & = + , : ; @ only, at most 256 characters: no spaces, quotes, #, $ or %. For example https://example.com/new-page."
	redirectDomainTo   = "A whole domain is redirected with each visitor's path kept, so give only the address of the other domain, such as https://example.com, with no path after it."
	redirectLoop       = "This redirect would send visitors in a loop: to the same address, or to a domain that is redirected too. Choose another address."

	alwaysHTTPSNotSetUp  = "This server's account service cannot change Always use HTTPS. Update and restart the account service, then try again."
	alwaysHTTPSNotActive = "Only a live website can change Always use HTTPS. Resume the website first."
	alwaysHTTPSForm      = "always_https must be true or false."
)

// websiteAliases is the list entry's view of an account's aliases, each with
// what covers it, and how many redirects the site has.
func websiteAliases(a hostaccounts.Account, certs SiteCertificates) ([]WebsiteDomain, int) {
	out := []WebsiteDomain{}
	if a.SiteDomains == nil {
		return out, 0
	}
	covered := certificateNames(a.Certificate)
	var waiting []string
	if certs != nil {
		waiting = certs.Waiting(a.ID)
	}
	for _, alias := range a.SiteDomains.Aliases {
		state := "pending"
		switch {
		case slices.Contains(covered, alias):
			state = "on"
		case certs == nil:
			state = "off"
		case slices.Contains(waiting, alias):
			state = "waiting_for_dns"
		}
		out = append(out, WebsiteDomain{Name: alias, HTTPS: state})
	}
	return out, a.SiteDomains.Redirects
}

func certificateNames(c hostaccounts.CertificateState) []string {
	if c.Names == "" {
		return nil
	}
	return strings.Split(c.Names, ",")
}

// websiteRedirects reads a site's redirects for its page. A site with none
// needs no read; one the account service does not answer for is shown with
// none, and redirect_count still says how many it has.
func websiteRedirects(ctx context.Context, o Options, site Website) []WebsiteRedirect {
	out := []WebsiteRedirect{}
	service, ok := o.Accounts.(hostaccounts.SiteDomainsService)
	if !ok || site.RedirectCount == 0 || site.State == partlyDeleted {
		return out
	}
	read, err := service.SiteDomains(ctx, site.AccountID)
	if err != nil {
		return out
	}
	for _, r := range read.Domains.Redirects {
		out = append(out, apiRedirect(r))
	}
	return out
}

func apiRedirect(r hostaccounts.SiteRedirect) WebsiteRedirect {
	from := r.Path
	if r.Domain != "" {
		from = r.Domain
	}
	return WebsiteRedirect{From: from, To: r.Target, Status: r.Status}
}

// registerWebsiteDomains adds the site page's domain and redirect changes
// and its Always use HTTPS switch, under /api/v1/websites/ with the same
// admission as its other changes.
func registerWebsiteDomains(a huma.API, o Options) {
	change := func(id, action string) huma.Operation {
		return huma.Operation{OperationID: id, Method: "POST", Path: "/api/v1/websites/sites/{account_id}/" + action, MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	huma.Register(a, change("add-website-domain", "domain-add"), func(ctx context.Context, in *websiteDomainInput) (*websiteOutput, error) {
		t, err := domainsTarget(ctx, o, in.AccountID, in.Body.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		domain := strings.ToLower(strings.TrimSpace(in.Body.Domain))
		switch {
		case !validAliasDomain(domain):
			return nil, huma.Error422UnprocessableEntity(domainForm)
		case domain == t.account.Domain:
			return nil, huma.Error422UnprocessableEntity(domain + " is already this website's main domain.")
		case slices.Contains(t.domains.Aliases, domain):
			return nil, huma.Error422UnprocessableEntity(domain + " is already a domain of this website.")
		case panelHost(o.PanelHosts, domain):
			return nil, huma.Error422UnprocessableEntity(panelHostTaken)
		case len(t.domains.Aliases) >= hostaccounts.MaxSiteAliases:
			return nil, huma.Error422UnprocessableEntity("A website can have at most 15 other domains. Remove one first.")
		}
		next := t.domains
		next.Aliases = append(slices.Clone(next.Aliases), domain)
		return applyDomains(ctx, o, t, next, "Domain "+domain+" added on the website's page", domain, true)
	})
	huma.Register(a, change("remove-website-domain", "domain-remove"), func(ctx context.Context, in *websiteDomainInput) (*websiteOutput, error) {
		t, err := domainsTarget(ctx, o, in.AccountID, in.Body.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		domain := strings.ToLower(strings.TrimSpace(in.Body.Domain))
		if domain == t.account.Domain {
			return nil, huma.Error422UnprocessableEntity(domain + " is the website's main domain, so it cannot be removed. Delete the website to remove it.")
		}
		if !slices.Contains(t.domains.Aliases, domain) {
			return nil, huma.Error409Conflict(domain+" is not a domain of this website. Reload the page to see its domains.", errors.New("domain not among the site's aliases"))
		}
		// Its whole-domain redirect goes with it: it would redirect nothing.
		next := hostaccounts.SiteDomains{Aliases: slices.DeleteFunc(slices.Clone(t.domains.Aliases), func(d string) bool { return d == domain })}
		next.Redirects = slices.DeleteFunc(slices.Clone(t.domains.Redirects), func(r hostaccounts.SiteRedirect) bool { return r.Domain == domain })
		return applyDomains(ctx, o, t, next, "Domain "+domain+" removed on the website's page", domain, true)
	})
	huma.Register(a, change("add-website-redirect", "redirect-add"), func(ctx context.Context, in *websiteRedirectInput) (*websiteOutput, error) {
		t, err := domainsTarget(ctx, o, in.AccountID, in.Body.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		r, problem := redirectFrom(t, in.Body)
		if problem != nil {
			return nil, problem
		}
		next := t.domains
		next.Redirects = append(slices.Clone(next.Redirects), r)
		domains := append([]string{t.account.Domain}, next.Aliases...)
		if olsweb.CheckRedirects(domains, olswebRedirects(next.Redirects)) != nil {
			return nil, huma.Error422UnprocessableEntity(redirectLoop)
		}
		from := apiRedirect(r).From
		return applyDomains(ctx, o, t, next, "Redirect from "+from+" added on the website's page", from, false)
	})
	huma.Register(a, change("remove-website-redirect", "redirect-remove"), func(ctx context.Context, in *websiteRedirectRemoveInput) (*websiteOutput, error) {
		t, err := domainsTarget(ctx, o, in.AccountID, in.Body.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		from := strings.TrimSpace(in.Body.From)
		next := t.domains
		next.Redirects = slices.DeleteFunc(slices.Clone(next.Redirects), func(r hostaccounts.SiteRedirect) bool { return apiRedirect(r).From == from })
		if len(next.Redirects) == len(t.domains.Redirects) {
			return nil, huma.Error409Conflict("This website has no redirect from "+from+". Reload the page to see its redirects.", errors.New("redirect not found"))
		}
		return applyDomains(ctx, o, t, next, "Redirect from "+from+" removed on the website's page", from, false)
	})
	huma.Register(a, change("set-website-always-https", "always-https"), func(ctx context.Context, in *websiteAlwaysHTTPSInput) (*websiteOutput, error) {
		site, account, err := findWebsite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		service, ok := o.Accounts.(hostaccounts.AlwaysHTTPSService)
		switch {
		case site.State == partlyDeleted:
			return nil, huma.Error409Conflict(websitePartly)
		case !ok:
			return nil, huma.Error503ServiceUnavailable(alwaysHTTPSNotSetUp)
		case in.Body.AlwaysHTTPS == nil:
			return nil, huma.Error422UnprocessableEntity(alwaysHTTPSForm)
		case in.Body.ExpectedRevision == 0:
			return nil, huma.Error422UnprocessableEntity(websiteNoRevision)
		case in.Body.ExpectedRevision != account.Revision:
			return nil, huma.Error409Conflict(websiteStale)
		case account.State == "recovery_required":
			return nil, huma.Error503ServiceUnavailable(websiteRecovery)
		case account.State != "active":
			return nil, huma.Error409Conflict(alwaysHTTPSNotActive)
		}
		reason := "Always use HTTPS: off, set on the website's page"
		if *in.Body.AlwaysHTTPS {
			reason = "Always use HTTPS: on, set on the website's page"
		}
		changeCtx, cancel := context.WithTimeout(ctx, websiteChangeLimit)
		defer cancel()
		changed, err := service.SetAlwaysHTTPS(changeCtx, account.ID, hostaccounts.AlwaysHTTPSInput{AlwaysHTTPS: in.Body.AlwaysHTTPS, ExpectedRevision: account.Revision, Reason: reason}, siteActor(ctx))
		if err != nil {
			return nil, websiteChangeError(err, "The web server's configuration test failed with this change, so nothing changed. Ask whoever runs this server to check the web server.")
		}
		site.Revision, site.AlwaysHTTPS = changed.Revision, !changed.PlainHTTP
		return &websiteOutput{Body: WebsiteDetail{Website: site, PHPVersions: installedPHP(), Redirects: websiteRedirects(ctx, o, site)}}, nil
	})
}

// domainsTarget is a site about to change its domains or redirects: its
// list entry, its broker account at the revision the page had, and its
// current set.
type domainsTargetSite struct {
	site    Website
	account hostaccounts.Account
	service hostaccounts.SiteDomainsService
	domains hostaccounts.SiteDomains
}

func domainsTarget(ctx context.Context, o Options, id string, revision uint64) (domainsTargetSite, error) {
	site, account, err := findWebsite(ctx, o, id)
	if err != nil {
		return domainsTargetSite{}, err
	}
	service, ok := o.Accounts.(hostaccounts.SiteDomainsService)
	switch {
	case site.State == partlyDeleted:
		return domainsTargetSite{}, huma.Error409Conflict(websitePartly)
	case !ok:
		return domainsTargetSite{}, huma.Error503ServiceUnavailable(domainsNotSetUp)
	case revision == 0:
		return domainsTargetSite{}, huma.Error422UnprocessableEntity(websiteNoRevision)
	case revision != account.Revision:
		return domainsTargetSite{}, huma.Error409Conflict(websiteStale)
	case account.State == "recovery_required":
		return domainsTargetSite{}, huma.Error503ServiceUnavailable(websiteRecovery)
	case account.State != "active":
		return domainsTargetSite{}, huma.Error409Conflict(domainsNotActive)
	}
	read, err := service.SiteDomains(ctx, id)
	if err != nil {
		return domainsTargetSite{}, huma.Error503ServiceUnavailable(domainsUnreadable, errors.New("account service: "+err.Error()))
	}
	if read.Account.Revision != account.Revision {
		return domainsTargetSite{}, huma.Error409Conflict(websiteStale)
	}
	return domainsTargetSite{site: site, account: account, service: service, domains: read.Domains}, nil
}

// redirectFrom checks a redirect the page asked for and says what is wrong
// with it in plain words.
func redirectFrom(t domainsTargetSite, b websiteRedirectBody) (hostaccounts.SiteRedirect, error) {
	from, to := strings.TrimSpace(b.From), strings.TrimSpace(b.To)
	if b.Status != 301 && b.Status != 302 {
		return hostaccounts.SiteRedirect{}, huma.Error422UnprocessableEntity("status must be 301 (moved for good) or 302 (moved for now).")
	}
	if strings.HasPrefix(from, "/") {
		if !olsweb.ValidRedirectPath(from) {
			return hostaccounts.SiteRedirect{}, huma.Error422UnprocessableEntity(redirectPathForm)
		}
		if _, ok := olsweb.ParseRedirectTarget(to, false); !ok {
			return hostaccounts.SiteRedirect{}, huma.Error422UnprocessableEntity(redirectTargetForm)
		}
		for _, r := range t.domains.Redirects {
			if r.Path == from {
				return hostaccounts.SiteRedirect{}, huma.Error422UnprocessableEntity("There is already a redirect from " + from + ". Remove it first to change where it goes.")
			}
		}
		return hostaccounts.SiteRedirect{Path: from, Target: to, Status: b.Status}, nil
	}
	domain := strings.ToLower(from)
	if domain != t.account.Domain && !slices.Contains(t.domains.Aliases, domain) {
		return hostaccounts.SiteRedirect{}, huma.Error422UnprocessableEntity(from + " is not a path or a domain of this website. A path starts with /; to redirect another domain, add it to the website first.")
	}
	// A trailing slash after the host is the domain's address all the same.
	if _, ok := olsweb.ParseRedirectTarget(strings.TrimSuffix(to, "/"), true); ok {
		to = strings.TrimSuffix(to, "/")
	} else if _, ok := olsweb.ParseRedirectTarget(to, false); ok {
		return hostaccounts.SiteRedirect{}, huma.Error422UnprocessableEntity(redirectDomainTo)
	} else {
		return hostaccounts.SiteRedirect{}, huma.Error422UnprocessableEntity(redirectTargetForm)
	}
	for _, r := range t.domains.Redirects {
		if r.Domain == domain {
			return hostaccounts.SiteRedirect{}, huma.Error422UnprocessableEntity(domain + " is already redirected. Remove that redirect first to change where it goes.")
		}
	}
	return hostaccounts.SiteRedirect{Domain: domain, Target: to, Status: b.Status}, nil
}

// applyDomains sends the new set to the broker and answers the site's page.
// After a domain change the certificate is brought up to date in the
// background: it takes minutes, and the page shows each domain's HTTPS as
// it reads the site again.
func applyDomains(ctx context.Context, o Options, t domainsTargetSite, next hostaccounts.SiteDomains, reason, subject string, domainChange bool) (*websiteOutput, error) {
	changeCtx, cancel := context.WithTimeout(ctx, websiteChangeLimit)
	defer cancel()
	res, err := t.service.SetSiteDomains(changeCtx, t.account.ID, hostaccounts.SiteDomainsInput{Aliases: next.Aliases, Redirects: next.Redirects, ExpectedRevision: t.account.Revision, Reason: reason}, siteActor(ctx))
	if errors.Is(err, hostaccounts.ErrDomainTaken) {
		return nil, domainTakenError(ctx, o, t.account.ID, subject, err)
	}
	if err != nil {
		rejected := "The web server's configuration test failed with this change, so nothing changed. Ask whoever runs this server to check the web server."
		return nil, websiteChangeError(err, rejected)
	}
	if domainChange && o.Certificates != nil {
		site := acme.Site{AccountID: res.Account.ID, Domain: res.Account.Domain, Aliases: res.Domains.Aliases, Covered: certificateNames(res.Account.Certificate), Revision: res.Account.Revision, Active: res.Account.State == "active"}
		if res.Account.Certificate.NotAfter > 0 {
			site.NotAfter = time.Unix(res.Account.Certificate.NotAfter, 0)
		}
		certs := o.Certificates
		go func() {
			refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), certificateRefreshLimit)
			defer cancel()
			// The manager logs the outcome and records it for the page.
			_ = certs.Refresh(refreshCtx, site)
		}()
	}
	account := res.Account
	account.SiteDomains = &hostaccounts.SiteDomainsSummary{Aliases: res.Domains.Aliases, Redirects: len(res.Domains.Redirects)}
	updated := t.site
	updated.Revision = account.Revision
	updated.Aliases, updated.RedirectCount = websiteAliases(account, o.Certificates)
	redirects := []WebsiteRedirect{}
	for _, r := range res.Domains.Redirects {
		redirects = append(redirects, apiRedirect(r))
	}
	return &websiteOutput{Body: WebsiteDetail{Website: updated, PHPVersions: installedPHP(), Redirects: redirects}}, nil
}

// domainTakenError names the website that has the domain, when the list
// says and the request is an admin's; the account service refused it
// either way.
func domainTakenError(ctx context.Context, o Options, id, domain string, err error) error {
	technical := errors.New("account service: " + err.Error())
	owner := ""
	if !mayNameOthers(ctx) {
		return huma.Error409Conflict(domain+" already belongs to another website on this server. A domain can belong to one website only.", technical)
	}
	if accounts, lerr := o.Accounts.List(ctx); lerr == nil {
		for _, a := range accounts {
			if a.ID != id && sameHost(a, domain) {
				owner = a.Domain
				break
			}
		}
	}
	if owner != "" && owner != domain {
		return huma.Error409Conflict(domain+" already belongs to another website on this server, "+owner+". A domain can belong to one website only: remove it there first.", technical)
	}
	return huma.Error409Conflict(domain+" already belongs to another website on this server. A domain can belong to one website only: remove it there first.", technical)
}

// sameHost reports whether an account has domain, as OpenLiteSpeed maps
// names: with one leading "www." removed.
func sameHost(a hostaccounts.Account, domain string) bool {
	key := strings.TrimPrefix(domain, "www.")
	names := []string{a.Domain}
	if a.SiteDomains != nil {
		names = append(names, a.SiteDomains.Aliases...)
	}
	for _, n := range names {
		if strings.TrimPrefix(n, "www.") == key {
			return true
		}
	}
	return false
}

// panelHostTaken refuses a website or alias named like the panel: the
// panel's certificate is validated on port 80 at that name, and the www.
// form is the same name to OpenLiteSpeed.
const panelHostTaken = "This name is the panel's own address. Use a different domain for the website."

// panelHost reports whether domain, in any case, is one of the panel's
// --panel-host names or its www. form.
func panelHost(hosts []string, domain string) bool {
	key := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "www.")
	for _, h := range hosts {
		if strings.TrimPrefix(strings.ToLower(h), "www.") == key {
			return true
		}
	}
	return false
}

func olswebRedirects(in []hostaccounts.SiteRedirect) []olsweb.Redirect {
	out := make([]olsweb.Redirect, 0, len(in))
	for _, r := range in {
		out = append(out, olsweb.Redirect{Domain: r.Domain, Path: r.Path, Target: r.Target, Status: r.Status})
	}
	return out
}

// validAliasDomain is the broker's rule for an alias: a lowercase host name
// of at least two labels that OpenLiteSpeed can map (not www.www.* or
// www.<one label>). The broker checks it again.
func validAliasDomain(s string) bool {
	if s == "" || len(s) > 253 || s != strings.ToLower(s) || net.ParseIP(s) != nil {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	key := strings.TrimPrefix(s, "www.")
	return !strings.HasPrefix(key, "www.") && strings.Contains(key, ".")
}
