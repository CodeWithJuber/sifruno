package hostaccounts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"sifruno/internal/olsweb"
)

// The domains operation sets a live site's other domains (aliases, served
// as the same site) and its redirects. The broker records them, journaled
// like a web change, and olsweb renders them from that record: the aliases
// in the listener map lines, the redirects as the vhost's own rewrite rules.
// No config text comes from the caller.

// SiteRedirect is one redirect: exactly one of Domain (one of the site's
// domains, sent whole to Target, a scheme and host) and Path (sent to
// Target on every domain of the site). Status is 301 or 302.
type SiteRedirect struct {
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
	Target string `json:"target"`
	Status int    `json:"status"`
}

// SiteDomains are a site's domains besides the account's own, and its
// redirects, in the broker's order: aliases sorted, then domain redirects by
// domain and path redirects by path.
type SiteDomains struct {
	Aliases   []string       `json:"aliases"`
	Redirects []SiteRedirect `json:"redirects"`
}

// SiteDomainsInput replaces the site's aliases and redirects. Both lists are
// required, each possibly empty.
type SiteDomainsInput struct {
	Aliases          []string       `json:"aliases"`
	Redirects        []SiteRedirect `json:"redirects"`
	ExpectedRevision uint64         `json:"expected_revision"`
	Reason           string         `json:"reason"`
}

type SiteDomainsResult struct {
	Account Account     `json:"account"`
	Domains SiteDomains `json:"domains"`
}

// SiteDomainsSummary is what the account list shows of a site's domains:
// the aliases, and how many redirects it has (SiteDomains reads them).
type SiteDomainsSummary struct {
	Aliases   []string `json:"aliases"`
	Redirects int      `json:"redirects"`
}

// SiteDomainsService is implemented by the client; the broker serves it from
// its store.
type SiteDomainsService interface {
	SiteDomains(ctx context.Context, id string) (SiteDomainsResult, error)
	SetSiteDomains(ctx context.Context, id string, in SiteDomainsInput, actor string) (SiteDomainsResult, error)
}

// AlwaysHTTPSInput turns a live site's "Always use HTTPS" on or off: whether
// plain http for the domains its certificate covers is sent to https.
// AlwaysHTTPS is required, so a request that leaves it out changes nothing.
type AlwaysHTTPSInput struct {
	AlwaysHTTPS      *bool  `json:"always_https"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}

// AlwaysHTTPSService is implemented by the client; the broker serves it
// from its store. The answer is the account, its PlainHTTP the new setting.
type AlwaysHTTPSService interface {
	SetAlwaysHTTPS(ctx context.Context, id string, in AlwaysHTTPSInput, actor string) (Account, error)
}

func validAlwaysHTTPSInput(in AlwaysHTTPSInput, actor string) bool {
	return in.AlwaysHTTPS != nil && in.ExpectedRevision != 0 && validText(in.Reason, 500) && validText(actor, 120)
}

// httpsTarget is the journal target of an "Always use HTTPS" change: "on",
// or "off" for plain http.
func httpsTarget(plainHTTP bool) string {
	if plainHTTP {
		return "off"
	}
	return "on"
}

// ErrDomainTaken is a domains change refused because one of its aliases is
// already a domain of another account: the account's own or an alias, in
// either its www. form or without it, which OpenLiteSpeed maps as one name.
// Nothing changed. It is a conflict too: errors.Is(err, ErrConflict) holds.
var ErrDomainTaken = fmt.Errorf("%w: domain belongs to another account", ErrConflict)

const (
	// MaxSiteAliases keeps the account's domain and its aliases within
	// olsweb's domains per site.
	MaxSiteAliases = olsweb.MaxDomainsPerSite - 1
	// MaxSiteRedirects is olsweb's bound, domain and path redirects together.
	MaxSiteRedirects = olsweb.MaxRedirectsPerSite
	// maxSiteDomainsBytes bounds a set as the record holds it (canonical
	// JSON, quoted again inside the record), so a record with the set and
	// the one being installed stays inside maxRecordBytes.
	maxSiteDomainsBytes = 60 << 10
	// maxSiteDomainsRequestBytes fits the largest set with its keys, the
	// reason and the actor.
	maxSiteDomainsRequestBytes = 96 << 10
)

var domainsDigestPattern = regexp.MustCompile(`^sha256=[0-9a-f]{64}$`)

// domainKey is the name OpenLiteSpeed registers for a mapped domain: it
// strips one leading "www." and serves www.<host> from <host>'s vhost, so a
// domain and its www. form belong to one account.
func domainKey(d string) string { return strings.TrimPrefix(d, "www.") }

// normalizeSiteDomains returns d in the broker's order, with empty lists
// rather than nil, without changing any value.
func normalizeSiteDomains(d SiteDomains) SiteDomains {
	out := SiteDomains{Aliases: append([]string{}, d.Aliases...), Redirects: append([]SiteRedirect{}, d.Redirects...)}
	sort.Strings(out.Aliases)
	sort.SliceStable(out.Redirects, func(i, j int) bool {
		a, b := out.Redirects[i], out.Redirects[j]
		if (a.Domain != "") != (b.Domain != "") {
			return a.Domain != ""
		}
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		return a.Path < b.Path
	})
	return out
}

// encodeSiteDomains is the record's form of a normalized set: empty for no
// aliases and no redirects, else its JSON without HTML escaping.
func encodeSiteDomains(d SiteDomains) string {
	if len(d.Aliases) == 0 && len(d.Redirects) == 0 {
		return ""
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(d) != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// decodeSiteDomains reads a record's set, which must be in canonical form:
// strict JSON that encodes back to exactly the same text.
func decodeSiteDomains(s string) (SiteDomains, bool) {
	if s == "" {
		return SiteDomains{Aliases: []string{}, Redirects: []SiteRedirect{}}, true
	}
	d := json.NewDecoder(strings.NewReader(s))
	d.DisallowUnknownFields()
	var out SiteDomains
	if d.Decode(&out) != nil || d.More() || out.Aliases == nil || out.Redirects == nil {
		return SiteDomains{}, false
	}
	if encodeSiteDomains(normalizeSiteDomains(out)) != s {
		return SiteDomains{}, false
	}
	return out, true
}

// siteDomainsSized reports whether an encoded set fits the record bound,
// measured as the record's JSON holds it.
func siteDomainsSized(encoded string) bool {
	quoted, err := json.Marshal(encoded)
	return err == nil && len(quoted) <= maxSiteDomainsBytes
}

// domainsDigest is the journal target for a domains operation.
func domainsDigest(encoded string) string {
	sum := sha256.Sum256([]byte(encoded))
	return "sha256=" + hex.EncodeToString(sum[:])
}

// validSiteDomains checks a set for an account whose own domain is primary:
// at most MaxSiteAliases aliases, each a valid domain that OpenLiteSpeed
// can map (not www.www.* or www.<single label>), not the account's own
// domain and listed once; and redirects that olsweb accepts for the site's
// domains. Whether another account has a domain is checked by domainTaken.
func validSiteDomains(primary string, d SiteDomains) bool {
	if len(d.Aliases) > MaxSiteAliases || len(d.Redirects) > MaxSiteRedirects {
		return false
	}
	domains := []string{primary}
	for _, a := range d.Aliases {
		key := domainKey(a)
		if !validDomain(a) || strings.HasPrefix(key, "www.") || !strings.Contains(key, ".") || slices.Contains(domains, a) {
			return false
		}
		domains = append(domains, a)
	}
	return olsweb.CheckRedirects(domains, olswebRedirects(d.Redirects)) == nil
}

// validStoredDomains checks a record's encoded set: canonical, sized and
// valid for the account.
func validStoredDomains(primary, encoded string) bool {
	d, ok := decodeSiteDomains(encoded)
	return ok && siteDomainsSized(encoded) && validSiteDomains(primary, d)
}

func olswebRedirects(in []SiteRedirect) []olsweb.Redirect {
	out := make([]olsweb.Redirect, 0, len(in))
	for _, r := range in {
		out = append(out, olsweb.Redirect{Domain: r.Domain, Path: r.Path, Target: r.Target, Status: r.Status})
	}
	return out
}

// recordSiteDomains is the set a record applies now: the one an unfinished
// domains operation installs, or the recorded one. records() has checked
// both, so a decode failure here yields the empty set.
func recordSiteDomains(r record) SiteDomains {
	encoded := r.Domains
	if r.Pending != nil && r.Pending.Action == "domains" {
		encoded = r.DomainsNext
	}
	d, ok := decodeSiteDomains(encoded)
	if !ok {
		return SiteDomains{Aliases: []string{}, Redirects: []SiteRedirect{}}
	}
	return d
}

// domainTaken reports whether domain is already a domain of an account
// other than the one named by id: its own domain or one of its aliases,
// recorded or being installed, compared as OpenLiteSpeed maps them.
func domainTaken(items []record, id, domain string) bool {
	key := domainKey(domain)
	for _, r := range items {
		if r.Account.ID == id {
			continue
		}
		names := []string{r.Account.Domain}
		if recorded, ok := decodeSiteDomains(r.Domains); ok {
			names = append(names, recorded.Aliases...)
		}
		if r.Pending != nil && r.Pending.Action == "domains" {
			if next, ok := decodeSiteDomains(r.DomainsNext); ok {
				names = append(names, next.Aliases...)
			}
		}
		for _, n := range names {
			if domainKey(n) == key {
				return true
			}
		}
	}
	return false
}

// siteDomainsSummary is the list's view of a record's recorded set, nil
// when it has none.
func siteDomainsSummary(r record) *SiteDomainsSummary {
	d, ok := decodeSiteDomains(r.Domains)
	if !ok || (len(d.Aliases) == 0 && len(d.Redirects) == 0) {
		return nil
	}
	return &SiteDomainsSummary{Aliases: d.Aliases, Redirects: len(d.Redirects)}
}

// SiteDomains reads the account's recorded aliases and redirects.
func (c *client) SiteDomains(ctx context.Context, id string) (SiteDomainsResult, error) {
	if !idPattern.MatchString(id) {
		return SiteDomainsResult{}, ErrInvalid
	}
	var out SiteDomainsResult
	err := c.request(ctx, "GET", "/v1/accounts/"+id+"/domains", nil, &out)
	return out, err
}

// SetSiteDomains asks the broker to replace the site's aliases and
// redirects. A 409 domain_taken answer means an alias is another account's
// (ErrDomainTaken); 422 web_rejected that the config with them failed its
// test and was restored. Either way the account is unchanged.
func (c *client) SetSiteDomains(ctx context.Context, id string, in SiteDomainsInput, actor string) (SiteDomainsResult, error) {
	if !idPattern.MatchString(id) || in.ExpectedRevision == 0 || !validText(in.Reason, 500) || !validText(actor, 120) {
		return SiteDomainsResult{}, ErrInvalid
	}
	// The broker refuses a list left out, so an empty one is sent as [].
	d := normalizeSiteDomains(SiteDomains{Aliases: in.Aliases, Redirects: in.Redirects})
	in.Aliases, in.Redirects = d.Aliases, d.Redirects
	var out SiteDomainsResult
	// The change runs the web apply, which can take minutes on a busy host.
	err := c.exchange(ctx, c.slow, "POST", "/v1/accounts/"+id+"/domains", struct {
		Input SiteDomainsInput `json:"input"`
		Actor string           `json:"actor"`
	}{in, actor}, maxSiteDomainsRequestBytes, &out, maxResponseBytes)
	return out, err
}

// SetAlwaysHTTPS asks the broker to turn the site's "Always use HTTPS" on
// or off. A 422 web_rejected answer means the config with the change failed
// its test and was restored: the account is unchanged.
func (c *client) SetAlwaysHTTPS(ctx context.Context, id string, in AlwaysHTTPSInput, actor string) (Account, error) {
	if !idPattern.MatchString(id) || !validAlwaysHTTPSInput(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	// The change runs the web apply, which can take minutes on a busy host.
	err := c.send(ctx, c.slow, "POST", "/v1/accounts/"+id+"/always-https", struct {
		Input AlwaysHTTPSInput `json:"input"`
		Actor string           `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}
