package olsweb

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// A redirect becomes OpenLiteSpeed rewrite rules in the site's vhconf.conf,
// written by the root broker, never in the tenant's .htaccess. Every value
// that reaches a rule is checked against an alphabet that has none of the
// rewrite engine's metacharacters for a substitution ('$' and '%' start a
// back-reference or a variable, '\' escapes) and none of the config file's
// (whitespace ends a token and a newline a rule, '#' starts a comment, '{'
// and '}' open and close a block, '<' starts a heredoc). A pattern is built
// here from a path or a domain whose only regular-expression metacharacter
// is '.', which is escaped.

var (
	// redirectPathPattern: '/', then letters, digits and - . _ ~ / only.
	redirectPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	// redirectTargetPattern: http or https, a lowercase host, an optional
	// port, then an optional path and query of letters, digits and
	// - . _ ~ / ? & = + , : ; @ only.
	redirectTargetPattern = regexp.MustCompile(`^(https?)://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?((?:/[A-Za-z0-9._~/?&=+,:;@-]*)?)$`)
)

// ValidRedirectPath reports whether p can be a path redirect's source: '/'
// then at most MaxRedirectPathBytes in all of letters, digits and - . _ ~ /,
// with no empty part and no part that starts with a dot, so neither
// /.well-known/acme-challenge/ nor a hidden file can be redirected.
func ValidRedirectPath(p string) bool {
	if len(p) > MaxRedirectPathBytes || !redirectPathPattern.MatchString(p) || strings.Contains(p, "//") {
		return false
	}
	for _, part := range strings.Split(p[1:], "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

// RedirectTarget is a checked redirect target, split into its parts.
type RedirectTarget struct {
	Scheme string // http or https
	Host   string // a lowercase DNS name with at least two labels
	Port   int    // 0 when the URL names none
	Path   string // the path and query, empty or starting with '/'
}

// ParseRedirectTarget checks a redirect's target: http:// or https://, a
// host that is a lowercase DNS name (no IP address, no user name), an
// optional port 1 to 65535, and an optional path and query of letters,
// digits and - . _ ~ / ? & = + , : ; @, at most MaxRedirectTargetBytes in
// all. hostOnly refuses any path, even "/": a domain redirect keeps the
// request's own path.
func ParseRedirectTarget(target string, hostOnly bool) (RedirectTarget, bool) {
	if len(target) > MaxRedirectTargetBytes {
		return RedirectTarget{}, false
	}
	m := redirectTargetPattern.FindStringSubmatch(target)
	if m == nil || !validDomain(m[2]) || (hostOnly && m[4] != "") {
		return RedirectTarget{}, false
	}
	t := RedirectTarget{Scheme: m[1], Host: m[2], Path: m[4]}
	if m[3] != "" {
		port, err := strconv.Atoi(m[3])
		if err != nil || port < 1 || port > 65535 {
			return RedirectTarget{}, false
		}
		t.Port = port
	}
	return t, true
}

// CheckRedirects validates redirects for a site with these domains (its
// own first) exactly as Validate does, so a caller can refuse them before it
// stores them. A FieldError names the field as site.redirects[i]...
func CheckRedirects(domains []string, redirects []Redirect) error {
	return checkRedirects("site", domains, redirects)
}

// checkRedirects validates a site's redirects against its domains: each a
// 301 or 302 with exactly one of a domain and a path; a domain one of the
// site's, redirected once, to a host that is not itself and not redirected
// further; a path redirected once, not to itself on one of the site's
// domains.
func checkRedirects(field string, domains []string, redirects []Redirect) error {
	if len(redirects) > MaxRedirectsPerSite {
		return fieldErr(field+".redirects", "at most %d redirects", MaxRedirectsPerSite)
	}
	byDomain := map[string]int{}
	byPath := map[string]int{}
	for i, r := range redirects {
		f := fmt.Sprintf("%s.redirects[%d]", field, i)
		if r.Status != 301 && r.Status != 302 {
			return fieldErr(f+".status", "must be 301 or 302")
		}
		switch {
		case r.Domain != "" && r.Path == "":
			if !slices.Contains(domains, r.Domain) {
				return fieldErr(f+".domain", "must be one of the site's domains")
			}
			if j, dup := byDomain[r.Domain]; dup {
				return fieldErr(f+".domain", "already redirected by redirects[%d]", j)
			}
			byDomain[r.Domain] = i
			t, ok := ParseRedirectTarget(r.Target, true)
			if !ok {
				return fieldErr(f+".target", "must be http:// or https:// and a domain, with no path")
			}
			if t.Host == r.Domain {
				return fieldErr(f+".target", "must not be the domain itself")
			}
		case r.Path != "" && r.Domain == "":
			if !ValidRedirectPath(r.Path) {
				return fieldErr(f+".path", "must be / then letters, digits and - . _ ~ /, at most %d bytes, with no empty part or part starting with a dot", MaxRedirectPathBytes)
			}
			if j, dup := byPath[r.Path]; dup {
				return fieldErr(f+".path", "already redirected by redirects[%d]", j)
			}
			byPath[r.Path] = i
			t, ok := ParseRedirectTarget(r.Target, false)
			if !ok {
				return fieldErr(f+".target", "must be http:// or https://, a domain and a path of letters, digits and - . _ ~ / ? & = + , : ; @, at most %d bytes", MaxRedirectTargetBytes)
			}
			to, _, _ := strings.Cut(t.Path, "?")
			// The rule matches the path itself and, without a trailing
			// slash, the path with one.
			loops := to == r.Path || (to == "" && r.Path == "/") || (!strings.HasSuffix(r.Path, "/") && to == r.Path+"/")
			if slices.Contains(domains, t.Host) && loops {
				return fieldErr(f+".target", "redirects the path to itself")
			}
		default:
			return fieldErr(f, "must name exactly one of domain and path")
		}
	}
	// A domain redirect whose target host is redirected too would chain, or
	// loop when two point at each other.
	for i, r := range redirects {
		if r.Domain == "" {
			continue
		}
		t, _ := ParseRedirectTarget(r.Target, true)
		if j, chained := byDomain[t.Host]; chained {
			return fieldErr(fmt.Sprintf("%s.redirects[%d].target", field, i), "%s is redirected too, by redirects[%d]", t.Host, j)
		}
	}
	return nil
}

// checkCovered validates a certificate's domains: each one of the site's,
// once, and only for a site with a certificate.
func checkCovered(field string, in Site) error {
	if len(in.TLS.Domains) == 0 {
		return nil
	}
	if in.TLS.CertFile == "" {
		return fieldErr(field+".tls.domains", "only a site with a certificate names the domains it covers")
	}
	seen := map[string]bool{}
	for k, d := range in.TLS.Domains {
		if !slices.Contains(in.Domains, d) || seen[d] {
			return fieldErr(fmt.Sprintf("%s.tls.domains[%d]", field, k), "must be one of the site's domains, listed once")
		}
		seen[d] = true
	}
	return nil
}

// securedDomains are the domains the secure listener maps for a site with a
// certificate: those it covers, in the order of the site's domains.
func securedDomains(v site) []string {
	if len(v.TLS.Domains) == 0 {
		return v.Domains
	}
	out := []string{}
	for _, d := range v.Domains {
		if slices.Contains(v.TLS.Domains, d) {
			out = append(out, d)
		}
	}
	return out
}

// redirectRules are an active site's redirects as rewrite rules: domain
// redirects first, sorted by domain, then path redirects, sorted by path, so
// equal input in any order renders the same. Each rule ends with L, so the
// first that matches answers and nothing after it (the tenant's .htaccess
// included) runs.
//
// A domain redirect matches the Host header (with or without a port), keeps
// the path and query, and leaves the ACME challenge path alone:
//
//	RewriteCond %{HTTP_HOST} ^www\.example\.com(:[0-9]+)?$ [NC]
//	RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
//	RewriteRule ^/?(.*)$ https://example.com/$1 [R=301,L]
//
// A path redirect matches the path with or without its leading slash, as
// the deny rules do, and the query string is passed on unless the target
// has its own:
//
//	RewriteRule ^/?old-page/?$ https://example.com/new-page [R=301,L]
func redirectRules(redirects []Redirect) []string {
	domains, paths := []Redirect{}, []Redirect{}
	for _, r := range redirects {
		if r.Domain != "" {
			domains = append(domains, r)
		} else {
			paths = append(paths, r)
		}
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })
	sort.Slice(paths, func(i, j int) bool { return paths[i].Path < paths[j].Path })
	rules := []string{}
	for _, r := range domains {
		rules = append(rules,
			`RewriteCond %{HTTP_HOST} ^`+quoteDots(r.Domain)+`(:[0-9]+)?$ [NC]`,
			`RewriteCond %{REQUEST_URI} !^`+quoteDots(acmeChallengeURI),
			`RewriteRule ^/?(.*)$ `+r.Target+`/$1 [R=`+strconv.Itoa(r.Status)+`,L]`)
	}
	for _, r := range paths {
		pattern := quoteDots(strings.TrimPrefix(r.Path, "/"))
		if !strings.HasSuffix(r.Path, "/") {
			pattern += "/?"
		}
		rules = append(rules, `RewriteRule ^/?`+pattern+`$ `+r.Target+` [R=`+strconv.Itoa(r.Status)+`,L]`)
	}
	return rules
}

// httpsRules send plain http requests for each of these domains (checked
// DNS names) to the same address on https, one rule each so the target
// names the domain itself and a Host header with a port goes to the default
// https port. The path and query are kept, and the ACME challenge path is
// left alone, as for a domain redirect:
//
//	RewriteCond %{HTTPS} !on
//	RewriteCond %{HTTP_HOST} ^example\.com(:[0-9]+)?$ [NC]
//	RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
//	RewriteRule ^/?(.*)$ https://example.com/$1 [R=301,L]
//
// One vhost serves both listeners, so the rule tests the request's own
// scheme: %{HTTPS} is "on" for a request over TLS (doc.go, Sources).
func httpsRules(domains []string) []string {
	rules := []string{}
	for _, d := range domains {
		rules = append(rules,
			`RewriteCond %{HTTPS} !on`,
			`RewriteCond %{HTTP_HOST} ^`+quoteDots(d)+`(:[0-9]+)?$ [NC]`,
			`RewriteCond %{REQUEST_URI} !^`+quoteDots(acmeChallengeURI),
			`RewriteRule ^/?(.*)$ https://`+d+`/$1 [R=301,L]`)
	}
	return rules
}

// quoteDots escapes the one regular-expression metacharacter a checked path
// or domain can hold.
func quoteDots(s string) string { return strings.ReplaceAll(s, ".", `\.`) }
