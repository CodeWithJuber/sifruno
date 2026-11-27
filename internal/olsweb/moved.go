package olsweb

import (
	"bytes"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
)

// The redirect and ErrorDocument lines of a migrated site's root .htaccess
// (internal/htaccess redirect.go) are written by the root broker into the
// site's vhconf.conf, as OpenLiteSpeed does not read them from .htaccess:
//
//	Redirect 301 /old https://example.com/new
//	  RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
//	  RewriteRule ^/?old(/.*)?$ https://example.com/new$1 [R=301,L]
//	RedirectMatch 302 ^/blog/(.*)$ /news/$1
//	  RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
//	  RewriteRule ^/blog/(.*)$ /news/$1 [R=302,L]
//	ErrorDocument 404 /404.html
//	  errorPage 404 { url /404.html }
//
// A Redirect's path matches itself and every path below it, the rest of
// the path appended to the target, as mod_alias does. The vhost's rewrite
// rules see the decoded path with its leading '/' (src/http/rewriteengine.cpp
// processRuleSet with no context: nothing is stripped), as a RedirectMatch
// expression does on Apache, and a target without '?' keeps the request's
// query string (processQueryString), as mod_alias appends it. The
// certificate challenge path is left alone, so the site's certificate can
// renew even when the old site sent every path elsewhere.
//
// Every value is checked against an alphabet without the config grammar's
// and the rewrite engine's special characters: no whitespace, quote, '#',
// '{', '}', '<' or '%', and '$' only before a digit in a RedirectMatch
// target, where it is the expression's group, as on Apache.

// HtaccessRedirect is one converted redirect line. Exactly one of Prefix
// (a URL path) and Pattern (a regular expression) is set; Target is an
// http or https URL or a URL path; Status is 301 or 302.
type HtaccessRedirect struct {
	Prefix  string `json:"prefix,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Target  string `json:"target"`
	Status  int    `json:"status"`
}

// ErrorPage is one converted ErrorDocument line: the page at URL, a URL
// path on the site, answers Status, which keeps its code.
type ErrorPage struct {
	Status int    `json:"status"`
	URL    string `json:"url"`
}

// Bounds for converted lines.
const (
	MaxHtaccessRedirects = 100
	maxMovedPathBytes    = 128
	maxMovedPatternBytes = 256
	maxMovedTargetBytes  = 256
)

var (
	movedPath    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	movedPattern = regexp.MustCompile(`^[A-Za-z0-9._~/^$*+?()\[\]|\\,:=!@-]+$`)
	movedTarget  = regexp.MustCompile(`^(?:https?://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?)?((?:/[A-Za-z0-9._~/?&=+,:;@$-]*)?)$`)
	movedRef     = regexp.MustCompile(`\$[0-9]`)
)

// movedURLPath is '/', then letters, digits and - . _ ~ /, with no empty
// part and no part starting with a dot.
func movedURLPath(p string) bool {
	if len(p) > maxMovedPathBytes || !movedPath.MatchString(p) || strings.Contains(p, "//") {
		return false
	}
	for _, part := range strings.Split(p[1:], "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

func validMovedTarget(t string, pattern bool) bool {
	m := movedTarget.FindStringSubmatch(t)
	if len(t) > maxMovedTargetBytes || m == nil {
		return false
	}
	if strings.HasPrefix(t, "http") {
		if !validDomain(m[1]) {
			return false
		}
		if port, err := strconv.Atoi(m[2]); m[2] != "" && (err != nil || port > 65535) {
			return false
		}
	} else if m[3] == "" {
		return false
	}
	dollars := strings.Count(t, "$")
	return dollars == 0 || (pattern && len(movedRef.FindAllString(t, -1)) == dollars)
}

// validMovedPattern is a RedirectMatch expression the vhost can carry: its
// alphabet, no leading '!' (which negates a rewrite pattern), and one Go's
// parser reads with Perl syntax, which leaves out the PCRE forms the two
// engines could read differently.
func validMovedPattern(p string) bool {
	if len(p) > maxMovedPatternBytes || !movedPattern.MatchString(p) || strings.HasPrefix(p, "!") {
		return false
	}
	_, err := syntax.Parse(p, syntax.Perl)
	return err == nil
}

// CheckMoved validates a site's converted redirects and error pages
// exactly as Validate does, so a caller can refuse them before it stores
// them. A FieldError names the field as site.htaccess_redirects[i]... or
// site.error_pages[i]...
func CheckMoved(redirects []HtaccessRedirect, pages []ErrorPage) error {
	return checkMoved("site", redirects, pages)
}

// checkMoved validates a site's converted redirects and error pages.
func checkMoved(field string, redirects []HtaccessRedirect, pages []ErrorPage) error {
	if len(redirects) > MaxHtaccessRedirects {
		return fieldErr(field+".htaccess_redirects", "at most %d redirects", MaxHtaccessRedirects)
	}
	for i, r := range redirects {
		f := fmt.Sprintf("%s.htaccess_redirects[%d]", field, i)
		if r.Status != 301 && r.Status != 302 {
			return fieldErr(f+".status", "must be 301 or 302")
		}
		switch {
		case r.Prefix != "" && r.Pattern == "":
			if !movedURLPath(r.Prefix) {
				return fieldErr(f+".prefix", "must be / then letters, digits and - . _ ~ /, at most %d bytes, with no empty part or part starting with a dot", maxMovedPathBytes)
			}
		case r.Pattern != "" && r.Prefix == "":
			if !validMovedPattern(r.Pattern) {
				return fieldErr(f+".pattern", "must be a regular expression of at most %d bytes without spaces, quotes, # or %%, not starting with !", maxMovedPatternBytes)
			}
		default:
			return fieldErr(f, "must name exactly one of prefix and pattern")
		}
		if !validMovedTarget(r.Target, r.Pattern != "") {
			return fieldErr(f+".target", "must be http:// or https:// and a domain, or a path, of letters, digits and - . _ ~ / ? & = + , : ; @, at most %d bytes", maxMovedTargetBytes)
		}
	}
	for i, p := range pages {
		f := fmt.Sprintf("%s.error_pages[%d]", field, i)
		if !(p.Status >= 400 && p.Status <= 451) && !(p.Status >= 500 && p.Status <= 510) {
			return fieldErr(f+".status", "must be 400 to 451 or 500 to 510")
		}
		if i > 0 && pages[i-1].Status >= p.Status {
			return fieldErr(f+".status", "error pages must be sorted by status, each once")
		}
		if p.URL == "/" || !movedURLPath(p.URL) {
			return fieldErr(f+".url", "must be / then letters, digits and - . _ ~ /, at most %d bytes, with no empty part or part starting with a dot", maxMovedPathBytes)
		}
	}
	return nil
}

// movedRules are the converted redirects as rewrite rules, in the order of
// the file: the first that matches answers.
func movedRules(redirects []HtaccessRedirect) []string {
	rules := []string{}
	for _, r := range redirects {
		pattern, target := r.Pattern, r.Target
		if r.Prefix != "" {
			// "/old" matches /old and /old/...; "/old/" matches /old/...;
			// the rest of the path is appended to the target.
			p := quoteDots(strings.TrimPrefix(r.Prefix, "/"))
			if strings.HasSuffix(r.Prefix, "/") || r.Prefix == "/" {
				pattern = "^/?" + p + "(.*)$"
			} else {
				pattern = "^/?" + p + "(/.*)?$"
			}
			target += "$1"
		}
		rules = append(rules,
			`RewriteCond %{REQUEST_URI} !^`+quoteDots(acmeChallengeURI),
			`RewriteRule `+pattern+` `+target+` [R=`+strconv.Itoa(r.Status)+`,L]`)
	}
	return rules
}

// renderErrorPages writes the vhost's error pages.
func renderErrorPages(b *bytes.Buffer, pages []ErrorPage) {
	for _, p := range pages {
		fmt.Fprintf(b, "\nerrorPage %d {\n", p.Status)
		kv(b, "url", p.URL)
		b.WriteString("}\n")
	}
}
