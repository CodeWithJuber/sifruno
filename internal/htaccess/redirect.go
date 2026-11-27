package htaccess

import (
	"net"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
)

// Redirect, RedirectMatch, RedirectPermanent, RedirectTemp (mod_alias) and
// ErrorDocument (core) do nothing on OpenLiteSpeed from .htaccess. In the
// site's root .htaccess, outside any section that scopes them, the simple
// forms move into the vhost: the root broker writes them as rewrite rules
// and error pages (olsweb moved.go). Everything else about them refuses,
// naming the line. Apache's behaviour, from the httpd 2.4.x
// source (modules/mappers/mod_alias.c, server/core.c set_error_document,
// server/util.c regsub_core), read on 2026-11-27:
//
//   - Redirect [status] URL-path URL. In .htaccess a status with one
//     argument is the expression form that sends the whole folder; it
//     refuses here. URL-path matches the %-decoded request path and every
//     path below it on a '/' boundary (alias_matches), and the rest of the
//     path is appended to URL. The status is temp (302) unless given:
//     permanent 301, temp 302, seeother 303, gone 410, or a number. Only 301
//     and 302 convert; 4xx and 5xx are access rules (classify.go).
//   - RedirectMatch [status] regex URL: regex is searched for in the
//     request path (ap_regexec, AP_REG_EXTENDED) and $0 to $9 in URL are its
//     groups; a backslash escapes the next character.
//   - Either way a URL-path target gets this request's scheme and host
//     (ap_construct_url), and the request's query string is appended unless
//     the target has its own '?'.
//   - The fixup that answers these runs after mod_rewrite's per-folder
//     fixup, which sets an internal rewrite but does not stop the redirect,
//     so a Redirect beside WordPress's rewrite block still answers. On
//     OpenLiteSpeed the converted rule runs at the vhost, before the
//     .htaccess rewrite rules; a .htaccess rule that answers itself ([R] or
//     [F]) for the same path is the one case that differs.
//   - ErrorDocument code text-or-path: "default" restores the server's page;
//     an argument with a space, or not starting with '/' and not a URL, is a
//     message; a path starting with '/' is served by an internal redirect
//     with the error status kept; a URL is a redirect to it (and ignored for
//     401). OpenLiteSpeed 1.9.4's vhost "errorPage code { url path }" serves
//     a path the same way (src/http/httpsession.cpp sendHttpError, redirect
//     with the status kept), for codes 400 to 451 and 500 to 510
//     (src/http/httpstatuscode.cpp).

// Redirect is a redirect line of the root .htaccess that the vhost
// carries. Exactly one of Prefix (a URL path: it and every path below it)
// and Pattern (a regular expression searched for in the URL path) is set.
// Target is an http or https URL or a URL path; with Pattern it may hold
// $0 to $9. Status is 301 or 302.
type Redirect struct {
	Line    int    `json:"line"`
	Prefix  string `json:"prefix,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Target  string `json:"target"`
	Status  int    `json:"status"`
}

// ErrorPage is an ErrorDocument line of the root .htaccess that the vhost
// carries: the page at URL (a URL path) answers Status. An empty URL is
// "default": the server's own page.
type ErrorPage struct {
	Line   int    `json:"line"`
	Status int    `json:"status"`
	URL    string `json:"url,omitempty"`
}

// Bounds of what converts; a longer value refuses.
const (
	MaxRedirectPrefixBytes  = 128
	MaxRedirectPatternBytes = 256
	MaxRedirectTargetBytes  = 256
)

var (
	// movedPath is a URL path this server writes into a rule: '/', then
	// letters, digits and - . _ ~ /.
	movedPath = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	// movedPattern is the alphabet of a RedirectMatch expression: no space,
	// quote, '#', '%' or brace, which the vhost's config or rewrite rules
	// would read differently.
	movedPattern = regexp.MustCompile(`^[A-Za-z0-9._~/^$*+?()\[\]|\\,:=!@-]+$`)
	// movedTarget is an http or https URL with a DNS name, an optional port
	// and an optional path and query, or a URL path with an optional
	// query, in letters, digits and - . _ ~ / ? & = + , : ; @ and, in a
	// RedirectMatch target, $ before a digit.
	movedTarget = regexp.MustCompile(`^(?:(https?)://([A-Za-z0-9.-]+)(:[1-9][0-9]{0,4})?)?((?:/[A-Za-z0-9._~/?&=+,:;@$-]*)?)$`)
	dnsName     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	backRef     = regexp.MustCompile(`\$[0-9]`)
	// apacheURL is server/util.c ap_is_url: letters, digits, + - . and
	// then a colon.
	apacheURL = regexp.MustCompile(`^[A-Za-z0-9+.-]+:`)
)

// redirectStatusWord reads a mod_alias status argument: ok is false when
// the argument is not one.
func redirectStatusWord(arg string) (status int, ok bool) {
	if s := redirectStatus(arg); s != 0 {
		return s, true
	}
	return 0, false
}

// convertRedirect reads a redirect line OpenLiteSpeed ignores. It returns
// the redirect the vhost carries, or no handling and why not.
func (c *classifier) convertRedirect(name string, args []string, sc scope) (Handling, string, *Redirect) {
	status, from, to := 302, "", ""
	switch name {
	case "redirectpermanent", "redirecttemp":
		if name == "redirectpermanent" {
			status = 301
		}
		if len(args) != 2 {
			return "", "a " + name + " line without a path and an address, which this server does not convert", nil
		}
		from, to = args[0], args[1]
	default:
		s, isStatus := 0, false
		if len(args) > 0 {
			s, isStatus = redirectStatusWord(args[0])
		}
		switch {
		case len(args) == 3 && isStatus:
			status, from, to = s, args[1], args[2]
		case len(args) == 2 && !isStatus:
			from, to = args[0], args[1]
		default:
			return "", "a redirect that sends this whole folder, or has no path or address, which this server does not convert", nil
		}
	}
	if !c.root || !movable(sc) {
		return "", "a redirect in a folder's .htaccess or inside a section, which this server converts only at the top level of the site's root .htaccess", nil
	}
	if status != 301 && status != 302 {
		return "", "a redirect with status " + strconv.Itoa(status) + ", which this server converts only for 301 and 302", nil
	}
	regex := name == "redirectmatch"
	target, ok := moveTarget(to, regex)
	if !ok {
		return "", "a redirect to an address this server does not write into its rules: it must be http:// or https:// with a domain name, or a path, of letters, digits and - . _ ~ / ? & = + , : ; @", nil
	}
	r := &Redirect{Target: target, Status: status}
	if regex {
		if !movablePattern(from) {
			return "", "a RedirectMatch expression this server does not write into its rules: it must be a plain regular expression without spaces, quotes, braces, # or %, not starting with !", nil
		}
		r.Pattern = from
	} else {
		if !movablePath(from, MaxRedirectPrefixBytes) {
			return "", "a redirect of a path this server does not write into its rules: it must be / then letters, digits and - . _ ~ /, with no empty part or part starting with a dot", nil
		}
		r.Prefix = from
	}
	return HandlingConverted, "redirect (" + strconv.Itoa(status) + "): OpenLiteSpeed does not read it from .htaccess, so this server writes the same redirect into the site's web server configuration", r
}

// convertErrorDocument reads an ErrorDocument line.
func (c *classifier) convertErrorDocument(args []string, sc scope) (Handling, string, *ErrorPage) {
	if len(args) != 2 {
		return "", "an ErrorDocument line without a status and a page", nil
	}
	status, err := strconv.Atoi(args[0])
	if err != nil || !((status >= 400 && status <= 451) || (status >= 500 && status <= 510)) {
		return "", "an ErrorDocument for a status OpenLiteSpeed has no error page for", nil
	}
	if !c.root || !movable(sc) {
		return "", "an ErrorDocument in a folder's .htaccess or inside a section, which this server converts only at the top level of the site's root .htaccess", nil
	}
	msg := args[1]
	switch {
	case strings.EqualFold(msg, "default"):
		return HandlingSifruno, "the server's own error page: OpenLiteSpeed shows its own for this status", &ErrorPage{Status: status}
	case strings.Contains(msg, " ") || (!strings.HasPrefix(msg, "/") && !apacheURL.MatchString(msg)):
		// The copy shows OpenLiteSpeed's own page, as for "default".
		return HandlingWarning, "a custom error text for status " + strconv.Itoa(status) + ": OpenLiteSpeed answers the same status with its own error page, without this text. Check that the site does not depend on it before cutover.", &ErrorPage{Status: status}
	case strings.HasPrefix(msg, "/") && movablePath(msg, MaxRedirectPrefixBytes) && msg != "/":
		return HandlingConverted, "error page: OpenLiteSpeed does not read it from .htaccess, so this server writes the same page for this status into the site's web server configuration", &ErrorPage{Status: status, URL: msg}
	case strings.HasPrefix(msg, "/"):
		return "", "an error page at a path this server does not write into its rules: it must be / then letters, digits and - . _ ~ /, with no query, empty part or part starting with a dot", nil
	}
	return "", "an error page on a full address: Apache answers it with a redirect, which this server does not convert", nil
}

// movable reports a line at the top level of its file, or inside
// <IfModule> sections Apache reads: OpenLiteSpeed's vhost rule applies to
// every request, and Apache applies the line to every request that reads
// the root .htaccess.
func movable(sc scope) bool {
	return !sc.scoped && !sc.conditional && !sc.negated && !sc.vendor
}

// movablePath is a URL path for a converted rule: '/', then letters,
// digits and - . _ ~ /, with no empty part and no part starting with a dot.
func movablePath(p string, max int) bool {
	if len(p) > max || !movedPath.MatchString(p) || strings.Contains(p, "//") {
		return false
	}
	for _, part := range strings.Split(p[1:], "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

// movablePattern is a RedirectMatch expression the vhost can carry: its
// alphabet, a length bound, no leading '!' (a negated rewrite pattern),
// and one Go's regexp parser reads with Perl syntax, which rules out the
// PCRE forms the two engines could read differently (lookarounds, back
// references, possessive and atomic groups).
func movablePattern(p string) bool {
	if len(p) > MaxRedirectPatternBytes || !movedPattern.MatchString(p) || strings.HasPrefix(p, "!") {
		return false
	}
	_, err := syntax.Parse(p, syntax.Perl)
	return err == nil
}

// moveTarget checks a redirect target and returns it with its host in
// lower case. Only a RedirectMatch target may hold $ (before a digit).
func moveTarget(t string, regex bool) (string, bool) {
	if len(t) > MaxRedirectTargetBytes {
		return "", false
	}
	m := movedTarget.FindStringSubmatch(t)
	if m == nil || (m[1] == "" && m[4] == "") {
		return "", false
	}
	if dollars := strings.Count(t, "$"); dollars > 0 && (!regex || len(backRef.FindAllString(t, -1)) != dollars) {
		return "", false
	}
	if m[1] == "" {
		return t, true
	}
	host := strings.ToLower(m[2])
	if !dnsName.MatchString(host) || net.ParseIP(host) != nil || len(host) > 253 {
		return "", false
	}
	if m[3] != "" {
		if port, err := strconv.Atoi(m[3][1:]); err != nil || port > 65535 {
			return "", false
		}
	}
	return m[1] + "://" + host + m[3] + m[4], true
}
