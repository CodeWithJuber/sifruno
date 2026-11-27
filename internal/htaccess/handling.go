package htaccess

import (
	"regexp"
	"strings"
)

// Handling says what Sifruno does about a directive OpenLiteSpeed does not
// act on. A line with no Handling keeps its file off the Native tier: only
// the classes below let a site move with a line OpenLiteSpeed ignores.
//
// Access control is decided before any class here (classify.go directive):
// a line that changes who may reach what, or whether a file runs as a
// script, is CategoryAccessControl and never gets a Handling. Anything
// unknown or unparseable fails closed the same way.
//
//	class        directives                                  why it may be ignored
//	ignored      ExpiresActive, ExpiresByType, ExpiresDefault browser caching hints
//	             FileETag                                     ETag format only
//	             Header set|append|add|merge|setifempty|unset caching or security response
//	               of a caching or security header           headers (lists below)
//	             AddOutputFilter[ByType], SetOutputFilter      compression, OpenLiteSpeed
//	               with DEFLATE or BROTLI_COMPRESS only,       compresses by its own settings
//	               Deflate*, Brotli*, mod_gzip_*,
//	               SetEnvIf*/BrowserMatch* setting only the
//	               compression variables, RequestHeader on
//	               Accept-Encoding
//	             AddType of a plain media type for file        MIME detail
//	               suffixes that are not scripts, and of the
//	               usual type for HTML, SVG, JS and XML
//	             AddDefaultCharset, AddCharset                 character set hint
//	             php_value, php_flag Off for a setting PHP     PHP 8 has no such setting
//	               5.4 removed (register_globals ...)
//	handled      AddHandler/AddType of cPanel's PHP handler    the PHP version comes from the
//	               for PHP suffixes only                       migration plan (PHPHandler); the
//	                                                           vhost refuses .phtml, .php8 ...
//	             Options -Indexes, -MultiViews, +FollowSymLinks the vhost does the same
//	             CacheLookup on                                the vhost's cache module looks up
//	             ErrorDocument code default (root .htaccess)   OpenLiteSpeed's own page
//	             session.save_path naming cPanel's session     this server's PHP keeps sessions
//	               folder, in the root .htaccess               in its own folder
//	converted    Redirect, RedirectMatch, RedirectPermanent,   the vhost carries them
//	               RedirectTemp 301/302, ErrorDocument code    (redirect.go)
//	               /path, at the top of the root .htaccess
//	             php_value, php_flag of a listed setting with  the vhost's phpIniOverride
//	               a checked value, at the top of the root     carries them (phpsettings.go)
//	               .htaccess
//	warning      Header on CORS headers or X-Robots-Tag        the vhost cannot send them yet
//	             SetEnvIf*/BrowserMatch* setting only          they condition headers that are
//	               variables Header lines test (env=)          not sent here either
//	             ErrorDocument code "text" (root .htaccess)    OpenLiteSpeed's own page instead
//
// The reasons, with their evidence, are in the comments of handle.
type Handling string

const (
	// HandlingIgnored: harmless to ignore. On Apache the line is a hint the
	// site does not depend on, and losing it opens nothing.
	HandlingIgnored Handling = "ignored"
	// HandlingSifruno: Sifruno does the same job another way.
	HandlingSifruno Handling = "handled"
	// HandlingConverted: OpenLiteSpeed does not read it from .htaccess, and
	// the root broker writes the same rule into the site's vhost
	// (SiteConversion.Redirects, ErrorPages and PHPSettings).
	HandlingConverted Handling = "converted"
	// HandlingWarning: OpenLiteSpeed does not apply it and Sifruno does not
	// convert it, but losing it opens nothing. The site moves, and the
	// migration shows the line as a note a person accepts before cutover.
	HandlingWarning Handling = "warning"
)

// CauseNotConverted is a refused line that OpenLiteSpeed ignores and that
// is not access control, not unknown and in no class above: losing it
// would change what the site does, so the file is not Native.
const CauseNotConverted = "not_converted"

// FileWarning is a line a person should check before cutover: what
// OpenLiteSpeed will not do that the old server did.
type FileWarning struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Directive string `json:"directive"`
	Reason    string `json:"reason"`
}

// PHPHandler is a line that chose the PHP version on the old server, for
// the folder at Path. Package is the version it named ("ea-php81",
// "alt-php74", "php74"), or empty for one that names none.
type PHPHandler struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Directive string `json:"directive"`
	Path      string `json:"path"`
	Package   string `json:"package,omitempty"`
}

// handle classifies one directive OpenLiteSpeed does not act on. name is
// lower case; envRead holds the lower-case environment variables the file's
// rewrite lines read (rewriteEnvReads), and headerEnv those its Header
// lines test (headerEnvReads). It returns no Handling for a line no class
// covers; php is the PHP package a handler line names.
func handle(name string, args []string, envRead, headerEnv map[string]bool) (h Handling, reason, php string) {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch name {
	case "expiresactive", "expiresbytype", "expiresdefault":
		// mod_expires adds Expires and Cache-Control max-age: how long a
		// browser may keep a response before asking again. Without them a
		// browser asks sooner; every answer is the same.
		return HandlingIgnored, "browser caching hint: browsers ask again sooner, and the site answers the same", ""
	case "fileetag":
		// FileETag picks the inode, time and size parts of Apache's ETag.
		// OpenLiteSpeed makes its own ETags for static files.
		return HandlingIgnored, "ETag format: OpenLiteSpeed makes its own ETags", ""
	case "header":
		if headerIsHint(args) {
			return HandlingIgnored, "caching or security response header: the copy does not send it, which changes how long browsers keep files or drops a browser-side defence, and opens nothing on the server", ""
		}
		// CORS and X-Robots-Tag change what other sites and search engines
		// do with the site's answers, and losing them opens nothing on the
		// server. OpenLiteSpeed 1.9.4 sends extra headers only from a
		// context's "Header Operations" (extraHeaders,
		// src/http/httpcontext.cpp); Sifruno's vhost has no context that
		// covers the whole site (a regex context would turn the site's
		// rewrite rules off below it, as for a converted folder), so it
		// cannot send them yet, and a person checks them before cutover.
		if h := warnedHeader(args); h != "" {
			return HandlingWarning, headerWarning(h), ""
		}
	case "requestheader":
		// The HTML5 Boilerplate fix for proxies that mangle
		// Accept-Encoding: it only lets more responses be compressed.
		if len(args) >= 2 && headerActions[strings.ToLower(args[0])] && strings.EqualFold(args[1], "Accept-Encoding") {
			return HandlingIgnored, "compression hint: OpenLiteSpeed compresses by its own settings", ""
		}
	case "addoutputfilterbytype", "addoutputfilter", "setoutputfilter":
		// mod_deflate and mod_brotli compress the response body; the content
		// is the same. OpenLiteSpeed compresses by its server settings.
		// Any other filter (INCLUDES, SUBSTITUTE, ...) changes the content.
		if compressionFilters(arg(0)) {
			return HandlingIgnored, "compression: OpenLiteSpeed compresses by its own settings", ""
		}
	case "setenvif", "setenvifnocase", "browsermatch", "browsermatchnocase", "setenvifexpr":
		// Only Apache's own compression variables (env.html, "Special
		// Purpose Environment Variables": no-gzip, dont-vary,
		// gzip-only-text/html, force-gzip; no-brotli for mod_brotli) and the
		// boilerplate's HAVE_Accept-Encoding. A variable the site's code
		// could read is not covered, nor one a rewrite line of the file
		// reads (%{ENV:no-gzip}): OpenLiteSpeed would not set it, so that
		// rule would change. A variable an Allow, Deny or Require line tests
		// made this line access control before handle runs.
		if compressionVariables(name, args, envRead) {
			return HandlingIgnored, "compression hint: OpenLiteSpeed compresses by its own settings", ""
		}
		// WP Rocket's CORS block sets IS_CORS for "Header ... env=IS_CORS".
		// Such a variable conditions a header the copy does not send
		// either, but PHP could read it too, so a person checks.
		if headerVariables(name, args, envRead, headerEnv) {
			return HandlingWarning, "sets a variable only this file's Header lines test, and those headers are not sent here: the copy does not set it. Check that the site's code does not read it before cutover.", ""
		}
	case "addtype":
		if pkg, ok := phpHandler(args); ok {
			return HandlingSifruno, phpHandlerReason, pkg
		}
		if plainType(args) {
			return HandlingIgnored, "MIME type for files that are not scripts: OpenLiteSpeed names types from its own list", ""
		}
	case "addhandler":
		if pkg, ok := phpHandler(args); ok {
			return HandlingSifruno, phpHandlerReason, pkg
		}
	case "adddefaultcharset", "addcharset":
		// The charset parameter of a static file's Content-Type. PHP pages
		// name their own (WordPress sends charset=UTF-8).
		return HandlingIgnored, "character set hint for static files: PHP pages send their own", ""
	case "options":
		if optionsHandled(args) {
			return HandlingSifruno, "OpenLiteSpeed does this already here: every Sifruno vhost has autoIndex 0 (no folder listings), OpenLiteSpeed 1.9.4 has no content negotiation (MultiViews), and the vhost follows links that stay inside the home (allowSymbolLink 1, restrained 1)", ""
		}
	case "cachelookup":
		// LiteSpeed Cache's "CacheLookup on" turns on LiteSpeed Enterprise's
		// cache lookup. OpenLiteSpeed ignores it; Sifruno's vhost turns the
		// cache module's lookup on for every request (olsweb render.go
		// cacheSettings: checkPublicCache 1, checkPrivateCache 1). Off is
		// not covered: the vhost would still look up.
		if len(args) > 0 && strings.EqualFold(args[len(args)-1], "on") {
			return HandlingSifruno, "LiteSpeed cache lookup: this server's cache module looks up every request already", ""
		}
	}
	if strings.HasPrefix(name, "deflate") || strings.HasPrefix(name, "brotli") || strings.HasPrefix(name, "mod_gzip_") {
		if e, ok := lookup(name); ok && e.category == CategoryCompression {
			return HandlingIgnored, "compression setting: OpenLiteSpeed compresses by its own settings", ""
		}
	}
	return "", "", ""
}

const phpHandlerReason = "PHP handler: this server runs the site's .php files with the PHP version the migration reads from the old server's settings for the site, and refuses (403) the other PHP suffixes, such as .phtml and .php8, so their source is never sent"

// headerActions are the Header actions that add, change or remove a
// response header outright. echo, edit and note are not covered.
var headerActions = map[string]bool{"set": true, "append": true, "add": true, "merge": true, "setifempty": true, "unset": true}

// hintHeaders are response headers a site can lose without anything on the
// server opening: caching headers (how long browsers and proxies keep a
// response), security headers (defences a browser applies) and
// X-Powered-By (names software; nothing reads it). A header such as
// Access-Control-Allow-Origin, X-Robots-Tag or Set-Cookie changes what
// clients may do with the site and is not covered.
var hintHeaders = map[string]bool{
	"cache-control": true, "expires": true, "pragma": true, "etag": true, "last-modified": true, "vary": true,
	"strict-transport-security": true, "x-content-type-options": true, "x-frame-options": true,
	"x-xss-protection": true, "referrer-policy": true, "permissions-policy": true, "feature-policy": true,
	"content-security-policy": true, "content-security-policy-report-only": true,
	"x-permitted-cross-domain-policies": true, "cross-origin-opener-policy": true,
	"cross-origin-embedder-policy": true, "cross-origin-resource-policy": true,
	"x-powered-by": true,
}

// headerIsHint reads Header [always|onsuccess] action header [value ...]
// (mod_headers) and reports a covered action on a hint header.
func headerIsHint(args []string) bool {
	h := headerName(args)
	return h != "" && hintHeaders[h]
}

// headerName is the lower-case header a Header line with a covered action
// changes, or "". mod_headers cuts the name at its first colon
// (modules/metadata/mod_headers.c header_inout_cmd: "The header name can
// include the colon, or not"), so WP Rocket's "Header append Vary:
// Accept-Encoding" changes Vary.
func headerName(args []string) string {
	if len(args) > 0 && (strings.EqualFold(args[0], "always") || strings.EqualFold(args[0], "onsuccess")) {
		args = args[1:]
	}
	if len(args) < 2 || !headerActions[strings.ToLower(args[0])] {
		return ""
	}
	name, _, _ := strings.Cut(args[1], ":")
	return strings.ToLower(name)
}

// warnedHeaders are the response headers a site can lose without anything
// on the server opening, but whose loss a person should see: CORS headers
// let pages on other domains (a CDN, another site) use the site's fonts,
// scripts and answers, and X-Robots-Tag keeps files out of search results.
var warnedHeaders = map[string]bool{
	"access-control-allow-origin": true, "access-control-allow-methods": true,
	"access-control-allow-headers": true, "access-control-allow-credentials": true,
	"access-control-expose-headers": true, "access-control-max-age": true,
	"x-robots-tag": true,
}

// warnedHeader is the header of a Header line on a warned header, or "".
func warnedHeader(args []string) string {
	if h := headerName(args); warnedHeaders[h] {
		return h
	}
	return ""
}

func headerWarning(h string) string {
	const base = "OpenLiteSpeed does not send response headers from .htaccess, and this server cannot write them into the site's configuration yet, so the copy does not send "
	if h == "x-robots-tag" {
		return base + "X-Robots-Tag: search engines may list pages or files the old site kept out of their results. Check them before cutover."
	}
	return base + "this CORS header (Access-Control-*): browsers then refuse the site's fonts, scripts or answers to pages on other domains, such as a CDN. Check them before cutover."
}

// headerEnvReads lists, lower case, the environment variables the file's
// Header lines test with env=VAR or env=!VAR.
func headerEnvReads(lines []Line) map[string]bool {
	read := map[string]bool{}
	for _, l := range lines {
		if l.Kind != LineDirective || !strings.EqualFold(l.Node.Name, "Header") {
			continue
		}
		for _, a := range l.Node.Args {
			if v, ok := strings.CutPrefix(strings.ToLower(a), "env="); ok {
				read[strings.TrimPrefix(v, "!")] = true
			}
		}
	}
	return read
}

// headerVariables reports a SetEnvIf-family line that sets only variables
// the file's Header lines test and no rewrite line reads.
func headerVariables(name string, args []string, envRead, headerEnv map[string]bool) bool {
	skip := 2
	if strings.HasPrefix(name, "browsermatch") || name == "setenvifexpr" {
		skip = 1
	}
	if len(args) <= skip {
		return false
	}
	for _, v := range args[skip:] {
		v, _, _ = strings.Cut(strings.TrimPrefix(v, "!"), "=")
		if v = strings.ToLower(v); !headerEnv[v] || envRead[v] {
			return false
		}
	}
	return true
}

func compressionFilters(list string) bool {
	if list == "" {
		return false
	}
	for _, f := range strings.Split(list, ";") {
		switch strings.ToUpper(strings.TrimSpace(f)) {
		case "DEFLATE", "BROTLI_COMPRESS":
		default:
			return false
		}
	}
	return true
}

var compressionVars = map[string]bool{"no-gzip": true, "dont-vary": true, "gzip-only-text/html": true, "force-gzip": true, "no-brotli": true, "have_accept-encoding": true}

// compressionVariables reports a SetEnvIf-family line that sets only
// compression variables that no rewrite line reads. SetEnvIf takes an
// attribute and a regex before them, BrowserMatch and SetEnvIfExpr one
// argument.
func compressionVariables(name string, args []string, envRead map[string]bool) bool {
	skip := 2
	if strings.HasPrefix(name, "browsermatch") || name == "setenvifexpr" {
		skip = 1
	}
	if len(args) <= skip {
		return false
	}
	for _, v := range args[skip:] {
		v, _, _ = strings.Cut(strings.TrimPrefix(v, "!"), "=")
		if v = strings.ToLower(v); !compressionVars[v] || envRead[v] {
			return false
		}
	}
	return true
}

var envReference = regexp.MustCompile(`(?i)%\{ENV:([^}]*)\}`)

// rewriteEnvReads lists, lower case, the environment variables the file's
// RewriteCond and RewriteRule lines read with %{ENV:name}.
func rewriteEnvReads(lines []Line) map[string]bool {
	read := map[string]bool{}
	for _, l := range lines {
		if l.Kind != LineDirective || (!strings.EqualFold(l.Node.Name, "RewriteCond") && !strings.EqualFold(l.Node.Name, "RewriteRule")) {
			continue
		}
		for _, a := range l.Node.Args {
			for _, m := range envReference.FindAllStringSubmatch(a, -1) {
				read[strings.ToLower(m[1])] = true
			}
		}
	}
	return read
}

// phpHandlerType matches the handler names cPanel's MultiPHP writes
// (application/x-httpd-ea-php81), CloudLinux's (x-httpd-alt-php74___lsphp)
// and the plain x-httpd-php and x-httpd-phpNN forms.
var phpHandlerType = regexp.MustCompile(`(?i)^(?:application/)?x-httpd-((?:ea-|alt-)?php(?:[0-9]{1,2})?)(?:___lsphp)?$`)

// phpHandler reads AddHandler or AddType naming a PHP handler for PHP
// suffixes only. On this server only .php runs as PHP, with the version
// the migration plan reads from the old server, so the line chooses
// nothing here; every vhost answers 403 for the other PHP suffixes
// (olsweb denyRules), which OpenLiteSpeed would otherwise send as files
// with their source. A handler that also names another suffix (.html)
// would run that suffix as PHP on Apache; OpenLiteSpeed would serve its
// source, so it is not covered.
func phpHandler(args []string) (string, bool) {
	if len(args) < 2 {
		return "", false
	}
	m := phpHandlerType.FindStringSubmatch(args[0])
	if m == nil {
		return "", false
	}
	for _, ext := range args[1:] {
		if !phpSuffix(ext) {
			return "", false
		}
	}
	pkg := strings.ToLower(m[1])
	if pkg == "php" {
		pkg = ""
	}
	return pkg, true
}

func phpSuffix(ext string) bool {
	switch strings.ToLower(strings.TrimPrefix(ext, ".")) {
	case "php", "php3", "php4", "php5", "php7", "php8", "phtml":
		return true
	}
	return false
}

var mediaType = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$`)
var suffixName = regexp.MustCompile(`^\.?[A-Za-z0-9_-]{1,16}$`)

// plainType reads AddType media-type suffix... and reports a plain media
// type for suffixes that are not scripts. A handler-like type
// (x-httpd-..., server-parsed) runs files on Apache, and a type for a
// script suffix (AddType text/plain .php) can be what stops a script from
// running there; OpenLiteSpeed ignoring either changes what runs, so
// neither is covered. A suffix a browser renders or runs (renderedTypes)
// is covered only with its usual type: AddType text/plain .html or
// application/octet-stream .svg is uploads hardening that keeps a browser
// from running what someone uploaded, and OpenLiteSpeed would serve those
// files with their usual type.
func plainType(args []string) bool {
	if len(args) < 2 || !mediaType.MatchString(args[0]) {
		return false
	}
	t := strings.ToLower(args[0])
	for _, bad := range []string{"x-httpd", "server-parsed", "php", "cgi"} {
		if strings.Contains(t, bad) {
			return false
		}
	}
	for _, ext := range args[1:] {
		if !suffixName.MatchString(ext) || scriptSuffix(ext) {
			return false
		}
		if usual, rendered := renderedTypes[strings.ToLower(strings.TrimPrefix(ext, "."))]; rendered && !strings.Contains(usual, " "+t+" ") {
			return false
		}
	}
	return true
}

// renderedTypes are the suffixes a browser renders or runs, each with the
// types that let it: OpenLiteSpeed 1.9.4's dist/conf/mime.properties gives
// these suffixes one of them.
var renderedTypes = map[string]string{
	"html":  " text/html ",
	"htm":   " text/html ",
	"xhtml": " application/xhtml+xml ",
	"svg":   " image/svg+xml ",
	"svgz":  " image/svg+xml ",
	"js":    " application/javascript text/javascript application/x-javascript ",
	"mjs":   " application/javascript text/javascript ",
	"xml":   " application/xml text/xml ",
}

func scriptSuffix(ext string) bool {
	e := strings.ToLower(strings.TrimPrefix(ext, "."))
	if strings.HasPrefix(e, "php") || strings.HasPrefix(e, "pht") {
		return true
	}
	switch e {
	case "phar", "cgi", "fcgi", "pl", "py", "rb", "sh", "shtml", "shtm", "stm", "asp", "aspx", "jsp", "inc":
		return true
	}
	return false
}

// optionsHandled reports an Options line whose every option is signed and
// one this server already applies: -Indexes (every Sifruno vhost's index
// block has autoIndex 0, olsweb render.go), -MultiViews (OpenLiteSpeed
// 1.9.4's src/ has no content negotiation: no "MultiViews" and no
// negotiation code), +FollowSymLinks (the vhost has allowSymbolLink 1 and
// restrained 1, which follows a link only while its target stays inside
// the home; Apache's own follows any). -FollowSymLinks,
// +SymLinksIfOwnerMatch and the rest would narrow or widen what is served
// differently on OpenLiteSpeed, and an unsigned list replaces Apache's set
// (optionsAccess), so none of them is covered.
func optionsHandled(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		switch strings.ToLower(a) {
		case "-indexes", "-multiviews", "+followsymlinks":
		default:
			return false
		}
	}
	return true
}

// labelToken is an argument safe to show beside a directive's name: a word
// without dots, slashes or quotes (a setting, header or option name, On,
// Off) or a number with an optional unit. A path, a domain or a free text
// value is left out, so a label never names a customer's account or site.
var labelToken = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9_-]{0,63}|[0-9]{1,9}[A-Za-z]?)$`)

// label is a directive's name with its first arguments while they are safe
// to show, at most four: what a person searches the file for. A first word
// that does not look like a directive name (an unknown line can hold any
// text) is not shown, as in the scan's TopUnknown.
func label(n *Node) string {
	if !directiveName.MatchString(n.Name) {
		return unknownPlaceholder
	}
	parts := []string{n.Name}
	for _, a := range n.Args {
		if len(parts) > 4 || !labelToken.MatchString(a) {
			break
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}
