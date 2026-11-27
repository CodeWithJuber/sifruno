package sitesource

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"sifruno/internal/olsweb"
	"sifruno/internal/sitemodel"
)

// ConvertNginx turns one nginx server block into what Sifruno's
// OpenLiteSpeed site holds (docs/migration-design.md):
//
//   - a prefix location that denies everyone (deny all, or return 403 or
//     404) becomes a closed folder in the site's config;
//   - a regular-expression location that denies everyone becomes a rewrite
//     rule that answers 403 ([F]);
//   - return 301 or 302 to an absolute URL in an exact location becomes a
//     site redirect; any other 3xx return becomes a rewrite rule;
//   - rewrite becomes a RewriteRule, with a RewriteCond for the location it
//     sits in; try_files $uri $uri/ FALLBACK becomes the usual
//     front-controller rules;
//   - the PHP location tells that the site runs PHP, which version its
//     socket names, and its fastcgi_param PHP_VALUE settings.
//
// The rewrite lines are Apache's syntax for the document root's .htaccess,
// which OpenLiteSpeed reads (internal/htaccess, doc.go): a per-directory
// pattern without the leading slash. Anything else is refused with its
// file, line and directive, and a site with a refusal is not Native, so it
// does not move until a person deals with that line. Directives that change
// only caching, logging or headers are noted and do not stop the move.

// Conversion is one server block converted.
type Conversion struct {
	Rewrites      []string
	Redirects     []sitemodel.Redirect
	Folders       []string
	Settings      []sitemodel.Setting
	Refused       []sitemodel.Item
	Notes         []sitemodel.Item
	HTTPSRedirect bool
	PHP           bool
	PHPSource     string
	TLS           *TLSFiles
}

// TLSFiles are the certificate and key files a server block names.
type TLSFiles struct{ Certificate, Key string }

// harmless directives change caching, logging, compression or headers, or
// set what Sifruno sets itself (listen, server names, root, TLS). They do
// not decide who may read what.
var harmless = map[string]string{
	"access_log": "", "error_log": "", "log_not_found": "", "server_tokens": "", "sendfile": "", "tcp_nopush": "", "tcp_nodelay": "",
	"keepalive_timeout": "", "charset": "", "listen": "", "server_name": "", "http2": "", "ssl_protocols": "", "ssl_ciphers": "",
	"ssl_prefer_server_ciphers": "", "ssl_session_cache": "", "ssl_session_timeout": "", "ssl_session_tickets": "", "ssl_dhparam": "",
	"ssl_stapling": "", "ssl_stapling_verify": "", "ssl_trusted_certificate": "", "ssl_ecdh_curve": "", "resolver": "", "resolver_timeout": "",
	"expires":              "Cache lifetimes for files (expires) are not carried; OpenLiteSpeed's defaults apply.",
	"add_header":           "Extra response headers (add_header) are not carried.",
	"etag":                 "The etag setting is not carried.",
	"gzip":                 "Compression settings (gzip) are not carried; OpenLiteSpeed compresses by its own settings.",
	"gzip_static":          "Compression settings (gzip_static) are not carried.",
	"gzip_types":           "Compression settings (gzip_types) are not carried.",
	"gzip_vary":            "Compression settings (gzip_vary) are not carried.",
	"gzip_comp_level":      "Compression settings (gzip_comp_level) are not carried.",
	"gzip_min_length":      "Compression settings (gzip_min_length) are not carried.",
	"gzip_proxied":         "Compression settings (gzip_proxied) are not carried.",
	"open_file_cache":      "File cache settings (open_file_cache) are not carried.",
	"error_page":           "Custom error pages (error_page) are not carried; set them in the site's files if needed.",
	"autoindex":            "Folder listings (autoindex) are not carried: this server does not list folders.",
	"client_max_body_size": "client_max_body_size is not carried: uploads here are bounded by PHP's upload_max_filesize and post_max_size.",
}

// phpLocation are the directives a PHP location may hold.
var phpLocation = map[string]bool{
	"fastcgi_pass": true, "fastcgi_param": true, "fastcgi_index": true, "fastcgi_split_path_info": true, "fastcgi_intercept_errors": true,
	"fastcgi_read_timeout": true, "fastcgi_buffers": true, "fastcgi_buffer_size": true, "fastcgi_busy_buffers_size": true,
	"fastcgi_temp_file_write_size": true, "fastcgi_connect_timeout": true, "fastcgi_send_timeout": true, "include": true, "try_files": true,
}

// knownIncludes are the stock files a configuration includes for PHP,
// MIME types and TLS options; they hold no access rules.
var knownIncludes = regexp.MustCompile(`^(/etc/nginx/)?(fastcgi_params|fastcgi\.conf|mime\.types|snippets/fastcgi-php\.conf|snippets/ssl-[a-z0-9-]+\.conf|letsencrypt/options-ssl-nginx\.conf|/etc/letsencrypt/options-ssl-nginx\.conf)$`)

var (
	// A rewrite value may hold only what both servers read the same way:
	// no white space, no quote, no backslash before a non-ASCII byte.
	ruleText = regexp.MustCompile(`^[\x21-\x7e]+$`)
	// Variables a replacement may name, and what Apache calls them.
	replacementVars = map[string]string{"args": "%{QUERY_STRING}", "query_string": "%{QUERY_STRING}", "host": "%{HTTP_HOST}", "http_host": "%{HTTP_HOST}"}
	varRef          = regexp.MustCompile(`\$([a-z_]+|[0-9]|\{[a-z_]+\})`)
	httpsRedirect   = regexp.MustCompile(`^https://(\$host|\$server_name|\$http_host|[a-z0-9.-]+)\$request_uri$`)
	phpSocket       = regexp.MustCompile(`php-?([5-8])\.?([0-9])`)
	// After mapping, a $ may only start a back-reference ($1 to $9).
	onlyBackReferences = regexp.MustCompile(`^[^$]*(\$[0-9][^$]*)*$`)
)

// Apply puts the conversion into the website model: its rules, its PHP
// settings, and every refused or noted line. A refusal makes the site not
// Native: it does not move until a person deals with that line.
func (c Conversion) Apply(site *sitemodel.Site) {
	site.Rules.Rewrites = append([]string{}, c.Rewrites...)
	site.Rules.Redirects = append([]sitemodel.Redirect{}, c.Redirects...)
	site.Rules.Folders = append([]string{}, c.Folders...)
	site.Rules.Native = len(c.Refused) == 0
	for _, s := range c.Settings {
		site.AddSetting(s.Name, s.Value, s.From)
	}
	for _, item := range c.Refused {
		site.Skip(item.Part, "Not moved: "+item.Text, item.Where)
	}
	for _, item := range c.Notes {
		site.Skip(item.Part, item.Text, item.Where)
	}
}

type converter struct {
	file string
	c    Conversion
	// late are the front-controller rules, which come last.
	late []string
	// rules are every rule before them, in file order.
	rules []string
}

func (v *converter) at(line int) string { return fmt.Sprintf("%s line %d", v.file, line) }

func (v *converter) refuse(d *Directive, label, why string) {
	if label == "" {
		label = d.Name
	}
	v.c.Refused = append(v.c.Refused, sitemodel.Item{Part: "rule", Text: label + ": " + why, Where: v.at(d.Line)})
}

func (v *converter) note(d *Directive, text string) {
	v.c.Notes = append(v.c.Notes, sitemodel.Item{Part: "rule", Text: d.Name + ": " + text, Where: v.at(d.Line)})
}

// ConvertNginx converts one server block.
func ConvertNginx(s Server) Conversion {
	v := &converter{file: s.File}
	for _, d := range s.Body {
		switch d.Name {
		case "root", "server_name":
		case "index":
			v.index(d)
		case "ssl_certificate", "ssl_certificate_key":
			if len(d.Args) == 1 {
				if v.c.TLS == nil {
					v.c.TLS = &TLSFiles{}
				}
				if d.Name == "ssl_certificate" {
					v.c.TLS.Certificate = d.Args[0]
				} else {
					v.c.TLS.Key = d.Args[0]
				}
			}
		case "include":
			v.include(d)
		case "rewrite":
			if rule, ok := v.rewrite(d, ""); ok {
				v.rules = append(v.rules, rule...)
			}
		case "return":
			if len(d.Args) == 2 && (d.Args[0] == "301" || d.Args[0] == "302") && httpsRedirect.MatchString(d.Args[1]) {
				v.c.HTTPSRedirect = true
				v.c.Notes = append(v.c.Notes, sitemodel.Item{Part: "rule", Text: "The old server sent every http request to https. Turn on Always use HTTPS on the website's page once it has a certificate.", Where: v.at(d.Line)})
				continue
			}
			v.refuse(d, "", "a return for the whole server is not converted; only http to https is.")
		case "location":
			v.location(d)
		case "fastcgi_param":
			v.fastcgiParam(d)
		default:
			if text, ok := harmless[d.Name]; ok {
				if text != "" {
					v.note(d, text)
				}
				continue
			}
			v.refuse(d, "", "Sifruno does not convert this directive, so the site would behave differently here.")
		}
	}
	if rules := append(v.rules, v.late...); len(rules) > 0 {
		v.c.Rewrites = append([]string{"RewriteEngine On"}, rules...)
	}
	return v.c
}

func (v *converter) index(d *Directive) {
	for _, a := range d.Args {
		if a != "index.php" && a != "index.html" && a != "index.htm" {
			v.note(d, "the index file "+clip(a)+" is not carried; this server serves index.php and index.html.")
		}
	}
}

func (v *converter) include(d *Directive) bool {
	if len(d.Args) == 1 && knownIncludes.MatchString(d.Args[0]) {
		return true
	}
	v.refuse(d, "", "the file it names was not read, so what it does on the old server is unknown.")
	return false
}

func (v *converter) fastcgiParam(d *Directive) {
	if len(d.Args) < 2 {
		return
	}
	switch d.Args[0] {
	case "PHP_VALUE":
		for _, line := range strings.Split(strings.Join(d.Args[1:], " "), "\n") {
			name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok {
				v.c.Settings = append(v.c.Settings, sitemodel.Setting{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value), From: v.at(d.Line)})
			}
		}
	case "PHP_ADMIN_VALUE":
		v.note(d, "PHP_ADMIN_VALUE holds settings only the server may set; they do not move to the website's own settings.")
	}
}

// location converts one location block by what it does.
func (v *converter) location(d *Directive) {
	mod, path := "", ""
	switch len(d.Args) {
	case 1:
		path = d.Args[0]
	case 2:
		mod, path = d.Args[0], d.Args[1]
	default:
		v.refuse(d, "location", "its form is not one nginx documents.")
		return
	}
	label := "location " + strings.TrimSpace(mod+" "+clip(path))
	if mod == "" && strings.HasPrefix(path, "@") {
		v.refuse(d, "location "+clip(path), "named locations are not converted.")
		return
	}
	if mod != "" && mod != "=" && mod != "~" && mod != "~*" && mod != "^~" {
		v.refuse(d, label, "its form is not one nginx documents.")
		return
	}
	regex := mod == "~" || mod == "~*"
	if !regex && !strings.HasPrefix(path, "/") {
		v.refuse(d, label, "the path does not start with /.")
		return
	}
	if regex && !ruleText.MatchString(path) {
		v.refuse(d, label, "the pattern holds spaces or other characters a rewrite rule cannot carry.")
		return
	}
	// What the block does decides the conversion.
	var denies, returns, rewrites, tries, php, others []*Directive
	for _, c := range d.Block {
		switch {
		case c.Name == "location":
			v.refuse(c, "location", "a location inside another location is not converted.")
			return
		case c.Name == "deny" && len(c.Args) == 1 && c.Args[0] == "all":
			denies = append(denies, c)
		case c.Name == "return":
			returns = append(returns, c)
		case c.Name == "rewrite":
			rewrites = append(rewrites, c)
		case c.Name == "try_files":
			tries = append(tries, c)
		case c.Name == "fastcgi_pass":
			php = append(php, c)
		default:
			others = append(others, c)
		}
	}
	if len(php) > 0 {
		v.php(d, label, php[0], d.Block)
		return
	}
	for _, c := range others {
		if text, ok := harmless[c.Name]; ok {
			if text != "" {
				v.note(c, text)
			}
			continue
		}
		switch c.Name {
		case "index":
			v.index(c)
		case "fastcgi_param":
			v.fastcgiParam(c)
		case "include":
			v.include(c)
		case "auth_basic", "auth_basic_user_file":
			v.refuse(c, "", "password-protected folders in nginx are not converted yet; the folder would open to everyone.")
			return
		case "allow", "deny":
			v.refuse(c, "", "address lists in nginx are not converted yet; the folder would open to everyone.")
			return
		default:
			v.refuse(c, "", "Sifruno does not convert this directive, so the site would behave differently here.")
			return
		}
	}
	closed := len(denies) > 0
	for _, r := range returns {
		if len(r.Args) == 1 && (r.Args[0] == "403" || r.Args[0] == "404") {
			closed = true
			if r.Args[0] == "404" && !regex {
				v.c.Notes = append(v.c.Notes, sitemodel.Item{Part: "rule", Text: "The folder " + clip(path) + " answered 404 there; here it is closed and answers 403.", Where: v.at(r.Line)})
			}
			continue
		}
		v.redirect(d, mod, path, r)
	}
	if closed {
		v.close(d, label, mod, path)
	}
	cond, ok := v.condition(d, label, mod, path)
	if !ok {
		return
	}
	for _, r := range rewrites {
		if rule, ok := v.rewrite(r, cond); ok {
			v.rules = append(v.rules, rule...)
		}
	}
	for _, t := range tries {
		v.tryFiles(t, cond)
	}
}

// close makes a location that refuses everyone a closed folder, or for a
// pattern a rule that answers 403.
func (v *converter) close(d *Directive, label, mod, path string) {
	if (mod == "" || mod == "^~") && olsweb.ValidFolderPath(path) {
		v.c.Folders = append(v.c.Folders, path)
		return
	}
	pattern, ok := perDirectory(mod, path, true)
	if !ok {
		v.refuse(d, label, "it closes a path this server cannot close as it is.")
		return
	}
	v.rules = append(v.rules, "RewriteRule "+pattern+" - "+flags(mod, "F", "L"))
}

// redirect converts a 3xx return in a location.
func (v *converter) redirect(d *Directive, mod, path string, r *Directive) {
	status := 0
	if len(r.Args) == 2 {
		status, _ = strconv.Atoi(r.Args[0])
	}
	if status != 301 && status != 302 && status != 303 && status != 307 && status != 308 {
		v.refuse(r, "", "only a redirect (301, 302, 303, 307 or 308 with a target) or 403 and 404 are converted.")
		return
	}
	target := r.Args[1]
	if mod == "=" && (status == 301 || status == 302) && olsweb.ValidRedirectPath(path) {
		if _, ok := olsweb.ParseRedirectTarget(target, false); ok {
			v.c.Redirects = append(v.c.Redirects, sitemodel.Redirect{Path: path, Target: target, Status: status})
			return
		}
	}
	replacement, ok := v.replacement(r, target)
	if !ok {
		return
	}
	pattern, ok := perDirectory(mod, path, false)
	if !ok {
		v.refuse(r, "", "the location's path cannot be matched the same way here.")
		return
	}
	v.rules = append(v.rules, "RewriteRule "+pattern+" "+replacement+" "+flags(mod, "R="+strconv.Itoa(status), "L"))
}

// condition is the RewriteCond that keeps a rule to its location.
func (v *converter) condition(d *Directive, label, mod, path string) (string, bool) {
	switch {
	case mod == "" && path == "/":
		return "", true
	case mod == "" || mod == "^~":
		return "RewriteCond %{REQUEST_URI} ^" + regexp.QuoteMeta(path), ruleText.MatchString(path)
	case mod == "=":
		return "RewriteCond %{REQUEST_URI} ^" + regexp.QuoteMeta(path) + "$", ruleText.MatchString(path)
	}
	cond := "RewriteCond %{REQUEST_URI} " + path
	if mod == "~*" {
		cond += " [NC]"
	}
	return cond, true
}

// perDirectory turns a location's path or an nginx pattern into a pattern
// for the document root's .htaccess, where the path has no leading slash.
// An exact or prefix path is quoted; a pattern anchored at "^/" loses the
// slash; with loose, a pattern that starts with "/" matches at the start
// or after any slash.
func perDirectory(mod, path string, loose bool) (string, bool) {
	switch mod {
	case "=":
		return "^" + regexp.QuoteMeta(strings.TrimPrefix(path, "/")) + "$", ruleText.MatchString(path)
	case "", "^~":
		return "^" + regexp.QuoteMeta(strings.TrimPrefix(path, "/")), ruleText.MatchString(path)
	}
	switch {
	case !ruleText.MatchString(path):
		return "", false
	case strings.HasPrefix(path, "^/"):
		return "^" + path[2:], true
	case strings.HasPrefix(path, "^"):
		return "", false
	case strings.HasPrefix(path, "/") && loose:
		return "(^|/)" + path[1:], true
	case strings.HasPrefix(path, "/"):
		return "", false
	}
	return path, true
}

func flags(mod string, list ...string) string {
	if mod == "~*" {
		list = append(list, "NC")
	}
	return "[" + strings.Join(list, ",") + "]"
}

// rewrite converts one rewrite directive; cond, when set, goes before it.
func (v *converter) rewrite(d *Directive, cond string) ([]string, bool) {
	if len(d.Args) != 2 && len(d.Args) != 3 {
		v.refuse(d, "", "it does not have a pattern, a replacement and at most one flag.")
		return nil, false
	}
	if !strings.HasPrefix(d.Args[0], "^/") || !ruleText.MatchString(d.Args[0]) {
		v.refuse(d, "", "only patterns that start with ^/ are converted, so the rule matches here exactly what it matched there.")
		return nil, false
	}
	pattern := "^" + d.Args[0][2:]
	replacement, ok := v.replacement(d, d.Args[1])
	if !ok {
		return nil, false
	}
	var fl []string
	switch flag := ""; {
	case len(d.Args) == 3:
		flag = d.Args[2]
		switch flag {
		case "last", "break":
			fl = []string{"L"}
		case "redirect":
			fl = []string{"R=302", "L"}
		case "permanent":
			fl = []string{"R=301", "L"}
		default:
			v.refuse(d, "", "the flag "+clip(flag)+" is not one nginx documents.")
			return nil, false
		}
	case strings.HasPrefix(replacement, "http://") || strings.HasPrefix(replacement, "https://"):
		fl = []string{"R=302", "L"}
	}
	// nginx adds the request's own query after a replacement's; Apache
	// drops it unless asked.
	if strings.Contains(replacement, "?") && !strings.HasSuffix(replacement, "?") {
		fl = append(fl, "QSA")
	}
	rule := "RewriteRule " + pattern + " " + replacement
	if len(fl) > 0 {
		rule += " [" + strings.Join(fl, ",") + "]"
	}
	if cond != "" {
		return []string{cond, rule}, true
	}
	return []string{rule}, true
}

// replacement maps an nginx replacement's variables to Apache's, refusing
// one it cannot map.
func (v *converter) replacement(d *Directive, s string) (string, bool) {
	if !ruleText.MatchString(s) || strings.ContainsAny(s, "%\\") {
		v.refuse(d, "", "the replacement holds spaces, % or \\, which a rewrite rule here reads differently.")
		return "", false
	}
	failed := ""
	out := varRef.ReplaceAllStringFunc(s, func(ref string) string {
		name := strings.Trim(ref[1:], "{}")
		if len(name) == 1 && name[0] >= '0' && name[0] <= '9' {
			return "$" + name
		}
		if mapped, ok := replacementVars[name]; ok {
			return mapped
		}
		failed = name
		return ref
	})
	if failed != "" {
		v.refuse(d, "", "the variable $"+clip(failed)+" has no equivalent here.")
		return "", false
	}
	if !onlyBackReferences.MatchString(out) {
		v.refuse(d, "", "the replacement holds a $ that is not a variable.")
		return "", false
	}
	return out, true
}

// tryFiles converts try_files: $uri and $uri/ become "not a file" and
// "not a folder" conditions, and the last value the rule they lead to.
func (v *converter) tryFiles(d *Directive, cond string) {
	if len(d.Args) < 2 {
		v.refuse(d, "", "it does not name what to try and a fallback.")
		return
	}
	var conds []string
	for _, a := range d.Args[:len(d.Args)-1] {
		switch a {
		case "$uri":
			conds = append(conds, "RewriteCond %{REQUEST_FILENAME} !-f")
		case "$uri/":
			conds = append(conds, "RewriteCond %{REQUEST_FILENAME} !-d")
		default:
			v.refuse(d, "", "it tries "+clip(a)+", which is not converted.")
			return
		}
	}
	last := d.Args[len(d.Args)-1]
	var rule string
	switch {
	case last == "=404":
		return // the web server's own behaviour
	case strings.HasPrefix(last, "/"):
		target, query, _ := strings.Cut(last, "?")
		target = strings.TrimSuffix(target, "$is_args$args")
		if !ruleText.MatchString(target) || strings.ContainsAny(target, "$%\\") {
			v.refuse(d, "", "its fallback "+clip(last)+" is not converted.")
			return
		}
		switch query {
		case "", "$args", "$query_string":
			rule = "RewriteRule ^ " + target + " [L]"
		case "q=$uri&$args", "q=$uri":
			rule = "RewriteRule ^(.*)$ " + target + "?q=/$1 [L,QSA]"
		default:
			v.refuse(d, "", "its fallback "+clip(last)+" is not converted.")
			return
		}
	default:
		v.refuse(d, "", "its fallback "+clip(last)+" is not converted.")
		return
	}
	if cond != "" {
		v.late = append(v.late, cond)
	}
	v.late = append(v.late, conds...)
	v.late = append(v.late, rule)
}

// php reads the PHP location: the site runs PHP, with the version its
// socket names, and its settings. Anything else in it is refused.
func (v *converter) php(d *Directive, label string, pass *Directive, block []*Directive) {
	v.c.PHP = true
	if len(pass.Args) == 1 {
		if m := phpSocket.FindStringSubmatch(pass.Args[0]); m != nil {
			v.c.PHPSource = "php" + m[1] + "." + m[2] + "-fpm"
		}
	}
	for _, c := range block {
		switch {
		case !phpLocation[c.Name] && harmless[c.Name] == "" && !isHarmless(c.Name):
			v.refuse(c, "", "the PHP location holds a directive Sifruno does not convert.")
		case c.Name == "include":
			v.include(c)
		case c.Name == "fastcgi_param":
			v.fastcgiParam(c)
		case c.Name == "try_files" && !(len(c.Args) == 2 && c.Args[0] == "$uri" && c.Args[1] == "=404"):
			v.refuse(c, "", "the PHP location's try_files is not the usual $uri =404.")
		}
	}
}

func isHarmless(name string) bool { _, ok := harmless[name]; return ok }

// clip keeps a value from the file to one short line in a message.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}
