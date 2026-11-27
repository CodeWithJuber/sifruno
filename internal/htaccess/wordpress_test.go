package htaccess

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// wordpressPlugins is testdata/wordpress-plugins.htaccess: a synthetic root
// .htaccess built from the blocks WP Rocket, Wordfence, Solid Security
// (iThemes Security) and WordPress write, with the wp-config.php rule of
// WordPress's hardening guide. The file's header names each source.
func wordpressPlugins(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/wordpress-plugins.htaccess")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// lineOf is the 1-based line of the nth (from 1) line of text that holds
// part.
func lineOf(t *testing.T, text, part string, nth int) int {
	t.Helper()
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, part) {
			if nth--; nth == 0 {
				return i + 1
			}
		}
	}
	t.Fatalf("no line %d with %q", nth, part)
	return 0
}

func TestWordPressPluginBlocksMove(t *testing.T) {
	text := wordpressPlugins(t)
	got := ConvertSite(siteOf(map[string]string{".htaccess": text}))
	if !got.Native || len(got.Refused) != 0 {
		t.Fatalf("not native: %+v", got.Refused)
	}
	want := []FolderRule{{File: ".htaccess", Path: "/", Hosts: Hosts{Kind: HostsAll}, Deny: &Names{Exact: []string{
		".htaccess", ".user.ini", "readme.html", "readme.txt", "wp-config.php", "xmlrpc.php",
	}}}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Fatalf("rules %+v", got.Rules)
	}
	// WP Rocket's CORS block (CDN option on): the headers, and the variable
	// only the image header tests, are not carried, and a person checks.
	var lines []int
	for _, w := range got.Warnings {
		lines = append(lines, w.Line)
		if w.File != ".htaccess" || w.Reason == "" {
			t.Errorf("warning %+v", w)
		}
	}
	wantLines := []int{
		lineOf(t, text, `SetEnvIf Origin ":" IS_CORS`, 1),
		lineOf(t, text, "Header set Access-Control-Allow-Origin", 1),
		lineOf(t, text, "Header set Access-Control-Allow-Origin", 2),
	}
	if !slices.Equal(lines, wantLines) {
		t.Fatalf("warning lines %v, want %v: %+v", lines, wantLines, got.Warnings)
	}
	if !strings.Contains(got.Warnings[1].Reason, "CORS") {
		t.Errorf("CORS warning does not say what is lost: %q", got.Warnings[1].Reason)
	}
	if len(got.Redirects) != 0 || len(got.ErrorPages) != 0 || len(got.PHP) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestWordPressPluginLines(t *testing.T) {
	text := wordpressPlugins(t)
	r := ClassifyFile(".htaccess", "/", []byte(text))
	handling := func(part string, nth int) Handling {
		line := lineOf(t, text, part, nth)
		for _, g := range r.Findings {
			if g.Line == line {
				return g.Handling
			}
		}
		t.Fatalf("no finding at line %d", line)
		return ""
	}
	for _, c := range []struct {
		part string
		want Handling
	}{
		// WP Rocket's deflate block: only compression variables.
		{"HAVE_Accept-Encoding", HandlingIgnored},
		{"RequestHeader append Accept-Encoding", HandlingIgnored},
		// Continued onto the next line: no-gzip dont-vary.
		{"SetEnvIfNoCase Request_URI", HandlingIgnored},
		// mod_headers cuts the name at its colon: this is Vary.
		{"Header append Vary: Accept-Encoding", HandlingIgnored},
		{"Header set X-Powered-By", HandlingIgnored},
		{"SetEnvIf Origin", HandlingWarning},
		{"Options -Indexes", HandlingSifruno},
	} {
		if got := handling(c.part, 1); got != c.want {
			t.Errorf("%s: handling %q, want %q", c.part, got, c.want)
		}
	}
}

// WP Rocket's cache block with gzip (rocket_force_gzip_htaccess_rules on)
// serves .html_gzip files through AddEncoding, which OpenLiteSpeed ignores:
// it would send them without Content-Encoding. That still refuses, named as
// the line to change: the file's access rules would convert without it.
func TestWPRocketGzipCacheStillRefuses(t *testing.T) {
	gzip := "<IfModule mod_mime.c>\nAddType text/html .html_gzip\nAddEncoding gzip .html_gzip\n</IfModule>\n<IfModule mod_setenvif.c>\nSetEnvIfNoCase Request_URI \\.html_gzip$ no-gzip\n</IfModule>\n"
	got := ConvertSite(siteOf(map[string]string{".htaccess": wordpressPlugins(t) + gzip}))
	if got.Native || len(got.Refused) != 1 || got.Refused[0].Directive != "AddEncoding gzip" || got.Refused[0].Cause != CauseNotConverted {
		t.Fatalf("%+v", got.Refused)
	}
}

func TestFilesDenyKeepsRewriteLines(t *testing.T) {
	text := "RewriteEngine On\n<IfModule mod_rewrite.c>\nRewriteRule ^x$ /y [L]\n</IfModule>\n<Files secret.json>\nRequire all denied\n</Files>\n"
	for _, path := range []string{"/", "/shop/"} {
		r := ClassifyFile(".htaccess", path, []byte(text))
		want := FolderRule{Path: path, Hosts: Hosts{Kind: HostsAll}, Deny: &Names{Exact: []string{"secret.json"}}}
		if r.Conversion == nil || r.Conversion.Rule == nil || !reflect.DeepEqual(*r.Conversion.Rule, want) {
			t.Fatalf("%s: %+v", path, r.Conversion)
		}
	}
	// Beside a folder rule the rewrite lines refuse: the folder's context
	// turns rewriting off below it.
	r := ClassifyFile(".htaccess", "/shop/", []byte(text+"Deny from 192.0.2.1\n"))
	if r.Conversion == nil || r.Conversion.Rule != nil || r.Conversion.Line != 1 {
		t.Fatalf("%+v", r.Conversion)
	}
}

func TestFilesDenyAcrossTheSite(t *testing.T) {
	root := wordpressBlock + "<Files wp-config.php>\nRequire all denied\n</Files>\n"
	got := ConvertSite(siteOf(map[string]string{
		".htaccess":                    root,
		"wp-content/uploads/.htaccess": "<Files *.php>\ndeny from all\n</Files>\n",
		"wp-content/.htaccess":         "Options -Indexes\n",
		"private/.htaccess":            "Deny from all\n",
	}))
	if !got.Native || len(got.Rules) != 3 {
		t.Fatalf("%+v", got)
	}
	if r := got.Rules[0]; r.Path != "/" || r.Folder() || r.Open() {
		t.Fatalf("%+v", r)
	}
	if r := got.Rules[2]; r.Path != "/wp-content/uploads/" || !r.Deny.CoversIndex() {
		t.Fatalf("%+v", r)
	}
	// A rewrite whose result a file path can choose skips the names'
	// contexts as it would a folder's.
	got = ConvertSite(siteOf(map[string]string{".htaccess": root + "RewriteRule ^go/(.*)$ /$1 [L]\n"}))
	if got.Native || !slices.ContainsFunc(got.Refused, func(r FileRefusal) bool { return strings.Contains(r.Reason, "rewrite rule") }) {
		t.Fatalf("%+v", got)
	}
	// A folder rule at the root still refuses.
	got = ConvertSite(siteOf(map[string]string{".htaccess": "Deny from all\n<Files a.php>\nDeny from all\n</Files>\n"}))
	if got.Native || got.Refused[0].Reason != "access rules for the whole site, which this server does not convert" {
		t.Fatalf("%+v", got)
	}
}

func TestNamesMatch(t *testing.T) {
	n := Names{Exact: []string{"wp-config.php"}, Endings: []string{".sql", "~"}}
	for name, want := range map[string]bool{
		"wp-config.php": true, "wp-config.php.bak": false, "my-wp-config.php": false,
		"dump.sql": true, ".sql": true, "dump.sql.gz": false, "index.php~": true, "index.php": false,
	} {
		if n.Match(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
	if n.CoversIndex() || !(Names{Endings: []string{"php"}}).CoversIndex() || !(Names{Exact: []string{"index.html"}}).CoversIndex() {
		t.Error("index files")
	}
}

func TestRedirectsAndErrorPagesConvert(t *testing.T) {
	text := wordpressBlock + `Redirect 301 /old-page https://example.com/new-page
Redirect /temp/ /elsewhere/
RedirectPermanent /a https://Example.COM:8443/b?x=1
RedirectTemp /c /d
<IfModule mod_alias.c>
RedirectMatch 301 ^/blog/([0-9]+)/(.*)$ /news/$2?id=$1
RedirectMatch \.htm$ https://example.com/
</IfModule>
ErrorDocument 404 /404.html
ErrorDocument 403 /errors/403.shtml
ErrorDocument 410 /gone.html
ErrorDocument 410 default
ErrorDocument 401 default
ErrorDocument 500 "Sorry"
`
	got := ConvertSite(siteOf(map[string]string{".htaccess": text}))
	if !got.Native {
		t.Fatalf("%+v", got.Refused)
	}
	base := strings.Count(wordpressBlock, "\n")
	want := []Redirect{
		{Line: base + 1, Prefix: "/old-page", Target: "https://example.com/new-page", Status: 301},
		{Line: base + 2, Prefix: "/temp/", Target: "/elsewhere/", Status: 302},
		{Line: base + 3, Prefix: "/a", Target: "https://example.com:8443/b?x=1", Status: 301},
		{Line: base + 4, Prefix: "/c", Target: "/d", Status: 302},
		{Line: base + 6, Pattern: "^/blog/([0-9]+)/(.*)$", Target: "/news/$2?id=$1", Status: 301},
		{Line: base + 7, Pattern: `\.htm$`, Target: "https://example.com/", Status: 302},
	}
	if !reflect.DeepEqual(got.Redirects, want) {
		t.Fatalf("redirects\n got %+v\nwant %+v", got.Redirects, want)
	}
	pages := []ErrorPage{{Line: base + 10, Status: 403, URL: "/errors/403.shtml"}, {Line: base + 9, Status: 404, URL: "/404.html"}}
	if !reflect.DeepEqual(got.ErrorPages, pages) {
		t.Fatalf("error pages %+v", got.ErrorPages)
	}
	if len(got.Warnings) != 1 || got.Warnings[0].Line != base+14 || !strings.Contains(got.Warnings[0].Reason, "error page") {
		t.Fatalf("warnings %+v", got.Warnings)
	}
}

func TestRedirectRefusals(t *testing.T) {
	root := map[string]string{
		"status 303":           "Redirect 303 /a /b\n",
		"seeother":             "Redirect seeother /a /b\n",
		"status 307":           "Redirect 307 /a /b\n",
		"whole folder":         "Redirect 301 https://example.com/\n",
		"no target":            "Redirect /a\n",
		"other scheme":         "Redirect 301 /a ftp://example.com/\n",
		"user in target":       "Redirect 301 /a https://user@example.com/\n",
		"address target":       "Redirect 301 /a https://192.0.2.1/\n",
		"brace pattern":        "RedirectMatch 301 ^/a{2}$ /c\n",
		"space in target":      "Redirect 301 /a \"https://example.com/a b\"\n",
		"percent in path":      "Redirect 301 /a%20b /c\n",
		"percent in target":    "Redirect 301 /a /b%20c\n",
		"dollar in Redirect":   "Redirect 301 /a /b$1\n",
		"relative path":        "Redirect 301 a /b\n",
		"dot part":             "Redirect 301 /.well-known/x /b\n",
		"lookbehind":           "RedirectMatch 301 (?<=a)b /c\n",
		"space in pattern":     "RedirectMatch 301 \"^/a b$\" /c\n",
		"negated pattern":      "RedirectMatch 301 !^/a /c\n",
		"percent pattern":      "RedirectMatch 301 ^/a%20 /c\n",
		"lone dollar":          "RedirectMatch 301 ^/a(.*)$ /c$\n",
		"inside files":         "<Files x.html>\nRedirect 301 /a /b\n</Files>\n",
		"negated module":       "<IfModule !mod_alias.c>\nRedirect 301 /a /b\n</IfModule>\n",
		"litespeed only":       "<IfModule LiteSpeed>\nRedirect 301 /a /b\n</IfModule>\n",
		"error page url":       "ErrorDocument 404 https://example.com/404\n",
		"error page query":     "ErrorDocument 404 /index.php?error=404\n",
		"error page status":    "ErrorDocument 302 /x.html\n",
		"error page odd path":  "ErrorDocument 404 /a%20b.html\n",
		"error page root":      "ErrorDocument 404 /\n",
		"error document alone": "ErrorDocument 404\n",
	}
	for name, text := range root {
		t.Run(name, func(t *testing.T) {
			got := ConvertSite(siteOf(map[string]string{".htaccess": text}))
			if got.Native || len(got.Refused) == 0 || got.Refused[0].Line == 0 || got.Refused[0].Reason == "" || len(got.Redirects) != 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
	for name, text := range map[string]string{
		"folder redirect":   "Redirect 301 /blog/a /blog/b\n",
		"folder error page": "ErrorDocument 404 /blog/404.html\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := ConvertSite(siteOf(map[string]string{"blog/.htaccess": text}))
			if got.Native || len(got.Refused) != 1 || !strings.Contains(got.Refused[0].Reason, "root .htaccess") {
				t.Fatalf("%+v", got)
			}
		})
	}
	var many strings.Builder
	for i := 0; i <= MaxSiteRedirects; i++ {
		many.WriteString("Redirect 301 /a" + strings.Repeat("b", i) + " /c\n")
	}
	if got := ConvertSite(siteOf(map[string]string{".htaccess": many.String()})); got.Native || got.Refused[0].Line != MaxSiteRedirects+1 {
		t.Fatalf("%+v", got.Refused)
	}
}
