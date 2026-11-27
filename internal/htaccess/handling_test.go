package htaccess

import (
	"reflect"
	"strings"
	"testing"
)

// cpanelWordPress is the root .htaccess of a typical WordPress site on a
// cPanel server: WordPress's rewrite block, cPanel's PHP handler block and
// the caching, compression and header blocks hosting guides and cache
// plugins add. Every line OpenLiteSpeed ignores here is harmless to ignore
// or handled by Sifruno.
const cpanelWordPress = `# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress

# php -- BEGIN cPanel-generated handler, do not edit
# Set the “ea-php81” package as the default “PHP” programming language.
<IfModule mime_module>
  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml
</IfModule>
# php -- END cPanel-generated handler, do not edit

<IfModule mod_expires.c>
ExpiresActive On
ExpiresByType image/webp "access plus 1 year"
ExpiresByType text/css "access plus 1 month"
ExpiresDefault "access plus 2 days"
</IfModule>
<IfModule mod_deflate.c>
AddOutputFilterByType DEFLATE text/plain text/html text/xml text/css \
  application/javascript application/json image/svg+xml
BrowserMatch ^Mozilla/4 gzip-only-text/html
BrowserMatch \bMSIE !no-gzip !gzip-only-text/html
</IfModule>
<IfModule mod_headers.c>
Header set X-Content-Type-Options nosniff
Header always set X-Frame-Options SAMEORIGIN
Header always set Strict-Transport-Security "max-age=31536000"
<FilesMatch "\.(js|css|webp|png|jpg|svg|woff2)$">
Header set Cache-Control "max-age=2592000, public"
</FilesMatch>
Header unset ETag
</IfModule>
FileETag None
Options -Indexes
AddType image/webp .webp
AddType font/woff2 .woff2
AddDefaultCharset UTF-8
`

func TestTypicalCPanelWordPressIsNative(t *testing.T) {
	r := ClassifyFile(".htaccess", "/", []byte(cpanelWordPress))
	if r.Verdict != VerdictNative || len(r.Causes) != 0 {
		t.Fatalf("verdict %s causes %v", r.Verdict, r.Causes)
	}
	for _, g := range r.Findings {
		if !g.Honoured && g.Category != CategoryStructure && g.Handling == "" {
			t.Errorf("line %d %s is not handled: %s", g.Line, g.Directive, g.Reason)
		}
		if g.Handling != "" && g.Reason == "" {
			t.Errorf("line %d %s has no reason", g.Line, g.Directive)
		}
	}
	got := ConvertSite(siteOf(map[string]string{".htaccess": cpanelWordPress}))
	if !got.Native || len(got.Refused) != 0 || len(got.Warnings) != 0 {
		t.Fatalf("%+v", got)
	}
	want := []PHPHandler{{File: ".htaccess", Line: 15, Directive: "AddHandler", Path: "/", Package: "ea-php81"}}
	if !reflect.DeepEqual(got.PHP, want) {
		t.Fatalf("php handlers %+v, want %+v", got.PHP, want)
	}
}

func TestHandlingOfEachClass(t *testing.T) {
	for _, tc := range []struct {
		text     string
		handling Handling
	}{
		// Harmless to ignore.
		{"ExpiresActive On", HandlingIgnored},
		{"ExpiresByType text/css A31536000", HandlingIgnored},
		{"FileETag MTime Size", HandlingIgnored},
		{"Header append Cache-Control public", HandlingIgnored},
		{"Header always set Referrer-Policy strict-origin-when-cross-origin", HandlingIgnored},
		{"Header set Content-Security-Policy \"default-src 'self'\"", HandlingIgnored},
		{"Header unset X-Powered-By", HandlingIgnored},
		{"Header set Vary Accept-Encoding env=gzip", HandlingIgnored},
		{"AddOutputFilterByType DEFLATE text/html", HandlingIgnored},
		{"AddOutputFilter DEFLATE;BROTLI_COMPRESS css js", HandlingIgnored},
		{"SetOutputFilter DEFLATE", HandlingIgnored},
		{"DeflateCompressionLevel 9", HandlingIgnored},
		{"mod_gzip_on Yes", HandlingIgnored},
		{"SetEnvIfNoCase Request_URI \\.(?:gif|jpe?g|png)$ no-gzip dont-vary", HandlingIgnored},
		{"BrowserMatch ^Mozilla/4\\.0[678] no-gzip", HandlingIgnored},
		{"RequestHeader append Accept-Encoding \"gzip,deflate\" env=HAVE_Accept-Encoding", HandlingIgnored},
		{"AddType image/avif .avif", HandlingIgnored},
		{"AddType application/font-woff2 woff2", HandlingIgnored},
		{"AddType image/svg+xml svg svgz", HandlingIgnored},
		{"AddType application/javascript js mjs", HandlingIgnored},
		{"AddDefaultCharset UTF-8", HandlingIgnored},
		{"AddCharset UTF-8 .css .js", HandlingIgnored},
		// Handled by Sifruno.
		{"AddHandler application/x-httpd-ea-php74 .php .php7 .phtml", HandlingSifruno},
		{"AddHandler application/x-httpd-alt-php81___lsphp .php", HandlingSifruno},
		{"AddType application/x-httpd-ea-php56 .php .php5 .phtml", HandlingSifruno},
		{"Options -Indexes", HandlingSifruno},
		{"Options -MultiViews -Indexes", HandlingSifruno},
		{"Options +FollowSymLinks", HandlingSifruno},
		{"CacheLookup on", HandlingSifruno},
		// A warning at cutover.
		{"php_value upload_max_filesize 64M", HandlingWarning},
		{"php_flag display_errors Off", HandlingWarning},
		// Not covered: the file stays off the Native tier.
		{"Header set X-Robots-Tag noindex", ""},
		{"Header set Access-Control-Allow-Origin *", ""},
		{"Header echo ^X-", ""},
		{"Header edit Cache-Control ^(.*)$ $1", ""},
		{"RequestHeader set X-Forwarded-Proto https", ""},
		{"AddOutputFilter INCLUDES .shtml", ""},
		{"SetEnvIf Request_URI ^/app APP_ENV=staging", ""},
		{"AddType text/plain .php", ""},
		{"AddType application/x-httpd-php .html", ""},
		{"AddType text/html .shtml", ""},
		// Uploads hardening: HTML, SVG and scripts sent as text or a
		// download do not run in the browser; OpenLiteSpeed would render
		// them.
		{"AddType text/plain .html .htm .svg", ""},
		{"AddType application/octet-stream .svg", ""},
		{"AddType text/plain js", ""},
		{"AddHandler application/x-httpd-ea-php81 .php .html", ""},
		{"AddHandler cgi-script .cgi", ""},
		{"AddEncoding gzip .gz", ""},
		{"Options +SymLinksIfOwnerMatch", ""},
		{"Options -FollowSymLinks", ""},
		{"CacheLookup off", ""},
		{"php_admin_value open_basedir none", ""},
		{"ErrorDocument 404 /404.php", ""},
		{"Redirect 301 /old /new", ""},
		{"DirectoryIndex index.html", ""},
		{"SetEnv WP_ENVIRONMENT_TYPE staging", ""},
	} {
		r := ClassifyFile(".htaccess", "/", []byte(tc.text+"\n"))
		if len(r.Findings) != 1 {
			t.Fatalf("%q: findings %+v", tc.text, r.Findings)
		}
		g := r.Findings[0]
		if g.Handling != tc.handling {
			t.Errorf("%q: handling %q, want %q (category %s, reason %q)", tc.text, g.Handling, tc.handling, g.Category, g.Reason)
		}
		if g.Category == CategoryAccessControl {
			t.Errorf("%q is classified as access control", tc.text)
		}
		wantVerdict := VerdictNative
		if tc.handling == "" {
			wantVerdict = VerdictConvertible
		}
		if r.Verdict != wantVerdict {
			t.Errorf("%q: verdict %s, want %s", tc.text, r.Verdict, wantVerdict)
		}
	}
}

func TestAccessRulesStayAccess(t *testing.T) {
	// Lines that change who may reach what are access control whatever the
	// classes above say: OpenLiteSpeed ignoring them would open something.
	for _, text := range []string{
		"php_flag engine off",
		"Options +Indexes",
		"Options Indexes FollowSymLinks",
		"Options +ExecCGI",
		"Deny from all",
		"SetHandler none",
	} {
		r := ClassifyFile(".htaccess", "/", []byte(text+"\n"))
		if r.Verdict != VerdictCompat || !reflect.DeepEqual(r.Causes, []string{CauseAccessControl}) {
			t.Errorf("%q: verdict %s causes %v", text, r.Verdict, r.Causes)
		}
	}
}

func TestCompressionVariableARewriteReadsIsNotHarmless(t *testing.T) {
	r := ClassifyFile(".htaccess", "/", []byte("SetEnvIfNoCase User-Agent BadBot no-gzip\nRewriteEngine On\nRewriteCond %{ENV:no-gzip} 1\nRewriteRule ^ - [F]\n"))
	if r.Findings[0].Handling != "" || r.Verdict == VerdictNative {
		t.Fatalf("verdict %s, SetEnvIf handling %q", r.Verdict, r.Findings[0].Handling)
	}
}

func TestLabelShowsOnlyDirectiveNames(t *testing.T) {
	r := ClassifyFile(".htaccess", "/", []byte("SECRET_KEY=abc123 x\nexample.com On\n"))
	for _, g := range r.Findings {
		if strings.Contains(g.Label, "abc123") || strings.Contains(g.Label, "example.com") || g.Label == "" {
			t.Errorf("line %d label %q", g.Line, g.Label)
		}
	}
}

func TestConverterRefusalIsAnAccessRefusal(t *testing.T) {
	// A password folder with WordPress's rewrite rules: the converter cannot
	// carry the rule, so OpenLiteSpeed would open the folder. The refusal is
	// an access refusal naming the line the converter stopped at.
	got := ConvertSite(siteOf(map[string]string{
		"members/.htaccess": "AuthType Basic\nAuthName Members\nAuthUserFile /home/u/.htpasswd\nRequire valid-user\nRewriteEngine On\nRewriteRule . /members/index.php [L]\n",
		"club/.htaccess":    "<If \"%{HTTPS} == 'on'\">\nRequire all denied\n</If>\n",
	}))
	if got.Native || len(got.Refused) != 2 {
		t.Fatalf("%+v", got.Refused)
	}
	for _, r := range got.Refused {
		if r.Cause != CauseAccessControl || r.Line == 0 {
			t.Errorf("%+v", r)
		}
	}
}

func TestFolderDenyIsConvertedBesideATypicalRoot(t *testing.T) {
	got := ConvertSite(siteOf(map[string]string{
		".htaccess":         cpanelWordPress,
		"private/.htaccess": "Order deny,allow\nDeny from all\n",
	}))
	if !got.Native || len(got.Rules) != 1 || got.Rules[0].Path != "/private/" || got.Rules[0].Hosts.Kind != HostsNone || got.Rules[0].File != "private/.htaccess" {
		t.Fatalf("%+v", got)
	}
}

func TestHarmlessLinesBesideAConvertedRule(t *testing.T) {
	// OpenLiteSpeed ignores these lines with or without the converted rule,
	// and none of them changes who may enter the folder.
	got := ConvertSite(siteOf(map[string]string{
		"private/.htaccess": "Deny from all\nOptions -MultiViews -Indexes\n<IfModule mod_expires.c>\nExpiresActive On\n</IfModule>\n<IfModule mod_php.c>\nphp_value max_execution_time 300\n</IfModule>\n",
	}))
	if !got.Native || len(got.Rules) != 1 || got.Rules[0].Hosts.Kind != HostsNone {
		t.Fatalf("%+v", got)
	}
	if len(got.Warnings) != 1 || got.Warnings[0].Line != 7 {
		t.Fatalf("warnings %+v", got.Warnings)
	}
	// An access line inside such a block still refuses.
	got = ConvertSite(siteOf(map[string]string{
		"private/.htaccess": "Deny from all\n<IfModule mod_expires.c>\nExpiresActive On\nAllow from 192.0.2.1\n</IfModule>\n",
	}))
	if got.Native {
		t.Fatalf("%+v", got)
	}
}

func TestUnknownDirectiveRefusesWithItsLine(t *testing.T) {
	got := ConvertSite(siteOf(map[string]string{
		".htaccess":            cpanelWordPress,
		"wp-content/.htaccess": "Header set Cache-Control max-age=60\nSifrunoUnknown On\n",
	}))
	want := []FileRefusal{{File: "wp-content/.htaccess", Line: 2, Directive: "SifrunoUnknown On", Cause: CauseUnknown, Reason: "a directive this panel does not know"}}
	if got.Native || !reflect.DeepEqual(got.Refused, want) {
		t.Fatalf("refused %+v, want %+v", got.Refused, want)
	}
}

func TestUnknownSectionRefusesWithItsLine(t *testing.T) {
	got := ConvertSite(siteOf(map[string]string{".htaccess": "RewriteEngine On\n<SifrunoBlock x>\nExpiresActive On\n</SifrunoBlock>\n"}))
	if got.Native || len(got.Refused) != 1 || got.Refused[0].Line != 2 || got.Refused[0].Directive != "<SifrunoBlock>" || got.Refused[0].Cause != CauseUnknown {
		t.Fatalf("%+v", got.Refused)
	}
}

func TestNotConvertedLineRefusesWithItsLine(t *testing.T) {
	got := ConvertSite(siteOf(map[string]string{".htaccess": cpanelWordPress + "Header set X-Robots-Tag noindex\nErrorDocument 404 /missing.html\n"}))
	if got.Native || len(got.Refused) != 2 {
		t.Fatalf("%+v", got.Refused)
	}
	lines := strings.Count(cpanelWordPress, "\n")
	for i, want := range []FileRefusal{
		{File: ".htaccess", Line: lines + 1, Directive: "Header set X-Robots-Tag noindex", Cause: CauseNotConverted},
		{File: ".htaccess", Line: lines + 2, Directive: "ErrorDocument 404", Cause: CauseNotConverted},
	} {
		r := got.Refused[i]
		if r.File != want.File || r.Line != want.Line || r.Directive != want.Directive || r.Cause != want.Cause || r.Reason == "" {
			t.Errorf("refusal %d: %+v, want %+v", i, r, want)
		}
		if strings.Contains(r.Reason, "protect") {
			t.Errorf("refusal %d claims a protected folder: %q", i, r.Reason)
		}
	}
}

func TestPHPValueIsAWarning(t *testing.T) {
	text := cpanelWordPress + "php_value upload_max_filesize 64M\nphp_flag display_errors Off\nphp_value auto_prepend_file '/home/alice/public_html/wordfence-waf.php'\n"
	got := ConvertSite(siteOf(map[string]string{".htaccess": text}))
	if !got.Native || len(got.Refused) != 0 {
		t.Fatalf("%+v", got)
	}
	lines := strings.Count(cpanelWordPress, "\n")
	want := []FileWarning{
		{File: ".htaccess", Line: lines + 1, Directive: "php_value upload_max_filesize 64M"},
		{File: ".htaccess", Line: lines + 2, Directive: "php_flag display_errors Off"},
		// The path is not shown: it can name the account.
		{File: ".htaccess", Line: lines + 3, Directive: "php_value auto_prepend_file"},
	}
	if len(got.Warnings) != len(want) {
		t.Fatalf("warnings %+v", got.Warnings)
	}
	for i, w := range got.Warnings {
		if w.File != want[i].File || w.Line != want[i].Line || w.Directive != want[i].Directive || !strings.Contains(w.Reason, "OpenLiteSpeed does not apply PHP settings from .htaccess") {
			t.Errorf("warning %d: %+v, want %+v", i, w, want[i])
		}
	}
	if !strings.Contains(got.Warnings[2].Reason, "before every script") {
		t.Errorf("auto_prepend_file warning does not say what is lost: %q", got.Warnings[2].Reason)
	}
}

func TestAccessRefusalsAreMarked(t *testing.T) {
	got := ConvertSite(siteOf(map[string]string{"a/.htaccess": "Deny from all\nSatisfy Any\n", ".htaccess": "Require all denied\n"}))
	if got.Native || len(got.Refused) != 2 {
		t.Fatalf("%+v", got.Refused)
	}
	for _, r := range got.Refused {
		if r.Cause != CauseAccessControl || r.Line == 0 || r.Directive == "" {
			t.Errorf("%+v", r)
		}
	}
}
