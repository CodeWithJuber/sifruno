package htaccess

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const wordpressBlock = `# BEGIN WordPress
# The directives (lines) between "BEGIN WordPress" and "END WordPress" are
# dynamically generated, and should only be modified via WordPress filters.
# Any changes to the directives between these markers will be overwritten.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>

# END WordPress
`

var wordpressFindings = []string{
	"5 <IfModule> structure true",
	"6 RewriteEngine rewrite true",
	"7 RewriteRule rewrite true",
	"8 RewriteBase rewrite true",
	"9 RewriteRule rewrite true",
	"10 RewriteCond rewrite true",
	"11 RewriteCond rewrite true",
	"12 RewriteRule rewrite true",
}

const cachePluginBlocks = `# BEGIN W3TC Browser Cache
<IfModule mod_mime.c>
    AddType text/css .css
    AddEncoding gzip .gz
</IfModule>
<IfModule mod_deflate.c>
    <IfModule mod_filter.c>
        AddOutputFilterByType DEFLATE text/css text/html application/javascript
    </IfModule>
</IfModule>
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css A31536000
</IfModule>
<FilesMatch "\.(css|htc|less|js)$">
    FileETag MTime Size
    <IfModule mod_headers.c>
        Header set Pragma "public"
        Header append Cache-Control "public"
    </IfModule>
</FilesMatch>
# END W3TC Browser Cache
# BEGIN WP Rocket
<IfModule mod_headers.c>
    Header set X-Powered-By "WP Rocket/3.15"
</IfModule>
# END WP Rocket
`

const liteSpeedCacheBlock = `# BEGIN LSCACHE
## LITESPEED WP CACHE PLUGIN - Do not edit the contents of this block! ##
<IfModule LiteSpeed>
RewriteEngine on
CacheLookup on
RewriteRule .* - [E=Cache-Control:no-autoflush]
RewriteRule \.litespeed_conf\.dat - [F,L]

### marker CACHE RESOURCE start ###
RewriteRule wp-content/.*/[^/]*(responsive|css|js|dynamic|loader|fonts)\.php - [E=cache-control:max-age=3600]
### marker CACHE RESOURCE end ###

### marker DROPQS start ###
CacheKeyModify -qs:fbclid
CacheKeyModify -qs:gclid
### marker DROPQS end ###
</IfModule>
## LITESPEED WP CACHE PLUGIN - Do not edit the contents of this block! ##
# END LSCACHE
# BEGIN NON_LSCACHE
## LITESPEED WP CACHE PLUGIN - Do not edit the contents of this block! ##
## LITESPEED WP CACHE PLUGIN - Do not edit the contents of this block! ##
# END NON_LSCACHE
`

const passwordProtected = `#----------------------------------------------------------------cp:ppd
# Section managed by cPanel: Password Protected Directories     -cp:ppd
# - Do not edit this section of the htaccess file!              -cp:ppd
#----------------------------------------------------------------cp:ppd
AuthType Basic
AuthName "Protected 'public_html/members'"
AuthUserFile "/home/alice/.htpasswds/public_html/members/passwd"
Require valid-user
#----------------------------------------------------------------cp:ppd
# End section managed by cPanel: Password Protected Directories -cp:ppd
#----------------------------------------------------------------cp:ppd
`

const cpanelHandler = `# php -- BEGIN cPanel-generated handler, do not edit
# Set the “ea-php81” package as the default “PHP” programming language.
<IfModule mime_module>
  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml
</IfModule>
# php -- END cPanel-generated handler, do not edit
`

const wordfenceBlock = `# Wordfence WAF
<IfModule mod_php7.c>
	php_value auto_prepend_file '/home/alice/public_html/wordfence-waf.php'
</IfModule>
<Files ".user.ini">
<IfModule mod_authz_core.c>
	Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
	Order deny,allow
	Deny from all
</IfModule>
</Files>
# END Wordfence WAF
`

func render(f Finding) string {
	s := fmt.Sprintf("%d %s %s %t", f.Line, f.Directive, f.Category, f.Honoured)
	if f.Handling != "" {
		s += " " + string(f.Handling)
	}
	if a := f.Access; a != nil {
		s += fmt.Sprintf(" %s %s", a.Kind, a.Path)
		if a.Files != "" {
			s += fmt.Sprintf(" files=%s regex=%t", a.Files, a.FilesRegex)
		}
		if a.Methods != "" {
			s += " methods=" + a.Methods
		}
		if a.Conditional {
			s += " conditional"
		}
		if a.URLRegex != "" {
			s += " url_regex=" + a.URLRegex
		}
		if a.Status != 0 {
			s += fmt.Sprintf(" status=%d", a.Status)
		}
	}
	return s
}

func renderRules(rules []AccessRule) []string {
	var out []string
	for _, r := range rules {
		out = append(out, fmt.Sprintf("%d %s %s files=%s methods=%s expect=%d", r.Line, r.Kind, r.Path, r.Files, r.Methods, r.ExpectStatus))
	}
	return out
}

func TestClassifyFixtures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		urlPath  string
		data     string
		verdict  Verdict
		causes   []string
		findings []string
		rules    []string
	}{
		{name: "stock WordPress", urlPath: "/", data: wordpressBlock, verdict: VerdictNative, findings: wordpressFindings},
		{name: "WordPress with CRLF", urlPath: "/", data: strings.ReplaceAll(wordpressBlock, "\n", "\r\n"), verdict: VerdictNative, findings: wordpressFindings},
		{name: "WordPress in a subdirectory", urlPath: "/blog/", data: strings.Replace(wordpressBlock, "RewriteBase /", "RewriteBase /blog/", 1), verdict: VerdictNative, findings: []string{
			"5 <IfModule> structure true", "6 RewriteEngine rewrite true", "7 RewriteRule rewrite true", "8 RewriteBase rewrite true",
			"9 RewriteRule rewrite true", "10 RewriteCond rewrite true", "11 RewriteCond rewrite true", "12 RewriteRule rewrite true",
		}},
		// AddEncoding (line 4) serves W3TC's pre-compressed files with their
		// encoding; OpenLiteSpeed ignoring it changes those responses.
		{name: "W3TC and WP Rocket blocks", urlPath: "/", data: cachePluginBlocks + wordpressBlock, verdict: VerdictConvertible, findings: append([]string{
			"2 <IfModule> structure true",
			"3 AddType mime_handlers false ignored",
			"4 AddEncoding mime_handlers false",
			"6 <IfModule> structure true",
			"7 <IfModule> structure true",
			"8 AddOutputFilterByType compression false ignored",
			"11 <IfModule> structure true",
			"12 ExpiresActive caching false ignored",
			"13 ExpiresByType caching false ignored",
			"15 <FilesMatch> structure false",
			"16 FileETag caching false ignored",
			"17 <IfModule> structure true",
			"18 Header headers false ignored",
			"19 Header headers false ignored",
			"24 <IfModule> structure true",
			"25 Header headers false ignored",
		}, shift(wordpressFindings, 27)...)},
		{name: "LiteSpeed Cache plugin", urlPath: "/", data: liteSpeedCacheBlock, verdict: VerdictNative, findings: []string{
			"3 <IfModule> vendor true",
			"4 RewriteEngine vendor true",
			"5 CacheLookup vendor false handled",
			"6 RewriteRule vendor true",
			"7 RewriteRule vendor true",
			"10 RewriteRule vendor true",
			"14 CacheKeyModify vendor true",
			"15 CacheKeyModify vendor true",
		}},
		{name: "password-protected directory", urlPath: "/members/", data: passwordProtected, verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"5 AuthType access_control false password /members/",
			"6 AuthName access_control false password /members/",
			"7 AuthUserFile access_control false password /members/",
			"8 Require access_control false password /members/",
		}, rules: []string{"5 password /members/ files= methods= expect=401"}},
		{name: "Apache 2.2 deny all", urlPath: "/", data: "Order deny,allow\nDeny from all\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 Order access_control false deny_allow /",
			"2 Deny access_control false deny_allow /",
		}, rules: []string{"1 deny_allow / files= methods= expect=403"}},
		{name: "deny with an allowed address", urlPath: "/admin/", data: "Order deny,allow\nDeny from all\nAllow from 192.0.2.10\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 Order access_control false deny_allow /admin/",
			"2 Deny access_control false deny_allow /admin/",
			"3 Allow access_control false deny_allow /admin/",
		}, rules: []string{"1 deny_allow /admin/ files= methods= expect=0"}},
		{name: "Files and FilesMatch deny blocks", urlPath: "/", data: "<Files wp-config.php>\nOrder allow,deny\nDeny from all\n</Files>\n<FilesMatch \"\\.(env|log)$\">\nRequire all denied\n</FilesMatch>\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 <Files> access_control false deny_allow / files=wp-config.php regex=false",
			"2 Order access_control false deny_allow / files=wp-config.php regex=false",
			"3 Deny access_control false deny_allow / files=wp-config.php regex=false",
			"5 <FilesMatch> access_control false deny_allow / files=\\.(env|log)$ regex=true",
			"6 Require access_control false deny_allow / files=\\.(env|log)$ regex=true",
		}, rules: []string{
			"1 deny_allow / files=wp-config.php methods= expect=0",
			"5 deny_allow / files=\\.(env|log)$ methods= expect=0",
		}},
		{name: "php_value lines", urlPath: "/", data: "php_value upload_max_filesize 64M\nphp_value post_max_size 64M\nphp_flag display_errors Off\n", verdict: VerdictNative, findings: []string{
			"1 php_value php_settings false converted",
			"2 php_value php_settings false converted",
			"3 php_flag php_settings false converted",
		}},
		{name: "cPanel PHP handler block", urlPath: "/", data: cpanelHandler, verdict: VerdictNative, findings: []string{
			"3 <IfModule> structure true",
			"4 AddHandler vendor false handled",
		}},
		{name: "unknown directive", urlPath: "/", data: "RewriteEngine On\nFooBarDirective on\n", verdict: VerdictCompat, causes: []string{CauseUnknown}, findings: []string{
			"1 RewriteEngine rewrite true",
			"2 FooBarDirective unknown false",
		}},
		{name: "nested deny protects only its directory", urlPath: "/private/", data: "Require all denied\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 Require access_control false deny_allow /private/",
		}, rules: []string{"1 deny_allow /private/ files= methods= expect=403"}},
		{name: "Wordfence WAF block", urlPath: "/", data: wordfenceBlock, verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"2 <IfModule> structure true",
			"3 php_value vendor false",
			"5 <Files> access_control false deny_allow / files=.user.ini regex=false",
			"6 <IfModule> structure true",
			"7 Require access_control false deny_allow / files=.user.ini regex=false",
			"9 <IfModule> structure true",
			"10 Order access_control false deny_allow / files=.user.ini regex=false",
			"11 Deny access_control false deny_allow / files=.user.ini regex=false",
		}, rules: []string{"5 deny_allow / files=.user.ini methods= expect=0"}},
		{name: "Laravel listing switch", urlPath: "/", data: "<IfModule mod_rewrite.c>\n    <IfModule mod_negotiation.c>\n        Options -MultiViews -Indexes\n    </IfModule>\n    RewriteEngine On\n    RewriteRule ^ index.php [L]\n</IfModule>\n", verdict: VerdictNative, findings: []string{
			"1 <IfModule> structure true",
			"2 <IfModule> structure true",
			"3 Options other false handled",
			"5 RewriteEngine rewrite true",
			"6 RewriteRule rewrite true",
		}},
		{name: "symlink options only", urlPath: "/", data: "Options +FollowSymLinks -MultiViews\nRewriteEngine On\n", verdict: VerdictNative, findings: []string{
			"1 Options other false handled",
			"2 RewriteEngine rewrite true",
		}},
		{name: "listing turned on", urlPath: "/", data: "Options +Indexes\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 Options access_control false listing /",
		}, rules: []string{"1 listing / files= methods= expect=0"}},
		{name: "uploads directory without PHP", urlPath: "/wp-content/uploads/", data: "php_flag engine off\nRemoveHandler .php .phtml\n<FilesMatch \"\\.php$\">\nSetHandler none\n</FilesMatch>\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 php_flag access_control false exec /wp-content/uploads/",
			"2 RemoveHandler access_control false exec /wp-content/uploads/",
			"3 <FilesMatch> access_control false exec /wp-content/uploads/ files=\\.php$ regex=true",
			"4 SetHandler access_control false exec /wp-content/uploads/ files=\\.php$ regex=true",
		}, rules: []string{
			"1 exec /wp-content/uploads/ files= methods= expect=0",
			"3 exec /wp-content/uploads/ files=\\.php$ methods= expect=0",
		}},
		{name: "403 redirect at the site root", urlPath: "/", data: "Redirect 403 /secret\nRedirectMatch 404 ^/\\.git\nRedirect 301 /old /new\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 Redirect access_control false deny_allow /secret status=403",
			"2 RedirectMatch access_control false deny_allow / url_regex=^/\\.git status=404",
			"3 Redirect redirect_alias false converted",
		}, rules: []string{
			"1 deny_allow /secret files= methods= expect=403",
			"2 deny_allow / files= methods= expect=0",
		}},
		{name: "403 redirect in a nested file", urlPath: "/sub/", data: "Redirect 403 /sub/secret\nRedirect gone /elsewhere\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 Redirect access_control false deny_allow /sub/secret status=403",
			"2 Redirect access_control false deny_allow /sub/ status=410",
		}, rules: []string{
			"1 deny_allow /sub/secret files= methods= expect=0",
			"2 deny_allow /sub/ files= methods= expect=0",
		}},
		{name: "method-limited password", urlPath: "/", data: "AuthType Basic\nAuthName x\nAuthUserFile /p\n<Limit POST>\nRequire valid-user\n</Limit>\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 AuthType access_control false password /",
			"2 AuthName access_control false password /",
			"3 AuthUserFile access_control false password /",
			"4 <Limit> access_control false password / methods=Limit POST",
			"5 Require access_control false password / methods=Limit POST",
		}, rules: []string{
			"1 password / files= methods= expect=0",
			"4 password / files= methods=Limit POST expect=0",
		}},
		{name: "SetEnvIf feeding deny", urlPath: "/", data: "SetEnvIf User-Agent BadBot bad_bot\nOrder Allow,Deny\nAllow from all\nDeny from env=bad_bot\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 SetEnvIf access_control false deny_allow /",
			"2 Order access_control false deny_allow /",
			"3 Allow access_control false deny_allow /",
			"4 Deny access_control false deny_allow /",
		}, rules: []string{"1 deny_allow / files= methods= expect=0"}},
		{name: "SetEnvIf alone is environment", urlPath: "/", data: "SetEnvIf Authorization \"(.*)\" HTTP_AUTHORIZATION=$1\n", verdict: VerdictConvertible, findings: []string{
			"1 SetEnvIf environment false",
		}},
		{name: "rewrite inside mod_headers and negated wrappers", urlPath: "/", data: "<IfModule mod_headers.c>\nRewriteRule ^a$ /b [L]\n</IfModule>\n<IfModule !mod_rewrite.c>\nRewriteRule ^c$ /d [L]\n</IfModule>\n", verdict: VerdictConvertible, findings: []string{
			"1 <IfModule> structure true",
			"2 RewriteRule rewrite false",
			"4 <IfModule> structure true",
			"5 RewriteRule rewrite false",
		}},
		{name: "rewrite inside a Files block loses its scope", urlPath: "/", data: "<Files feed.xml>\nRewriteRule .* /feed [L]\n</Files>\n", verdict: VerdictConvertible, findings: []string{
			"1 <Files> structure false",
			"2 RewriteRule rewrite false",
		}},
		{name: "RewriteCond not followed by RewriteRule stops OLS", urlPath: "/", data: "RewriteEngine On\nRewriteCond %{HTTPS} off\nErrorDocument 404 /404.html\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]\nRewriteRule ^x$ /y [L]\n", verdict: VerdictConvertible, findings: []string{
			"1 RewriteEngine rewrite true",
			"2 RewriteCond rewrite false",
			"3 ErrorDocument error_documents false converted",
			"4 RewriteRule rewrite false",
			"5 RewriteRule rewrite false",
		}},
		{name: "continued rewrite rule", urlPath: "/", data: "RewriteRule ^a$ \\\n  /b [L]\n", verdict: VerdictConvertible, findings: []string{
			"1 RewriteRule rewrite false",
		}},
		{name: "RewriteBase for another path", urlPath: "/", data: "RewriteEngine On\nRewriteBase /shop/\n", verdict: VerdictConvertible, findings: []string{
			"1 RewriteEngine rewrite true",
			"2 RewriteBase rewrite false",
		}},
		{name: "unclosed section is malformed", urlPath: "/", data: "<IfModule mod_rewrite.c>\nRewriteEngine On\n", verdict: VerdictCompat, causes: []string{CauseMalformed}, findings: []string{
			"1 <IfModule> structure true",
			"2 RewriteEngine rewrite true",
		}},
		{name: "Directory section is not allowed", urlPath: "/", data: "<Directory /var/www>\nRewriteEngine On\n</Directory>\n", verdict: VerdictCompat, causes: []string{CauseMalformed}, findings: []string{
			"1 <Directory> structure false",
			"2 RewriteEngine rewrite false",
		}},
		{name: "SSL and HTTPS requirement", urlPath: "/", data: "SSLRequireSSL\n", verdict: VerdictCompat, causes: []string{CauseAccessControl}, findings: []string{
			"1 SSLRequireSSL access_control false tls /",
		}, rules: []string{"1 tls / files= methods= expect=0"}},
		{name: "empty file", urlPath: "/", data: "", verdict: VerdictNative},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ClassifyFile("site/.htaccess", tc.urlPath, []byte(tc.data))
			var got []string
			for _, f := range r.Findings {
				if f.File != "site/.htaccess" || f.Reason == "" {
					t.Fatalf("finding missing file or reason: %+v", f)
				}
				got = append(got, render(f))
			}
			if r.Verdict != tc.verdict || !reflect.DeepEqual(r.Causes, tc.causes) {
				t.Fatalf("verdict %s causes %v, want %s %v; findings %q problems %v", r.Verdict, r.Causes, tc.verdict, tc.causes, got, r.Problems)
			}
			if !reflect.DeepEqual(got, tc.findings) {
				t.Fatalf("findings:\n got %q\nwant %q", got, tc.findings)
			}
			if rules := renderRules(r.AccessRules); !reflect.DeepEqual(rules, tc.rules) {
				t.Fatalf("access rules:\n got %q\nwant %q", rules, tc.rules)
			}
		})
	}
}

func shift(findings []string, offset int) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		var line int
		var rest string
		fmt.Sscanf(f, "%d", &line)
		rest = strings.SplitN(f, " ", 2)[1]
		out[i] = fmt.Sprintf("%d %s", line+offset, rest)
	}
	return out
}

func TestClassifyOversizeFailsClosed(t *testing.T) {
	r := ClassifyFile("x/.htaccess", "/", make([]byte, MaxFileBytes+1))
	if r.Verdict != VerdictCompat || !reflect.DeepEqual(r.Causes, []string{CauseOversizeFile}) || r.Error == "" {
		t.Fatalf("oversize file: %+v", r)
	}
}
