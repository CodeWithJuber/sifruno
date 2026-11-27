package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sifruno/internal/htaccess"
)

const testWordPressHtaccess = `# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
`

func buildCPanelTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"alice/public_html/.htaccess":                  testWordPressHtaccess,
		"alice/public_html/members/.htaccess":          "AuthType Basic\nAuthName \"Members\"\nAuthUserFile /home/alice/.htpasswds/members/passwd\nRequire valid-user\n",
		"bob/public_html/.htaccess":                    "ExpiresActive On\nExpiresByType image/png \"access plus 1 month\"\n" + testWordPressHtaccess,
		"carol/public_html/.htaccess":                  testWordPressHtaccess,
		"carol/public_html/shop.example.com/.htaccess": "FooBarDirective on\n",
		"dave/mail/inbox":                              "no docroot",
	}
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errs bytes.Buffer
	err := run(args, &out, &errs)
	if errs.Len() != 0 {
		t.Fatalf("unexpected diagnostics: %q", errs.String())
	}
	return out.String(), err
}

func TestHtaccessScanSummaryHidesNamesAndPaths(t *testing.T) {
	root := buildCPanelTree(t)
	out, err := runCLI(t, "htaccess", "scan", "--root", root, "--layout", "cpanel")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"layout cpanel",
		// bob's Expires lines are harmless to ignore.
		"sites: 3 (native 1, convertible 0, compat 2)",
		".htaccess files: 5 (native 3, convertible 0, compat 2, not readable 0)",
		"directives OpenLiteSpeed ignores that Sifruno covers: harmless 2, handled 0, warnings 0\n",
		"  access_control: 4\n",
		"  unknown: 1\n",
		"  access_control: 1\n",
		"compat sites by cause combination:\n  access_control: 1\n  unknown: 1\n",
		"compat sites caused only by nested .htaccess files: 2",
		"accounts without a document root: 1",
		"top unknown directives: foobardirective 1;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary lacks %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"alice", "bob", "carol", "dave", "public_html", "members", "shop.example.com", root, "htpasswds"} {
		if strings.Contains(out, secret) {
			t.Fatalf("summary leaks %q:\n%s", secret, out)
		}
	}
}

func TestHtaccessScanJSON(t *testing.T) {
	root := buildCPanelTree(t)
	out, err := runCLI(t, "htaccess", "scan", "--root", root, "--layout", "cpanel", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var report htaccess.Report
	if err = json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Sites != nil || strings.Contains(out, "alice") || strings.Contains(out, "public_html") || strings.Contains(out, root) {
		t.Fatalf("JSON without --details leaks per-site data:\n%s", out)
	}
	tt := report.Totals
	if tt.Sites != 3 || tt.SitesByVerdict[htaccess.VerdictCompat] != 2 || tt.AccountsWithoutDocroot != 1 || tt.CompatSitesNestedOnly != 2 ||
		tt.CompatSitesByCause[htaccess.CauseAccessControl] != 1 || tt.CompatSitesByCause[htaccess.CauseUnknown] != 1 {
		t.Fatalf("totals %+v", tt)
	}

	out, err = runCLI(t, "htaccess", "scan", "--root", root, "--layout", "cpanel", "--json", "--details")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Sites) != 3 || report.Sites[0].Name != "alice/public_html" {
		t.Fatalf("details %+v", report.Sites)
	}
	members := report.Sites[0].Files[1]
	if members.Path != "alice/public_html/members/.htaccess" || len(members.AccessRules) != 1 || members.AccessRules[0].Path != "/members/" || members.AccessRules[0].ExpectStatus != 401 {
		t.Fatalf("members file %+v", members)
	}
}

func TestHtaccessScanDetailsText(t *testing.T) {
	root := buildCPanelTree(t)
	out, err := runCLI(t, "htaccess", "scan", "--root", root, "--layout", "cpanel", "--details")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"site alice/public_html: compat access_control", "alice/public_html/members/.htaccess (/members/)", "access password /members/"} {
		if !strings.Contains(out, want) {
			t.Fatalf("details lack %q:\n%s", want, out)
		}
	}
}

// TestHtaccessScanDetailsNameEachLine: with --details, each site says
// whether it moves to OpenLiteSpeed and names the file, line and directive
// of each refusal, warning and PHP handler.
func TestHtaccessScanDetailsNameEachLine(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		".htaccess": "# php -- BEGIN cPanel-generated handler, do not edit\n<IfModule mime_module>\n  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml\n</IfModule>\n" +
			"# php -- END cPanel-generated handler, do not edit\nphp_value upload_max_filesize 64M\nHeader set Cache-Control \"max-age=600\"\n" +
			"Redirect 301 /old /new\nErrorDocument 404 /404.html\n<Files wp-config.php>\nRequire all denied\n</Files>\n" + testWordPressHtaccess,
		"tools/.htaccess": "ExpiresActive On\nSifrunoUnknown On\n",
	}
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, err := runCLI(t, "htaccess", "scan", "--root", root, "--details")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"    line 3 AddHandler [vendor, handled]: PHP handler",
		"    line 6 php_value [php_settings, converted]: PHP setting: OpenLiteSpeed does not read it from .htaccess",
		"    line 7 Header [headers, ignored]: caching or security response header",
		"  moves to OpenLiteSpeed: no\n",
		"    refused: tools/.htaccess line 2 (SifrunoUnknown On): a directive this panel does not know\n",
		"    PHP handler: .htaccess line 3 for /: ea-php81\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("details lack %q:\n%s", want, out)
		}
	}
	if err := os.Remove(filepath.Join(root, "tools", ".htaccess")); err != nil {
		t.Fatal(err)
	}
	if out, err = runCLI(t, "htaccess", "scan", "--root", root, "--details"); err != nil || !strings.Contains(out, "  moves to OpenLiteSpeed: yes\n") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	for _, want := range []string{
		"    converted: .htaccess for /\n",
		"    converted: line 8, redirect (301) of /old to /new\n",
		"    converted: line 9, error page /404.html for 404\n",
		"    converted: line 6, PHP setting upload_max_filesize 64M\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("details lack %q:\n%s", want, out)
		}
	}
}

func TestHtaccessScanUsageAndRootErrors(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{
		{"htaccess"},
		{"htaccess", "list"},
		{"htaccess", "scan"},
		{"htaccess", "scan", "--root", root, "--layout", "flat"},
		{"htaccess", "scan", "--root", root, "extra"},
		{"htaccess", "scan", "--root", filepath.Join(root, "missing")},
	} {
		out, err := runCLI(t, args...)
		if err == nil || out != "" {
			t.Fatalf("%v: err=%v out=%q", args, err, out)
		}
		if strings.Contains(err.Error(), root) {
			t.Fatalf("%v: error leaks the path: %v", args, err)
		}
	}
	out, err := runCLI(t, "htaccess", "scan", "--root", root)
	if err != nil || !strings.Contains(out, "layout single") || !strings.Contains(out, "sites: 1 (native 1, convertible 0, compat 0)") {
		t.Fatalf("empty single root: err=%v out=%q", err, out)
	}
}
