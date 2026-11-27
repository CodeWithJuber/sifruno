package htaccess

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// cpanelINIBlock is what cPanel's MultiPHP INI Editor writes into a root
// .htaccess for the DSO and LSAPI handlers.
const cpanelINIBlock = `# BEGIN cPanel-generated php ini directives, do not edit
# Manual editing of this file may result in unexpected behavior.
# To make changes to this file, use the cPanel MultiPHP INI Editor (Home >> Software >> MultiPHP INI Editor)
# For more information, read our documentation (https://go.cpanel.net/EA4ModifyINI)
<IfModule php8_module>
   php_flag display_errors Off
   php_value max_execution_time 300
   php_value max_input_time 600
   php_value max_input_vars 3000
   php_value memory_limit 512M
   php_value post_max_size 128M
   php_value session.gc_maxlifetime 1440
   php_value session.save_path "/var/cpanel/php/sessions/ea-php81"
   php_value upload_max_filesize 128M
   php_flag zlib.output_compression Off
</IfModule>
<IfModule lsapi_module>
   php_flag display_errors Off
   php_value max_execution_time 300
   php_value max_input_time 600
   php_value max_input_vars 3000
   php_value memory_limit 512M
   php_value post_max_size 128M
   php_value session.gc_maxlifetime 1440
   php_value session.save_path "/var/cpanel/php/sessions/ea-php81"
   php_value upload_max_filesize 128M
   php_flag zlib.output_compression Off
</IfModule>
# END cPanel-generated php ini directives, do not edit
`

func TestPHPLines(t *testing.T) {
	converted := func(name, value string, flag bool) *PHPSetting {
		return &PHPSetting{Line: 1, Name: name, Value: value, Flag: flag}
	}
	for _, tc := range []struct {
		text     string
		handling Handling
		setting  *PHPSetting
		reason   string
	}{
		{"php_value memory_limit 256M", HandlingConverted, converted("memory_limit", "256M", false), ""},
		{"php_value memory_limit -1", HandlingConverted, converted("memory_limit", "-1", false), ""},
		{"php_value Memory_Limit 1G", HandlingConverted, converted("memory_limit", "1G", false), ""},
		{"php_value upload_max_filesize 134217728", HandlingConverted, converted("upload_max_filesize", "134217728", false), ""},
		{"php_value max_execution_time 0", HandlingConverted, converted("max_execution_time", "0", false), ""},
		{"php_value max_input_time -1", HandlingConverted, converted("max_input_time", "-1", false), ""},
		{"php_value error_reporting 32767", HandlingConverted, converted("error_reporting", "32767", false), ""},
		{"php_flag display_errors On", HandlingConverted, converted("display_errors", "on", true), ""},
		{"php_flag log_errors 1", HandlingConverted, converted("log_errors", "on", true), ""},
		{"php_value display_errors 0", HandlingConverted, converted("display_errors", "off", true), ""},
		{"php_value output_buffering 4096", HandlingConverted, converted("output_buffering", "4096", false), ""},
		{"php_flag output_buffering off", HandlingConverted, converted("output_buffering", "off", true), ""},
		{`php_value date.timezone "Europe/Berlin"`, HandlingConverted, converted("date.timezone", "Europe/Berlin", false), ""},
		{"php_value date.timezone America/Argentina/Buenos_Aires", HandlingConverted, converted("date.timezone", "America/Argentina/Buenos_Aires", false), ""},
		{"php_flag magic_quotes_gpc off", HandlingIgnored, nil, "removed"},
		{`php_value session.save_path "/var/cpanel/php/sessions/ea-php74"`, HandlingSifruno, nil, "session folder"},
		// Refused, each with why.
		{"php_value upload_max_filesize -1", "", nil, "a size such as 256M"},
		{"php_value memory_limit 256MB", "", nil, "a size such as 256M"},
		{"php_value memory_limit 99999999G", "", nil, "a size"},
		{"php_flag display_errors yes", "", nil, "On, Off, 1 or 0"},
		{"php_flag memory_limit 1", "", nil, "a size"},
		{"php_value error_reporting E_ALL", "", nil, "whole number"},
		{"php_value date.timezone ../../etc/passwd", "", nil, "time zone"},
		{"php_value max_input_vars 3000 4000", "", nil, "one value"},
		{"php_value auto_prepend_file /home/u/public_html/wordfence-waf.php", "", nil, "firewall"},
		{"php_value auto_append_file /home/u/public_html/end.php", "", nil, "after every script"},
		{"php_value open_basedir none", "", nil, "security setting"},
		{"php_value disable_functions exec", "", nil, "security setting"},
		{"php_value include_path .:/usr/share/php", "", nil, "names a file, folder or program"},
		{"php_value sendmail_path /usr/sbin/sendmail", "", nil, "names a file, folder or program"},
		{"php_value session.save_path /home/u/tmp", "", nil, "names a file, folder or program"},
		{"php_value xdebug.output_dir /tmp", "", nil, "names a file or folder"},
		{"php_value session.name SHOP", "", nil, "does not carry"},
		{"php_flag register_globals on", "", nil, "does not carry"},
		{"php_admin_value memory_limit 256M", "", nil, "administrator"},
		{"php_admin_flag display_errors off", "", nil, "administrator"},
	} {
		r := ClassifyFile(".htaccess", "/", []byte(tc.text+"\n"))
		if len(r.Findings) != 1 {
			t.Fatalf("%q: findings %+v", tc.text, r.Findings)
		}
		g := r.Findings[0]
		if g.Handling != tc.handling || !reflect.DeepEqual(g.PHPSetting, tc.setting) || !strings.Contains(g.Reason, tc.reason) {
			t.Errorf("%q: handling %q setting %+v reason %q; want %q %+v %q", tc.text, g.Handling, g.PHPSetting, g.Reason, tc.handling, tc.setting, tc.reason)
		}
		if g.Category != CategoryPHPSettings {
			t.Errorf("%q: category %s", tc.text, g.Category)
		}
	}
}

func TestPHPLinesCarryFromTheRootTopLevelOnly(t *testing.T) {
	for _, tc := range []struct {
		name, file, text string
		carried          bool
	}{
		{"top level", ".htaccess", "php_value memory_limit 256M\n", true},
		{"inside <IfModule mod_php7.c>", ".htaccess", "<IfModule mod_php7.c>\nphp_value memory_limit 256M\n</IfModule>\n", true},
		{"inside cPanel's lsapi_module block", ".htaccess", "<IfModule lsapi_module>\nphp_value memory_limit 256M\n</IfModule>\n", true},
		{"inside <IfModule !mod_php.c>", ".htaccess", "<IfModule !mod_php.c>\nphp_value memory_limit 256M\n</IfModule>\n", false},
		{"inside <IfModule LiteSpeed>", ".htaccess", "<IfModule LiteSpeed>\nphp_value memory_limit 256M\n</IfModule>\n", false},
		{"inside <Files>", ".htaccess", "<Files upload.php>\nphp_value upload_max_filesize 64M\n</Files>\n", false},
		{"inside <If>", ".htaccess", "<If \"%{HTTP_HOST} == 'example.com'\">\nphp_value memory_limit 256M\n</If>\n", false},
		{"a folder's .htaccess", "wp-admin/.htaccess", "php_value memory_limit 256M\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ConvertSite(siteOf(map[string]string{tc.file: tc.text}))
			if tc.carried {
				if !got.Native || len(got.PHPSettings) != 1 || got.PHPSettings[0].Name != "memory_limit" && got.PHPSettings[0].Name != "upload_max_filesize" {
					t.Fatalf("%+v", got)
				}
				return
			}
			if got.Native || len(got.PHPSettings) != 0 || len(got.Refused) != 1 || got.Refused[0].File != tc.file || got.Refused[0].Line == 0 || got.Refused[0].Cause != CauseNotConverted {
				t.Fatalf("%+v", got)
			}
		})
	}
}

// Wordfence's mod_php block holds its auto_prepend_file line beside a
// <Files ".user.ini"> rule: the line is the reason, named with its own,
// not the access rule the converter would carry without it.
func TestWordfenceModPHPBlockRefusesItsPrependLine(t *testing.T) {
	got := ConvertSite(siteOf(map[string]string{".htaccess": wordfenceBlock}))
	if got.Native || len(got.Refused) != 1 {
		t.Fatalf("%+v", got)
	}
	r := got.Refused[0]
	if r.File != ".htaccess" || r.Line != 3 || r.Directive != "php_value auto_prepend_file" || r.Cause != CauseNotConverted || !strings.Contains(r.Reason, "firewall") {
		t.Fatalf("%+v", r)
	}
	// Without the line, the rule converts.
	got = ConvertSite(siteOf(map[string]string{".htaccess": strings.Replace(wordfenceBlock, "\tphp_value auto_prepend_file '/home/alice/public_html/wordfence-waf.php'\n", "", 1)}))
	if !got.Native || len(got.Rules) != 1 || got.Rules[0].Deny == nil {
		t.Fatalf("%+v", got)
	}
}

func TestCPanelINIBlockMovesWithItsSettings(t *testing.T) {
	got := ConvertSite(siteOf(map[string]string{".htaccess": cpanelWordPress + cpanelINIBlock}))
	if !got.Native || len(got.Refused) != 0 || len(got.Warnings) != 0 {
		t.Fatalf("%+v", got)
	}
	// Each setting once, in the order it first appears, from its last line.
	lines := strings.Count(cpanelWordPress, "\n")
	want := []PHPSetting{
		{Line: lines + 18, Name: "display_errors", Value: "off", Flag: true},
		{Line: lines + 19, Name: "max_execution_time", Value: "300"},
		{Line: lines + 20, Name: "max_input_time", Value: "600"},
		{Line: lines + 21, Name: "max_input_vars", Value: "3000"},
		{Line: lines + 22, Name: "memory_limit", Value: "512M"},
		{Line: lines + 23, Name: "post_max_size", Value: "128M"},
		{Line: lines + 24, Name: "session.gc_maxlifetime", Value: "1440"},
		{Line: lines + 26, Name: "upload_max_filesize", Value: "128M"},
		{Line: lines + 27, Name: "zlib.output_compression", Value: "off", Flag: true},
	}
	if !reflect.DeepEqual(got.PHPSettings, want) {
		t.Fatalf("settings\n%+v\nwant\n%+v", got.PHPSettings, want)
	}
	for _, s := range got.PHPSettings {
		if !CarriedPHPSetting(s) {
			t.Errorf("%+v is not one the broker carries", s)
		}
	}
}

func TestLaterPHPLineWins(t *testing.T) {
	got := ConvertSite(siteOf(map[string]string{".htaccess": "php_value memory_limit 128M\nphp_flag display_errors on\nphp_value memory_limit 256M\n"}))
	want := []PHPSetting{{Line: 3, Name: "memory_limit", Value: "256M"}, {Line: 2, Name: "display_errors", Value: "on", Flag: true}}
	if !got.Native || !reflect.DeepEqual(got.PHPSettings, want) {
		t.Fatalf("%+v", got.PHPSettings)
	}
}

func TestTooManyPHPSettingsRefuse(t *testing.T) {
	var b strings.Builder
	names := []string{"memory_limit", "upload_max_filesize", "post_max_size"}
	for i := 0; i <= MaxSitePHPSettings; i++ {
		// Settings repeat, so the bound counts settings, not lines.
		fmt.Fprintf(&b, "php_value %s %dM\n", names[i%len(names)], i+1)
	}
	if got := ConvertSite(siteOf(map[string]string{".htaccess": b.String()})); !got.Native || len(got.PHPSettings) != 3 {
		t.Fatalf("%+v", got)
	}
	b.Reset()
	numbers := []string{"max_execution_time", "max_input_time", "max_input_vars", "max_input_nesting_level", "max_file_uploads", "session.gc_maxlifetime", "session.cookie_lifetime", "default_socket_timeout", "pcre.backtrack_limit", "pcre.recursion_limit", "error_reporting"}
	flags := []string{"display_errors", "display_startup_errors", "log_errors", "html_errors", "short_open_tag", "session.cookie_httponly", "session.cookie_secure", "session.use_strict_mode", "session.use_only_cookies", "output_buffering", "zlib.output_compression"}
	for _, n := range names {
		fmt.Fprintf(&b, "php_value %s 64M\n", n)
	}
	for _, n := range numbers {
		fmt.Fprintf(&b, "php_value %s 30\n", n)
	}
	for _, n := range flags {
		fmt.Fprintf(&b, "php_flag %s on\n", n)
	}
	b.WriteString("php_value date.timezone UTC\n")
	if len(phpSettings) != len(names)+len(numbers)+len(flags)+1 {
		t.Fatalf("the test names %d settings, the list has %d", len(names)+len(numbers)+len(flags)+1, len(phpSettings))
	}
	if got := ConvertSite(siteOf(map[string]string{".htaccess": b.String()})); !got.Native || len(got.PHPSettings) != len(phpSettings) || len(phpSettings) > MaxSitePHPSettings {
		t.Fatalf("every listed setting once: %+v", got)
	}
}

func TestCarriedPHPSettingChecksWhatTheBrokerRecords(t *testing.T) {
	for _, tc := range []struct {
		s  PHPSetting
		ok bool
	}{
		{PHPSetting{Name: "memory_limit", Value: "256M"}, true},
		{PHPSetting{Name: "display_errors", Value: "on", Flag: true}, true},
		{PHPSetting{Name: "output_buffering", Value: "4096"}, true},
		{PHPSetting{Name: "date.timezone", Value: "Europe/Berlin"}, true},
		{PHPSetting{Name: "display_errors", Value: "On", Flag: true}, false},
		{PHPSetting{Name: "display_errors", Value: "on"}, false},
		{PHPSetting{Name: "memory_limit", Value: "256M", Flag: true}, false},
		{PHPSetting{Name: "memory_limit", Value: "256M\nauto_prepend_file /tmp/x"}, false},
		{PHPSetting{Name: "auto_prepend_file", Value: "/home/u/public_html/x.php"}, false},
		{PHPSetting{Name: "Memory_Limit", Value: "256M"}, false},
	} {
		if got := CarriedPHPSetting(tc.s); got != tc.ok {
			t.Errorf("%+v: %t, want %t", tc.s, got, tc.ok)
		}
	}
}

// wordfenceUserINI is what Wordfence 9's performInstallation writes for the
// "cgi" (PHP-FPM) case.
const wordfenceUserINI = "; Wordfence WAF\nauto_prepend_file = '/home/alice/public_html/wordfence-waf.php'\n; END Wordfence WAF\n"

func TestUserINIWarnings(t *testing.T) {
	got := UserINIWarnings(".user.ini", []byte(wordfenceUserINI))
	if len(got) != 1 || got[0].File != ".user.ini" || got[0].Line != 2 || got[0].Directive != "auto_prepend_file" || !strings.Contains(got[0].Reason, "Wordfence") || !strings.Contains(got[0].Reason, "before every script") {
		t.Fatalf("%+v", got)
	}
	if strings.Contains(got[0].Reason, "/home/") {
		t.Errorf("the warning names the old server's path: %q", got[0].Reason)
	}
	got = UserINIWarnings(".user.ini", []byte("memory_limit = 256M\r\nAUTO_APPEND_FILE=\"/home/a/end.php\" ; tail\r\n"))
	if len(got) != 1 || got[0].Line != 2 || got[0].Directive != "auto_append_file" || !strings.Contains(got[0].Reason, "after every script") {
		t.Fatalf("%+v", got)
	}
	for _, text := range []string{
		"",
		"max_execution_time = 60\n",
		"; auto_prepend_file = '/home/a/w.php'\n",
		"auto_prepend_file =\n",
		"auto_prepend_file = ''\n",
		"auto_prepend_file = none\n",
		"auto_prepend_file = Off ; turned off\n",
		"[HOST=example.com]\n",
	} {
		if got := UserINIWarnings(".user.ini", []byte(text)); len(got) != 0 {
			t.Errorf("%q: %+v", text, got)
		}
	}
}

func TestScanReadsTheDocumentRootUserINI(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".htaccess":              wordpressBlock,
		".user.ini":              wordfenceUserINI,
		"blog/.user.ini":         wordfenceUserINI,
		".user.ini.bak/x.txt":    "a folder whose name starts like it",
		"uploads/.htaccess":      "Options -Indexes\n",
		"uploads/info/x.txt":     "x",
		"uploads/info/.htaccess": "Options -Indexes\n",
	})
	r := scan(t, root, LayoutSingle, DefaultLimits())
	site := r.Sites[0]
	if len(site.UserINI) != 1 || site.UserINI[0].File != ".user.ini" || site.UserINI[0].Line != 2 {
		t.Fatalf("user.ini warnings %+v", site.UserINI)
	}
	if len(site.Files) != 3 {
		t.Fatalf("files %+v", site.Files)
	}
	conv := ConvertSite(site)
	if !conv.Native || len(conv.Warnings) != 1 || conv.Warnings[0].Directive != "auto_prepend_file" {
		t.Fatalf("%+v", conv)
	}

	// A link is not followed, and a folder of that name is walked.
	root = t.TempDir()
	writeTree(t, root, map[string]string{"real.ini": wordfenceUserINI, "other/.user.ini/.htaccess": "Deny from all\n"})
	symlink(t, "real.ini", filepath.Join(root, ".user.ini"))
	site = scan(t, root, LayoutSingle, DefaultLimits()).Sites[0]
	if len(site.UserINI) != 1 || site.UserINI[0].Line != 0 || !strings.Contains(site.UserINI[0].Reason, "a link") {
		t.Fatalf("linked .user.ini: %+v", site.UserINI)
	}
	if len(site.Files) != 1 || site.Files[0].Path != "other/.user.ini/.htaccess" {
		t.Fatalf("files %+v", site.Files)
	}

	root = t.TempDir()
	writeTree(t, root, map[string]string{".user.ini/.htaccess": "Deny from all\n"})
	site = scan(t, root, LayoutSingle, DefaultLimits()).Sites[0]
	if len(site.UserINI) != 0 || len(site.Files) != 1 {
		t.Fatalf("a folder named .user.ini: %+v", site)
	}

	root = t.TempDir()
	writeTree(t, root, map[string]string{"index.php": "x"})
	if err := os.WriteFile(filepath.Join(root, ".user.ini"), make([]byte, MaxFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	site = scan(t, root, LayoutSingle, DefaultLimits()).Sites[0]
	if len(site.UserINI) != 1 || !strings.Contains(site.UserINI[0].Reason, "larger than 1 MiB") {
		t.Fatalf("a large .user.ini: %+v", site.UserINI)
	}
}
