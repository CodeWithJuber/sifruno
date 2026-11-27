package sitemodel

import (
	"errors"
	"strings"
	"testing"

	"sifruno/internal/cpsource"
)

func good() Site {
	return Site{Source: SourceArchive, Account: "shop", Domain: "example.com", Aliases: []string{"example.net"}, DocRoot: "public_html",
		Databases: []Database{{Name: "shop_wp", Dump: "mysql/shop_wp.sql"}},
		Users:     []User{{Name: "shop_wp", HasHash: true, Grants: []cpsource.Grant{{Database: "shop_wp", Privileges: []string{"ALL PRIVILEGES"}}}}},
		Cron:      []cpsource.CronLine{{Schedule: "*/5 * * * *", Command: "php ~/public_html/wp-cron.php"}},
		PHP:       PHP{Source: "ea-php82", Version: "8.2", Exact: true}}
}

func TestCheckAcceptsAWebsite(t *testing.T) {
	s := good()
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRefusesWhatCannotBeHosted(t *testing.T) {
	cases := map[string]func(*Site){
		"source":          func(s *Site) { s.Source = "plesk" },
		"account":         func(s *Site) { s.Account = "Shop" },
		"domain":          func(s *Site) { s.Domain = "Example.COM" },
		"alias":           func(s *Site) { s.Aliases = []string{"example.com"} },
		"php":             func(s *Site) { s.PHP.Version = "7.4" },
		"docroot outside": func(s *Site) { s.DocRoot = "../etc" },
		"docroot abs":     func(s *Site) { s.DocRoot = "/var/www" },
		"other database":  func(s *Site) { s.Databases = []Database{{Name: "other_wp"}} },
		"bare database":   func(s *Site) { s.Databases = []Database{{Name: "shop_"}} },
		"twice":           func(s *Site) { s.Databases = append(s.Databases, s.Databases[0]) },
		"grant elsewhere": func(s *Site) { s.Users[0].Grants = []cpsource.Grant{{Database: "shop_other"}} },
		"setting name":    func(s *Site) { s.PHP.Settings = []Setting{{Name: "x;y", Value: "1"}} },
		"setting value": func(s *Site) {
			s.PHP.Settings = []Setting{{Name: "memory_limit", Value: "1\nauto_prepend_file=/etc/passwd"}}
		},
		"rewrite newline": func(s *Site) { s.Rules.Rewrites = []string{"RewriteRule ^ - [L]\nDeny"} },
		"too many":        func(s *Site) { s.Aliases = make([]string, MaxAliases+1) },
		"negative disk":   func(s *Site) { s.DiskUsedMiB = -1 },
	}
	for name, change := range cases {
		s := good()
		change(&s)
		if err := s.Check(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Check = %v, want ErrInvalid", name, err)
		}
	}
}

func TestSkipIsBounded(t *testing.T) {
	var s Site
	for range MaxNotCarried * 2 {
		s.Skip("mail", strings.Repeat("x", 5000), "where\nnext")
	}
	if len(s.NotCarried) != MaxNotCarried || s.NotCarried[MaxNotCarried-1].Part != "more" {
		t.Fatalf("NotCarried = %d items, last %+v", len(s.NotCarried), s.NotCarried[len(s.NotCarried)-1])
	}
	if len(s.NotCarried[0].Text) > maxText || strings.Contains(s.NotCarried[0].Where, "\n") {
		t.Fatalf("an item is not one bounded line: %q", s.NotCarried[0].Where)
	}
}

func TestHtaccessSettingsBecomeUserINI(t *testing.T) {
	htaccess := `# BEGIN cPanel-generated php ini directives
<IfModule php8_module>
   php_flag display_errors Off
   php_value max_execution_time 300
   php_value memory_limit 256M
   php_value upload_max_filesize 64M
   php_value date.timezone "Europe/London"
   php_value error_reporting "E_ALL & ~E_NOTICE"
   php_value session.save_path "/var/cpanel/php/sessions/ea-php82"
   php_admin_value open_basedir /home/shop
   php_value memory_limit 512M
   php_value include_path ".:/opt/cpanel/ea-php82/root/usr/share/pear"
   php_flag zlib.output_compression maybe
</IfModule>
RewriteEngine On
`
	var s Site
	s.HtaccessSettings("public_html/.htaccess", []byte(htaccess))
	got := string(s.PHP.UserINI())
	want := `; PHP settings carried from the old server by Sifruno's move.
date.timezone = Europe/London
display_errors = Off
error_reporting = E_ALL & ~E_NOTICE
max_execution_time = 300
memory_limit = 512M
upload_max_filesize = 64M
`
	if got != want {
		t.Fatalf("UserINI:\n%s\nwant:\n%s", got, want)
	}
	var texts []string
	for _, item := range s.NotCarried {
		texts = append(texts, item.Where+": "+item.Text)
	}
	joined := strings.Join(texts, "\n")
	for _, w := range []string{"line 9: The PHP setting session.save_path is not one", "line 10: The PHP setting open_basedir is one only", "line 12: The PHP setting include_path is not one", "line 13: The PHP flag zlib.output_compression is not on or off"} {
		if !strings.Contains(joined, w) {
			t.Errorf("not carried lacks %q:\n%s", w, joined)
		}
	}
}

func TestUserINIQuotesOnlyWhatItMust(t *testing.T) {
	var s Site
	s.AddSetting("session.cookie_samesite", "Lax", "nginx line 4")
	s.AddSetting("arg_separator.output", "&amp;", "nginx line 5")
	s.AddSetting("default_charset", "UTF-8, x", "nginx line 6")
	s.AddSetting("precision", `14"; auto_prepend_file="/tmp/x`, "nginx line 7")
	got := string(s.PHP.UserINI())
	if !strings.Contains(got, "session.cookie_samesite = Lax\n") || !strings.Contains(got, `default_charset = "UTF-8, x"`) || strings.Contains(got, "precision") || strings.Contains(got, "&amp;") {
		t.Fatalf("UserINI:\n%s", got)
	}
	if len(s.NotCarried) != 2 {
		t.Fatalf("NotCarried = %+v", s.NotCarried)
	}
	if (PHP{}).UserINI() != nil {
		t.Fatal("no settings should give no file")
	}
}
