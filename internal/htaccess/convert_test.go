package htaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func convertText(t *testing.T, urlPath, text string) *Conversion {
	t.Helper()
	f, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return Convert(f, urlPath)
}

func TestConvertPatterns(t *testing.T) {
	none := Hosts{Kind: HostsNone}
	all := Hosts{Kind: HostsAll}
	cases := []struct {
		name, text string
		want       FolderRule
	}{
		{"deny from all", "Deny from all\n", FolderRule{Hosts: none}},
		{"order allow,deny alone", "Order Allow,Deny\n", FolderRule{Hosts: none}},
		{"order deny,allow deny all", "Order Deny,Allow\nDeny from all\n", FolderRule{Hosts: none}},
		{"allow,deny deny all wins", "Order Allow,Deny\nAllow from all\nDeny from all\n", FolderRule{Hosts: none}},
		{"deny,allow allow all wins", "Order Deny,Allow\nDeny from all\nAllow from all\n", FolderRule{Hosts: all}},
		{"require all denied", "Require all denied\n", FolderRule{Hosts: none}},
		{"require all granted", "Require all granted\n", FolderRule{Hosts: all}},
		{"options -indexes only", "Options -Indexes\n", FolderRule{Hosts: all}},
		{"deny all with listing off", "Options -Indexes\nDeny from all\n", FolderRule{Hosts: none}},
		{"allow only a network", "Order Deny,Allow\nDeny from all\nAllow from 192.0.2.0/24 198.51.100.7\nAllow from 10.1\n",
			FolderRule{Hosts: Hosts{Kind: HostsOnly, Networks: []string{"10.1.0.0/16", "192.0.2.0/24", "198.51.100.7/32"}}}},
		{"allow,deny allow list", "Order Allow,Deny\nAllow from 2001:db8::/32\n",
			FolderRule{Hosts: Hosts{Kind: HostsOnly, Networks: []string{"2001:db8::/32"}}}},
		{"deny a network", "Order Allow,Deny\nAllow from all\nDeny from 203.0.113.0/24\n",
			FolderRule{Hosts: Hosts{Kind: HostsExcept, Networks: []string{"203.0.113.0/24"}}}},
		{"deny,allow deny list", "Deny from 203.0.113.9\n",
			FolderRule{Hosts: Hosts{Kind: HostsExcept, Networks: []string{"203.0.113.9/32"}}}},
		{"require ip", "Require ip 192.0.2.10 192.0.2.0/28\nRequire ip 10\n",
			FolderRule{Hosts: Hosts{Kind: HostsOnly, Networks: []string{"10.0.0.0/8", "192.0.2.0/28", "192.0.2.10/32"}}}},
		{"pair agrees on deny", "<IfModule !mod_authz_core.c>\nOrder Deny,Allow\nDeny from all\n</IfModule>\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n", FolderRule{Hosts: none}},
		{"pair by module identifier", "<IfModule !authz_core_module>\nDeny from all\n</IfModule>\n<IfModule authz_core_module>\nRequire all denied\n</IfModule>\n", FolderRule{Hosts: none}},
		{"pair agrees on a network", "<IfModule !mod_authz_core.c>\nOrder Deny,Allow\nDeny from all\nAllow from 192.0.2.0/24\n</IfModule>\n<IfModule mod_authz_core.c>\nRequire ip 192.0.2.0/24\n</IfModule>\n",
			FolderRule{Hosts: Hosts{Kind: HostsOnly, Networks: []string{"192.0.2.0/24"}}}},
		{"password valid-user", "AuthType Basic\nAuthName \"Members only\"\nAuthUserFile /home/u/.htpasswds/public_html/members/passwd\nRequire valid-user\n",
			FolderRule{Hosts: all, Realm: &Realm{Name: "Members only", UserFile: "/home/u/.htpasswds/public_html/members/passwd"}}},
		{"password named users", "AuthType basic\nAuthName Staff\nAuthUserFile /home/u/.htpasswd\nAuthBasicProvider file\nRequire user bob alice\nRequire user bob\n",
			FolderRule{Hosts: all, Realm: &Realm{Name: "Staff", UserFile: "/home/u/.htpasswd", Users: []string{"alice", "bob"}}}},
		{"valid-user covers user", "AuthType Basic\nAuthName Staff\nAuthUserFile /home/u/.htpasswd\nRequire user bob\nRequire valid-user\n",
			FolderRule{Hosts: all, Realm: &Realm{Name: "Staff", UserFile: "/home/u/.htpasswd"}}},
		{"password and a network", "Order Deny,Allow\nDeny from all\nAllow from 192.0.2.0/24\nAuthType Basic\nAuthName Staff\nAuthUserFile /home/u/.htpasswd\nRequire valid-user\n",
			FolderRule{Hosts: Hosts{Kind: HostsOnly, Networks: []string{"192.0.2.0/24"}}, Realm: &Realm{Name: "Staff", UserFile: "/home/u/.htpasswd"}}},
		{"password with deny all", "Deny from all\nAuthType Basic\nAuthName Staff\nAuthUserFile /home/u/.htpasswd\nRequire valid-user\n",
			FolderRule{Hosts: none}},
		{"files allow-list", "Deny from all\n<Files \"style.css\">\nAllow from all\n</Files>\n<FilesMatch \"^(app|admin)\\.js$\">\nAllow from all\n</FilesMatch>\n",
			FolderRule{Hosts: none, Allow: []string{"admin.js", "app.js", "style.css"}}},
		{"files tilde regex", "Require all denied\n<Files ~ \"^logo\\.(png|svg)$\">\nRequire all granted\n</Files>\n",
			FolderRule{Hosts: none, Allow: []string{"logo.png", "logo.svg"}}},
		{"files section without access lines", "Deny from all\n<Files a.css>\n</Files>\n", FolderRule{Hosts: none}},
		{"files fresh compat config opens", "Deny from all\n<Files a.css>\nAllow from 192.0.2.1\n</Files>\n",
			FolderRule{Hosts: none, Allow: []string{"a.css"}}},
		{"comments and case", "# keep out\ndeny FROM ALL\n", FolderRule{Hosts: none}},
		// On 2.4 the Files section's Require does not lift mod_access_compat's
		// Deny from all (Satisfy All), so nothing opens.
		{"files grant under compat deny", "Deny from all\n<IfModule mod_authz_core.c>\n<Files a.css>\nRequire all granted\n</Files>\n</IfModule>\n", FolderRule{Hosts: none}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := convertText(t, "/private/", c.text)
			c.want.Path = "/private/"
			if got.Rule == nil {
				t.Fatalf("refused at line %d: %s", got.Line, got.Refused)
			}
			if !reflect.DeepEqual(*got.Rule, c.want) {
				t.Fatalf("got %+v\nwant %+v", *got.Rule, c.want)
			}
		})
	}
}

// TestConvertRefusals lists every ambiguous or unconverted form; each must
// refuse with a reason.
func TestConvertRefusals(t *testing.T) {
	auth := "AuthType Basic\nAuthName Staff\nAuthUserFile /home/u/.htpasswd\n"
	cases := map[string]string{
		"satisfy any":               "Deny from all\nSatisfy Any\n",
		"satisfy all":               "Deny from all\nSatisfy All\n",
		"limit":                     "<Limit GET POST>\nDeny from all\n</Limit>\n",
		"limitexcept":               "<LimitExcept GET>\nRequire all denied\n</LimitExcept>\n",
		"require any":               "<RequireAny>\nRequire ip 192.0.2.1\n</RequireAny>\n",
		"require all container":     "<RequireAll>\nRequire all granted\n</RequireAll>\n",
		"require not":               "Require not ip 192.0.2.1\n",
		"require host":              "Require host example.com\n",
		"require env":               "Require env let_in\n",
		"require expr":              "Require expr %{REMOTE_ADDR} == '1.2.3.4'\n",
		"require group":             auth + "Require group staff\n",
		"require mixed ip user":     auth + "Require ip 192.0.2.1\nRequire valid-user\n",
		"require granted denied":    "Require all granted\nRequire all denied\n",
		"env allow":                 "SetEnvIf User-Agent bot let_in\nOrder Deny,Allow\nDeny from all\nAllow from env=let_in\n",
		"allow env only":            "Order Deny,Allow\nDeny from all\nAllow from env=let_in\n",
		"host name":                 "Deny from all\nAllow from example.com\n",
		"netmask form":              "Deny from all\nAllow from 10.0.0.0/255.0.0.0\n",
		"host bits":                 "Deny from all\nAllow from 10.0.0.1/8\n",
		"zero prefix":               "Deny from all\nAllow from 0.0.0.0/0\n",
		"leading zero":              "Deny from all\nAllow from 010.1\n",
		"both sides lists":          "Order Deny,Allow\nDeny from 10.0.0.0/8\nAllow from 10.1.0.0/16\n",
		"allow,deny both lists":     "Order Allow,Deny\nAllow from 10.0.0.0/8\nDeny from 10.1.0.0/16\n",
		"compat and require lists":  "Deny from all\nAllow from 10.0.0.0/8\n<IfModule mod_authz_core.c>\nRequire ip 10.0.0.0/8\n</IfModule>\n",
		"mutual failure":            "Order Mutual-failure\n",
		"order twice":               "Order Deny,Allow\nOrder Allow,Deny\n",
		"order spaced":              "Order Deny, Allow\n",
		"allow without from":        "Allow all\n",
		"pair disagrees":            "<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n<IfModule mod_authz_core.c>\nRequire all granted\n</IfModule>\n",
		"require ip on 2.2":         "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\nRequire ip 192.0.2.1\n",
		"other ifmodule":            "<IfModule mod_access_compat.c>\nDeny from all\n</IfModule>\n",
		"ifversion":                 "<IfVersion >= 2.4>\nRequire all denied\n</IfVersion>\n",
		"nested files":              "Deny from all\n<Files a.css>\n<Files b.css>\nAllow from all\n</Files>\n</Files>\n",
		"directory in htaccess":     "<Directory /home>\nDeny from all\n</Directory>\n",
		"files wildcard":            "Deny from all\n<Files *.css>\nAllow from all\n</Files>\n",
		"filesmatch suffix":         "Deny from all\n<FilesMatch \"\\.(css|js)$\">\nAllow from all\n</FilesMatch>\n",
		"filesmatch unanchored":     "Deny from all\n<FilesMatch \"^style\\.css\">\nAllow from all\n</FilesMatch>\n",
		"filesmatch star":           "Deny from all\n<FilesMatch \"^a.*\\.css$\">\nAllow from all\n</FilesMatch>\n",
		"filesmatch any char":       "Deny from all\n<FilesMatch \"^a.css$\">\nAllow from all\n</FilesMatch>\n",
		"filesmatch caseless":       "Deny from all\n<FilesMatch \"(?i)^a\\.css$\">\nAllow from all\n</FilesMatch>\n",
		"files php":                 "Deny from all\n<Files index.php>\nAllow from all\n</Files>\n",
		"files no suffix":           "Deny from all\n<Files README>\nAllow from all\n</Files>\n",
		"files deny in open dir":    "<Files wp-config.php>\nOrder Allow,Deny\nDeny from all\n</Files>\n",
		"files in password dir":     auth + "Require valid-user\n<Files a.css>\nRequire all granted\n</Files>\n",
		"files partial open":        "Deny from all\n<Files a.css>\nOrder Deny,Allow\nDeny from all\nAllow from 192.0.2.1\n</Files>\n",
		"password in files":         "Deny from all\n<Files a.css>\nAuthType Basic\n</Files>\n",
		"auth without require":      auth + "Require all granted\n",
		"require user without auth": "Require valid-user\n",
		"authtype digest":           "AuthType Digest\nAuthName Staff\nAuthUserFile /home/u/.htdigest\nRequire valid-user\n",
		"relative user file":        "AuthType Basic\nAuthName Staff\nAuthUserFile .htpasswd\nRequire valid-user\n",
		"dbm provider":              auth + "AuthBasicProvider dbm\nRequire valid-user\n",
		"group file":                auth + "AuthGroupFile /home/u/.htgroup\nRequire valid-user\n",
		"authname quote":            "AuthType Basic\nAuthName 'it\"s'\nAuthUserFile /home/u/.htpasswd\nRequire valid-user\n",
		"authname brace":            "AuthType Basic\nAuthName \"a{b}\"\nAuthUserFile /home/u/.htpasswd\nRequire valid-user\n",
		"authmerging":               "AuthMerging And\nRequire all denied\n",
		"rewrite with deny":         "RewriteEngine On\nRewriteRule ^x$ /y [L]\nDeny from all\n",
		"header with deny":          "Header set X-A b\nDeny from all\n",
		"options indexes on":        "Options +Indexes\nDeny from all\n",
		"options execcgi":           "Options -ExecCGI\nDeny from all\n",
		"redirect 403":              "Redirect 403 /private/\n",
		"malformed":                 "<IfModule mod_authz_core.c>\nRequire all denied\n",
		"user name odd":             auth + "Require user b\\ob\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			got := convertText(t, "/private/", text)
			if got.Rule != nil || got.Refused == "" {
				t.Fatalf("converted: %+v", got.Rule)
			}
		})
	}
}

// The .htaccess of the Akismet plugin as WordPress 7.1.5 ships it
// (https://downloads.wordpress.org/release/wordpress-7.1.5.zip, sha1
// d7d004a092a4e8f2b28dc8f4089a11fea9a38807, the current release on
// 2026-11-24; wp-content/plugins/akismet/.htaccess, Akismet 5.7.2).
const akismetSHA256 = "63553e7f320285fe2417cdb00664a136958d70baa07d7325e86f0847f11dd17c"

func akismetHtaccess(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/akismet-5.7.2.htaccess")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != akismetSHA256 {
		t.Fatalf("testdata/akismet-5.7.2.htaccess is not the pinned file")
	}
	return data
}

func TestConvertAkismet(t *testing.T) {
	r := ClassifyFile("wp-content/plugins/akismet/.htaccess", "/wp-content/plugins/akismet/", akismetHtaccess(t))
	if !convertible(r) || r.Conversion == nil || r.Conversion.Rule == nil {
		t.Fatalf("not converted: verdict %s causes %v conversion %+v", r.Verdict, r.Causes, r.Conversion)
	}
	want := FolderRule{Path: "/wp-content/plugins/akismet/", Hosts: Hosts{Kind: HostsNone}, Allow: []string{
		"akismet-activation-banner-elements.png", "akismet-admin-rtl.css", "akismet-admin.css", "akismet-admin.js",
		"akismet-frontend.js", "akismet-refresh-logo.svg", "akismet-refresh-logo@2x.png", "akismet-rtl.css",
		"akismet.css", "akismet.js", "arrow-left.svg", "copy.svg", "form.js", "inter.css", "logo-a-2x.png",
	}}
	if !reflect.DeepEqual(*r.Conversion.Rule, want) {
		t.Fatalf("got %+v\nwant %+v", *r.Conversion.Rule, want)
	}
}

func siteOf(files map[string]string) SiteResult {
	site := SiteResult{Name: ".", Files: []FileResult{}}
	for path, text := range files {
		dir := strings.TrimSuffix(strings.TrimSuffix(path, ".htaccess"), "/")
		urlPath := "/"
		if dir != "" {
			urlPath = "/" + dir + "/"
		}
		site.Files = append(site.Files, ClassifyFile(path, urlPath, []byte(text)))
	}
	finishSite(&site)
	return site
}

func TestConvertSite(t *testing.T) {
	wordpress := wordpressBlock
	akismet := string(akismetHtaccess(t))
	password := "AuthType Basic\nAuthName Staff\nAuthUserFile /home/u/.htpasswd\nRequire valid-user\n"
	t.Run("wordpress with akismet and a password folder", func(t *testing.T) {
		got := ConvertSite(siteOf(map[string]string{".htaccess": wordpress, "wp-content/plugins/akismet/.htaccess": akismet, "members/.htaccess": password, "logs/.htaccess": "Options -Indexes\n"}))
		if !got.Native || len(got.Rules) != 2 || got.Rules[0].Path != "/members/" || got.Rules[1].Path != "/wp-content/plugins/akismet/" {
			t.Fatalf("%+v", got)
		}
	})
	refused := map[string]map[string]string{
		"root rule":           {".htaccess": "Deny from all\n"},
		"nested htaccess":     {"members/.htaccess": password, "members/sub/.htaccess": "RewriteEngine On\n"},
		"nested rule":         {"a/.htaccess": "Deny from all\n", "a/b/.htaccess": password},
		"unknown":             {"a/.htaccess": "Deny from all\nFoo bar\n"},
		"convertible headers": {"a/.htaccess": "Header set X-A b\n"},
		"refused conversion":  {"a/.htaccess": "Satisfy Any\n"},
	}
	for name, files := range refused {
		t.Run(name, func(t *testing.T) {
			got := ConvertSite(siteOf(files))
			if got.Native || len(got.Refused) == 0 || len(got.Rules) != 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
	t.Run("open rule does not shadow", func(t *testing.T) {
		got := ConvertSite(siteOf(map[string]string{"a/.htaccess": "Options -Indexes\n", "a/b/.htaccess": "RewriteEngine On\n"}))
		if !got.Native || len(got.Rules) != 0 {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("verdict without a file", func(t *testing.T) {
		if got := ConvertSite(SiteResult{Verdict: VerdictCompat, Causes: []string{CauseAccessControl}}); got.Native {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("rule names its file", func(t *testing.T) {
		got := ConvertSite(siteOf(map[string]string{"a/.htaccess": "Deny from all\n"}))
		if !got.Native || len(got.Rules) != 1 || got.Rules[0].File != "a/.htaccess" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("site causes", func(t *testing.T) {
		site := siteOf(map[string]string{"a/.htaccess": "Deny from all\n"})
		site.SymlinkedDirs = []string{"x"}
		finishSite(&site)
		if got := ConvertSite(site); got.Native {
			t.Fatalf("%+v", got)
		}
	})
}

func TestNormalizeUserFile(t *testing.T) {
	apr1 := "$apr1$x1Y2z3$abcdefghijklmnopqrstuv"
	sha := "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
	bcrypt := "$2y$05$" + strings.Repeat("a", 53)
	bcryptB := "$2b$12$" + strings.Repeat("b", 53)
	in := "# users\n\nalice:" + apr1 + "\r\nbob:" + sha + "\ncarol:" + bcrypt + "\ndave:" + bcryptB + "\n"
	out, users, err := NormalizeUserFile([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := "alice:" + apr1 + "\nbob:" + sha + "\ncarol:" + bcrypt + "\ndave:" + bcryptB + "\n"
	if string(out) != want || !reflect.DeepEqual(users, []string{"alice", "bob", "carol", "dave"}) {
		t.Fatalf("%q %v", out, users)
	}
	// Formats OpenLiteSpeed 1.9.4 compares as plain text first: the stored
	// text would sign in, so they refuse, naming the user.
	for name, hash := range map[string]string{
		"des crypt":    "kF2EDBE2Ux8sQ",
		"md5 crypt":    "$1$saltsalt$" + strings.Repeat("c", 22),
		"sha256 crypt": "$5$saltsalt$" + strings.Repeat("d", 43),
		"sha512 crypt": "$6$rounds=5000$saltsalt$" + strings.Repeat("e", 86),
		"bcrypt 2a":    "$2a$05$" + strings.Repeat("a", 53),
	} {
		_, _, err := NormalizeUserFile([]byte("alice:" + apr1 + "\nfrank:" + hash + "\n"))
		var bad *UserFileError
		if !errors.As(err, &bad) || bad.User != "frank" || bad.Line != 2 || !strings.Contains(bad.Reason, "older format") {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]string{
		"plain text":   "alice:secret\n",
		"bcrypt cost":  "alice:$2y$03$" + strings.Repeat("a", 53) + "\n",
		"third field":  "alice:" + apr1 + ":staff\n",
		"space":        "alice: " + apr1 + "\n",
		"twice":        "alice:" + apr1 + "\nalice:" + sha + "\n",
		"user name":    "al ice:" + apr1 + "\n",
		"no colon":     "alice\n",
		"empty":        "# none\n",
		"not text":     "alice:\xff\n",
		"empty hash":   "alice:\n",
		"short sha512": "alice:$6$salt$abc\n",
	}
	for name, text := range bad {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NormalizeUserFile([]byte(text)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, _, err := NormalizeUserFile([]byte(strings.Repeat("#", MaxUserFileBytes+1))); err == nil {
		t.Fatal("accepted an oversize file")
	}
}

// FuzzConvert feeds arbitrary .htaccess text through the classifier and the
// converter. It must not panic, and every rule it produces must hold only
// values the renderer can write: a valid folder path, canonical networks,
// static allow-list names, a printable realm name and an absolute user file.
func FuzzConvert(f *testing.F) {
	f.Add([]byte("Deny from all\n"), "/a/")
	f.Add([]byte("Require ip 192.0.2.0/24\n"), "/a/b/")
	f.Add([]byte("AuthType Basic\nAuthName x\nAuthUserFile /h\nRequire user a b\n"), "/p/")
	f.Add([]byte("Deny from all\n<FilesMatch \"^(a|b(-c)?)\\.css$\">\nAllow from all\n</FilesMatch>\n"), "/w/")
	f.Add([]byte("<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n"), "/z/")
	f.Fuzz(func(t *testing.T, data []byte, urlPath string) {
		if len(data) > 4096 {
			return
		}
		r := ClassifyFile(".htaccess", urlPath, data)
		if !convertible(r) {
			if r.Conversion != nil {
				t.Fatal("conversion for a file that is not compat for access control alone")
			}
			return
		}
		c := r.Conversion
		if c == nil || (c.Rule == nil) == (c.Refused == "") {
			t.Fatalf("conversion must be a rule or a refusal: %+v", c)
		}
		if c.Rule == nil {
			return
		}
		rule := c.Rule
		if !validRulePath(rule.Path) || rule.Path != urlPath {
			t.Fatalf("path %q", rule.Path)
		}
		switch rule.Hosts.Kind {
		case HostsAll, HostsNone:
			if len(rule.Hosts.Networks) != 0 {
				t.Fatalf("networks on %s", rule.Hosts.Kind)
			}
		case HostsOnly, HostsExcept:
			if len(rule.Hosts.Networks) == 0 || len(rule.Hosts.Networks) > MaxRuleNetworks {
				t.Fatalf("networks %v", rule.Hosts.Networks)
			}
			for _, n := range rule.Hosts.Networks {
				p, ok := parseApacheNet(n)
				if !ok || p.String() != n {
					t.Fatalf("network %q", n)
				}
			}
		default:
			t.Fatalf("kind %q", rule.Hosts.Kind)
		}
		if len(rule.Allow) > 0 && (rule.Hosts.Kind != HostsNone || rule.Realm != nil) {
			t.Fatal("allow-list outside a folder closed to everyone")
		}
		for _, name := range rule.Allow {
			if !allowName(name) {
				t.Fatalf("allow name %q", name)
			}
		}
		if rule.Realm != nil {
			if !realmNamePattern.MatchString(rule.Realm.Name) || !strings.HasPrefix(rule.Realm.UserFile, "/") {
				t.Fatalf("realm %+v", rule.Realm)
			}
			for _, u := range rule.Realm.Users {
				if !realmUserPattern.MatchString(u) {
					t.Fatalf("user %q", u)
				}
			}
		}
		// Fail closed: a file whose text says nothing that closes the folder
		// cannot come out closed, and a closing word cannot come out open.
		lower := strings.ToLower(string(data))
		closes := strings.Contains(lower, "deny") || strings.Contains(lower, "require") || strings.Contains(lower, "order")
		if !rule.Open() && !closes {
			t.Fatalf("closed rule from text without deny, order or require: %q", data)
		}
	})
}

func FuzzNormalizeUserFile(f *testing.F) {
	f.Add([]byte("alice:$apr1$x1Y2z3$abcdefghijklmnopqrstuv\n"))
	f.Add([]byte("bob:secret\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		out, users, err := NormalizeUserFile(data)
		if err != nil {
			return
		}
		again, users2, err := NormalizeUserFile(out)
		if err != nil || string(again) != string(out) || !reflect.DeepEqual(users, users2) {
			t.Fatalf("not stable: %q", out)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			if strings.Count(line, ":") != 1 || strings.ContainsAny(line, " \t\r#") {
				t.Fatalf("line %q", line)
			}
		}
	})
}

// TestRewriteIntoProtectedFolders: a rewrite whose result is a URL path is
// checked again by OpenLiteSpeed in the target's context, so a site keeps
// its converted folders; one whose result the request or a file path could
// choose refuses the site, because OpenLiteSpeed would look it up by file
// location and skip the folder's regex context.
func TestRewriteIntoProtectedFolders(t *testing.T) {
	closed := "Deny from all\n"
	ok := map[string]string{
		"wordpress":          wordpressBlock,
		"url path":           "RewriteEngine On\nRewriteRule ^pub/(.*)$ /private/$1 [L]\n",
		"relative url path":  "RewriteEngine On\nRewriteRule ^pub/(.*)$ private/$1 [L]\n",
		"external redirect":  "RewriteEngine On\nRewriteRule ^(.*)$ https://example.com/$1 [R=301,L]\n",
		"flag redirect":      "RewriteEngine On\nRewriteRule ^old/(.*)$ /$1 [R,L]\n",
		"no substitution":    "RewriteEngine On\nRewriteRule \\.bak$ - [F,L]\n",
		"base equals folder": "RewriteEngine On\nRewriteBase /\nRewriteRule . /index.php [L]\n",
	}
	for name, root := range ok {
		t.Run("keeps "+name, func(t *testing.T) {
			if got := ConvertSite(siteOf(map[string]string{".htaccess": root, "private/.htaccess": closed})); !got.Native || len(got.Rules) != 1 {
				t.Fatalf("%+v", got)
			}
		})
	}
	refused := map[string]string{
		"back-reference":      "RewriteEngine On\nRewriteRule ^go/(.*)$ /$1 [L]\n",
		"bare back-reference": "RewriteEngine On\nRewriteRule ^go/(.*)$ $1 [L]\n",
		"variable":            "RewriteEngine On\nRewriteRule ^go$ %{REQUEST_URI} [L]\n",
		"server variable":     "RewriteEngine On\nRewriteRule ^go$ %{DOCUMENT_ROOT}/private/x [L]\n",
		"file path":           "RewriteEngine On\nRewriteRule ^go$ /home/u/public_html/private/x [L]\n",
		"relative home":       "RewriteEngine On\nRewriteRule ^go$ home/u/public_html/private/x [L]\n",
		"variable in part":    "RewriteEngine On\nRewriteRule ^go/(.*)$ /ho$1/x [L]\n",
		"rewrite base home":   "RewriteEngine On\nRewriteBase /home/u/public_html/\nRewriteRule ^go$ private/x [L]\n",
	}
	for name, root := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			got := ConvertSite(siteOf(map[string]string{".htaccess": root, "private/.htaccess": closed}))
			rewrite := slices.ContainsFunc(got.Refused, func(r FileRefusal) bool {
				return r.File == ".htaccess" && r.Line > 0 && strings.Contains(r.Reason, "rewrite rule")
			})
			if got.Native || !rewrite {
				t.Fatalf("%+v", got)
			}
			// Without a converted folder the rule is not this check's concern.
			alone := ConvertSite(siteOf(map[string]string{".htaccess": root}))
			if slices.ContainsFunc(alone.Refused, func(r FileRefusal) bool { return strings.Contains(r.Reason, "rewrite rule") }) {
				t.Fatalf("a site without folders: %+v", alone)
			}
		})
	}
}
