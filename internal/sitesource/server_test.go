package sitesource

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/htaccess"
)

// nginxDump is nginx -T on a plain nginx server: the main file with its
// default server, a WordPress site with its http-to-https block, a site
// that proxies to an application, and a stock include.
const nginxDump = `nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# configuration file /etc/nginx/nginx.conf:
user nginx;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    server {
        listen 80 default_server;
        server_name _;
        root /usr/share/nginx/html;
    }
}

# configuration file /etc/nginx/mime.types:
types {
    text/html html htm;
}

# configuration file /etc/nginx/conf.d/blog.conf:
server {
    listen 80;
    server_name www.blog.example.com blog.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    server_name blog.example.com www.blog.example.com;
    root /var/www/blog/;
    index index.php;
    ssl_certificate /etc/letsencrypt/live/blog.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/blog.example.com/privkey.pem;
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php-fpm/www.sock;
        include fastcgi_params;
    }
    location /private/ {
        deny all;
    }
    location = /old-page {
        return 301 https://blog.example.com/new-page;
    }
}

# configuration file /etc/nginx/conf.d/app.conf:
server {
    listen 80;
    server_name app.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
`

func dumpSites(t *testing.T) []ServerSite {
	t.Helper()
	files, err := ParseNginxDump([]byte(nginxDump))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 || files[2].Name != "/etc/nginx/conf.d/blog.conf" {
		t.Fatalf("files = %d", len(files))
	}
	return ServerSites(files, nil)
}

func TestNginxDumpGivesOneSitePerDomain(t *testing.T) {
	sites := dumpSites(t)
	if len(sites) != 2 || sites[0].Domain != "app.example.com" || sites[1].Domain != "blog.example.com" {
		t.Fatalf("sites = %+v", sites)
	}
	blog := sites[1]
	if !blog.WWW || len(blog.Aliases) != 0 || blog.DocRoot != "/var/www/blog" || blog.Where != "/etc/nginx/conf.d/blog.conf line 6" || blog.Server != "nginx" {
		t.Fatalf("blog = %+v", blog)
	}
	if !blog.Movable() || blog.TLS == nil || blog.TLS.Key != "/etc/letsencrypt/live/blog.example.com/privkey.pem" || blog.PHPPass != "unix:/run/php-fpm/www.sock" {
		t.Fatalf("blog = %+v", blog)
	}
	if !strings.Contains(items(blog.Notes), "sent every http request to https") {
		t.Fatalf("the https block's note is missing: %s", items(blog.Notes))
	}
	root := blog.Htaccess[""]
	for _, want := range []string{"# Moved by Sifruno from nginx: /etc/nginx/conf.d/blog.conf line 6\n", "RedirectMatch 301 ^/old-page$ https://blog.example.com/new-page\n", "RewriteRule ^ /index.php [L]\n"} {
		if !strings.Contains(root, want) {
			t.Errorf("root .htaccess lacks %q:\n%s", want, root)
		}
	}
	if !strings.HasSuffix(blog.Htaccess["private"], "\nRequire all denied\n") || len(blog.Htaccess) != 2 {
		t.Fatalf("htaccess files = %v", blog.Htaccess)
	}
	app := sites[0]
	if app.Movable() || app.DocRoot != "" || !strings.Contains(items(app.Refused), "app.conf line 5: proxy_pass") {
		t.Fatalf("app = %+v", app)
	}
}

func TestBlocksThatDifferRefuseTheSite(t *testing.T) {
	files, err := ParseNginxDump([]byte("# configuration file /etc/nginx/conf.d/x.conf:\n" +
		"server { listen 80; server_name shop.example.com; root /var/www/shop; }\n" +
		"server { listen 443 ssl; server_name shop.example.com; root /var/www/other; }\n"))
	if err != nil {
		t.Fatal(err)
	}
	sites := ServerSites(files, nil)
	if len(sites) != 1 || sites[0].Movable() || !strings.Contains(items(sites[0].Refused), "x.conf line 2: Another block for shop.example.com") {
		t.Fatalf("sites = %+v", sites)
	}
}

func TestBothWebServersNamingADomainIsRefused(t *testing.T) {
	files, err := ParseNginxDump([]byte("# configuration file /etc/nginx/conf.d/x.conf:\nserver { server_name shop.example.com; root /var/www/shop; }\n"))
	if err != nil {
		t.Fatal(err)
	}
	apache, err := ParseApache("/etc/httpd/conf.d/shop.conf", []byte("<VirtualHost *:8080>\nServerName shop.example.com\nDocumentRoot /var/www/shop\n</VirtualHost>\n"))
	if err != nil {
		t.Fatal(err)
	}
	sites := ServerSites(files, apache)
	if len(sites) != 1 || sites[0].Movable() || !strings.Contains(items(sites[0].Refused), "Both nginx (/etc/nginx/conf.d/x.conf line 1) and Apache (/etc/httpd/conf.d/shop.conf line 1) name shop.example.com") {
		t.Fatalf("sites = %+v", sites)
	}
}

func TestADocumentRootOutsideTheWebFoldersIsRefused(t *testing.T) {
	for _, root := range []string{"/", "/etc", "/root/site", "/var/lib/mysql", "/var/www", "/home", "/var/www/a b", "/var/www/../etc", "/var/www/$x"} {
		if ValidDocRoot(root) {
			t.Errorf("%q is accepted", root)
		}
	}
	for _, root := range []string{"/var/www/html", "/home/shop/public_html", "/srv/www/site", "/usr/share/nginx/html", "/var/www/vhosts/example.com/httpdocs"} {
		if !ValidDocRoot(root) {
			t.Errorf("%q is refused", root)
		}
	}
	apache, err := ParseApache("/etc/httpd/conf.d/x.conf", []byte("<VirtualHost *:80>\nServerName x.example.com\nDocumentRoot /etc\n</VirtualHost>\n"))
	if err != nil {
		t.Fatal(err)
	}
	sites := ServerSites(nil, apache)
	if len(sites) != 1 || sites[0].Movable() || !strings.Contains(items(sites[0].Refused), "is not below /var/www") {
		t.Fatalf("sites = %+v", sites)
	}
}

// httpdS is httpd -S on AlmaLinux 9 with two name-based sites.
const httpdS = `AH00558: httpd: Could not reliably determine the server's fully qualified domain name
VirtualHost configuration:
*:80                   is a NameVirtualHost
         default server wp.example.com (/etc/httpd/conf.d/wp.conf:1)
         port 80 namevhost wp.example.com (/etc/httpd/conf.d/wp.conf:1)
                 alias www.wp.example.com
         port 80 namevhost plain.example.com (/etc/httpd/conf.d/plain.conf:1)
*:443                  wp.example.com (/etc/httpd/conf.d/wp-ssl.conf:2)
ServerRoot: "/etc/httpd"
Main DocumentRoot: "/var/www/html"
Main ErrorLog: "/etc/httpd/logs/error_log"
`

func TestApacheVhostFilesAreListedOnce(t *testing.T) {
	files, err := ApacheFiles([]byte(httpdS))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(files, []string{"/etc/httpd/conf.d/wp.conf", "/etc/httpd/conf.d/plain.conf", "/etc/httpd/conf.d/wp-ssl.conf"}) {
		t.Fatalf("files = %v", files)
	}
	for _, f := range files {
		if _, err := ConfigFileCommand(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	for _, bad := range []string{"/etc/shadow", "/home/user/conf/web/x.conf", "/etc/httpd/../shadow", "/etc/httpd/conf.d/a b.conf", "/etc/httpd/conf.d/$(id).conf"} {
		if _, err := ConfigFileCommand(bad); err == nil {
			t.Errorf("%q is read", bad)
		}
	}
}

func TestApacheSitesMergeTheirTLSBlock(t *testing.T) {
	plain, err := ParseApache("/etc/httpd/conf.d/wp.conf", []byte("<VirtualHost *:80>\nServerName wp.example.com\nServerAlias www.wp.example.com\nDocumentRoot \"/var/www/wp/\"\n<Directory /var/www/wp>\nAllowOverride All\nRequire all granted\n</Directory>\n</VirtualHost>\n"))
	if err != nil {
		t.Fatal(err)
	}
	tls, err := ParseApache("/etc/httpd/conf.d/wp-ssl.conf", []byte("\n<VirtualHost *:443>\nServerName wp.example.com\nDocumentRoot /var/www/wp\nSSLEngine on\nSSLCertificateFile /etc/pki/tls/certs/wp.crt\nSSLCertificateKeyFile /etc/pki/tls/private/wp.key\n</VirtualHost>\n"))
	if err != nil {
		t.Fatal(err)
	}
	sites := ServerSites(nil, append(plain, tls...))
	if len(sites) != 1 {
		t.Fatalf("sites = %+v", sites)
	}
	s := sites[0]
	if !s.Movable() || !s.WWW || s.DocRoot != "/var/www/wp" || s.TLS == nil || s.TLS.Certificate != "/etc/pki/tls/certs/wp.crt" || s.Server != "apache" {
		t.Fatalf("site = %+v", s)
	}
}

func TestPHPComesFromThePoolOrTheOnlyVersion(t *testing.T) {
	pools := ParseFPMPools([]byte("== /etc/php-fpm.d/www.conf\nlisten = /run/php-fpm/www.sock\n== /etc/php/8.2/fpm/pool.d/shop.conf\nlisten = \"/run/php/shop.sock\"\n== /etc/opt/remi/php74/php-fpm.d/old.conf\n  listen = 127.0.0.1:9074\n"))
	if len(pools) != 3 || pools[1].Version != "8.2" || pools[1].Listen[0] != "/run/php/shop.sock" || pools[2].Version != "7.4" || pools[0].Version != "" {
		t.Fatalf("pools = %+v", pools)
	}
	versions := ParseFPMVersions([]byte("== /usr/sbin/php-fpm PHP 8.0.30 (fpm-fcgi) (built: Aug  3 2023 17:13:08)\n== /opt/remi/php74/root/usr/sbin/php-fpm \n"))
	if versions["/usr/sbin/php-fpm"] != "8.0" || versions["/opt/remi/php74/root/usr/sbin/php-fpm"] != "7.4" {
		t.Fatalf("versions = %v", versions)
	}
	for pass, want := range map[string]string{
		"unix:/run/php-fpm/www.sock":                       "php8.0-fpm",
		`"proxy:unix:/run/php/shop.sock|fcgi://localhost"`: "php8.2-fpm",
		"proxy:fcgi://127.0.0.1:9074":                      "php7.4-fpm",
		"127.0.0.1:9074":                                   "php7.4-fpm",
		"unix:/run/other.sock":                             "",
	} {
		s := ServerSite{PHPPass: pass}
		s.ResolvePHP(pools, versions)
		if s.PHPSource != want {
			t.Errorf("%s: %q, want %q", pass, s.PHPSource, want)
		}
	}
	only := ServerSite{Server: "apache"}
	only.ResolvePHP(nil, map[string]string{"/usr/sbin/php-fpm": "8.3"})
	if only.PHPSource != "php8.3-fpm" || !strings.Contains(items(only.Notes), "runs PHP 8.3 only") || only.Notes[0].Part != "info" {
		t.Fatalf("only = %+v", only)
	}
	// An nginx block without fastcgi_pass runs no PHP.
	static := ServerSite{Server: "nginx"}
	static.ResolvePHP(nil, map[string]string{"/usr/sbin/php-fpm": "8.3"})
	if static.PHPSource != "" || len(static.Notes) != 0 {
		t.Fatalf("static = %+v", static)
	}
	for source, want := range map[string]string{"php8.2-fpm": "8.2 true", "php8.0-fpm": "8.1 false", "php7.4-fpm": "8.1 false", "php9.0-fpm": "8.4 false", "": "8.3 false"} {
		v, exact := PHPVersion(source)
		if got := v + " " + map[bool]string{true: "true", false: "false"}[exact]; got != want {
			t.Errorf("%q: %s, want %s", source, got, want)
		}
	}
}

func TestStatNamesTheOwner(t *testing.T) {
	if c, _ := StatCommand("/var/www/wp"); c != "/usr/bin/stat -c '%n|%F|%U|%u|%a' -- /var /var/www /var/www/wp" {
		t.Fatalf("stat command = %q", c)
	}
	const parents = "/var|directory|root|0|755\n/var/www|directory|root|0|755\n"
	o, err := ParsePath([]byte(parents+"/var/www/wp|directory|www-data|33|2775\n"), "/var/www/wp")
	if err != nil || o.Name != "www-data" || o.UID != 33 {
		t.Fatalf("%+v %v", o, err)
	}
	// A home folder the site's own user holds is on the way to its root.
	home := "/home|directory|root|0|755\n/home/alice|directory|alice|1001|711\n/home/alice/public_html|directory|alice|1001|750\n"
	if o, err := ParsePath([]byte(home), "/home/alice/public_html"); err != nil || o.Name != "alice" {
		t.Fatalf("a home folder: %+v %v", o, err)
	}
	// A link anywhere on the way is refused, not only at the end: stat
	// would follow /var/www/x to wherever it points.
	for _, link := range []string{
		parents + "/var/www/wp|symbolic link|root|0|777\n",
		"/var|directory|root|0|755\n/var/www|symbolic link|root|0|777\n/var/www/wp|directory|root|0|755\n",
	} {
		if _, err := ParsePath([]byte(link), "/var/www/wp"); !errors.Is(err, ErrNotFolder) {
			t.Errorf("a link on the way: %v", err)
		}
	}
	// A folder on the way that another user could swap for a link: root's
	// with group or other write, another user's, or the user's own on the
	// way to a root-owned root (the user could lead root anywhere).
	for _, c := range []struct{ out, root, folder string }{
		{"/var|directory|root|0|755\n/var/www|directory|root|0|777\n/var/www/wp|directory|apache|48|755\n", "/var/www/wp", "/var/www"},
		{"/var|directory|root|0|755\n/var/www|directory|root|0|775\n/var/www/wp|directory|apache|48|755\n", "/var/www/wp", "/var/www"},
		{"/var|directory|root|0|755\n/var/www|directory|bob|1002|755\n/var/www/wp|directory|apache|48|755\n", "/var/www/wp", "/var/www"},
		{"/home|directory|root|0|755\n/home/alice|directory|alice|1001|711\n/home/alice/etc|directory|root|0|755\n", "/home/alice/etc", "/home/alice"},
	} {
		var changeable *PathError
		if _, err := ParsePath([]byte(c.out), c.root); !errors.As(err, &changeable) || changeable.Folder != c.folder {
			t.Errorf("%q: %v", c.out, err)
		}
	}
	for _, bad := range []string{
		parents + "/var/www/wp|directory|UNKNOWN user|1001|755\n",
		parents + "/var/www/wp|directory|root|5|755\n",
		parents + "/var/www/wp|directory|alice|-1|755\n",
		parents + "/var/www/wp|directory|alice|1001|755",
		parents + "/var/www/wp|directory|alice|1001\n",
		parents + "/var/www/wp|directory|alice|1001|9z\n",
		parents + "/var/www/other|directory|alice|1001|755\n",
		"/var/www/wp|directory|alice|1001|755\n",
	} {
		if _, err := ParsePath([]byte(bad), "/var/www/wp"); err == nil {
			t.Errorf("%q is read", bad)
		}
	}
	if c, _ := RootTreeCommand("/var/www/wp"); c != `/usr/bin/find -P /var/www/wp -xdev \( ! -uid 0 -o -type d \( -perm -0002 -o -perm -0020 \) \) -print -quit` {
		t.Fatalf("root tree command = %q", c)
	}
	if _, err := RootTreeCommand("/etc"); err == nil {
		t.Fatal("a folder outside the web roots is walked")
	}
	if c, _ := WPConfigCommand("/var/www/wp", Owner{Name: "apache", UID: 48}); c != "/usr/sbin/runuser -u apache -- /usr/bin/head -c 262145 -- /var/www/wp/wp-config.php" {
		t.Fatalf("wp-config command = %q", c)
	}
	if c, _ := WPConfigCommand("/var/www/wp", Owner{Name: "root", UID: 0}); c != "/usr/bin/head -c 262145 -- /var/www/wp/wp-config.php" {
		t.Fatalf("root's wp-config command = %q", c)
	}
	if _, err := CrontabCommand(Owner{Name: "root", UID: 0}); err == nil {
		t.Fatal("root's crontab is read for a site")
	}
	if n, err := ParseDiskMiB([]byte("42\t/var/www/wp\n")); err != nil || n != 42 {
		t.Fatalf("du = %d %v", n, err)
	}
}

func TestNamesHere(t *testing.T) {
	cases := []struct {
		owner  Owner
		domain string
		want   string
	}{
		{Owner{"alice", 1001}, "blog.example.com", "alice"},
		{Owner{"apache", 48}, "wp.example.com", "wpsite"},
		{Owner{"www-data", 33}, "www.my-shop.example.com", "myshop"},
		{Owner{"root", 0}, "1.example.com", "site1"},
		{Owner{"Alice", 1001}, "averyveryverylongname.example.com", "averyveryverylon"},
	}
	for _, c := range cases {
		if got := AccountName(c.owner, c.domain); got != c.want {
			t.Errorf("%+v %s: %q, want %q", c.owner, c.domain, got, c.want)
		}
	}
	for _, c := range []struct{ name, want string }{{"wordpress", "wp_wordpress"}, {"wp_site", "wp_site"}, {"my-db", "wp_my_db"}} {
		if got, ok := HereName("wp", c.name, 64); !ok || got != c.want {
			t.Errorf("%s: %q", c.name, got)
		}
	}
	if _, ok := HereName("wp", strings.Repeat("u", 46), 47); ok {
		t.Error("a name past the limit is accepted")
	}
}

func TestWPConfigIsPointedAtTheDatabaseHere(t *testing.T) {
	in := "<?php\n// define('DB_NAME', 'commented');\ndefine( 'DB_NAME', 'wordpress' );\ndefine('DB_USER', \"wpuser\");\ndefine('DB_PASSWORD', 'p@ss\\'word');\n/* define('DB_HOST', 'x'); */\ndefine('DB_HOST', '127.0.0.1:3306');\ndefine('DB_NAME', 'second');\n$table_prefix = 'wp_';\n"
	out, err := RewriteWPConfig([]byte(in), "wp_wordpress", "wp_wpuser")
	if err != nil {
		t.Fatal(err)
	}
	want := "<?php\n// define('DB_NAME', 'commented');\ndefine( 'DB_NAME', 'wp_wordpress' );\ndefine('DB_USER', 'wp_wpuser');\ndefine('DB_PASSWORD', 'p@ss\\'word');\n/* define('DB_HOST', 'x'); */\ndefine('DB_HOST', 'localhost');\ndefine('DB_NAME', 'second');\n$table_prefix = 'wp_';\n"
	if string(out) != want {
		t.Fatalf("got:\n%s", out)
	}
	c, err := ParseWPConfig(out)
	if err != nil || c.Name != "wp_wordpress" || c.User != "wp_wpuser" || c.Password != "p@ss'word" || !c.LocalDatabase() {
		t.Fatalf("read back: %+v %v", c, err)
	}
	if _, err := RewriteWPConfig([]byte(in), "bad name", "u"); err == nil {
		t.Fatal("a name with a space is written")
	}
	if _, err := RewriteWPConfig([]byte("<?php define('DB_NAME', getenv('X'));"), "a", "b"); !errors.Is(err, ErrWPConfig) {
		t.Fatalf("an expression: %v", err)
	}
}

// The .htaccess files an nginx site's rules become are ones the copy's own
// scan converts: OpenLiteSpeed acts on all of them, the closed folder
// becomes a protected folder, and the redirect moves into the vhost.
func TestNginxRulesConvertAsTheCopyConvertsThem(t *testing.T) {
	blog := dumpSites(t)[1]
	dir := t.TempDir()
	for folder, text := range blog.Htaccess {
		at := filepath.Join(dir, folder)
		if err := os.MkdirAll(at, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(at, ".htaccess"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report, err := htaccess.Scan(dir, htaccess.LayoutSingle, htaccess.DefaultLimits())
	if err != nil || len(report.Sites) != 1 {
		t.Fatalf("scan: %v %+v", err, report)
	}
	conv := htaccess.ConvertSite(report.Sites[0])
	if !conv.Native || len(conv.Refused) != 0 {
		t.Fatalf("not native: %+v", conv)
	}
	if len(conv.Rules) != 1 || conv.Rules[0].Path != "/private/" || len(conv.Redirects) != 1 || conv.Redirects[0].Pattern != "^/old-page$" || conv.Redirects[0].Status != 301 {
		t.Fatalf("conversion = %+v", conv)
	}
}
