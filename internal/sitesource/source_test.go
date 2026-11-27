package sitesource

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const apacheVhosts = `# Plesk and bare servers keep one file per site.
<VirtualHost *:80>
    ServerName example.com:80
    ServerAlias www.example.com shop.example.net
    DocumentRoot /var/www/vhosts/example.com/httpdocs
    SuexecUserGroup exampleuser psacln
    ErrorLog /var/log/httpd/example-error.log
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php-fpm/php8.1-fpm-example.sock|fcgi://localhost"
    </FilesMatch>
    <Directory /var/www/vhosts/example.com/httpdocs>
        AllowOverride All
        Options -Indexes +FollowSymLinks
        Require all granted
    </Directory>
    php_admin_value open_basedir /var/www/vhosts/example.com
</VirtualHost>
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName example.org
    DocumentRoot /home/admin/web/example.org/public_html
    SSLEngine on
    SSLCertificateFile /home/admin/conf/web/ssl.example.org.crt
    SSLCertificateKeyFile /home/admin/conf/web/ssl.example.org.key
    <Directory /home/admin/web/example.org/public_html/private>
        Require ip 192.0.2.0/24
    </Directory>
    ProxyPass /app http://127.0.0.1:8080/
</VirtualHost>
</IfModule>
`

func TestApacheVirtualHostsAreRead(t *testing.T) {
	sites, err := ParseApache("httpd/conf.d/example.conf", []byte(apacheVhosts))
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 {
		t.Fatalf("sites = %d", len(sites))
	}
	a := sites[0]
	if !slices.Equal(a.Names, []string{"example.com", "www.example.com", "shop.example.net"}) || a.Root != "/var/www/vhosts/example.com/httpdocs" || a.User != "exampleuser" || a.PHPSource != "php8.1-fpm" || a.Line != 2 {
		t.Fatalf("first site = %+v", a)
	}
	if len(a.Refused) != 0 || len(a.Notes) != 1 || !strings.Contains(a.Notes[0].Text, "open_basedir") {
		t.Fatalf("first site's lines: %+v %+v", a.Refused, a.Notes)
	}
	b := sites[1]
	if b.TLS == nil || b.TLS.Key != "/home/admin/conf/web/ssl.example.org.key" || b.Root != "/home/admin/web/example.org/public_html" {
		t.Fatalf("second site = %+v", b)
	}
	refused := items(b.Refused)
	for _, w := range []string{"line 26: Require", "line 28: ProxyPass"} {
		if !strings.Contains(refused, w) {
			t.Errorf("refusals lack %q:\n%s", w, refused)
		}
	}
	if _, err := ParseApache("x.conf", []byte("<VirtualHost *:80>\nServerName a.example.com\n")); !errors.Is(err, ErrNginx) {
		t.Fatalf("an unclosed section: %v", err)
	}
}

func TestWPConfigNamesTheDatabase(t *testing.T) {
	text := `<?php
// define( 'DB_NAME', 'commented_out' );
/* define( 'DB_USER', 'old' ); */
define( 'DB_NAME', 'wordpress' );
define( "DB_USER", "wp_user" );
define( 'DB_PASSWORD', 'it\'s-a-test' );
define( 'DB_HOST', 'localhost:3306' );
define( 'DB_NAME', 'second_define_is_ignored' );
$table_prefix = 'wpx_';
`
	c, err := ParseWPConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "wordpress" || c.User != "wp_user" || c.Password != "it's-a-test" || c.Host != "localhost:3306" || c.Prefix != "wpx_" || !c.LocalDatabase() {
		t.Fatalf("config = %+v", c)
	}
	// SHA1(SHA1("it's-a-test")), as MariaDB's PASSWORD() makes it.
	if h := c.NativeHash(); len(h) != 41 || h[0] != '*' || strings.ToUpper(h) != h {
		t.Fatalf("hash = %q", h)
	}
	for name, text := range map[string]string{
		"from the environment": "<?php define('DB_NAME', getenv('DB_NAME')); define('DB_USER', 'u'); define('DB_PASSWORD', 'p');",
		"interpolated":         `<?php define('DB_NAME', "site_$x"); define('DB_USER', 'u'); define('DB_PASSWORD', 'p');`,
		"no user":              "<?php define('DB_NAME', 'n'); define('DB_PASSWORD', 'p');",
		"too big":              "<?php " + strings.Repeat(" ", maxWPConfig),
	} {
		if _, err := ParseWPConfig([]byte(text)); !errors.Is(err, ErrWPConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	remote := WPConfig{Host: "db.example.com"}
	if remote.LocalDatabase() {
		t.Fatal("a database on another server is not local")
	}
}

// The hash is MariaDB's: PASSWORD('example') is this value.
func TestNativeHashIsMariaDBs(t *testing.T) {
	if h := (WPConfig{Password: "example"}).NativeHash(); h != "*57237BB49761F29AB9724BA084E811D70C12393D" {
		t.Fatalf("hash = %s", h)
	}
}
