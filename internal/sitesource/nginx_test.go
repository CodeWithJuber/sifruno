package sitesource

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/sitemodel"
)

const wordpressServer = `# A WordPress site on a plain nginx server.
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    root /var/www/example.com/public;
    index index.php index.html;
    access_log /var/log/nginx/example.access.log;
    client_max_body_size 64m;

    rewrite ^/blog/(.*)$ /news/$1 permanent;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param PHP_VALUE "upload_max_filesize=64M \n post_max_size=64M";
    }
    location ~ /\.ht {
        deny all;
    }
    location ~ /\.(?!well-known) {
        deny all;
    }
    location = /old-page {
        return 301 https://example.com/new-page;
    }
    location = /moved {
        return 302 /elsewhere;
    }
    location /private/ {
        deny all;
    }
    location /hidden/ {
        return 404;
    }
    location /shop/ {
        rewrite ^/shop/item/([0-9]+)$ /shop/index.php?item=$1 last;
    }
    location ~* \.(css|js|png)$ {
        expires 30d;
        add_header Cache-Control "public";
    }
}
`

func servers(t *testing.T, text string) []Server {
	t.Helper()
	f, err := ParseNginx("sites-enabled/example.com", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return f.Servers()
}

func TestNginxWordPressServerConverts(t *testing.T) {
	list := servers(t, wordpressServer)
	if len(list) != 1 {
		t.Fatalf("servers = %d", len(list))
	}
	s := list[0]
	if !slices.Equal(s.Names, []string{"example.com", "www.example.com"}) || s.Root != "/var/www/example.com/public" || s.Line != 2 {
		t.Fatalf("server = %+v", s)
	}
	c := ConvertNginx(s)
	want := []string{
		"RewriteEngine On",
		"RewriteRule ^blog/(.*)$ /news/$1 [R=301,L]",
		"RewriteRule (^|/)\\.ht - [F,L]",
		"RewriteRule (^|/)\\.(?!well-known) - [F,L]",
		"RewriteRule ^moved$ /elsewhere [R=302,L]",
		"RewriteCond %{REQUEST_URI} ^/shop/",
		"RewriteRule ^shop/item/([0-9]+)$ /shop/index.php?item=$1 [L,QSA]",
		"RewriteCond %{REQUEST_FILENAME} !-f",
		"RewriteCond %{REQUEST_FILENAME} !-d",
		"RewriteRule ^ /index.php [L]",
	}
	if strings.Join(c.Rewrites, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rewrites:\n%s\nwant:\n%s", strings.Join(c.Rewrites, "\n"), strings.Join(want, "\n"))
	}
	if !slices.Equal(c.Redirects, []sitemodel.Redirect{{Path: "/old-page", Target: "https://example.com/new-page", Status: 301}}) {
		t.Fatalf("redirects = %+v", c.Redirects)
	}
	if !slices.Equal(c.Folders, []string{"/private/", "/hidden/"}) {
		t.Fatalf("closed folders = %v", c.Folders)
	}
	if !c.PHP || c.PHPSource != "php8.2-fpm" {
		t.Fatalf("php = %v %q", c.PHP, c.PHPSource)
	}
	if len(c.Refused) != 0 {
		t.Fatalf("refused: %+v", c.Refused)
	}
	var site sitemodel.Site
	c.Apply(&site)
	if !site.Rules.Native || len(site.PHP.Settings) != 2 || site.PHP.Settings[0].Name != "upload_max_filesize" || site.PHP.Settings[0].From != "sites-enabled/example.com line 19" {
		t.Fatalf("site = %+v", site)
	}
	notes := items(site.NotCarried)
	for _, w := range []string{
		"line 9: client_max_body_size",
		"line 37: The folder /hidden/ answered 404 there; here it is closed and answers 403.",
		"line 43: expires",
		"line 44: add_header",
	} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
}

func items(list []sitemodel.Item) string {
	var lines []string
	for _, i := range list {
		lines = append(lines, i.Where+": "+i.Text)
	}
	return strings.Join(lines, "\n")
}

func TestNginxRefusesWhatOpenLiteSpeedCannotDoNamingTheLine(t *testing.T) {
	text := `server {
    server_name example.com;
    root /srv/site;
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
    }
    location /files/ {
        alias /srv/files/;
    }
    if ($http_user_agent ~ bot) {
        return 403;
    }
    location /staff/ {
        auth_basic "Staff";
        auth_basic_user_file /etc/nginx/htpasswd;
    }
    location @fallback {
        rewrite ^ /index.php;
    }
    location /a/ {
        location /a/b/ {
            deny all;
        }
    }
    rewrite /loose/(.*) /x/$1;
    rewrite ^/scheme$ $scheme://example.com/ permanent;
    location ~ \.txt$ {
        add_header X-Thing 1;
    }
    location /office/ {
        allow 192.0.2.0/24;
        deny all;
    }
    return 444;
    frobnicate on;
}
`
	c := ConvertNginx(servers(t, text)[0])
	refused := items(c.Refused)
	for _, w := range []string{
		"line 5: proxy_pass",
		"line 8: alias",
		"line 10: if",
		"line 14: auth_basic",
		"line 17: location @fallback",
		"line 21: location",
		"line 25: rewrite",
		"line 26: rewrite",
		"line 31: allow",
		"line 34: return",
		"line 35: frobnicate",
	} {
		if !strings.Contains(refused, w) {
			t.Errorf("refusals lack %q:\n%s", w, refused)
		}
	}
	var site sitemodel.Site
	c.Apply(&site)
	if site.Rules.Native {
		t.Fatal("a site with refused lines is Native")
	}
}

func TestNginxHTTPSRedirectAndSeveralServers(t *testing.T) {
	text := `http {
  server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
  }
  server {
    listen 443 ssl http2;
    server_name example.com www.example.com;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    root /home/site/public_html;
    location / { try_files $uri $uri/ =404; }
    location ~ \.php$ { fastcgi_pass 127.0.0.1:9000; include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }
  }
}
`
	list := servers(t, text)
	if len(list) != 2 {
		t.Fatalf("servers = %d", len(list))
	}
	first := ConvertNginx(list[0])
	if !first.HTTPSRedirect || len(first.Refused) != 0 {
		t.Fatalf("the http server: %+v", first)
	}
	second := ConvertNginx(list[1])
	if second.HTTPSRedirect || len(second.Refused) != 0 || !second.PHP || second.Rewrites != nil || second.TLS == nil || second.TLS.Certificate != "/etc/letsencrypt/live/example.com/fullchain.pem" {
		t.Fatalf("the https server: %+v %+v", second, second.TLS)
	}
}

func TestNginxParserRefusesBrokenFiles(t *testing.T) {
	for name, text := range map[string]string{
		"open block":     "server {\n  listen 80;\n",
		"stray close":    "listen 80;\n}\n",
		"open quote":     "server { server_name \"example.com; }\n",
		"no semicolon":   "server { listen 80 }\n",
		"deep":           strings.Repeat("a {\n", 40) + strings.Repeat("}\n", 40),
		"nul":            "server { listen 80\x00; }\n",
		"block no name":  "{ }\n",
		"semicolon only": ";\n",
	} {
		if _, err := ParseNginx("x.conf", []byte(text)); !errors.Is(err, ErrNginx) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := ParseNginx("x.conf", make([]byte, MaxConfigBytes+1)); !errors.Is(err, ErrNginx) {
		t.Error("an oversized file was read")
	}
	var perr *ParseError
	_, err := ParseNginx("x.conf", []byte("server {\n  listen 80;\n  root /x\n}\n"))
	if !errors.As(err, &perr) || perr.Line != 4 {
		t.Fatalf("the error names no line: %v", err)
	}
}
