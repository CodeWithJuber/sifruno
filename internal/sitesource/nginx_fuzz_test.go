package sitesource

import (
	"strings"
	"testing"

	"sifruno/internal/olsweb"
	"sifruno/internal/sitemodel"
)

// FuzzNginx feeds the parser and the converter arbitrary text. Neither may
// panic, and whatever the converter emits must be safe to write: one line
// per rewrite with nothing a rule reads specially beyond what it means,
// closed folders and redirects olsweb accepts, and a model that passes
// Check's rule rules.
func FuzzNginx(f *testing.F) {
	f.Add(wordpressServer)
	f.Add("server { location ~* \\.(js)$ { deny all; } rewrite ^/(.*)$ /x?$args? last; return 301 https://$host$request_uri; }")
	f.Add("http { server { server_name a.example.com; location = /a { return 302 https://example.com/b; } location / { try_files $uri $uri/ /index.php?q=$uri&$args; } } }")
	f.Add("server { location /x/ { allow 192.0.2.1; deny all; } location ${a} { } }")
	f.Fuzz(func(t *testing.T, text string) {
		file, err := ParseNginx("fuzz.conf", []byte(text))
		if err != nil {
			return
		}
		for _, s := range file.Servers() {
			c := ConvertNginx(s)
			for _, line := range c.Rewrites {
				if strings.ContainsAny(line, "\x00\r\n") || !strings.HasPrefix(line, "Rewrite") {
					t.Fatalf("an unsafe rewrite line %q", line)
				}
			}
			for _, folder := range c.Folders {
				if !olsweb.ValidFolderPath(folder) {
					t.Fatalf("a folder olsweb refuses: %q", folder)
				}
			}
			for _, r := range c.Redirects {
				if _, ok := olsweb.ParseRedirectTarget(r.Target, false); !ok || !olsweb.ValidRedirectPath(r.Path) {
					t.Fatalf("a redirect olsweb refuses: %+v", r)
				}
			}
			site := sitemodel.Site{Source: sitemodel.SourceSSH, Account: "shop", Domain: "example.com", PHP: sitemodel.PHP{Version: "8.3"}}
			c.Apply(&site)
			if err := site.Check(); err != nil && len(site.Rules.Rewrites) <= sitemodel.MaxRewrites {
				t.Fatalf("the converted rules fail Check: %v", err)
			}
		}
	})
}
