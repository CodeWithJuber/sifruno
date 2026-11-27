package olsweb

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func movedSite(redirects []HtaccessRedirect, pages []ErrorPage) Server {
	s := folderSite()
	s.Sites[0].HtaccessRedirects, s.Sites[0].ErrorPages = redirects, pages
	return s
}

func TestMovedValidation(t *testing.T) {
	ok := []HtaccessRedirect{
		{Prefix: "/", Target: "https://new.example.com/", Status: 301},
		{Prefix: "/old-page", Target: "https://example.com:8443/new?a=1&b=2", Status: 302},
		{Prefix: "/docs/", Target: "/manual/", Status: 301},
		{Pattern: `^/blog/([0-9]+)/(.*)\.html$`, Target: "/news/$2?id=$1", Status: 301},
		{Pattern: `(?i)^/Shop$`, Target: "https://shop.example.com", Status: 302},
	}
	pages := []ErrorPage{{Status: 401, URL: "/401.html"}, {Status: 404, URL: "/errors/404.shtml"}, {Status: 503, URL: "/down.html"}}
	if err := Validate(movedSite(ok, pages)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Server{
		"status":             movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "/b", Status: 307}}, nil),
		"both":               movedSite([]HtaccessRedirect{{Prefix: "/a", Pattern: "^/a", Target: "/b", Status: 301}}, nil),
		"neither":            movedSite([]HtaccessRedirect{{Target: "/b", Status: 301}}, nil),
		"prefix space":       movedSite([]HtaccessRedirect{{Prefix: "/a b", Target: "/b", Status: 301}}, nil),
		"prefix dot":         movedSite([]HtaccessRedirect{{Prefix: "/.well-known/", Target: "/b", Status: 301}}, nil),
		"pattern space":      movedSite([]HtaccessRedirect{{Pattern: "^/a b", Target: "/b", Status: 301}}, nil),
		"pattern percent":    movedSite([]HtaccessRedirect{{Pattern: "^/a%{HTTP_HOST}", Target: "/b", Status: 301}}, nil),
		"pattern brace":      movedSite([]HtaccessRedirect{{Pattern: "^/a{2}", Target: "/b", Status: 301}}, nil),
		"pattern negated":    movedSite([]HtaccessRedirect{{Pattern: "!^/a", Target: "/b", Status: 301}}, nil),
		"pattern lookbehind": movedSite([]HtaccessRedirect{{Pattern: "(?<=a)b", Target: "/b", Status: 301}}, nil),
		"pattern newline":    movedSite([]HtaccessRedirect{{Pattern: "^/a\nRewriteRule", Target: "/b", Status: 301}}, nil),
		"target percent":     movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "/b%{HTTP_HOST}", Status: 301}}, nil),
		"target dollar":      movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "/b$1", Status: 301}}, nil),
		"target lone $":      movedSite([]HtaccessRedirect{{Pattern: "^/a", Target: "/b$", Status: 301}}, nil),
		"target scheme":      movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "ftp://example.com/", Status: 301}}, nil),
		"target address":     movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "https://192.0.2.1/", Status: 301}}, nil),
		"target upper":       movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "https://Example.com/", Status: 301}}, nil),
		"target relative":    movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "b", Status: 301}}, nil),
		"target space":       movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "/b c", Status: 301}}, nil),
		"target port":        movedSite([]HtaccessRedirect{{Prefix: "/a", Target: "https://example.com:70000/", Status: 301}}, nil),
		"page status":        movedSite(nil, []ErrorPage{{Status: 302, URL: "/x.html"}}),
		"page unsorted":      movedSite(nil, []ErrorPage{{Status: 404, URL: "/x.html"}, {Status: 403, URL: "/y.html"}}),
		"page query":         movedSite(nil, []ErrorPage{{Status: 404, URL: "/index.php?e=404"}}),
		"page root":          movedSite(nil, []ErrorPage{{Status: 404, URL: "/"}}),
		"page url":           movedSite(nil, []ErrorPage{{Status: 404, URL: "https://example.com/404"}}),
	}
	for name, s := range bad {
		t.Run(name, func(t *testing.T) {
			var fe *FieldError
			if err := Validate(s); !errors.As(err, &fe) || !(strings.Contains(fe.Field, "htaccess_redirects") || strings.Contains(fe.Field, "error_pages")) {
				t.Fatalf("got %v", err)
			}
		})
	}
	many := make([]HtaccessRedirect, MaxHtaccessRedirects+1)
	for i := range many {
		many[i] = HtaccessRedirect{Prefix: "/a", Target: "/b", Status: 301}
	}
	if err := Validate(movedSite(many, nil)); err == nil {
		t.Fatal("accepted more redirects than the bound")
	}
}

// The rendered rules redirect what mod_alias would, read here with Go's
// engine on the path with its leading '/', as the vhost's rules see it.
func TestMovedRules(t *testing.T) {
	rules := movedRules([]HtaccessRedirect{
		{Prefix: "/old.page", Target: "https://example.com/new", Status: 301},
		{Prefix: "/docs/", Target: "/manual/", Status: 302},
		{Prefix: "/", Target: "https://new.example.com/", Status: 301},
	})
	want := []string{
		`RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/`,
		`RewriteRule ^/?old\.page(/.*)?$ https://example.com/new$1 [R=301,L]`,
		`RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/`,
		`RewriteRule ^/?docs/(.*)$ /manual/$1 [R=302,L]`,
		`RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/`,
		`RewriteRule ^/?(.*)$ https://new.example.com/$1 [R=301,L]`,
	}
	if !slices.Equal(rules, want) {
		t.Fatalf("got %q", rules)
	}
	prefix := regexp.MustCompile(strings.Fields(want[1])[1])
	for path, rest := range map[string]string{"/old.page": "", "/old.page/x/y": "/x/y", "/old.pagex": "-", "/oldXpage": "-"} {
		m := prefix.FindStringSubmatch(path)
		if (m == nil) != (rest == "-") || (m != nil && m[1] != rest) {
			t.Errorf("%s: %q", path, m)
		}
	}
	slash := regexp.MustCompile(strings.Fields(want[3])[1])
	if m := slash.FindStringSubmatch("/docs/a/b"); m == nil || m[1] != "a/b" || slash.MatchString("/docs") {
		t.Errorf("trailing slash prefix: %q", m)
	}
}

func TestMovedRendered(t *testing.T) {
	s := movedSite([]HtaccessRedirect{{Prefix: "/old", Target: "/new", Status: 301}}, []ErrorPage{{Status: 404, URL: "/404.html"}})
	s.Sites[0].Redirects = []Redirect{{Path: "/shop", Target: "https://shop.example.com/", Status: 302}}
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	vh := string(files[VhostConfigPath("blog")])
	if !strings.Contains(vh, "\nerrorPage 404 {\n  url                     /404.html\n}\n") {
		t.Errorf("no error page:\n%s", vh)
	}
	panel, moved := strings.Index(vh, "RewriteRule ^/?shop/?$"), strings.Index(vh, "RewriteRule ^/?old(/.*)?$ /new$1 [R=301,L]")
	if panel < 0 || moved < panel {
		t.Errorf("the panel's redirect must come first:\n%s", vh)
	}
	if _, err := confShape(files[VhostConfigPath("blog")]); err != nil {
		t.Fatal(err)
	}
	s.Sites[0].Suspended = true
	files, err = Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if vh := string(files[VhostConfigPath("blog")]); strings.Contains(vh, "errorPage") || strings.Contains(vh, "/new") {
		t.Errorf("a suspended site renders converted lines:\n%s", vh)
	}
}
