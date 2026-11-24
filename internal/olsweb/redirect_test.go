package olsweb

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func redirectServer(redirects ...Redirect) Server {
	s := baseServer()
	s.Sites[0].Domains = []string{"example.com", "www.example.com", "example.net"}
	s.Sites[0].Redirects = redirects
	return s
}

func TestRedirectsAccepted(t *testing.T) {
	s := redirectServer(
		Redirect{Domain: "www.example.com", Target: "https://example.com", Status: 301},
		Redirect{Domain: "example.net", Target: "http://example.org:8443", Status: 302},
		Redirect{Path: "/", Target: "https://example.com/home", Status: 302},
		Redirect{Path: "/old-page", Target: "https://example.com/new-page?x=1&y=two", Status: 301},
		Redirect{Path: "/a/b_c~d-e.html", Target: "https://other.example.org/@me/a,b;c:d=e+f", Status: 301},
	)
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	vh := string(files[VhostConfigPath("blog")])
	for _, want := range []string{
		"RewriteCond %{HTTP_HOST} ^www\\.example\\.com(:[0-9]+)?$ [NC]\nRewriteCond %{REQUEST_URI} !^/\\.well-known/acme-challenge/\nRewriteRule ^/?(.*)$ https://example.com/$1 [R=301,L]\n",
		"RewriteRule ^/?(.*)$ http://example.org:8443/$1 [R=302,L]\n",
		"RewriteRule ^/?$ https://example.com/home [R=302,L]\n",
		"RewriteRule ^/?old-page/?$ https://example.com/new-page?x=1&y=two [R=301,L]\n",
		"RewriteRule ^/?a/b_c~d-e\\.html/?$ https://other.example.org/@me/a,b;c:d=e+f [R=301,L]\n",
	} {
		if !strings.Contains(vh, want) {
			t.Errorf("vhconf.conf lacks %q\n%s", want, vh)
		}
	}
	// The deny rules come first, so a redirect never serves a protected file.
	if strings.Index(vh, "RewriteRule (^|/)\\.env") > strings.Index(vh, "RewriteCond %{HTTP_HOST}") {
		t.Error("a redirect is rendered before the deny rules")
	}
}

func TestRedirectsSuspendedRenderNone(t *testing.T) {
	s := redirectServer(Redirect{Domain: "www.example.com", Target: "https://example.com", Status: 301}, Redirect{Path: "/x", Target: "https://example.com/y", Status: 301})
	s.Sites[0].Suspended = true
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	vh := string(files[VhostConfigPath("blog")])
	if strings.Contains(vh, "RewriteCond") || strings.Contains(vh, "R=301") || !strings.Contains(vh, "RewriteRule .* - [F,L]\n") {
		t.Fatalf("a suspended site renders redirects:\n%s", vh)
	}
	// Its aliases stay mapped to the suspended vhost, which answers 403.
	if !strings.Contains(string(files[ServerConfigPath]), "map                     sifruno-blog example.com, www.example.com, example.net\n") {
		t.Fatalf("a suspended site's domains left the listener:\n%s", files[ServerConfigPath])
	}
}

func TestSecuredDomainsMapOnlyCovered(t *testing.T) {
	s := redirectServer()
	s.Sites[0].TLS.Domains = []string{"example.net", "example.com"}
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(files[ServerConfigPath])
	https := conf[strings.Index(conf, "listener sifruno-https"):]
	if !strings.Contains(https, "map                     sifruno-blog example.com, example.net\n") {
		t.Fatalf("the secure listener does not map exactly the covered domains:\n%s", https)
	}
	http := conf[strings.Index(conf, "listener sifruno-http "):strings.Index(conf, "listener sifruno-https")]
	if !strings.Contains(http, "map                     sifruno-blog example.com, www.example.com, example.net\n") {
		t.Fatalf("the plain listener does not map every domain:\n%s", http)
	}
}

// TestRedirectsHostile: each refused redirect fails, wraps ErrInvalid and
// names its field. Many are attempts to end the rule, add flags or rules,
// expand a variable or reach a back-reference in the config the broker
// writes as root.
func TestRedirectsHostile(t *testing.T) {
	path := func(p, target string) Redirect { return Redirect{Path: p, Target: target, Status: 301} }
	domain := func(d, target string) Redirect { return Redirect{Domain: d, Target: target, Status: 301} }
	long := "/" + strings.Repeat("a", MaxRedirectPathBytes)
	cases := []struct {
		name     string
		redirect []Redirect
		field    string
	}{
		{"newline in target", []Redirect{path("/a", "https://example.com/\nRewriteRule .* /etc/passwd")}, "redirects[0].target"},
		{"carriage return in target", []Redirect{path("/a", "https://example.com/\r")}, "redirects[0].target"},
		{"space and flags in target", []Redirect{path("/a", "https://example.com/ [R=302,L]")}, "redirects[0].target"},
		{"heredoc end in target", []Redirect{path("/a", "https://example.com/\n  END_rules\n}\nvirtualhost x {")}, "redirects[0].target"},
		{"back-reference in target", []Redirect{path("/a", "https://example.com/$1")}, "redirects[0].target"},
		{"variable in target", []Redirect{path("/a", "https://example.com/%{HTTP_COOKIE}")}, "redirects[0].target"},
		{"config variable in target", []Redirect{path("/a", "https://example.com/${VH_ROOT}")}, "redirects[0].target"},
		{"percent in target", []Redirect{path("/a", "https://example.com/a%20b")}, "redirects[0].target"},
		{"backslash in target", []Redirect{path("/a", "https://example.com/a\\b")}, "redirects[0].target"},
		{"comment in target", []Redirect{path("/a", "https://example.com/#x")}, "redirects[0].target"},
		{"brace in target", []Redirect{path("/a", "https://example.com/}")}, "redirects[0].target"},
		{"quote in target", []Redirect{path("/a", "https://example.com/\"x")}, "redirects[0].target"},
		{"tab in target", []Redirect{path("/a", "https://example.com/\tx")}, "redirects[0].target"},
		{"non-ASCII in target", []Redirect{path("/a", "https://example.com/ü")}, "redirects[0].target"},
		{"javascript target", []Redirect{path("/a", "javascript:alert(1)")}, "redirects[0].target"},
		{"ftp target", []Redirect{path("/a", "ftp://example.com/")}, "redirects[0].target"},
		{"relative target", []Redirect{path("/a", "/b")}, "redirects[0].target"},
		{"scheme-relative target", []Redirect{path("/a", "//example.com/b")}, "redirects[0].target"},
		{"uppercase scheme", []Redirect{path("/a", "HTTPS://example.com/")}, "redirects[0].target"},
		{"uppercase host", []Redirect{path("/a", "https://Example.com/")}, "redirects[0].target"},
		{"user in target", []Redirect{path("/a", "https://user@example.com/")}, "redirects[0].target"},
		{"IP target", []Redirect{path("/a", "https://192.0.2.1/")}, "redirects[0].target"},
		{"IPv6 target", []Redirect{path("/a", "https://[2001:db8::1]/")}, "redirects[0].target"},
		{"single label host", []Redirect{path("/a", "https://localhost/")}, "redirects[0].target"},
		{"port 0", []Redirect{path("/a", "https://example.com:0/")}, "redirects[0].target"},
		{"port too large", []Redirect{path("/a", "https://example.com:70000/")}, "redirects[0].target"},
		{"target too long", []Redirect{path("/a", "https://example.com/"+strings.Repeat("a", MaxRedirectTargetBytes))}, "redirects[0].target"},
		{"empty target", []Redirect{path("/a", "")}, "redirects[0].target"},
		{"path to itself", []Redirect{path("/a", "https://www.example.com/a")}, "redirects[0].target"},
		{"path to itself with a slash", []Redirect{path("/a", "http://example.net/a/?x=1")}, "redirects[0].target"},
		{"home to itself", []Redirect{path("/", "https://example.com")}, "redirects[0].target"},
		{"relative path", []Redirect{path("a", "https://example.com/")}, "redirects[0].path"},
		{"regex in path", []Redirect{path("/a.*", "https://example.com/")}, "redirects[0].path"},
		{"anchor in path", []Redirect{path("/a$", "https://example.com/")}, "redirects[0].path"},
		{"group in path", []Redirect{path("/(a|b)", "https://example.com/")}, "redirects[0].path"},
		{"space in path", []Redirect{path("/a b", "https://example.com/")}, "redirects[0].path"},
		{"newline in path", []Redirect{path("/a\nRewriteRule", "https://example.com/")}, "redirects[0].path"},
		{"percent in path", []Redirect{path("/a%2e", "https://example.com/")}, "redirects[0].path"},
		{"query in path", []Redirect{path("/a?b=1", "https://example.com/")}, "redirects[0].path"},
		{"double slash in path", []Redirect{path("/a//b", "https://example.com/")}, "redirects[0].path"},
		{"dot part in path", []Redirect{path("/a/../b", "https://example.com/")}, "redirects[0].path"},
		{"ACME challenge path", []Redirect{path("/.well-known/acme-challenge/x", "https://example.com/")}, "redirects[0].path"},
		{"hidden file path", []Redirect{path("/.env", "https://example.com/")}, "redirects[0].path"},
		{"path too long", []Redirect{path(long, "https://example.com/")}, "redirects[0].path"},
		{"same path twice", []Redirect{path("/a", "https://example.org/"), path("/a", "https://example.org/b")}, "redirects[1].path"},
		{"status 200", []Redirect{{Path: "/a", Target: "https://example.org/", Status: 200}}, "redirects[0].status"},
		{"status 307", []Redirect{{Path: "/a", Target: "https://example.org/", Status: 307}}, "redirects[0].status"},
		{"both domain and path", []Redirect{{Domain: "www.example.com", Path: "/a", Target: "https://example.org", Status: 301}}, "redirects[0]"},
		{"neither domain nor path", []Redirect{{Target: "https://example.org", Status: 301}}, "redirects[0]"},
		{"domain of another site", []Redirect{domain("legacy.example.net", "https://example.com")}, "redirects[0].domain"},
		{"domain not of the site", []Redirect{domain("unrelated.example", "https://example.com")}, "redirects[0].domain"},
		{"domain twice", []Redirect{domain("www.example.com", "https://example.com"), domain("www.example.com", "https://example.net")}, "redirects[1].domain"},
		{"domain to itself", []Redirect{domain("www.example.com", "https://www.example.com")}, "redirects[0].target"},
		{"domain target with a path", []Redirect{domain("www.example.com", "https://example.com/")}, "redirects[0].target"},
		{"domain target with a query", []Redirect{domain("www.example.com", "https://example.com?x")}, "redirects[0].target"},
		{"domain redirect loop", []Redirect{domain("www.example.com", "https://example.com"), domain("example.com", "https://www.example.com")}, "redirects[0].target"},
		{"domain redirect chain", []Redirect{domain("example.net", "https://www.example.com"), domain("www.example.com", "https://example.com")}, "redirects[0].target"},
		{"domain with injection", []Redirect{domain("www.example.com$", "https://example.com")}, "redirects[0].domain"},
	}
	for _, c := range cases {
		err := Validate(redirectServer(c.redirect...))
		var fe *FieldError
		if err == nil || !errors.Is(err, ErrInvalid) || !errors.As(err, &fe) {
			t.Errorf("%s: accepted or wrong error type: %v", c.name, err)
			continue
		}
		if want := "sites[0]." + c.field; fe.Field != want {
			t.Errorf("%s: field %q, want %q (%v)", c.name, fe.Field, want, err)
		}
	}

	tooMany := make([]Redirect, MaxRedirectsPerSite+1)
	for i := range tooMany {
		tooMany[i] = path(fmt.Sprintf("/p%d", i), "https://example.org/")
	}
	if err := Validate(redirectServer(tooMany...)); err == nil || !strings.Contains(err.Error(), "sites[0].redirects:") {
		t.Errorf("%d redirects accepted: %v", len(tooMany), err)
	}
	if err := Validate(redirectServer(tooMany[:MaxRedirectsPerSite]...)); err != nil {
		t.Errorf("%d redirects refused: %v", MaxRedirectsPerSite, err)
	}
}

func TestCoveredDomainsHostile(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Site)
	}{
		{"a domain the site does not have", func(x *Site) { x.TLS.Domains = []string{"example.com", "legacy.example.net"} }},
		{"a domain twice", func(x *Site) { x.TLS.Domains = []string{"example.com", "example.com"} }},
		{"no certificate", func(x *Site) { x.TLS = TLS{Domains: []string{"example.com"}} }},
	}
	for _, c := range cases {
		s := baseServer()
		c.edit(&s.Sites[0])
		if err := Validate(s); err == nil || !strings.Contains(err.Error(), "sites[0].tls.domains") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

var (
	pathRuleShape   = regexp.MustCompile(`^RewriteRule \^/\?[A-Za-z0-9_~/\\.-]*\??\$ https?://[a-z0-9.-]+(:[0-9]+)?[A-Za-z0-9._~/?&=+,:;@-]* \[R=30[12],L\]$`)
	domainRuleShape = regexp.MustCompile(`^RewriteRule \^/\?\(\.\*\)\$ https?://[a-z0-9.-]+(:[0-9]+)?/\$1 \[R=30[12],L\]$`)
)

// FuzzRedirect feeds arbitrary paths, domains and targets through the
// validators. A refusal must be a FieldError. An accepted redirect must add
// exactly its own rule lines to the rules block, each of the one shape the
// renderer writes, with the target verbatim and nothing after the flags.
func FuzzRedirect(f *testing.F) {
	f.Add("/old-page", "", "https://example.com/new-page", 301)
	f.Add("", "www.example.com", "https://example.com", 301)
	f.Add("/a", "", "https://example.com/ [R=302,L]\nRewriteRule .* -", 302)
	f.Add("/a\n  END_rules", "", "https://example.com/$1", 301)
	f.Add("", "www.example.com", "https://example.com/%{HTTP_HOST}", 301)
	f.Add("/", "", "http://example.org:8080/?a=b&c=d", 302)
	f.Fuzz(func(t *testing.T, path, domain, target string, status int) {
		s := redirectServer(Redirect{Path: path, Domain: domain, Target: target, Status: status})
		err := Validate(s)
		if err != nil {
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field == "" || !errors.Is(err, ErrInvalid) {
				t.Fatalf("refusal is not a named FieldError: %v", err)
			}
			return
		}
		files, err := Render(s)
		if err != nil {
			t.Fatalf("validated redirect failed to render: %v", err)
		}
		base, err := Render(redirectServer())
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Split(string(files[VhostConfigPath("blog")]), "\n")
		want := strings.Split(string(base[VhostConfigPath("blog")]), "\n")
		extra := 1
		if domain != "" {
			extra = 3
		}
		if len(got) != len(want)+extra {
			t.Fatalf("the redirect added %d lines, want %d:\n%s", len(got)-len(want), extra, files[VhostConfigPath("blog")])
		}
		end := 0
		for i, line := range got {
			if line == "  END_rules" {
				end = i
			}
		}
		rule := got[end-1]
		shape := pathRuleShape
		if domain != "" {
			shape = domainRuleShape
			if !strings.HasPrefix(got[end-3], "RewriteCond %{HTTP_HOST} ^") || got[end-2] != `RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/` {
				t.Fatalf("domain conditions have another shape:\n%s\n%s", got[end-3], got[end-2])
			}
		}
		if !shape.MatchString(rule) || !strings.Contains(rule, " "+target) {
			t.Fatalf("rule has another shape or lost its target: %q", rule)
		}
		if _, err := confShape(files[VhostConfigPath("blog")]); err != nil {
			t.Fatalf("rendered vhost does not parse: %v", err)
		}
	})
}
