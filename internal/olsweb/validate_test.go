package olsweb

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidateAcceptsBase(t *testing.T) {
	if err := Validate(baseServer()); err != nil {
		t.Fatal(err)
	}
	edge := Server{
		HTTPDWorkers: 16,
		Listeners:    []Listener{{Name: "a", Address: "::", Port: 1}, {Name: "b", Address: "192.0.2.1", Port: 65535}, {Name: "c", Address: "192.0.2.2", Port: 65535}},
		Sites: []Site{{
			Name: "a", Username: "abc", Group: "abc", DocRoot: "/home/abc/x", PHPVersion: "8.4",
			Domains: []string{"www.a.b", "a.b", "x-1.example", "1.example"},
			Limits:  Limits{PHPChildren: 100, MemoryMiB: 256, Processes: (3*100 + 50) * 16},
		}},
	}
	for i := 4; i < MaxDomainsPerSite; i++ {
		edge.Sites[0].Domains = append(edge.Sites[0].Domains, fmt.Sprintf("d%d.example", i))
	}
	if err := Validate(edge); err != nil {
		t.Fatal(err)
	}
	if _, err := Render(Server{}); err != nil {
		t.Fatalf("an empty server must render: %v", err)
	}
}

// TestValidateHostile checks that each refused input fails, wraps ErrInvalid
// and names the field it came from.
func TestValidateHostile(t *testing.T) {
	site0 := func(f func(*Site)) func(*Server) { return func(s *Server) { f(&s.Sites[0]) } }
	tls := func(cert, key string) func(*Server) {
		return site0(func(x *Site) { x.TLS = TLS{CertFile: cert, KeyFile: key} })
	}
	const key0 = TLSRoot + "/blog/privkey.pem"
	cases := []struct {
		name  string
		edit  func(*Server)
		field string
	}{
		{"newline in domain", site0(func(x *Site) { x.Domains[0] = "example.com\nlistener evil {" }), "sites[0].domains[0]"},
		{"space in domain", site0(func(x *Site) { x.Domains[1] = "www.example.com evil.com" }), "sites[0].domains[1]"},
		{"uppercase domain", site0(func(x *Site) { x.Domains[0] = "Example.com" }), "sites[0].domains[0]"},
		{"wildcard domain", site0(func(x *Site) { x.Domains[0] = "*.example.com" }), "sites[0].domains[0]"},
		{"ip as domain", site0(func(x *Site) { x.Domains[0] = "192.0.2.1" }), "sites[0].domains[0]"},
		{"single label domain", site0(func(x *Site) { x.Domains[0] = "localhost" }), "sites[0].domains[0]"},
		{"trailing dot domain", site0(func(x *Site) { x.Domains[0] = "example.com." }), "sites[0].domains[0]"},
		{"www.www domain", site0(func(x *Site) { x.Domains[0] = "www.www.example.com" }), "sites[0].domains[0]"},
		{"www.tld domain", site0(func(x *Site) { x.Domains[0] = "www.com" }), "sites[0].domains[0]"},
		{"no domains", site0(func(x *Site) { x.Domains = nil }), "sites[0].domains"},
		{"too many domains", site0(func(x *Site) {
			for i := 0; i < MaxDomainsPerSite; i++ {
				x.Domains = append(x.Domains, fmt.Sprintf("d%d.example.com", i))
			}
		}), "sites[0].domains"},
		{"domain twice in one site", site0(func(x *Site) { x.Domains[1] = x.Domains[0] }), "sites[0].domains[1]"},
		{"duplicate domain across sites", func(s *Server) { s.Sites[1].Domains[0] = "example.com" }, "sites[1].domains[0]"},
		{"www form of another site's domain", func(s *Server) {
			s.Sites[1].Domains[0] = "www.legacy.example.net"
			s.Sites[2].Domains[0] = "legacy.example.net"
		}, "sites[2].domains[0]"},
		{"brace in docroot", site0(func(x *Site) { x.DocRoot = "/home/blogowner/public_html}" }), "sites[0].doc_root"},
		{"brace line in docroot", site0(func(x *Site) { x.DocRoot = "/home/blogowner/x {" }), "sites[0].doc_root"},
		{"docroot escapes with ..", site0(func(x *Site) { x.DocRoot = "/home/blogowner/../legacyapp/www" }), "sites[0].doc_root"},
		{"docroot is the home", site0(func(x *Site) { x.DocRoot = "/home/blogowner" }), "sites[0].doc_root"},
		{"docroot is the home with slash", site0(func(x *Site) { x.DocRoot = "/home/blogowner/" }), "sites[0].doc_root"},
		{"docroot in another home", site0(func(x *Site) { x.DocRoot = "/home/legacyapp/www/htdocs" }), "sites[0].doc_root"},
		{"docroot prefix of another home", site0(func(x *Site) { x.DocRoot = "/home/blogownerx/public_html" }), "sites[0].doc_root"},
		{"docroot hidden directory", site0(func(x *Site) { x.DocRoot = "/home/blogowner/.ssh" }), "sites[0].doc_root"},
		{"docroot variable", site0(func(x *Site) { x.DocRoot = "$VH_ROOT/public_html" }), "sites[0].doc_root"},
		{"docroot heredoc", site0(func(x *Site) { x.DocRoot = "/home/blogowner/a<<<END" }), "sites[0].doc_root"},
		{"docroot continuation", site0(func(x *Site) { x.DocRoot = "/home/blogowner/a\\" }), "sites[0].doc_root"},
		{"docroot NUL", site0(func(x *Site) { x.DocRoot = "/home/blogowner/a\x00b" }), "sites[0].doc_root"},
		{"docroot relative", site0(func(x *Site) { x.DocRoot = "home/blogowner/public_html" }), "sites[0].doc_root"},
		{"docroot too long", site0(func(x *Site) { x.DocRoot = "/home/blogowner/" + strings.Repeat("a", MaxPathBytes) }), "sites[0].doc_root"},
		{"username root", site0(func(x *Site) { x.Username, x.Group, x.DocRoot = "root", "root", "/home/root/public_html" }), "sites[0].username"},
		{"username lsadm", site0(func(x *Site) { x.Username, x.Group, x.DocRoot = "lsadm", "lsadm", "/home/lsadm/public_html" }), "sites[0].username"},
		{"username nobody", site0(func(x *Site) { x.Username, x.Group, x.DocRoot = "nobody", "nobody", "/home/nobody/public_html" }), "sites[0].username"},
		{"username sifpanel", site0(func(x *Site) { x.Username, x.Group, x.DocRoot = "sifpanel", "sifpanel", "/home/sifpanel/public_html" }), "sites[0].username"},
		{"username www_data", site0(func(x *Site) { x.Username, x.Group, x.DocRoot = "www_data", "www_data", "/home/www_data/public_html" }), "sites[0].username"},
		{"username uppercase", site0(func(x *Site) { x.Username = "Blogowner" }), "sites[0].username"},
		{"username with space", site0(func(x *Site) { x.Username = "blog owner" }), "sites[0].username"},
		{"username too short", site0(func(x *Site) { x.Username = "ab" }), "sites[0].username"},
		{"group wheel", site0(func(x *Site) { x.Group = "wheel" }), "sites[0].group"},
		{"group of another tenant", site0(func(x *Site) { x.Group = "legacyapp" }), "sites[0].group"},
		{"empty group", site0(func(x *Site) { x.Group = "" }), "sites[0].group"},
		{"unknown php version", site0(func(x *Site) { x.PHPVersion = "7.4" }), "sites[0].php_version"},
		{"php version with space", site0(func(x *Site) { x.PHPVersion = "8.3 " }), "sites[0].php_version"},
		{"php version as path", site0(func(x *Site) { x.PHPVersion = "/usr/bin/php" }), "sites[0].php_version"},
		{"empty site name", site0(func(x *Site) { x.Name = "" }), "sites[0].name"},
		{"site name with brace", site0(func(x *Site) { x.Name = "blog}" }), "sites[0].name"},
		{"site name with space", site0(func(x *Site) { x.Name = "blog x" }), "sites[0].name"},
		{"site name uppercase", site0(func(x *Site) { x.Name = "Blog" }), "sites[0].name"},
		{"site name path", site0(func(x *Site) { x.Name = "../etc" }), "sites[0].name"},
		{"site name too long", site0(func(x *Site) { x.Name = strings.Repeat("a", 33) }), "sites[0].name"},
		{"duplicate site name", func(s *Server) { s.Sites[1].Name = "blog" }, "sites[1].name"},
		{"10,000 sites", func(s *Server) {
			s.Sites = make([]Site, 10000)
			for i := range s.Sites {
				u := fmt.Sprintf("user%05d", i)
				s.Sites[i] = Site{Name: fmt.Sprintf("s%d", i), Username: u, Group: u, Domains: []string{fmt.Sprintf("s%d.example.com", i)}, DocRoot: "/home/" + u + "/public_html", PHPVersion: "8.3"}
			}
		}, "sites"},
		{"php children too high", site0(func(x *Site) { x.Limits.PHPChildren = 101 }), "sites[0].limits.php_children"},
		{"php children negative", site0(func(x *Site) { x.Limits.PHPChildren = -1 }), "sites[0].limits.php_children"},
		{"memory too low", site0(func(x *Site) { x.Limits.MemoryMiB = 64 }), "sites[0].limits.memory_mib"},
		{"memory too high", site0(func(x *Site) { x.Limits.MemoryMiB = 1 << 20 }), "sites[0].limits.memory_mib"},
		{"processes below OLS floor", site0(func(x *Site) { x.Limits.Processes = 100 }), "sites[0].limits.processes"},
		{"processes below floor for workers", func(s *Server) { s.HTTPDWorkers = 4; s.Sites[0].Limits.Processes = (3*10+50)*4 - 1 }, "sites[0].limits.processes"},
		{"processes too high", site0(func(x *Site) { x.Limits.Processes = 1 << 20 }), "sites[0].limits.processes"},
		{"httpd workers too high", func(s *Server) { s.HTTPDWorkers = 17 }, "httpd_workers"},
		{"cert via /proc/self/root", tls("/proc/self/root"+TLSRoot+"/blog/fullchain.pem", key0), "sites[0].tls.cert_file"},
		{"cert in /tmp", tls("/tmp/fullchain.pem", key0), "sites[0].tls.cert_file"},
		{"key is /etc/shadow", tls(TLSRoot+"/blog/fullchain.pem", "/etc/shadow"), "sites[0].tls.key_file"},
		{"cert in another site's directory", tls(TLSRoot+"/legacy/fullchain.pem", key0), "sites[0].tls.cert_file"},
		{"cert is the site directory", tls(TLSRoot+"/blog", key0), "sites[0].tls.cert_file"},
		{"cert is the TLS root", tls(TLSRoot, key0), "sites[0].tls.cert_file"},
		{"cert in a subdirectory", tls(TLSRoot+"/blog/sub/fullchain.pem", key0), "sites[0].tls.cert_file"},
		{"key traverses to another site", tls(TLSRoot+"/blog/fullchain.pem", TLSRoot+"/blog/../legacy/privkey.pem"), "sites[0].tls.key_file"},
		{"hidden cert name", tls(TLSRoot+"/blog/.fullchain.pem", key0), "sites[0].tls.cert_file"},
		{"cert without key", tls(TLSRoot+"/blog/fullchain.pem", ""), "sites[0].tls.key_file"},
		{"key without cert", tls("", key0), "sites[0].tls.cert_file"},
		{"cert equals key", tls(key0, key0), "sites[0].tls.key_file"},
		{"listener cert is /etc/shadow", func(s *Server) { s.Listeners[1].CertFile = "/etc/shadow" }, "listeners[1].cert_file"},
		{"listener cert in a site directory", func(s *Server) { s.Listeners[1].CertFile = TLSRoot + "/blog/fullchain.pem" }, "listeners[1].cert_file"},
		{"listener cert is the TLS root", func(s *Server) { s.Listeners[1].KeyFile = TLSRoot }, "listeners[1].key_file"},
		{"secure listener without cert", func(s *Server) { s.Listeners[1].CertFile = "" }, "listeners[1].cert_file"},
		{"plain listener with cert", func(s *Server) { s.Listeners[0].CertFile = TLSRoot + "/x.pem" }, "listeners[0].cert_file"},
		{"listener address with port", func(s *Server) { s.Listeners[0].Address = "0.0.0.0:80" }, "listeners[0].address"},
		{"listener address hostname", func(s *Server) { s.Listeners[0].Address = "example.com" }, "listeners[0].address"},
		{"listener address with zone", func(s *Server) { s.Listeners[0].Address = "fe80::1%eth0" }, "listeners[0].address"},
		{"listener address not canonical", func(s *Server) { s.Listeners[0].Address = "2001:DB8::1" }, "listeners[0].address"},
		{"listener address newline", func(s *Server) { s.Listeners[0].Address = "*\n}" }, "listeners[0].address"},
		{"listener port zero", func(s *Server) { s.Listeners[0].Port = 0 }, "listeners[0].port"},
		{"listener port too high", func(s *Server) { s.Listeners[0].Port = 70000 }, "listeners[0].port"},
		{"listener name with brace", func(s *Server) { s.Listeners[0].Name = "http {" }, "listeners[0].name"},
		{"duplicate listener name", func(s *Server) { s.Listeners[1].Name = "http" }, "listeners[1].name"},
		{"duplicate listener bind", func(s *Server) { s.Listeners[1] = Listener{Name: "again", Address: "*", Port: 80} }, "listeners[1].address"},
		{"wildcard and specific on one port", func(s *Server) { s.Listeners[1] = Listener{Name: "again", Address: "192.0.2.1", Port: 80} }, "listeners[1].port"},
		{"too many listeners", func(s *Server) {
			for i := 0; i < MaxListeners; i++ {
				s.Listeners = append(s.Listeners, Listener{Name: fmt.Sprintf("l%d", i), Address: "192.0.2.1", Port: 1000 + i})
			}
		}, "listeners"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := baseServer()
			tc.edit(&s)
			err := Validate(s)
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("accepted or untyped error: %v", err)
			}
			if fe.Field != tc.field {
				t.Fatalf("field %q, want %q (%v)", fe.Field, tc.field, err)
			}
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error does not wrap ErrInvalid or name the field: %v", err)
			}
			if files, rerr := Render(s); rerr == nil || files != nil {
				t.Fatal("Render produced output for refused input")
			}
		})
	}
}

// ProcessFloor is the number Validate holds a site's process limit to: the
// floor itself is accepted and one below it is refused, with the assumed
// httpd workers and with a stated count.
func TestProcessFloor(t *testing.T) {
	if got := ProcessFloor(4, 0); got != (3*4+50)*DefaultHTTPDWorkers {
		t.Fatalf("ProcessFloor(4, 0) = %d", got)
	}
	if got := ProcessFloor(6, 2); got != 136 {
		t.Fatalf("ProcessFloor(6, 2) = %d", got)
	}
	for _, workers := range []int{0, 1, 4, 16} {
		s := baseServer()
		s.HTTPDWorkers = workers
		s.Sites = s.Sites[:1]
		s.Sites[0].Limits = Limits{PHPChildren: 4, Processes: ProcessFloor(4, workers)}
		if err := Validate(s); err != nil {
			t.Fatalf("workers %d: the floor is refused: %v", workers, err)
		}
		s.Sites[0].Limits.Processes--
		if err := Validate(s); !errors.Is(err, ErrInvalid) {
			t.Fatalf("workers %d: one below the floor is accepted: %v", workers, err)
		}
	}
}
