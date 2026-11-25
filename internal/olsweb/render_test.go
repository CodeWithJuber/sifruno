package olsweb

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/golden")

func loadSpec(t *testing.T, path string) Server {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Server
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return s
}

// TestGolden renders each testdata/golden/<case>/spec.json and compares the
// whole file set, both ways, with testdata/golden/<case>/want/.
func TestGolden(t *testing.T) {
	cases := []string{"wordpress", "second-php", "suspended", "namespace-limits", "certificate", "no-certificate", "account-limits", "aliases-redirects", "protected-folders"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("testdata", "golden", name)
			files, err := Render(loadSpec(t, filepath.Join(dir, "spec.json")))
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(dir, "want")
			if *update {
				if err := os.RemoveAll(want); err != nil {
					t.Fatal(err)
				}
				for path, data := range files {
					target := filepath.Join(want, filepath.FromSlash(path))
					if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, data, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			found := map[string]bool{}
			err = filepath.WalkDir(want, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				rel, err := filepath.Rel(want, path)
				if err != nil {
					return err
				}
				rel = filepath.ToSlash(rel)
				found[rel] = true
				golden, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				got, ok := files[rel]
				if !ok {
					t.Errorf("golden file %s was not rendered", rel)
				} else if !bytes.Equal(got, golden) {
					t.Errorf("%s differs from golden (run go test -run TestGolden -update to inspect)\n--- got\n%s", rel, got)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for path := range files {
				if !found[path] {
					t.Errorf("rendered %s has no golden file", path)
				}
			}
		})
	}
}

func baseServer() Server {
	return Server{
		Listeners: []Listener{
			{Name: "http", Address: "*", Port: 80},
			{Name: "https", Address: "*", Port: 443, Secure: true, CertFile: TLSRoot + "/listener-fullchain.pem", KeyFile: TLSRoot + "/listener-privkey.pem"},
		},
		Sites: []Site{
			{Name: "blog", Username: "blogowner", Group: "blogowner", Domains: []string{"example.com", "www.example.com"}, DocRoot: "/home/blogowner/public_html", PHPVersion: "8.3", TLS: TLS{CertFile: TLSRoot + "/blog/fullchain.pem", KeyFile: TLSRoot + "/blog/privkey.pem"}},
			{Name: "legacy", Username: "legacyapp", Group: "legacyapp", Domains: []string{"legacy.example.net"}, DocRoot: "/home/legacyapp/www/htdocs", PHPVersion: "8.1", Limits: Limits{PHPChildren: 2}},
			{Name: "paused", Username: "pauseduser", Group: "pauseduser", Domains: []string{"paused.example.org"}, DocRoot: "/home/pauseduser/public_html", PHPVersion: "8.2", Suspended: true},
			{Name: "iso", Username: "isouser", Group: "isouser", Domains: []string{"isolated.example.com", "www.isolated.example.com"}, DocRoot: "/home/isouser/public_html", PHPVersion: "8.4", Isolation: Isolation{Namespace: true, CGroups: true}, Limits: Limits{MemoryMiB: 512, PHPChildren: 6}},
			{Name: "shop", Username: "blogowner", Group: "blogowner", Domains: []string{"shop.example.com"}, DocRoot: "/home/blogowner/shop", PHPVersion: "8.3"},
		},
	}
}

func TestRenderDeterministic(t *testing.T) {
	base := baseServer()
	want, err := Render(base)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 50; i++ {
		s := baseServer()
		rng.Shuffle(len(s.Sites), func(a, b int) { s.Sites[a], s.Sites[b] = s.Sites[b], s.Sites[a] })
		rng.Shuffle(len(s.Listeners), func(a, b int) { s.Listeners[a], s.Listeners[b] = s.Listeners[b], s.Listeners[a] })
		got, err := Render(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("shuffle %d: %d files, want %d", i, len(got), len(want))
		}
		for path, data := range want {
			if !bytes.Equal(got[path], data) {
				t.Fatalf("shuffle %d: %s differs", i, path)
			}
		}
	}
	// Render must not reorder the caller's slices.
	if base.Sites[0].Name != "blog" || base.Listeners[0].Name != "http" {
		t.Fatal("Render changed the caller's input order")
	}
	for path, data := range want {
		if !bytes.HasSuffix(data, []byte("}\n")) {
			t.Errorf("%s does not end with a closing brace and newline", path)
		}
	}
}

func TestRenderShape(t *testing.T) {
	files, err := Render(baseServer())
	if err != nil {
		t.Fatal(err)
	}
	server := string(files[ServerConfigPath])
	paused := string(files[VhostConfigPath("paused")])
	iso := string(files[VhostConfigPath("iso")])
	blog := string(files[VhostConfigPath("blog")])
	legacy := string(files[VhostConfigPath("legacy")])

	httpsBlock := server[strings.Index(server, "listener sifruno-https {"):]
	httpBlock := server[strings.Index(server, "listener sifruno-http {"):strings.Index(server, "listener sifruno-https {")]
	for _, want := range []string{"map                     sifruno-blog example.com, www.example.com", "map                     sifruno-legacy legacy.example.net", "map                     sifruno-paused paused.example.org"} {
		if !strings.Contains(httpBlock, want) {
			t.Errorf("http listener lacks %q", want)
		}
	}
	if strings.Contains(httpsBlock, "sifruno-legacy") || strings.Contains(httpsBlock, "sifruno-paused") || !strings.Contains(httpsBlock, "sifruno-blog example.com") {
		t.Errorf("https listener must map only sites with their own certificate:\n%s", httpsBlock)
	}
	if !strings.Contains(server, "virtualhost sifruno-paused {\n  vhRoot                  /var/lib/sifruno-suspended/\n  configFile              /usr/local/lsws/conf/vhosts/sifruno-paused/vhconf.conf\n  allowSymbolLink         1\n  enableScript            0\n") {
		t.Error("suspended vhost does not disable scripts")
	}
	for _, forbidden := range []string{"extprocessor", "scripthandler", "lsphp", "namespace", "autoLoadHtaccess        1"} {
		if strings.Contains(paused, forbidden) {
			t.Errorf("suspended vhconf contains %q", forbidden)
		}
	}
	if !strings.Contains(paused, "RewriteRule .* - [F,L]\n") {
		t.Error("suspended vhconf does not refuse every request")
	}
	for _, want := range []string{"namespace                 2\n", "cgroups                   2\n", "memSoftLimit            512M\n", "procSoftLimit           1000\n", "env                     PHP_LSAPI_CHILDREN=6\n", "maxConns                6\n"} {
		if !strings.Contains(iso, want) {
			t.Errorf("isolated vhconf lacks %q", want)
		}
	}
	if strings.Contains(blog, "namespace") || strings.Contains(blog, "cgroups") {
		t.Error("namespace or cgroups rendered without being requested")
	}
	if !strings.Contains(legacy, "path                    /usr/local/lsws/lsphp81/bin/lsphp\n") || !strings.Contains(blog, "path                    /usr/local/lsws/lsphp83/bin/lsphp\n") {
		t.Error("PHP version does not select its lsphp binary")
	}
	if strings.Contains(legacy, "vhssl") || !strings.Contains(blog, "vhssl  {\n  keyFile                 /etc/sifruno/tls/blog/privkey.pem\n") {
		t.Error("vhssl rendered for the wrong sites")
	}
	// Two sites of one account get separate lsphp apps and sockets.
	shop := string(files[VhostConfigPath("shop")])
	if !strings.Contains(shop, "uds://tmp/lshttpd/sifruno-shop.sock") || !strings.Contains(blog, "uds://tmp/lshttpd/sifruno-blog.sock") {
		t.Error("sites do not get their own lsphp socket")
	}
}

// A suspended site names no path under the homes root, neither in its
// vhconf.conf nor in its virtualhost block: its config test then depends on
// nothing the tenant controls. Resumed, the same site renders its own home
// and document root again.
func TestSuspendedSiteNamesNoTenantPath(t *testing.T) {
	render := func(suspended bool) (vhost, block string) {
		t.Helper()
		s := baseServer()
		s.Sites[2].Suspended = suspended
		files, err := Render(s)
		if err != nil {
			t.Fatal(err)
		}
		server := string(files[ServerConfigPath])
		block = server[strings.Index(server, "virtualhost sifruno-paused {"):]
		block = block[:strings.Index(block, "\n}\n")]
		return string(files[VhostConfigPath("paused")]), block
	}
	vhost, block := render(true)
	for name, text := range map[string]string{"vhconf.conf": vhost, "virtualhost block": block} {
		if strings.Contains(text, HomeRoot+"/") || strings.Contains(text, "public_html") {
			t.Errorf("suspended %s names a path in the tenant's home:\n%s", name, text)
		}
	}
	if !strings.Contains(vhost, "\ndocRoot                   /var/lib/sifruno-suspended/\n") || !strings.Contains(block, "\n  vhRoot                  /var/lib/sifruno-suspended/\n") {
		t.Errorf("suspended site does not use SuspendedDocRoot:\n%s\n%s", block, vhost)
	}
	vhost, block = render(false)
	if !strings.Contains(vhost, "\ndocRoot                   /home/pauseduser/public_html/\n") || !strings.Contains(block, "\n  vhRoot                  /home/pauseduser/\n") || strings.Contains(vhost+block, SuspendedDocRoot) {
		t.Errorf("resumed site does not use its own home again:\n%s\n%s", block, vhost)
	}
}

// Every active site gets the cache module with its own store outside every
// home and nothing cached unless its response asks; a suspended site gets
// the module off, with no store and nothing to look up.
func TestCacheModulePerSite(t *testing.T) {
	files, err := Render(baseServer())
	if err != nil {
		t.Fatal(err)
	}
	block := func(name string) string {
		t.Helper()
		vhost := string(files[VhostConfigPath(name)])
		if strings.Count(vhost, "\nmodule ") != 1 {
			t.Fatalf("%s: not one module block:\n%s", name, vhost)
		}
		b := vhost[strings.Index(vhost, "\nmodule cache {\n")+1:]
		return b[:strings.Index(b, "\n}\n")+3]
	}
	stores := map[string]bool{}
	for _, name := range []string{"blog", "legacy", "iso", "shop"} {
		b := block(name)
		want := "module cache {\n" +
			"  ls_enabled              1\n" +
			"  storagePath             /var/lib/sifruno-lscache/sifruno-" + name + "\n" +
			"  checkPublicCache        1\n" +
			"  checkPrivateCache       1\n" +
			"  enableCache             0\n" +
			"  enablePrivateCache      0\n" +
			"  qsCache                 1\n" +
			"  reqCookieCache          1\n" +
			"  respCookieCache         1\n" +
			"  ignoreReqCacheCtrl      1\n" +
			"  ignoreRespCacheCtrl     0\n" +
			"  expireInSeconds         3600\n" +
			"  privateExpireInSeconds  3600\n" +
			"  maxStaleAge             200\n" +
			"  maxCacheObjSize         10000000\n" +
			"}\n"
		if b != want {
			t.Errorf("%s cache block:\n%s", name, b)
		}
		store := strings.Fields(b[strings.Index(b, "storagePath"):])[1]
		if stores[store] || strings.HasPrefix(store, HomeRoot+"/") || !strings.HasPrefix(store, CacheRoot+"/"+NamePrefix) {
			t.Errorf("%s: store %s is shared or not in %s", name, store, CacheRoot)
		}
		stores[store] = true
	}
	// Two sites of one account still get one store each.
	if !stores[CacheRoot+"/sifruno-blog"] || !stores[CacheRoot+"/sifruno-shop"] {
		t.Error("sites of one account share a store")
	}
	const off = "module cache {\n" +
		"  ls_enabled              0\n" +
		"  checkPublicCache        0\n" +
		"  checkPrivateCache       0\n" +
		"  enableCache             0\n" +
		"  enablePrivateCache      0\n" +
		"}\n"
	if b := block("paused"); b != off {
		t.Errorf("suspended cache block:\n%s", b)
	}
	// The module block sits before the vhost rewrite block, so it never
	// joins the rules heredoc.
	for _, name := range []string{"blog", "paused"} {
		vhost := string(files[VhostConfigPath(name)])
		if strings.Index(vhost, "\nmodule cache {\n") > strings.Index(vhost, "\nrewrite  {\n") {
			t.Errorf("%s: module block after the rewrite block", name)
		}
	}
}

// Every vhost, suspended or not, with or without a certificate, maps the
// HTTP-01 path to the shared challenge directory as static files only.
func TestACMEChallengeContext(t *testing.T) {
	files, err := Render(baseServer())
	if err != nil {
		t.Fatal(err)
	}
	const want = "\ncontext /.well-known/acme-challenge/ {\n" +
		"  location                /var/lib/sifruno-acme/\n" +
		"  allowBrowse             1\n" +
		"  autoIndex               0\n" +
		"  forceType               text/plain\n" +
		"  rewrite  {\n" +
		"    enable                0\n" +
		"  }\n" +
		"}\n"
	for _, name := range []string{"blog", "legacy", "paused", "iso", "shop"} {
		vhost := string(files[VhostConfigPath(name)])
		if strings.Count(vhost, "context ") != 1 || !strings.Contains(vhost, want) {
			t.Errorf("%s: no single challenge context:\n%s", name, vhost)
		}
		// The context comes before the vhost rewrite block, which keeps its
		// deny rules (or the suspended refusal) unchanged.
		if strings.Index(vhost, want) > strings.Index(vhost, "\nrewrite  {\n") {
			t.Errorf("%s: challenge context after the vhost rewrite block", name)
		}
	}
	if !strings.Contains(string(files[VhostConfigPath("blog")]), denyRules[0]+"\n") {
		t.Error("the deny rules for other dot paths are gone")
	}
}

// The secure listener exists only while some site has its own certificate,
// and then maps only those sites.
func TestSecureListenerOnlyWithCertificates(t *testing.T) {
	s := baseServer()
	for i := range s.Sites {
		s.Sites[i].TLS = TLS{}
	}
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	server := string(files[ServerConfigPath])
	if strings.Contains(server, "listener sifruno-https") || strings.Contains(server, "secure                  1") {
		t.Errorf("secure listener rendered without any certificate:\n%s", server)
	}
	if !strings.Contains(server, "listener sifruno-http {") {
		t.Error("the plain listener went away")
	}
	for path, data := range files {
		if strings.Contains(string(data), "vhssl") {
			t.Errorf("%s has vhssl without a certificate", path)
		}
	}

	s.Sites[4].TLS = TLS{CertFile: TLSRoot + "/shop/cert.pem", KeyFile: TLSRoot + "/shop/key.pem"}
	files, err = Render(s)
	if err != nil {
		t.Fatal(err)
	}
	server = string(files[ServerConfigPath])
	start := strings.Index(server, "listener sifruno-https {")
	if start < 0 {
		t.Fatalf("secure listener missing with one certificate:\n%s", server)
	}
	https := server[start:]
	if strings.Count(https, "map ") != 1 || !strings.Contains(https, "map                     sifruno-shop shop.example.com\n") {
		t.Errorf("secure listener must map only the site with a certificate:\n%s", https)
	}
	if !strings.Contains(string(files[VhostConfigPath("shop")]), "vhssl  {\n  keyFile                 /etc/sifruno/tls/shop/key.pem\n  certFile                /etc/sifruno/tls/shop/cert.pem\n  certChain               1\n}\n") {
		t.Error("the site with a certificate has no vhssl block")
	}
	if strings.Contains(string(files[VhostConfigPath("blog")]), "vhssl") {
		t.Error("vhssl rendered for a site without a certificate")
	}
}

// TestDenyRules runs the rendered rule patterns, with Go's regexp standing in
// for OpenLiteSpeed's PCRE (the patterns use only syntax both share), against
// paths WordPress must keep and paths that must be refused.
func TestDenyRules(t *testing.T) {
	var patterns []*regexp.Regexp
	for _, rule := range denyRules {
		fields := strings.Fields(rule)
		if len(fields) != 4 || fields[0] != "RewriteRule" || fields[2] != "-" || fields[3] != "[F,L,NC]" {
			t.Fatalf("unexpected rule shape %q", rule)
		}
		patterns = append(patterns, regexp.MustCompile("(?i)"+fields[1]))
	}
	denied := func(path string) bool {
		for _, p := range patterns {
			if p.MatchString(path) {
				return true
			}
		}
		return false
	}
	for _, path := range []string{
		"/.htaccess", "/.htpasswd", "/wp-admin/.htaccess", "/.git/config", "/.git/HEAD", "/sub/.git/index",
		"/.gitignore", "/.svn/entries", "/.hg/store/data", "/.env", "/.env.local", "/app/.env.production",
		"/.user.ini", "/wp-admin/.user.ini", "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save",
		"/wp-config.php.orig", "/.wp-config.php.swp", "/blog/wp-config.php.old", "/WP-CONFIG.PHP.BAK",
		"/wp-config.bak", "/wp-config.old", "/wp-config.orig", "/wp-config.save", "/wp-config.swp", "/wp-config.txt",
		"/wp-content/debug.log", ".htaccess", "wp-config.php.bak",
	} {
		if !denied(path) {
			t.Errorf("%s is not denied", path)
		}
	}
	for _, path := range []string{
		"/", "/index.php", "/wp-login.php", "/wp-admin/", "/wp-admin/admin-ajax.php", "/wp-admin/load-styles.php",
		"/wp-json/wp/v2/posts", "/wp-cron.php", "/xmlrpc.php", "/wp-config.php", "/wp-config-sample.php",
		"/wp-content/uploads/2026/11/photo.jpg", "/wp-content/plugins/akismet/readme.txt",
		"/wp-content/themes/twentytwentyfive/style.css", "/wp-includes/js/jquery/jquery.min.js",
		"/.well-known/acme-challenge/abc123", "/.well-known/security.txt", "/environment.html", "/feed/",
		"/sitemap.xml", "/wp-sitemap.xml", "/2026/11/hello-world/", "/wp-content/cache/debug.log.html",
	} {
		if denied(path) {
			t.Errorf("%s is denied but WordPress needs it", path)
		}
	}
}
