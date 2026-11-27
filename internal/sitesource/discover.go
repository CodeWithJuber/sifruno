package sitesource

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"sifruno/internal/cpsource"
	"sifruno/internal/sitemodel"
)

// ServerSite is one website another Linux server's web server serves, as
// its virtual host (Apache) or server block (nginx) names it.
type ServerSite struct {
	Domain  string
	Aliases []string
	// WWW says the block names www.<Domain> too.
	WWW bool
	// Server is "apache" or "nginx"; Where is the file and line of the
	// block ("/etc/nginx/conf.d/shop.conf line 1").
	Server  string
	Where   string
	DocRoot string
	// PHPSource is "phpX.Y-fpm" once something names the version;
	// PHPPass is the handler or fastcgi_pass as written, for the pool.
	PHPSource string
	PHPPass   string
	TLS       *TLSFiles
	// Htaccess holds an nginx site's converted rules as the .htaccess
	// files OpenLiteSpeed and the copy's own scan read, by folder relative
	// to the document root ("" for the root itself).
	Htaccess map[string]string
	// Refused are the lines that keep the site from moving as it is;
	// Notes what moves differently, or does not move, without stopping it.
	Refused []sitemodel.Item
	Notes   []sitemodel.Item
}

// Movable reports a site with a document root the copy may read and
// nothing refused.
func (s ServerSite) Movable() bool {
	return ValidDocRoot(s.DocRoot) && len(s.Refused) == 0
}

// MaxServerSites bounds the websites read from one server.
const MaxServerSites = 500

// ServerSites assembles the old server's websites from nginx's files and
// Apache's virtual hosts. Blocks that name the same domain are one site:
// one that only sends http to https adds a note, one with the same root
// and rules adds its certificate, and any other is a refusal, since which
// one answers then depends on the address. A domain both web servers name
// is refused too (nginx in front of Apache, as Plesk and HestiaCP run
// them): this version moves a site one web server serves. Blocks that name
// no domain (nginx's default "_", localhost) are left out.
func ServerSites(nginx []*NginxFile, apache []ApacheSite) []ServerSite {
	byDomain := map[string][]ServerSite{}
	var order []string
	add := func(s ServerSite, names []string) {
		domain, aliases, www, skipped := primary(names)
		if domain == "" {
			return
		}
		s.Domain, s.Aliases, s.WWW = domain, aliases, www
		for _, n := range skipped {
			s.Notes = append(s.Notes, sitemodel.Item{Part: "domain", Text: "The name " + clip(n) + " is not a plain domain, so it is not added here.", Where: s.Where})
		}
		if _, seen := byDomain[domain]; !seen {
			order = append(order, domain)
		}
		byDomain[domain] = append(byDomain[domain], s)
	}
	for _, f := range nginx {
		for _, srv := range f.Servers() {
			add(nginxBlock(srv), srv.Names)
		}
	}
	for _, a := range apache {
		add(apacheBlock(a), a.Names)
	}
	sort.Strings(order)
	out := []ServerSite{}
	for _, domain := range order {
		if len(out) == MaxServerSites {
			break
		}
		out = append(out, merge(byDomain[domain]))
	}
	return out
}

// primary picks a block's domain from its names: the first plain domain,
// without "www." when the bare name is listed too. www says www.<domain>
// is listed; aliases are the other plain domains; skipped the names that
// are not plain domains, other than nginx's catch-all ones.
func primary(names []string) (domain string, aliases []string, www bool, skipped []string) {
	var valid []string
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		switch {
		case cpsource.ValidDomain(n):
			if !slices.Contains(valid, n) {
				valid = append(valid, n)
			}
		case n == "_" || n == "" || n == "localhost" || n == `""`:
		default:
			skipped = append(skipped, n)
		}
	}
	if len(valid) == 0 {
		return "", nil, false, nil
	}
	domain = valid[0]
	if bare, ok := strings.CutPrefix(domain, "www."); ok && slices.Contains(valid, bare) {
		domain = bare
	}
	aliases = []string{}
	for _, n := range valid {
		switch {
		case n == domain:
		case n == "www."+domain:
			www = true
		case len(aliases) < sitemodel.MaxAliases:
			aliases = append(aliases, n)
		}
	}
	return domain, aliases, www, skipped
}

func cleanRoot(root string) string {
	if len(root) > 1 {
		root = strings.TrimRight(root, "/")
	}
	return root
}

func nginxBlock(s Server) ServerSite {
	c := ConvertNginx(s)
	where := fmt.Sprintf("%s line %d", s.File, s.Line)
	site := ServerSite{Server: "nginx", Where: where, DocRoot: cleanRoot(s.Root), PHPSource: c.PHPSource, PHPPass: c.PHPPass, TLS: c.TLS,
		Htaccess: nginxHtaccess(c, where), Refused: slices.Clone(c.Refused), Notes: slices.Clone(c.Notes)}
	for _, p := range c.Settings {
		site.Notes = append(site.Notes, sitemodel.Item{Part: "php", Text: "The PHP setting " + clip(p.Name) + " = " + clip(p.Value) + " (fastcgi_param PHP_VALUE) is not carried; set it again in the website's PHP settings.", Where: p.From})
	}
	return site
}

func apacheBlock(a ApacheSite) ServerSite {
	return ServerSite{Server: "apache", Where: fmt.Sprintf("%s line %d", a.File, a.Line), DocRoot: cleanRoot(a.Root), PHPSource: a.PHPSource, PHPPass: a.PHPHandler, TLS: a.TLS,
		Refused: slices.Clone(a.Refused), Notes: slices.Clone(a.Notes)}
}

// httpsOnly reports an nginx block that only sends http to https.
func httpsOnly(s ServerSite) bool {
	return s.Server == "nginx" && s.DocRoot == "" && len(s.Refused) == 0 && len(s.Htaccess) == 0 && s.PHPPass == "" &&
		slices.ContainsFunc(s.Notes, func(i sitemodel.Item) bool { return strings.Contains(i.Text, "sent every http request to https") })
}

// rules is what a block does with requests, to compare two blocks.
func rules(s ServerSite) string {
	keys := make([]string, 0, len(s.Htaccess))
	for k := range s.Htaccess {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		// The first line names the block; the rules follow it.
		_, body, _ := strings.Cut(s.Htaccess[k], "\n")
		b.WriteString(k + "\x00" + body + "\x00")
	}
	b.WriteString(s.PHPSource + "\x00" + s.PHPPass)
	return b.String()
}

func merge(blocks []ServerSite) ServerSite {
	first := slices.IndexFunc(blocks, func(s ServerSite) bool { return s.DocRoot != "" })
	if first < 0 {
		first = 0
	}
	site := blocks[first]
	site.Aliases = slices.Clone(site.Aliases)
	for i, b := range blocks {
		switch {
		case i == first:
		case b.Server != site.Server:
			site.Refused = append(site.Refused, sitemodel.Item{Part: "rule", Text: "Both nginx (" + whereOf(blocks, "nginx") + ") and Apache (" + whereOf(blocks, "apache") + ") name " + site.Domain + ": nginx passes its requests on to Apache, or one of them is not used. This version moves a website one web server serves.", Where: b.Where})
		case httpsOnly(b):
			site.Notes = appendItems(site.Notes, b.Notes)
		case b.DocRoot != site.DocRoot || rules(b) != rules(site):
			site.Refused = append(site.Refused, sitemodel.Item{Part: "rule", Text: "Another block for " + site.Domain + " serves it from another folder or with other rules, so what answers depends on how a visitor comes in. This version moves a website one block serves, or blocks that serve it the same way.", Where: b.Where})
		default:
			if site.TLS == nil {
				site.TLS = b.TLS
			}
			site.WWW = site.WWW || b.WWW
			for _, a := range b.Aliases {
				if !slices.Contains(site.Aliases, a) && len(site.Aliases) < sitemodel.MaxAliases {
					site.Aliases = append(site.Aliases, a)
				}
			}
			site.Refused = appendItems(site.Refused, b.Refused)
			site.Notes = appendItems(site.Notes, b.Notes)
		}
	}
	switch {
	case site.DocRoot == "" && len(site.Refused) == 0:
		site.Refused = append(site.Refused, sitemodel.Item{Part: "rule", Text: "The block names no folder of files (no root), so there is nothing to copy.", Where: site.Where})
	case site.DocRoot != "" && !ValidDocRoot(site.DocRoot):
		site.Refused = append(site.Refused, sitemodel.Item{Part: "file", Text: "The website's folder " + clip(site.DocRoot) + " is not below /var/www, /srv or /home (or nginx's /usr/share/nginx/html), or its name has characters this version does not copy. Copying it could hand system files to the website.", Where: site.Where})
	}
	return site
}

func whereOf(blocks []ServerSite, server string) string {
	for _, b := range blocks {
		if b.Server == server {
			return b.Where
		}
	}
	return ""
}

// appendItems adds the items not already listed.
func appendItems(list, more []sitemodel.Item) []sitemodel.Item {
	for _, item := range more {
		if !slices.Contains(list, item) {
			list = append(list, item)
		}
	}
	return list
}

// nginxHtaccess writes an nginx block's converted rules as .htaccess
// files: the redirects (RedirectMatch on the exact path, as nginx's "="
// location matched it) and rewrite lines in the document root's, and each
// closed folder as its own file that denies everyone. The copy's .htaccess
// scan then converts them as it converts an Apache site's, so they reach
// OpenLiteSpeed the same way and verify checks them the same way.
func nginxHtaccess(c Conversion, where string) map[string]string {
	files := map[string]string{}
	header := "# Moved by Sifruno from nginx: " + printable(where) + "\n"
	var root []string
	for _, r := range c.Redirects {
		root = append(root, "RedirectMatch "+strconv.Itoa(r.Status)+" ^"+regexp.QuoteMeta(r.Path)+"$ "+r.Target)
	}
	root = append(root, c.Rewrites...)
	if len(root) > 0 {
		files[""] = header + strings.Join(root, "\n") + "\n"
	}
	for _, f := range c.Folders {
		files[strings.Trim(f, "/")] = header + "Require all denied\n"
	}
	return files
}

// printable keeps a file name for a comment line: printable ASCII only.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

// socketOf reads the address PHP is handed to from an nginx fastcgi_pass
// or an Apache handler: a unix socket's path, or host:port.
func socketOf(pass string) string {
	pass = strings.Trim(strings.TrimSpace(pass), `"'`)
	pass = strings.TrimPrefix(pass, "proxy:")
	if rest, ok := strings.CutPrefix(pass, "unix:"); ok {
		socket, _, _ := strings.Cut(rest, "|")
		return socket
	}
	if rest, ok := strings.CutPrefix(pass, "fcgi://"); ok {
		hostPort, _, _ := strings.Cut(rest, "/")
		return hostPort
	}
	return pass
}

// listens reports a pool's listen value that is the address given: the
// same socket, or the same port (a pool listening on "9000" takes
// 127.0.0.1:9000).
func listens(pool FPMPool, address string) bool {
	for _, l := range pool.Listen {
		if l == address {
			return true
		}
		if _, port, ok := strings.Cut(address, ":"); ok && l == port {
			return true
		}
	}
	return false
}

// ResolvePHP names the site's PHP version when its handler does not: from
// the PHP-FPM pool that listens where the handler points, or, when the
// virtual host names no handler (RHEL's php.conf sets one for every site),
// from the server's only PHP-FPM. With several and no pool, it stays
// unknown.
func (s *ServerSite) ResolvePHP(pools []FPMPool, versions map[string]string) {
	if s.PHPSource != "" {
		return
	}
	if address := socketOf(s.PHPPass); address != "" {
		for _, p := range pools {
			if !listens(p, address) {
				continue
			}
			v := p.Version
			if v == "" {
				v = versions["/usr/sbin/php-fpm"]
			}
			if v != "" {
				s.PHPSource = "php" + v + "-fpm"
				return
			}
		}
	}
	distinct := []string{}
	for _, v := range versions {
		if !slices.Contains(distinct, v) {
			distinct = append(distinct, v)
		}
	}
	if len(distinct) == 1 {
		s.PHPSource = "php" + distinct[0] + "-fpm"
		s.Notes = append(s.Notes, sitemodel.Item{Part: "php", Text: "The website's block names no PHP-FPM pool of its own; the old server runs PHP " + distinct[0] + " only, so that is its version.", Where: s.Where})
	}
}
