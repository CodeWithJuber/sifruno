package olsweb

import (
	"fmt"
	"net"
	"net/netip"
	pathpkg "path"
	"regexp"
	"strings"
)

var (
	siteNamePattern     = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	listenerNamePattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,14}[a-z0-9])?$`)
	usernamePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)
	tlsFileNamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// Validate checks a spec without rendering it. Render calls it first; it is
// exported so a caller can refuse input before storing it.
func Validate(s Server) error {
	_, err := normalize(s)
	return err
}

// ProcessFloor is the lowest procSoftLimit and procHardLimit OpenLiteSpeed
// 1.9.4 keeps for an lsphp app with phpChildren LSAPI children: below
// (3 x children + 50) x httpdWorkers it raises both to that number and logs
// a notice (LocalWorkerConfig::config in src/extensions/localworkerconfig.cpp,
// where Max connections equals the children here). httpdWorkers 0 assumes
// DefaultHTTPDWorkers, as a Server does. A caller that derives a site's
// process limit from something else uses it to render a number
// OpenLiteSpeed keeps.
func ProcessFloor(phpChildren, httpdWorkers int) int {
	if httpdWorkers == 0 {
		httpdWorkers = DefaultHTTPDWorkers
	}
	return (3*phpChildren + 50) * httpdWorkers
}

// site is a validated Site with its defaults filled in.
type site struct {
	Site
	children  int
	memoryMiB int
	processes int
	phpBinary string
}

// normalize validates s and returns the sites with defaults applied, in input
// order. Every string that reaches the output is checked here against a
// pattern that excludes whitespace, braces, quotes, '$', '#', '<', '\' and
// control characters, which is what keeps any value from ending a line,
// opening or closing a block, starting a heredoc or expanding a variable.
func normalize(s Server) ([]site, error) {
	workers := s.HTTPDWorkers
	if workers == 0 {
		workers = DefaultHTTPDWorkers
	}
	if workers < 1 || workers > 16 {
		return nil, fieldErr("httpd_workers", "must be 0 (assume %d) or 1 to 16", DefaultHTTPDWorkers)
	}
	if len(s.Listeners) > MaxListeners {
		return nil, fieldErr("listeners", "at most %d listeners", MaxListeners)
	}
	if len(s.Sites) > MaxSites {
		return nil, fieldErr("sites", "at most %d sites", MaxSites)
	}
	if err := validateListeners(s.Listeners); err != nil {
		return nil, err
	}

	out := make([]site, 0, len(s.Sites))
	names := map[string]int{}
	// hostKeys maps each host name OpenLiteSpeed will register to the site
	// index that owns it. OpenLiteSpeed strips one leading "www." when it maps
	// a domain (vhostmap.cpp) and falls back from www.<host> to <host> at
	// request time, so example.com and www.example.com are one key.
	hostKeys := map[string]int{}
	for i, in := range s.Sites {
		field := fmt.Sprintf("sites[%d]", i)
		v, err := validateSite(field, in, workers)
		if err != nil {
			return nil, err
		}
		if j, dup := names[in.Name]; dup {
			return nil, fieldErr(field+".name", "duplicates sites[%d].name", j)
		}
		names[in.Name] = i
		seen := map[string]bool{}
		for k, d := range in.Domains {
			if seen[d] {
				return nil, fieldErr(fmt.Sprintf("%s.domains[%d]", field, k), "listed twice")
			}
			seen[d] = true
			key := hostKey(d)
			if j, taken := hostKeys[key]; taken && j != i {
				return nil, fieldErr(fmt.Sprintf("%s.domains[%d]", field, k), "%s is already served by sites[%d]", key, j)
			}
			hostKeys[key] = i
		}
		out = append(out, v)
	}
	if err := checkFolderListeners(s.Listeners, s.Sites); err != nil {
		return nil, err
	}
	return out, nil
}

func validateListeners(listeners []Listener) error {
	names := map[string]int{}
	binds := map[string]int{}
	ports := map[int][]int{}
	for i, l := range listeners {
		field := fmt.Sprintf("listeners[%d]", i)
		if !listenerNamePattern.MatchString(l.Name) {
			return fieldErr(field+".name", "must match %s", listenerNamePattern)
		}
		if j, dup := names[l.Name]; dup {
			return fieldErr(field+".name", "duplicates listeners[%d].name", j)
		}
		names[l.Name] = i
		if _, err := listenerAddress(l); err != nil {
			return fieldErr(field+".address", "%v", err)
		}
		if l.Port < 1 || l.Port > 65535 {
			return fieldErr(field+".port", "must be 1 to 65535")
		}
		bind := l.Address + " " + fmt.Sprint(l.Port)
		if j, dup := binds[bind]; dup {
			return fieldErr(field+".address", "same address and port as listeners[%d]", j)
		}
		binds[bind] = i
		// A wildcard bind and a specific bind on one port cannot both open.
		for _, j := range ports[l.Port] {
			if l.Address == "*" || listeners[j].Address == "*" {
				return fieldErr(field+".port", "port %d is also bound by listeners[%d] and one of them is *", l.Port, j)
			}
		}
		ports[l.Port] = append(ports[l.Port], i)
		if !l.Secure {
			if l.CertFile != "" || l.KeyFile != "" {
				return fieldErr(field+".cert_file", "only a secure listener takes a certificate")
			}
			continue
		}
		if err := checkListenerTLSFile(l.CertFile); err != nil {
			return fieldErr(field+".cert_file", "%v", err)
		}
		if err := checkListenerTLSFile(l.KeyFile); err != nil {
			return fieldErr(field+".key_file", "%v", err)
		}
		if l.CertFile == l.KeyFile {
			return fieldErr(field+".key_file", "must differ from cert_file")
		}
	}
	return nil
}

// listenerAddress returns the address as OpenLiteSpeed's listener expects it.
func listenerAddress(l Listener) (string, error) {
	port := fmt.Sprint(l.Port)
	if l.Address == "*" {
		return "*:" + port, nil
	}
	a, err := netip.ParseAddr(l.Address)
	if err != nil || a.Zone() != "" || a.String() != l.Address {
		return "", fmt.Errorf("must be * or a canonical IPv4 or IPv6 address without a zone")
	}
	return net.JoinHostPort(a.String(), port), nil
}

func validateSite(field string, in Site, workers int) (site, error) {
	if !siteNamePattern.MatchString(in.Name) {
		return site{}, fieldErr(field+".name", "must match %s", siteNamePattern)
	}
	if !usernamePattern.MatchString(in.Username) {
		return site{}, fieldErr(field+".username", "must match %s", usernamePattern)
	}
	if reservedUsernames[in.Username] {
		return site{}, fieldErr(field+".username", "%s is a reserved system account", in.Username)
	}
	if in.Group != in.Username {
		return site{}, fieldErr(field+".group", "must equal username (private group)")
	}
	if len(in.Domains) == 0 || len(in.Domains) > MaxDomainsPerSite {
		return site{}, fieldErr(field+".domains", "must list 1 to %d domains", MaxDomainsPerSite)
	}
	for k, d := range in.Domains {
		f := fmt.Sprintf("%s.domains[%d]", field, k)
		if !validDomain(d) {
			return site{}, fieldErr(f, "must be a lowercase DNS name with at least two labels")
		}
		key := hostKey(d)
		if strings.HasPrefix(key, "www.") || !strings.Contains(key, ".") {
			// OpenLiteSpeed would register www.www.x as www.x, capturing
			// requests for another site's www name, and www.tld as a bare TLD.
			return site{}, fieldErr(f, "must not be www.www.* or www.<single label>")
		}
	}
	home := pathpkg.Join(HomeRoot, in.Username)
	if !cleanPath(in.DocRoot) || !strings.HasPrefix(in.DocRoot, home+"/") {
		return site{}, fieldErr(field+".doc_root", "must be a clean absolute path strictly inside %s/ without hidden components", home)
	}
	binary, ok := phpBinaries[in.PHPVersion]
	if !ok {
		return site{}, fieldErr(field+".php_version", "must be one of 8.1, 8.2, 8.3, 8.4")
	}
	v := site{Site: in, phpBinary: binary}
	v.children = in.Limits.PHPChildren
	if v.children == 0 {
		v.children = DefaultPHPChildren
	}
	if v.children < 1 || v.children > 100 {
		return site{}, fieldErr(field+".limits.php_children", "must be 0 (default %d) or 1 to 100", DefaultPHPChildren)
	}
	v.memoryMiB = in.Limits.MemoryMiB
	if v.memoryMiB == 0 {
		v.memoryMiB = DefaultMemoryMiB
	}
	if v.memoryMiB < 256 || v.memoryMiB > 65536 {
		return site{}, fieldErr(field+".limits.memory_mib", "must be 0 (default %d) or 256 to 65536", DefaultMemoryMiB)
	}
	// OpenLiteSpeed raises any process limit below this floor itself and logs
	// a notice (localworkerconfig.cpp), so the rendered number would not be
	// the one in force. Refusing it keeps the spec honest.
	floor := ProcessFloor(v.children, workers)
	v.processes = in.Limits.Processes
	if v.processes == 0 {
		v.processes = max(DefaultProcesses, floor)
	}
	if v.processes < floor || v.processes > 65536 {
		return site{}, fieldErr(field+".limits.processes", "must be 0 (default) or %d to 65536 for %d PHP children and %d httpd workers", floor, v.children, workers)
	}
	if in.TLS.CertFile != "" || in.TLS.KeyFile != "" {
		dir := pathpkg.Join(TLSRoot, in.Name)
		if err := checkTLSFileIn(dir, in.TLS.CertFile); err != nil {
			return site{}, fieldErr(field+".tls.cert_file", "%v", err)
		}
		if err := checkTLSFileIn(dir, in.TLS.KeyFile); err != nil {
			return site{}, fieldErr(field+".tls.key_file", "%v", err)
		}
		if in.TLS.CertFile == in.TLS.KeyFile {
			return site{}, fieldErr(field+".tls.key_file", "must differ from cert_file")
		}
	}
	if err := checkCovered(field, in); err != nil {
		return site{}, err
	}
	if in.AlwaysHTTPS && in.TLS.CertFile == "" {
		return site{}, fieldErr(field+".always_https", "only a site with a certificate redirects http to https")
	}
	if err := checkRedirects(field, in.Domains, in.Redirects); err != nil {
		return site{}, err
	}
	if err := checkFolders(field, in.Name, in.Folders); err != nil {
		return site{}, err
	}
	return v, nil
}

// checkTLSFileIn accepts only a plain file name directly inside dir. A site's
// directory is named after the site, so one site cannot name another's key.
func checkTLSFileIn(dir, file string) error {
	if !cleanPath(file) || pathpkg.Dir(file) != dir || !tlsFileNamePattern.MatchString(pathpkg.Base(file)) {
		return fmt.Errorf("must be a file directly inside %s/", dir)
	}
	return nil
}

// checkListenerTLSFile accepts files directly in TLSRoot, which cannot be any
// site's directory: a site directory is a directory, these are files.
func checkListenerTLSFile(file string) error {
	return checkTLSFileIn(TLSRoot, file)
}

// hostKey is the name OpenLiteSpeed registers for a mapped domain.
func hostKey(d string) string { return strings.TrimPrefix(d, "www.") }

// validDomain is copied from internal/hostaccounts (types.go) so this package
// does not depend on the account service.
func validDomain(s string) bool {
	if s == "" || len(s) > 253 || s != strings.ToLower(s) || net.ParseIP(s) != nil {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// cleanPath accepts a clean absolute path of letters, digits, '.', '_', '-'
// and '/', with no component starting with '.', so no hidden directory such
// as ~/.ssh can become a document root.
func cleanPath(p string) bool {
	if p == "/" || p == "" || len(p) > MaxPathBytes || !pathpkg.IsAbs(p) || pathpkg.Clean(p) != p {
		return false
	}
	for _, r := range p {
		if !(r == '/' || r == '.' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	for _, part := range strings.Split(p[1:], "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

func fieldErr(field, format string, args ...any) error {
	return &FieldError{Field: field, Reason: fmt.Sprintf(format, args...)}
}
