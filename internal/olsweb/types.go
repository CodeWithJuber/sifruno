package olsweb

import (
	"errors"
)

// Fixed host layout. These are constants rather than inputs so that no spec
// can point OpenLiteSpeed at another server root, home tree or key store.
const (
	// ServerRoot is the install root of the LiteSpeed repository packages.
	ServerRoot = "/usr/local/lsws"
	// HomeRoot holds one home per account; a document root must lie inside
	// HomeRoot/<username>/.
	HomeRoot = "/home"
	// TLSRoot holds listener certificates directly and one directory per site
	// (TLSRoot/<site name>/) for that site's certificate and key.
	TLSRoot = "/etc/sifruno/tls"
	// ACMEChallengeDir holds the HTTP-01 challenge files for every site. It
	// is outside every home, so no tenant can write or link into it. Every
	// vhost maps /.well-known/acme-challenge/ to it; tokens are random, so
	// one directory serves all sites.
	ACMEChallengeDir = "/var/lib/sifruno-acme"
	// SuspendedDocRoot is the vhRoot and docRoot of every suspended site: an
	// empty directory owned by root, outside every home, which the root
	// broker makes. A suspended vhost names no path its tenant controls, so
	// the tenant cannot make its config test fail and keep the site serving.
	SuspendedDocRoot = "/var/lib/sifruno-suspended"
	// NamePrefix starts every virtual host, listener and external app name
	// Sifruno emits, so they never collide with the administrator's own.
	NamePrefix = "sifruno-"
	// ServerConfigPath is the server-level fragment, relative to ServerRoot.
	// httpd_config.conf includes it with one line.
	ServerConfigPath = "conf/sifruno.conf"
	// LogRoot holds one directory of access and error logs per site. It is
	// root-owned and outside every home so a tenant cannot plant a symlink
	// where the server opens its log files.
	LogRoot = ServerRoot + "/logs/sifruno"
	// CacheRoot is the openlitespeed package's own cache directory
	// (root-owned 0755). Each active site caches pages in
	// CacheRoot/NamePrefix+NAME, outside every home: OpenLiteSpeed creates
	// that directory as root when it loads the config and chowns it to the
	// server user, so a tenant must not be able to put a link there.
	CacheRoot = ServerRoot + "/cachedata"
)

// Bounds. OpenLiteSpeed aborts a whole file at a line of 8192 bytes or more,
// so the domain count and path lengths keep every rendered line far below it.
const (
	MaxSites          = 500
	MaxListeners      = 8
	MaxDomainsPerSite = 16
	MaxPathBytes      = 200
	maxLineBytes      = 8191
)

// Defaults applied when a limit is zero in the spec.
const (
	DefaultPHPChildren = 10
	DefaultMemoryMiB   = 2047
	DefaultProcesses   = 1000
	// DefaultHTTPDWorkers is assumed when the spec does not state the server's
	// httpdWorkers. OpenLiteSpeed defaults it to the CPU count capped at 8, and
	// the process-limit floor below scales with it, so 8 is the safe guess.
	DefaultHTTPDWorkers = 8
)

// Server is everything Sifruno renders for one OpenLiteSpeed host.
type Server struct {
	// HTTPDWorkers must match httpdWorkers in httpd_config.conf when set; 0
	// assumes DefaultHTTPDWorkers. It is used only to check process limits.
	HTTPDWorkers int        `json:"httpd_workers,omitempty"`
	Listeners    []Listener `json:"listeners"`
	Sites        []Site     `json:"sites"`
}

// Listener is one Sifruno-owned listener. Plain listeners map every site; a
// secure listener maps only the sites that have their own certificate, so no
// site is served under another name's certificate. A secure listener is
// rendered only while at least one site has a certificate: with none it
// would serve no site.
type Listener struct {
	Name string `json:"name"`
	// Address is "*" for all interfaces or a literal IPv4/IPv6 address.
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Secure   bool   `json:"secure,omitempty"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

// Site is one virtual host with its own Linux user and lsphp process group.
type Site struct {
	// Name is the stable site id; rendered names, socket and log paths derive
	// from it.
	Name     string `json:"name"`
	Username string `json:"username"`
	// Group must equal Username: every account has a private group.
	Group string `json:"group"`
	// Domains are served by this site; the first is the primary name.
	Domains    []string  `json:"domains"`
	DocRoot    string    `json:"doc_root"`
	PHPVersion string    `json:"php_version"`
	Suspended  bool      `json:"suspended,omitempty"`
	Limits     Limits    `json:"limits"`
	Isolation  Isolation `json:"isolation"`
	TLS        TLS       `json:"tls"`
}

// Limits are applied to the site's lsphp process group as rlimits and LSAPI
// children. Zero selects the default.
type Limits struct {
	// MemoryMiB becomes RLIMIT_AS (address space) for each lsphp process.
	MemoryMiB int `json:"memory_mib,omitempty"`
	// Processes becomes RLIMIT_NPROC, which the kernel counts across all of
	// the user's processes, not only PHP.
	Processes   int `json:"processes,omitempty"`
	PHPChildren int `json:"php_children,omitempty"`
}

// Isolation selects OpenLiteSpeed's process containment for the site's PHP.
type Isolation struct {
	// Namespace starts lsphp in OpenLiteSpeed's namespace container. It takes
	// effect only when httpd_config.conf sets namespace to 1 or 2.
	Namespace bool `json:"namespace,omitempty"`
	// CGroups starts lsphp in the user's cgroup. It takes effect only when the
	// server-level cgroups setting in CGIRLimit is 1 or 2.
	CGroups bool `json:"cgroups,omitempty"`
}

// TLS names the site's own certificate. Both files are empty or both are set.
type TLS struct {
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

// ErrInvalid is wrapped by every validation error.
var ErrInvalid = errors.New("invalid olsweb input")

// FieldError names the spec field that was refused, using the JSON names, for
// example "sites[1].doc_root".
type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string { return "olsweb: " + e.Field + ": " + e.Reason }

// Unwrap lets callers test errors.Is(err, ErrInvalid).
func (e *FieldError) Unwrap() error { return ErrInvalid }

// phpBinaries maps each accepted PHP version to the lsphp binary installed by
// the LiteSpeed repository package lsphpXY.
var phpBinaries = map[string]string{
	"8.1": ServerRoot + "/lsphp81/bin/lsphp",
	"8.2": ServerRoot + "/lsphp82/bin/lsphp",
	"8.3": ServerRoot + "/lsphp83/bin/lsphp",
	"8.4": ServerRoot + "/lsphp84/bin/lsphp",
}

// reservedUsernames are system and service accounts that a site must never
// run as. The OpenLiteSpeed WebAdmin itself refuses root and lsadm as an
// external app user, and root, sudo, wheel, shadow and lsadm as its group.
var reservedUsernames = map[string]bool{
	"root": true, "lsadm": true, "nobody": true, "nogroup": true, "daemon": true,
	"bin": true, "sys": true, "sync": true, "games": true, "man": true, "lp": true,
	"mail": true, "news": true, "uucp": true, "proxy": true, "www_data": true,
	"backup": true, "list": true, "irc": true, "gnats": true,
	"systemd_network": true, "systemd_resolve": true, "dbus": true,
	"polkitd": true, "sshd": true, "apache": true, "nginx": true, "mysql": true,
	"postgres": true, "ftp": true, "operator": true, "sifruno": true,
	"sifpanel": true, "sudo": true, "wheel": true, "shadow": true, "adm": true,
	"disk": true, "docker": true, "lxd": true, "systemd_journal": true,
}
