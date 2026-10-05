// Package hostweb compiles a bounded, fail-closed Apache/PHP-FPM layout for
// the native account foundation. Compile is deliberately pure: it emits
// configuration bytes and never creates files, starts processes, or changes a
// host.
package hostweb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	pathpkg "path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"sifruno/internal/hostaccounts"
)

const (
	// RestrictedChrootV1 is the only layout emitted by this package.
	RestrictedChrootV1   = "restricted-chroot-v1"
	MaxManagedAccounts   = 100
	MaxBundleFiles       = 1 + MaxManagedAccounts*2
	MaxBundleFileBytes   = 256 << 10
	MaxBundleBytes       = 8 << 20
	MaxBundlePathBytes   = 256
	DefaultBackendPort   = 18443
	DefaultFrontendPort  = 80
	DefaultFrontendIP    = "127.0.0.1"
	DefaultFrontUID      = 48
	DefaultFrontGID      = 48
	DefaultControllerUID = 2000
)

var (
	accountIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	usernamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)
	domainLabel      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	hexPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Profile contains only root-owned, operator-selected paths and listener
// values. Paths are emitted as absolute configuration references; Compile
// does not inspect, create, or activate any of them.
type Profile struct {
	// Name is a stable label included in the bundle manifest.
	Name string
	// ManagedRoot contains only generated compiler output. It is not a tenant
	// home and must be an absolute, clean path.
	ManagedRoot string
	// ManagedHomeRoot is the root prepared by hostaccounts for tenant homes.
	// Compile only accepts exact descendants of this path.
	ManagedHomeRoot string
	// FrontChroot is the immutable root for the shared front Apache. It must
	// not be an ancestor of any account Home or PublicHTML.
	FrontChroot string
	// ApacheModuleRoot contains root-owned module files referenced by absolute
	// path in generated configs.
	ApacheModuleRoot string
	// BackendChrootRoot and RuntimeRoot are root-prepared directories. Each
	// account receives exactly BackendChrootRoot/<account ID> and
	// RuntimeRoot/<account ID> mappings; Compile only references them.
	BackendChrootRoot string
	RuntimeRoot       string
	// ApacheBinary and FPMBinary are root-owned executable paths recorded for a
	// future installer. Compile emits no launch unit and never reads or
	// executes these paths.
	ApacheBinary string
	FPMBinary    string
	// TLSRoot contains root-owned per-account cert.pem and key.pem files.
	// CAFile is the root-owned CA used by the front proxy.
	TLSRoot string
	CAFile  string
	// FrontendIP is normally 0.0.0.0 or a numeric listener address.
	FrontendIP    string
	FrontendPort  uint16
	BackendPort   uint16
	FrontUID      uint32
	FrontGID      uint32
	ControllerUID uint32
}

// File is one deterministic managed output. Data is copied into the bundle;
// callers can safely retain or mutate their input account slice afterwards.
type File struct {
	Path   string
	Mode   os.FileMode
	SHA256 string
	Data   []byte
}

// Bundle is a complete immutable-at-the-boundary configuration plan. It is
// suitable for a later privileged installer, but this package performs no
// installation or daemon activation.
type Bundle struct {
	Profile string
	Files   []File
	SHA256  string
}

var (
	ErrInvalidProfile = errors.New("invalid hostweb profile")
	ErrInvalidAccount = errors.New("invalid hostweb account")
	ErrDuplicate      = errors.New("duplicate hostweb identity")
	ErrLimit          = errors.New("hostweb account limit exceeded")
)

// Compile deterministically renders one shared front Apache, one restricted
// backend Apache and one PHP-FPM pool per managed account. Account order does
// not affect the output. Suspended accounts are denied by the front router and
// receive no backend or FPM configuration.
func Compile(p Profile, accounts []hostaccounts.Account) (Bundle, error) {
	if err := validateProfile(p); err != nil {
		return Bundle{}, err
	}
	if p.FrontendIP == "" {
		p.FrontendIP = DefaultFrontendIP
	}
	if p.FrontendPort == 0 {
		p.FrontendPort = DefaultFrontendPort
	}
	if p.BackendPort == 0 {
		p.BackendPort = DefaultBackendPort
	}
	if p.FrontUID == 0 {
		p.FrontUID = DefaultFrontUID
	}
	if p.FrontGID == 0 {
		p.FrontGID = DefaultFrontGID
	}
	if p.ControllerUID == 0 {
		p.ControllerUID = DefaultControllerUID
	}
	if len(accounts) > MaxManagedAccounts {
		return Bundle{}, ErrLimit
	}
	items := append([]hostaccounts.Account(nil), accounts...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Domain < items[j].Domain
	})
	seenID, seenUID, seenGID, seenDomain, seenUsername := map[string]bool{}, map[int]bool{}, map[int]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range items {
		if err := validateAccount(p, a); err != nil {
			return Bundle{}, err
		}
		if uint32(a.UID) == p.FrontUID || uint32(a.GID) == p.FrontGID {
			return Bundle{}, ErrDuplicate
		}
		if seenID[a.ID] || seenUID[a.UID] || seenGID[a.GID] || seenDomain[a.Domain] || seenUsername[a.Username] {
			return Bundle{}, ErrDuplicate
		}
		seenID[a.ID], seenUID[a.UID], seenGID[a.GID], seenDomain[a.Domain], seenUsername[a.Username] = true, true, true, true, true
	}

	files := make([]File, 0, 2+len(items)*2)
	front, err := renderFrontend(p, items)
	if err != nil {
		return Bundle{}, err
	}
	files = append(files, makeFile("apache/front.conf", front))
	for _, a := range items {
		if a.State == "suspended" {
			continue
		}
		backend, err := renderBackend(p, a)
		if err != nil {
			return Bundle{}, err
		}
		fpm, err := renderFPM(p, a)
		if err != nil {
			return Bundle{}, err
		}
		files = append(files, makeFile("apache/backends/"+a.ID+".conf", backend))
		files = append(files, makeFile("fpm/"+a.ID+".conf", fpm))
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	bundleDigest := sha256.New()
	for _, f := range files {
		bundleDigest.Write([]byte(f.Path))
		bundleDigest.Write([]byte{0})
		bundleDigest.Write([]byte(strconv.FormatUint(uint64(f.Mode), 8)))
		bundleDigest.Write([]byte{0})
		bundleDigest.Write([]byte(f.SHA256))
		bundleDigest.Write([]byte{0})
	}
	return Bundle{Profile: p.Name, Files: files, SHA256: hex.EncodeToString(bundleDigest.Sum(nil))}, nil
}

func makeFile(path string, data []byte) File {
	copyData := append([]byte(nil), data...)
	h := sha256.Sum256(copyData)
	return File{Path: path, Mode: 0600, SHA256: hex.EncodeToString(h[:]), Data: copyData}
}

func validateProfile(p Profile) error {
	if p.Name != RestrictedChrootV1 {
		return ErrInvalidProfile
	}
	for _, path := range []string{p.ManagedRoot, p.ManagedHomeRoot, p.FrontChroot, p.ApacheModuleRoot, p.BackendChrootRoot, p.RuntimeRoot, p.ApacheBinary, p.FPMBinary, p.TLSRoot, p.CAFile} {
		if !absoluteClean(path) {
			return ErrInvalidProfile
		}
	}
	if p.FrontChroot == p.BackendChrootRoot || p.FrontChroot == p.RuntimeRoot || p.FrontChroot == p.ManagedRoot || p.FrontChroot == p.ManagedHomeRoot {
		return ErrInvalidProfile
	}
	roots := []string{p.ManagedRoot, p.ManagedHomeRoot, p.FrontChroot, p.BackendChrootRoot, p.RuntimeRoot, p.TLSRoot}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if roots[i] == roots[j] || isDescendant(roots[i], roots[j]) || isDescendant(roots[j], roots[i]) {
				return ErrInvalidProfile
			}
		}
	}
	if !isDescendant(p.CAFile, p.TLSRoot) {
		return ErrInvalidProfile
	}
	if p.FrontUID == 0 {
		p.FrontUID = DefaultFrontUID
	}
	if p.FrontGID == 0 {
		p.FrontGID = DefaultFrontGID
	}
	if p.ControllerUID == 0 {
		p.ControllerUID = DefaultControllerUID
	}
	if p.FrontUID < 1 || p.FrontUID >= 20000 || p.FrontGID < 1 || p.FrontGID >= 20000 || p.FrontUID == p.ControllerUID || p.FrontGID == p.ControllerUID {
		return ErrInvalidProfile
	}
	if p.FrontendIP == "" {
		p.FrontendIP = DefaultFrontendIP
	}
	ip := net.ParseIP(p.FrontendIP)
	if ip == nil || ip.To4() == nil || (ip.IsLoopback() && p.FrontendIP != "127.0.0.1") {
		return ErrInvalidProfile
	}
	if p.FrontendPort == 0 {
		p.FrontendPort = DefaultFrontendPort
	}
	if p.BackendPort == 0 {
		p.BackendPort = DefaultBackendPort
	}
	if p.FrontendPort < 1 || p.FrontendPort > 65535 || p.BackendPort != DefaultBackendPort {
		return ErrInvalidProfile
	}
	return nil
}

func validateAccount(p Profile, a hostaccounts.Account) error {
	if !accountIDPattern.MatchString(a.ID) || !usernamePattern.MatchString(a.Username) || !validDomain(a.Domain) {
		return ErrInvalidAccount
	}
	if a.UID < 20000 || a.UID > 60000 || a.GID != a.UID || a.Revision == 0 {
		return ErrInvalidAccount
	}
	if a.State != "active" && a.State != "suspended" {
		return ErrInvalidAccount
	}
	if !absoluteClean(a.Home) || !absoluteClean(a.PublicHTML) || a.Home != pathpkg.Join(p.ManagedHomeRoot, a.Username) || pathpkg.Join(a.Home, "public_html") != a.PublicHTML {
		return ErrInvalidAccount
	}
	if !isDescendant(a.Home, p.ManagedHomeRoot) || !isDescendant(a.PublicHTML, p.ManagedHomeRoot) {
		return ErrInvalidAccount
	}
	if isDescendant(p.FrontChroot, a.Home) || isDescendant(a.Home, p.FrontChroot) {
		return ErrInvalidAccount
	}
	if isDescendant(p.BackendChrootRoot, a.Home) || isDescendant(a.Home, p.BackendChrootRoot) {
		return ErrInvalidAccount
	}
	if isDescendant(p.RuntimeRoot, a.Home) || isDescendant(a.Home, p.RuntimeRoot) {
		return ErrInvalidAccount
	}
	return nil
}

func validDomain(s string) bool {
	if len(s) < 3 || len(s) > 253 || s != strings.ToLower(s) || net.ParseIP(s) != nil {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !domainLabel.MatchString(part) {
			return false
		}
	}
	return true
}

func absoluteClean(path string) bool {
	if path == "/" || len(path) > 240 || !pathpkg.IsAbs(path) || pathpkg.Clean(path) != path {
		return false
	}
	for _, r := range path {
		if !(r == '/' || r == '.' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func isDescendant(path, root string) bool {
	if !absoluteClean(path) || !absoluteClean(root) || path == root {
		return false
	}
	return strings.HasPrefix(path, strings.TrimSuffix(root, "/")+"/")
}

func backendIP(uid int) string {
	return fmt.Sprintf("127.73.%d.%d", uid>>8, uid&255)
}

func jailPath(p Profile, a hostaccounts.Account) string {
	return pathpkg.Join(p.BackendChrootRoot, a.ID)
}

func renderFrontend(p Profile, accounts []hostaccounts.Account) ([]byte, error) {
	var b bytes.Buffer
	fport := p.FrontendPort
	b.WriteString("# sifruno hostweb restricted-chroot-v1; generated, do not edit\n")
	b.WriteString("ServerRoot \"" + p.FrontChroot + "\"\n")
	b.WriteString("PidFile \"" + pathpkg.Join(p.ManagedRoot, "front.pid") + "\"\n")
	b.WriteString("ErrorLog \"" + pathpkg.Join(p.ManagedRoot, "front-error.log") + "\"\nMutex file:" + pathpkg.Join(p.ManagedRoot, "front-mutex") + "\n")
	b.WriteString("Listen " + p.FrontendIP + ":" + strconv.Itoa(int(fport)) + "\n")
	b.WriteString("LoadModule mpm_event_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_mpm_event.so") + "\"\n")
	b.WriteString("LoadModule unixd_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_unixd.so") + "\"\n")
	b.WriteString("LoadModule authz_core_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_authz_core.so") + "\"\n")
	b.WriteString("LoadModule authz_host_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_authz_host.so") + "\"\n")
	b.WriteString("LoadModule dir_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_dir.so") + "\"\n")
	b.WriteString("LoadModule log_config_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_log_config.so") + "\"\n")
	b.WriteString("LoadModule proxy_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_proxy.so") + "\"\n")
	b.WriteString("LoadModule proxy_http_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_proxy_http.so") + "\"\n")
	b.WriteString("LoadModule proxy_fcgi_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_proxy_fcgi.so") + "\"\n")
	b.WriteString("LoadModule ssl_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_ssl.so") + "\"\n")
	b.WriteString("User #" + strconv.FormatUint(uint64(p.FrontUID), 10) + "\nGroup #" + strconv.FormatUint(uint64(p.FrontGID), 10) + "\n")
	b.WriteString("SSLProxyEngine on\nSSLProxyVerify require\nSSLProxyCheckPeerName on\nSSLProxyCheckPeerExpire on\nSSLProxyVerifyDepth 1\nSSLProxyCACertificateFile \"" + p.CAFile + "\"\n")
	b.WriteString("ProxyPreserveHost On\n")
	// The default virtual host is an explicit denial. Foreign Host values do
	// not fall through to a tenant and suspended tenants are denied below.
	b.WriteString("<VirtualHost " + p.FrontendIP + ":" + strconv.Itoa(int(fport)) + ">\nServerName default.invalid\n<Location />\nRequire all denied\n</Location>\n</VirtualHost>\n")
	for _, a := range accounts {
		if a.State == "suspended" {
			b.WriteString("<VirtualHost " + p.FrontendIP + ":" + strconv.Itoa(int(fport)) + ">\nServerName " + a.Domain + "\n<Location />\nRequire all denied\n</Location>\n</VirtualHost>\n")
			continue
		}
		ip := backendIP(a.UID)
		b.WriteString("<VirtualHost " + p.FrontendIP + ":" + strconv.Itoa(int(fport)) + ">\n")
		b.WriteString("ServerName " + a.Domain + "\nServerAlias " + a.Domain + "\n")
		b.WriteString("ProxyPassMatch ^/(.*\\.php)$ https://" + ip + ":18443/" + "$1 retry=0\n")
		b.WriteString("ProxyPass / https://" + ip + ":18443/ retry=0\nProxyPassReverse / https://" + ip + ":18443/\n")
		b.WriteString("<Location />\nRequire expr \"%{HTTP_HOST} == '" + a.Domain + "'\"\n</Location>\n</VirtualHost>\n")
	}
	return b.Bytes(), nil
}

func renderBackend(p Profile, a hostaccounts.Account) ([]byte, error) {
	var b bytes.Buffer
	ip := backendIP(a.UID)
	chroot := jailPath(p, a)
	runtime := pathpkg.Join(p.RuntimeRoot, a.ID)
	cert := pathpkg.Join(p.TLSRoot, a.ID, "cert.pem")
	key := pathpkg.Join(p.TLSRoot, a.ID, "key.pem")
	b.WriteString("# sifruno hostweb restricted-chroot-v1; generated, do not edit\n")
	b.WriteString("ServerRoot \"" + chroot + "\"\n")
	b.WriteString("PidFile \"" + pathpkg.Join(p.ManagedRoot, "backend", a.ID+".pid") + "\"\nErrorLog \"" + pathpkg.Join(p.ManagedRoot, "logs", a.ID+"-apache.log") + "\"\nMutex file:" + pathpkg.Join(p.ManagedRoot, "backend", a.ID+"-mutex") + "\n")
	b.WriteString("Listen " + ip + ":18443\n")
	b.WriteString("LoadModule unixd_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_unixd.so") + "\"\n")
	b.WriteString("LoadModule mpm_event_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_mpm_event.so") + "\"\n")
	b.WriteString("LoadModule authz_core_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_authz_core.so") + "\"\n")
	b.WriteString("LoadModule authz_host_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_authz_host.so") + "\"\n")
	b.WriteString("LoadModule dir_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_dir.so") + "\"\n")
	b.WriteString("LoadModule mime_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_mime.so") + "\"\n")
	b.WriteString("LoadModule log_config_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_log_config.so") + "\"\n")
	b.WriteString("LoadModule ssl_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_ssl.so") + "\"\nLoadModule proxy_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_proxy.so") + "\"\nLoadModule proxy_fcgi_module \"" + pathpkg.Join(p.ApacheModuleRoot, "mod_proxy_fcgi.so") + "\"\n")
	b.WriteString("ChrootDir \"" + chroot + "\"\n")
	b.WriteString("User #" + strconv.Itoa(a.UID) + "\nGroup #" + strconv.Itoa(a.GID) + "\n")
	b.WriteString("TypesConfig /etc/mime.types\n")
	b.WriteString("SSLEngine on\nSSLCertificateFile \"" + cert + "\"\nSSLCertificateKeyFile \"" + key + "\"\n")
	b.WriteString("SSLProtocol -all +TLSv1.2 +TLSv1.3\nDocumentRoot \"" + a.PublicHTML + "\"\n")
	b.WriteString("<VirtualHost " + ip + ":18443>\nServerName default.invalid\n<Location />\nRequire all denied\n</Location>\n</VirtualHost>\n")
	b.WriteString("<VirtualHost " + ip + ":18443>\nServerName " + a.Domain + "\n")
	b.WriteString("<Directory \"" + a.PublicHTML + "\">\nAllowOverride None\nOptions -Indexes -ExecCGI -Includes -FollowSymLinks\nRequire all granted\n</Directory>\n")
	b.WriteString("<FilesMatch \"\\.php$\">\nSetHandler \"proxy:unix:" + pathpkg.Join(runtime, "php-fpm.sock") + "|fcgi://localhost/\"\n</FilesMatch>\n")
	b.WriteString("<Location />\nRequire expr \"%{HTTP_HOST} == '" + a.Domain + "'\"\n</Location>\nDirectoryIndex index.php index.html\n</VirtualHost>\n")
	return b.Bytes(), nil
}

func renderFPM(p Profile, a hostaccounts.Account) ([]byte, error) {
	var b bytes.Buffer
	jail := jailPath(p, a)
	sock := pathpkg.Join(p.RuntimeRoot, a.ID, "php-fpm.sock")
	b.WriteString("; sifruno hostweb restricted-chroot-v1; generated, do not edit\n")
	logRoot := pathpkg.Join(p.ManagedRoot, "logs")
	b.WriteString("[global]\ndaemonize = no\nerror_log = " + pathpkg.Join(logRoot, a.ID+"-fpm.log") + "\n")
	b.WriteString("[" + a.Username + "]\nslowlog = " + pathpkg.Join(logRoot, a.ID+"-fpm-slow.log") + "\nuser = " + strconv.Itoa(a.UID) + "\ngroup = " + strconv.Itoa(a.GID) + "\n")
	b.WriteString("listen = " + sock + "\nlisten.owner = " + strconv.Itoa(a.UID) + "\nlisten.group = " + strconv.Itoa(a.GID) + "\nlisten.mode = 0600\n")
	b.WriteString("chroot = " + jail + "\nchdir = /\nclear_env = yes\nsecurity.limit_extensions = .php\n")
	b.WriteString("pm = ondemand\npm.max_children = 2\npm.process_idle_timeout = 10s\npm.max_requests = 100\nrequest_terminate_timeout = 30s\nrequest_slowlog_timeout = 5s\n")
	b.WriteString("php_admin_flag[allow_url_include] = off\nphp_admin_value[session.save_path] = " + pathpkg.Join(a.Home, "tmp") + "\n")
	return b.Bytes(), nil
}

// Validate checks hashes, modes, path uniqueness, and deterministic ordering
// before an installer consumes a Bundle.
func (b Bundle) Validate() error {
	if b.Profile != RestrictedChrootV1 || len(b.Files) == 0 || len(b.Files) > MaxBundleFiles || !hexPattern.MatchString(b.SHA256) {
		return errors.New("invalid hostweb bundle")
	}
	last := ""
	frontSeen := false
	backends := map[string]bool{}
	fpm := map[string]bool{}
	totalBytes := 0
	h := sha256.New()
	for _, f := range b.Files {
		if f.Path == "" || len(f.Path) > MaxBundlePathBytes || pathpkg.IsAbs(f.Path) || strings.Contains(f.Path, "..") || f.Mode != 0600 || f.Path <= last {
			return errors.New("invalid hostweb bundle file")
		}
		switch {
		case f.Path == "apache/front.conf":
			if frontSeen {
				return errors.New("duplicate hostweb front file")
			}
			frontSeen = true
		case strings.HasPrefix(f.Path, "apache/backends/") && strings.HasSuffix(f.Path, ".conf"):
			id := strings.TrimSuffix(strings.TrimPrefix(f.Path, "apache/backends/"), ".conf")
			if !accountIDPattern.MatchString(id) || backends[id] {
				return errors.New("invalid hostweb backend inventory")
			}
			backends[id] = true
		case strings.HasPrefix(f.Path, "fpm/") && strings.HasSuffix(f.Path, ".conf"):
			id := strings.TrimSuffix(strings.TrimPrefix(f.Path, "fpm/"), ".conf")
			if !accountIDPattern.MatchString(id) || fpm[id] {
				return errors.New("invalid hostweb fpm inventory")
			}
			fpm[id] = true
		default:
			return errors.New("unknown hostweb bundle file")
		}
		if len(f.Data) > MaxBundleFileBytes || totalBytes > MaxBundleBytes-len(f.Data) {
			return errors.New("hostweb bundle exceeds size bound")
		}
		totalBytes += len(f.Data)
		last = f.Path
		digest := sha256.Sum256(f.Data)
		if hex.EncodeToString(digest[:]) != f.SHA256 || !hexPattern.MatchString(f.SHA256) {
			return errors.New("hostweb bundle hash mismatch")
		}
		h.Write([]byte(f.Path))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatUint(uint64(f.Mode), 8)))
		h.Write([]byte{0})
		h.Write([]byte(f.SHA256))
		h.Write([]byte{0})
	}
	if !frontSeen || len(backends) != len(fpm) || len(backends) > MaxManagedAccounts {
		return errors.New("incomplete hostweb bundle inventory")
	}
	for id := range backends {
		if !fpm[id] {
			return errors.New("mismatched hostweb bundle inventory")
		}
	}
	if !bytes.Equal(h.Sum(nil), mustDecodeHex(b.SHA256)) {
		return errors.New("hostweb bundle digest mismatch")
	}
	return nil
}

func mustDecodeHex(s string) []byte {
	v, _ := hex.DecodeString(s)
	return v
}
