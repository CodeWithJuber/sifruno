package sitesource

import (
	"bytes"
	"errors"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"sifruno/internal/cpsource"
)

// Another Linux server, read over the migration's SSH (docs/migration-design.md,
// adapter 3): the broker runs these fixed commands as root there and hands
// their output to the parsers below. Every value put into a command passes
// a strict pattern first, so the old server's root shell sees fixed words
// and plain paths only. The commands name the programs where RHEL-family
// and Debian-family servers keep them (merged /usr): util-linux's runuser,
// coreutils' head, stat and du, cronie's or cron's crontab.
const (
	runuserPath = "/usr/sbin/runuser"
	headPath    = "/usr/bin/head"
	statPath    = "/usr/bin/stat"
	duPath      = "/usr/bin/du"
	crontabPath = "/usr/bin/crontab"
)

// NginxDumpCommand prints nginx's whole configuration as nginx reads it:
// nginx -T tests the configuration and dumps every file it read, each after
// a line "# configuration file NAME:" (nginx.org/en/docs/switches.html). It
// prints nothing on a server without /usr/sbin/nginx. nginx's own messages
// go to its error output, which the broker keeps apart.
const NginxDumpCommand = "if [ -x /usr/sbin/nginx ]; then exec /usr/sbin/nginx -T; fi; exit 0"

// ApacheVhostsCommand lists Apache's virtual hosts with the file and line
// of each (httpd -S, "show the settings as parsed from the config file":
// httpd.apache.org/docs/2.4/programs/httpd.html). Debian-family servers run
// it through apache2ctl, which reads the environment apache2 needs. It
// prints nothing on a server with neither.
const ApacheVhostsCommand = "if [ -x /usr/sbin/httpd ]; then exec /usr/sbin/httpd -S 2>&1; elif [ -x /usr/sbin/apache2ctl ]; then exec /usr/sbin/apache2ctl -S 2>&1; fi; exit 0"

// FPMPoolsCommand prints each PHP-FPM pool file's listen lines after a
// line "== FILE": RHEL's /etc/php-fpm.d, Debian's /etc/php/X.Y/fpm/pool.d
// and Remi's /etc/opt/remi/phpXY/php-fpm.d.
const FPMPoolsCommand = `for f in /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf; do [ -f "$f" ] || continue; printf '== %s\n' "$f"; /usr/bin/grep -E '^[[:space:]]*listen[[:space:]]*=' -- "$f"; done; exit 0`

// FPMVersionsCommand prints each PHP-FPM program's path and the first line
// of its -v: "== /usr/sbin/php-fpm PHP 8.2.13 (fpm-fcgi) ...".
const FPMVersionsCommand = `for b in /usr/sbin/php-fpm /usr/sbin/php-fpm[0-9]* /opt/remi/php[0-9]*/root/usr/sbin/php-fpm; do [ -x "$b" ] || continue; v=$("$b" -v 2>/dev/null | /usr/bin/head -n 1); printf '== %s %s\n' "$b" "$v"; done; exit 0`

// Bounds of what the commands read.
const (
	maxConfigRead = MaxConfigBytes + 1
	// MaxConfigFiles bounds the Apache files read for one server.
	MaxConfigFiles = 64
	maxTLSRead     = 64 << 10
	maxNginxFiles  = 500
)

// ErrServer means an answer from the old server is not in the form the
// command prints.
var ErrServer = errors.New("the old server's answer could not be read")

var (
	// safePath is an absolute path of plain characters: no space, quote,
	// $, backslash or anything else the old server's shell reads.
	safePath = regexp.MustCompile(`^(/[A-Za-z0-9._@+-]+)+$`)
	// apacheConfigDirs are where Apache configuration is read from: the
	// distributions' own folders, and DirectAdmin's per-user files.
	apacheConfigDirs = []string{"/etc/httpd/", "/etc/apache2/", "/usr/local/directadmin/data/users/", "/usr/local/apache/conf/"}
	// webRoots are where a document root may be: a site's files, never a
	// system folder the copy would hand to a tenant.
	webRoots = []string{"/var/www/", "/srv/", "/home/", "/usr/share/nginx/html"}
	// tlsDirs are where a certificate or key may be read from.
	tlsDirs = []string{"/etc/letsencrypt/", "/etc/pki/", "/etc/ssl/", "/etc/httpd/", "/etc/nginx/", "/etc/apache2/"}
	// systemUser is a Linux user name as useradd takes it on both
	// families: www-data has a dash.
	systemUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// cleanPath reports an absolute path of plain characters, with no empty,
// "." or ".." part.
func cleanPath(p string) bool {
	if len(p) > 4096 || !safePath.MatchString(p) || path.Clean(p) != p {
		return false
	}
	for _, part := range strings.Split(p[1:], "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func under(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasSuffix(d, "/") {
			if strings.HasPrefix(p, d) && len(p) > len(d) {
				return true
			}
		} else if p == d {
			return true
		}
	}
	return false
}

// ValidDocRoot reports a document root the copy may read: a plain path
// below /var/www, /srv or /home, or nginx's own /usr/share/nginx/html. A
// site whose files are elsewhere (/, /etc, /root) is refused: its copy
// would hand system files to the moved site.
func ValidDocRoot(p string) bool { return cleanPath(p) && under(p, webRoots) }

// ValidSystemUser reports a Linux user name a command may name.
func ValidSystemUser(name string) bool { return systemUser.MatchString(name) }

// ConfigFileCommand reads one Apache configuration file httpd -S named,
// at most 1 MiB and a byte (so a larger one is seen as larger), from the
// configuration folders only.
func ConfigFileCommand(file string) (string, error) {
	if !cleanPath(file) || !under(file, apacheConfigDirs) {
		return "", ErrServer
	}
	return headPath + " -c " + strconv.Itoa(maxConfigRead) + " -- " + file, nil
}

// StatCommand prints what a document root is, its owner's name and number,
// and its group's name: "directory|apache|48|apache". stat does not
// follow a link, so a root that is one says "symbolic link".
func StatCommand(root string) (string, error) {
	if !ValidDocRoot(root) {
		return "", ErrServer
	}
	return statPath + " -c '%F|%U|%u|%G' -- " + root, nil
}

// DiskCommand prints the MiB the document root holds on its own
// filesystem.
func DiskCommand(root string) (string, error) {
	if !ValidDocRoot(root) {
		return "", ErrServer
	}
	return duPath + " -s -m -x -- " + root, nil
}

// asOwner runs a command as the files' owner, never as root unless root
// owns them: what a tenant swaps in (a link to /root) then gives only what
// the owner may read itself. runuser -u runs the program directly, not
// through the owner's shell, so a nologin shell does not stop it.
func asOwner(owner Owner, command string) (string, bool) {
	if owner.UID == 0 {
		return command, owner.Name == "root"
	}
	if owner.UID < 0 || owner.Name == "root" || !ValidSystemUser(owner.Name) {
		return "", false
	}
	return runuserPath + " -u " + owner.Name + " -- " + command, true
}

// WPConfigCommand reads the document root's wp-config.php as its owner, at
// most 256 KiB and a byte.
func WPConfigCommand(root string, owner Owner) (string, error) {
	if !ValidDocRoot(root) {
		return "", ErrServer
	}
	command, ok := asOwner(owner, headPath+" -c "+strconv.Itoa(maxWPConfig+1)+" -- "+root+"/wp-config.php")
	if !ok {
		return "", ErrServer
	}
	return command, nil
}

// CrontabCommand prints the owner's crontab (crontab -l -u). Root's is the
// server's own and is never read for a site.
func CrontabCommand(owner Owner) (string, error) {
	if owner.UID <= 0 || !ValidSystemUser(owner.Name) {
		return "", ErrServer
	}
	return crontabPath + " -l -u " + owner.Name, nil
}

// TLSFileCommand reads a certificate or key file a virtual host names, as
// root (keys are root's alone), from the usual certificate folders only.
func TLSFileCommand(file string) (string, error) {
	if !cleanPath(file) || !under(file, tlsDirs) {
		return "", ErrServer
	}
	return headPath + " -c " + strconv.Itoa(maxTLSRead+1) + " -- " + file, nil
}

// MaxTLSFile is the largest certificate or key file read.
const MaxTLSFile = maxTLSRead

// ParseNginxDump splits nginx -T's output into the files it names and
// reads each with ParseNginx. Text before the first file line is nginx's
// own and is skipped.
func ParseNginxDump(out []byte) ([]*NginxFile, error) {
	if !utf8.Valid(out) {
		return nil, &ParseError{File: "nginx -T", Reason: "the answer is not plain text"}
	}
	var files []*NginxFile
	name, start := "", -1
	flush := func(end int) error {
		if start < 0 {
			return nil
		}
		if len(files) == maxNginxFiles {
			return &ParseError{File: "nginx -T", Reason: "nginx read more than 500 files"}
		}
		f, err := ParseNginx(name, out[start:end])
		if err != nil {
			return err
		}
		files = append(files, f)
		return nil
	}
	pos := 0
	for pos < len(out) {
		end := bytes.IndexByte(out[pos:], '\n')
		next := len(out)
		if end >= 0 {
			next = pos + end + 1
		}
		line := strings.TrimRight(string(out[pos:next]), "\r\n")
		if rest, ok := strings.CutPrefix(line, "# configuration file "); ok && strings.HasSuffix(rest, ":") {
			if err := flush(pos); err != nil {
				return nil, err
			}
			name, start = strings.TrimSuffix(rest, ":"), next
		}
		pos = next
	}
	if err := flush(len(out)); err != nil {
		return nil, err
	}
	return files, nil
}

// apacheVhostLine is a line of httpd -S that names where a virtual host is:
// "... name (/etc/httpd/conf.d/site.conf:1)".
var apacheVhostLine = regexp.MustCompile(`\((/[^()\s]+):([0-9]{1,7})\)\s*$`)

// ApacheFiles lists, in the order httpd -S names them and each once, the
// files that hold virtual hosts. More than MaxConfigFiles is ErrServer.
func ApacheFiles(out []byte) ([]string, error) {
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		m := apacheVhostLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		file := m[1]
		if !slicesContains(files, file) {
			if len(files) == MaxConfigFiles {
				return nil, ErrServer
			}
			files = append(files, file)
		}
	}
	return files, nil
}

func slicesContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// FPMPool is one PHP-FPM pool file: where it listens, and the PHP version
// its folder names ("" for RHEL's /etc/php-fpm.d, whose version is
// /usr/sbin/php-fpm's).
type FPMPool struct {
	File    string
	Listen  []string
	Version string
}

var (
	debianPool = regexp.MustCompile(`^/etc/php/([5-8])\.([0-9])/fpm/pool\.d/`)
	remiPool   = regexp.MustCompile(`^/etc/opt/remi/php([5-8])([0-9])/php-fpm\.d/`)
	fpmVersion = regexp.MustCompile(`PHP ([5-8])\.([0-9]{1,2})\.`)
	fpmProgram = regexp.MustCompile(`^/opt/remi/php([5-8])([0-9])/`)
	fpmSource  = regexp.MustCompile(`^php([5-9])\.([0-9])-fpm$`)
)

// ParseFPMPools reads FPMPoolsCommand's answer.
func ParseFPMPools(out []byte) []FPMPool {
	var pools []FPMPool
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if file, ok := strings.CutPrefix(line, "== "); ok {
			p := FPMPool{File: file}
			if m := debianPool.FindStringSubmatch(file); m != nil {
				p.Version = m[1] + "." + m[2]
			} else if m := remiPool.FindStringSubmatch(file); m != nil {
				p.Version = m[1] + "." + m[2]
			}
			if len(pools) < 256 {
				pools = append(pools, p)
			}
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != "listen" || len(pools) == 0 {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if last := &pools[len(pools)-1]; value != "" && len(last.Listen) < 8 {
			last.Listen = append(last.Listen, value)
		}
	}
	return pools
}

// ParseFPMVersions reads FPMVersionsCommand's answer: each program's PHP
// version ("8.2"), by its path.
func ParseFPMVersions(out []byte) map[string]string {
	versions := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "== ")
		if !ok || len(versions) == 32 {
			continue
		}
		program, banner, _ := strings.Cut(rest, " ")
		if m := fpmVersion.FindStringSubmatch(banner); m != nil {
			versions[program] = m[1] + "." + m[2]
		} else if m := fpmProgram.FindStringSubmatch(program); m != nil {
			versions[program] = m[1] + "." + m[2]
		}
	}
	return versions
}

// Owner is who owns a document root on the old server.
type Owner struct {
	Name string
	UID  int
}

// ErrNotFolder means the document root is not a folder (a link, a file, or
// nothing).
var ErrNotFolder = errors.New("the document root is not a folder")

// ParseStat reads StatCommand's answer.
func ParseStat(out []byte) (Owner, error) {
	line, ok := strings.CutSuffix(string(out), "\n")
	if !ok || strings.Contains(line, "\n") {
		return Owner{}, ErrServer
	}
	parts := strings.Split(line, "|")
	if len(parts) != 4 {
		return Owner{}, ErrServer
	}
	if parts[0] != "directory" {
		return Owner{}, ErrNotFolder
	}
	uid, err := strconv.Atoi(parts[2])
	if err != nil || uid < 0 || uid > 1<<31-2 || strconv.Itoa(uid) != parts[2] || !ValidSystemUser(parts[1]) || (uid == 0) != (parts[1] == "root") {
		return Owner{}, ErrServer
	}
	return Owner{Name: parts[1], UID: uid}, nil
}

// ParseDiskMiB reads DiskCommand's answer: "123\t/var/www/site".
func ParseDiskMiB(out []byte) (int64, error) {
	field, _, ok := strings.Cut(string(out), "\t")
	if !ok {
		return 0, ErrServer
	}
	n, err := strconv.ParseInt(field, 10, 64)
	if err != nil || n < 0 || n > 1<<40 {
		return 0, ErrServer
	}
	return n, nil
}

// PHPVersion maps a source's PHP ("php8.2-fpm", or "" when nothing names
// it) to the version this server runs the copy with (8.1 to 8.4). exact is
// false when they differ: older than 8.1 becomes 8.1, newer than 8.4
// becomes 8.4, unknown becomes 8.3.
func PHPVersion(source string) (version string, exact bool) {
	m := fpmSource.FindStringSubmatch(source)
	if m == nil {
		return "8.3", false
	}
	v := m[1] + "." + m[2]
	switch v {
	case "8.1", "8.2", "8.3", "8.4":
		return v, true
	}
	if v < "8.1" {
		return "8.1", false
	}
	return "8.4", false
}

// AccountName is the account name a site from another server gets here
// unless the person picks another: its files' owner when that is a
// person's account (a number of 1000 or more, named as accounts here are
// named), else the domain's first label in letters and digits.
func AccountName(owner Owner, domain string) string {
	if owner.UID >= 1000 && owner.Name != "nobody" && cpsource.UserPattern.MatchString(owner.Name) {
		return owner.Name
	}
	label, _, _ := strings.Cut(strings.TrimPrefix(domain, "www."), ".")
	var b strings.Builder
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	name := b.String()
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "site" + name
	}
	if len(name) < 3 {
		name += "site"
	}
	if len(name) > 16 {
		name = name[:16]
	}
	return name
}

// HereName is the name a database or database user from another server
// gets here: the account's own prefix and the old name, with any character
// other than letters, digits and _ made _, unless the old name has the
// prefix already. ok is false when that is longer than max.
func HereName(account, name string, max int) (string, bool) {
	if name == "" || len(name) > 64 || !utf8.ValidString(name) {
		return "", false
	}
	if strings.HasPrefix(name, account+"_") && len(name) > len(account)+1 && cpsource.DatabasePattern.MatchString(name) && len(name) <= max {
		return name, true
	}
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, name)
	out := account + "_" + clean
	if len(out) > max {
		return "", false
	}
	return out, true
}
