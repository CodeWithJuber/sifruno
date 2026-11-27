package cpmove

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
	"sifruno/internal/sitemodel"
)

// Read is the cPanel backup file adapter (docs/migration-design.md): it
// reads a cpmove-USER.tar.gz, USER.tar.gz or backup-…_USER.tar.gz once,
// in the layout cPanel's public "Backup Tarball Contents" page describes
// (https://docs.cpanel.net/knowledge-base/backup/backup-tarball-contents/,
// read 2026-11-27), into a website model. The website's home (homedir/)
// and its database dumps (mysql/NAME.sql) go to a Sink; the small metadata
// files are read into memory. cPanel says the layout can change and is not
// an integration endpoint, so a file this does not know is left out and a
// part it cannot carry is named in the model's NotCarried.
//
// The archive is untrusted. Read keeps Inspect's framing guards (one TAR
// stream, gzip checked, every size, count and path length bounded, a
// strict end) and refuses a name that is absolute, holds "..", repeats, or
// lies outside the archive's one top folder. A link that points outside
// the home, a hard link, a device or a FIFO is not handed to the Sink;
// setuid, setgid and sticky bits never reach it.

// ErrNotCPMove means the archive is not a cPanel account backup: it has no
// cp/USER file for the user its top folder names.
var ErrNotCPMove = errors.New("not a cPanel account backup")

// Bounds on the metadata Read keeps in memory.
const (
	maxMetadataFile  = 1 << 20
	maxMetadataTotal = 16 << 20
	maxMetadataFiles = 512
)

// Archive is what one backup file holds. Users carry the database users'
// password hashes and KeyPEM the certificate's private key, for the broker's
// copy steps only: neither is in Site, and neither may be logged or kept.
type Archive struct {
	Site           sitemodel.Site
	Users          []cpsource.DatabaseUser
	CertificatePEM []byte
	KeyPEM         []byte
	// HomeBytes is what the home's files hold, for the room check.
	HomeBytes int64
}

// Sink takes what Read extracts. Names are clean relative paths: "home"
// and "home/<path>" for the website's home, "mysql/<db>.sql" for a dump.
// Modes are permission bits only.
type Sink interface {
	Dir(name string, mode fs.FileMode) error
	File(name string, mode fs.FileMode, r io.Reader) error
	Symlink(name, target string) error
}

// homeExcludes are the parts of a cPanel home that are not the website,
// the same list the SSH copy leaves out (hostaccounts migrateExcludes):
// mail and its settings, logs, caches, old keys and certificates, and www,
// a link to public_html.
var homeExcludes = map[string]bool{
	"mail": true, "etc": true, ".cpanel": true, ".cphorde": true, "logs": true, "tmp": true, "access-logs": true, "www": true,
	".trash": true, "ssl": true, ".ssh": true, ".cagefs": true, ".cl.selector": true, ".softaculous": true, ".spamassassin": true,
	".razor": true, ".lastlogin": true, ".bash_history": true, "public_ftp": true, ".gnupg": true,
}

// Read reads one backup file. limits bound it as they bound Inspect.
func Read(ctx context.Context, r io.Reader, limits Limits, sink Sink) (*Archive, error) {
	if ctx == nil || r == nil || sink == nil || !limits.valid() {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	source := &boundedReader{ctx: ctx, r: r, max: limits.MaxArchiveBytes}
	buffered := bufio.NewReaderSize(source, 32768)
	magic, err := buffered.Peek(2)
	if err != nil {
		return nil, sanitize(err)
	}
	var decoded io.Reader = buffered
	if magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, sanitize(err)
		}
		defer gz.Close()
		decoded = gz
	}
	expanded := &boundedReader{ctx: ctx, r: decoded, max: limits.MaxExpandedBytes}
	guard := &tarGuard{r: expanded, limits: limits}
	tr := tar.NewReader(guard)
	rd := &reader{ctx: ctx, sink: sink, meta: map[string][]byte{}, present: map[string]bool{}, seen: map[string]bool{}, dumps: map[string]bool{}}
	entries := 0
	for {
		if ctx.Err() != nil {
			return nil, ErrCanceled
		}
		h, err := tr.Next()
		if err == tar.ErrInsecurePath && h != nil {
			err = nil
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, sanitize(err)
		}
		if entries++; entries > limits.MaxEntries {
			return nil, ErrLimit
		}
		if h.Size < 0 || h.Size > limits.MaxFileBytes {
			return nil, ErrLimit
		}
		if len(h.Name) > limits.MaxPathBytes || len(h.Linkname) > limits.MaxPathBytes {
			return nil, ErrLimit
		}
		name, ok := canonicalName(h.Name, h.Typeflag == tar.TypeDir)
		if !ok || name == "." || rd.seen[name] {
			return nil, ErrArchive
		}
		rd.seen[name] = true
		if err := rd.entry(name, h, tr); err != nil {
			if ctx.Err() != nil {
				return nil, ErrCanceled
			}
			return nil, err
		}
	}
	if err := guard.finish(); err != nil {
		return nil, sanitize(err)
	}
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	return rd.archive()
}

type reader struct {
	ctx       context.Context
	sink      Sink
	top, user string
	seen      map[string]bool
	meta      map[string][]byte
	metaBytes int
	present   map[string]bool
	dumps     map[string]bool
	htaccess  []byte
	homeBytes int64
	homeMade  bool
	site      sitemodel.Site
}

// topUser is the account a top folder names: cpmove-USER, USER, or
// backup-DATE_USER (the restorepkg page's accepted names).
func topUser(top string) string {
	switch {
	case strings.HasPrefix(top, "cpmove-"):
		return strings.TrimPrefix(top, "cpmove-")
	case strings.HasPrefix(top, "backup-"):
		if i := strings.LastIndexByte(top, '_'); i >= 0 {
			return top[i+1:]
		}
		return ""
	}
	return top
}

func (rd *reader) entry(name string, h *tar.Header, body io.Reader) error {
	top, rest, _ := strings.Cut(name, "/")
	switch {
	case rd.top == "":
		rd.top, rd.user = top, topUser(top)
		if !cpsource.UserPattern.MatchString(rd.user) {
			return ErrNotCPMove
		}
	case top != rd.top:
		return ErrArchive
	}
	if rest == "" {
		return nil
	}
	if rest == "homedir" || strings.HasPrefix(rest, "homedir/") {
		return rd.home(strings.TrimPrefix(strings.TrimPrefix(rest, "homedir"), "/"), h, body)
	}
	part, _, _ := strings.Cut(rest, "/")
	rd.present[part] = true
	if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
		return nil
	}
	if strings.HasPrefix(rest, "mysql/") && strings.HasSuffix(rest, ".sql") && strings.Count(rest, "/") == 1 {
		db := strings.TrimSuffix(strings.TrimPrefix(rest, "mysql/"), ".sql")
		if !owned(rd.user, db) {
			rd.skip("database", "The database "+clip(db)+" is not named after the account ("+rd.user+"_ and a suffix), so it was not carried.", rest)
			return nil
		}
		rd.dumps[db] = true
		return rd.file(rest, 0600, h.Size, body)
	}
	if !metadata(rest, rd.user) {
		return nil
	}
	if h.Size > maxMetadataFile || len(rd.meta) >= maxMetadataFiles || rd.metaBytes+int(h.Size) > maxMetadataTotal {
		return ErrLimit
	}
	data, err := io.ReadAll(io.LimitReader(body, h.Size))
	if err != nil {
		return sanitize(err)
	}
	if int64(len(data)) != h.Size {
		return ErrArchive
	}
	rd.metaBytes += len(data)
	rd.meta[rest] = data
	return nil
}

// metadata names the small files Read keeps; the shadow file, mail and
// everything else are never read.
func metadata(rest, user string) bool {
	switch {
	case rest == "cp/"+user, rest == "cron/"+user, rest == "mysql.sql", rest == "version", rest == "quota":
		return true
	case strings.HasPrefix(rest, "userdata/"), strings.HasPrefix(rest, "apache_tls/"):
		return strings.Count(rest, "/") == 1
	}
	return false
}

func (rd *reader) home(rel string, h *tar.Header, body io.Reader) error {
	if !rd.homeMade {
		if err := rd.sink.Dir("home", 0750); err != nil {
			return ErrIO
		}
		rd.homeMade = true
	}
	if rel == "" {
		return nil
	}
	first, _, _ := strings.Cut(rel, "/")
	if homeExcludes[first] {
		if first == "mail" {
			rd.present["homedir/mail"] = true
		}
		return nil
	}
	target := "home/" + rel
	mode := fs.FileMode(h.Mode).Perm()
	switch h.Typeflag {
	case tar.TypeDir:
		if rd.sink.Dir(target, mode) != nil {
			return ErrIO
		}
	case tar.TypeReg, tar.TypeRegA:
		rd.homeBytes += h.Size
		if rel == "public_html/.htaccess" && h.Size <= htaccess.MaxFileBytes {
			data, err := io.ReadAll(io.LimitReader(body, h.Size))
			if err != nil {
				return sanitize(err)
			}
			rd.htaccess = data
			body = bytes.NewReader(data)
		}
		if err := rd.file(target, mode, h.Size, body); err != nil {
			return err
		}
	case tar.TypeSymlink:
		if _, inside := linkTarget(rel, h.Linkname, false); !inside {
			rd.skip("file", "A link to a place outside the website's home was not copied.", rel)
			return nil
		}
		if rd.sink.Symlink(target, h.Linkname) != nil {
			return ErrIO
		}
	case tar.TypeLink:
		rd.skip("file", "A second name (hard link) for another file was not copied; the file itself was.", rel)
	default:
		rd.skip("file", "A device, pipe or other special file was not copied.", rel)
	}
	return nil
}

// file hands one member to the sink and checks it took all of it. A read
// failure (a bound, a broken archive, a cancel) is the archive's, not the
// sink's.
func (rd *reader) file(name string, mode fs.FileMode, size int64, body io.Reader) error {
	counted := &countingReader{r: body}
	if err := rd.sink.File(name, mode, counted); err != nil {
		if rd.ctx.Err() != nil {
			return ErrCanceled
		}
		if counted.err != nil {
			return sanitize(counted.err)
		}
		return ErrIO
	}
	if counted.n != size {
		return ErrArchive
	}
	return nil
}

type countingReader struct {
	r   io.Reader
	n   int64
	err error
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if err != nil && err != io.EOF {
		c.err = err
	}
	return n, err
}

func (rd *reader) skip(part, text, where string) { rd.site.Skip(part, text, where) }

func owned(account, name string) bool {
	return cpsource.DatabasePattern.MatchString(name) && strings.HasPrefix(name, account+"_") && len(name) > len(account)+1
}

func clip(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// archive puts the model together once every entry is read.
func (rd *reader) archive() (*Archive, error) {
	cp, ok := rd.meta["cp/"+rd.user]
	if rd.top == "" || !ok {
		return nil, ErrNotCPMove
	}
	s := &rd.site
	notes := s.NotCarried
	*s = sitemodel.Site{Source: sitemodel.SourceArchive, Account: rd.user, DocRoot: "public_html", Aliases: []string{}, Databases: []sitemodel.Database{}, Users: []sitemodel.User{},
		Cron: []cpsource.CronLine{}, PHP: sitemodel.PHP{Settings: []sitemodel.Setting{}},
		Rules: sitemodel.Rules{Redirects: []sitemodel.Redirect{}, Folders: []string{}, Rewrites: []string{}}, NotCarried: notes}
	a := &Archive{Users: []cpsource.DatabaseUser{}, HomeBytes: rd.homeBytes}
	fields := keyValues(cp)
	main := yamlFile(rd.meta["userdata/main"])
	s.Domain = strings.ToLower(main.value("main_domain"))
	if s.Domain == "" {
		s.Domain = strings.ToLower(fields["DNS"])
	}
	if !cpsource.ValidDomain(s.Domain) || (fields["DNS"] != "" && strings.ToLower(fields["DNS"]) != s.Domain) {
		return nil, fmt.Errorf("%w: the backup's main domain could not be read", ErrNotCPMove)
	}
	for _, alias := range main.list("parked_domains") {
		alias = strings.ToLower(alias)
		if cpsource.ValidDomain(alias) && alias != s.Domain && len(s.Aliases) < sitemodel.MaxAliases {
			s.Aliases = append(s.Aliases, alias)
		}
	}
	for _, sub := range append(main.list("sub_domains"), main.keys("addon_domains")...) {
		s.Skip("domain", "The sub-domain or addon domain "+clip(sub)+" has its own folder; this version moves the main domain's website. Move or add it as a website of its own.", "userdata/main")
	}
	site := yamlFile(rd.meta["userdata/"+s.Domain])
	home, root := site.value("homedir"), site.value("documentroot")
	if rel, ok := strings.CutPrefix(root, home+"/"); home != "" && ok && path.Clean(rel) == rel && !strings.HasPrefix(rel, "../") {
		s.DocRoot = rel
	} else if root != "" {
		s.DocRoot = ""
		s.Skip("files", "The website's document root is not inside the account's home, so its files cannot be placed here as they are.", "userdata/"+s.Domain)
	}
	for _, alias := range strings.Fields(site.value("serveralias")) {
		if strings.EqualFold(alias, "www."+s.Domain) {
			s.WWW = true
		}
	}
	s.PHP.Source = site.value("phpversion")
	s.PHP.Version, s.PHP.Exact = cpsource.PHPVersion(s.PHP.Source)
	if rd.htaccess != nil {
		s.HtaccessSettings("public_html/.htaccess", rd.htaccess)
	}
	if q, err := strconv.ParseInt(strings.TrimSpace(string(rd.meta["quota"])), 10, 64); err == nil && q > 0 {
		s.DiskLimitMiB = (q + 1<<20 - 1) >> 20
	}
	s.DiskUsedMiB = (rd.homeBytes + 1<<20 - 1) >> 20
	if data, ok := rd.meta["cron/"+rd.user]; ok {
		jobs, skipped, err := cpsource.ParseCrontab(data)
		if err != nil {
			s.Skip("cron", "The account's scheduled jobs could not be read, so none were carried.", "cron/"+rd.user)
		}
		s.Cron = append(s.Cron, jobs...)
		for _, why := range skipped {
			s.Skip("cron", "A scheduled-job line was not copied: "+why+".", "cron/"+rd.user)
		}
	}
	dbs := make([]string, 0, len(rd.dumps))
	for db := range rd.dumps {
		dbs = append(dbs, db)
	}
	sort.Strings(dbs)
	for _, db := range dbs {
		if len(s.Databases) == sitemodel.MaxDatabases {
			s.Skip("database", "The website has more databases than one move carries; "+db+" was not carried.", "mysql/"+db+".sql")
			continue
		}
		s.Databases = append(s.Databases, sitemodel.Database{Name: db, Dump: "mysql/" + db + ".sql"})
	}
	a.Users = rd.grants(s, rd.meta["mysql.sql"], dbs)
	for _, u := range a.Users {
		s.Users = append(s.Users, sitemodel.User{Name: u.Name, HasHash: u.Hash != "", Grants: u.Grants})
	}
	rd.certificate(a, s, rd.meta["apache_tls/"+s.Domain])
	for _, p := range []struct{ key, part, text string }{
		{"homedir/mail", "mail", "Email accounts and their mail stay with the old host: this version moves the website. Point the domain's MX records where the mail is."},
		{"va", "mail", "Email forwarders and autoresponders are not carried."},
		{"dnszones", "dns", "The DNS zone is not carried: the domain's DNS stays where it is, and the move names the records to change."},
		{"psql", "database", "PostgreSQL databases are not carried: this server runs MariaDB."},
		{"mm", "mail", "Mailing lists are not carried."},
		{"proftpdpasswd", "ftp", "FTP accounts are not carried: this server gives the website SFTP with keys."},
	} {
		if rd.present[p.key] {
			s.Skip(p.part, p.text, "")
		}
	}
	if err := s.Check(); err != nil {
		return nil, err
	}
	a.Site = *s
	return a, nil
}

// keyValues reads cp/USER's KEY=value lines.
func keyValues(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k != "" {
			out[k] = v
		}
	}
	return out
}

// yaml is the flat subset of YAML cPanel's userdata files use: top-level
// "key: value" lines, "key:" with "  - item" lines under it, and "key:"
// with "  name: value" lines (a map, whose names keys returns).
type yaml struct {
	values map[string]string
	lists  map[string][]string
	maps   map[string][]string
}

var yamlKey = regexp.MustCompile(`^([A-Za-z0-9_.-]+):(?:\s+(.*))?$`)

func yamlFile(data []byte) yaml {
	y := yaml{values: map[string]string{}, lists: map[string][]string{}, maps: map[string][]string{}}
	current := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, " \t\r")
		switch {
		case line == "" || line == "---" || strings.HasPrefix(strings.TrimSpace(line), "#"):
		case strings.HasPrefix(line, " "):
			item := strings.TrimSpace(line)
			if current == "" {
				continue
			}
			if v, ok := strings.CutPrefix(item, "- "); ok {
				y.lists[current] = append(y.lists[current], unquote(v))
			} else if m := yamlKey.FindStringSubmatch(item); m != nil {
				y.maps[current] = append(y.maps[current], unquote(m[1]))
			}
		default:
			m := yamlKey.FindStringSubmatch(line)
			if m == nil {
				current = ""
				continue
			}
			current = m[1]
			if v := strings.TrimSpace(m[2]); v != "" && v != "{}" && v != "[]" && v != "~" {
				y.values[current] = unquote(v)
			}
		}
	}
	return y
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' && s[len(s)-1] == '\'' || s[0] == '"' && s[len(s)-1] == '"') {
		return s[1 : len(s)-1]
	}
	return s
}

func (y yaml) value(k string) string  { return y.values[k] }
func (y yaml) list(k string) []string { return y.lists[k] }
func (y yaml) keys(k string) []string { return y.maps[k] }

// grantLine is one line of mysql.sql as MariaDB's SHOW GRANTS prints it,
// which pkgacct writes there: privileges, the database (or *.*), the user
// and host, and for the USAGE line the mysql_native_password hash.
var grantLine = regexp.MustCompile("^GRANT (.+) ON (\\*\\.\\*|`([^`]+)`\\.\\*) TO '([^']+)'@'([^']+)'(?: IDENTIFIED BY PASSWORD '(\\*[0-9A-F]{40})')?.*$")

var (
	knownPrivileges = map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "CREATE": true, "DROP": true, "REFERENCES": true, "INDEX": true,
		"ALTER": true, "CREATE TEMPORARY TABLES": true, "LOCK TABLES": true, "CREATE VIEW": true, "SHOW VIEW": true, "CREATE ROUTINE": true,
		"ALTER ROUTINE": true, "EXECUTE": true, "EVENT": true, "TRIGGER": true}
	nativeHash = regexp.MustCompile(`^\*[0-9A-F]{40}$`)
)

// grants reads mysql.sql into the account's database users, with their
// hashes and their grants on the account's own databases at localhost.
func (rd *reader) grants(s *sitemodel.Site, data []byte, dbs []string) []cpsource.DatabaseUser {
	known := map[string]bool{}
	for _, d := range dbs {
		known[d] = true
	}
	users := map[string]*cpsource.DatabaseUser{}
	var order []string
	noted := map[string]bool{}
	note := func(part, text string) {
		if !noted[text] {
			noted[text] = true
			s.Skip(part, text, "mysql.sql")
		}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(strings.TrimSpace(raw), ";")
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		m := grantLine.FindStringSubmatch(line)
		if m == nil {
			note("database", "A line of the database grants could not be read, so it was not carried.")
			continue
		}
		privileges, db, user, host, hash := m[1], m[3], m[4], m[5], m[6]
		switch {
		case user == rd.user:
			note("database", "The database user "+rd.user+" is the cPanel account's own sign-in; it is not carried. The website's own database users are.")
			continue
		case !owned(rd.user, user):
			note("database", "The database user "+clip(user)+" is not named after the account, so it was not carried.")
			continue
		case host != "localhost":
			note("database", "A grant of "+user+" from hosts other than localhost was not carried: the website reaches its database on this server only.")
			continue
		}
		u := users[user]
		if u == nil {
			if len(order) == sitemodel.MaxUsers {
				note("database", "The website has more database users than one move carries.")
				continue
			}
			u = &cpsource.DatabaseUser{Name: user, Grants: []cpsource.Grant{}}
			users[user] = u
			order = append(order, user)
		}
		if hash != "" && nativeHash.MatchString(hash) {
			u.Hash = hash
		}
		if m[2] == "*.*" {
			continue
		}
		db = unescapeDB(db)
		if !known[db] {
			note("database", "A database grant was not copied: a grant of "+user+" on a database name pattern or another database.")
			continue
		}
		var privs []string
		for _, p := range strings.Split(privileges, ",") {
			p = strings.TrimSpace(p)
			switch {
			case p == "ALL PRIVILEGES" || p == "ALL":
				privs = []string{"ALL PRIVILEGES"}
			case knownPrivileges[p]:
				privs = append(privs, p)
			default:
				note("database", "The database privilege "+clip(p)+" is not one this server grants, so it was left out.")
			}
			if len(privs) == 1 && privs[0] == "ALL PRIVILEGES" {
				break
			}
		}
		if len(privs) > 0 {
			u.Grants = append(u.Grants, cpsource.Grant{Database: db, Privileges: privs})
		}
	}
	out := []cpsource.DatabaseUser{}
	for _, name := range order {
		u := *users[name]
		if u.Hash == "" {
			u.Problem = "The backup keeps no mysql_native_password hash for " + u.Name + " (it uses another sign-in method), so its password cannot move as it is."
		}
		out = append(out, u)
	}
	return out
}

// unescapeDB undoes SHOW GRANTS' escaping of _ and %; a name with an
// unescaped % or _ is a pattern, which matches no dump name exactly.
func unescapeDB(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case s[i] == '%' || s[i] == '_':
			return ""
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// certificate reads apache_tls/DOMAIN, the key and certificate chain the
// account's virtual host served, into the archive; the model gets what the
// certificate says, never the key.
func (rd *reader) certificate(a *Archive, s *sitemodel.Site, data []byte) {
	if len(data) == 0 {
		return
	}
	var certs, key []byte
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			certs = append(certs, pem.EncodeToMemory(block)...)
		case strings.HasSuffix(block.Type, "PRIVATE KEY") && key == nil:
			key = pem.EncodeToMemory(block)
		}
	}
	block, _ := pem.Decode(certs)
	if block == nil {
		s.Skip("certificate", "The backup's certificate for "+s.Domain+" could not be read, so it was not carried. The website gets a new one once its domain points here.", "apache_tls/"+s.Domain)
		return
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.Skip("certificate", "The backup's certificate for "+s.Domain+" could not be read, so it was not carried. The website gets a new one once its domain points here.", "apache_tls/"+s.Domain)
		return
	}
	s.Certificate = &sitemodel.Certificate{Domains: append([]string{}, leaf.DNSNames...), Issuer: clip(leaf.Issuer.CommonName), NotAfter: leaf.NotAfter.UTC(), HasKey: key != nil}
	a.CertificatePEM, a.KeyPEM = certs, key
}

// RootSink writes what Read extracts under an os.Root: every name stays
// inside it, whatever links the archive made. Directories are made with
// the owner's write bit, so their own files can follow; files must be new.
type RootSink struct{ Root *os.Root }

func (s RootSink) Dir(name string, mode fs.FileMode) error {
	if err := s.Root.MkdirAll(path.Dir(name), 0700); err != nil {
		return err
	}
	err := s.Root.Mkdir(name, mode.Perm()|0700)
	if errors.Is(err, fs.ErrExist) {
		if info, statErr := s.Root.Lstat(name); statErr == nil && info.IsDir() {
			return s.Root.Chmod(name, mode.Perm()|0700)
		}
	}
	return err
}

func (s RootSink) File(name string, mode fs.FileMode, r io.Reader) error {
	if err := s.Root.MkdirAll(path.Dir(name), 0700); err != nil {
		return err
	}
	f, err := s.Root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	_, err = io.CopyBuffer(f, r, make([]byte, 32768))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (s RootSink) Symlink(name, target string) error {
	if err := s.Root.MkdirAll(path.Dir(name), 0700); err != nil {
		return err
	}
	return s.Root.Symlink(target, name)
}
