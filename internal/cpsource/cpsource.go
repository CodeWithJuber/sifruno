// Package cpsource is what migration v1 reads from a cPanel server over root
// SSH: the fixed commands the broker runs there, and parsers for what they
// print. It runs nothing and reads no file; the root broker
// (internal/hostaccounts) runs the commands with the migration's own key and
// gives the output to these parsers.
//
// cPanel's behaviour is taken from its public API documentation only, read
// on 2026-11-24:
//
//   - Command line use of both APIs: https://api.docs.cpanel.net/whm/introduction
//     and https://api.docs.cpanel.net/cpanel/introduction ("whmapi1
//     --output=json function key=value", "uapi --user=username
//     --output=json Module function"; on CloudLinux the full paths
//     /usr/local/cpanel/bin/whmapi1 and /usr/local/cpanel/bin/uapi are
//     required, so they are always used here). A command line call returns
//     no metadata when an error stops the function.
//   - Each function's page is cited where its command is built.
//
// Database password hashes and grants come from MariaDB itself (SHOW CREATE
// USER, the mysql.db grant table), not from a cPanel API: cPanel's APIs do
// not return them.
//
// Every value put into a command passes a strict pattern first, so the
// source's root shell, which reads the command line, sees only fixed words
// and plain names.
package cpsource

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The programs run on the source. whmapi1 and uapi are cPanel's own command
// line tools (see the package comment for their documentation).
const (
	whmapi1  = "/usr/local/cpanel/bin/whmapi1"
	uapi     = "/usr/local/cpanel/bin/uapi"
	crontab  = "/usr/bin/crontab"
	keysFile = "/root/.ssh/authorized_keys"
)

// Limits on what the source may answer, so a broken or hostile source cannot
// make the broker hold unbounded data.
const (
	MaxAccounts   = 5000
	MaxDatabases  = 64
	MaxUsers      = 64
	MaxCronLines  = 200
	MaxTables     = 2000
	MaxOutput     = 8 << 20
	maxCronLine   = 1024
	maxTableName  = 64
	maxAliasCount = 64
)

var (
	// UserPattern is a cPanel username that is also a Sifruno account name
	// (hostaccounts: 3 to 32 of [a-z0-9_], starting with a letter).
	UserPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)
	domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	// DatabasePattern is dbhost's identifier rule for a database or user.
	DatabasePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	homePattern     = regexp.MustCompile(`^(/[a-z0-9_]+)+$`)
	idPattern       = regexp.MustCompile(`^[a-f0-9]{32}$`)
	// nativeHash is a mysql_native_password hash: "*" and 40 hex digits.
	nativeHash = regexp.MustCompile(`^\*[0-9A-F]{40}$`)
	sizeMiB    = regexp.MustCompile(`^([0-9]{1,12})M?$`)
)

// ValidDomain reports whether s is a lowercase DNS name with two labels or
// more, the form Sifruno's accounts take.
func ValidDomain(s string) bool { return len(s) <= 253 && domainPattern.MatchString(s) }

// ErrOutput means the source printed something this package does not read
// as the documented shape.
var ErrOutput = errors.New("the old server's answer could not be read")

// ListAccountsCommand lists every cPanel account.
// WHM API 1 listaccts: https://api.docs.cpanel.net/openapi/whm/operation/listaccts/
func ListAccountsCommand() string { return whmapi1 + " --output=json listaccts" }

// DomainUserDataCommand reads a domain's virtual host data: its user, home
// and document root.
// WHM API 1 domainuserdata: https://api.docs.cpanel.net/openapi/whm/operation/domainuserdata/
func DomainUserDataCommand(domain string) (string, error) {
	if !ValidDomain(domain) {
		return "", ErrOutput
	}
	return whmapi1 + " --output=json domainuserdata domain=" + domain, nil
}

// VhostPHPCommand lists the PHP version of every virtual host (EasyApache 4).
// WHM API 1 php_get_vhost_versions: https://api.docs.cpanel.net/openapi/whm/operation/php_get_vhost_versions/
func VhostPHPCommand() string { return whmapi1 + " --output=json php_get_vhost_versions" }

// DatabasesCommand lists the account's MySQL databases with their users.
// UAPI Mysql::list_databases: https://api.docs.cpanel.net/openapi/cpanel/operation/list_databases/
func DatabasesCommand(user string) (string, error) {
	if !UserPattern.MatchString(user) {
		return "", ErrOutput
	}
	return uapi + " --output=json --user=" + user + " Mysql list_databases", nil
}

// DatabaseUsersCommand lists the account's MySQL users with their databases.
// UAPI Mysql::list_users: https://api.docs.cpanel.net/specifications/cpanel.openapi/user-management/mysql-list_users
func DatabaseUsersCommand(user string) (string, error) {
	if !UserPattern.MatchString(user) {
		return "", ErrOutput
	}
	return uapi + " --output=json --user=" + user + " Mysql list_users", nil
}

// CrontabCommand prints the user's crontab. cronie's crontab exits 1 with
// "no crontab for" on stderr when the user has none; the caller reads that
// as no jobs.
func CrontabCommand(user string) (string, error) {
	if !UserPattern.MatchString(user) {
		return "", ErrOutput
	}
	return crontab + " -l -u " + user, nil
}

// SQLCommand runs SQL from standard input as the source's root database
// user, who signs in from /root/.my.cnf on a cPanel server. Newer MariaDB
// ships the client as mariadb; older servers have only mysql.
func SQLCommand() string {
	args := " --batch --skip-column-names --raw"
	return "if [ -x /usr/bin/mariadb ]; then exec /usr/bin/mariadb" + args + "; else exec /usr/bin/mysql" + args + "; fi"
}

// DumpCommand dumps one database's tables and rows, as the broker's own
// backup does: no triggers, routines or events (a database holding them, or
// views, is refused before the dump), binary columns in hex, one consistent
// transaction for InnoDB.
func DumpCommand(db string) (string, error) {
	if !DatabasePattern.MatchString(db) {
		return "", ErrOutput
	}
	args := " --single-transaction --quick --skip-triggers --hex-blob --no-tablespaces --default-character-set=utf8mb4 -- " + db
	return "if [ -x /usr/bin/mariadb-dump ]; then exec /usr/bin/mariadb-dump" + args + "; else exec /usr/bin/mysqldump" + args + "; fi", nil
}

// KeyComment names one migration's key in the source's authorized_keys.
func KeyComment(id string) string { return "sifruno-migration-" + id }

// KeyLine is the authorized_keys line the admin adds on the source: the
// broker's public key, with "restrict" (no forwarding, no terminal) and the
// migration's comment, which RemoveKeyCommand removes it by.
func KeyLine(publicKey, id string) string { return "restrict " + publicKey + " " + KeyComment(id) }

// InstallKeyCommand is what the admin runs as root on the source to add the
// key line. It only appends; Sifruno never sees a password of the source.
func InstallKeyCommand(publicKey, id string) string {
	return "mkdir -p /root/.ssh && chmod 700 /root/.ssh && printf '\\n%s\\n' '" + KeyLine(publicKey, id) + "' >> " + keysFile + " && chmod 600 " + keysFile
}

// RemoveKeyCommand deletes exactly the lines this migration's install added
// (starting with "restrict ssh-ed25519 " and ending with its comment) from
// root's authorized_keys on the source.
func RemoveKeyCommand(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrOutput
	}
	return "/usr/bin/sed -i -e '/^restrict ssh-ed25519 [A-Za-z0-9+\\/=]* " + KeyComment(id) + "$/d' " + keysFile, nil
}

// Account is one cPanel account as listaccts shows it. Problem is why
// migration v1 cannot move it, or "".
type Account struct {
	User         string `json:"user"`
	Domain       string `json:"domain"`
	DiskUsedMiB  int64  `json:"disk_used_mib"`
	DiskLimitMiB int64  `json:"disk_limit_mib"` // 0: unlimited
	Suspended    bool   `json:"suspended"`
	Problem      string `json:"problem,omitempty"`
}

// ParseAccounts reads whmapi1 --output=json listaccts: data.acct is the list,
// each with user, domain, diskused ("14M"), disklimit ("unlimited" or MB)
// and suspended (1 or 0).
func ParseAccounts(out []byte) ([]Account, error) {
	var raw struct {
		Data struct {
			Acct []struct {
				User      string          `json:"user"`
				Domain    string          `json:"domain"`
				DiskUsed  json.RawMessage `json:"diskused"`
				DiskLimit json.RawMessage `json:"disklimit"`
				Suspended json.RawMessage `json:"suspended"`
			} `json:"acct"`
		} `json:"data"`
	}
	if len(out) > MaxOutput || json.Unmarshal(out, &raw) != nil || len(raw.Data.Acct) > MaxAccounts {
		return nil, ErrOutput
	}
	items := make([]Account, 0, len(raw.Data.Acct))
	for _, a := range raw.Data.Acct {
		used, okUsed := mib(a.DiskUsed)
		limit, okLimit := mib(a.DiskLimit)
		item := Account{User: a.User, Domain: a.Domain, DiskUsedMiB: used, DiskLimitMiB: limit, Suspended: flag(a.Suspended)}
		switch {
		case !UserPattern.MatchString(a.User):
			item.User = clean(a.User, 32)
			item.Problem = "The account name does not fit this server's rule (3 to 32 lowercase letters, digits or _, starting with a letter), so it cannot keep its name here."
		case !ValidDomain(a.Domain):
			item.Domain = clean(a.Domain, 253)
			item.Problem = "The account's main domain is not a plain lowercase domain name."
		case !okUsed || !okLimit:
			item.Problem = "The old server's disk figures for this account could not be read."
		case item.Suspended:
			item.Problem = "The account is suspended on the old server. Unsuspend it there first."
		}
		items = append(items, item)
	}
	return items, nil
}

// mib reads a size in MB: a number, or a string of digits with an optional
// "M"; "unlimited" is 0.
func mib(raw json.RawMessage) (int64, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		var n json.Number
		if json.Unmarshal(raw, &n) != nil {
			return 0, false
		}
		s = n.String()
	}
	if s == "unlimited" || s == "" {
		return 0, true
	}
	m := sizeMiB.FindStringSubmatch(s)
	if m == nil {
		if f, err := strconv.ParseFloat(strings.TrimSuffix(s, "M"), 64); err == nil && f >= 0 && f < 1e12 {
			return int64(f + 0.999), true
		}
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	return n, err == nil
}

func flag(raw json.RawMessage) bool {
	s := strings.Trim(string(raw), `"`)
	return s == "1" || s == "true"
}

// clean keeps a printable, bounded copy of a name the source sent, for
// display only.
func clean(s string, max int) string {
	b := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsPrint(r) && len(b) < max {
			b = append(b, r)
		}
	}
	return string(b)
}

// Site is the domain's virtual host as domainuserdata shows it.
type Site struct {
	User         string
	HomeDir      string
	DocumentRoot string
	// Aliases are the virtual host's other names, www.<domain> left out.
	Aliases []string
}

// ParseSite reads whmapi1 --output=json domainuserdata and checks that the
// site is the account's main site in its public_html: migration v1 keeps
// /home/<user>/public_html, so a site elsewhere is refused.
func ParseSite(out []byte, user, domain string) (Site, error) {
	var raw struct {
		Data struct {
			Userdata struct {
				User         string `json:"user"`
				HomeDir      string `json:"homedir"`
				DocumentRoot string `json:"documentroot"`
				ServerName   string `json:"servername"`
				ServerAlias  string `json:"serveralias"`
			} `json:"userdata"`
		} `json:"data"`
	}
	if len(out) > MaxOutput || json.Unmarshal(out, &raw) != nil {
		return Site{}, ErrOutput
	}
	u := raw.Data.Userdata
	if u.User != user || u.ServerName != domain {
		return Site{}, fmt.Errorf("%w: the domain belongs to another account or virtual host", ErrOutput)
	}
	if !homePattern.MatchString(u.HomeDir) || path.Base(u.HomeDir) != user || path.Clean(u.HomeDir) != u.HomeDir {
		return Site{}, fmt.Errorf("%w: the account's home folder is not a plain path ending in its name", ErrOutput)
	}
	if u.DocumentRoot != u.HomeDir+"/public_html" {
		return Site{}, ErrNotPublicHTML
	}
	site := Site{User: u.User, HomeDir: u.HomeDir, DocumentRoot: u.DocumentRoot, Aliases: []string{}}
	for _, alias := range strings.Fields(u.ServerAlias) {
		if alias == "www."+domain || alias == domain {
			continue
		}
		if !ValidDomain(alias) || len(site.Aliases) >= maxAliasCount {
			return Site{}, fmt.Errorf("%w: an alias of the site is not a plain domain name", ErrOutput)
		}
		site.Aliases = append(site.Aliases, alias)
	}
	return site, nil
}

// ErrNotPublicHTML is a site whose document root is not the account's
// public_html: migration v1 does not move it.
var ErrNotPublicHTML = errors.New("the site's files are not in the account's public_html")

// ParseVhostPHP reads whmapi1 --output=json php_get_vhost_versions and
// returns the version of the domain's virtual host, such as "ea-php81".
func ParseVhostPHP(out []byte, user, domain string) (string, error) {
	var raw struct {
		Data struct {
			Versions []struct {
				Vhost   string `json:"vhost"`
				Account string `json:"account"`
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"data"`
	}
	if len(out) > MaxOutput || json.Unmarshal(out, &raw) != nil {
		return "", ErrOutput
	}
	for _, v := range raw.Data.Versions {
		if v.Vhost == domain && v.Account == user {
			if len(v.Version) > 64 || !utf8.ValidString(v.Version) {
				return "", ErrOutput
			}
			return v.Version, nil
		}
	}
	return "", fmt.Errorf("%w: the old server lists no PHP version for the site", ErrOutput)
}

// PHPVersion maps the source's PHP package (ea-php81, alt-php81, inherit)
// to one this server runs (8.1 to 8.4). exact is false when the copy runs
// another version than the old site: older than 8.1 becomes 8.1, a version
// this package does not know becomes 8.3.
func PHPVersion(source string) (version string, exact bool) {
	digits := ""
	for _, prefix := range []string{"ea-php", "alt-php"} {
		if rest, ok := strings.CutPrefix(source, prefix); ok && len(rest) == 2 && rest[0] >= '0' && rest[0] <= '9' && rest[1] >= '0' && rest[1] <= '9' {
			digits = rest
		}
	}
	if digits == "" {
		return "8.3", false
	}
	v := digits[:1] + "." + digits[1:]
	switch v {
	case "8.1", "8.2", "8.3", "8.4":
		return v, true
	}
	if digits < "81" {
		return "8.1", false
	}
	return "8.4", false
}

// Database is one source database and the users granted on it.
type Database struct {
	Name  string   `json:"name"`
	Users []string `json:"users"`
}

// uapiResult unwraps UAPI's command line answer: {"result": {"data": ...,
// "status": 1, "errors": ...}}, with apiversion, func and module beside it.
func uapiResult(out []byte, data any) error {
	var raw struct {
		Result struct {
			Data   json.RawMessage `json:"data"`
			Status int             `json:"status"`
		} `json:"result"`
	}
	if len(out) > MaxOutput || json.Unmarshal(out, &raw) != nil || raw.Result.Status != 1 {
		return ErrOutput
	}
	if json.Unmarshal(raw.Result.Data, data) != nil {
		return ErrOutput
	}
	return nil
}

// ParseDatabases reads uapi Mysql list_databases: data is a list of
// {database, disk_usage, users}. Every name must carry the account's
// "<user>_" prefix, as Sifruno's databases do.
func ParseDatabases(out []byte, user string) ([]Database, error) {
	var items []struct {
		Database string   `json:"database"`
		Users    []string `json:"users"`
	}
	if err := uapiResult(out, &items); err != nil || len(items) > MaxDatabases {
		return nil, ErrOutput
	}
	dbs := make([]Database, 0, len(items))
	for _, d := range items {
		if !DatabasePattern.MatchString(d.Database) || !strings.HasPrefix(d.Database, user+"_") {
			return nil, fmt.Errorf("%w: the database %q does not carry the account's %s_ prefix", ErrUnprefixed, clean(d.Database, 64), user)
		}
		users := []string{}
		for _, u := range d.Users {
			if !DatabasePattern.MatchString(u) || len(u) > 47 || !strings.HasPrefix(u, user+"_") {
				return nil, fmt.Errorf("%w: the database user %q does not carry the account's %s_ prefix", ErrUnprefixed, clean(u, 64), user)
			}
			users = append(users, u)
		}
		dbs = append(dbs, Database{Name: d.Database, Users: users})
	}
	return dbs, nil
}

// ErrUnprefixed is a database or database user without the account's
// prefix: Sifruno ties every database to its account by that prefix.
var ErrUnprefixed = errors.New("a database name lacks the account's prefix")

// ParseDatabaseUsers reads uapi Mysql list_users: data is a list of {user,
// shortuser, databases}. It returns the full user names.
func ParseDatabaseUsers(out []byte, user string) ([]string, error) {
	var items []struct {
		User string `json:"user"`
	}
	if err := uapiResult(out, &items); err != nil || len(items) > MaxUsers {
		return nil, ErrOutput
	}
	names := make([]string, 0, len(items))
	for _, u := range items {
		if !DatabasePattern.MatchString(u.User) || len(u.User) > 47 || !strings.HasPrefix(u.User, user+"_") {
			return nil, fmt.Errorf("%w: the database user %q does not carry the account's %s_ prefix", ErrUnprefixed, clean(u.User, 64), user)
		}
		names = append(names, u.User)
	}
	return names, nil
}

func sqlString(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

func sqlIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// userMark starts each user's lines in the answer to UsersSQL.
const userMark = "sifruno-user"

// privilegeColumns are the mysql.db columns of the privileges dbhost
// grants, in its names. Grant_priv is left out: dbhost never grants it.
var privilegeColumns = []struct{ column, privilege string }{
	{"Select_priv", "SELECT"}, {"Insert_priv", "INSERT"}, {"Update_priv", "UPDATE"}, {"Delete_priv", "DELETE"},
	{"Create_priv", "CREATE"}, {"Drop_priv", "DROP"}, {"References_priv", "REFERENCES"}, {"Index_priv", "INDEX"},
	{"Alter_priv", "ALTER"}, {"Create_tmp_table_priv", "CREATE TEMPORARY TABLES"}, {"Lock_tables_priv", "LOCK TABLES"},
	{"Create_view_priv", "CREATE VIEW"}, {"Show_view_priv", "SHOW VIEW"}, {"Create_routine_priv", "CREATE ROUTINE"},
	{"Alter_routine_priv", "ALTER ROUTINE"}, {"Execute_priv", "EXECUTE"}, {"Event_priv", "EVENT"}, {"Trigger_priv", "TRIGGER"},
}

// UsersSQL asks the source's MariaDB for each user's password hash (SHOW
// CREATE USER) and database grants (the mysql.db table), for the user at
// localhost, the host cPanel and dbhost grant. The names were checked by
// ParseDatabaseUsers.
func UsersSQL(users []string) (string, error) {
	var b strings.Builder
	quoted := make([]string, 0, len(users))
	for _, u := range users {
		if !DatabasePattern.MatchString(u) {
			return "", ErrOutput
		}
		quoted = append(quoted, sqlString(u))
		fmt.Fprintf(&b, "SELECT '%s', %s;\nSHOW CREATE USER %s@'localhost';\n", userMark, sqlString(u), sqlString(u))
	}
	if len(users) > 0 {
		cols := make([]string, 0, len(privilegeColumns))
		for _, c := range privilegeColumns {
			cols = append(cols, c.column)
		}
		fmt.Fprintf(&b, "SELECT 'sifruno-grant', User, Db, %s FROM mysql.db WHERE Host='localhost' AND User IN (%s) ORDER BY User, Db;\n", strings.Join(cols, ", "), strings.Join(quoted, ", "))
	}
	return b.String(), nil
}

// DatabaseUser is one source user: its mysql_native_password hash, or
// Problem when it has none this server can use, and its grants.
type DatabaseUser struct {
	Name    string  `json:"name"`
	Hash    string  `json:"hash,omitempty"`
	Problem string  `json:"problem,omitempty"`
	Grants  []Grant `json:"grants"`
}

// Grant is one user's privileges on one database, in dbhost's names.
type Grant struct {
	Database   string   `json:"database"`
	Privileges []string `json:"privileges"`
}

var (
	// MariaDB prints "IDENTIFIED BY PASSWORD '*...'" or "IDENTIFIED VIA
	// mysql_native_password USING '*...'"; MySQL "IDENTIFIED WITH
	// 'mysql_native_password' AS '*...'".
	hashForms = []*regexp.Regexp{
		regexp.MustCompile(`IDENTIFIED BY PASSWORD '(\*[0-9A-F]{40})'`),
		regexp.MustCompile(`IDENTIFIED VIA mysql_native_password USING '(\*[0-9A-F]{40})'`),
		regexp.MustCompile("IDENTIFIED WITH [`']?mysql_native_password[`']? AS '(\\*[0-9A-F]{40})'"),
	}
)

// ParseUsers reads the answer to UsersSQL. A user without a
// mysql_native_password hash gets Problem: plan says such a user needs a
// new password, so the migration stops for it. dbs are the account's
// databases; a grant on anything else (a pattern, another account's
// database) is left out and listed in skipped.
func ParseUsers(out []byte, users []string, dbs []string) (items []DatabaseUser, skipped []string, err error) {
	if len(out) > MaxOutput || !utf8.Valid(out) {
		return nil, nil, ErrOutput
	}
	byName := map[string]*DatabaseUser{}
	for _, u := range users {
		items = append(items, DatabaseUser{Name: u, Grants: []Grant{}})
	}
	for i := range items {
		byName[items[i].Name] = &items[i]
	}
	known := map[string]bool{}
	for _, d := range dbs {
		known[d] = true
	}
	var current *DatabaseUser
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		switch {
		case len(fields) == 2 && fields[0] == userMark:
			current = byName[fields[1]]
			if current == nil {
				return nil, nil, ErrOutput
			}
		case len(fields) == 3+len(privilegeColumns) && fields[0] == "sifruno-grant":
			u := byName[fields[1]]
			if u == nil {
				return nil, nil, ErrOutput
			}
			db := unescapeGrantDB(fields[2])
			if !known[db] {
				skipped = append(skipped, "a grant of "+u.Name+" on a database name pattern or another database")
				continue
			}
			var privs []string
			for i, c := range privilegeColumns {
				switch fields[3+i] {
				case "Y":
					privs = append(privs, c.privilege)
				case "N":
				default:
					return nil, nil, ErrOutput
				}
			}
			switch {
			case len(privs) == len(privilegeColumns):
				privs = []string{"ALL PRIVILEGES"}
			case len(privs) == 0:
				continue
			}
			u.Grants = append(u.Grants, Grant{Database: db, Privileges: privs})
		case len(fields) == 1 && current != nil && strings.HasPrefix(line, "CREATE USER "):
			current.Hash = ""
			for _, form := range hashForms {
				if m := form.FindStringSubmatch(line); m != nil && nativeHash.MatchString(m[1]) {
					current.Hash = m[1]
				}
			}
			current = nil
		default:
			return nil, nil, ErrOutput
		}
	}
	for i := range items {
		if items[i].Hash == "" {
			items[i].Problem = "The old server keeps no mysql_native_password hash for " + items[i].Name + " (it uses another sign-in method), so its password cannot move as it is."
		}
	}
	return items, skipped, nil
}

// unescapeGrantDB undoes the escaping of "_" and "%" in mysql.db's Db
// column. An unescaped "_" is read as the letter: the grant then covers at
// least that database, and the copy grants on it alone, which is narrower
// than the source. An unescaped "%" makes the name match no database, so
// the grant is left out.
func unescapeGrantDB(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if s[i] == '%' {
			return "\x00" + s
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ObjectsSQL lists what a table-and-rows dump would leave out (views,
// triggers, routines, events) and whether the database exists, as the
// broker's own backup checks before a dump.
func ObjectsSQL(db string) (string, error) {
	if !DatabasePattern.MatchString(db) {
		return "", ErrOutput
	}
	q := sqlString(db)
	return "SELECT 'missing' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=" + q + ")" +
		" UNION ALL SELECT 'view' FROM information_schema.VIEWS WHERE TABLE_SCHEMA=" + q +
		" UNION ALL SELECT 'trigger' FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=" + q +
		" UNION ALL SELECT 'routine' FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=" + q +
		" UNION ALL SELECT 'event' FROM information_schema.EVENTS WHERE EVENT_SCHEMA=" + q + ";\n", nil
}

// TablesSQL lists the database's base tables.
func TablesSQL(db string) (string, error) {
	if !DatabasePattern.MatchString(db) {
		return "", ErrOutput
	}
	return "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=" + sqlString(db) + " AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME;\n", nil
}

// ParseTables reads the answer to TablesSQL. A table name with a control
// character or past 64 bytes is refused: the counts' answer could not be
// read back line by line.
func ParseTables(out []byte) ([]string, error) {
	if len(out) > MaxOutput || !utf8.Valid(out) {
		return nil, ErrOutput
	}
	tables := []string{}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		if len(line) > maxTableName || strings.ContainsFunc(line, unicode.IsControl) || strings.ContainsAny(line, `'\`) || len(tables) >= MaxTables {
			return nil, ErrOutput
		}
		tables = append(tables, line)
	}
	return tables, nil
}

// CountsSQL counts every table's rows exactly.
func CountsSQL(db string, tables []string) (string, error) {
	if !DatabasePattern.MatchString(db) || len(tables) > MaxTables {
		return "", ErrOutput
	}
	if len(tables) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(tables))
	for _, t := range tables {
		if len(t) > maxTableName || strings.ContainsFunc(t, unicode.IsControl) {
			return "", ErrOutput
		}
		parts = append(parts, "SELECT "+sqlString(t)+", COUNT(*) FROM "+sqlIdent(db)+"."+sqlIdent(t))
	}
	return strings.Join(parts, " UNION ALL ") + ";\n", nil
}

// ParseCounts reads the answer to CountsSQL for exactly these tables.
func ParseCounts(out []byte, tables []string) (map[string]int64, error) {
	if len(out) > MaxOutput || !utf8.Valid(out) {
		return nil, ErrOutput
	}
	want := map[string]bool{}
	for _, t := range tables {
		want[t] = true
	}
	counts := map[string]int64{}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "\t")
		n, err := strconv.ParseInt(value, 10, 64)
		if !ok || err != nil || n < 0 || !want[name] {
			return nil, ErrOutput
		}
		if _, dup := counts[name]; dup {
			return nil, ErrOutput
		}
		counts[name] = n
	}
	if len(counts) != len(tables) {
		return nil, ErrOutput
	}
	return counts, nil
}

// CronLine is one job of the source's crontab: five schedule fields one
// space apart, and the command.
type CronLine struct {
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
}

// shortcuts are cron's "@" names that stand for a schedule.
var shortcuts = map[string]string{
	"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
	"@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
}

var envLine = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*[ \t]*=`)

// ParseCrontab reads the user's crontab as crontab -l prints it. Comments
// and blank lines are left out. A variable line (MAILTO=, SHELL=, PATH=) or
// @reboot cannot become a job here and is counted in skipped with the
// reason; skipped never quotes a command, which may hold a secret.
func ParseCrontab(out []byte) (jobs []CronLine, skipped []string, err error) {
	if len(out) > 256<<10 || !utf8.Valid(out) {
		return nil, nil, ErrOutput
	}
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(jobs)+len(skipped) >= MaxCronLines {
			return nil, nil, ErrOutput
		}
		if envLine.MatchString(line) {
			skipped = append(skipped, "a variable line (such as MAILTO or PATH): jobs here run with the server's defaults")
			continue
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(fields[0], "@") {
			schedule, ok := shortcuts[fields[0]]
			if !ok || len(fields) < 2 {
				skipped = append(skipped, "a job with the schedule "+clean(fields[0], 16)+", which this server's jobs do not offer")
				continue
			}
			jobs = append(jobs, CronLine{Schedule: schedule, Command: strings.TrimSpace(strings.TrimPrefix(line, fields[0]))})
			continue
		}
		if len(fields) < 6 {
			skipped = append(skipped, "a line that is not a schedule and a command")
			continue
		}
		rest := line
		for i := 0; i < 5; i++ {
			rest = strings.TrimLeft(rest, " \t")
			rest = rest[len(fields[i]):]
		}
		command := strings.TrimSpace(rest)
		if len(command) > maxCronLine {
			skipped = append(skipped, "a job whose command is longer than 1024 bytes")
			continue
		}
		jobs = append(jobs, CronLine{Schedule: strings.Join(fields[:5], " "), Command: command})
	}
	return jobs, skipped, nil
}
