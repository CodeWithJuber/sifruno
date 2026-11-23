package dbhost

import (
	"fmt"
	"regexp"
	"strings"
)

// SQL builders for the MariaDB surface. Identifiers are validated against a
// strict policy and never interpolated raw; string literals (passwords) are
// escaped. Privileges pass a whitelist matching the cPanel 138 MariaDB set.

// cPanel 138 with MariaDB 10.11 enforces prefixed names (<account>_suffix).
// Limits observed/documented: database 64 chars total, user 47 chars total
// (cPanel policy; MariaDB itself allows 80 for users).
const (
	MaxDatabaseLen = 64
	MaxUserLen     = 47
)

var identRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// ValidateIdentifier enforces the prefixed-name charset and length policy.
// name must already include the "<account>_" prefix (enforced by callers).
func ValidateIdentifier(kind, name string, max int) error {
	if name == "" {
		return fmt.Errorf("%s name is required", kind)
	}
	if len(name) > max {
		return fmt.Errorf("%s name exceeds the %d-character limit", kind, max)
	}
	if !identRe.MatchString(name) {
		return fmt.Errorf("%s name %q contains characters outside [a-zA-Z0-9_]", kind, name)
	}
	return nil
}

// quoteIdent backtick-quotes a validated identifier.
func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// quoteString single-quotes a literal with backslash escaping. Control
// characters are rejected upstream (policy) — this is the second fence.
func quoteString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}

// AllowedPrivileges is the cPanel 138 MariaDB privilege whitelist (account
// scope). Anything outside this set is rejected before SQL is built.
var AllowedPrivileges = map[string]bool{
	"ALL PRIVILEGES":          true,
	"ALTER":                   true,
	"ALTER ROUTINE":           true,
	"CREATE":                  true,
	"CREATE ROUTINE":          true,
	"CREATE TEMPORARY TABLES": true,
	"CREATE VIEW":             true,
	"DELETE":                  true,
	"DROP":                    true,
	"EVENT":                   true,
	"EXECUTE":                 true,
	"INDEX":                   true,
	"INSERT":                  true,
	"LOCK TABLES":             true,
	"REFERENCES":              true,
	"SELECT":                  true,
	"SHOW VIEW":               true,
	"TRIGGER":                 true,
	"UPDATE":                  true,
}

// ParsePrivileges validates a comma-separated privilege list (UAPI wire
// format). "ALL PRIVILEGES" must stand alone.
func ParsePrivileges(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToUpper(strings.TrimSpace(p))
		p = strings.Join(strings.Fields(p), " ")
		if !AllowedPrivileges[p] {
			return nil, fmt.Errorf("unsupported privilege %q", p)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one privilege is required")
	}
	if len(out) > 1 {
		for _, p := range out {
			if p == "ALL PRIVILEGES" {
				return nil, fmt.Errorf("ALL PRIVILEGES cannot be combined with other privileges")
			}
		}
	}
	return out, nil
}

func sqlCreateDatabase(db string) string {
	return fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", quoteIdent(db))
}

// sqlCreateDatabaseStrict fails with error 1007 if the database exists.
func sqlCreateDatabaseStrict(db string) string {
	return fmt.Sprintf("CREATE DATABASE %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", quoteIdent(db))
}

func sqlDropDatabase(db string) string {
	return fmt.Sprintf("DROP DATABASE IF EXISTS %s", quoteIdent(db))
}

func sqlCreateUser(user, host, password string) string {
	return fmt.Sprintf("CREATE USER IF NOT EXISTS %s@%s IDENTIFIED BY %s", quoteString(user), quoteString(host), quoteString(password))
}

// sqlCreateUserStrict fails with error 1396 if the user exists on that host.
func sqlCreateUserStrict(user, host, password string) string {
	return fmt.Sprintf("CREATE USER %s@%s IDENTIFIED BY %s", quoteString(user), quoteString(host), quoteString(password))
}

func sqlDropUser(user, host string) string {
	return fmt.Sprintf("DROP USER IF EXISTS %s@%s", quoteString(user), quoteString(host))
}

func sqlSetPassword(user, host, password string) string {
	return fmt.Sprintf("ALTER USER %s@%s IDENTIFIED BY %s", quoteString(user), quoteString(host), quoteString(password))
}

func sqlGrant(db, user, host string, privs []string) string {
	return fmt.Sprintf("GRANT %s ON %s.* TO %s@%s", strings.Join(privs, ", "), quoteIdent(db), quoteString(user), quoteString(host))
}

func sqlRevokeAll(db, user, host string) string {
	return fmt.Sprintf("REVOKE ALL PRIVILEGES ON %s.* FROM %s@%s", quoteIdent(db), quoteString(user), quoteString(host))
}

func sqlRenameUser(user, host, newUser string) string {
	return fmt.Sprintf("RENAME USER %s@%s TO %s@%s", quoteString(user), quoteString(host), quoteString(newUser), quoteString(host))
}

const (
	sqlListDatabases = "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','sys') ORDER BY SCHEMA_NAME"
	sqlListUsers     = "SELECT User, Host FROM mysql.user WHERE User NOT IN ('root','mysql','mariadb.sys','mysql.sys','mysql.session','mysql.infoschema','debian-sys-maint') ORDER BY User"
	sqlVersion       = "SELECT VERSION()"
)

// sqlServerHasDatabase and sqlServerHasUser count what the server itself
// holds, registered or not; a user counts on any host.
func sqlServerHasDatabase(db string) string {
	return fmt.Sprintf("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s", quoteString(db))
}

func sqlServerHasUser(user string) string {
	return fmt.Sprintf("SELECT COUNT(*) FROM mysql.user WHERE User=%s", quoteString(user))
}

func sqlPrivileges(user string) string {
	return fmt.Sprintf("SHOW GRANTS FOR %s@'localhost'", quoteString(user))
}
