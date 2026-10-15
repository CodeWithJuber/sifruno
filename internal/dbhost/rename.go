package dbhost

// db.grants batch 2: database rename (table-move semantics, like the
// reference's Mysql::rename_database) and per-account remote access hosts
// (the reference's dbmap "remote hosts" list — each host becomes a
// '<user>'@'<host>' MariaDB account with the same auth plugin/hash and the
// same per-database grants as the localhost entry).

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// accessHostRe permits IPv4 literals, hostnames, and MariaDB wildcards
// (% and _). Anything else (quotes, whitespace, semicolons) is rejected
// before a statement is ever built.
var accessHostRe = regexp.MustCompile(`^[a-zA-Z0-9._%-]{1,255}$`)

// ValidateAccessHost checks a remote access host value.
func ValidateAccessHost(host string) error {
	if !accessHostRe.MatchString(host) {
		return errors.New("invalid access host: letters, digits, dot, dash, underscore and % are allowed")
	}
	return nil
}

func sqlRenameTable(oldDB, newDB, table string) string {
	return fmt.Sprintf("RENAME TABLE %s.%s TO %s.%s",
		quoteIdent(oldDB), quoteIdent(table), quoteIdent(newDB), quoteIdent(table))
}

func sqlTablesIn(db string) string {
	return fmt.Sprintf("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s", quoteString(db))
}

// sqlMoveGrants repoints per-database grants from the old database name to
// the new one (mysql.db rows carry Db literally; RENAME TABLE does not
// touch them).
func sqlMoveGrants(oldDB, newDB string) string {
	return fmt.Sprintf("UPDATE mysql.db SET Db=%s WHERE Db=%s", quoteString(newDB), quoteString(oldDB))
}

const sqlFlushPrivileges = "FLUSH PRIVILEGES"

func sqlUserAuth(user, host string) string {
	return fmt.Sprintf("SELECT plugin, authentication_string FROM mysql.user WHERE User=%s AND Host=%s",
		quoteString(user), quoteString(host))
}

func sqlCreateUserWithHash(user, host, plugin, hash string) string {
	if !accessHostRe.MatchString(host) || !accessHostRe.MatchString(plugin) {
		return ""
	}
	return fmt.Sprintf("CREATE USER IF NOT EXISTS %s@%s IDENTIFIED VIA %s USING %s",
		quoteString(user), quoteString(host), quoteIdent(plugin), quoteString(hash))
}

// RenameDatabase moves every table to a new prefixed database, repoints
// grants, drops the old database, and updates the registry — matching the
// reference behaviour where users keep working against the new name.
func (s *LocalService) RenameDatabase(ctx context.Context, owner, oldName, newSuffix string) (string, error) {
	if err := s.ownCheck(owner, oldName); err != nil {
		return "", err
	}
	newName := PrefixedName(owner, newSuffix)
	if err := ValidateIdentifier("database", newName, MaxDatabaseLen); err != nil {
		return "", err
	}
	if newName == oldName {
		return "", errors.New("new name must differ from the current name")
	}
	if _, taken := s.Registry.ownerOf(newName); taken {
		return "", errors.New("target database already exists: " + newName)
	}
	if _, err := s.Probe(ctx); err != nil {
		return "", err
	}
	if _, err := s.Run.Run(ctx, sqlCreateDatabase(newName)); err != nil {
		return "", err
	}
	tables, err := s.Run.Run(ctx, sqlTablesIn(oldName))
	if err != nil {
		return "", err
	}
	for _, t := range tables {
		if _, err := s.Run.Run(ctx, sqlRenameTable(oldName, newName, t)); err != nil {
			return "", fmt.Errorf("move table %s: %w", t, err)
		}
	}
	if _, err := s.Run.Run(ctx, sqlMoveGrants(oldName, newName)); err != nil {
		return "", err
	}
	if _, err := s.Run.Run(ctx, sqlDropDatabase(oldName)); err != nil {
		return "", err
	}
	if _, err := s.Run.Run(ctx, sqlFlushPrivileges); err != nil {
		return "", err
	}
	if err := s.Registry.dropDatabase(oldName); err != nil {
		return "", err
	}
	return newName, s.Registry.putDatabase(Database{Name: newName, Owner: owner})
}

// grantsOnDatabases returns SHOW GRANTS lines scoped to the given
// databases (skipping the global USAGE line).
func grantsOnDatabases(grants []string) []string {
	out := []string{}
	for _, g := range grants {
		if strings.Contains(g, " ON *.* ") {
			continue
		}
		out = append(out, g)
	}
	return out
}

// replayGrant rewrites a SHOW GRANTS line to target user@newHost.
func replayGrant(line, user, newHost string) string {
	idx := strings.Index(line, " TO ")
	if idx < 0 {
		return ""
	}
	return line[:idx] + fmt.Sprintf(" TO %s@%s", quoteString(user), quoteString(newHost))
}

// AddAccessHost creates '<user>'@'<host>' for every database user of the
// account, copying the localhost auth plugin/hash and replaying the
// per-database grants — the reference's "Additional MySQL Access Hosts".
func (s *LocalService) AddAccessHost(ctx context.Context, owner, host string) error {
	if err := ValidateAccessHost(host); err != nil {
		return err
	}
	if host == "localhost" {
		return errors.New("localhost is the default access host and cannot be added")
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	users := s.Registry.users(owner)
	if len(users) == 0 {
		return errors.New("no database users for account " + owner)
	}
	localHost := s.host()
	for _, u := range users {
		rows, err := s.Run.Run(ctx, sqlUserAuth(u.Name, localHost))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return fmt.Errorf("no local auth row for %s; cannot clone credentials", u.Name)
		}
		parts := strings.SplitN(rows[0], "\t", 2)
		plugin := parts[0]
		hash := ""
		if len(parts) == 2 {
			hash = parts[1]
		}
		if plugin == "" || plugin == "unix_socket" || hash == "" {
			return fmt.Errorf("user %s uses %s auth which cannot be cloned to a remote host", u.Name, plugin)
		}
		stmt := sqlCreateUserWithHash(u.Name, host, plugin, hash)
		if stmt == "" {
			return fmt.Errorf("auth plugin %q is not cloneable", plugin)
		}
		if _, err := s.Run.Run(ctx, stmt); err != nil {
			return err
		}
		grants, err := s.GrantsFor(ctx, u.Name)
		if err != nil {
			return err
		}
		for _, g := range grantsOnDatabases(grants) {
			replayed := replayGrant(g, u.Name, host)
			if replayed == "" {
				continue
			}
			if _, err := s.Run.Run(ctx, replayed); err != nil {
				return fmt.Errorf("replay grant for %s@%s: %w", u.Name, host, err)
			}
		}
	}
	return s.Registry.putHost(owner, host)
}

// DeleteAccessHost drops '<user>'@'<host>' for every account database user
// and removes the host from the registry.
func (s *LocalService) DeleteAccessHost(ctx context.Context, owner, host string) error {
	if err := ValidateAccessHost(host); err != nil {
		return err
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	for _, u := range s.Registry.users(owner) {
		if _, err := s.Run.Run(ctx, sqlDropUser(u.Name, host)); err != nil {
			return err
		}
	}
	return s.Registry.dropHost(owner, host)
}

// ListAccessHosts returns the account's registered remote access hosts.
func (s *LocalService) ListAccessHosts(ctx context.Context, owner string) []string {
	return s.Registry.hosts(owner)
}
