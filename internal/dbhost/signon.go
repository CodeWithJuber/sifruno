package dbhost

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Temporary users for phpMyAdmin's one-click sign-in (internal/phpmyadmin).
// Each has a random name with SignonUserPrefix, a random password the panel
// never stores, and SignonPrivileges on one website's databases only. They are
// not in the registry: no website lists them, no backup or account move
// carries them, and the panel drops them when they expire.
//
// The prefix starts with capitals. A hosting account's name is lowercase
// (^[a-z][a-z0-9_]{2,31}$) and MariaDB user names are case-sensitive, so no
// account's prefix can cover a temporary user and no account can create one.

// SignonUserPrefix starts every temporary phpMyAdmin user's name.
const SignonUserPrefix = "SifrunoPMA_"

var signonUserPattern = regexp.MustCompile(`^SifrunoPMA_[a-f0-9]{20}$`)

// SignonPrivileges are what a temporary user gets on each database: the
// table and data privileges, without TRIGGER, CREATE VIEW, CREATE ROUTINE,
// ALTER ROUTINE and EVENT. A trigger, view, routine or event records its
// DEFINER, and once the sweeper drops the temporary user it would fail for
// the site's own user (MariaDB error 1449). The site's own database user
// makes those.
var SignonPrivileges = []string{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "REFERENCES", "INDEX", "ALTER",
	"CREATE TEMPORARY TABLES", "LOCK TABLES", "EXECUTE", "SHOW VIEW"}

// ValidSignonUser reports whether name is a temporary user's name: the
// prefix and 20 lowercase hexadecimal characters.
func ValidSignonUser(name string) bool { return signonUserPattern.MatchString(name) }

// sqlSignonUsers lists the temporary users on the server. The prefix's "_" is
// escaped, so LIKE matches it literally; mysql.user's User column compares
// case-sensitively.
const sqlSignonUsers = `SELECT User FROM mysql.user WHERE Host='localhost' AND User LIKE 'SifrunoPMA\\_%' ORDER BY User`

// sqlEndSessions ends every connection the user has open. MariaDB raises no
// error for a user with none, or one already dropped.
func sqlEndSessions(user, host string) string {
	return fmt.Sprintf("KILL HARD USER %s@%s", quoteString(user), quoteString(host))
}

// CreateSignonUser makes the temporary user name with password and grants it
// SignonPrivileges on each of databases, all of which must be owner's in the
// registry. Each grant names its database exactly (grantDB escapes "_" and
// "%"). A name already on the server is ErrExists and nothing changes. When a
// grant fails, the user is dropped again before the error is returned.
func (s *LocalService) CreateSignonUser(ctx context.Context, owner, name, password string, databases []string) error {
	if !ValidSignonUser(name) {
		return fmt.Errorf("%q is not a temporary phpMyAdmin user's name", name)
	}
	if owner == "" {
		return errors.New("a temporary phpMyAdmin user needs the owner of its databases")
	}
	if password == "" || strings.ContainsAny(password, "\x00\n\r") {
		return errors.New("password is empty or contains control characters")
	}
	if len(databases) == 0 {
		return errors.New("a temporary phpMyAdmin user needs at least one database")
	}
	for _, db := range databases {
		if err := ValidateIdentifier("database", db, MaxDatabaseLen); err != nil {
			return err
		}
		if err := s.ownCheck(owner, db); err != nil {
			return err
		}
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	if _, err := s.Run.Run(ctx, sqlCreateUserStrict(name, s.host(), password)); err != nil {
		if isServerError(err, 1396) {
			return fmt.Errorf("%w: %v", ErrExists, err)
		}
		return err
	}
	grants := make([]string, len(databases))
	for i, db := range databases {
		grants[i] = sqlGrant(db, name, s.host(), SignonPrivileges)
	}
	if _, err := s.Run.Run(ctx, strings.Join(grants, ";\n")); err != nil {
		if dropErr := s.DropSignonUser(context.WithoutCancel(ctx), name); dropErr != nil {
			return fmt.Errorf("%w; dropping the user again also failed: %v", err, dropErr)
		}
		return err
	}
	return nil
}

// DropSignonUser drops a temporary user, then ends the connections it still
// has open: MariaDB keeps a dropped user's sessions running. Dropping a user
// that is already gone is not an error.
func (s *LocalService) DropSignonUser(ctx context.Context, name string) error {
	if !ValidSignonUser(name) {
		return fmt.Errorf("%q is not a temporary phpMyAdmin user's name", name)
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	_, err := s.Run.Run(ctx, sqlDropUser(name, s.host())+";\n"+sqlEndSessions(name, s.host()))
	return err
}

// SignonUsers lists the temporary users the server has, whatever the panel
// recorded, so users left by a crash can be dropped too.
func (s *LocalService) SignonUsers(ctx context.Context) ([]string, error) {
	if _, err := s.Probe(ctx); err != nil {
		return nil, err
	}
	rows, err := s.Run.Run(ctx, sqlSignonUsers)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, row := range rows {
		if ValidSignonUser(row) {
			out = append(out, row)
		}
	}
	return out, nil
}
