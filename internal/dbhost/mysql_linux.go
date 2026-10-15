package dbhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// CLIRunner runs SQL through the mysql client over the local unix socket,
// batch mode without column names. The client — never a network DSN — is
// the transport, matching how the reference host tools talk to MariaDB.
type CLIRunner struct {
	Socket string // e.g. /var/lib/mysql/mysql.sock
	Bin    string // mysql client path; default "mysql"
	// DefaultsFile is an option file holding the panel's database admin
	// credentials (0600, controller-only), cPanel's /root/.my.cnf analogue.
	DefaultsFile string
}

func (r CLIRunner) Run(ctx context.Context, sql string) ([]string, error) {
	bin := r.Bin
	if bin == "" {
		bin = "mysql"
	}
	args := []string{"--protocol=socket", "--socket=" + r.Socket,
		"--batch", "--skip-column-names", "--raw"}
	if r.DefaultsFile != "" {
		args = append([]string{"--defaults-extra-file=" + r.DefaultsFile}, args...)
	}
	cmd := exec.CommandContext(ctx, bin, append(args, "-e", sql)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	out := []string{}
	for _, line := range strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// LocalService implements Service against the local MariaDB via a Runner.
// All operations validate identifiers and check ownership in the registry
// before touching the server — fail-closed on both fences.
type LocalService struct {
	Run      Runner
	Registry *Registry
	// Host is the grant host; cPanel 138 grants 'localhost' by default.
	Host string
}

func (s *LocalService) host() string {
	if s.Host == "" {
		return "localhost"
	}
	return s.Host
}

// Probe checks socket presence first (cheap fail-closed) then VERSION().
func (s *LocalService) Probe(ctx context.Context) (string, error) {
	if r, ok := s.Run.(CLIRunner); ok {
		if _, err := os.Stat(r.Socket); err != nil {
			return "", ErrUnavailable
		}
	}
	rows, err := s.Run.Run(ctx, sqlVersion)
	if err != nil || len(rows) == 0 {
		return "", ErrUnavailable
	}
	return rows[0], nil
}

// PrefixedName joins account and suffix per the 138 prefix convention.
func PrefixedName(account, suffix string) string {
	if strings.HasPrefix(suffix, account+"_") {
		return suffix
	}
	return account + "_" + suffix
}

func (s *LocalService) ownCheck(owner, name string) error {
	o, ok := s.Registry.ownerOf(name)
	if !ok {
		return errors.New("not found: " + name)
	}
	if owner != "" && o != owner {
		return errors.New("access denied: " + name + " belongs to another account")
	}
	return nil
}

func (s *LocalService) CreateDatabase(ctx context.Context, owner, name string) error {
	if err := ValidateIdentifier("database", name, MaxDatabaseLen); err != nil {
		return err
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	if _, err := s.Run.Run(ctx, sqlCreateDatabase(name)); err != nil {
		return err
	}
	return s.Registry.putDatabase(Database{Name: name, Owner: owner})
}

func (s *LocalService) DropDatabase(ctx context.Context, owner, name string) error {
	if err := s.ownCheck(owner, name); err != nil {
		return err
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	if _, err := s.Run.Run(ctx, sqlDropDatabase(name)); err != nil {
		return err
	}
	return s.Registry.dropDatabase(name)
}

func (s *LocalService) CreateUser(ctx context.Context, owner, name, password string) error {
	if err := ValidateIdentifier("user", name, MaxUserLen); err != nil {
		return err
	}
	if strings.ContainsAny(password, "\x00\n\r") {
		return errors.New("password contains control characters")
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	if _, err := s.Run.Run(ctx, sqlCreateUser(name, s.host(), password)); err != nil {
		return err
	}
	return s.Registry.putUser(User{Name: name, Owner: owner, Hosts: []string{s.host()}})
}

func (s *LocalService) DropUser(ctx context.Context, owner, name string) error {
	if err := s.ownCheck(owner, name); err != nil {
		return err
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	if _, err := s.Run.Run(ctx, sqlDropUser(name, s.host())); err != nil {
		return err
	}
	// detach from every database entry
	for _, d := range s.Registry.databases("") {
		users := d.Users[:0]
		for _, u := range d.Users {
			if u != name {
				users = append(users, u)
			}
		}
		if len(users) != len(d.Users) {
			d.Users = users
			if err := s.Registry.putDatabase(d); err != nil {
				return err
			}
		}
	}
	return s.Registry.dropUser(name)
}

func (s *LocalService) SetPassword(ctx context.Context, owner, name, password string) error {
	if err := s.ownCheck(owner, name); err != nil {
		return err
	}
	if strings.ContainsAny(password, "\x00\n\r") {
		return errors.New("password contains control characters")
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	_, err := s.Run.Run(ctx, sqlSetPassword(name, s.host(), password))
	return err
}

func (s *LocalService) SetPrivileges(ctx context.Context, owner, user, db string, privs []string) error {
	if err := s.ownCheck(owner, user); err != nil {
		return err
	}
	if err := s.ownCheck(owner, db); err != nil {
		return err
	}
	if len(privs) == 0 {
		return errors.New("at least one privilege is required")
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	// set semantics: revoke then grant — matches the reference's replace.
	// MariaDB errors 1141 when nothing was granted yet; that is the normal
	// first-grant path, not a failure.
	if _, err := s.Run.Run(ctx, sqlRevokeAll(db, user, s.host())); err != nil && !isNoSuchGrant(err) {
		return err
	}
	if _, err := s.Run.Run(ctx, sqlGrant(db, user, s.host(), privs)); err != nil {
		return err
	}
	d, _ := s.Registry.ownerOf(db)
	entry := Database{Name: db, Owner: d}
	for _, x := range s.Registry.databases("") {
		if x.Name == db {
			entry = x
		}
	}
	found := false
	for _, u := range entry.Users {
		if u == user {
			found = true
		}
	}
	if !found {
		entry.Users = append(entry.Users, user)
	}
	return s.Registry.putDatabase(entry)
}

func (s *LocalService) RevokeAccess(ctx context.Context, owner, user, db string) error {
	if err := s.ownCheck(owner, user); err != nil {
		return err
	}
	if err := s.ownCheck(owner, db); err != nil {
		return err
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	if _, err := s.Run.Run(ctx, sqlRevokeAll(db, user, s.host())); err != nil {
		return err
	}
	for _, x := range s.Registry.databases("") {
		if x.Name == db {
			users := x.Users[:0]
			for _, u := range x.Users {
				if u != user {
					users = append(users, u)
				}
			}
			x.Users = users
			return s.Registry.putDatabase(x)
		}
	}
	return nil
}

func (s *LocalService) RenameUser(ctx context.Context, owner, name, newName string) error {
	if err := s.ownCheck(owner, name); err != nil {
		return err
	}
	if err := ValidateIdentifier("user", newName, MaxUserLen); err != nil {
		return err
	}
	if _, err := s.Probe(ctx); err != nil {
		return err
	}
	if _, err := s.Run.Run(ctx, sqlRenameUser(name, s.host(), newName)); err != nil {
		return err
	}
	u := User{Name: newName, Owner: owner, Hosts: []string{s.host()}}
	for _, x := range s.Registry.users("") {
		if x.Name == name {
			u = x
			u.Name = newName
		}
	}
	for _, d := range s.Registry.databases("") {
		changed := false
		for i, x := range d.Users {
			if x == name {
				d.Users[i] = newName
				changed = true
			}
		}
		if changed {
			if err := s.Registry.putDatabase(d); err != nil {
				return err
			}
		}
	}
	if err := s.Registry.dropUser(name); err != nil {
		return err
	}
	return s.Registry.putUser(u)
}

func (s *LocalService) ListDatabases(ctx context.Context, owner string) ([]Database, error) {
	if _, err := s.Probe(ctx); err != nil {
		return nil, err
	}
	return s.Registry.databases(owner), nil
}

func (s *LocalService) ListUsers(ctx context.Context, owner string) ([]User, error) {
	if _, err := s.Probe(ctx); err != nil {
		return nil, err
	}
	return s.Registry.users(owner), nil
}

func (s *LocalService) AllDatabases(ctx context.Context) ([]Database, error) {
	return s.ListDatabases(ctx, "")
}

func (s *LocalService) AllUsers(ctx context.Context) ([]User, error) {
	return s.ListUsers(ctx, "")
}

// isNoSuchGrant reports MariaDB error 1141 (no grant defined yet).
func isNoSuchGrant(err error) bool {
	return strings.Contains(err.Error(), "1141") || strings.Contains(err.Error(), "no such grant")
}

// GrantsFor returns raw SHOW GRANTS lines for a user (diagnostics).
func (s *LocalService) GrantsFor(ctx context.Context, user string) ([]string, error) {
	if _, err := s.Probe(ctx); err != nil {
		return nil, err
	}
	return s.Run.Run(ctx, sqlPrivileges(user))
}
