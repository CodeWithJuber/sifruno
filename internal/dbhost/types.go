package dbhost

import (
	"context"
	"errors"
)

// ErrUnavailable is returned when the local MariaDB server is absent or not
// answering — surfaces fail-closed, mirroring the reference's offline state.
var ErrUnavailable = errors.New("database server unavailable")

// ErrExists is returned by the strict creates when the database or user is
// already in the registry or on the server (MariaDB errors 1007 and 1396).
// Nothing was created or registered.
var ErrExists = errors.New("database or user already exists")

// ErrNotRegistered is returned by the strict creates when the server made the
// database or user but the registry file could not be written. The object
// exists and belongs to the caller to remove; the registry keeps the entry in
// memory, so DropDatabase and DropUser still accept it.
var ErrNotRegistered = errors.New("created on the database server but not recorded in the registry")

// Database is one registry entry: the prefixed database plus the users
// granted on it.
type Database struct {
	Name  string   `json:"name"`
	Owner string   `json:"owner"` // owning panel account
	Users []string `json:"users,omitempty"`
}

// User is one registry entry for a prefixed database user.
type User struct {
	Name  string   `json:"name"`
	Owner string   `json:"owner"`
	Hosts []string `json:"hosts,omitempty"`
}

// Runner executes one SQL statement batch and returns tab-separated rows
// (mysql --batch --skip-column-names semantics). Implementations: CLIRunner
// (real) and fakes in tests.
type Runner interface {
	Run(ctx context.Context, sql string) ([]string, error)
}

// Prober reports whether the local server is reachable.
type Prober interface {
	Probe(ctx context.Context) (version string, err error)
}

// Service is the account-facing database contract.
type Service interface {
	Prober
	CreateDatabase(ctx context.Context, owner, name string) error
	DropDatabase(ctx context.Context, owner, name string) error
	CreateUser(ctx context.Context, owner, name, password string) error
	DropUser(ctx context.Context, owner, name string) error
	SetPassword(ctx context.Context, owner, name, password string) error
	SetPrivileges(ctx context.Context, owner, user, db string, privs []string) error
	RevokeAccess(ctx context.Context, owner, user, db string) error
	RenameUser(ctx context.Context, owner, name, newName string) error
	ListDatabases(ctx context.Context, owner string) ([]Database, error)
	ListUsers(ctx context.Context, owner string) ([]User, error)
	// AllDatabases/AllUsers are the root (WHM) views across owners.
	AllDatabases(ctx context.Context) ([]Database, error)
	AllUsers(ctx context.Context) ([]User, error)
}

// RenameService is the batch-2 database rename capability
// (Mysql::rename_database). LocalService implements it.
type RenameService interface {
	RenameDatabase(ctx context.Context, owner, oldName, newSuffix string) (string, error)
}

// AccessHostService is the batch-2 remote access host capability
// (Mysql::add_host/delete_host/list_hosts). LocalService implements it.
type AccessHostService interface {
	AddAccessHost(ctx context.Context, owner, host string) error
	DeleteAccessHost(ctx context.Context, owner, host string) error
	ListAccessHosts(ctx context.Context, owner string) []string
}
