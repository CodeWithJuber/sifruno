package dbhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A stand-in mysql client records its arguments and stdin, so the test sees
// exactly what another local user could read in the process list.
func TestCLIRunnerSendsSQLOnStdin(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mysql")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + dir + "/argv\"\ncat > \"" + dir + "/stdin\"\nprintf 'row\\n'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	r := CLIRunner{Socket: "/run/mysqld/mysqld.sock", Bin: bin, DefaultsFile: "/etc/sifruno/db.cnf"}
	sql := sqlCreateUser("acct_wp", "localhost", "s3cret;pass")
	rows, err := r.Run(context.Background(), sql)
	if err != nil || len(rows) != 1 || rows[0] != "row" {
		t.Fatalf("rows %v err %v", rows, err)
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	stdin, _ := os.ReadFile(filepath.Join(dir, "stdin"))
	if strings.Contains(string(argv), "s3cret") || strings.Contains(string(argv), "CREATE USER") || strings.Contains("\n"+string(argv), "\n-e\n") {
		t.Fatalf("SQL reached the arguments: %q", argv)
	}
	if !strings.HasPrefix(string(argv), "--defaults-extra-file=/etc/sifruno/db.cnf\n") {
		t.Fatalf("the option file must come first: %q", argv)
	}
	if string(stdin) != sql+";\n" {
		t.Fatalf("stdin %q", stdin)
	}
}

// The strict creates never adopt: what exists fails with ErrExists and the
// registry is left as it was.
func TestStrictCreatesRefuseWhatExists(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	f.errs = map[string]error{
		sqlCreateDatabaseStrict("acct_wp"):                     errors.New("ERROR 1007 (HY000) at line 1: Can't create database 'acct_wp'; database exists"),
		sqlCreateUserStrict("acct_wp", "localhost", "s3cret!"): errors.New("ERROR 1396 (HY000) at line 1: Operation CREATE USER failed for 'acct_wp'@'localhost'"),
	}
	if err := svc.CreateDatabaseStrict(ctx, "acct", "acct_wp"); !errors.Is(err, ErrExists) {
		t.Fatalf("existing database: %v", err)
	}
	if err := svc.CreateUserStrict(ctx, "acct", "acct_wp", "s3cret!"); !errors.Is(err, ErrExists) {
		t.Fatalf("existing user: %v", err)
	}
	if dbs, _ := svc.AllDatabases(ctx); len(dbs) != 0 {
		t.Fatalf("an existing database was registered: %+v", dbs)
	}
	if users, _ := svc.AllUsers(ctx); len(users) != 0 {
		t.Fatalf("an existing user was registered: %+v", users)
	}
	for _, stmt := range f.stmts {
		if strings.Contains(stmt, "IF NOT EXISTS") {
			t.Fatalf("strict create adopts: %s", stmt)
		}
	}

	// Another server error is passed on as it is, not as ErrExists.
	f.errs = map[string]error{sqlCreateDatabaseStrict("acct_db"): errors.New("ERROR 1044 (42000) at line 1: Access denied")}
	if err := svc.CreateDatabaseStrict(ctx, "acct", "acct_db"); err == nil || errors.Is(err, ErrExists) || errors.Is(err, ErrNotRegistered) {
		t.Fatalf("access denied: %v", err)
	}

	// Already in the registry: refused before any SQL.
	f.errs = nil
	if err := svc.CreateDatabase(ctx, "other", "other_wp"); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateUser(ctx, "other", "other_u", "pw"); err != nil {
		t.Fatal(err)
	}
	f.stmts = nil
	if err := svc.CreateDatabaseStrict(ctx, "acct", "other_wp"); !errors.Is(err, ErrExists) {
		t.Fatalf("registered database: %v", err)
	}
	if err := svc.CreateUserStrict(ctx, "acct", "other_u", "pw"); !errors.Is(err, ErrExists) {
		t.Fatalf("registered user: %v", err)
	}
	if len(f.stmts) != 0 {
		t.Fatalf("SQL ran for a registered name: %q", f.stmts)
	}
	if dbs, _ := svc.ListDatabases(ctx, "other"); len(dbs) != 1 || dbs[0].Owner != "other" {
		t.Fatalf("registry entry changed: %+v", dbs)
	}
}

func TestStrictCreatesRunExactSQLAndRegister(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	if err := svc.CreateDatabaseStrict(ctx, "acct", "acct_wp"); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateUserStrict(ctx, "acct", "acct_wp", "p'w"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CREATE DATABASE `acct_wp` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		`CREATE USER 'acct_wp'@'localhost' IDENTIFIED BY 'p\'w'`,
	} {
		if !slices.Contains(f.stmts, want) {
			t.Fatalf("missing %q in %q", want, f.stmts)
		}
	}
	dbs, _ := svc.ListDatabases(ctx, "acct")
	users, _ := svc.ListUsers(ctx, "acct")
	if len(dbs) != 1 || dbs[0].Name != "acct_wp" || len(users) != 1 || users[0].Name != "acct_wp" {
		t.Fatalf("registry %+v %+v", dbs, users)
	}
}

// MariaDB keeps a database's grants when the database is dropped. A drop
// removes them too, so a later database of the same name (account "bob_x"
// can name one bob_x_wp just as "bob" can) does not open to the old users.
func TestDroppedDatabasesTakeTheirGrants(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	for _, name := range []string{"bob_x_wp", "bob_old"} {
		if err := svc.CreateDatabaseStrict(ctx, "bob", name); err != nil {
			t.Fatal(err)
		}
	}
	f.stmts = nil
	if err := svc.DropDatabase(ctx, "bob", "bob_x_wp"); err != nil {
		t.Fatal(err)
	}
	if _, purgeErrs := svc.PurgeOwner(ctx, "bob"); len(purgeErrs) > 0 {
		t.Fatal(purgeErrs)
	}
	want := []string{
		sqlDropDatabase("bob_x_wp"), sqlForgetGrants("bob_x_wp"),
		sqlDropDatabase("bob_old"), sqlForgetGrants("bob_old"),
	}
	var got []string
	for _, s := range f.stmts {
		if strings.HasPrefix(s, "DROP DATABASE") || strings.HasPrefix(s, "DELETE FROM mysql.") {
			got = append(got, s)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("statements\n%q\nwant\n%q", got, want)
	}
	// The grants go only after the database: a failed drop leaves both.
	f.errs = map[string]error{sqlDropDatabase("bob_y"): errors.New("ERROR 1010 (HY000)")}
	if err := svc.CreateDatabaseStrict(ctx, "bob", "bob_y"); err != nil {
		t.Fatal(err)
	}
	f.stmts = nil
	if err := svc.DropDatabase(ctx, "bob", "bob_y"); err == nil || slices.Contains(f.stmts, sqlForgetGrants("bob_y")) {
		t.Fatalf("a failed drop: err %v, statements %q", err, f.stmts)
	}
	if _, ok := svc.Registry.ownerOf("bob_y"); !ok {
		t.Fatal("a failed drop removed the registry entry")
	}
}

// A grant written before the names were escaped has the plain spelling, and
// a REVOKE matches the spelling exactly: both are revoked, and a spelling
// with no grant (1141) is no failure unless neither had one.
func TestRevokesFindGrantsOfEitherSpelling(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	for _, err := range []error{
		svc.CreateDatabaseStrict(ctx, "acct", "acct_wp"),
		svc.CreateUserStrict(ctx, "acct", "acct_u", "pw"),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	noGrant := errors.New("ERROR 1141 (42000) at line 1: There is no such grant defined for user")
	escaped, plain := sqlRevokeAll("acct_wp", "acct_u", "localhost"), sqlRevokeAllPlain("acct_wp", "acct_u", "localhost")
	if escaped == plain || !strings.Contains(plain, "`acct_wp`") {
		t.Fatalf("spellings: %s / %s", escaped, plain)
	}
	for _, tc := range []struct {
		name       string
		errs       map[string]error
		revokeFail bool
	}{
		{"an escaped grant", map[string]error{plain: noGrant}, false},
		{"a plain grant", map[string]error{escaped: noGrant}, false},
		{"no grant", map[string]error{escaped: noGrant, plain: noGrant}, true},
	} {
		f.errs, f.stmts = tc.errs, nil
		if err := svc.SetPrivileges(ctx, "acct", "acct_u", "acct_wp", []string{"SELECT"}); err != nil {
			t.Fatalf("%s: set: %v", tc.name, err)
		}
		if !slices.Contains(f.stmts, escaped) || !slices.Contains(f.stmts, plain) {
			t.Fatalf("%s: set did not revoke both spellings: %q", tc.name, f.stmts)
		}
		if err := svc.RevokeAccess(ctx, "acct", "acct_u", "acct_wp"); (err != nil) != tc.revokeFail || (err != nil && !isNoSuchGrant(err)) {
			t.Fatalf("%s: revoke: %v", tc.name, err)
		}
	}
	// Any other refusal stops it.
	f.errs, f.stmts = map[string]error{escaped: errors.New("ERROR 2013 (HY000): Lost connection")}, nil
	if err := svc.RevokeAccess(ctx, "acct", "acct_u", "acct_wp"); err == nil || slices.Contains(f.stmts, plain) {
		t.Fatalf("a failed revoke went on: %v %q", err, f.stmts)
	}
}

// Made on the server but not recorded: ErrNotRegistered, and the caller can
// still remove it.
func TestStrictCreatesReportAnUnrecordedObject(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// The registry file's directory does not exist yet; a plain file put in
	// its place makes every registry write fail, as root too.
	reg, err := OpenRegistry(filepath.Join(dir, "state", "dbmap.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "state"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{}
	svc := &LocalService{Run: f, Registry: reg}
	if err = svc.CreateDatabaseStrict(ctx, "acct", "acct_wp"); !errors.Is(err, ErrNotRegistered) || errors.Is(err, ErrExists) {
		t.Fatalf("database: %v", err)
	}
	if err = svc.CreateUserStrict(ctx, "acct", "acct_wp", "pw"); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("user: %v", err)
	}
	f.stmts = nil
	// The removals pass the ownership check and run their SQL; only the
	// registry write fails again.
	_ = svc.DropUser(ctx, "acct", "acct_wp")
	_ = svc.DropDatabase(ctx, "acct", "acct_wp")
	joined := strings.Join(f.stmts, "\n")
	if !strings.Contains(joined, sqlDropUser("acct_wp", "localhost")) || !strings.Contains(joined, sqlDropDatabase("acct_wp")) {
		t.Fatalf("an unrecorded object could not be removed:\n%s", joined)
	}
}

func TestServerHas(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	f.rows = map[string][]string{
		sqlServerHasDatabase("acct_wp"): {"1"},
		sqlServerHasDatabase("free_wp"): {"0"},
		sqlServerHasUser("acct_wp"):     {"2"},
		sqlServerHasUser("free_wp"):     {"0"},
	}
	for _, tc := range []struct {
		kind, name string
		want       bool
	}{{"database", "acct_wp", true}, {"database", "free_wp", false}, {"user", "acct_wp", true}, {"user", "free_wp", false}} {
		got, err := svc.ServerHas(ctx, tc.kind, tc.name)
		if err != nil || got != tc.want {
			t.Fatalf("%s %s: %v %v", tc.kind, tc.name, got, err)
		}
	}
	joined := strings.Join(f.stmts, "\n")
	for _, want := range []string{
		"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='acct_wp'",
		"SELECT COUNT(*) FROM mysql.user WHERE User='acct_wp'",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	// A name outside the identifier rules never reaches SQL; an answer that
	// is not one count is an error, not "absent".
	f.stmts = nil
	for _, bad := range []struct{ kind, name string }{{"database", "x' OR '1'='1"}, {"user", ""}, {"table", "acct_wp"}} {
		if _, err := svc.ServerHas(ctx, bad.kind, bad.name); err == nil {
			t.Fatalf("%s %q accepted", bad.kind, bad.name)
		}
	}
	if len(f.stmts) != 0 {
		t.Fatalf("SQL ran for a refused name: %q", f.stmts)
	}
	if _, err := svc.ServerHas(ctx, "database", "none_wp"); err == nil {
		t.Fatal("an empty answer counted as absent")
	}
	f.rows[sqlServerHasUser("odd_wp")] = []string{"yes"}
	if _, err := svc.ServerHas(ctx, "user", "odd_wp"); err == nil {
		t.Fatal("a non-number counted")
	}
	f.fail = true
	if _, err := svc.ServerHas(ctx, "database", "acct_wp"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("server down: %v", err)
	}
}

// A user moved from another server keeps its password as the hash: the
// statement names only the hash, the registry lists the user, and an error
// never quotes the hash.
func TestCreateUserWithHashStrict(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	hash := "*" + strings.Repeat("0A", 20)
	if err := svc.CreateUserWithHashStrict(ctx, "acct", "acct_wpu", hash); err != nil {
		t.Fatal(err)
	}
	want := "CREATE USER 'acct_wpu'@'localhost' IDENTIFIED VIA mysql_native_password USING '" + hash + "'"
	if !slices.Contains(f.stmts, want) {
		t.Fatalf("missing %q in %q", want, f.stmts)
	}
	if users, _ := svc.ListUsers(ctx, "acct"); len(users) != 1 || users[0].Name != "acct_wpu" {
		t.Fatalf("registry %+v", users)
	}
	for _, bad := range []string{"", "plain-password", "*" + strings.Repeat("0a", 20), "'; DROP USER root; --", "$2y$10$abc"} {
		if err := svc.CreateUserWithHashStrict(ctx, "acct", "acct_other", bad); err == nil {
			t.Errorf("%q accepted as a hash", bad)
		}
	}
	if err := svc.CreateUserWithHashStrict(ctx, "acct", "acct_wpu", hash); !errors.Is(err, ErrExists) {
		t.Fatalf("a registered user: %v", err)
	}
	other := "*" + strings.Repeat("1B", 20)
	f.errs = map[string]error{sqlCreateUserWithHashStrict("acct_ro", "localhost", other): errors.New("ERROR 1064 near 'USING '" + other + "''")}
	err := svc.CreateUserWithHashStrict(ctx, "acct", "acct_ro", other)
	if err == nil || strings.Contains(err.Error(), other) {
		t.Fatalf("an error quoted the hash: %v", err)
	}
}
