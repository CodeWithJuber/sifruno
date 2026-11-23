package dbhost

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateIdentifier(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"wlive01_wp", true},
		{"wlive01_a1", true},
		{"", false},
		{"wlive01_wp;DROP", false},
		{"wlive01 wp", false},
		{"wlive01-wp", false},
		{"wlive01_wp`", false},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("a", 64), true},
	}
	for _, c := range cases {
		err := ValidateIdentifier("database", c.name, MaxDatabaseLen)
		if c.ok && err != nil {
			t.Fatalf("%q should pass: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("%q should be rejected", c.name)
		}
	}
}

func TestParsePrivileges(t *testing.T) {
	p, err := ParsePrivileges("select, insert")
	if err != nil || len(p) != 2 || p[0] != "SELECT" || p[1] != "INSERT" {
		t.Fatalf("basic: %v %v", p, err)
	}
	if _, err := ParsePrivileges("ALL PRIVILEGES"); err != nil {
		t.Fatalf("all alone: %v", err)
	}
	if _, err := ParsePrivileges("ALL PRIVILEGES, SELECT"); err == nil {
		t.Fatal("ALL PRIVILEGES combined must be rejected")
	}
	if _, err := ParsePrivileges("SUPER"); err == nil {
		t.Fatal("SUPER must be rejected (whitelist)")
	}
	if _, err := ParsePrivileges("DROP;DELETE FROM mysql.user"); err == nil {
		t.Fatal("injection-shaped privilege must be rejected")
	}
	if _, err := ParsePrivileges(""); err == nil {
		t.Fatal("empty must be rejected")
	}
	if _, err := ParsePrivileges("create   temporary    tables"); err != nil {
		t.Fatalf("whitespace-normalized multiword: %v", err)
	}
}

func TestSQLBuilders(t *testing.T) {
	if got := sqlCreateDatabase("wlive01_wp"); !strings.Contains(got, "`wlive01_wp`") || !strings.Contains(got, "utf8mb4") {
		t.Fatalf("create db: %s", got)
	}
	if got := sqlCreateUser("wlive01_u", "localhost", "p'w\\d"); !strings.Contains(got, `'p\'w\\d'`) {
		t.Fatalf("password escaping: %s", got)
	}
	if got := sqlGrant("wlive01_wp", "wlive01_u", "localhost", []string{"SELECT", "INSERT"}); !strings.Contains(got, "GRANT SELECT, INSERT ON `wlive01_wp`.* TO 'wlive01_u'@'localhost'") {
		t.Fatalf("grant: %s", got)
	}
	if got := sqlRenameUser("a_u", "localhost", "a_v"); !strings.Contains(got, "RENAME USER 'a_u'@'localhost' TO 'a_v'@'localhost'") {
		t.Fatalf("rename: %s", got)
	}
}

// fakeRunner records statements; probe succeeds with a pinned version.
type fakeRunner struct {
	stmts []string
	rows  map[string][]string
	errs  map[string]error // statements the server refuses
	fail  bool
}

func (f *fakeRunner) Run(_ context.Context, sql string) ([]string, error) {
	if f.fail {
		return nil, errors.New("cannot connect")
	}
	f.stmts = append(f.stmts, sql)
	if err, ok := f.errs[sql]; ok {
		return nil, err
	}
	if strings.HasPrefix(sql, sqlVersion[:15]) {
		return []string{"10.11.19-MariaDB"}, nil
	}
	if f.rows != nil {
		if r, ok := f.rows[sql]; ok {
			return r, nil
		}
	}
	return []string{}, nil
}

func newTestService(t *testing.T) (*LocalService, *fakeRunner) {
	t.Helper()
	reg, err := OpenRegistry(filepath.Join(t.TempDir(), "dbmap.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{}
	return &LocalService{Run: f, Registry: reg}, f
}

func TestLifecycleWithFakeRunner(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)

	if v, err := svc.Probe(ctx); err != nil || v != "10.11.19-MariaDB" {
		t.Fatalf("probe: %v %v", v, err)
	}
	if err := svc.CreateDatabase(ctx, "wlive01", "wlive01_wp"); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateUser(ctx, "wlive01", "wlive01_u", "s3cret!"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetPrivileges(ctx, "wlive01", "wlive01_u", "wlive01_wp", []string{"ALL PRIVILEGES"}); err != nil {
		t.Fatal(err)
	}
	dbs, _ := svc.ListDatabases(ctx, "wlive01")
	if len(dbs) != 1 || dbs[0].Users[0] != "wlive01_u" {
		t.Fatalf("registry after grant: %+v", dbs)
	}
	// ownership fence: another account cannot touch wlive01's database
	if err := svc.DropDatabase(ctx, "attacker", "wlive01_wp"); err == nil {
		t.Fatal("cross-account drop must be denied")
	}
	if err := svc.RenameUser(ctx, "wlive01", "wlive01_u", "wlive01_v"); err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeAccess(ctx, "wlive01", "wlive01_v", "wlive01_wp"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DropUser(ctx, "wlive01", "wlive01_v"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DropDatabase(ctx, "wlive01", "wlive01_wp"); err != nil {
		t.Fatal(err)
	}
	dbs, _ = svc.ListDatabases(ctx, "")
	if len(dbs) != 0 {
		t.Fatalf("residue: %+v", dbs)
	}
	joined := strings.Join(f.stmts, "\n")
	for _, want := range []string{"CREATE DATABASE", "CREATE USER", "REVOKE ALL PRIVILEGES", "GRANT ALL PRIVILEGES", "RENAME USER", "DROP USER", "DROP DATABASE"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing statement %q in:\n%s", want, joined)
		}
	}
}

func TestFailClosedWhenServerDown(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	f.fail = true
	if err := svc.CreateDatabase(ctx, "a", "a_db"); err != ErrUnavailable {
		t.Fatalf("create must fail closed: %v", err)
	}
	if _, err := svc.ListDatabases(ctx, "a"); err != ErrUnavailable {
		t.Fatalf("list must fail closed: %v", err)
	}
	// registry must not have recorded the failed create
	dbs, _ := svc.AllDatabases(context.Background())
	_ = f
	if len(dbs) != 0 {
		t.Fatalf("phantom registry entry after failed create: %+v", dbs)
	}
}

func TestPrefixedName(t *testing.T) {
	if PrefixedName("wlive01", "wp") != "wlive01_wp" {
		t.Fatal("suffix join")
	}
	if PrefixedName("wlive01", "wlive01_wp") != "wlive01_wp" {
		t.Fatal("already-prefixed must pass through")
	}
}
