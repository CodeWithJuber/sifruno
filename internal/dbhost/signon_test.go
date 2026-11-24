package dbhost

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

const signonName = "SifrunoPMA_0123456789abcdef0123"

// signonPrivileges is the grant's privilege list, spelled out: what a
// temporary user can do, and that it can make nothing that records it as
// DEFINER.
const signonPrivileges = "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, SHOW VIEW"

func TestSignonPrivilegesMakeNothingWithADefiner(t *testing.T) {
	for _, p := range SignonPrivileges {
		if !AllowedPrivileges[p] {
			t.Fatalf("%s is not in the account privilege whitelist", p)
		}
		for _, definer := range []string{"ALL PRIVILEGES", "TRIGGER", "CREATE VIEW", "CREATE ROUTINE", "ALTER ROUTINE", "EVENT"} {
			if p == definer {
				t.Fatalf("a temporary user gets %s", p)
			}
		}
	}
}

func TestSignonUserNames(t *testing.T) {
	for _, name := range []string{signonName, "SifrunoPMA_ffffffffffffffffffff"} {
		if !ValidSignonUser(name) {
			t.Fatalf("%q should be a temporary user", name)
		}
	}
	for _, name := range []string{"", "sifrunopma_0123456789abcdef0123", "SifrunoPMA_0123456789ABCDEF0123", "SifrunoPMA_0123", "SifrunoPMA_0123456789abcdef01234",
		"alpha_wp", "SifrunoPMA_0123456789abcdef012'", "SifrunoPMA_0123456789abcdef0123\n"} {
		if ValidSignonUser(name) {
			t.Fatalf("%q must not be a temporary user", name)
		}
	}
	// No hosting account's prefix can cover one: account names are lowercase.
	if databaseOwnerLike := strings.ToLower(SignonUserPrefix); databaseOwnerLike == SignonUserPrefix {
		t.Fatal("the prefix must hold a capital letter")
	}
}

func TestCreateSignonUserGrantsTheWebsitesDatabasesOnly(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	for _, db := range []string{"alpha_wp", "alpha_shop"} {
		if err := svc.CreateDatabase(ctx, "alpha", db); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.CreateDatabase(ctx, "beta", "beta_wp"); err != nil {
		t.Fatal(err)
	}
	f.stmts = nil
	if err := svc.CreateSignonUser(ctx, "alpha", signonName, "pw'secret", []string{"alpha_wp", "alpha_shop"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		sqlVersion,
		"CREATE USER '" + signonName + "'@'localhost' IDENTIFIED BY 'pw\\'secret'",
		"GRANT " + signonPrivileges + " ON `alpha\\_wp`.* TO '" + signonName + "'@'localhost';\n" +
			"GRANT " + signonPrivileges + " ON `alpha\\_shop`.* TO '" + signonName + "'@'localhost'",
	}
	if !slices.Equal(f.stmts, want) {
		t.Fatalf("statements\n%q\nwant\n%q", f.stmts, want)
	}
	// Not in the registry: no website lists it.
	if users, _ := svc.AllUsers(ctx); len(users) != 0 {
		t.Fatalf("a temporary user was registered: %+v", users)
	}

	// Another account's database, an unknown one, a bad name: refused before any SQL.
	f.stmts = nil
	for _, dbs := range [][]string{{"beta_wp"}, {"alpha_wp", "beta_wp"}, {"alpha_gone"}, {"alpha_%"}, {}} {
		if err := svc.CreateSignonUser(ctx, "alpha", signonName, "pw", dbs); err == nil {
			t.Fatalf("databases %q were accepted", dbs)
		}
	}
	for _, name := range []string{"alpha_wp", "root", "SifrunoPMA_x"} {
		if err := svc.CreateSignonUser(ctx, "alpha", name, "pw", []string{"alpha_wp"}); err == nil {
			t.Fatalf("user name %q was accepted", name)
		}
	}
	if err := svc.CreateSignonUser(ctx, "", signonName, "pw", []string{"alpha_wp"}); err == nil {
		t.Fatal("an empty owner, which dbhost reads as every account, was accepted")
	}
	if err := svc.CreateSignonUser(ctx, "alpha", signonName, "pw\nGRANT", []string{"alpha_wp"}); err == nil {
		t.Fatal("a password with a line break was accepted")
	}
	if len(f.stmts) != 0 {
		t.Fatalf("SQL ran for a refused request: %q", f.stmts)
	}
}

func TestCreateSignonUserUndoesAFailedGrant(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	if err := svc.CreateDatabase(ctx, "alpha", "alpha_wp"); err != nil {
		t.Fatal(err)
	}
	grant := "GRANT " + signonPrivileges + " ON `alpha\\_wp`.* TO '" + signonName + "'@'localhost'"
	f.errs = map[string]error{grant: errors.New("ERROR 1044 (42000) at line 1: Access denied")}
	f.stmts = nil
	if err := svc.CreateSignonUser(ctx, "alpha", signonName, "pw", []string{"alpha_wp"}); err == nil {
		t.Fatal("a failed grant was not reported")
	}
	drop := "DROP USER IF EXISTS '" + signonName + "'@'localhost';\nKILL HARD USER '" + signonName + "'@'localhost'"
	if f.stmts[len(f.stmts)-1] != drop {
		t.Fatalf("the user was not dropped again: %q", f.stmts)
	}

	// A name the server already has is ErrExists.
	create := "CREATE USER '" + signonName + "'@'localhost' IDENTIFIED BY 'pw'"
	f.errs = map[string]error{create: errors.New("ERROR 1396 (HY000) at line 1: Operation CREATE USER failed")}
	if err := svc.CreateSignonUser(ctx, "alpha", signonName, "pw", []string{"alpha_wp"}); !errors.Is(err, ErrExists) {
		t.Fatalf("existing user: %v", err)
	}
}

func TestDropAndListSignonUsers(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	if err := svc.DropSignonUser(ctx, signonName); err != nil {
		t.Fatal(err)
	}
	if got := f.stmts[len(f.stmts)-1]; got != "DROP USER IF EXISTS '"+signonName+"'@'localhost';\nKILL HARD USER '"+signonName+"'@'localhost'" {
		t.Fatalf("drop: %q", got)
	}
	for _, name := range []string{"alpha_wp", "root", "SifrunoPMA_"} {
		if err := svc.DropSignonUser(ctx, name); err == nil {
			t.Fatalf("dropping %q was accepted", name)
		}
	}
	f.rows = map[string][]string{sqlSignonUsers: {signonName, "SifrunoPMA_admins_own", "SifrunoPMA_ffffffffffffffffffff"}}
	users, err := svc.SignonUsers(ctx)
	if err != nil || !slices.Equal(users, []string{signonName, "SifrunoPMA_ffffffffffffffffffff"}) {
		t.Fatalf("list %q %v", users, err)
	}
	if !strings.Contains(sqlSignonUsers, `LIKE 'SifrunoPMA\\_%'`) || !strings.Contains(sqlSignonUsers, "Host='localhost'") {
		t.Fatalf("list SQL %s", sqlSignonUsers)
	}
	f.fail = true
	if _, err := svc.SignonUsers(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("server down: %v", err)
	}
}
