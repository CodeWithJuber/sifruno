package dbhost

import (
	"context"
	"strings"
	"testing"
)

func TestValidateAccessHost(t *testing.T) {
	for _, ok := range []string{"203.0.113.9", "%", "10.0.0.%", "db.example.com", "host_%"} {
		if err := ValidateAccessHost(ok); err != nil {
			t.Fatalf("host %q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "x';DROP", "a,b", "%s\"", strings.Repeat("a", 300)} {
		if err := ValidateAccessHost(bad); err == nil {
			t.Fatalf("host %q should be rejected", bad)
		}
	}
}

func TestRenameDatabase(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	if err := svc.CreateDatabase(ctx, "acct1", "acct1_old"); err != nil {
		t.Fatal(err)
	}
	f.rows = map[string][]string{
		sqlTablesIn("acct1_old"): {"wp_posts", "wp_options"},
	}
	newName, err := svc.RenameDatabase(ctx, "acct1", "acct1_old", "new")
	if err != nil {
		t.Fatal(err)
	}
	if newName != "acct1_new" {
		t.Fatalf("new name: %s", newName)
	}
	joined := strings.Join(f.stmts, "\n")
	for _, want := range []string{
		"CREATE DATABASE IF NOT EXISTS `acct1_new`",
		"RENAME TABLE `acct1_old`.`wp_posts` TO `acct1_new`.`wp_posts`",
		"RENAME TABLE `acct1_old`.`wp_options` TO `acct1_new`.`wp_options`",
		`UPDATE mysql.db SET Db='acct1\\_new' WHERE Db IN ('acct1\\_old', 'acct1_old')`,
		"DROP DATABASE IF EXISTS `acct1_old`",
		"FLUSH PRIVILEGES",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing statement %q in:\n%s", want, joined)
		}
	}
	if _, ok := svc.Registry.ownerOf("acct1_new"); !ok {
		t.Fatal("registry did not record the renamed database")
	}
	if _, ok := svc.Registry.ownerOf("acct1_old"); ok {
		t.Fatal("registry still holds the old database name")
	}
	// cross-account fence
	if _, err := svc.RenameDatabase(ctx, "other", "acct1_new", "x"); err == nil ||
		!strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected ownership fence, got %v", err)
	}
}

func TestAccessHosts(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	if err := svc.CreateDatabase(ctx, "acct1", "acct1_wp"); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateUser(ctx, "acct1", "acct1_u", "pw"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetPrivileges(ctx, "acct1", "acct1_u", "acct1_wp", []string{"ALL PRIVILEGES"}); err != nil {
		t.Fatal(err)
	}
	f.rows = map[string][]string{
		sqlUserAuth("acct1_u", "localhost"): {"mysql_native_password\t*ABCDEF1234567890"},
		sqlPrivileges("acct1_u"): {
			"GRANT USAGE ON *.* TO 'acct1_u'@'localhost'",
			"GRANT ALL PRIVILEGES ON `acct1_wp`.* TO 'acct1_u'@'localhost'",
		},
	}
	if err := svc.AddAccessHost(ctx, "acct1", "10.0.0.%"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.stmts, "\n")
	if !strings.Contains(joined, "CREATE USER IF NOT EXISTS 'acct1_u'@'10.0.0.%' IDENTIFIED VIA `mysql_native_password` USING '*ABCDEF1234567890'") {
		t.Fatalf("clone statement missing:\n%s", joined)
	}
	if !strings.Contains(joined, "GRANT ALL PRIVILEGES ON `acct1_wp`.* TO 'acct1_u'@'10.0.0.%'") {
		t.Fatalf("grant replay missing:\n%s", joined)
	}
	if strings.Contains(joined, "USAGE ON *.* TO 'acct1_u'@'10.0.0.%'") {
		t.Fatal("global USAGE line must not be replayed")
	}
	if got := svc.ListAccessHosts(ctx, "acct1"); len(got) != 1 || got[0] != "10.0.0.%" {
		t.Fatalf("list hosts: %v", got)
	}

	if err := svc.DeleteAccessHost(ctx, "acct1", "10.0.0.%"); err != nil {
		t.Fatal(err)
	}
	last := f.stmts[len(f.stmts)-1]
	if !strings.Contains(last, "DROP USER IF EXISTS 'acct1_u'@'10.0.0.%'") {
		t.Fatalf("drop statement: %s", last)
	}
	if got := svc.ListAccessHosts(ctx, "acct1"); len(got) != 0 {
		t.Fatalf("hosts after delete: %v", got)
	}

	// negative: evil host value never reaches SQL
	stmtsBefore := len(f.stmts)
	if err := svc.AddAccessHost(ctx, "acct1", "x';DROP USER 'root'@'%"); err == nil {
		t.Fatal("invalid host accepted")
	}
	if len(f.stmts) != stmtsBefore {
		t.Fatal("invalid host still executed SQL")
	}
}

func TestAddAccessHostUnixSocketUserRejected(t *testing.T) {
	ctx := context.Background()
	svc, f := newTestService(t)
	if err := svc.CreateUser(ctx, "acct1", "acct1_u", "pw"); err != nil {
		t.Fatal(err)
	}
	f.rows = map[string][]string{
		sqlUserAuth("acct1_u", "localhost"): {"unix_socket\t"},
	}
	err := svc.AddAccessHost(ctx, "acct1", "203.0.113.9")
	if err == nil || !strings.Contains(err.Error(), "cannot be cloned") {
		t.Fatalf("expected uncloneable-auth error, got %v", err)
	}
}
