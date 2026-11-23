package dbhost

import (
	"context"
	"os"
	"path/filepath"
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
