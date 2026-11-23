// Command dbdrive creates a site's database, user and grant through the
// panel's own database code (internal/dbhost), for dev VM proofs. The
// password comes from a file, so it is in no process's arguments.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"sifruno/internal/dbhost"
)

func main() {
	fs := flag.NewFlagSet("dbdrive", flag.ContinueOnError)
	socket := fs.String("socket", "/var/lib/mysql/mysql.sock", "MariaDB socket")
	defaults := fs.String("defaults-file", "", "Option file with the database admin credentials; empty uses socket auth as the invoking user")
	registry := fs.String("registry", "", "Path of the dbhost registry file")
	owner := fs.String("owner", "", "Owning account username")
	name := fs.String("name", "", "Database and user name, with the account prefix")
	passwordFile := fs.String("password-file", "", "File holding the database user's password")
	if fs.Parse(os.Args[1:]) != nil || *registry == "" || *owner == "" || *name == "" || *passwordFile == "" {
		fmt.Fprintln(os.Stderr, "usage: dbdrive --registry PATH --owner USER --name USER_db --password-file FILE [--socket PATH] [--defaults-file FILE]")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read the password file:", err)
		os.Exit(2)
	}
	password := strings.TrimRight(string(raw), "\r\n")
	reg, err := dbhost.OpenRegistry(*registry)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open the registry:", err)
		os.Exit(1)
	}
	svc := &dbhost.LocalService{Run: dbhost.CLIRunner{Socket: *socket, DefaultsFile: *defaults}, Registry: reg}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, step := range []struct {
		what string
		run  func() error
	}{
		{"create the database", func() error { return svc.CreateDatabase(ctx, *owner, *name) }},
		{"create the user", func() error { return svc.CreateUser(ctx, *owner, *name, password) }},
		{"grant the user the database", func() error {
			return svc.SetPrivileges(ctx, *owner, *name, *name, []string{"ALL PRIVILEGES"})
		}},
	} {
		if err := step.run(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", step.what, err)
			os.Exit(1)
		}
	}
	fmt.Printf("database %s with user %s@localhost\n", *name, *name)
}
