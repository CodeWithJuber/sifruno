// Command brokerdrive calls the root account broker the way the panel does:
// as the controller user, over the broker's Unix socket, through the same
// client library. The dev VM proofs use it so they exercise the real broker
// operations without needing the panel's HTTP API and session in front.
//
// It prints the broker's JSON answer and exits 0, or prints the error class
// and exits 1. It is a proof tool, not a product command.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"sifruno/internal/hostaccounts"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	global := flag.NewFlagSet("brokerdrive", flag.ContinueOnError)
	global.SetOutput(stderr)
	socket := global.String("socket", "", "Absolute path of the broker's Unix socket")
	actor := global.String("actor", "devvm proof", "Actor recorded in the broker journal")
	if global.Parse(args) != nil || *socket == "" || global.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: brokerdrive --socket PATH [--actor NAME] capability|list|create|state|ssh-keys|show-keys|web|wordpress|delete [flags]")
		return 2
	}
	service := hostaccounts.NewClient(*socket)
	// A WordPress install downloads WordPress and takes minutes.
	timeout := 60 * time.Second
	if global.Arg(0) == "wordpress" {
		timeout = 12 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	command := flag.NewFlagSet(global.Arg(0), flag.ContinueOnError)
	command.SetOutput(stderr)
	id := command.String("id", "", "Account ID")
	revision := command.Uint64("revision", 0, "Expected account revision")
	reason := command.String("reason", "Dev VM proof", "Reason recorded in the broker journal")
	username := command.String("username", "", "Account username (create)")
	domain := command.String("domain", "", "Account domain (create)")
	state := command.String("state", "", "active or suspended (state)")
	php := command.String("php", "8.3", "PHP version for the site (web)")
	quota := command.Int("quota-mib", 0, "Disk quota in MiB (web)")
	title := command.String("title", "", "Site title (wordpress)")
	adminUser := command.String("admin-user", "", "WordPress admin username (wordpress)")
	adminEmail := command.String("admin-email", "", "WordPress admin email (wordpress)")
	https := command.Bool("https", false, "Site address uses https (wordpress)")
	dbName := command.String("db-name", "", "Database name (wordpress)")
	dbUser := command.String("db-user", "", "Database user (wordpress)")
	// Passwords come from files, so they are not in this process's arguments.
	adminPasswordFile := command.String("admin-password-file", "", "File holding the WordPress admin password (wordpress)")
	dbPasswordFile := command.String("db-password-file", "", "File holding the database password (wordpress)")
	var keyFiles multiFlag
	command.Var(&keyFiles, "key-file", "Public key file to install (ssh-keys); repeat for several, omit all to remove access")
	if command.Parse(global.Args()[1:]) != nil || command.NArg() != 0 {
		return 2
	}

	var result any
	var err error
	switch global.Arg(0) {
	case "capability":
		result, err = service.Capability(ctx)
	case "list":
		result, err = service.List(ctx)
	case "create":
		result, err = service.Create(ctx, hostaccounts.CreateInput{Username: *username, Domain: *domain, Reason: *reason}, *actor)
	case "state":
		result, err = service.SetState(ctx, *id, hostaccounts.StateInput{State: *state, ExpectedRevision: *revision, Reason: *reason}, *actor)
	case "delete":
		result, err = service.Delete(ctx, *id, hostaccounts.DeleteInput{ExpectedRevision: *revision, Reason: *reason}, *actor)
	case "show-keys":
		keys, ok := service.(hostaccounts.SSHKeyService)
		if !ok {
			fmt.Fprintln(stderr, "this client has no SSH key surface")
			return 1
		}
		result, err = keys.SSHKeys(ctx, *id)
	case "ssh-keys":
		keys, ok := service.(hostaccounts.SSHKeyService)
		if !ok {
			fmt.Fprintln(stderr, "this client has no SSH key surface")
			return 1
		}
		lines := []string{}
		for _, file := range keyFiles {
			raw, readErr := os.ReadFile(file)
			if readErr != nil {
				fmt.Fprintf(stderr, "cannot read %s\n", file)
				return 1
			}
			lines = append(lines, strings.TrimSpace(string(raw)))
		}
		result, err = keys.SetSSHKeys(ctx, *id, hostaccounts.SSHKeysInput{Keys: lines, ExpectedRevision: *revision, Reason: *reason}, *actor)
	case "web":
		web, ok := service.(hostaccounts.WebService)
		if !ok {
			fmt.Fprintln(stderr, "this client has no web surface")
			return 1
		}
		result, err = web.SetWeb(ctx, *id, hostaccounts.WebInput{PHPVersion: *php, QuotaMiB: *quota, ExpectedRevision: *revision, Reason: *reason}, *actor)
	case "wordpress":
		wp, ok := service.(hostaccounts.WordPressService)
		if !ok {
			fmt.Fprintln(stderr, "this client has no WordPress surface")
			return 1
		}
		adminPassword, readErr := readSecret(*adminPasswordFile)
		if readErr != nil {
			fmt.Fprintln(stderr, "read the admin password file:", readErr)
			return 2
		}
		dbPassword, readErr := readSecret(*dbPasswordFile)
		if readErr != nil {
			fmt.Fprintln(stderr, "read the database password file:", readErr)
			return 2
		}
		var installed hostaccounts.WordPressResult
		installed, err = wp.InstallWordPress(ctx, *id, hostaccounts.WordPressInput{ExpectedRevision: *revision, HTTPS: *https, Title: *title, AdminUser: *adminUser, AdminEmail: *adminEmail, AdminPassword: adminPassword, DBName: *dbName, DBUser: *dbUser, DBPassword: dbPassword}, *actor)
		var failed *hostaccounts.InstallError
		if errors.As(err, &failed) {
			fmt.Fprintf(stderr, "broker refused: WordPress %s step failed: %s\n", failed.Step, failed.Detail)
			return 1
		}
		result = installed
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", global.Arg(0))
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "broker refused: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if encoder.Encode(result) != nil {
		return 1
	}
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// readSecret reads a one-line secret file, without its line ending.
func readSecret(path string) (string, error) {
	if path == "" {
		return "", errors.New("no file given")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}
