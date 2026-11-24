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
		fmt.Fprintln(stderr, "usage: brokerdrive --socket PATH [--actor NAME] capability|list|create|state|plan|ssh-keys|show-keys|web|certificate|wordpress|public-html|delete|backup-status|backup-target|backup-password|backup-password-saved|backup|backups|restore|drill|prune [flags]")
		return 2
	}
	service := hostaccounts.NewClient(*socket)
	// A WordPress install downloads WordPress and takes minutes; a web
	// change, a certificate and a delete rewrite the web server's config,
	// which the broker allows up to four minutes on a busy host.
	timeout := 60 * time.Second
	switch global.Arg(0) {
	case "wordpress":
		timeout = 12 * time.Minute
	case "web", "certificate", "delete", "state", "plan", "backup-target", "backups":
		// A state change of a live site re-applies the site list too, and
		// so does a plan change of its limits.
		timeout = 6 * time.Minute
	case "backup", "restore", "drill", "prune":
		timeout = 125 * time.Minute
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
	plan := command.String("plan", "default", "Plan name (plan)")
	processes := command.Int("processes", 0, "Process limit of the account; with --memory-mib and --cpu-percent, or none to keep the limits (plan)")
	memoryMiB := command.Int("memory-mib", 0, "Memory limit of the account in MiB (plan)")
	cpuPercent := command.Int("cpu-percent", 0, "CPU limit of the account, 100 is one CPU (plan)")
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
	certFile := command.String("cert-file", "", "PEM certificate chain, leaf first (certificate)")
	host := command.String("host", "", "Storage server host (backup-target)")
	port := command.Int("port", 22, "Storage server SSH port (backup-target)")
	user := command.String("user", "", "Storage server SFTP user (backup-target)")
	path := command.String("path", "", "Repository folder on the storage server (backup-target)")
	knownHostsFile := command.String("known-hosts-file", "", "ssh-keyscan output for the storage server (backup-target)")
	// The repository password is shown until it is confirmed saved; it goes
	// to this file, never to the output.
	passwordOut := command.String("password-out", "", "File (0600) that receives the repository password when it is shown (backup-target, backup-password)")
	snapshot := command.String("snapshot", "", "Snapshot ID (restore)")
	files := command.Bool("files", false, "Restore the files (restore)")
	var databases multiFlag
	command.Var(&databases, "db", "Database to back up or restore; repeat for several (backup, restore)")
	var keyFiles multiFlag
	command.Var(&keyFiles, "key-file", "Public key file to install (ssh-keys); repeat for several, omit all to remove access. With certificate: the PEM private key, once")
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
	case "plan":
		limits := hostaccounts.AccountLimits{Processes: *processes, MemoryMiB: *memoryMiB, CPUPercent: *cpuPercent}
		result, err = service.SetPlan(ctx, *id, hostaccounts.PlanInput{Plan: *plan, Limits: limits, ExpectedRevision: *revision, Reason: *reason}, *actor)
	case "delete":
		result, err = service.Delete(ctx, *id, hostaccounts.DeleteInput{ExpectedRevision: *revision, Reason: *reason}, *actor)
	case "public-html":
		folders, ok := service.(hostaccounts.SiteFolderService)
		if !ok {
			fmt.Fprintln(stderr, "this client has no site folder surface")
			return 1
		}
		result, err = folders.AdoptPublicHTML(ctx, *id, hostaccounts.AdoptInput{ExpectedRevision: *revision, Reason: *reason}, *actor)
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
	case "certificate":
		certs, ok := service.(hostaccounts.CertificateService)
		if !ok {
			fmt.Fprintln(stderr, "this client has no certificate surface")
			return 1
		}
		if *certFile == "" || len(keyFiles) != 1 {
			fmt.Fprintln(stderr, "certificate needs --cert-file and one --key-file")
			return 2
		}
		chain, readErr := os.ReadFile(*certFile)
		if readErr != nil {
			fmt.Fprintln(stderr, "read the certificate file:", readErr)
			return 2
		}
		// The key goes to the broker in the request body and is never printed.
		key, readErr := os.ReadFile(keyFiles[0])
		if readErr != nil {
			fmt.Fprintln(stderr, "read the key file:", readErr)
			return 2
		}
		result, err = certs.SetCertificate(ctx, *id, hostaccounts.CertificateInput{ExpectedRevision: *revision, CertPEM: string(chain), KeyPEM: string(key), Reason: *reason}, *actor)
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
	case "backup-status", "backup-target", "backup-password", "backup-password-saved", "backup", "backups", "restore", "drill", "prune":
		backups, ok := service.(hostaccounts.BackupService)
		if !ok {
			fmt.Fprintln(stderr, "this client has no backup surface")
			return 1
		}
		dbs := []string(databases)
		if dbs == nil {
			dbs = []string{}
		}
		switch global.Arg(0) {
		case "backup-status":
			result, err = backups.BackupStatus(ctx)
		case "backup-target":
			known, readErr := os.ReadFile(*knownHostsFile)
			if readErr != nil || *passwordOut == "" {
				fmt.Fprintln(stderr, "backup-target needs --known-hosts-file and --password-out")
				return 2
			}
			var saved hostaccounts.BackupTargetResult
			saved, err = backups.SetBackupTarget(ctx, hostaccounts.BackupTargetInput{Host: *host, Port: *port, User: *user, Path: *path, KnownHosts: string(known), Reason: *reason}, *actor)
			if err == nil && saved.Password != "" {
				if writeErr := os.WriteFile(*passwordOut, []byte(saved.Password+"\n"), 0600); writeErr != nil {
					fmt.Fprintln(stderr, "write the password file:", writeErr)
					return 1
				}
				fmt.Fprintf(stderr, "repository password shown (until it is confirmed saved): written to %s\n", *passwordOut)
				saved.Password = ""
			}
			result = saved
		case "backup-password":
			if *passwordOut == "" {
				fmt.Fprintln(stderr, "backup-password needs --password-out")
				return 2
			}
			var shown hostaccounts.BackupPassword
			shown, err = backups.ShowBackupPassword(ctx, hostaccounts.BackupPasswordInput{Reason: *reason}, *actor)
			if err == nil {
				if writeErr := os.WriteFile(*passwordOut, []byte(shown.Password+"\n"), 0600); writeErr != nil {
					fmt.Fprintln(stderr, "write the password file:", writeErr)
					return 1
				}
				fmt.Fprintf(stderr, "repository password shown again: written to %s\n", *passwordOut)
			}
			result = struct {
				Written string `json:"written"`
			}{*passwordOut}
		case "backup-password-saved":
			result, err = backups.ConfirmBackupPassword(ctx, hostaccounts.BackupPasswordInput{Reason: *reason}, *actor)
		case "backup":
			result, err = backups.BackupAccount(ctx, *id, hostaccounts.BackupInput{Databases: dbs, Reason: *reason}, *actor)
		case "backups":
			result, err = backups.ListBackups(ctx, *id)
		case "restore":
			result, err = backups.RestoreAccount(ctx, *id, hostaccounts.RestoreInput{ExpectedRevision: *revision, Snapshot: *snapshot, Files: *files, Databases: dbs, Reason: *reason}, *actor)
		case "drill":
			result, err = backups.DrillAccount(ctx, *id, hostaccounts.DrillInput{Reason: *reason}, *actor)
		case "prune":
			result, err = backups.PruneBackups(ctx, hostaccounts.PruneInput{Reason: *reason}, *actor)
		}
		var failed *hostaccounts.BackupError
		if errors.As(err, &failed) {
			fmt.Fprintf(stderr, "broker refused: backup %s step failed: %s\n", failed.Step, failed.Detail)
			return 1
		}
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
