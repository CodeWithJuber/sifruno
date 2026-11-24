package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// An ed25519 public key in authorized_keys form (fixture key, public only).
const fixtureHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func targetInput() BackupTargetInput {
	return BackupTargetInput{Host: "backup.example.test", Port: 22, User: "sifbackup", Path: "/srv/sifruno-backup/restic", KnownHosts: "# backup.example.test:22 SSH-2.0-OpenSSH_8.7\nbackup.example.test " + fixtureHostKey + "\n", Reason: "Set backup storage"}
}

func TestBackupTargetValidation(t *testing.T) {
	got, ok := validBackupTarget(targetInput(), "test operator")
	if !ok || !slices.Equal(got.HostKeys, []string{fixtureHostKey}) {
		t.Fatalf("a valid target was refused: %+v %v", got, ok)
	}
	for name, change := range map[string]func(*BackupTargetInput){
		"host starting with -":     func(in *BackupTargetInput) { in.Host = "-oProxyCommand=x" },
		"host with a space":        func(in *BackupTargetInput) { in.Host = "backup example" },
		"host in capitals":         func(in *BackupTargetInput) { in.Host = "Backup.example.test" },
		"unspecified address":      func(in *BackupTargetInput) { in.Host = "0.0.0.0" },
		"port 0":                   func(in *BackupTargetInput) { in.Port = 0 },
		"port too high":            func(in *BackupTargetInput) { in.Port = 70000 },
		"user starting with -":     func(in *BackupTargetInput) { in.User = "-l" },
		"user with a space":        func(in *BackupTargetInput) { in.User = "sif backup" },
		"relative path":            func(in *BackupTargetInput) { in.Path = "srv/restic" },
		"path with a space":        func(in *BackupTargetInput) { in.Path = "/srv/my backups" },
		"path with a quote":        func(in *BackupTargetInput) { in.Path = `/srv/"x"` },
		"path with ..":             func(in *BackupTargetInput) { in.Path = "/srv/../etc" },
		"path with a trailing /":   func(in *BackupTargetInput) { in.Path = "/srv/restic/" },
		"no host key":              func(in *BackupTargetInput) { in.KnownHosts = "# only a comment\n" },
		"host key of another host": func(in *BackupTargetInput) { in.KnownHosts = "other.example.test " + fixtureHostKey },
		"host key with options":    func(in *BackupTargetInput) { in.KnownHosts = "@cert-authority * " + fixtureHostKey },
		"broken host key": func(in *BackupTargetInput) {
			in.KnownHosts = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJ"
		},
		"unknown key type":           func(in *BackupTargetInput) { in.KnownHosts = "ssh-dss " + strings.Fields(fixtureHostKey)[1] },
		"the same key twice":         func(in *BackupTargetInput) { in.KnownHosts = fixtureHostKey + "\n" + fixtureHostKey },
		"carriage return":            func(in *BackupTargetInput) { in.KnownHosts = fixtureHostKey + "\r\n" },
		"reason with a line break":   func(in *BackupTargetInput) { in.Reason = "a\nb" },
		"IPv6 not in canonical form": func(in *BackupTargetInput) { in.Host = "0:0::1" },
	} {
		in := targetInput()
		change(&in)
		if _, ok := validBackupTarget(in, "test operator"); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, accepted := range []string{fixtureHostKey, "[backup.example.test]:22 " + fixtureHostKey, "|1|c2FsdA==|aGFzaA== " + fixtureHostKey, "backup.example.test " + fixtureHostKey + " a comment"} {
		in := targetInput()
		in.KnownHosts = accepted
		if got, ok := validBackupTarget(in, "test operator"); !ok || got.HostKeys[0] != fixtureHostKey {
			t.Errorf("%q refused", accepted)
		}
	}
	in := targetInput()
	in.Host, in.Port, in.KnownHosts = "::1", 2222, "[::1]:2222 "+fixtureHostKey
	if _, ok := validBackupTarget(in, "test operator"); !ok {
		t.Error("an IPv6 target on another port was refused")
	}
}

// restic splits sftp.command on spaces and quotes and starts the result
// directly. The command must split back into exactly the arguments.
func TestSFTPCommandIsAnExactArgumentList(t *testing.T) {
	target, _ := validBackupTarget(targetInput(), "test operator")
	dir := "/var/lib/sifruno-broker/backup"
	want := []string{"/usr/bin/ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=/var/lib/sifruno-broker/backup/known_hosts", "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "HostKeyAlias=sifruno-backup-target", "-o", "UpdateHostKeys=no", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		"-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=4",
		"-i", "/var/lib/sifruno-broker/backup/ssh_key", "-p", "22", "-l", "sifbackup", "-s", "--", "backup.example.test", "sftp"}
	if got := sftpArgs(dir, "known_hosts", target); !slices.Equal(got, want) {
		t.Fatalf("ssh arguments:\n got %q\nwant %q", got, want)
	}
	command, ok := sftpCommand(dir, "known_hosts", target)
	if !ok || !slices.Equal(strings.Fields(command), want) || strings.ContainsAny(command, "\"'\\\t\n") {
		t.Fatalf("command %q does not split back into the arguments", command)
	}
	global, ok := resticGlobal(dir, "known_hosts.next", target)
	if !ok || !slices.Equal(global[:2], []string{"--repo", "sftp::/srv/sifruno-backup/restic"}) || global[2] != "--option" || !strings.HasPrefix(global[3], "sftp.command=/usr/bin/ssh ") || !strings.Contains(global[3], "UserKnownHostsFile="+dir+"/known_hosts.next ") {
		t.Fatalf("restic global arguments %q", global)
	}
	if _, ok := sftpCommand("/var/lib/my state/backup", "known_hosts", target); ok {
		t.Fatal("a state folder with a space must be refused, since restic would split it")
	}
	for _, env := range resticEnv(dir) {
		if strings.HasPrefix(env, "RESTIC_PASSWORD=") {
			t.Fatal("the password must reach restic as a file, never as a value")
		}
	}
	if !slices.Contains(resticEnv(dir), "RESTIC_PASSWORD_FILE="+dir+"/password") {
		t.Fatal("restic must read the root-only password file")
	}
}

func TestKnownHostsFileUsesTheAlias(t *testing.T) {
	target, _ := validBackupTarget(targetInput(), "test operator")
	if got := string(knownHostsFile(target)); got != "sifruno-backup-target "+fixtureHostKey+"\n" {
		t.Fatalf("known_hosts %q", got)
	}
	if !validStoredTarget(target) {
		t.Fatal("a canonical target must read back")
	}
	target.HostKeys = []string{fixtureHostKey + " comment"}
	if validStoredTarget(target) {
		t.Fatal("a stored host key must be canonical")
	}
}

func TestAccountDatabases(t *testing.T) {
	others := []string{"fixtureacct", "fixtureacct_x", "otheracct"}
	got, ok := accountDatabases([]string{"fixtureacct_wp", "fixtureacct_a"}, "fixtureacct", others)
	if !ok || !slices.Equal(got, []string{"fixtureacct_a", "fixtureacct_wp"}) {
		t.Fatalf("databases %v %v", got, ok)
	}
	if got, ok := accountDatabases(nil, "fixtureacct", others); !ok || len(got) != 0 {
		t.Fatal("no databases is a files-only backup")
	}
	for name, dbs := range map[string][]string{
		"another account's database":            {"otheracct_wp"},
		"inside another account's prefix":       {"fixtureacct_x_wp"},
		"the bare prefix":                       {"fixtureacct_"},
		"a name with a dot":                     {"fixtureacct_wp.x"},
		"a name with a backquote":               {"fixtureacct_w`p"},
		"a name over 64 characters":             {"fixtureacct_" + strings.Repeat("d", 60)},
		"the same name twice":                   {"fixtureacct_wp", "fixtureacct_wp"},
		"more databases than a backup may name": slices.Repeat([]string{"fixtureacct_a"}, 17),
	} {
		if _, ok := accountDatabases(dbs, "fixtureacct", others); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRestoreUserSQL(t *testing.T) {
	sql := createRestoreUserSQL("fixtureacct_wp", "sifruno_rst_0123456789abcdef", "00112233445566778899aabbccddeeff")
	want := "CREATE USER 'sifruno_rst_0123456789abcdef'@'localhost' IDENTIFIED BY '00112233445566778899aabbccddeeff';\n" +
		"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX, LOCK TABLES, REFERENCES ON `fixtureacct\\_wp`.* TO 'sifruno_rst_0123456789abcdef'@'localhost';\n"
	if sql != want {
		t.Fatalf("restore user SQL:\n got %q\nwant %q", sql, want)
	}
	// No privilege that could create an object running as another user.
	for _, p := range []string{"ALL", "SUPER", "SET USER", "TRIGGER", "ROUTINE", "EVENT", "VIEW", "GRANT OPTION", "FILE"} {
		if strings.Contains(restorePrivileges, p) {
			t.Errorf("restore user may %s", p)
		}
	}
	if got := dropRestoreUserSQL("sifruno_rst_0123456789abcdef"); got != "DROP USER IF EXISTS 'sifruno_rst_0123456789abcdef'@'localhost';\n" {
		t.Fatalf("drop SQL %q", got)
	}
	// The broker never makes a database: a restore into one that is gone
	// is refused first.
	if strings.Contains(sql, "CREATE DATABASE") {
		t.Fatal("the restore user's SQL makes a database")
	}
	if got := databaseExistsSQL("fixtureacct_wp"); got != "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='fixtureacct_wp';\n" {
		t.Fatalf("exists SQL %q", got)
	}
	const fixtureSecret = "00112233445566778899aabbccddeeff"
	wantConfig := "[client]\nuser=sifruno_rst_0123456789abcdef\n" + "pass" + "word=" + fixtureSecret + "\nprotocol=socket\nsocket=/var/lib/mysql/mysql.sock\n"
	if got := string(restoreClientConfig("sifruno_rst_0123456789abcdef", fixtureSecret)); got != wantConfig {
		t.Fatalf("option file %q", got)
	}
}

func TestDatabaseToolArguments(t *testing.T) {
	dump := dumpArgs("fixtureacct_wp")
	if dump[0] != "--no-defaults" || !slices.Contains(dump, "--skip-triggers") || !slices.Contains(dump, "--single-transaction") || dump[len(dump)-2] != "--" || dump[len(dump)-1] != "fixtureacct_wp" {
		t.Fatalf("dump arguments %q", dump)
	}
	for _, a := range dump {
		if a == "--routines" || a == "--events" || a == "--triggers" || strings.HasPrefix(a, "--defaults") || strings.HasPrefix(a, "--password") {
			t.Fatalf("dump argument %q", a)
		}
	}
	imp := importArgs("/var/lib/sifruno-restore/op/client-fixtureacct_wp.cnf", "fixtureacct_wp")
	if !slices.Equal(imp, []string{"--defaults-file=/var/lib/sifruno-restore/op/client-fixtureacct_wp.cnf", "--binary-mode", "--batch", "--one-database", "fixtureacct_wp"}) {
		t.Fatalf("import arguments %q", imp)
	}
	if root := rootSQLArgs(); root[0] != "--no-defaults" || !slices.Contains(root, "--user=root") {
		t.Fatalf("root SQL arguments %q", root)
	}
	if got := copyArgs("/var/lib/sifruno-restore/op/files", "/home/fixtureacct"); !slices.Equal(got, []string{"-R", "-P", "--preserve=mode,timestamps,links", "--remove-destination", "-T", "--", "/var/lib/sifruno-restore/op/files", "/home/fixtureacct"}) {
		t.Fatalf("copy arguments %q", got)
	}
	obj := dbObjectsSQL("fixtureacct_wp")
	for _, table := range []string{"SCHEMATA", "VIEWS", "TRIGGERS", "ROUTINES", "EVENTS"} {
		if !strings.Contains(obj, "information_schema."+table) {
			t.Errorf("the object check misses %s", table)
		}
	}
}

func TestResticArguments(t *testing.T) {
	id := strings.Repeat("a", 32)
	got := backupArgs("/home/fixtureacct", "/state/backup/dump/"+id, id, []string{"fixtureacct_wp"})
	want := []string{"backup", "--json", "--host", "sifruno", "--tag", "sifruno,acct-" + id + ",db-fixtureacct_wp", "--one-file-system", "/home/fixtureacct", "/state/backup/dump/" + id}
	if !slices.Equal(got, want) {
		t.Fatalf("backup arguments %q", got)
	}
	if got := forgetArgs(); !slices.Equal(got, []string{"forget", "--json", "--host", "sifruno", "--keep-daily", "7", "--keep-weekly", "4", "--prune"}) {
		t.Fatalf("forget arguments %q", got)
	}
	if got := snapshotsArgs(id); !slices.Contains(got, "--no-lock") || !slices.Contains(got, "acct-"+id) {
		t.Fatalf("snapshots arguments %q", got)
	}
	if got := drillSubset(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)); got != "1/8" {
		t.Fatalf("week 48's subset %q", got)
	}
}

func TestParseSnapshots(t *testing.T) {
	id := strings.Repeat("a", 32)
	home, dumps := "/home/fixtureacct", "/state/backup/dump/"+id
	snap := func(sid, when, host string, tags, paths []string) map[string]any {
		return map[string]any{"id": sid, "time": when, "hostname": host, "tags": tags, "paths": paths, "summary": map[string]any{"total_bytes_processed": 1234, "total_files_processed": 5}}
	}
	own := []string{"sifruno", "acct-" + id, "db-fixtureacct_wp"}
	raw, _ := json.Marshal([]any{
		snap(strings.Repeat("1", 64), "2026-11-20T01:00:00Z", "sifruno", own, []string{dumps, home}),
		snap(strings.Repeat("2", 64), "2026-11-22T01:00:00Z", "sifruno", own, []string{home, dumps}),
		snap(strings.Repeat("3", 64), "2026-11-23T01:00:00Z", "sifruno", []string{"acct-" + strings.Repeat("b", 32)}, []string{home, dumps}),
		snap(strings.Repeat("4", 64), "2026-11-23T01:00:00Z", "elsewhere", own, []string{home, dumps}),
		snap(strings.Repeat("5", 64), "2026-11-23T01:00:00Z", "sifruno", own, []string{"/home/otheracct", dumps}),
		snap("short", "2026-11-23T01:00:00Z", "sifruno", own, []string{home, dumps}),
	})
	items, err := parseSnapshots(raw, id, home, dumps)
	if err != nil || len(items) != 2 || items[0].ID != strings.Repeat("2", 64) || items[1].ID != strings.Repeat("1", 64) {
		t.Fatalf("snapshots %+v %v", items, err)
	}
	if items[0].Bytes != 1234 || items[0].Files != 5 || !slices.Equal(items[0].Databases, []string{"fixtureacct_wp"}) {
		t.Fatalf("snapshot %+v", items[0])
	}
	if _, err := parseSnapshots([]byte("not json"), id, home, dumps); !errors.Is(err, ErrBackupFailed) {
		t.Fatalf("unreadable list: %v", err)
	}
}

func TestParseResticOutput(t *testing.T) {
	out := []byte(`{"message_type":"status","percent_done":0.5}` + "\n" + `{"message_type":"summary","snapshot_id":"` + strings.Repeat("c", 64) + `","backup_start":"2026-11-24T01:00:00Z","total_files_processed":3,"total_bytes_processed":37}` + "\n")
	s, ok := parseBackupSummary(out)
	if !ok || s.SnapshotID != strings.Repeat("c", 64) || s.TotalBytes != 37 {
		t.Fatalf("summary %+v %v", s, ok)
	}
	if _, ok := parseBackupSummary([]byte(`{"message_type":"summary","snapshot_id":"x"}`)); ok {
		t.Fatal("a summary without a snapshot id must not count")
	}
	if n := parsePruneRemoved([]byte(`[{"remove":[{},{}]},{"remove":null},{"remove":[{}]}]`)); n != 3 {
		t.Fatalf("removed %d", n)
	}
}

// fakeBackup is a backupEngine that records what the store asked for.
type fakeBackup struct {
	mu          sync.Mutex
	store       *store
	backups     []string
	restores    []RestoreInput
	cleaned     []string
	failCleanup bool
	failRestore error
	drill       DrillResult
	drillErr    error
	gate        chan struct{}
	started     chan struct{}
	seen        []backupLeftover // leftovers recorded when Restore ran
	initialized bool
}

func (f *fakeBackup) Status(context.Context) (string, bool, error) {
	return "ssh-ed25519 AAAA sifruno-backup", true, nil
}
func (f *fakeBackup) Password() (string, error) { return "repository-password-fixture", nil }
func (f *fakeBackup) SetTarget(context.Context, BackupTarget) (bool, error) {
	f.initialized = !f.initialized
	return f.initialized, nil
}
func (f *fakeBackup) Backup(_ context.Context, _ BackupTarget, r record, dbs []string) (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.backups = append(f.backups, r.Account.ID+":"+strings.Join(dbs, ","))
	return Snapshot{ID: strings.Repeat("d", 64), Databases: dbs}, nil
}
func (f *fakeBackup) Snapshots(context.Context, BackupTarget, record) ([]Snapshot, error) {
	return []Snapshot{{ID: strings.Repeat("d", 64)}}, nil
}
func (f *fakeBackup) Restore(_ context.Context, _ BackupTarget, _ record, in RestoreInput, _ backupLeftover) error {
	items, _ := f.store.leftovers()
	f.mu.Lock()
	f.seen = items
	f.restores = append(f.restores, in)
	f.mu.Unlock()
	if f.started != nil {
		f.started <- struct{}{}
		<-f.gate
	}
	return f.failRestore
}
func (f *fakeBackup) Drill(_ context.Context, _ BackupTarget, r record, _ backupLeftover, now time.Time) (DrillResult, error) {
	if f.drillErr != nil {
		return DrillResult{}, f.drillErr
	}
	d := f.drill
	d.AccountID, d.CheckedAt = r.Account.ID, now
	return d, nil
}
func (f *fakeBackup) Prune(context.Context, BackupTarget) (PruneResult, error) {
	return PruneResult{Removed: 2}, nil
}
func (f *fakeBackup) Cleanup(_ context.Context, l backupLeftover) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCleanup {
		return ErrUnavailable
	}
	f.cleaned = append(f.cleaned, l.Op)
	return nil
}

func backupStore(t *testing.T) (*store, *fakeBackup) {
	t.Helper()
	s, _, _ := setupStore(t)
	f := &fakeBackup{store: s}
	s.backup = f
	return s, f
}

func configureTarget(t *testing.T, s *store) BackupTargetResult {
	t.Helper()
	got, err := s.setBackupTarget(context.Background(), targetInput(), "test operator")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func restoreInput(a Account) RestoreInput {
	return RestoreInput{ExpectedRevision: a.Revision, Snapshot: strings.Repeat("d", 64), Files: true, Databases: []string{a.Username + "_wp"}, Reason: "Restore the site"}
}

// The repository password stays available until the admin confirms saving
// it, so a dropped answer does not lose it; after that no answer carries it.
func TestBackupPasswordStaysUntilSaved(t *testing.T) {
	s, _ := backupStore(t)
	ctx := context.Background()
	why := BackupPasswordInput{Reason: "Backup storage page"}
	status, err := s.backupStatus(ctx)
	if err != nil || status.Configured || status.Target != nil || !status.Ready || status.PublicKey == "" || status.PasswordSaved {
		t.Fatalf("status before a target: %+v %v", status, err)
	}
	var failed *BackupError
	if _, err := s.showBackupPassword(ctx, why, "test operator"); !errors.As(err, &failed) || failed.Step != "target" {
		t.Fatalf("the password before a target: %v", err)
	}
	if _, err := s.confirmBackupPassword(ctx, why, "test operator"); !errors.As(err, &failed) || failed.Step != "target" {
		t.Fatalf("a confirmation before a target: %v", err)
	}
	first := configureTarget(t, s)
	if first.Password != "repository-password-fixture" || !first.Initialized || !first.Status.Configured || first.Status.Target.Host != "backup.example.test" || first.Status.PasswordSaved {
		t.Fatalf("first target: %+v", first)
	}
	// The answer was lost: the admin can still read the password, and
	// saving the target again shows it again.
	got, err := s.showBackupPassword(ctx, why, "test operator")
	if err != nil || got.Password != "repository-password-fixture" {
		t.Fatalf("the password again: %+v %v", got, err)
	}
	if second := configureTarget(t, s); second.Password != "repository-password-fixture" {
		t.Fatal("an unconfirmed password must be shown again")
	}
	status, err = s.backupStatus(ctx)
	raw, _ := json.Marshal(status)
	if err != nil || !status.Configured || status.PasswordSaved || strings.Contains(string(raw), "repository-password-fixture") {
		t.Fatalf("status before the confirmation: %s %v", raw, err)
	}
	if _, err := s.confirmBackupPassword(ctx, BackupPasswordInput{Reason: "a\nb"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an invalid reason: %v", err)
	}
	status, err = s.confirmBackupPassword(ctx, why, "test operator")
	if err != nil || !status.PasswordSaved || !status.Configured {
		t.Fatalf("confirm: %+v %v", status, err)
	}
	if status, err = s.confirmBackupPassword(ctx, why, "test operator"); err != nil || !status.PasswordSaved {
		t.Fatalf("a second confirmation: %+v %v", status, err)
	}
	if _, err := s.showBackupPassword(ctx, why, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("the password after the confirmation: %v", err)
	}
	third := configureTarget(t, s)
	if third.Password != "" || !third.Status.PasswordSaved {
		t.Fatalf("a target change after the confirmation: %+v", third)
	}
	status, err = s.backupStatus(ctx)
	raw, _ = json.Marshal(status)
	if err != nil || !status.PasswordSaved || strings.Contains(string(raw), "repository-password-fixture") {
		t.Fatalf("status after the confirmation: %s %v", raw, err)
	}
	// A broker that showed the password once under the old rule stored
	// password_shown true: that counts as saved.
	var stored map[string]any
	s.readBackup("target", &stored)
	if stored["password_shown"] != true {
		t.Fatalf("stored target %v", stored)
	}
	bad := targetInput()
	bad.Host = "-oProxyCommand=x"
	if _, err := s.setBackupTarget(ctx, bad, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an invalid target: %v", err)
	}
}

// The status never waits for a running backup, and a target change does
// not queue behind one: it is refused at once.
func TestBackupStatusAndTargetDoNotWaitForABackup(t *testing.T) {
	s, _ := backupStore(t)
	configureTarget(t, s)
	s.backupMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := s.backupStatus(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the status waited for the backup lock")
	}
	if _, err := s.setBackupTarget(context.Background(), targetInput(), "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a target change during a backup: %v", err)
	}
	s.backupMu.Unlock()
}

func TestRestoreArgumentsLeaveSELinuxLabels(t *testing.T) {
	if got := restoreArgs("abc:/home/fixtureacct", "/var/lib/sifruno-restore/op/files", false); !slices.Equal(got, []string{"restore", "--json", "--sparse", "--exclude-xattr", "security.selinux", "abc:/home/fixtureacct", "--target", "/var/lib/sifruno-restore/op/files"}) {
		t.Fatalf("restore arguments %q", got)
	}
	if got := restoreArgs("abc", "/x/all", true); !slices.Contains(got, "--verify") || !slices.Contains(got, "--sparse") {
		t.Fatalf("drill restore arguments %q", got)
	}
}

func TestDiskSpaceRules(t *testing.T) {
	const gib = 1 << 30
	for _, c := range []struct{ total, margin uint64 }{{10 * gib, 2 * gib}, {40 * gib, 2 * gib}, {100 * gib, 5 * gib}, {2000 * gib, 100 * gib}} {
		if got := freeMargin(c.total); got != c.margin {
			t.Errorf("margin of %d GiB: %d", c.total/gib, got/gib)
		}
	}
	if roomLeft(1*gib, 100*gib) != 0 || roomLeft(6*gib, 100*gib) != gib {
		t.Fatal("room beyond the margin")
	}
	if got := restoreNeed(1000, 10, 4096); got != 1000+40960 {
		t.Fatalf("need %d", got)
	}
	if restoreNeed(^uint64(0)-5, 1, 4096) != ^uint64(0) || restoreNeed(1, ^uint64(0)/2, 4096) != ^uint64(0) {
		t.Fatal("an estimate that overflows must not fit")
	}
	if spaceForRestore(gib, 7*gib, 100*gib) != nil {
		t.Fatal("1 GiB with 2 GiB beyond the margin must fit")
	}
	err := spaceForRestore(3*gib, 7*gib, 100*gib)
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "space" || failed.Detail != "The backup needs up to 3.0 GiB of disk to restore, and the server has 7.0 GiB free, of which 5.0 GiB must stay free for the server itself. Free up disk space on the server, then try again." {
		t.Fatalf("refusal %v", err)
	}
	if size, entries, ok := parseRestoreSize([]byte(`{"total_size":1234,"total_file_count":7,"snapshots_count":1}`)); !ok || size != 1234 || entries != 7 {
		t.Fatalf("stats %d %d %v", size, entries, ok)
	}
	if size, entries, ok := parseRestoreSize([]byte(`{"total_size":0,"snapshots_count":1}`)); !ok || size != 0 || entries != 0 {
		t.Fatal("restic leaves out a zero count")
	}
	for _, bad := range []string{`{"snapshots_count":1}`, `{"total_size":-1,"total_file_count":1}`, `not json`} {
		if _, _, ok := parseRestoreSize([]byte(bad)); ok {
			t.Errorf("%s: accepted", bad)
		}
	}
	for n, want := range map[uint64]string{0: "0 bytes", 1023: "1023 bytes", 1536: "1.5 KiB", 300 << 20: "300.0 MiB", maxDumpBytes: "32.0 GiB"} {
		if got := byteSize(n); got != want {
			t.Errorf("%d: %q", n, got)
		}
	}
}

func TestBackupNeedsATargetAndJournalsNothing(t *testing.T) {
	s, f := backupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	before := recordFor(t, s, a.ID)
	_, err := s.backupAccount(ctx, a.ID, BackupInput{Databases: []string{"fixtureacct_wp"}, Reason: "Nightly backup"}, "scheduler")
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "target" {
		t.Fatalf("backup without a target: %v", err)
	}
	configureTarget(t, s)
	got, err := s.backupAccount(ctx, a.ID, BackupInput{Databases: []string{"fixtureacct_wp"}, Reason: "Nightly backup"}, "scheduler")
	if err != nil || got.ID == "" || !slices.Equal(f.backups, []string{a.ID + ":fixtureacct_wp"}) {
		t.Fatalf("backup: %+v %v %v", got, err, f.backups)
	}
	if _, err := s.backupAccount(ctx, a.ID, BackupInput{Databases: []string{"otheracct_wp"}, Reason: "Nightly backup"}, "scheduler"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another account's database: %v", err)
	}
	if _, err := s.backupAccount(ctx, strings.Repeat("f", 32), BackupInput{Reason: "Nightly backup"}, "scheduler"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
	if after := recordFor(t, s, a.ID); after.HistorySequence != before.HistorySequence || after.Account != before.Account {
		t.Fatal("a backup wrote to the account's journal")
	}
	items, err := s.listBackups(ctx, a.ID)
	if err != nil || len(items) != 1 {
		t.Fatalf("list: %v %v", items, err)
	}
	s.backup = nil
	if _, err := s.backupAccount(ctx, a.ID, BackupInput{Reason: "Nightly backup"}, "scheduler"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("backups off: %v", err)
	}
}

// The restore's staging folder and temporary database users are recorded
// before the engine makes them and cleared once removed; what cannot be
// removed stays recorded and is removed before the next operation.
func TestRestoreRecordsItsLeftoversFirst(t *testing.T) {
	s, f := backupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	configureTarget(t, s)
	before := recordFor(t, s, a.ID)
	got, err := s.restoreAccount(ctx, a.ID, restoreInput(a), "test operator")
	if err != nil || !got.Files || !slices.Equal(got.Databases, []string{"fixtureacct_wp"}) {
		t.Fatalf("restore: %+v %v", got, err)
	}
	if len(f.seen) != 1 || !f.seen[0].valid() || !restoreUserPattern.MatchString(f.seen[0].Users["fixtureacct_wp"]) {
		t.Fatalf("leftovers when the engine ran: %+v", f.seen)
	}
	if items, _ := s.leftovers(); len(items) != 0 || !slices.Equal(f.cleaned, []string{f.seen[0].Op}) {
		t.Fatalf("after the restore: %+v cleaned %v", items, f.cleaned)
	}
	if after := recordFor(t, s, a.ID); after.HistorySequence != before.HistorySequence || len(s.installing) != 0 {
		t.Fatal("a restore journaled or left the account busy")
	}
	// A failed restore whose cleanup also fails keeps its entry.
	f.failRestore, f.failCleanup = &BackupError{Step: "import", Detail: "ERROR 1064"}, true
	_, err = s.restoreAccount(ctx, a.ID, restoreInput(a), "test operator")
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "import" {
		t.Fatalf("failed restore: %v", err)
	}
	kept, _ := s.leftovers()
	if len(kept) != 1 {
		t.Fatalf("an uncleaned restore must stay recorded: %+v", kept)
	}
	// The next operation removes it first.
	f.failRestore, f.failCleanup = nil, false
	if _, err := s.backupAccount(ctx, a.ID, BackupInput{Reason: "Nightly backup"}, "scheduler"); err != nil {
		t.Fatal(err)
	}
	if items, _ := s.leftovers(); len(items) != 0 || !slices.Contains(f.cleaned, kept[0].Op) {
		t.Fatalf("the next operation did not clean up: %+v %v", items, f.cleaned)
	}
}

// At start the broker removes what a restore or drill interrupted by a
// crash left; what it cannot remove yet stays listed and is not an error
// that stops the broker.
func TestBrokerStartCleansBackupLeftovers(t *testing.T) {
	s, f := backupStore(t)
	ctx := context.Background()
	l := backupLeftover{Op: strings.Repeat("b", 32), Users: map[string]string{"fixtureacct_wp": "sifruno_rst_0123456789abcdef"}}
	if err := s.recordLeftover(l); err != nil {
		t.Fatal(err)
	}
	f.failCleanup = true
	if err := s.cleanBackupLeftoversAtStart(ctx); err == nil {
		t.Fatal("a leftover that could not be removed must be reported")
	}
	if items, _ := s.leftovers(); len(items) != 1 {
		t.Fatalf("the leftover must stay listed for the next operation: %+v", items)
	}
	f.failCleanup = false
	if err := s.cleanBackupLeftoversAtStart(ctx); err != nil {
		t.Fatal(err)
	}
	if items, _ := s.leftovers(); len(items) != 0 || !slices.Equal(f.cleaned, []string{l.Op}) {
		t.Fatalf("after a clean start: %+v cleaned %v", items, f.cleaned)
	}
	s.backup = nil
	if err := s.cleanBackupLeftoversAtStart(ctx); err != nil {
		t.Fatalf("backups off: %v", err)
	}
}

func TestRestoreRefusals(t *testing.T) {
	s, f := backupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	configureTarget(t, s)
	for name, change := range map[string]func(*RestoreInput){
		"stale revision": func(in *RestoreInput) { in.ExpectedRevision++ },
	} {
		in := restoreInput(a)
		change(&in)
		if _, err := s.restoreAccount(ctx, a.ID, in, "test operator"); !errors.Is(err, ErrConflict) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, change := range map[string]func(*RestoreInput){
		"another account's database": func(in *RestoreInput) { in.Databases = []string{"otheracct_wp"} },
		"short snapshot id":          func(in *RestoreInput) { in.Snapshot = "dddddddd" },
		"nothing to restore":         func(in *RestoreInput) { in.Files, in.Databases = false, nil },
		"no revision":                func(in *RestoreInput) { in.ExpectedRevision = 0 },
	} {
		in := restoreInput(a)
		change(&in)
		if _, err := s.restoreAccount(ctx, a.ID, in, "test operator"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.restores) != 0 {
		t.Fatal("a refused restore reached the engine")
	}
}

// A restore runs outside the broker lock but holds its account busy: the
// copy and the import run as the site user.
func TestRestoreHoldsTheAccountBusy(t *testing.T) {
	s, f := backupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	configureTarget(t, s)
	f.started, f.gate = make(chan struct{}, 1), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.restoreAccount(ctx, a.ID, restoreInput(a), "test operator")
		done <- err
	}()
	<-f.started
	if _, err := s.list(ctx); err != nil {
		t.Fatalf("list during a restore: %v", err)
	}
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete during a restore: %v", err)
	}
	if _, err := s.setState(ctx, a.ID, StateInput{State: "suspended", ExpectedRevision: a.Revision, Reason: "Pause"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("suspend during a restore: %v", err)
	}
	if _, err := s.restoreAccount(ctx, a.ID, restoreInput(a), "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second restore during the first: %v", err)
	}
	close(f.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatalf("delete after the restore: %v", err)
	}
}

func TestDrillReportsAFailedStepAsAResult(t *testing.T) {
	s, f := backupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	got, err := s.drillAccount(ctx, a.ID, DrillInput{Reason: "Weekly restore drill"}, "scheduler")
	if err != nil || got.Passed || got.Step != "target" || got.AccountID != a.ID {
		t.Fatalf("drill without a target: %+v %v", got, err)
	}
	configureTarget(t, s)
	f.drill = DrillResult{Snapshot: strings.Repeat("d", 64), Passed: true, Files: 12, Subset: "1/8"}
	got, err = s.drillAccount(ctx, a.ID, DrillInput{Reason: "Weekly restore drill"}, "scheduler")
	if err != nil || !got.Passed || got.Files != 12 || got.CheckedAt.IsZero() {
		t.Fatalf("drill: %+v %v", got, err)
	}
	f.drillErr = &BackupError{Step: "compare", Detail: "/home/fixtureacct/public_html/index.php was not restored"}
	got, err = s.drillAccount(ctx, a.ID, DrillInput{Reason: "Weekly restore drill"}, "scheduler")
	if err != nil || got.Passed || got.Step != "compare" || !strings.Contains(got.Detail, "index.php") {
		t.Fatalf("failed drill: %+v %v", got, err)
	}
	if items, _ := s.leftovers(); len(items) != 0 {
		t.Fatalf("a drill left its staging recorded: %+v", items)
	}
}

func TestBackupHTTPContract(t *testing.T) {
	s, f := backupStore(t)
	a := createFixture(t, s)
	h := handler(s)
	call := func(method, path, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://unix"+path, strings.NewReader(payload))
		if payload != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	target, _ := json.Marshal(map[string]any{"actor": "test operator", "input": targetInput()})
	if rec := call("POST", "/v1/backup/target", strings.Replace(string(target), `"host"`, `"command":"x","host"`, 1)); rec.Code != 400 {
		t.Fatalf("an unknown key must be refused: %d", rec.Code)
	}
	rec := call("POST", "/v1/backup/target", string(target))
	var result BackupTargetResult
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Password == "" {
		t.Fatalf("target over HTTP: %d %s", rec.Code, rec.Body)
	}
	if rec := call("GET", "/v1/backup", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), result.Password) || !strings.Contains(rec.Body.String(), `"password_saved":false`) {
		t.Fatalf("status over HTTP: %d %s", rec.Code, rec.Body)
	}
	reason, _ := json.Marshal(map[string]any{"actor": "test operator", "input": BackupPasswordInput{Reason: "Backup storage page"}})
	if rec := call("POST", "/v1/backup/password", strings.Replace(string(reason), `"reason"`, `"show":true,"reason"`, 1)); rec.Code != 400 {
		t.Fatalf("an unknown key must be refused: %d", rec.Code)
	}
	if rec := call("POST", "/v1/backup/password", string(reason)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"password":"`+result.Password+`"`) {
		t.Fatalf("the password again over HTTP: %d %s", rec.Code, rec.Body)
	}
	if rec := call("POST", "/v1/backup/password-saved", string(reason)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"password_saved":true`) || strings.Contains(rec.Body.String(), result.Password) {
		t.Fatalf("confirm over HTTP: %d %s", rec.Code, rec.Body)
	}
	if rec := call("POST", "/v1/backup/password", string(reason)); rec.Code != 409 || strings.Contains(rec.Body.String(), result.Password) {
		t.Fatalf("the password after the confirmation over HTTP: %d %s", rec.Code, rec.Body)
	}
	backup, _ := json.Marshal(map[string]any{"actor": "scheduler", "input": BackupInput{Databases: []string{"fixtureacct_wp"}, Reason: "Nightly backup"}})
	if rec := call("POST", "/v1/accounts/"+a.ID+"/backup", string(backup)); rec.Code != 200 {
		t.Fatalf("backup over HTTP: %d %s", rec.Code, rec.Body)
	}
	if rec := call("GET", "/v1/accounts/"+a.ID+"/backups", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"items":[{"id":"`) {
		t.Fatalf("list over HTTP: %d %s", rec.Code, rec.Body)
	}
	f.failRestore = &BackupError{Step: "copy", Detail: "cp: cannot create regular file"}
	restore, _ := json.Marshal(map[string]any{"actor": "test operator", "input": restoreInput(a)})
	rec = call("POST", "/v1/accounts/"+a.ID+"/restore", string(restore))
	var failure struct{ Error, Step, Detail string }
	if rec.Code != 422 || json.Unmarshal(rec.Body.Bytes(), &failure) != nil || failure.Error != "backup_failed" || failure.Step != "copy" {
		t.Fatalf("failed restore over HTTP: %d %s", rec.Code, rec.Body)
	}
	drill, _ := json.Marshal(map[string]any{"actor": "test operator", "input": DrillInput{Reason: "Restore drill"}})
	if rec := call("POST", "/v1/accounts/"+a.ID+"/drill", string(drill)); rec.Code != 200 {
		t.Fatalf("drill over HTTP: %d %s", rec.Code, rec.Body)
	}
	prune, _ := json.Marshal(map[string]any{"actor": "scheduler", "input": PruneInput{Reason: "Weekly prune"}})
	if rec := call("POST", "/v1/backup/prune", string(prune)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"removed":2`) {
		t.Fatalf("prune over HTTP: %d %s", rec.Code, rec.Body)
	}
}
