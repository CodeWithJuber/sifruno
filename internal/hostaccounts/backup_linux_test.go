//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/dbhost"
)

func TestResticPin(t *testing.T) {
	if resticSHA256 != "c109579d3a1a4d26094bef5400ac5645fceb1043414c05f51b8fb48272001c72" {
		t.Fatal("the pin must be restic 0.20.0's decompressed linux/amd64 binary")
	}
	if pinnedSHA256(strings.NewReader("not restic"), maxRestic, resticSHA256) == nil {
		t.Fatal("other bytes passed the pin")
	}
	// sha256("abc"), and a reader longer than the bound.
	if pinnedSHA256(strings.NewReader("abc"), 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != nil {
		t.Fatal("matching bytes failed the pin")
	}
	if pinnedSHA256(strings.NewReader("abcd"), 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == nil {
		t.Fatal("bytes past the bound passed the pin")
	}
	if _, err := os.Lstat(resticPath); errors.Is(err, os.ErrNotExist) && checkRestic() == nil {
		t.Fatal("a missing restic passed the check")
	}
}

// The broker keeps its own copies of dbhost's rules so the client builds on
// every system; they must stay the same rules.
func TestDatabaseRulesMatchDBHost(t *testing.T) {
	for _, name := range []string{"fixtureacct_wp", "a", "A_b_9", "x-y", "x.y", "x y", "x`y", "", strings.Repeat("d", 64), strings.Repeat("d", 65), "ü", "x%", `x\y`} {
		if validDatabaseName(name) != (dbhost.ValidateIdentifier("database", name, dbhost.MaxDatabaseLen) == nil) {
			t.Errorf("%q: the rules differ", name)
		}
	}
	for _, name := range []string{"fixtureacct_wp", "a%b", `a\b`, "a`b", "plain"} {
		if grantDatabase(name) != dbhost.GrantDatabase(name) {
			t.Errorf("%q: grant names differ: %s vs %s", name, grantDatabase(name), dbhost.GrantDatabase(name))
		}
	}
}

type ranCommand struct {
	path     string
	args     []string
	env      []string
	uid, gid int
	stdin    string
}

// fakeTools stands in for restic, the MariaDB tools and cp.
type fakeTools struct {
	mu        sync.Mutex
	t         *testing.T
	ran       []ranCommand
	sql       []string
	snapshots string
	failSQL   string // a statement prefix that fails
	missingDB bool   // the database a restore names is gone
	failCopy  bool
	failLoad  bool
	catConfig int
	restored  map[string]string // file name -> content, written by restic restore
	dump      string
	lsNodes   []map[string]any
	// stats is what restic stats --mode restore-size prints.
	stats     string
	duringRun func(c backupCommand)
}

func (f *fakeTools) run(_ context.Context, c backupCommand) ([]byte, int, error) {
	var stdin string
	if c.stdin != nil {
		b, _ := io.ReadAll(c.stdin)
		stdin = string(b)
	}
	f.mu.Lock()
	f.ran = append(f.ran, ranCommand{path: c.path, args: slices.Clone(c.args), env: slices.Clone(c.env), uid: c.uid, gid: c.gid, stdin: stdin})
	f.mu.Unlock()
	if f.duringRun != nil {
		f.duringRun(c)
	}
	switch c.path {
	case mariadbPath:
		if c.uid == 0 {
			f.sql = append(f.sql, stdin)
			if f.failSQL != "" && strings.HasPrefix(stdin, f.failSQL) {
				return []byte("ERROR 1044 (42000): Access denied"), 1, nil
			}
			if strings.HasPrefix(stdin, "SELECT COUNT(*) FROM information_schema.SCHEMATA") {
				if f.missingDB {
					return []byte("0\n"), 0, nil
				}
				return []byte("1\n"), 0, nil
			}
			return nil, 0, nil
		}
		if f.failLoad {
			return []byte("ERROR 1064 (42000) at line 3"), 1, nil
		}
		return nil, 0, nil
	case mariadbDumpPath:
		io.WriteString(c.stdout, f.dump)
		return nil, 0, nil
	case cpPath:
		if f.failCopy {
			return []byte("cp: cannot create regular file"), 1, nil
		}
		return nil, 0, nil
	case resticPath:
		return f.restic(c)
	}
	f.t.Errorf("unexpected program %s", c.path)
	return nil, 1, nil
}

func (f *fakeTools) restic(c backupCommand) ([]byte, int, error) {
	args := c.args[8:] // after --repo, --option, --cache-dir and --retry-lock
	switch args[0] {
	case "cat":
		return []byte("Fatal: repository does not exist"), f.catConfig, nil
	case "init":
		return nil, 0, nil
	case "snapshots":
		io.WriteString(c.stdout, f.snapshots)
		return nil, 0, nil
	case "backup":
		return []byte(`{"message_type":"summary","snapshot_id":"` + strings.Repeat("e", 64) + `","backup_start":"2026-11-24T01:00:00Z","total_files_processed":2,"total_bytes_processed":99}`), 0, nil
	case "restore":
		target := args[slices.Index(args, "--target")+1]
		if err := os.MkdirAll(target, 0700); err != nil {
			return nil, 1, nil
		}
		for name, content := range f.restored {
			p := filepath.Join(target, name)
			os.MkdirAll(filepath.Dir(p), 0700)
			os.WriteFile(p, []byte(content), 0600)
		}
		return []byte(`{"message_type":"summary"}`), 0, nil
	case "ls":
		for _, node := range f.lsNodes {
			b, _ := json.Marshal(node)
			c.stdout.Write(append(b, '\n'))
		}
		return nil, 0, nil
	case "stats":
		io.WriteString(c.stdout, f.stats)
		return nil, 0, nil
	case "check":
		return []byte(`{"message_type":"summary","num_errors":0}`), 0, nil
	case "unlock":
		return nil, 0, nil
	case "forget":
		io.WriteString(c.stdout, `[{"remove":[{}]}]`)
		return nil, 0, nil
	}
	return nil, 1, nil
}

type chownCall struct {
	name     string
	uid, gid int
}

func testEngine(t *testing.T) (*resticEngine, *fakeTools, *[]chownCall) {
	t.Helper()
	base := t.TempDir()
	tools := &fakeTools{t: t, catConfig: 10, restored: map[string]string{}, stats: `{"total_size":1048576,"total_file_count":100,"snapshots_count":1}`}
	calls := &[]chownCall{}
	var mu sync.Mutex
	e := &resticEngine{dir: base + "/backup", stage: base + "/restore", run: tools.run, tools: func() error { return nil }, owner: os.Getuid(),
		chown: func(f *os.File, uid, gid int) error {
			mu.Lock()
			defer mu.Unlock()
			*calls = append(*calls, chownCall{filepath.Base(f.Name()), uid, gid})
			return nil
		},
		// A roomy disk unless a test says otherwise.
		space: func(string) (uint64, uint64, uint64, error) { return 500 << 30, 1 << 40, 4096, nil }}
	e.prepare = func() error {
		for _, d := range []string{e.dir, e.dir + "/cache", e.dir + "/tmp", e.dir + "/dump"} {
			if err := os.MkdirAll(d, 0700); err != nil {
				return err
			}
		}
		return os.MkdirAll(e.stage, 0711)
	}
	return e, tools, calls
}

func engineRecord(base string) record {
	return record{Account: Account{ID: strings.Repeat("a", 32), Username: "fixtureacct", Home: base + "/home/fixtureacct", PublicHTML: base + "/home/fixtureacct/public_html", UID: 20000, GID: 20000}}
}

func engineTarget(t *testing.T) BackupTarget {
	target, ok := validBackupTarget(targetInput(), "test operator")
	if !ok {
		t.Fatal("fixture target refused")
	}
	return target
}

func TestStatusMakesTheKeyAndPasswordOnce(t *testing.T) {
	e, _, _ := testEngine(t)
	ctx := context.Background()
	key, ready, err := e.Status(ctx)
	if err != nil || !ready || !strings.HasPrefix(key, "ssh-ed25519 ") || !strings.HasSuffix(key, " sifruno-backup") {
		t.Fatalf("status: %q %v %v", key, ready, err)
	}
	if _, _, ok := normalizeSSHKeys([]string{key}); !ok {
		t.Fatal("the public key is not one a storage server's authorized_keys accepts")
	}
	again, _, err := e.Status(ctx)
	if err != nil || again != key {
		t.Fatal("a second status made a new key")
	}
	password, err := e.Password()
	if err != nil || !repositoryPasswordPattern.MatchString(password) {
		t.Fatalf("password: %v", err)
	}
	for _, name := range []string{"ssh_key", "password"} {
		info, err := os.Lstat(filepath.Join(e.dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("%s: %v %v", name, info.Mode(), err)
		}
	}
	os.Chmod(filepath.Join(e.dir, "password"), 0644)
	if _, err := e.Password(); err == nil {
		t.Fatal("a password file others can read must be refused")
	}
}

func TestSetTargetKeepsTheOldHostKeysUntilConfirmed(t *testing.T) {
	e, tools, _ := testEngine(t)
	ctx := context.Background()
	target := engineTarget(t)
	if _, _, err := e.Status(ctx); err != nil {
		t.Fatal(err)
	}
	tools.catConfig = 12
	_, err := e.SetTarget(ctx, target)
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "password" {
		t.Fatalf("a repository the password does not open: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(e.dir, "known_hosts")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused target wrote its host keys")
	}
	tools.catConfig = 10
	initialized, err := e.SetTarget(ctx, target)
	if err != nil || !initialized {
		t.Fatalf("a new repository: %v %v", initialized, err)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, "known_hosts"))
	if err != nil || string(b) != "sifruno-backup-target "+fixtureHostKey+"\n" {
		t.Fatalf("known_hosts %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(e.dir, "known_hosts.next")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the candidate file was left behind")
	}
	// The trial ran against the candidate file, never the live one.
	for _, c := range tools.ran {
		if c.path == resticPath && !strings.Contains(strings.Join(c.args, " "), "UserKnownHostsFile="+e.dir+"/known_hosts.next ") {
			t.Fatalf("restic tried the target with %q", c.args)
		}
	}
	tools.catConfig = 0
	if initialized, err = e.SetTarget(ctx, target); err != nil || initialized {
		t.Fatalf("an existing repository: %v %v", initialized, err)
	}
}

func TestBackupDumpsAndNoSecretInAnyArgument(t *testing.T) {
	e, tools, _ := testEngine(t)
	ctx := context.Background()
	r := engineRecord(filepath.Dir(e.dir))
	if _, _, err := e.Status(ctx); err != nil {
		t.Fatal(err)
	}
	password, _ := e.Password()
	tools.dump = "CREATE TABLE wp_options (a int);\n"
	var dumped string
	tools.duringRun = func(c backupCommand) {
		if c.path == resticPath && c.args[8] == "backup" {
			b, _ := os.ReadFile(dumpDir(e.dir, r.Account.ID) + "/fixtureacct_wp.sql")
			dumped = string(b)
		}
	}
	snap, err := e.Backup(ctx, engineTarget(t), r, []string{"fixtureacct_wp"})
	if err != nil || snap.ID != strings.Repeat("e", 64) || snap.Bytes != 99 || !slices.Equal(snap.Databases, []string{"fixtureacct_wp"}) {
		t.Fatalf("backup: %+v %v", snap, err)
	}
	if dumped != tools.dump {
		t.Fatalf("restic did not get the dump: %q", dumped)
	}
	if _, err := os.Lstat(dumpDir(e.dir, r.Account.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the plain dump outlived the backup")
	}
	for _, c := range tools.ran {
		if c.uid != 0 {
			t.Fatalf("a backup ran %s as a site user", c.path)
		}
		if strings.Contains(strings.Join(c.args, " "), password) || strings.Contains(strings.Join(c.env, " "), password) {
			t.Fatalf("%s got the repository password in its arguments or environment", c.path)
		}
	}
	if len(tools.sql) != 1 || !strings.Contains(tools.sql[0], "information_schema.TRIGGERS") {
		t.Fatalf("the database was not checked first: %q", tools.sql)
	}
	// A database with a trigger is refused before anything is dumped.
	tools.ran = nil
	e.run = func(ctx context.Context, c backupCommand) ([]byte, int, error) {
		if c.path == mariadbPath {
			return []byte("trigger\nview\ntrigger\n"), 0, nil
		}
		return tools.run(ctx, c)
	}
	_, err = e.Backup(ctx, engineTarget(t), r, []string{"fixtureacct_wp"})
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "database" || !strings.Contains(failed.Detail, "(trigger, view)") || len(tools.ran) != 0 {
		t.Fatalf("a database with a trigger: %v %+v", err, tools.ran)
	}
}

func restoreSnapshots(r record, dir string) string {
	raw, _ := json.Marshal([]map[string]any{{"id": strings.Repeat("d", 64), "time": "2026-11-23T01:00:00Z", "hostname": "sifruno",
		"tags": []string{"sifruno", "acct-" + r.Account.ID, "db-fixtureacct_wp"}, "paths": []string{r.Account.Home, dumpDir(dir, r.Account.ID)}}})
	return string(raw)
}

func engineLeftover() backupLeftover {
	return backupLeftover{Op: strings.Repeat("b", 32), Users: map[string]string{"fixtureacct_wp": "sifruno_rst_0123456789abcdef"}}
}

// Root restores into its own staging folder, then opens it to the site's
// group only; the copy and the import run as the site user, and the
// temporary database user exists only around the import.
func TestRestoreStagesAndRunsAsTheSiteUser(t *testing.T) {
	e, tools, calls := testEngine(t)
	ctx := context.Background()
	r := engineRecord(filepath.Dir(e.dir))
	tools.snapshots = restoreSnapshots(r, e.dir)
	tools.restored = map[string]string{"public_html/index.php": "<?php echo 'hi';", "fixtureacct_wp.sql": "CREATE TABLE t (a int);\n"}
	l := engineLeftover()
	stagePath := filepath.Join(e.stage, l.Op)
	var stagedMode, filesMode os.FileMode
	var cnfMode os.FileMode
	var cnfText string
	tools.duringRun = func(c backupCommand) {
		if c.path == cpPath {
			info, _ := os.Lstat(stagePath)
			stagedMode = info.Mode().Perm()
			info, _ = os.Lstat(stagePath + "/files")
			filesMode = info.Mode().Perm()
		}
		if c.path == mariadbPath && c.uid != 0 {
			cnf := strings.TrimPrefix(c.args[0], "--defaults-file=")
			info, err := os.Lstat(cnf)
			if err == nil {
				cnfMode = info.Mode().Perm()
				b, _ := os.ReadFile(cnf)
				cnfText = string(b)
			}
		}
	}
	in := RestoreInput{ExpectedRevision: 1, Snapshot: strings.Repeat("d", 64), Files: true, Databases: []string{"fixtureacct_wp"}, Reason: "Restore"}
	if err := e.Restore(ctx, engineTarget(t), r, in, l); err != nil {
		t.Fatal(err)
	}
	// restic ran as root, into the staging folder; nothing else did.
	var asSite []ranCommand
	for _, c := range tools.ran {
		if c.uid != 0 {
			asSite = append(asSite, c)
		}
	}
	if len(asSite) != 2 {
		t.Fatalf("site-user commands: %+v", asSite)
	}
	cp, load := asSite[0], asSite[1]
	if cp.path != cpPath || cp.uid != 20000 || cp.gid != 20000 || !slices.Equal(cp.args, copyArgs(stagePath+"/files", r.Account.Home)) {
		t.Fatalf("copy: %+v", cp)
	}
	if load.path != mariadbPath || load.uid != 20000 || load.gid != 20000 || !slices.Equal(load.args, importArgs(stagePath+"/client-fixtureacct_wp.cnf", "fixtureacct_wp")) || load.stdin != "CREATE TABLE t (a int);\n" {
		t.Fatalf("import: %+v", load)
	}
	for _, c := range asSite {
		if !slices.Contains(c.env, "HOME="+r.Account.Home) || slices.ContainsFunc(c.env, func(v string) bool { return strings.HasPrefix(v, "RESTIC_") }) {
			t.Fatalf("site-user environment %q", c.env)
		}
	}
	if stagedMode != 0750 || filesMode != 0750 {
		t.Fatalf("staging modes during the copy: %o %o", stagedMode, filesMode)
	}
	wantChown := []chownCall{{"files", 20000, 20000}, {l.Op, os.Getuid(), 20000}}
	var stageChowns []chownCall
	for _, c := range *calls {
		if c.name == "files" || c.name == l.Op {
			stageChowns = append(stageChowns, c)
		}
	}
	if !slices.Equal(stageChowns[1:], wantChown) || stageChowns[0] != (chownCall{l.Op, os.Getuid(), os.Getuid()}) {
		t.Fatalf("ownership changes: %+v", stageChowns)
	}
	if cnfMode != 0440 || !strings.Contains(cnfText, "user=sifruno_rst_0123456789abcdef\n") {
		t.Fatalf("option file during the import: %o %q", cnfMode, cnfText)
	}
	if _, err := os.Lstat(stagePath + "/client-fixtureacct_wp.cnf"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the option file outlived the import")
	}
	if len(tools.sql) != 3 || tools.sql[0] != databaseExistsSQL("fixtureacct_wp") || !strings.HasPrefix(tools.sql[1], "CREATE USER 'sifruno_rst_0123456789abcdef'@'localhost'") || !strings.Contains(tools.sql[1], "ON `fixtureacct\\_wp`.* TO 'sifruno_rst_0123456789abcdef'@'localhost'") || tools.sql[2] != dropRestoreUserSQL("sifruno_rst_0123456789abcdef") {
		t.Fatalf("root SQL: %q", tools.sql)
	}
	password := strings.TrimSuffix(strings.SplitN(strings.SplitN(cnfText, "word=", 2)[1], "\n", 2)[0], "\n")
	for _, c := range tools.ran {
		if strings.Contains(strings.Join(c.args, " "), password) {
			t.Fatalf("%s got the temporary password as an argument", c.path)
		}
	}
	if err := e.Cleanup(ctx, l); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cleanup left the staging folder")
	}
}

func TestRestoreDropsTheTemporaryUserOnFailure(t *testing.T) {
	for name, setup := range map[string]func(*fakeTools){
		"the load fails":  func(f *fakeTools) { f.failLoad = true },
		"the grant fails": func(f *fakeTools) { f.failSQL = "CREATE USER" },
	} {
		t.Run(name, func(t *testing.T) {
			e, tools, _ := testEngine(t)
			r := engineRecord(filepath.Dir(e.dir))
			tools.snapshots = restoreSnapshots(r, e.dir)
			tools.restored = map[string]string{"fixtureacct_wp.sql": "CREATE TABLE t (a int);\n"}
			setup(tools)
			in := RestoreInput{ExpectedRevision: 1, Snapshot: strings.Repeat("d", 64), Databases: []string{"fixtureacct_wp"}, Reason: "Restore"}
			err := e.Restore(context.Background(), engineTarget(t), r, in, engineLeftover())
			var failed *BackupError
			if !errors.As(err, &failed) || failed.Step != "import" {
				t.Fatalf("restore: %v", err)
			}
			if last := tools.sql[len(tools.sql)-1]; last != dropRestoreUserSQL("sifruno_rst_0123456789abcdef") {
				t.Fatalf("the temporary user was not dropped: %q", tools.sql)
			}
		})
	}
}

// A database that is gone is not made again: the restore is refused before
// anything is staged or any MariaDB user is made.
func TestRestoreRefusesAMissingDatabase(t *testing.T) {
	e, tools, _ := testEngine(t)
	r := engineRecord(filepath.Dir(e.dir))
	tools.snapshots = restoreSnapshots(r, e.dir)
	tools.restored = map[string]string{"fixtureacct_wp.sql": "CREATE TABLE t (a int);\n"}
	tools.missingDB = true
	in := RestoreInput{ExpectedRevision: 1, Snapshot: strings.Repeat("d", 64), Files: true, Databases: []string{"fixtureacct_wp"}, Reason: "Restore"}
	err := e.Restore(context.Background(), engineTarget(t), r, in, engineLeftover())
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "database" || !strings.Contains(failed.Detail, "fixtureacct_wp does not exist") {
		t.Fatalf("a missing database: %v", err)
	}
	if !slices.Equal(tools.sql, []string{databaseExistsSQL("fixtureacct_wp")}) {
		t.Fatalf("root SQL after the refusal: %q", tools.sql)
	}
	if entries, _ := os.ReadDir(e.stage); len(entries) != 0 {
		t.Fatalf("a refused restore staged %v", entries)
	}
	for _, c := range tools.ran {
		if c.path == resticPath && c.args[8] == "restore" || c.path == cpPath {
			t.Fatalf("ran %s %q after the refusal", c.path, c.args)
		}
	}
}

func TestRestoreRefusesAnotherAccountsSnapshot(t *testing.T) {
	e, tools, _ := testEngine(t)
	r := engineRecord(filepath.Dir(e.dir))
	other := r
	other.Account.ID = strings.Repeat("c", 32)
	tools.snapshots = restoreSnapshots(other, e.dir)
	in := RestoreInput{ExpectedRevision: 1, Snapshot: strings.Repeat("d", 64), Files: true, Reason: "Restore"}
	err := e.Restore(context.Background(), engineTarget(t), r, in, engineLeftover())
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "snapshot" {
		t.Fatalf("another account's snapshot: %v", err)
	}
	for _, c := range tools.ran {
		if c.path != resticPath || c.args[8] != "snapshots" {
			t.Fatalf("ran %s %q after the snapshot check failed", c.path, c.args)
		}
	}
}

func TestDrillComparesTheRestoredTree(t *testing.T) {
	e, tools, _ := testEngine(t)
	r := engineRecord(filepath.Dir(e.dir))
	tools.snapshots = restoreSnapshots(r, e.dir)
	home := strings.TrimPrefix(r.Account.Home, "/")
	tools.restored = map[string]string{home + "/public_html/index.php": "hello"}
	tools.lsNodes = []map[string]any{
		{"message_type": "snapshot", "id": strings.Repeat("d", 64)},
		{"message_type": "node", "type": "dir", "path": r.Account.Home},
		{"message_type": "node", "type": "file", "path": r.Account.Home + "/public_html/index.php", "size": 5},
	}
	now := time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC)
	got, err := e.Drill(context.Background(), engineTarget(t), r, backupLeftover{Op: strings.Repeat("b", 32)}, now)
	if err != nil || !got.Passed || got.Files != 2 || got.Subset != "1/8" || got.Snapshot != strings.Repeat("d", 64) {
		t.Fatalf("drill: %+v %v", got, err)
	}
	for _, c := range tools.ran {
		if c.uid != 0 {
			t.Fatal("a drill ran something as the site user")
		}
	}
	if !slices.ContainsFunc(tools.ran, func(c ranCommand) bool { return slices.Contains(c.args, "--read-data-subset=1/8") }) {
		t.Fatal("the drill did not check part of the repository's data")
	}
	tools.lsNodes = append(tools.lsNodes, map[string]any{"message_type": "node", "type": "file", "path": r.Account.Home + "/public_html/missing.php", "size": 1})
	_, err = e.Drill(context.Background(), engineTarget(t), r, backupLeftover{Op: strings.Repeat("c", 32)}, now)
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "compare" || !strings.Contains(failed.Detail, "missing.php was not restored") {
		t.Fatalf("a missing file: %v", err)
	}
}

func TestPruneKeepsSevenDailyAndFourWeekly(t *testing.T) {
	e, tools, _ := testEngine(t)
	got, err := e.Prune(context.Background(), engineTarget(t))
	if err != nil || got.Removed != 1 {
		t.Fatalf("prune: %+v %v", got, err)
	}
	last := tools.ran[len(tools.ran)-1]
	if !slices.Equal(last.args[8:], forgetArgs()) {
		t.Fatalf("forget arguments %q", last.args)
	}
}

func TestRunBackupCommand(t *testing.T) {
	out, code, err := runBackupCommand(context.Background(), backupCommand{path: "/bin/sh", args: []string{"-c", "read x; echo got $x; exit 3"}, env: []string{"PATH=/usr/bin:/bin"}, stdin: strings.NewReader("line\n"), limit: 5 * time.Second})
	if err != nil || code != 3 || !bytes.Contains(out, []byte("got line")) {
		t.Fatalf("run: %q %d %v", out, code, err)
	}
	if _, _, err := runBackupCommand(context.Background(), backupCommand{path: "/bin/sh", args: []string{"-c", "sleep 5"}, limit: 100 * time.Millisecond}); err == nil {
		t.Fatal("a command past its limit must fail")
	}
	if _, _, err := runBackupCommand(context.Background(), backupCommand{path: "sh", limit: time.Second}); err == nil {
		t.Fatal("a relative program path must be refused")
	}
	if _, _, err := runBackupCommand(context.Background(), backupCommand{path: "/bin/true", uid: 20000, limit: time.Second}); err == nil {
		t.Fatal("a site user without its group must be refused")
	}
}

// A restore or drill whose snapshot would not leave the margin free on the
// staging disk is refused before anything is staged.
func TestRestoreAndDrillRefuseWhatTheDiskCannotHold(t *testing.T) {
	e, tools, _ := testEngine(t)
	r := engineRecord(filepath.Dir(e.dir))
	tools.snapshots = restoreSnapshots(r, e.dir)
	tools.restored = map[string]string{"public_html/index.php": "<?php"}
	// A 500 GiB sparse file: restic counts it whole.
	tools.stats = `{"total_size":536870912000,"total_file_count":3,"snapshots_count":1}`
	var asked []string
	e.space = func(dir string) (uint64, uint64, uint64, error) {
		asked = append(asked, dir)
		return 40 << 30, 100 << 30, 4096, nil
	}
	in := RestoreInput{ExpectedRevision: 1, Snapshot: strings.Repeat("d", 64), Files: true, Reason: "Restore"}
	err := e.Restore(context.Background(), engineTarget(t), r, in, engineLeftover())
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "space" || !strings.Contains(failed.Detail, "500.0 GiB") || !strings.Contains(failed.Detail, "5.0 GiB must stay free") {
		t.Fatalf("a restore larger than the disk: %v", err)
	}
	if !slices.Equal(asked, []string{e.stage}) {
		t.Fatalf("free space was read for %q, not the staging folder", asked)
	}
	_, err = e.Drill(context.Background(), engineTarget(t), r, backupLeftover{Op: strings.Repeat("c", 32)}, time.Now())
	if !errors.As(err, &failed) || failed.Step != "space" {
		t.Fatalf("a drill larger than the disk: %v", err)
	}
	if entries, _ := os.ReadDir(e.stage); len(entries) != 0 {
		t.Fatalf("a refused restore staged %v", entries)
	}
	for _, c := range tools.ran {
		if c.path != resticPath || c.args[8] != "snapshots" && c.args[8] != "stats" {
			t.Fatalf("ran %s %q after the size check refused", c.path, c.args)
		}
	}
	if !slices.ContainsFunc(tools.ran, func(c ranCommand) bool { return slices.Equal(c.args[8:], restoreSizeArgs(strings.Repeat("d", 64))) }) {
		t.Fatal("restic was not asked for the snapshot's restore size")
	}
	// The same snapshot fits once it is small enough, and restic restores
	// it sparse.
	tools.stats = `{"total_size":1048576,"total_file_count":3,"snapshots_count":1}`
	if err := e.Restore(context.Background(), engineTarget(t), r, in, engineLeftover()); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(tools.ran, func(c ranCommand) bool { return c.args[8] == "restore" && slices.Contains(c.args, "--sparse") }) {
		t.Fatal("the restore did not write sparse files as sparse")
	}
	// A size restic did not give is refused too.
	tools.stats = `{"snapshots_count":1}`
	err = e.Restore(context.Background(), engineTarget(t), r, in, backupLeftover{Op: strings.Repeat("e", 32)})
	if !errors.As(err, &failed) || failed.Step != "restore" {
		t.Fatalf("an unreadable size: %v", err)
	}
}

// Each dump may use the free space beyond the margin and is stopped past it;
// with no room left, nothing is dumped at all.
func TestDumpsStopAtTheDiskMargin(t *testing.T) {
	e, tools, _ := testEngine(t)
	r := engineRecord(filepath.Dir(e.dir))
	tools.dump = strings.Repeat("INSERT INTO t VALUES (1);\n", 100)
	// A 100 GiB disk: the margin is 5 GiB, and 1 KiB is left beyond it.
	e.space = func(string) (uint64, uint64, uint64, error) { return 5<<30 + 1024, 100 << 30, 4096, nil }
	_, err := e.Backup(context.Background(), engineTarget(t), r, []string{"fixtureacct_wp"})
	var failed *BackupError
	if !errors.As(err, &failed) || failed.Step != "space" || !strings.Contains(failed.Detail, "fixtureacct_wp") || !strings.Contains(failed.Detail, "5.0 GiB") {
		t.Fatalf("a dump past the margin: %v", err)
	}
	if _, err := os.Lstat(dumpDir(e.dir, r.Account.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the stopped dump was left on the disk")
	}
	if slices.ContainsFunc(tools.ran, func(c ranCommand) bool { return c.path == resticPath }) {
		t.Fatal("restic ran after a dump was stopped")
	}
	tools.ran = nil
	e.space = func(string) (uint64, uint64, uint64, error) { return 4 << 30, 100 << 30, 4096, nil }
	_, err = e.Backup(context.Background(), engineTarget(t), r, []string{"fixtureacct_wp"})
	if !errors.As(err, &failed) || failed.Step != "space" || slices.ContainsFunc(tools.ran, func(c ranCommand) bool { return c.path == mariadbDumpPath || c.path == resticPath }) {
		t.Fatalf("no room at all: %v %+v", err, tools.ran)
	}
	// A files-only backup with no room is refused before restic too.
	tools.ran = nil
	_, err = e.Backup(context.Background(), engineTarget(t), r, nil)
	if !errors.As(err, &failed) || failed.Step != "space" || len(tools.ran) != 0 {
		t.Fatalf("files only, no room: %v %+v", err, tools.ran)
	}
}

func TestCappedWriterStopsAtItsCap(t *testing.T) {
	var b bytes.Buffer
	w := &cappedWriter{w: &b, max: 10}
	if n, err := w.Write([]byte("12345")); n != 5 || err != nil || w.over {
		t.Fatal("a write under the cap failed")
	}
	if _, err := w.Write([]byte("678901")); err == nil || !w.over || b.String() != "12345" {
		t.Fatalf("a write past the cap went through: %q", b.String())
	}
	if _, _, _, err := diskSpace(t.TempDir()); err != nil {
		t.Fatalf("statfs of a folder: %v", err)
	}
}
