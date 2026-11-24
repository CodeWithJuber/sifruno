//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
)

// fakeSource stands in for ssh, ssh-keyscan, rsync, cp and the MariaDB
// client: it records each program and answers as a cPanel server would.
type fakeSource struct {
	mu   sync.Mutex
	t    *testing.T
	ran  []ranCommand
	home map[string]string // relative path -> content rsync writes; "->x" makes a link
	// remote answers a remote command by its prefix.
	remote   map[string]string
	dump     string
	objects  string // what the source's object check finds
	failCopy bool
	counts   string // the copy's row counts (rootSQL), when they differ
}

func (f *fakeSource) run(_ context.Context, c backupCommand) ([]byte, int, error) {
	var stdin string
	if c.stdin != nil {
		b, _ := io.ReadAll(c.stdin)
		stdin = string(b)
	}
	f.mu.Lock()
	f.ran = append(f.ran, ranCommand{path: c.path, args: slices.Clone(c.args), env: slices.Clone(c.env), uid: c.uid, gid: c.gid, stdin: stdin})
	f.mu.Unlock()
	switch c.path {
	case sshKeyscanPath:
		io.WriteString(c.stdout, "source.example.test "+fixtureHostKey+"\n")
		return nil, 0, nil
	case rsyncPath:
		dest := strings.TrimSuffix(c.args[len(c.args)-1], "/")
		htaccessOnly := slices.Contains(c.args, "--include=.htaccess")
		for name, content := range f.home {
			if htaccessOnly && filepath.Base(name) != ".htaccess" {
				continue
			}
			p := filepath.Join(dest, name)
			os.MkdirAll(filepath.Dir(p), 0755)
			if target, ok := strings.CutPrefix(content, "->"); ok {
				os.Symlink(target, p)
				continue
			}
			os.WriteFile(p, []byte(content), 0644)
		}
		return nil, 0, nil
	case cpPath:
		if f.failCopy {
			return []byte("cp: Disk quota exceeded"), 1, nil
		}
		return nil, 0, nil
	case mariadbPath:
		if c.uid != 0 {
			return nil, 0, nil
		}
		// Answers go to standard output when the caller reads it apart;
		// a warning on standard error must then not count as an answer.
		answer := func(s string) ([]byte, int, error) {
			if c.stdout != nil {
				io.WriteString(c.stdout, s)
				return []byte("Warning: a note on standard error\n"), 0, nil
			}
			return []byte(s), 0, nil
		}
		switch {
		case strings.HasPrefix(stdin, "SELECT COUNT(*) FROM information_schema.SCHEMATA"):
			return answer("1\n")
		case strings.HasPrefix(stdin, "SELECT TABLE_NAME"):
			return answer("wp_options\nwp_posts\n")
		case strings.HasPrefix(stdin, "SELECT 'wp_options'"):
			if f.counts != "" {
				return answer(f.counts)
			}
			return answer("wp_options\t120\nwp_posts\t3\n")
		}
		return nil, 0, nil
	case sshPath:
		command := c.args[len(c.args)-1]
		if command == cpsource.SQLCommand() {
			switch {
			case strings.HasPrefix(stdin, "SELECT 'missing'"):
				io.WriteString(c.stdout, f.objects)
				return nil, 0, nil
			case strings.HasPrefix(stdin, "SELECT TABLE_NAME"):
				io.WriteString(c.stdout, "wp_options\nwp_posts\n")
			case strings.HasPrefix(stdin, "SELECT 'wp_options'"):
				io.WriteString(c.stdout, "wp_options\t120\nwp_posts\t3\n")
			}
			return nil, 0, nil
		}
		if strings.Contains(command, "dump") {
			io.WriteString(c.stdout, f.dump)
			return nil, 0, nil
		}
		for prefix, answer := range f.remote {
			if strings.HasPrefix(command, prefix) {
				if c.stdout != nil {
					io.WriteString(c.stdout, answer)
					return nil, 0, nil
				}
				return []byte(answer), 0, nil
			}
		}
		return []byte("Permission denied (publickey)."), 255, nil
	}
	f.t.Errorf("unexpected program %s", c.path)
	return nil, 1, nil
}

func testMigrator(t *testing.T) (*migrator, *fakeSource, *[]chownCall) {
	t.Helper()
	e, _, calls := testEngine(t)
	f := &fakeSource{t: t, home: map[string]string{}, remote: map[string]string{}}
	e.run = f.run
	m := &migrator{e: e, dir: filepath.Dir(e.dir) + "/migrate", tools: func() error { return nil }}
	m.prepareDir = func() error { return os.MkdirAll(m.dir, 0700) }
	return m, f, calls
}

func openedRecord(t *testing.T, m *migrator) migrationRecord {
	t.Helper()
	id := strings.Repeat("c", 32)
	public, err := m.Open(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Pin(id, fixtureHostKey); err != nil {
		t.Fatal(err)
	}
	return migrationRecord{ID: id, Host: "source.example.test", Port: 22, PublicKey: public, HostKeys: []string{fixtureHostKey}, Pinned: fixtureHostKey, CreatedAt: time.Now().UTC()}
}

func TestMigrationKeyIsPrivateAndSSHIsPinned(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := openedRecord(t, m)
	if _, _, ok := normalizeSSHKey(rec.PublicKey); !ok || !strings.HasPrefix(rec.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("public key %q", rec.PublicKey)
	}
	for _, name := range []string{"ssh_key", "known_hosts"} {
		info, err := os.Lstat(filepath.Join(m.dir, rec.ID, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(m.dir, rec.ID, "known_hosts"))
	if string(b) != migrateHostKeyAlias+" "+fixtureHostKey+"\n" {
		t.Fatalf("known_hosts %q", b)
	}
	if _, err := m.Open(rec.ID); err == nil {
		t.Fatal("a second key in the same folder")
	}
	f.remote[cpsource.ListAccountsCommand()] = "{}"
	if _, code, err := m.Remote(context.Background(), rec, cpsource.ListAccountsCommand(), nil, nil, time.Minute); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	if _, _, err := m.Remote(context.Background(), rec, "ls\nid", nil, nil, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatal("a command with a new line ran")
	}
	c := f.ran[len(f.ran)-1]
	args := strings.Join(c.args, " ")
	for _, want := range []string{"-o BatchMode=yes", "-o StrictHostKeyChecking=yes", "-o UserKnownHostsFile=" + m.dir + "/" + rec.ID + "/known_hosts", "-o HostKeyAlias=" + migrateHostKeyAlias, "-o IdentityAgent=none", "-o PasswordAuthentication=no", "-i " + m.dir + "/" + rec.ID + "/ssh_key", "-l root -- source.example.test /usr/local/cpanel/bin/whmapi1"} {
		if !strings.Contains(args, want) {
			t.Errorf("ssh lacks %q: %s", want, args)
		}
	}
	if c.uid != 0 || slices.ContainsFunc(c.env, func(s string) bool { return strings.HasPrefix(s, "SSH_AUTH_SOCK") }) {
		t.Fatalf("ssh ran with %v %v", c.uid, c.env)
	}
	if err := m.Forget(rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(m.dir, rec.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the key outlived Forget")
	}
}

func TestMigrateFilesStagesAsRootAndCopiesAsTheSiteUser(t *testing.T) {
	m, f, calls := testMigrator(t)
	rec := openedRecord(t, m)
	r := engineRecord(filepath.Dir(m.e.dir))
	f.home = map[string]string{
		"public_html/index.php":     "<?php echo 'hi';",
		"public_html/wp-config.php": "<?php define('DB_NAME', 'fixtureacct_wp');",
		"public_html/.htaccess":     "RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]\n",
	}
	l := backupLeftover{Op: strings.Repeat("1", 32)}
	got, err := m.Files(context.Background(), rec, "/home/fixtureacct", r, 10, l)
	if err != nil || !got.WordPress {
		t.Fatalf("files: %+v %v", got, err)
	}
	var rsync, cp *ranCommand
	for i := range f.ran {
		switch f.ran[i].path {
		case rsyncPath:
			if !slices.Contains(f.ran[i].args, "--include=.htaccess") {
				rsync = &f.ran[i]
			}
		case cpPath:
			cp = &f.ran[i]
		}
	}
	if rsync == nil || rsync.uid != 0 {
		t.Fatal("rsync did not run as root")
	}
	args := strings.Join(rsync.args, " ")
	if slices.ContainsFunc(rsync.args[1:], func(a string) bool {
		return a == "-o" || a == "-a" || strings.HasPrefix(a, "--chown") || strings.HasPrefix(a, "--owner")
	}) {
		t.Errorf("rsync gives the staged files an owner: %s", args)
	}
	for _, want := range []string{"--chmod=ug-s", "--exclude=/mail/", "--exclude=/.ssh/", "--exclude=/ssl/", "-- source.example.test:/home/fixtureacct/ " + m.e.stage + "/" + l.Op + "/files/"} {
		if !strings.Contains(args, want) {
			t.Errorf("rsync lacks %q: %s", want, args)
		}
	}
	if !strings.HasPrefix(rsync.args[0], "--rsh="+sshPath+" -F /dev/null -T ") {
		t.Errorf("rsh %q", rsync.args[0])
	}
	if cp == nil || cp.uid != 20000 || cp.gid != 20000 || !slices.Equal(cp.args, copyArgs(m.e.stage+"/"+l.Op+"/files", r.Account.Home)) {
		t.Fatalf("cp: %+v", cp)
	}
	// The staging folder was handed to the site's group before cp ran, and
	// every staged entry is root's and that group's: none counts against
	// the site's quota.
	if !slices.Contains(*calls, chownCall{l.Op, os.Getuid(), 20000}) {
		t.Fatalf("chowns %v", *calls)
	}
	for _, name := range []string{"files", "public_html", "index.php", "wp-config.php", ".htaccess"} {
		if !slices.Contains(*calls, chownCall{name, os.Getuid(), 20000}) {
			t.Errorf("%s was not given to root and the site's group: %v", name, *calls)
		}
	}
	if slices.ContainsFunc(*calls, func(c chownCall) bool { return c.uid == 20000 }) {
		t.Errorf("a staged entry was given to the site's user: %v", *calls)
	}
	for name, want := range map[string]os.FileMode{"files/public_html/index.php": 0644, "files/public_html": 0750} {
		if info, err := os.Lstat(filepath.Join(m.e.stage, l.Op, name)); err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v %v", name, info.Mode().Perm(), err)
		}
	}
}

// The source's rsync sender runs as the account, never as root: rsync hands
// --rsync-path to the source's shell as it is, so each word the shell splits
// off must be fixed or the account's checked name.
func TestRsyncSenderRunsAsTheAccount(t *testing.T) {
	sender, ok := senderPath("/home/fixtureacct")
	if !ok || !slices.Equal(strings.Fields(sender), []string{"/usr/sbin/runuser", "-u", "fixtureacct", "--", "/usr/bin/rsync"}) {
		t.Fatalf("sender %q", sender)
	}
	for _, word := range strings.Fields(sender) {
		if !regexp.MustCompile(`^[A-Za-z0-9/_-]+$`).MatchString(word) {
			t.Fatalf("a word the source's shell would read specially: %q", word)
		}
	}
	for _, home := range []string{"/home/root", "/home/x;id", "/home/Abc", "home/fixtureacct", "/home/fixtureacct/", "/home/a b", "/home/$(id)", "/home/sshd"} {
		if _, ok := senderPath(home); ok {
			t.Errorf("%q gave a sender", home)
		}
	}
	for name, args := range map[string]func() ([]string, bool){
		"copy": func() ([]string, bool) {
			return fetchArgs("/usr/bin/ssh", "source.example.test", "/home/fixtureacct", "/stage/files")
		},
		"htaccess": func() ([]string, bool) {
			return htaccessArgs("/usr/bin/ssh", "source.example.test", "/home/fixtureacct", "/stage/htaccess")
		},
	} {
		list, ok := args()
		if !ok || !slices.Contains(list, "--rsync-path="+sender) {
			t.Errorf("%s: %q", name, list)
		}
	}
	if _, ok := fetchArgs("/usr/bin/ssh", "source.example.test", "/home/root", "/stage/files"); ok {
		t.Error("a copy as root was built")
	}
}

// What the account may not read on the source stops the copy (rsync 23)
// with a plain reason; nothing reaches the home.
func TestUnreadableSourceFilesStopTheCopy(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := openedRecord(t, m)
	f.home = map[string]string{"public_html/index.php": "x"}
	run := f.run
	m.e.run = func(ctx context.Context, c backupCommand) ([]byte, int, error) {
		if c.path == rsyncPath {
			return []byte(`rsync: [sender] send_files failed to open "/home/fixtureacct/public_html/hl.txt": Permission denied (13)`), 23, nil
		}
		return run(ctx, c)
	}
	_, err := m.Files(context.Background(), rec, "/home/fixtureacct", engineRecord(filepath.Dir(m.e.dir)), 1, backupLeftover{Op: strings.Repeat("9", 32)})
	var failed *MigrationError
	if !errors.As(err, &failed) || failed.Step != "fetch" || !strings.Contains(failed.Detail, "cannot be read by the account itself") {
		t.Fatalf("refusal: %v", err)
	}
	if slices.ContainsFunc(f.ran, func(c ranCommand) bool { return c.path == cpPath }) {
		t.Fatal("cp ran into the home")
	}
}

func TestMigrateFilesRefusesWhatOpenLiteSpeedWouldOpen(t *testing.T) {
	for name, home := range map[string]map[string]string{
		"password folder": {"public_html/index.php": "x", "public_html/staff/.htaccess": "AuthType Basic\nAuthName x\nAuthUserFile /home/u/.htpasswds/p\nRequire valid-user\n"},
		"home .htaccess":  {"public_html/index.php": "x", ".htaccess": "Deny from all\n"},
		"linked docroot":  {"public_html": "->/etc"},
	} {
		t.Run(name, func(t *testing.T) {
			m, f, _ := testMigrator(t)
			rec := openedRecord(t, m)
			f.home = home
			_, err := m.Files(context.Background(), rec, "/home/fixtureacct", engineRecord(filepath.Dir(m.e.dir)), 1, backupLeftover{Op: strings.Repeat("2", 32)})
			var failed *MigrationError
			if !errors.As(err, &failed) || (failed.Step != "tier" && failed.Step != "copy") {
				t.Fatalf("refusal: %v", err)
			}
			if slices.ContainsFunc(f.ran, func(c ranCommand) bool { return c.path == cpPath }) {
				t.Fatal("cp ran into the home")
			}
		})
	}
}

func TestPreflightScansOnlyHtaccess(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := openedRecord(t, m)
	f.home = map[string]string{"public_html/index.php": "x", "public_html/staff/.htaccess": "AuthType Basic\nAuthName \"Staff\"\nAuthUserFile /home/u/.htpasswds/public_html/staff/passwd\nRequire valid-user\n"}
	site, home, err := m.Preflight(context.Background(), rec, "/home/fixtureacct", backupLeftover{Op: strings.Repeat("3", 32)})
	if err != nil || home || site.Verdict != htaccess.VerdictCompat {
		t.Fatalf("preflight: %+v %v %v", site, home, err)
	}
	if probes := probesOf(site); !slices.Contains(probes, MigrationProbe{Path: "/staff/", Kind: "auth"}) {
		t.Fatalf("probes %v", probes)
	}
	f.home = map[string]string{"public_html/index.php": "x"}
	site, _, err = m.Preflight(context.Background(), rec, "/home/fixtureacct", backupLeftover{Op: strings.Repeat("4", 32)})
	if err != nil || site.Verdict != htaccess.VerdictNative {
		t.Fatalf("no .htaccess: %+v %v", site, err)
	}
	if _, _, err := m.Preflight(context.Background(), rec, "/home/x y", backupLeftover{Op: strings.Repeat("5", 32)}); err == nil {
		t.Fatal("a home with a space was fetched")
	}
}

func TestMigrateDatabaseDumpsOverSSHAndImportsAsTheSiteUser(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := openedRecord(t, m)
	r := engineRecord(filepath.Dir(m.e.dir))
	f.dump = "CREATE TABLE wp_options (a int);\n"
	l := backupLeftover{Op: strings.Repeat("6", 32), Users: map[string]string{"fixtureacct_wp": "sifruno_rst_0123456789abcdef"}}
	var staged string
	run := f.run
	m.e.run = func(ctx context.Context, c backupCommand) ([]byte, int, error) {
		if c.path == mariadbPath && c.uid != 0 {
			b, _ := os.ReadFile(m.e.stage + "/" + l.Op + "/db/fixtureacct_wp.sql")
			staged = string(b)
		}
		return run(ctx, c)
	}
	got, err := m.Database(context.Background(), rec, "fixtureacct_wp", r, l)
	if err != nil || len(got.Tables) != 2 || got.Tables[0] != (MigrationTable{Table: "wp_options", Source: 120, Copy: 120}) {
		t.Fatalf("database: %+v %v", got, err)
	}
	if staged != f.dump {
		t.Fatalf("the import read %q", staged)
	}
	var load *ranCommand
	for i := range f.ran {
		if f.ran[i].path == mariadbPath && f.ran[i].uid != 0 {
			load = &f.ran[i]
		}
		if strings.Contains(strings.Join(f.ran[i].args, " "), "sifruno_rst_") && !strings.Contains(strings.Join(f.ran[i].args, " "), "client-") {
			t.Fatalf("a temporary user name in arguments: %v", f.ran[i].args)
		}
	}
	if load == nil || load.uid != 20000 || load.stdin != f.dump {
		t.Fatalf("import: %+v", load)
	}
	// A difference in the copy is reported, not hidden.
	f.counts = "wp_options\t120\nwp_posts\t2\n"
	l.Op = strings.Repeat("7", 32)
	if got, err = m.Database(context.Background(), rec, "fixtureacct_wp", r, l); err != nil || got.Tables[1] != (MigrationTable{Table: "wp_posts", Source: 3, Copy: 2}) {
		t.Fatalf("a difference: %+v %v", got, err)
	}
	// A database with a trigger on the source is refused before the dump.
	f.objects = "trigger\n"
	l.Op = strings.Repeat("8", 32)
	var failed *MigrationError
	if _, err = m.Database(context.Background(), rec, "fixtureacct_wp", r, l); !errors.As(err, &failed) || failed.Step != "database" || !strings.Contains(failed.Detail, "trigger") {
		t.Fatalf("a trigger: %v", err)
	}
}
