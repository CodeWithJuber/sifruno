//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
	"sifruno/internal/olsweb"
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
	// realCopy runs cp and the mode fix for real (realProgram); modes are
	// the modes rsync writes entries with (default 0644 and 0755).
	realCopy bool
	modes    map[string]os.FileMode
	counts   string // the copy's row counts (rootSQL), when they differ
}

func (f *fakeSource) run(_ context.Context, c backupCommand) ([]byte, int, error) {
	var stdin string
	if c.stdin != nil {
		b, _ := io.ReadAll(c.stdin)
		stdin = string(b)
	}
	f.mu.Lock()
	f.ran = append(f.ran, ranCommand{path: c.path, args: slices.Clone(c.args), env: slices.Clone(c.env), uid: c.uid, gid: c.gid, stdin: stdin, dir: c.dir})
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
		for name, mode := range f.modes {
			if !htaccessOnly {
				os.Chmod(filepath.Join(dest, name), mode)
			}
		}
		return nil, 0, nil
	case cpPath:
		if f.failCopy {
			return []byte("cp: Disk quota exceeded"), 1, nil
		}
		if f.realCopy {
			return realProgram(c, stdin)
		}
		return nil, 0, nil
	case xargsPath:
		if f.realCopy {
			return realProgram(c, stdin)
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
	noFolders := func(SiteProtection) error {
		t.Fatal("protect ran for a site without protected folders")
		return nil
	}
	got, err := m.Files(context.Background(), rec, "/home/fixtureacct", r, 10, l, noFolders)
	if err != nil || !got.WordPress || len(got.Folders) != 0 || len(got.Probes) != 0 {
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

// noProtection is the protect step of a copy whose site has no protected
// folders: it must not run.
func noProtection(t *testing.T) func(SiteProtection) error {
	return func(SiteProtection) error {
		t.Error("protect ran for a site without protected folders")
		return nil
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
	_, err := m.Files(context.Background(), rec, "/home/fixtureacct", engineRecord(filepath.Dir(m.e.dir)), 1, backupLeftover{Op: strings.Repeat("9", 32)}, noProtection(t))
	var failed *MigrationError
	if !errors.As(err, &failed) || failed.Step != "fetch" || !strings.Contains(failed.Detail, "cannot be read by the account itself") {
		t.Fatalf("refusal: %v", err)
	}
	if slices.ContainsFunc(f.ran, func(c ranCommand) bool { return c.path == cpPath }) {
		t.Fatal("cp ran into the home")
	}
}

// A moved site keeps the old server's modes: a 0600 file and a 0700
// folder are not left group-readable by the staging, a 0644 file stays.
func TestMigrateFilesKeepsTheOldServersModes(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := openedRecord(t, m)
	r := engineRecord(filepath.Dir(m.e.dir))
	if err := os.MkdirAll(r.Account.Home, 0750); err != nil {
		t.Fatal(err)
	}
	f.realCopy = true
	f.home = map[string]string{"public_html/wp-config.php": "<?php", "public_html/index.php": "<?php", "public_html/private/notes.txt": "n", "bin/run.sh": "#!/bin/sh"}
	f.modes = map[string]os.FileMode{"public_html/wp-config.php": 0600, "public_html/private": 0700, "public_html/private/notes.txt": 0600, "bin/run.sh": 0700, "public_html": 0700}
	if _, err := m.Files(context.Background(), rec, "/home/fixtureacct", r, 1, backupLeftover{Op: strings.Repeat("a", 31) + "b"}, noProtection(t)); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{
		"public_html/wp-config.php": 0600, "public_html/index.php": 0644, "public_html/private": 0700,
		"public_html/private/notes.txt": 0600, "bin/run.sh": 0700, "public_html": 0750, ".": 0750,
	} {
		info, err := os.Lstat(filepath.Join(r.Account.Home, name))
		if err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %o", name, info.Mode().Perm(), err, want)
		}
	}
	var fixes []string
	for _, c := range f.ran {
		if c.path == xargsPath {
			if c.uid != 20000 || c.dir != r.Account.Home || !slices.Equal(c.args[:3], []string{"-0", "-r", "--"}) {
				t.Errorf("the mode fix ran as %d in %s with %q", c.uid, c.dir, c.args)
			}
			fixes = append(fixes, c.args[4]+":"+c.stdin)
		}
	}
	slices.Sort(fixes)
	want := []string{"g-r:bin/run.sh\x00public_html/private/notes.txt\x00public_html/wp-config.php\x00", "g-rx:public_html/private\x00"}
	if !slices.Equal(fixes, want) {
		t.Errorf("mode fixes %q, want %q", fixes, want)
	}
}

func TestMigrateFilesRefusesWhatOpenLiteSpeedWouldOpen(t *testing.T) {
	password := "AuthType Basic\nAuthName x\nAuthUserFile /home/fixtureacct/.htpasswds/p\nRequire valid-user\n"
	for name, home := range map[string]map[string]string{
		"user file outside the home": {"public_html/index.php": "x", "public_html/staff/.htaccess": "AuthType Basic\nAuthName x\nAuthUserFile /home/u/.htpasswds/p\nRequire valid-user\n"},
		"user file missing":          {"public_html/index.php": "x", "public_html/staff/.htaccess": password},
		"user file a link":           {"public_html/index.php": "x", "public_html/staff/.htaccess": password, ".htpasswds/p": "->/etc/shadow"},
		"plain-text password":        {"public_html/index.php": "x", "public_html/staff/.htaccess": password, ".htpasswds/p": "bob:secret\n"},
		"crypt password":             {"public_html/index.php": "x", "public_html/staff/.htaccess": password, ".htpasswds/p": "bob:$6$saltsalt$" + strings.Repeat("e", 86) + "\n"},
		"satisfy any":                {"public_html/index.php": "x", "public_html/staff/.htaccess": "Deny from all\nSatisfy Any\n"},
		"unknown directive":          {"public_html/index.php": "x", "public_html/staff/.htaccess": "Deny from all\nFoo bar\n"},
		"home .htaccess":             {"public_html/index.php": "x", ".htaccess": "Deny from all\n"},
		"linked docroot":             {"public_html": "->/etc"},
	} {
		t.Run(name, func(t *testing.T) {
			m, f, _ := testMigrator(t)
			rec := openedRecord(t, m)
			f.home = home
			protect := func(SiteProtection) error {
				t.Fatal("protect ran for a refused site")
				return nil
			}
			_, err := m.Files(context.Background(), rec, "/home/fixtureacct", engineRecord(filepath.Dir(m.e.dir)), 1, backupLeftover{Op: strings.Repeat("2", 32)}, protect)
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

// TestMigrateFilesNamesTheUserWithAnOldHash: a password folder whose user
// file holds a crypt hash refuses the copy and says whose password to set
// again, and how.
func TestMigrateFilesNamesTheUserWithAnOldHash(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := openedRecord(t, m)
	f.home = map[string]string{
		"public_html/index.php":       "x",
		"public_html/staff/.htaccess": "AuthType Basic\nAuthName x\nAuthUserFile /home/fixtureacct/.htpasswds/p\nRequire valid-user\n",
		".htpasswds/p":                "alice:$apr1$x1Y2z3$abcdefghijklmnopqrstuv\nbob:$1$saltsalt$" + strings.Repeat("c", 22) + "\n",
	}
	_, err := m.Files(context.Background(), rec, "/home/fixtureacct", engineRecord(filepath.Dir(m.e.dir)), 1, backupLeftover{Op: strings.Repeat("8", 32)}, noProtection(t))
	var failed *MigrationError
	if !errors.As(err, &failed) || failed.Step != "tier" || !strings.Contains(failed.Detail, "for bob again on the old server with a modern hash") || !strings.Contains(failed.Detail, "after the move") {
		t.Fatalf("refusal: %v", err)
	}
	if slices.ContainsFunc(f.ran, func(c ranCommand) bool { return c.path == cpPath }) {
		t.Fatal("cp ran into the home")
	}
}

// TestMigrateFilesProtectsBeforeCopy: a WordPress site with Akismet's
// .htaccess and a password folder converts; protect gets the folders and
// the normalized user file before cp makes the files reachable, and the
// answer lists the folders and the URLs verify checks, open files included.
func TestMigrateFilesProtectsBeforeCopy(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := openedRecord(t, m)
	r := engineRecord(filepath.Dir(m.e.dir))
	akismet, err := os.ReadFile("../htaccess/testdata/akismet-5.7.2.htaccess")
	if err != nil {
		t.Fatal(err)
	}
	hash := "$apr1$x1Y2z3$abcdefghijklmnopqrstuv"
	f.home = map[string]string{
		"public_html/index.php":                                   "x",
		"public_html/.htaccess":                                   "RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]\n",
		"public_html/wp-content/plugins/akismet/.htaccess":        string(akismet),
		"public_html/wp-content/plugins/akismet/akismet.php":      "<?php",
		"public_html/wp-content/plugins/akismet/_inc/akismet.css": "a{}",
		"public_html/wp-content/plugins/akismet/_inc/form.js":     "1",
		"public_html/wp-content/plugins/akismet/a b/akismet.js":   "1",
		"public_html/members/.htaccess":                           "AuthType Basic\nAuthName \"Members only\"\nAuthUserFile /home/fixtureacct/.htpasswds/public_html/members/passwd\nRequire valid-user\n",
		"public_html/members/index.html":                          "members",
		".htpasswds/public_html/members/passwd":                   "# users\nalice:" + hash + "\n",
	}
	var got SiteProtection
	cpBefore := false
	protect := func(p SiteProtection) error {
		got = p
		cpBefore = slices.ContainsFunc(f.ran, func(c ranCommand) bool { return c.path == cpPath })
		return nil
	}
	res, err := m.Files(context.Background(), rec, "/home/fixtureacct", r, 10, backupLeftover{Op: strings.Repeat("7", 32)}, protect)
	if err != nil {
		t.Fatal(err)
	}
	if cpBefore || !slices.ContainsFunc(f.ran, func(c ranCommand) bool { return c.path == cpPath }) {
		t.Fatal("cp ran before the folders were protected, or not at all")
	}
	site := siteName(r.Account.ID)
	if len(got.Folders) != 2 || got.Folders[0].Path != "/members/" || got.Folders[0].Realm == nil || got.Folders[0].Realm.UserFile != olsweb.RealmFile(site, 1) ||
		got.Folders[1].Path != "/wp-content/plugins/akismet/" || got.Folders[1].Hosts != olsweb.HostsNone || len(got.Folders[1].Allow) != 15 {
		t.Fatalf("folders %+v", got.Folders)
	}
	if string(got.Users[olsweb.RealmFile(site, 1)]) != "alice:"+hash+"\n" || len(got.Users) != 1 {
		t.Fatalf("users %q", got.Users)
	}
	if err := olsweb.CheckFolders(site, got.Folders); err != nil {
		t.Fatal(err)
	}
	wantProbes := []MigrationProbe{
		{Path: "/members/", Kind: "auth"},
		{Path: "/wp-content/plugins/akismet/", Kind: "deny"},
		{Path: "/wp-content/plugins/akismet/_inc/", Kind: "deny"},
		{Path: "/wp-content/plugins/akismet/_inc/akismet.css", Kind: "allow"},
		{Path: "/wp-content/plugins/akismet/_inc/form.js", Kind: "allow"},
	}
	if !reflect.DeepEqual(res.Probes, wantProbes) || len(res.Folders) != 2 || res.Folders[1].File != "wp-content/plugins/akismet/.htaccess" {
		t.Fatalf("result %+v", res)
	}
}

// TestMigrateFilesProbesSubfoldersAndAddressLists: verify checks one real
// subfolder below a closed and a password folder, with the parent's
// status, and every folder open to some addresses only. Before, a
// subfolder that answered otherwise on the copy (/private/sub/) and an
// address-list folder (/lobby/) went unchecked and the gate opened.
func TestMigrateFilesProbesSubfoldersAndAddressLists(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := openedRecord(t, m)
	f.home = map[string]string{
		"public_html/index.php":                 "x",
		"public_html/private/.htaccess":         "AuthType Basic\nAuthName \"Staff area\"\nAuthUserFile /home/fixtureacct/.htpasswds/public_html/private/passwd\nRequire valid-user\n",
		"public_html/private/index.html":        "staff",
		"public_html/private/sub/index.html":    "payroll",
		"public_html/private/zz/index.html":     "later",
		".htpasswds/public_html/private/passwd": "alice:$apr1$x1Y2z3$abcdefghijklmnopqrstuv\n",
		"public_html/backups/.htaccess":         "Deny from all\n",
		"public_html/backups/a b/x.sql":         "x",
		"public_html/backups/old.d/x.sql":       "x",
		"public_html/backups/old/x.sql":         "x",
		"public_html/lobby/.htaccess":           "Order Allow,Deny\nAllow from all\nDeny from 127.0.0.2\n",
		"public_html/lobby/index.html":          "lobby",
		"public_html/office/.htaccess":          "Order Deny,Allow\nDeny from all\nAllow from 127.0.0.2\n",
		"public_html/office/index.html":         "office",
	}
	res, err := m.Files(context.Background(), rec, "/home/fixtureacct", engineRecord(filepath.Dir(m.e.dir)), 1, backupLeftover{Op: strings.Repeat("e", 32)}, func(SiteProtection) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	has := func(path, kind string) bool {
		return slices.ContainsFunc(res.Probes, func(p MigrationProbe) bool { return p.Path == path && p.Kind == kind })
	}
	for _, want := range [][2]string{{"/private/", "auth"}, {"/private/sub/", "auth"}, {"/backups/", "deny"}, {"/backups/old/", "deny"}} {
		if !has(want[0], want[1]) {
			t.Errorf("no %s probe for %s: %+v", want[1], want[0], res.Probes)
		}
	}
	for _, path := range []string{"/lobby/", "/office/"} {
		if !slices.ContainsFunc(res.Probes, func(p MigrationProbe) bool { return p.Path == path }) {
			t.Errorf("the address-list folder %s is not probed: %+v", path, res.Probes)
		}
	}
	// An address-list folder carries its rule, which verify's expected
	// statuses come from; its subfolders are not probed.
	for _, want := range []MigrationProbe{
		{Path: "/lobby/", Kind: "hosts", Hosts: "except", Networks: []string{"127.0.0.2/32"}},
		{Path: "/office/", Kind: "hosts", Hosts: "only", Networks: []string{"127.0.0.2/32"}},
	} {
		if !slices.ContainsFunc(res.Probes, func(p MigrationProbe) bool { return reflect.DeepEqual(p, want) }) {
			t.Errorf("no probe %+v: %+v", want, res.Probes)
		}
	}
	if len(res.Probes) != 6 {
		t.Errorf("%d probes: %+v", len(res.Probes), res.Probes)
	}
	// One subfolder per folder, the first by name whose name verify can put
	// in a URL as it is.
	for _, path := range []string{"/private/zz/", "/backups/a b/", "/backups/old.d/"} {
		if slices.ContainsFunc(res.Probes, func(p MigrationProbe) bool { return p.Path == path }) {
			t.Errorf("%s probed: %+v", path, res.Probes)
		}
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
	conv := htaccess.ConvertSite(site)
	if probes := foldersProbes(conv.Rules); !conv.Native || !reflect.DeepEqual(probes, []MigrationProbe{{Path: "/staff/", Kind: "auth"}}) {
		t.Fatalf("conversion %+v probes %v", conv, probes)
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
