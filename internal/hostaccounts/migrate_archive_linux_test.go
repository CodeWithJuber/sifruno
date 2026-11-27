//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sifruno/internal/htaccess"
)

func archiveRecord(t *testing.T, m *migrator, data []byte) migrationRecord {
	t.Helper()
	id := strings.Repeat("d", 32)
	if _, err := m.SaveArchive(context.Background(), id, int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(m.dir, id, archiveName))
	if err != nil || info.Mode().Perm() != 0600 || info.Size() != int64(len(data)) {
		t.Fatalf("the kept file: %v %v", info, err)
	}
	return migrationRecord{ID: id, Via: ViaArchive, CreatedAt: time.Now().UTC(), Archive: &MigrationArchive{User: "fixtureacct", Domain: "fixture.test", Databases: []string{"fixtureacct_wp"}, Bytes: int64(len(data)), Home: "/home/fixtureacct"}}
}

// A backup file's home is staged as root, in the root-only staging folder,
// and reaches the site's home through cp as the site's user, as an SSH
// copy's does; no ssh or rsync runs, and mail stays out.
func TestArchiveFilesStageTheBackupsHome(t *testing.T) {
	m, f, _ := testMigrator(t)
	data := fixtureArchive(t, "cpmove-fixtureacct", map[string]string{
		"homedir/public_html/wp-config.php": "<?php define('DB_NAME', 'fixtureacct_wp');",
		"homedir/public_html/.htaccess":     "RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]\n",
	})
	rec := archiveRecord(t, m, data)
	r := engineRecord(filepath.Dir(m.e.dir))
	l := backupLeftover{Op: strings.Repeat("1", 32)}
	got, err := m.Files(context.Background(), rec, "/home/fixtureacct", r, 1, l, noProtection(t))
	if err != nil || !got.WordPress {
		t.Fatalf("files: %+v %v", got, err)
	}
	var cp *ranCommand
	for i := range f.ran {
		switch f.ran[i].path {
		case rsyncPath, sshPath:
			t.Fatalf("%s ran for a backup file", f.ran[i].path)
		case cpPath:
			cp = &f.ran[i]
		}
	}
	if cp == nil || cp.uid != 20000 || cp.gid != 20000 {
		t.Fatalf("cp: %+v", cp)
	}
	staged := filepath.Join(m.e.stage, l.Op, "files")
	if b, err := os.ReadFile(filepath.Join(staged, "public_html", "index.php")); err != nil || string(b) != "<?php echo 1;\n" {
		t.Fatalf("index.php: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(staged, "mail")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mail was staged")
	}
	if _, err := os.Lstat(filepath.Join(staged, "mysql")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a dump was staged with the home")
	}
}

func TestArchivePreflightStagesOnlyHtaccess(t *testing.T) {
	m, _, _ := testMigrator(t)
	rec := archiveRecord(t, m, fixtureArchive(t, "cpmove-fixtureacct", map[string]string{
		"homedir/public_html/staff/.htaccess": "AuthType Basic\nAuthName \"Staff\"\nAuthUserFile /home/fixtureacct/.htpasswds/public_html/staff/passwd\nRequire valid-user\n",
		"homedir/public_html/.user.ini":       "auto_prepend_file = '/home/fixtureacct/public_html/wordfence-waf.php'\n",
		"homedir/public_html/staff/.user.ini": "auto_prepend_file = '/home/fixtureacct/public_html/x.php'\n",
	}))
	l := backupLeftover{Op: strings.Repeat("3", 32)}
	site, home, err := m.Preflight(context.Background(), rec, "/home/fixtureacct", l)
	if err != nil || home || site.Verdict != htaccess.VerdictCompat {
		t.Fatalf("preflight: %+v %v %v", site, home, err)
	}
	// The document root's .user.ini is staged too, and no other.
	if len(site.UserINI) != 1 || site.UserINI[0].File != ".user.ini" {
		t.Fatalf(".user.ini warnings %+v", site.UserINI)
	}
	if _, err := os.Lstat(filepath.Join(m.e.stage, l.Op, "htaccess", "public_html", "staff", ".user.ini")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the tier check staged a folder's .user.ini")
	}
	if _, err := os.Lstat(filepath.Join(m.e.stage, l.Op, "htaccess", "public_html", "index.php")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the tier check staged more than .htaccess files")
	}
}

func TestArchiveDatabaseLoadsTheBackupsDump(t *testing.T) {
	m, f, _ := testMigrator(t)
	rec := archiveRecord(t, m, fixtureArchive(t, "cpmove-fixtureacct", nil))
	r := engineRecord(filepath.Dir(m.e.dir))
	l := backupLeftover{Op: strings.Repeat("6", 32), Users: map[string]string{"fixtureacct_wp": "sifruno_rst_0123456789abcdef"}}
	var staged string
	run := f.run
	m.e.run = func(ctx context.Context, c backupCommand) ([]byte, int, error) {
		if c.path == mariadbPath && c.uid != 0 {
			b, _ := os.ReadFile(m.e.stage + "/" + l.Op + "/db/fixtureacct_wp.sql")
			staged = string(b)
		}
		if c.path == sshPath || c.path == rsyncPath {
			t.Fatalf("%s ran for a backup file", c.path)
		}
		return run(ctx, c)
	}
	got, err := m.Database(context.Background(), rec, "fixtureacct_wp", r, l)
	if err != nil || len(got.Tables) == 0 || got.Tables[0].Source != got.Tables[0].Copy {
		t.Fatalf("database: %+v %v", got, err)
	}
	if staged != "CREATE TABLE t (id int);\n" {
		t.Fatalf("the import read %q", staged)
	}
	// A dump that made a trigger is refused once loaded, as the SSH path
	// refuses one before its dump; the job's undo drops the database.
	f.localObjects = "trigger\n"
	var failed *MigrationError
	if _, err := m.Database(context.Background(), rec, "fixtureacct_wp", r, backupLeftover{Op: strings.Repeat("5", 32), Users: l.Users}); !errors.As(err, &failed) || failed.Step != "database" || !strings.Contains(failed.Detail, "trigger") {
		t.Fatalf("a trigger in the dump: %v", err)
	}
	f.localObjects = ""
	l.Op = strings.Repeat("7", 32)
	if _, err := m.Database(context.Background(), rec, "fixtureacct_shop", r, backupLeftover{Op: l.Op, Users: map[string]string{"fixtureacct_shop": "sifruno_rst_0123456789abcdef"}}); !errors.As(err, &failed) || failed.Step != "database" {
		t.Fatalf("a dump the file does not hold: %v", err)
	}
}

func TestSaveArchiveKeepsNothingOfAShortUpload(t *testing.T) {
	m, _, _ := testMigrator(t)
	data := fixtureArchive(t, "cpmove-fixtureacct", nil)
	id := strings.Repeat("e", 32)
	var failed *MigrationError
	if _, err := m.SaveArchive(context.Background(), id, int64(len(data))+10, bytes.NewReader(data)); !errors.As(err, &failed) || failed.Step != "archive" {
		t.Fatalf("short upload: %v", err)
	}
}
