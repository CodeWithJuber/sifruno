package hostaccounts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// fixtureArchive is a synthetic cpmove-fixtureacct.tar.gz, in the layout
// cPanel's "Backup Tarball Contents" page describes, for the store's
// fixture account and domain.
func fixtureArchive(t *testing.T, top string, extra map[string]string) []byte {
	t.Helper()
	hash := "*" + strings.Repeat("AB", 20)
	files := map[string]string{
		"cp/fixtureacct":                "DNS=fixture.test\nUSER=fixtureacct\n",
		"userdata/main":                 "---\nmain_domain: fixture.test\nparked_domains: []\nsub_domains: []\n",
		"userdata/fixture.test":         "---\ndocumentroot: /home/fixtureacct/public_html\nhomedir: /home/fixtureacct\nphpversion: ea-php82\nserveralias: www.fixture.test\nservername: fixture.test\n",
		"cron/fixtureacct":              "*/5 * * * * php /home/fixtureacct/public_html/wp-cron.php\n",
		"mysql.sql":                     "GRANT USAGE ON *.* TO 'fixtureacct_wpu'@'localhost' IDENTIFIED BY PASSWORD '" + hash + "';\nGRANT ALL PRIVILEGES ON `fixtureacct\\_wp`.* TO 'fixtureacct_wpu'@'localhost';\n",
		"mysql/fixtureacct_wp.sql":      "CREATE TABLE t (id int);\n",
		"homedir/public_html/index.php": "<?php echo 1;\n",
		"homedir/mail/inbox":            "stays\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	slices.Sort(names)
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	tw := tar.NewWriter(z)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: top + "/" + name, Mode: 0644, Size: int64(len(files[name])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if tw.Close() != nil || z.Close() != nil {
		t.Fatal("archive")
	}
	return b.Bytes()
}

func openArchive(t *testing.T, s *store, data []byte) (Migration, error) {
	t.Helper()
	return s.openArchiveMigration(context.Background(), MigrationArchiveInput{Size: int64(len(data)), Reason: "Move a website here"}, bytes.NewReader(data), "test operator")
}

func TestArchiveMigrationMovesTheBackupsAccount(t *testing.T) {
	s, f, _ := migrateStore(t)
	ctx := context.Background()
	m, err := openArchive(t, s, fixtureArchive(t, "cpmove-fixtureacct", nil))
	if err != nil {
		t.Fatal(err)
	}
	if m.Via != ViaArchive || m.Archive == nil || m.Archive.User != "fixtureacct" || m.Archive.Domain != "fixture.test" || !slices.Equal(m.Archive.Databases, []string{"fixtureacct_wp"}) || m.Host != "" || m.InstallCommand != "" {
		t.Fatalf("migration = %+v", m)
	}
	if !strings.Contains(notCarried(m), "mail: Email accounts") {
		t.Fatalf("not carried = %s", notCarried(m))
	}
	accounts, err := s.migrationAccounts(ctx, m.ID)
	if err != nil || len(accounts) != 1 || accounts[0].User != "fixtureacct" {
		t.Fatalf("accounts = %+v, %v", accounts, err)
	}
	plan, err := s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "x"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Domain != "fixture.test" || plan.PHPSource != "ea-php82" || !plan.WWW || plan.Tier != "native" || len(plan.Cron) != 1 || len(plan.Users) != 1 || plan.Users[0].Hash == "" ||
		len(plan.Databases) != 1 || !slices.Equal(plan.Databases[0].Users, []string{"fixtureacct_wpu"}) || len(plan.NotCarried) == 0 {
		t.Fatalf("plan = %+v", plan)
	}
	// No command ran on any server.
	if len(f.commands) != 0 {
		t.Fatalf("commands = %v", f.commands)
	}
	var failed *MigrationError
	if _, err := s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "otheracct", Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "account_missing" {
		t.Fatalf("another account: %v", err)
	}
	a := createFixture(t, s)
	got, err := s.migrateFiles(ctx, a.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: a.Revision, Reason: "x"}, "test operator")
	if err != nil || !got.WordPress || !slices.Equal(f.files, []string{"/home/fixtureacct -> fixtureacct"}) {
		t.Fatalf("files: %+v %v %v", got, err, f.files)
	}
	if _, err := s.migrateDatabase(ctx, a.ID, MigrateDatabaseInput{Migration: m.ID, Database: "fixtureacct_wp", ExpectedRevision: a.Revision, Reason: "x"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.migrateDatabase(ctx, a.ID, MigrateDatabaseInput{Migration: m.ID, Database: "fixtureacct_shop", ExpectedRevision: a.Revision, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "database" {
		t.Fatalf("a database the file does not hold: %v", err)
	}
	other := createFixtureNamed(t, s, "otheracct", "fixture.test.example")
	if _, err = s.migrateFiles(ctx, other.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: other.Revision, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "source" {
		t.Fatalf("another account: %v", err)
	}
	// WHM answers are refused for a backup file's move.
	if _, err = s.migrateFiles(ctx, a.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: a.Revision, CPanel: &CPanelAnswers{}, Reason: "x"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cPanel answers: %v", err)
	}
	done, err := s.finishMigration(ctx, m.ID, MigrationFinishInput{Reason: "x"}, "test operator")
	if err != nil || !done.RemovedFromSource || f.folders[m.ID] {
		t.Fatalf("finish = %+v, %v; folder kept %v", done, err, f.folders[m.ID])
	}
	if stale, _ := s.staleKeys(); len(stale) != 0 {
		t.Fatalf("a backup file left a stale key line: %+v", stale)
	}
}

func notCarried(m Migration) string {
	var lines []string
	for _, item := range m.Archive.NotCarried {
		lines = append(lines, item.Part+": "+item.Text)
	}
	return strings.Join(lines, "\n")
}

func TestArchiveMigrationRefusesWhatItCannotUse(t *testing.T) {
	s, f, _ := migrateStore(t)
	cases := map[string][]byte{
		"not cPanel":          fixtureArchive(t, "site", map[string]string{"cp/fixtureacct": ""}),
		"outside public_html": fixtureArchive(t, "cpmove-fixtureacct", map[string]string{"userdata/fixture.test": "documentroot: /home/fixtureacct/www/site\nhomedir: /home/fixtureacct\n"}),
		"truncated":           fixtureArchive(t, "cpmove-fixtureacct", nil)[:200],
	}
	for name, data := range cases {
		var failed *MigrationError
		if _, err := openArchive(t, s, data); !errors.As(err, &failed) || (failed.Step != "archive" && failed.Step != "source") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.folders) != 0 {
		t.Fatalf("a refused file kept its folder: %v", f.folders)
	}
	if _, err := s.openArchiveMigration(context.Background(), MigrationArchiveInput{Size: maxArchiveBytes + 1, Reason: "x"}, strings.NewReader(""), "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too big: %v", err)
	}
}

func TestArchiveUploadRoute(t *testing.T) {
	s, _, _ := migrateStore(t)
	data := fixtureArchive(t, "cpmove-fixtureacct", nil)
	head, _ := json.Marshal(map[string]any{"input": map[string]any{"size": len(data), "reason": "Move a website here"}, "actor": "test operator"})
	body := append(append(head, '\n'), data...)
	req := httptest.NewRequest("POST", "http://unix/v1/migrations/archive", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	handler(s).ServeHTTP(rec, req)
	var m Migration
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &m) != nil || m.Archive == nil || m.Archive.User != "fixtureacct" {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	// A size that does not match the body is refused before anything is kept.
	req = httptest.NewRequest("POST", "http://unix/v1/migrations/archive", bytes.NewReader(body[:len(body)-1]))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec = httptest.NewRecorder()
	handler(s).ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatalf("a short body was accepted: %s", rec.Body.String())
	}
}
