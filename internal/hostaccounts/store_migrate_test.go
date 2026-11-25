package hostaccounts

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
)

// fakeMigrate is the migration engine with a cPanel server behind it: it
// answers the fixed commands with the documented shapes.
type fakeMigrate struct {
	mu        sync.Mutex
	folders   map[string]bool
	pinned    map[string]string
	commands  []string
	answers   map[string]string
	site      htaccess.SiteResult
	homeFile  bool
	removed   bool // the source's line is gone: the next sign-in is refused
	files     []string
	databases []string
	failFiles error
	// protection is what the copy converts to; Files hands it to protect.
	protection SiteProtection
}

func newFakeMigrate() *fakeMigrate {
	hash := "*" + strings.Repeat("AB", 20)
	return &fakeMigrate{folders: map[string]bool{}, pinned: map[string]string{}, site: htaccess.SiteResult{Verdict: htaccess.VerdictNative},
		answers: map[string]string{
			cpsource.ListAccountsCommand(): `{"data":{"acct":[{"user":"fixtureacct","domain":"fixture.test","diskused":"20M","disklimit":"unlimited","suspended":0}]},"metadata":{"result":1}}`,
			"/usr/local/cpanel/bin/whmapi1 --output=json domainuserdata domain=fixture.test": `{"data":{"userdata":{"user":"fixtureacct","homedir":"/home/fixtureacct","documentroot":"/home/fixtureacct/public_html","servername":"fixture.test","serveralias":"www.fixture.test"}}}`,
			cpsource.VhostPHPCommand(): `{"data":{"versions":[{"account":"fixtureacct","vhost":"fixture.test","version":"ea-php82"}]}}`,
			"/usr/local/cpanel/bin/uapi --output=json --user=fixtureacct Mysql list_databases": `{"result":{"data":[{"database":"fixtureacct_wp","users":["fixtureacct_wpu"]}],"status":1}}`,
			"/usr/local/cpanel/bin/uapi --output=json --user=fixtureacct Mysql list_users":     `{"result":{"data":[{"user":"fixtureacct_wpu","databases":["fixtureacct_wp"]}],"status":1}}`,
			cpsource.SQLCommand():                "sifruno-user\tfixtureacct_wpu\nCREATE USER `fixtureacct_wpu`@`localhost` IDENTIFIED BY PASSWORD '" + hash + "'\nsifruno-grant\tfixtureacct_wpu\tfixtureacct\\_wp\t" + strings.TrimSuffix(strings.Repeat("Y\t", 18), "\t") + "\n",
			"/usr/bin/crontab -l -u fixtureacct": "*/5 * * * * php /home/fixtureacct/public_html/wp-cron.php\n",
		}}
}

func (f *fakeMigrate) Open(id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.folders[id] = true
	return fixtureHostKey, nil
}
func (f *fakeMigrate) Scan(context.Context, string, int) ([]byte, error) {
	return []byte("source.example.test " + fixtureHostKey + "\n"), nil
}
func (f *fakeMigrate) Pin(id, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned[id] = key
	return nil
}
func (f *fakeMigrate) Remote(_ context.Context, m migrationRecord, command string, _ io.Reader, stdout io.Writer, _ time.Duration) ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, command)
	if f.removed || !f.folders[m.ID] || f.pinned[m.ID] == "" {
		return []byte("root@source: Permission denied (publickey)."), 255, nil
	}
	if remove, _ := cpsource.RemoveKeyCommand(m.ID); command == remove {
		f.removed = true
		return nil, 0, nil
	}
	answer, ok := f.answers[command]
	if !ok {
		return []byte("unexpected command"), 1, nil
	}
	if stdout == nil {
		return []byte(answer), 0, nil
	}
	io.WriteString(stdout, answer)
	return nil, 0, nil
}
func (f *fakeMigrate) Preflight(context.Context, migrationRecord, string, backupLeftover) (htaccess.SiteResult, bool, error) {
	return f.site, f.homeFile, nil
}
func (f *fakeMigrate) Files(_ context.Context, _ migrationRecord, home string, r record, _ int64, _ backupLeftover, protect func(SiteProtection) error) (MigrateFilesResult, error) {
	f.mu.Lock()
	protection := f.protection
	f.files = append(f.files, home+" -> "+r.Account.Username)
	f.mu.Unlock()
	if len(protection.Folders) > 0 {
		if err := protect(protection); err != nil {
			return MigrateFilesResult{}, err
		}
	}
	return MigrateFilesResult{WordPress: true}, f.failFiles
}
func (f *fakeMigrate) Database(_ context.Context, _ migrationRecord, db string, _ record, l backupLeftover) (MigrateDatabaseResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.databases = append(f.databases, db+" as "+l.Users[db])
	return MigrateDatabaseResult{Database: db, Tables: []MigrationTable{{Table: "wp_posts", Source: 3, Copy: 3}}}, nil
}
func (f *fakeMigrate) Forget(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.folders, id)
	return nil
}
func (f *fakeMigrate) Folders() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id := range f.folders {
		out = append(out, id)
	}
	return out, nil
}

func migrateStore(t *testing.T) (*store, *fakeMigrate, *fakeBackup) {
	t.Helper()
	s, b := backupStore(t)
	f := newFakeMigrate()
	s.migrate = f
	return s, f, b
}

func openFixtureMigration(t *testing.T, s *store) Migration {
	t.Helper()
	m, err := s.openMigration(context.Background(), MigrationOpenInput{Host: "source.example.test", Port: 22, Reason: "Move a website here"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMigrationNeedsTheConfirmedHostKey(t *testing.T) {
	s, f, _ := migrateStore(t)
	ctx := context.Background()
	m := openFixtureMigration(t, s)
	if !strings.HasPrefix(m.PublicKey, "restrict ssh-ed25519 ") || !strings.HasSuffix(m.PublicKey, " sifruno-migration-"+m.ID) || len(m.HostKeys) != 1 || m.Pinned != "" {
		t.Fatalf("opened: %+v", m)
	}
	if !strings.Contains(m.InstallCommand, ">> /root/.ssh/authorized_keys") {
		t.Fatalf("install command %q", m.InstallCommand)
	}
	var failed *MigrationError
	if _, err := s.migrationAccounts(ctx, m.ID); !errors.As(err, &failed) || failed.Step != "host_key" {
		t.Fatalf("accounts before the host key: %v", err)
	}
	if len(f.commands) != 0 {
		t.Fatal("a command ran on a server whose host key nobody confirmed")
	}
	if _, err := s.pinMigrationHostKey(ctx, m.ID, MigrationPinInput{Fingerprint: "SHA256:" + strings.Repeat("A", 43), Reason: "Fingerprint checked"}, "test operator"); !errors.As(err, &failed) || failed.Step != "host_key" {
		t.Fatalf("a wrong fingerprint: %v", err)
	}
	pinned, err := s.pinMigrationHostKey(ctx, m.ID, MigrationPinInput{Fingerprint: m.HostKeys[0].Fingerprint, Reason: "Fingerprint checked"}, "test operator")
	if err != nil || pinned.Pinned != m.HostKeys[0].Fingerprint || f.pinned[m.ID] != fixtureHostKey {
		t.Fatalf("pin: %+v %v", pinned, err)
	}
	items, err := s.migrationAccounts(ctx, m.ID)
	if err != nil || len(items) != 1 || items[0].User != "fixtureacct" {
		t.Fatalf("accounts: %+v %v", items, err)
	}
}

func pinnedMigration(t *testing.T, s *store) Migration {
	t.Helper()
	m := openFixtureMigration(t, s)
	m, err := s.pinMigrationHostKey(context.Background(), m.ID, MigrationPinInput{Fingerprint: m.HostKeys[0].Fingerprint, Reason: "Fingerprint checked"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMigrationPlanReadsTheAccount(t *testing.T) {
	s, f, b := migrateStore(t)
	ctx := context.Background()
	m := pinnedMigration(t, s)
	plan, err := s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Domain != "fixture.test" || plan.PHPSource != "ea-php82" || plan.Tier != "native" || plan.DiskUsedMiB != 20 || len(plan.Cron) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	if len(plan.Users) != 1 || plan.Users[0].Hash == "" || !slices.Equal(plan.Users[0].Grants[0].Privileges, []string{"ALL PRIVILEGES"}) {
		t.Fatalf("users: %+v", plan.Users)
	}
	if items, _ := s.leftovers(); len(items) != 0 || len(b.cleaned) != 1 {
		t.Fatalf("the preflight's staging folder must be removed: %v %v", items, b.cleaned)
	}
	// An access rule the converter takes stays Native, with the conversion
	// and its probe in the plan.
	closed := htaccess.ClassifyFile("private/.htaccess", "/private/", []byte("Deny from all\n"))
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictCompat, Causes: []string{htaccess.CauseAccessControl}, Files: []htaccess.FileResult{closed}}
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier != "native" || len(plan.Converted) != 1 || plan.Converted[0].Path != "/private/" || !slices.Equal(plan.Probes, []MigrationProbe{{Path: "/private/", Kind: "deny"}}) {
		t.Fatalf("converted: %+v %v", plan, err)
	}
	// One it refuses sends the site to Compat, saying why.
	refused := htaccess.ClassifyFile("private/.htaccess", "/private/", []byte("Deny from all\nSatisfy Any\n"))
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictCompat, Causes: []string{htaccess.CauseAccessControl}, Files: []htaccess.FileResult{refused}}
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier != "compat" || len(plan.TierRefusals) != 1 || !strings.Contains(plan.TierRefusals[0], "private/.htaccess line 2") || len(plan.Converted) != 0 {
		t.Fatalf("compat: %+v %v", plan, err)
	}
	// A verdict no file accounts for fails closed.
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictCompat, Causes: []string{htaccess.CauseAccessControl}}
	if plan, _ = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator"); plan.Tier != "compat" {
		t.Fatalf("no file: %+v", plan)
	}
	f.site, f.homeFile = htaccess.SiteResult{Verdict: htaccess.VerdictNative}, true
	if plan, _ = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator"); plan.Tier != "compat" || !slices.Contains(plan.TierCauses, "home_htaccess") {
		t.Fatalf("a home .htaccess: %+v", plan)
	}
	var failed *MigrationError
	if _, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "someone", Reason: "Move a website here"}, "test operator"); !errors.As(err, &failed) || failed.Step != "source" {
		t.Fatalf("an account the source does not have: %v", err)
	}
}

func TestMigrateCopiesOnlyTheSameNamedAccount(t *testing.T) {
	s, f, _ := migrateStore(t)
	ctx := context.Background()
	m := pinnedMigration(t, s)
	a := createFixture(t, s)
	got, err := s.migrateFiles(ctx, a.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: a.Revision, Reason: "Move a website here"}, "test operator")
	if err != nil || !got.WordPress || !slices.Equal(f.files, []string{"/home/fixtureacct -> fixtureacct"}) {
		t.Fatalf("files: %+v %v %v", got, err, f.files)
	}
	if len(s.installing) != 0 {
		t.Fatal("the account stayed busy")
	}
	if _, err = s.migrateFiles(ctx, a.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: a.Revision + 1, Reason: "x"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a stale revision: %v", err)
	}
	db, err := s.migrateDatabase(ctx, a.ID, MigrateDatabaseInput{Migration: m.ID, Database: "fixtureacct_wp", ExpectedRevision: a.Revision, Reason: "Move a website here"}, "test operator")
	if err != nil || db.Database != "fixtureacct_wp" || len(f.databases) != 1 || !strings.Contains(f.databases[0], " as sifruno_rst_") {
		t.Fatalf("database: %+v %v %v", db, err, f.databases)
	}
	for _, name := range []string{"otheracct_wp", "fixtureacct_shop"} {
		_, err = s.migrateDatabase(ctx, a.ID, MigrateDatabaseInput{Migration: m.ID, Database: name, ExpectedRevision: a.Revision, Reason: "x"}, "test operator")
		var failed *MigrationError
		if !errors.Is(err, ErrInvalid) && !(errors.As(err, &failed) && failed.Step == "database") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Another account here is not the source's fixtureacct.
	other := createFixtureNamed(t, s, "otheracct", "fixture.test.example")
	var failed *MigrationError
	if _, err = s.migrateFiles(ctx, other.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: other.Revision, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "source" {
		t.Fatalf("a differently named account: %v", err)
	}
}

func TestFinishRemovesTheKeyEverywhere(t *testing.T) {
	s, f, _ := migrateStore(t)
	ctx := context.Background()
	m := pinnedMigration(t, s)
	got, err := s.finishMigration(ctx, m.ID, MigrationFinishInput{Reason: "Migration ended"}, "test operator")
	if err != nil || !got.RemovedFromSource || f.folders[m.ID] {
		t.Fatalf("finish: %+v %v", got, err)
	}
	if _, err = s.getMigration(ctx, m.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the record outlived the finish: %v", err)
	}
	// A source that does not run the removal: the local key still goes and
	// the answer says what to remove by hand.
	f.removed = false
	m = pinnedMigration(t, s)
	f.answers = map[string]string{}
	broken := &fakeRemoveFails{fakeMigrate: f}
	s.migrate = broken
	got, err = s.finishMigration(ctx, m.ID, MigrationFinishInput{Reason: "Migration ended"}, "test operator")
	if err != nil || got.RemovedFromSource || !strings.Contains(got.Detail, "sifruno-migration-"+m.ID) || f.folders[m.ID] {
		t.Fatalf("a failed removal: %+v %v", got, err)
	}
}

type fakeRemoveFails struct{ *fakeMigrate }

func (f *fakeRemoveFails) Remote(_ context.Context, _ migrationRecord, _ string, _ io.Reader, _ io.Writer, _ time.Duration) ([]byte, int, error) {
	return []byte("sed: couldn't open temporary file"), 4, nil
}

func expire(t *testing.T, s *store, id string) {
	t.Helper()
	rec, err := s.anyMigration(id)
	if err != nil {
		t.Fatal(err)
	}
	rec.CreatedAt = rec.CreatedAt.Add(-migrationLifetime - time.Minute)
	if err = s.putMigration(rec); err != nil {
		t.Fatal(err)
	}
}

func sweep(t *testing.T, s *store) {
	t.Helper()
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	if err := s.sweepMigrations(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

// An expired migration's line is removed from the source with the key the
// broker still holds before the key is forgotten; only what is proved
// removed is not recorded as a stale line.
func TestExpiredMigrationsRemoveTheirKeyLine(t *testing.T) {
	s, f, _ := migrateStore(t)
	ctx := context.Background()
	m := pinnedMigration(t, s)
	expire(t, s, m.ID)
	if _, err := s.getMigration(ctx, m.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired migration is still served: %v", err)
	}
	f.folders[strings.Repeat("d", 32)] = true // a folder no record names
	sweep(t, s)
	if len(f.folders) != 0 || !f.removed {
		t.Fatalf("folders left %v, line removed %v", f.folders, f.removed)
	}
	if items, _ := s.staleKeys(); len(items) != 0 {
		t.Fatalf("a removed line was recorded as stale: %+v", items)
	}
	// A source that does not remove the line: it is recorded, with the
	// exact line and server, and never reported removed.
	f.removed = false
	m = pinnedMigration(t, s)
	expire(t, s, m.ID)
	s.migrate = &fakeRemoveFails{fakeMigrate: f}
	sweep(t, s)
	items, err := s.staleKeys()
	if err != nil || len(items) != 1 || items[0].ID != m.ID || items[0].Host != "source.example.test" || items[0].Comment != "sifruno-migration-"+m.ID ||
		!strings.Contains(items[0].Detail, "sifruno-migration-"+m.ID+" from /root/.ssh/authorized_keys on source.example.test") {
		t.Fatalf("stale lines: %+v %v", items, err)
	}
	if f.folders[m.ID] {
		t.Fatal("the expired key stayed on this server")
	}
	// A job finishing it later hears the same, not "removed".
	got, err := s.finishMigration(ctx, m.ID, MigrationFinishInput{Reason: "Migration ended"}, "test operator")
	if err != nil || got.RemovedFromSource || !strings.Contains(got.Detail, "on source.example.test") {
		t.Fatalf("finish of an expired migration: %+v %v", got, err)
	}
	listed, err := s.listStaleKeys(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list: %+v %v", listed, err)
	}
	if err = s.clearStaleKey(ctx, m.ID, MigrationFinishInput{Reason: "Removed by hand"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if items, _ = s.staleKeys(); len(items) != 0 {
		t.Fatalf("cleared line still listed: %+v", items)
	}
	if _, err = s.finishMigration(ctx, m.ID, MigrationFinishInput{Reason: "x"}, "test operator"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown migration: %v", err)
	}
	// Never signed in (no confirmed host key): recorded, as the admin may
	// have added the line anyway.
	s.migrate = f
	m = openFixtureMigration(t, s)
	expire(t, s, m.ID)
	sweep(t, s)
	if items, _ = s.staleKeys(); len(items) != 1 || !strings.Contains(items[0].Detail, "never confirmed") {
		t.Fatalf("an unconfirmed expired migration: %+v", items)
	}
}

// A finish whose removal the source refuses keeps the line as stale.
func TestFinishKeepsALineItCouldNotRemove(t *testing.T) {
	s, f, _ := migrateStore(t)
	m := pinnedMigration(t, s)
	s.migrate = &fakeRemoveFails{fakeMigrate: f}
	got, err := s.finishMigration(context.Background(), m.ID, MigrationFinishInput{Reason: "Migration ended"}, "test operator")
	if err != nil || got.RemovedFromSource {
		t.Fatalf("finish: %+v %v", got, err)
	}
	if items, _ := s.staleKeys(); len(items) != 1 || items[0].ID != m.ID {
		t.Fatalf("stale lines: %+v", items)
	}
}

func TestMigrationInputsAreChecked(t *testing.T) {
	for _, host := range []string{"", "localhost", "127.0.0.1", "::1", "2001:db8::1", "-oProxyCommand=x", "a b.test", "UPPER.test", "0.0.0.0"} {
		if validMigrationOpen(MigrationOpenInput{Host: host, Port: 22, Reason: "x"}, "a") {
			t.Errorf("%q accepted", host)
		}
	}
	if !validMigrationOpen(MigrationOpenInput{Host: "203.0.113.5", Port: 2222, Reason: "x"}, "a") {
		t.Error("an IPv4 address refused")
	}
	if validMigrationPin(MigrationPinInput{Fingerprint: "MD5:aa", Reason: "x"}, "a") {
		t.Error("an MD5 fingerprint accepted")
	}
	rsh, ok := migrateRsh("/var/lib/sifruno-broker/migrate/"+strings.Repeat("a", 32), 22)
	if !ok || strings.ContainsAny(rsh, "'\"\\") {
		t.Fatalf("rsh %q", rsh)
	}
	if _, ok := migrateRsh("/var/lib/with space", 22); ok {
		t.Fatal("a folder with a space went into rsync's ssh command")
	}
}
