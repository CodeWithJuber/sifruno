package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/cpmove"
	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
)

// fakeMigrate is the migration engine with a cPanel server behind it: it
// answers the fixed commands with the documented shapes.
type fakeMigrate struct {
	mu       sync.Mutex
	folders  map[string]bool
	pinned   map[string]string
	commands []string
	answers  map[string]string
	// fails answers a command with this error output and exit code.
	fails     map[string]fakeFailure
	site      htaccess.SiteResult
	homeFile  bool
	removed   bool // the source's line is gone: the next sign-in is refused
	files     []string
	databases []string
	failFiles error
	// protection is what the copy converts to; Files hands it to protect.
	protection SiteProtection
	// copied runs when Files has put the files in the home.
	copied func()
	// archives are the uploaded backup files, by migration.
	archives map[string][]byte
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
			cpsource.ClientAddressCommand():      "203.0.113.5 51234 198.51.100.7 22\n",
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
	if fail, ok := f.fails[command]; ok {
		return []byte(fail.out), fail.code, nil
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
	if f.copied != nil && f.failFiles == nil {
		f.copied()
	}
	return MigrateFilesResult{WordPress: true}, f.failFiles
}
func (f *fakeMigrate) Database(_ context.Context, _ migrationRecord, db string, _ record, l backupLeftover) (MigrateDatabaseResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.databases = append(f.databases, db+" as "+l.Users[db])
	return MigrateDatabaseResult{Database: db, Tables: []MigrationTable{{Table: "wp_posts", Source: 3, Copy: 3}}}, nil
}
func (f *fakeMigrate) SaveArchive(ctx context.Context, id string, size int64, body io.Reader) (*cpmove.Archive, error) {
	data, err := io.ReadAll(io.LimitReader(body, size))
	if err != nil || int64(len(data)) != size {
		return nil, &MigrationError{Step: "archive", Detail: "short upload"}
	}
	f.mu.Lock()
	if f.archives == nil {
		f.archives = map[string][]byte{}
	}
	f.folders[id], f.archives[id] = true, data
	f.mu.Unlock()
	return f.ReadArchive(ctx, migrationRecord{ID: id, Via: ViaArchive})
}
func (f *fakeMigrate) ReadArchive(ctx context.Context, m migrationRecord) (*cpmove.Archive, error) {
	f.mu.Lock()
	data, ok := f.archives[m.ID]
	ok = ok && f.folders[m.ID]
	f.mu.Unlock()
	if !ok {
		return nil, ErrUnavailable
	}
	a, err := cpmove.Read(ctx, bytes.NewReader(data), cpmove.DefaultLimits(), discardArchive{})
	if err != nil {
		return nil, archiveFailure(err)
	}
	return a, nil
}

// discardArchive reads every member and keeps none, as the fake engine
// extracts nothing.
type discardArchive struct{}

func (discardArchive) Dir(string, fs.FileMode) error { return nil }
func (discardArchive) File(_ string, _ fs.FileMode, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}
func (discardArchive) Symlink(string, string) error { return nil }

func (f *fakeMigrate) Forget(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.folders, id)
	delete(f.archives, id)
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
	if plan.Domain != "fixture.test" || plan.PHPSource != "ea-php82" || plan.Tier != "native" || plan.DiskUsedMiB != 20 || len(plan.Cron) != 1 || plan.ClientAddress != "203.0.113.5" {
		t.Fatalf("plan: %+v", plan)
	}
	if len(plan.Users) != 1 || plan.Users[0].Hash == "" || !slices.Equal(plan.Users[0].Grants[0].Privileges, []string{"ALL PRIVILEGES"}) {
		t.Fatalf("users: %+v", plan.Users)
	}
	if items, _ := s.leftovers(); len(items) != 0 || len(b.cleaned) != 1 {
		t.Fatalf("the preflight's staging folder must be removed: %v %v", items, b.cleaned)
	}
	// A source whose sshd does not say where this server comes from still
	// plans; verify then fails the folders that depend on it.
	f.answers[cpsource.ClientAddressCommand()] = "\n"
	if plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator"); err != nil || plan.ClientAddress != "" {
		t.Fatalf("no client address: %q %v", plan.ClientAddress, err)
	}
	delete(f.answers, cpsource.ClientAddressCommand())
	if plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator"); err != nil || plan.ClientAddress != "" {
		t.Fatalf("a failed client address command: %q %v", plan.ClientAddress, err)
	}
	// An access rule the converter takes stays Native, with the conversion
	// and its probe in the plan.
	closed := htaccess.ClassifyFile("private/.htaccess", "/private/", []byte("Deny from all\n"))
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictCompat, Causes: []string{htaccess.CauseAccessControl}, Files: []htaccess.FileResult{closed}}
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier != "native" || len(plan.Converted) != 1 || plan.Converted[0].Path != "/private/" || !reflect.DeepEqual(plan.Probes, []MigrationProbe{{Path: "/private/", Kind: "deny"}}) {
		t.Fatalf("converted: %+v %v", plan, err)
	}
	// A folder open to some addresses only goes to verify with its rule.
	lobby := htaccess.ClassifyFile("lobby/.htaccess", "/lobby/", []byte("Order Allow,Deny\nAllow from all\nDeny from 192.0.2.0/24\n"))
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictCompat, Causes: []string{htaccess.CauseAccessControl}, Files: []htaccess.FileResult{lobby}}
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier != "native" || !reflect.DeepEqual(plan.Probes, []MigrationProbe{{Path: "/lobby/", Kind: "hosts", Hosts: "except", Networks: []string{"192.0.2.0/24"}}}) {
		t.Fatalf("address list: %+v %v", plan.Probes, err)
	}
	// One it refuses sends the site to Compat, saying why.
	refused := htaccess.ClassifyFile("private/.htaccess", "/private/", []byte("Deny from all\nSatisfy Any\n"))
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictCompat, Causes: []string{htaccess.CauseAccessControl}, Files: []htaccess.FileResult{refused}}
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier != "compat" || len(plan.TierRefusals) != 1 || !strings.Contains(plan.TierRefusals[0], "private/.htaccess line 2 (Satisfy Any)") || len(plan.Converted) != 0 {
		t.Fatalf("compat: %+v %v", plan, err)
	}
	if !plan.TierAccess || !slices.Equal(plan.TierFix, []string{"private/.htaccess line 2 (Satisfy Any)"}) {
		t.Fatalf("an access rule it cannot convert: access %t fix %q", plan.TierAccess, plan.TierFix)
	}
	// A typical cPanel WordPress root moves: the handler block names the
	// plan's PHP (ea-php82), the Expires and Header lines are harmless, and
	// php_value is a warning naming its line.
	root := htaccess.ClassifyFile(".htaccess", "/", []byte("<IfModule mime_module>\n  AddHandler application/x-httpd-ea-php82 .php .php8 .phtml\n</IfModule>\n"+
		"ExpiresActive On\nHeader set Cache-Control \"max-age=600\"\nphp_value upload_max_filesize 64M\n"))
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictNative, Files: []htaccess.FileResult{root}}
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier != "native" || len(plan.TierWarnings) != 1 || !strings.HasPrefix(plan.TierWarnings[0], ".htaccess line 6 (php_value upload_max_filesize 64M): OpenLiteSpeed does not apply PHP settings") {
		t.Fatalf("typical root: %+v %v", plan, err)
	}
	// A handler for another PHP version than the plan's is a warning too.
	legacy := htaccess.ClassifyFile("legacy/.htaccess", "/legacy/", []byte("AddHandler application/x-httpd-ea-php74 .php\n"))
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictNative, Files: []htaccess.FileResult{root, legacy}}
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier != "native" || len(plan.TierWarnings) != 2 || !strings.Contains(plan.TierWarnings[1], "legacy/.htaccess line 1 (AddHandler): the old server runs /legacy/ with PHP ea-php74") || !strings.Contains(plan.TierWarnings[1], "ea-php82") {
		t.Fatalf("another PHP version: %q %v", plan.TierWarnings, err)
	}
	// A line OpenLiteSpeed ignores that nothing covers is not an access
	// rule: the plan names it as a line to change.
	other := htaccess.ClassifyFile(".htaccess", "/", []byte("RewriteEngine On\nHeader set Set-Cookie a=b\n"))
	f.site = htaccess.SiteResult{Verdict: htaccess.VerdictConvertible, Files: []htaccess.FileResult{other}}
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier != "compat" || plan.TierAccess || !slices.Equal(plan.TierFix, []string{".htaccess line 2 (Header set Set-Cookie)"}) ||
		!slices.Equal(plan.TierCauses, []string{htaccess.CauseNotConverted}) || len(plan.TierWarnings) != 0 {
		t.Fatalf("not converted: %+v %v", plan, err)
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
	if _, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "someone", Reason: "Move a website here"}, "test operator"); !errors.As(err, &failed) || failed.Step != "account_missing" {
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
	if got.Revision != a.Revision {
		t.Fatalf("a copy without protected folders answered revision %d, not %d", got.Revision, a.Revision)
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
	if _, err = s.migrateFiles(ctx, other.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: other.Revision, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "account_missing" {
		t.Fatalf("a differently named account: %v", err)
	}
}

// TestMigrateFilesReloadsTheSiteAfterTheCopy: OpenLiteSpeed reads a site's
// .htaccess (its rewrite rules) only when it restarts, and the protected
// folders' restart runs before the files reach the home. So once the files
// are there and the web server's access is set, the unchanged site list is
// installed once more, a graceful restart, while the account is still busy
// (D-0004). Before, the copy, its preview and verify ran without the
// site's rewrites until some later restart.
func TestMigrateFilesReloadsTheSiteAfterTheCopy(t *testing.T) {
	s, f, _ := migrateStore(t)
	native := s.native.(*fakeNative)
	s.web = &WebOptions{ServerUser: "nobody"}
	ctx := context.Background()
	m := pinnedMigration(t, s)
	live := liveFixture(t, s)
	f.protection = fixtureProtection(live.Account.ID)
	appliesAtCopy, grantsAtCopy := -1, -1
	f.copied = func() { appliesAtCopy, grantsAtCopy = native.siteApplies, native.webGrants }
	got, err := s.migrateFiles(ctx, live.Account.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: live.Account.Revision, Reason: "Move a website here"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if appliesAtCopy < 0 || native.siteApplies != appliesAtCopy+1 || native.webGrants != grantsAtCopy+1 {
		t.Fatalf("site list installs: %d when the files were copied, %d after", appliesAtCopy, native.siteApplies)
	}
	// The reload installs the site list as it is, folders included, and
	// changes no record.
	if site := siteOf(t, native.sites, live.Account.ID); len(site.Folders) != 2 {
		t.Fatalf("site %+v", site)
	}
	if r := recordFor(t, s, live.Account.ID); r.Account.Revision != got.Revision || r.Pending != nil || len(s.installing) != 0 {
		t.Fatalf("record %+v, answered revision %d", r, got.Revision)
	}

	// A reload that fails stops the move with a reason of its own.
	s2, f2, _ := migrateStore(t)
	native2 := s2.native.(*fakeNative)
	s2.web = &WebOptions{ServerUser: "nobody"}
	m2 := pinnedMigration(t, s2)
	live2 := liveFixture(t, s2)
	f2.copied = func() { native2.failure = "sites" }
	_, err = s2.migrateFiles(ctx, live2.Account.ID, MigrateFilesInput{Migration: m2.ID, ExpectedRevision: live2.Account.Revision, Reason: "Move a website here"}, "test operator")
	var failed *MigrationError
	if !errors.As(err, &failed) || failed.Step != "reload" || !strings.Contains(failed.Detail, "The files are in place") || len(s2.installing) != 0 {
		t.Fatalf("a failed reload: %v", err)
	}

	// A site that is not live has nothing to reload.
	s3, _, _ := migrateStore(t)
	native3 := s3.native.(*fakeNative)
	m3 := pinnedMigration(t, s3)
	a := createFixture(t, s3)
	before := native3.siteApplies
	if _, err = s3.migrateFiles(ctx, a.ID, MigrateFilesInput{Migration: m3.ID, ExpectedRevision: a.Revision, Reason: "Move a website here"}, "test operator"); err != nil || native3.siteApplies != before {
		t.Fatalf("not live: %d installs, %v", native3.siteApplies-before, err)
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

type fakeFailure struct {
	out  string
	code int
}

// TestMigrationFailuresAreNamed: every way the old server fails gets its
// own step, so the panel can say what happened and what to do (D-0006),
// and what the old server printed travels apart from the broker's words:
// the panel shows it only under Technical details.
func TestMigrationFailuresAreNamed(t *testing.T) {
	preload := "2026/01/02 03:04:05 LD_Preload detected, refusing to run 2026/01/02 03:04:05 libinjected.so.1 The subprocess reported error number 3 when it ended. at bin/apitool.pl line 369."
	for _, c := range []struct {
		name, out, step, detail string
		code                    int
		answer                  string
	}{
		{name: "a cPanel tool that refuses to run", out: preload, code: 3, step: "cpanel_tool"},
		{name: "a cPanel tool that prints no JSON", answer: "LD_Preload detected, refusing to run", step: "cpanel_output", detail: "whmapi1 listaccts"},
		{name: "the key refused", out: "root@203.0.113.9: Permission denied (publickey).", code: 255, step: "key_refused"},
		{name: "another host key", out: "Host key verification failed.", code: 255, step: "host_key_changed"},
		{name: "no answer", out: "ssh: connect to host 203.0.113.9 port 22: Connection timed out", code: 255, step: "unreachable"},
		{name: "an ssh failure ssh does not name", out: "ssh: something else", code: 255, step: "connect"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, f, _ := migrateStore(t)
			m := pinnedMigration(t, s)
			if c.answer != "" {
				f.answers[cpsource.ListAccountsCommand()] = c.answer
			} else {
				f.fails = map[string]fakeFailure{cpsource.ListAccountsCommand(): {c.out, c.code}}
			}
			_, err := s.migrationAccounts(context.Background(), m.ID)
			var failed *MigrationError
			if !errors.As(err, &failed) || failed.Step != c.step || !strings.Contains(failed.Detail, c.detail) {
				t.Fatalf("%+v %v", failed, err)
			}
			if c.out != "" && (failed.Output != installDetail([]byte(c.out)) || strings.Contains(failed.Detail, c.out)) {
				t.Fatalf("the old server's output is not kept apart: %+v", failed)
			}
		})
	}
	s, _, _ := migrateStore(t)
	m := pinnedMigration(t, s)
	var failed *MigrationError
	if _, err := s.planMigration(context.Background(), m.ID, MigrationPlanInput{Username: "someone", Reason: "Move a website here"}, "test operator"); !errors.As(err, &failed) || failed.Step != "account_missing" || failed.Output != "" {
		t.Fatalf("an account the old server does not have: %+v %v", failed, err)
	}
}

// fixtureAnswers are WHM's answers for fixtureacct, as the panel relays
// them: the same documents whmapi1 and uapi print over SSH.
func fixtureAnswers(f *fakeMigrate) *CPanelAnswers {
	return &CPanelAnswers{
		Accounts:      json.RawMessage(f.answers[cpsource.ListAccountsCommand()]),
		Site:          json.RawMessage(f.answers["/usr/local/cpanel/bin/whmapi1 --output=json domainuserdata domain=fixture.test"]),
		PHP:           json.RawMessage(f.answers[cpsource.VhostPHPCommand()]),
		Databases:     json.RawMessage(f.answers["/usr/local/cpanel/bin/uapi --output=json --user=fixtureacct Mysql list_databases"]),
		DatabaseUsers: json.RawMessage(f.answers["/usr/local/cpanel/bin/uapi --output=json --user=fixtureacct Mysql list_users"]),
	}
}

// A migration connected with the old server's WHM login takes what the
// copy asks of cPanel from the panel, which read it through WHM's API, and
// never runs whmapi1 or uapi over SSH, where a broken or hijacked cPanel
// on the old server refuses (D-0005). rsync, the dump and SQL still run
// over SSH. An SSH migration takes no answers from the panel.
func TestWHMMigrationTakesCPanelAnswersFromThePanel(t *testing.T) {
	s, f, _ := migrateStore(t)
	ctx := context.Background()
	opened, err := s.openMigration(ctx, MigrationOpenInput{Host: "source.example.test", Port: 22, Via: ViaWHM, Reason: "Move a website here"}, "test operator")
	if err != nil || opened.Via != ViaWHM {
		t.Fatalf("open: %+v %v", opened, err)
	}
	if _, err = s.openMigration(ctx, MigrationOpenInput{Host: "source.example.test", Port: 22, Via: "ftp", Reason: "x"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another way in: %v", err)
	}
	m, err := s.pinMigrationHostKey(ctx, opened.ID, MigrationPinInput{Fingerprint: opened.HostKeys[0].Fingerprint, Reason: "Fingerprint checked"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	answers := fixtureAnswers(f)
	if _, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", Reason: "x"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a plan without WHM's answers: %v", err)
	}
	if _, err = s.migrationAccounts(ctx, m.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the broker listed a WHM migration's accounts: %v", err)
	}
	plan, err := s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", CPanel: answers, Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Domain != "fixture.test" || plan.PHPSource != "ea-php82" || len(plan.Databases) != 1 || len(plan.Users) != 1 || plan.Users[0].Hash == "" || len(plan.Cron) != 1 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	a := createFixture(t, s)
	if _, err = s.migrateFiles(ctx, a.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: a.Revision, Reason: "x"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a copy without WHM's answers: %v", err)
	}
	if _, err = s.migrateFiles(ctx, a.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: a.Revision, CPanel: answers, Reason: "Move a website here"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.migrateDatabase(ctx, a.ID, MigrateDatabaseInput{Migration: m.ID, Database: "fixtureacct_wp", ExpectedRevision: a.Revision, CPanel: answers, Reason: "Move a website here"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.commands {
		if strings.Contains(c, "/usr/local/cpanel/") {
			t.Fatalf("a cPanel tool ran over SSH for a WHM migration: %s", c)
		}
	}
	// An answer that is not WHM's documented JSON is named as such.
	bad := *answers
	bad.Accounts = json.RawMessage(`"LD_Preload detect"`)
	var failed *MigrationError
	if _, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "fixtureacct", CPanel: &bad, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "cpanel_output" {
		t.Fatalf("an answer that is not JSON: %v", err)
	}
	ssh := pinnedMigration(t, s)
	if _, err = s.planMigration(ctx, ssh.ID, MigrationPlanInput{Username: "fixtureacct", CPanel: answers, Reason: "x"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an SSH migration took the panel's answers: %v", err)
	}

	// Over the broker's HTTP: via and cpanel are accepted keys, and a
	// failure carries the old server's output apart from the broker's words.
	h := handler(s)
	call := func(method, path string, payload any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(method, "http://unix"+path, strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := call("POST", "/v1/migrations", map[string]any{"actor": "test operator", "input": map[string]any{"host": "source.example.test", "port": 22, "via": "whm", "reason": "x"}})
	var viaHTTP Migration
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &viaHTTP) != nil || viaHTTP.Via != ViaWHM {
		t.Fatalf("open over HTTP: %d %s", rec.Code, rec.Body)
	}
	rec = call("POST", "/v1/migrations/"+m.ID+"/plan", map[string]any{"actor": "test operator", "input": map[string]any{"username": "fixtureacct", "cpanel": answers, "reason": "x"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"domain":"fixture.test"`) {
		t.Fatalf("plan over HTTP: %d %s", rec.Code, rec.Body)
	}
	f.fails = map[string]fakeFailure{"/usr/bin/crontab -l -u fixtureacct": {"crontab: LD_Preload detect", 3}}
	rec = call("POST", "/v1/migrations/"+m.ID+"/plan", map[string]any{"actor": "test operator", "input": map[string]any{"username": "fixtureacct", "cpanel": answers, "reason": "x"}})
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"step":"source"`) || !strings.Contains(rec.Body.String(), `"output":"crontab: LD_Preload detect"`) {
		t.Fatalf("a failure over HTTP: %d %s", rec.Code, rec.Body)
	}
}
