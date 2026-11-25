package wizard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"sifruno/internal/cpsource"
	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/migrateverify"
)

const testHash = "*0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A"

var sourceID = strings.Repeat("c", 32)

// fakeMigrationBroker is the broker's migration surface with a cPanel
// account behind it.
type fakeMigrationBroker struct {
	mu       sync.Mutex
	order    *journal
	plan     hostaccounts.MigrationPlan
	planErr  error
	filesErr error
	// filesResult is what MigrateFiles answers besides WordPress.
	filesResult hostaccounts.MigrateFilesResult
	dbErr       error
	tables      []hostaccounts.MigrationTable
	pinned      bool
	finished    int
	cron        []hostaccounts.CronJob
	accounts    *fakeAccounts
	removedOK   bool
	finishErr   error
	detail      string
}

func (f *fakeMigrationBroker) GetMigration(_ context.Context, id string) (hostaccounts.Migration, error) {
	if id != sourceID {
		return hostaccounts.Migration{}, hostaccounts.ErrNotFound
	}
	m := hostaccounts.Migration{ID: id, Host: "old.example.test", Port: 22}
	if f.pinned {
		m.Pinned = "SHA256:abc"
	}
	return m, nil
}
func (f *fakeMigrationBroker) PlanMigration(_ context.Context, id string, in hostaccounts.MigrationPlanInput, _ string) (hostaccounts.MigrationPlan, error) {
	f.order.add("plan " + in.Username)
	return f.plan, f.planErr
}

// revision checks an expected revision as the broker does, and raises it
// when the operation changes the account.
func (f *fakeMigrationBroker) revision(id string, expected uint64, raise bool) error {
	f.accounts.mu.Lock()
	defer f.accounts.mu.Unlock()
	for i := range f.accounts.accounts {
		if f.accounts.accounts[i].ID == id {
			if f.accounts.accounts[i].Revision != expected {
				return hostaccounts.ErrConflict
			}
			if raise {
				f.accounts.accounts[i].Revision++
			}
			return nil
		}
	}
	return hostaccounts.ErrNotFound
}
func (f *fakeMigrationBroker) MigrateFiles(_ context.Context, id string, in hostaccounts.MigrateFilesInput, _ string) (hostaccounts.MigrateFilesResult, error) {
	f.order.add(fmt.Sprintf("files %s rev=%d", id[28:], in.ExpectedRevision))
	if f.filesErr != nil {
		return hostaccounts.MigrateFilesResult{}, f.filesErr
	}
	res := f.filesResult
	res.WordPress = true
	// Protected folders go live as a journaled change of the account.
	if err := f.revision(id, in.ExpectedRevision, len(res.Folders) > 0); err != nil {
		return hostaccounts.MigrateFilesResult{}, err
	}
	res.Revision = in.ExpectedRevision
	if len(res.Folders) > 0 {
		res.Revision++
	}
	return res, nil
}
func (f *fakeMigrationBroker) MigrateDatabase(_ context.Context, id string, in hostaccounts.MigrateDatabaseInput, _ string) (hostaccounts.MigrateDatabaseResult, error) {
	f.order.add("copy-db " + in.Database)
	if f.dbErr != nil {
		return hostaccounts.MigrateDatabaseResult{}, f.dbErr
	}
	if err := f.revision(id, in.ExpectedRevision, false); err != nil {
		return hostaccounts.MigrateDatabaseResult{}, err
	}
	tables := f.tables
	if tables == nil {
		tables = []hostaccounts.MigrationTable{{Table: "wp_posts", Source: 3, Copy: 3}}
	}
	return hostaccounts.MigrateDatabaseResult{Database: in.Database, Tables: tables}, nil
}
func (f *fakeMigrationBroker) FinishMigration(context.Context, string, hostaccounts.MigrationFinishInput, string) (hostaccounts.MigrationFinishResult, error) {
	f.order.add("finish")
	f.mu.Lock()
	f.finished++
	f.mu.Unlock()
	return hostaccounts.MigrationFinishResult{RemovedFromSource: f.removedOK, Detail: f.detail}, f.finishErr
}
func (f *fakeMigrationBroker) SetCron(_ context.Context, id string, in hostaccounts.CronInput, _ string) (hostaccounts.CronResult, error) {
	f.order.add(fmt.Sprintf("cron %s %d", id[28:], len(in.Jobs)))
	f.cron = in.Jobs
	f.accounts.mu.Lock()
	defer f.accounts.mu.Unlock()
	for i := range f.accounts.accounts {
		if f.accounts.accounts[i].ID == id {
			if f.accounts.accounts[i].Revision != in.ExpectedRevision {
				return hostaccounts.CronResult{}, hostaccounts.ErrConflict
			}
			f.accounts.accounts[i].Revision++
			return hostaccounts.CronResult{Account: f.accounts.accounts[i]}, nil
		}
	}
	return hostaccounts.CronResult{}, hostaccounts.ErrNotFound
}

type hashDatabases struct{ *fakeDatabases }

func (h hashDatabases) CreateUserWithHashStrict(_ context.Context, owner, name, hash string) error {
	h.record("create-user-hash " + owner + " " + name)
	if hash != testHash {
		return errors.New("wrong hash")
	}
	return h.create("user", name)
}

func migrationPlan() hostaccounts.MigrationPlan {
	return hostaccounts.MigrationPlan{
		Username: "shopone", Domain: "shop.example.test", WWW: true, PHPSource: "ea-php81", DiskUsedMiB: 40, Tier: "native",
		Databases: []cpsource.Database{{Name: "shopone_wp", Users: []string{"shopone_wpu"}}},
		Users:     []cpsource.DatabaseUser{{Name: "shopone_wpu", Hash: testHash, Grants: []cpsource.Grant{{Database: "shopone_wp", Privileges: []string{"ALL PRIVILEGES"}}}}},
		Cron:      []cpsource.CronLine{{Schedule: "*/15 * * * *", Command: "php /home/shopone/public_html/wp-cron.php"}},
		Probes:    []hostaccounts.MigrationProbe{{Path: "/private/", Kind: "deny"}},
	}
}

type migrationFixture struct {
	fixture
	broker  *fakeMigrationBroker
	verify  []migrateverify.Options
	verdict migrateverify.Report
}

func newMigrationFixture(t *testing.T) *migrationFixture {
	f := &migrationFixture{fixture: newFixture(t)}
	f.broker = &fakeMigrationBroker{order: f.order, plan: migrationPlan(), pinned: true, accounts: f.acc, removedOK: true}
	f.verdict = migrateverify.Report{CutoverAllowed: true, Verdict: "CUTOVER ALLOWED: every compared page and closed URL matches the old site", Counts: migrateverify.Counts{PagesCompared: 5, PagesPass: 5, ProbesPass: 1}}
	f.runner.EnableMigrations(MigrationOptions{Broker: f.broker, Databases: hashDatabases{f.dbs}, Connect: "127.0.0.1:80", Address: "203.0.113.7",
		Verify: func(_ context.Context, o migrateverify.Options) (migrateverify.Report, error) {
			f.verify = append(f.verify, o)
			return f.verdict, nil
		}})
	return f
}

func (f *migrationFixture) migrate(t *testing.T) Job {
	t.Helper()
	job, err := f.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "shopone"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	f.runner.Wait()
	done, ok := f.runner.Get(job.ID)
	if !ok {
		t.Fatal("job lost")
	}
	return done
}

func TestMigrationCopiesInOrderAndOpensTheGate(t *testing.T) {
	f := newMigrationFixture(t)
	job := f.migrate(t)
	if job.State != StateSucceeded || job.Domain != "shop.example.test" || job.Result.AccountID == "" || job.Result.AdminURL != "http://shop.example.test/wp-admin/" {
		t.Fatalf("job: %+v %+v", job, job.Error)
	}
	m := job.Migration
	if m.Gate != GateOpen || !m.KeyRemoved || !m.WordPress || !slices.Equal(m.Databases, []string{"shopone_wp"}) || !slices.Equal(m.DatabaseUsers, []string{"shopone_wpu"}) {
		t.Fatalf("migration: %+v", m)
	}
	for _, s := range job.Steps {
		if s.State != StepDone {
			t.Errorf("step %s: %s %s", s.Name, s.State, s.Message)
		}
	}
	// StartMigration lists accounts, the source step lists them again for
	// the domain, then every step in order, and the key goes last.
	want := []string{"list", "plan shopone", "list", "create shopone", "web 0001 php=8.1 quota=1024 rev=1 reason=Website migration", "files 0001 rev=2", "create-db shopone shopone_wp", "create-user-hash shopone shopone_wpu", "grant shopone shopone_wpu shopone_wp", "copy-db shopone_wp", "cron 0001 1", "finish"}
	if !slices.Equal(f.order.all, want) {
		t.Fatalf("order\n got %q\nwant %q", f.order.all, want)
	}
	if len(f.verify) != 1 || f.verify[0].New != "http://shop.example.test" || f.verify[0].NewConnect != "127.0.0.1:80" || len(f.verify[0].Probes) != 1 || !slices.Contains(f.verify[0].Paths, "/wp-login.php") {
		t.Fatalf("verify: %+v", f.verify)
	}
	// The job record never holds the hash.
	raw, _ := os.ReadFile(filepath.Join(f.dir, "jobs.json"))
	if strings.Contains(string(raw), testHash) || !strings.Contains(string(raw), `"gate":"open"`) {
		t.Fatalf("job file: %s", raw)
	}
	ready, err := f.runner.ReadyMigration(context.Background(), job.ID, "test operator")
	if err != nil || ready.Migration.Gate != GateReady || len(ready.Migration.DNS) != 2 || ready.Migration.DNS[0] != (DNSRecord{Name: "shop.example.test", Type: "A", Value: "203.0.113.7"}) {
		t.Fatalf("ready: %+v %v", ready.Migration, err)
	}
}

// The DNS records name www.<domain> only when the old site answered for it.
func TestReadyNamesWWWOnlyWhenTheOldSiteHadIt(t *testing.T) {
	for _, c := range []struct {
		domain string
		www    bool
		want   int
	}{{"shop.example.test", true, 2}, {"blog.shop.example.test", false, 1}, {"www.shop.example.test", true, 1}} {
		f := newMigrationFixture(t)
		f.broker.plan.Domain, f.broker.plan.WWW = c.domain, c.www
		job := f.migrate(t)
		ready, err := f.runner.ReadyMigration(context.Background(), job.ID, "test operator")
		if err != nil || len(ready.Migration.DNS) != c.want || slices.ContainsFunc(ready.Migration.DNS, func(r DNSRecord) bool { return strings.HasPrefix(r.Name, "www.www.") }) {
			t.Errorf("%s: %+v %v", c.domain, ready.Migration, err)
		}
	}
}

// TestConvertedSiteMigratesWithItsProbes: a site whose access rules were
// converted is Native; the copy's conversion replaces the plan's, and verify
// gets its 403, 401 and 200 probes.
func TestConvertedSiteMigratesWithItsProbes(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.plan.Converted = []hostaccounts.MigrationFolder{{File: "wp-content/plugins/akismet/.htaccess", Path: "/wp-content/plugins/akismet/", Rule: "closed to everyone (403)"}}
	f.broker.plan.Probes = []hostaccounts.MigrationProbe{{Path: "/wp-content/plugins/akismet/", Kind: "deny"}}
	f.broker.filesResult = hostaccounts.MigrateFilesResult{
		Folders: []hostaccounts.MigrationFolder{
			{File: "members/.htaccess", Path: "/members/", Rule: "password"},
			{File: "wp-content/plugins/akismet/.htaccess", Path: "/wp-content/plugins/akismet/", Rule: "closed to everyone (403)"},
		},
		Probes: []hostaccounts.MigrationProbe{{Path: "/members/", Kind: "auth"}, {Path: "/wp-content/plugins/akismet/", Kind: "deny"}, {Path: "/wp-content/plugins/akismet/_inc/akismet.css", Kind: "allow"}},
	}
	job := f.migrate(t)
	if job.State != StateSucceeded {
		t.Fatalf("job: %+v %+v", job.State, job.Error)
	}
	if !strings.Contains(job.Steps[0].Message, "/wp-content/plugins/akismet/ (closed to everyone (403))") {
		t.Fatalf("source step: %q", job.Steps[0].Message)
	}
	if i := slices.IndexFunc(job.Steps, func(s Step) bool { return s.Name == StepFiles }); !strings.Contains(job.Steps[i].Message, "/members/ (password)") {
		t.Fatalf("files step: %q", job.Steps[i].Message)
	}
	want := []migrateverify.Probe{{Path: "/members/", Kind: migrateverify.ProbeAuth}, {Path: "/wp-content/plugins/akismet/", Kind: migrateverify.ProbeDeny}, {Path: "/wp-content/plugins/akismet/_inc/akismet.css", Kind: migrateverify.ProbeAllow}}
	if len(f.verify) != 1 || !reflect.DeepEqual(f.verify[0].Probes, want) || len(job.Migration.Converted) != 2 {
		t.Fatalf("verify %+v converted %+v", f.verify, job.Migration.Converted)
	}
}

// TestAddressListFoldersGoToVerifyWithBothAddresses: a folder open to some
// addresses only reaches verify with its rule, the address the old server
// saw this server come from, and the copy's own (the loopback address verify
// connects from), on the first run and on a later one, after the key is gone.
func TestAddressListFoldersGoToVerifyWithBothAddresses(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.plan.ClientAddress = "198.51.100.9"
	lobby := hostaccounts.MigrationProbe{Path: "/lobby/", Kind: "hosts", Hosts: "except", Networks: []string{"127.0.0.2/32"}}
	f.broker.filesResult = hostaccounts.MigrateFilesResult{
		Folders: []hostaccounts.MigrationFolder{{File: "lobby/.htaccess", Path: "/lobby/", Rule: "closed to 127.0.0.2/32"}},
		Probes:  []hostaccounts.MigrationProbe{lobby},
	}
	// A failed check's plain message goes to the person, critical ones
	// first; the technical lines stay apart.
	f.verdict = migrateverify.Report{Verdict: "CUTOVER LOCKED: 3 failed check(s)", Counts: migrateverify.Counts{PagesCompared: 5, PagesPass: 5, ProbesFail: 3}, Probes: []migrateverify.ProbeResult{
		{Path: "/lobby/", Kind: migrateverify.ProbeHosts, Result: migrateverify.Fail, Code: migrateverify.CodeClientUnknown, Reason: "technical", Message: "/lobby/ is closed to some addresses. Check /lobby/ from an address it allows, then accept."},
		{Path: "/office/", Kind: migrateverify.ProbeHosts, Result: migrateverify.Fail, Code: migrateverify.CodeNewOpen, Critical: true, Reason: "technical", Message: "/office/ is open only to some addresses. Accept only if it is closed."},
		{Path: "/private/", Kind: migrateverify.ProbeAuth, Result: migrateverify.Fail, Code: migrateverify.CodeNewDiffers, Reason: "status 401 → 403"},
	}}
	job := f.migrate(t)
	if job.State != StateSucceeded {
		t.Fatalf("job: %+v %+v", job.State, job.Error)
	}
	v := job.Migration.Verify
	if job.Migration.Gate != GateClosed || !slices.Equal(v.Problems, []string{f.verdict.Probes[1].Message, f.verdict.Probes[0].Message}) || len(v.Lines) != 3 {
		t.Fatalf("gate %s verify %+v", job.Migration.Gate, v)
	}
	want := []migrateverify.Probe{{Path: "/lobby/", Kind: migrateverify.ProbeHosts, Hosts: migrateverify.HostsExcept, Networks: []string{"127.0.0.2/32"}}}
	if len(f.verify) != 1 || !reflect.DeepEqual(f.verify[0].Probes, want) || f.verify[0].OldClient != "198.51.100.9" || f.verify[0].NewClient != "127.0.0.1" {
		t.Fatalf("verify %+v", f.verify)
	}
	if _, err := f.runner.VerifyMigration(context.Background(), job.ID, "test operator"); err != nil {
		t.Fatal(err)
	}
	f.runner.Wait()
	if len(f.verify) != 2 || f.verify[1].OldClient != "198.51.100.9" || f.verify[1].NewClient != "127.0.0.1" {
		t.Fatalf("verify again %+v", f.verify)
	}
}

func TestCompatSiteIsRefusedBeforeAnythingIsMade(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.plan.Tier, f.broker.plan.TierCauses = "compat", []string{"access_control"}
	f.broker.plan.TierRefusals = []string{"staff/.htaccess line 2: Satisfy Any"}
	job := f.migrate(t)
	if job.State != StateFailed || job.Error.Step != StepSource || !strings.Contains(job.Error.Why, "password-protected folders") || !strings.Contains(job.Error.Next, "Apache tier") || !strings.Contains(job.Error.Technical, "staff/.htaccess line 2") {
		t.Fatalf("job: %+v %+v", job.State, job.Error)
	}
	for _, call := range f.order.all {
		if strings.HasPrefix(call, "create") || strings.HasPrefix(call, "web") || strings.HasPrefix(call, "files") {
			t.Fatalf("%q ran for a Compat site", call)
		}
	}
	if f.broker.finished != 1 {
		t.Fatal("the key was not removed after the refusal")
	}
	if job.Steps[len(job.Steps)-1].State != StepDone {
		t.Fatalf("key step: %+v", job.Steps[len(job.Steps)-1])
	}
}

func TestFailedMigrationUndoesWhatItMade(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.dbErr = &hostaccounts.MigrationError{Step: "import", Detail: "ERROR 1064 at line 3"}
	job := f.migrate(t)
	if job.State != StateFailed || job.Error.Step != StepDatabase || !strings.Contains(job.Error.Why, "A database could not be copied") {
		t.Fatalf("job: %+v %+v", job.State, job.Error)
	}
	for _, want := range []string{"drop-user shopone shopone_wpu", "drop-db shopone shopone_wp"} {
		if !slices.Contains(f.order.all, want) {
			t.Fatalf("undo lacks %q: %q", want, f.order.all)
		}
	}
	if !slices.ContainsFunc(f.order.all, func(s string) bool { return strings.HasPrefix(s, "delete ") }) || len(f.acc.accounts) != 0 {
		t.Fatalf("the account was not removed: %q", f.order.all)
	}
	if f.order.all[len(f.order.all)-1] != "finish" {
		t.Fatalf("the key must go after the undo: %q", f.order.all)
	}
	states := map[string]string{}
	for _, s := range job.Steps {
		states[s.Name] = s.State
	}
	if states[StepAccount] != StepUndone || states[StepFiles] != StepUndone || states[StepCron] != StepSkipped || states[StepKey] != StepDone {
		t.Fatalf("states %v", states)
	}
	raw, _ := json.Marshal(job)
	if strings.Contains(string(raw), testHash) {
		t.Fatal("the hash reached the job")
	}
}

// A web server that could not reload after the copy is named as such, not
// as a copy that failed.
func TestFailedReloadSaysTheFilesAreInPlace(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.filesErr = &hostaccounts.MigrationError{Step: "reload", Detail: "The files are in place, but the web server could not reload to read the site's .htaccess rules, so its rewrites are not in force."}
	job := f.migrate(t)
	if job.State != StateFailed || job.Error.Step != StepFiles || strings.Contains(job.Error.Why, "could not be copied") || !strings.Contains(job.Error.Why, "could not reload") || !strings.Contains(job.Error.Next, "systemctl status lsws") {
		t.Fatalf("job: %+v %+v", job.State, job.Error)
	}
}

func TestRedLinesKeepTheGateClosedUntilAccepted(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.plan.PHPSource = "ea-php74"
	f.verdict = migrateverify.Report{Verdict: "CUTOVER LOCKED: 1 failed check(s)", Counts: migrateverify.Counts{PagesCompared: 3, PagesFail: 1},
		Pages: []migrateverify.PageResult{{Path: "/shop/", Result: migrateverify.Fail, Reason: "status 200 on the old site, 500 on the new"}}}
	job := f.migrate(t)
	m := job.Migration
	if job.State != StateSucceeded || m.Gate != GateClosed || len(m.Notes) == 0 || !strings.Contains(m.Notes[0], "8.1") || len(m.Verify.Lines) == 0 {
		t.Fatalf("job: %+v %+v", job.State, m)
	}
	if _, err := f.runner.ReadyMigration(context.Background(), job.ID, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("ready with a closed gate: %v", err)
	}
	if _, err := f.runner.AcceptMigration(context.Background(), job.ID, "  ", "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty reason: %v", err)
	}
	accepted, err := f.runner.AcceptMigration(context.Background(), job.ID, "The shop page error is a known plugin issue", "test operator")
	if err != nil || accepted.Migration.Gate != GateAccepted || accepted.Migration.Accepted.Reason == "" {
		t.Fatalf("accept: %+v %v", accepted.Migration, err)
	}
	last := accepted.Migration.Activity[len(accepted.Migration.Activity)-1]
	if last.Actor != "test operator" || !strings.Contains(last.What, "known plugin issue") {
		t.Fatalf("activity: %+v", last)
	}
	if _, err := f.runner.ReadyMigration(context.Background(), accepted.ID, "test operator"); err != nil {
		t.Fatal(err)
	}
}

func TestStartMigrationNeedsAConfirmedSource(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.pinned = false
	if _, err := f.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "shopone"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("an unconfirmed host key: %v", err)
	}
	f.broker.pinned = true
	for _, in := range []MigrationInput{{Source: "x", Username: "shopone"}, {Source: sourceID, Username: "Shop"}, {Source: sourceID, Username: "root"}} {
		if _, err := f.runner.StartMigration(context.Background(), in, "test operator"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", in, err)
		}
	}
	f.acc.accounts = append(f.acc.accounts, hostaccounts.Account{ID: strings.Repeat("9", 32), Username: "shopone", Domain: "other.test", Revision: 1})
	if _, err := f.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "shopone"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a name in use: %v", err)
	}
	none := newFixture(t)
	if _, err := none.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "shopone"}, "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("migrations off: %v", err)
	}
}

// A migration job survives the store's own checks when the panel restarts.
func TestMigrationJobsReadBack(t *testing.T) {
	f := newMigrationFixture(t)
	job := f.migrate(t)
	store, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	again, ok := store.Get(job.ID)
	if !ok || again.Migration == nil || again.Migration.Gate != GateOpen || len(store.sites()) != 1 {
		t.Fatalf("read back: %+v", again)
	}
}

// A moved website's delete takes the databases and users it made, with the
// old server's names, not <user>_wp.
func TestDeletingAMovedSiteTakesItsDatabases(t *testing.T) {
	f := newMigrationFixture(t)
	job := f.migrate(t)
	f.dbs.existing = []dbhost.Database{{Name: "shopone_wp", Owner: "shopone"}}
	f.dbs.users = []dbhost.User{{Name: "shopone_wpu", Owner: "shopone"}}
	a := f.acc.accounts[0]
	got, err := f.runner.RemoveSite(context.Background(), job.Result.AccountID, "shop.example.test", a.Revision, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"the database user shopone_wpu", "the database shopone_wp"} {
		if !slices.Contains(got.Removed, want) {
			t.Fatalf("removed %q", got.Removed)
		}
	}
}

// The key step reports a removal only when the old server proved it; any
// other answer names the line and the server, in the step and the
// activity log alike.
func TestKeyStepNeverClaimsARemovalItDidNotSee(t *testing.T) {
	line := "sifruno-migration-" + sourceID + " from /root/.ssh/authorized_keys on old.example.test"
	for name, setup := range map[string]func(*fakeMigrationBroker){
		"refused": func(b *fakeMigrationBroker) {
			b.removedOK, b.detail = false, "The old server did not remove the key: sed: Permission denied."
		},
		"not found": func(b *fakeMigrationBroker) { b.removedOK, b.finishErr = false, hostaccounts.ErrNotFound },
		"no answer": func(b *fakeMigrationBroker) { b.removedOK, b.finishErr = false, hostaccounts.ErrUnavailable },
	} {
		t.Run(name, func(t *testing.T) {
			f := newMigrationFixture(t)
			setup(f.broker)
			job := f.migrate(t)
			key := job.Steps[len(job.Steps)-1]
			last := job.Migration.Activity[len(job.Migration.Activity)-1].What
			if key.State != StepFailed || !strings.Contains(key.Message, line) || job.Migration.KeyRemoved || !strings.Contains(last, line) {
				t.Fatalf("key step %+v, activity %q", key, last)
			}
			if strings.Contains(strings.ToLower(last), "was removed") {
				t.Fatalf("the activity log claims a removal: %q", last)
			}
		})
	}
}

func TestMigrationQuota(t *testing.T) {
	for _, c := range []struct {
		used, limit int64
		want        int
	}{{40, 0, 1024}, {900, 0, 2056}, {40, 500, 500}, {900, 500, 1156}, {0, 10, 256}, {0, 2 << 20, 1 << 20}} {
		if got := migrationQuota(c.used, c.limit); got != c.want {
			t.Errorf("%d/%d: %d", c.used, c.limit, got)
		}
	}
}
