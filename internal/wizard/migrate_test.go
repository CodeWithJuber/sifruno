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
	"time"

	"sifruno/internal/acme"
	"sifruno/internal/cpsource"
	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/migrateverify"
	"sifruno/internal/whmsource"
	"sifruno/internal/whmsource/whmtest"
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
	// via is the source's way in; cpanel counts the steps that carried
	// WHM's answers, cleared the stale lines taken off the list.
	via     string
	cpanel  []string
	cleared int
	// certificate is what MigrateCertificate answers (no certificate on
	// the old server unless a test sets one), certErr its failure, and
	// withSSL the steps whose WHM answers carried the site's certificate.
	certificate hostaccounts.MigrateCertificateResult
	certErr     error
	withSSL     []string
}

func (f *fakeMigrationBroker) ClearStaleMigrationKey(context.Context, string, hostaccounts.MigrationFinishInput, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleared++
	return nil
}

func (f *fakeMigrationBroker) sawCPanel(step string, a *hostaccounts.CPanelAnswers) {
	if a != nil {
		f.mu.Lock()
		f.cpanel = append(f.cpanel, step)
		if len(a.SSL) > 0 {
			f.withSSL = append(f.withSSL, step)
		}
		f.mu.Unlock()
	}
}

func (f *fakeMigrationBroker) MigrateCertificate(_ context.Context, id string, in hostaccounts.MigrateCertificateInput, _ string) (hostaccounts.MigrateCertificateResult, error) {
	f.order.add(fmt.Sprintf("certificate %s rev=%d", id[28:], in.ExpectedRevision))
	f.sawCPanel("certificate", in.CPanel)
	if f.certErr != nil {
		return hostaccounts.MigrateCertificateResult{}, f.certErr
	}
	res := f.certificate
	if !res.Copied && res.Refused == "" {
		res.Refused, res.Detail = "no_certificate", "The old server has no certificate for shop.example.test."
	}
	if err := f.revision(id, in.ExpectedRevision, res.Copied); err != nil {
		return hostaccounts.MigrateCertificateResult{}, err
	}
	res.Revision = in.ExpectedRevision
	if res.Copied {
		res.Revision++
	}
	return res, nil
}

func (f *fakeMigrationBroker) GetMigration(_ context.Context, id string) (hostaccounts.Migration, error) {
	if id != sourceID {
		return hostaccounts.Migration{}, hostaccounts.ErrNotFound
	}
	m := hostaccounts.Migration{ID: id, Host: "old.example.test", Port: 22, Via: f.via, PublicKey: "restrict ssh-ed25519 AAAA sifruno-migration-" + id}
	if f.pinned {
		m.Pinned = "SHA256:abc"
	}
	return m, nil
}
func (f *fakeMigrationBroker) PlanMigration(_ context.Context, id string, in hostaccounts.MigrationPlanInput, _ string) (hostaccounts.MigrationPlan, error) {
	f.order.add("plan " + in.Username)
	f.sawCPanel("plan", in.CPanel)
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
	f.sawCPanel("files", in.CPanel)
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
	f.sawCPanel("database", in.CPanel)
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
	// The old server has no certificate here: that step alone is skipped.
	for _, s := range job.Steps {
		if s.State != StepDone && !(s.Name == StepSSL && s.State == StepSkipped) {
			t.Errorf("step %s: %s %s", s.Name, s.State, s.Message)
		}
	}
	// StartMigration lists accounts, the source step lists them again for
	// the domain, then every step in order, and the key goes last.
	want := []string{"list", "plan shopone", "list", "create shopone", "web 0001 php=8.1 quota=1024 rev=1 reason=Website migration", "files 0001 rev=2", "create-db shopone shopone_wp", "create-user-hash shopone shopone_wpu", "grant shopone shopone_wpu shopone_wp", "copy-db shopone_wp", "cron 0001 1", "certificate 0001 rev=3", "finish"}
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

// Every failure of a move says why and what to do for that case, and the
// old server's own words stay in Technical details (D-0006).
func TestMigrationFailuresSayWhatToDo(t *testing.T) {
	preload := "2026/01/02 03:04:05 LD_Preload detected, refusing to run 2026/01/02 03:04:05 libinjected.so.1 The subprocess reported error number 3 when it ended. at bin/apitool.pl line 369."
	for _, c := range []struct {
		name            string
		plan, files, db error
		why, next, tech string
	}{
		{name: "unreachable", plan: &hostaccounts.MigrationError{Step: "unreachable", Output: "ssh: connect to host 203.0.113.9 port 22: No route to host"},
			why: "Sifruno could not reach the old server", next: "firewall accepts connections from this server, then move the website again.", tech: "No route to host"},
		{name: "key refused", plan: &hostaccounts.MigrationError{Step: "key_refused", Output: "root@203.0.113.9: Permission denied (publickey)."},
			why: "did not accept the migration key", next: "PermitRootLogin prohibit-password or yes", tech: "Permission denied"},
		{name: "host key changed", plan: &hostaccounts.MigrationError{Step: "host_key_changed", Output: "Host key verification failed."},
			why: "SSH host key is not the one you confirmed", next: "Stop until you know why", tech: "Host key verification failed"},
		{name: "cPanel tool", plan: &hostaccounts.MigrationError{Step: "cpanel_tool", Output: preload},
			why:  "cPanel's own tools on the old server did not answer properly. This happens when something injects a preload library into them (a security problem on the old server) or when cPanel's files are damaged or being updated.",
			next: "Check the old server's security and cPanel (cPanel support can help), or connect with the WHM login, then move the website again.", tech: "LD_Preload detect"},
		{name: "cPanel output", plan: &hostaccounts.MigrationError{Step: "cpanel_output", Detail: "The old server's details of the site could not be read (whmapi1 domainuserdata)."},
			why: "did not answer properly", next: "cPanel support can help", tech: "whmapi1 domainuserdata"},
		{name: "account missing", plan: &hostaccounts.MigrationError{Step: "account_missing", Detail: "The old server has no account named shopone."},
			why: "The old server has no account named shopone.", next: "List the old server's accounts again", tech: "step account_missing"},
		{name: "no room here", files: &hostaccounts.MigrationError{Step: "space", Detail: "The copy needs about 3.0 GiB, but only 1.0 GiB is free on this server beyond the 2.0 GiB it keeps free."},
			why: "This server does not have room for the copy. The copy needs about 3.0 GiB", next: "Free space on this server", tech: "step space"},
		{name: "database", db: &hostaccounts.MigrationError{Step: "dump", Output: "mysqldump: Got error: 1045: Access denied for user 'root'@'localhost'"},
			why: "A database could not be copied: the old server's dump tool stopped.", next: "Check the database on the old server", tech: "Access denied for user"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMigrationFixture(t)
			f.broker.planErr, f.broker.filesErr, f.broker.dbErr = c.plan, c.files, c.db
			job := f.migrate(t)
			e := job.Error
			if job.State != StateFailed || e == nil || !strings.Contains(e.Why, c.why) || !strings.Contains(e.Next, c.next) || !strings.Contains(e.Technical, c.tech) {
				t.Fatalf("%+v", e)
			}
			var failed *hostaccounts.MigrationError
			for _, err := range []error{c.plan, c.files, c.db} {
				if errors.As(err, &failed) && failed.Output != "" && strings.Contains(e.Why+e.Next, failed.Output) {
					t.Fatalf("the old server's words are outside Technical details: %+v", e)
				}
			}
			if strings.Contains(e.Next, "Fix the value") || strings.Contains(e.Why, "The old server's answer could not be used") {
				t.Fatalf("a generic text: %+v", e)
			}
		})
	}
}

// A comparison that finds differences says so in plain words, with the
// next step; one that matches says nothing more.
func TestVerifyDifferencesSayWhatToDo(t *testing.T) {
	f := newMigrationFixture(t)
	f.verdict = migrateverify.Report{Verdict: "CUTOVER LOCKED: 1 failed check(s)", Counts: migrateverify.Counts{PagesCompared: 3, PagesFail: 1, ProbesFail: 1}}
	job := f.migrate(t)
	v := job.Migration.Verify
	if v == nil || !strings.Contains(v.Why, "1 page(s) differ") || !strings.Contains(v.Why, "1 closed URL(s)") || !strings.Contains(v.Next, "press Compare again") || !strings.Contains(v.Next, "accept the red lines") {
		t.Fatalf("verify: %+v", v)
	}
	f = newMigrationFixture(t)
	if v = f.migrate(t).Migration.Verify; v.Why != "" || v.Next != "" {
		t.Fatalf("a matching copy: %+v", v)
	}
}

// whmFixture is a move connected with the old server's WHM login: the fake
// WHM holds the broker's key, and the panel holds the login in memory.
func whmFixture(t *testing.T) (*migrationFixture, *whmtest.Server, *whmsource.Sessions) {
	t.Helper()
	whm := whmtest.New()
	t.Cleanup(whm.Close)
	c, err := whmsource.New(whm.Address(), whmsource.Login{Token: whm.Token}, whm.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	line := "restrict ssh-ed25519 AAAA sifruno-migration-" + sourceID
	if err = c.AuthorizeKey(context.Background(), line, sourceID); err != nil {
		t.Fatal(err)
	}
	logins := whmsource.NewSessions()
	logins.Put(sourceID, c, line, time.Now().Add(time.Hour))
	f := newMigrationFixture(t)
	f.broker.via = hostaccounts.ViaWHM
	o := *f.runner.migrationOptions()
	o.WHM = logins
	f.runner.EnableMigrations(o)
	return f, whm, logins
}

// D-0005: on the WHM path every step that asks cPanel carries WHM's own
// answers, fetched through its API; the key is removed over SSH, and WHM's
// API deletes its file; the login is then forgotten.
func TestWHMMoveAsksCPanelThroughWHM(t *testing.T) {
	f, whm, logins := whmFixture(t)
	job := f.migrate(t)
	if job.State != StateSucceeded || job.Migration.Via != hostaccounts.ViaWHM || !job.Migration.KeyRemoved {
		t.Fatalf("job: %+v %+v", job.Migration, job.Error)
	}
	if !slices.Equal(f.broker.cpanel, []string{"plan", "files", "database", "certificate"}) {
		t.Fatalf("steps with WHM's answers: %q", f.broker.cpanel)
	}
	// The site's certificate, with its key, goes to the broker with the
	// certificate step alone.
	if !slices.Equal(f.broker.withSSL, []string{"certificate"}) {
		t.Fatalf("steps that carried the certificate: %q", f.broker.withSSL)
	}
	calls := strings.Join(whm.CallList(), ",")
	for _, want := range []string{"listaccts", "domainuserdata", "php_get_vhost_versions", "uapi_cpanel", "fetch_vhost_ssl_components", "deletesshkey", "listsshkeys"} {
		if !strings.Contains(calls, want) {
			t.Fatalf("WHM was not asked %s: %s", want, calls)
		}
	}
	if ok, _ := whm.Authorized("ssh-ed25519 AAAA sifruno-migration-" + sourceID); ok || logins.Has(sourceID) {
		t.Fatal("the key or the login stayed")
	}
	key := job.Steps[len(job.Steps)-1]
	if key.State != StepDone || !strings.Contains(key.Message, "WHM's API also deleted the key's file") {
		t.Fatalf("key step: %+v", key)
	}
}

// When SSH cannot remove the key, WHM's API removes it, and the step says
// plainly that it is gone and how.
func TestWHMRemovesTheKeyWhenSSHCannot(t *testing.T) {
	f, whm, _ := whmFixture(t)
	f.broker.removedOK, f.broker.detail = false, "The old server did not remove the key: Connection refused."
	job := f.migrate(t)
	key := job.Steps[len(job.Steps)-1]
	if !job.Migration.KeyRemoved || key.State != StepDone || !strings.Contains(key.Message, "WHM's API removed it") || f.broker.cleared != 1 {
		t.Fatalf("key step: %+v removed=%v cleared=%d", key, job.Migration.KeyRemoved, f.broker.cleared)
	}
	if ok, _ := whm.Authorized("ssh-ed25519 AAAA sifruno-migration-" + sourceID); ok {
		t.Fatal("the key is still authorized")
	}
}

// A WHM that answers with something other than its JSON stops the move with
// its own explanation, and the old server's words stay technical.
func TestWHMMoveWithABrokenWHM(t *testing.T) {
	f, whm, _ := whmFixture(t)
	whm.Broken = "LD_Preload detected, refusing to run"
	job := f.migrate(t)
	if job.State != StateFailed || !strings.Contains(job.Error.Why, "did not answer with the data cPanel documents") || strings.Contains(job.Error.Why+job.Error.Next, "LD_Preload") || !strings.Contains(job.Error.Technical, "LD_Preload") {
		t.Fatalf("job: %+v", job.Error)
	}
	if len(f.broker.cpanel) != 0 {
		t.Fatalf("the broker was asked without WHM's answers: %q", f.broker.cpanel)
	}
}

// A panel that restarted no longer holds the login: the move is refused
// before anything is made.
func TestWHMMoveNeedsTheLoginInMemory(t *testing.T) {
	f, _, logins := whmFixture(t)
	logins.Forget(sourceID)
	_, err := f.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "shopone"}, "test operator")
	var refusal *Refusal
	if !errors.As(err, &refusal) || !errors.Is(err, ErrConflict) || !strings.Contains(refusal.Detail, "connect with the WHM login again") {
		t.Fatalf("%v", err)
	}
}

// The old site's certificate is copied after the scheduled jobs: the site
// answers https here at once, the certificate manager records where it
// came from, and the copy is compared with the old site over https on both
// sides, the copy through this server's port 443.
func TestMigrationCopiesTheOldSitesCertificate(t *testing.T) {
	f := newMigrationFixture(t)
	withCertificates(t, f.fixture, fakeIssuer{}, fakeInstaller{acc: f.acc})
	until := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	f.broker.certificate = hostaccounts.MigrateCertificateResult{Copied: true, Issuer: "Old CA",
		Certificate: hostaccounts.CertificateState{NotAfter: until.Unix(), Fingerprint: strings.Repeat("ab", 32), Names: "shop.example.test,www.shop.example.test"}}
	job := f.migrate(t)
	if job.State != StateSucceeded {
		t.Fatalf("job: %s %+v", job.State, job.Error)
	}
	i := slices.IndexFunc(job.Steps, func(s Step) bool { return s.Name == StepSSL })
	if i < 1 || job.Steps[i-1].Name != StepCron || job.Steps[i+1].Name != StepVerify || job.Steps[i].Title != "Copy the website's certificate" {
		t.Fatalf("steps: %s", stepStates(job))
	}
	want := "Copied the old server's certificate for shop.example.test, issued by Old CA, valid until 2027-03-01: the site answers https on this server already. The panel replaces it with a Let's Encrypt certificate before then, once the domain points here."
	if job.Steps[i].State != StepDone || job.Steps[i].Message != want {
		t.Fatalf("step: %+v", job.Steps[i])
	}
	if c := job.Migration.Certificate; c == nil || !c.Copied || c.NotAfter != "2027-03-01T12:00:00Z" || c.Issuer != "Old CA" || c.Why != "" {
		t.Fatalf("record: %+v", c)
	}
	if got, ok := f.runner.certificates.(*acme.Manager).CopiedUntil(job.Result.AccountID); !ok || !got.Equal(until) {
		t.Fatalf("not recorded as copied: %v %v", got, ok)
	}
	if job.Result.URL != "https://shop.example.test/" || job.Result.AdminURL != "https://shop.example.test/wp-admin/" {
		t.Fatalf("result: %+v", job.Result)
	}
	if !slices.Contains(f.order.all, "certificate 0001 rev=3") {
		t.Fatalf("order %q", f.order.all)
	}
	https := func(o migrateverify.Options) bool {
		return o.Old == "https://shop.example.test" && o.New == "https://shop.example.test" && o.NewConnect == "127.0.0.1:443" && o.NewClient == "127.0.0.1" && !o.InsecureNewTLS
	}
	if len(f.verify) != 1 || !https(f.verify[0]) {
		t.Fatalf("verify: %+v", f.verify)
	}
	if _, err := f.runner.VerifyMigration(context.Background(), job.ID, "test operator"); err != nil {
		t.Fatal(err)
	}
	f.runner.Wait()
	if len(f.verify) != 2 || !https(f.verify[1]) {
		t.Fatalf("a later comparison: %+v", f.verify)
	}
}

// A certificate that cannot be copied leaves the site on http and the move
// goes on: the step says why, and that https follows once the domain
// points here; the old server's own words stay in the activity log.
func TestMigrationGoesOnWithoutTheCertificate(t *testing.T) {
	follows := " The site uses http on this server until shop.example.test points here; then the panel gets it a certificate by itself."
	for _, c := range []struct {
		name    string
		result  hostaccounts.MigrateCertificateResult
		err     error
		certs   bool
		message string
		log     string
	}{
		{name: "expired", certs: true, result: hostaccounts.MigrateCertificateResult{Refused: "expired", Detail: "It expired on 2026-10-01."},
			message: "The old server's certificate was not copied. It expired on 2026-10-01." + follows},
		{name: "none", certs: true, message: "The old server has no certificate for shop.example.test." + follows},
		{name: "certificates off", result: hostaccounts.MigrateCertificateResult{Refused: "self_signed", Detail: "It is self-signed, so visitors' browsers would warn about it."},
			message: "The old server's certificate was not copied. It is self-signed, so visitors' browsers would warn about it. The site uses http on this server: certificates are not set up here."},
		{name: "a failing cPanel tool", certs: true, err: &hostaccounts.MigrationError{Step: "cpanel_tool", Output: "whmapi1: refused to run"},
			message: "The old server's certificate was not copied: " + cpanelTools.why + follows, log: "whmapi1: refused to run"},
	} {
		f := newMigrationFixture(t)
		if c.certs {
			withCertificates(t, f.fixture, fakeIssuer{}, fakeInstaller{acc: f.acc})
		}
		f.broker.certificate, f.broker.certErr = c.result, c.err
		job := f.migrate(t)
		i := slices.IndexFunc(job.Steps, func(s Step) bool { return s.Name == StepSSL })
		if job.State != StateSucceeded || job.Steps[i].State != StepSkipped || job.Steps[i].Message != c.message {
			t.Errorf("%s: %s %+v", c.name, job.State, job.Steps[i])
			continue
		}
		if m := job.Migration; m.Certificate == nil || m.Certificate.Copied || m.Certificate.Why == "" || strings.Contains(m.Certificate.Why, "refused to run") {
			t.Errorf("%s: record %+v", c.name, m.Certificate)
		}
		if job.Result.URL != "http://shop.example.test/" || len(f.verify) != 1 || f.verify[0].New != "http://shop.example.test" || f.verify[0].NewConnect != "127.0.0.1:80" {
			t.Errorf("%s: result %+v verify %+v", c.name, job.Result, f.verify)
		}
		if c.log != "" && !slices.ContainsFunc(job.Migration.Activity, func(a Activity) bool { return strings.Contains(a.What, c.log) }) {
			t.Errorf("%s: activity %+v", c.name, job.Migration.Activity)
		}
	}
}
