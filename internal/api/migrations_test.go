package api

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/migrateverify"
	"sifruno/internal/wizard"
)

var testSourceID = strings.Repeat("e", 32)

// migrationSpy is the broker's migration surface: one old server, whose
// host key the admin confirms, with one account.
type migrationSpy struct {
	pinned   bool
	finished int
}

func (m *migrationSpy) view() hostaccounts.Migration {
	v := hostaccounts.Migration{ID: testSourceID, Host: "old.example.test", Port: 22, PublicKey: "restrict ssh-ed25519 AAAA sifruno-migration-" + testSourceID,
		InstallCommand: "echo 'restrict ssh-ed25519 AAAA' >> /root/.ssh/authorized_keys", HostKeys: []hostaccounts.MigrationHostKey{{Type: "ssh-ed25519", Fingerprint: "SHA256:abc"}}}
	if m.pinned {
		v.Pinned = "SHA256:abc"
	}
	return v
}
func (m *migrationSpy) OpenMigration(_ context.Context, in hostaccounts.MigrationOpenInput, _ string) (hostaccounts.Migration, error) {
	if in.Host == "bad host" {
		return hostaccounts.Migration{}, hostaccounts.ErrInvalid
	}
	return m.view(), nil
}
func (m *migrationSpy) GetMigration(context.Context, string) (hostaccounts.Migration, error) {
	return m.view(), nil
}
func (m *migrationSpy) PinMigrationHostKey(_ context.Context, _ string, in hostaccounts.MigrationPinInput, _ string) (hostaccounts.Migration, error) {
	if in.Fingerprint != "SHA256:abc" {
		return hostaccounts.Migration{}, &hostaccounts.MigrationError{Step: "host_key"}
	}
	m.pinned = true
	return m.view(), nil
}
func (m *migrationSpy) MigrationAccounts(context.Context, string) ([]cpsource.Account, error) {
	if !m.pinned {
		return nil, &hostaccounts.MigrationError{Step: "host_key", Detail: "not confirmed"}
	}
	return []cpsource.Account{{User: "shopone", Domain: "shop.example.test", DiskUsedMiB: 14}}, nil
}
func (m *migrationSpy) PlanMigration(context.Context, string, hostaccounts.MigrationPlanInput, string) (hostaccounts.MigrationPlan, error) {
	return hostaccounts.MigrationPlan{Username: "shopone", Domain: "shop.example.test", PHPSource: "ea-php83", Tier: "native"}, nil
}
func (m *migrationSpy) MigrateFiles(context.Context, string, hostaccounts.MigrateFilesInput, string) (hostaccounts.MigrateFilesResult, error) {
	return hostaccounts.MigrateFilesResult{}, nil
}
func (m *migrationSpy) MigrateDatabase(context.Context, string, hostaccounts.MigrateDatabaseInput, string) (hostaccounts.MigrateDatabaseResult, error) {
	return hostaccounts.MigrateDatabaseResult{}, nil
}
func (m *migrationSpy) FinishMigration(context.Context, string, hostaccounts.MigrationFinishInput, string) (hostaccounts.MigrationFinishResult, error) {
	m.finished++
	return hostaccounts.MigrationFinishResult{RemovedFromSource: true}, nil
}
func (m *migrationSpy) SetCron(context.Context, string, hostaccounts.CronInput, string) (hostaccounts.CronResult, error) {
	return hostaccounts.CronResult{}, nil
}

type hashSpy struct{ wizardDatabaseSpy }

func (hashSpy) CreateUserWithHashStrict(context.Context, string, string, string) error { return nil }

func migrationFixture(t *testing.T) (siteFixture, *wizard.Runner, *migrationSpy) {
	t.Helper()
	f := websiteFixture(t)
	store, err := wizard.OpenStore(filepath.Join(realTempDir(t), "wizard"))
	if err != nil {
		t.Fatal(err)
	}
	broker := &sitesBroker{}
	spy := &migrationSpy{}
	runner := wizard.New(broker, wizardDatabaseSpy{}, store, nil)
	runner.EnableMigrations(wizard.MigrationOptions{Broker: spy, Databases: hashSpy{}, Connect: "127.0.0.1:80", Address: "203.0.113.7",
		Verify: func(context.Context, migrateverify.Options) (migrateverify.Report, error) {
			return migrateverify.Report{CutoverAllowed: true, Verdict: "CUTOVER ALLOWED", Counts: migrateverify.Counts{PagesCompared: 1, PagesPass: 1}}, nil
		}})
	t.Cleanup(runner.Wait)
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Wizard: runner, Migrations: spy, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return f, runner, spy
}

func TestMoveAWebsiteHereRoutes(t *testing.T) {
	f, runner, spy := migrationFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	base := "/api/v1/websites/migrations"
	if w := websiteRequest(f.handler, "POST", base+"/sources", map[string]any{"host": "old.example.test", "port": 22}, nil, ""); w.Code != 401 {
		t.Fatalf("without a session: %d", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", base+"/sources", map[string]any{"host": "old.example.test", "port": 22}, cookie, ""); w.Code != 403 {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", base+"/sources", map[string]any{"host": "old.example.test", "port": 22, "password": "x"}, cookie, csrf); w.Code != 422 {
		t.Fatalf("a password field: %d %s", w.Code, w.Body.String())
	}
	w := websiteRequest(f.handler, "POST", base+"/sources", map[string]any{"host": "old.example.test", "port": 22}, cookie, csrf)
	var opened struct {
		Source MigrationSource `json:"source"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &opened) != nil || opened.Source.ID != testSourceID || !strings.Contains(opened.Source.KeyLine, "sifruno-migration-") || opened.Source.Pinned != "" {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "GET", base+"/sources/"+testSourceID+"/accounts", nil, cookie, ""); w.Code != 422 {
		t.Fatalf("accounts before the fingerprint: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "POST", base+"/sources/"+testSourceID+"/host-key", map[string]any{"fingerprint": "SHA256:zzz"}, cookie, csrf); w.Code != 422 || !strings.Contains(w.Body.String(), "something else answered") {
		t.Fatalf("a wrong fingerprint: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "POST", base+"/sources/"+testSourceID+"/host-key", map[string]any{"fingerprint": "SHA256:abc"}, cookie, csrf); w.Code != 200 || !spy.pinned {
		t.Fatalf("pin: %d %s", w.Code, w.Body.String())
	}
	w = websiteRequest(f.handler, "GET", base+"/sources/"+testSourceID+"/accounts", nil, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"user":"shopone"`) {
		t.Fatalf("accounts: %d %s", w.Code, w.Body.String())
	}
	w = websiteRequest(f.handler, "POST", base, map[string]any{"source": testSourceID, "username": "shopone"}, cookie, csrf)
	var started websiteJobBody
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &started) != nil || started.Job.Kind != wizard.KindMigration {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	runner.Wait()
	job, _ := runner.Get(started.Job.ID)
	if job.State != wizard.StateSucceeded || job.Migration.Gate != wizard.GateOpen || spy.finished != 1 {
		t.Fatalf("job: %+v %+v", job, job.Error)
	}
	if w := websiteRequest(f.handler, "POST", base+"/"+job.ID+"/accept", map[string]any{"reason": "fine"}, cookie, csrf); w.Code != 409 {
		t.Fatalf("accept with an open gate: %d %s", w.Code, w.Body.String())
	}
	w = websiteRequest(f.handler, "POST", base+"/"+job.ID+"/ready", map[string]any{}, cookie, csrf)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"gate":"ready"`) || !strings.Contains(w.Body.String(), "203.0.113.7") {
		t.Fatalf("ready: %d %s", w.Code, w.Body.String())
	}
	// The moved site is listed as a website of its kind.
	sites := decodeSites(t, websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "").Body.Bytes())
	if len(sites) != 1 || sites[0].Kind != wizard.KindPHP || sites[0].Domain != "shop.example.test" {
		t.Fatalf("sites: %+v", sites)
	}
	if w := websiteRequest(f.handler, "POST", base+"/"+strings.Repeat("0", 32)+"/verify", map[string]any{}, cookie, csrf); w.Code != 404 {
		t.Fatalf("an unknown job: %d %s", w.Code, w.Body.String())
	}
}

// An API token may not start a migration or read its key: the key signs in
// to another server as root.
func TestMoveAWebsiteHereRefusesAPITokens(t *testing.T) {
	f, _, spy := migrationFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "POST", "/api/v1/session/tokens", map[string]any{"name": "Billing", "expires_in_days": 30}, cookie, csrf)
	var created struct {
		Token string `json:"token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.Token == "" {
		t.Fatalf("create token: %d %s", w.Code, w.Body.String())
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/websites/migrations/sources"},
		{"GET", "/api/v1/websites/migrations/sources/" + testSourceID},
		{"GET", "/api/v1/websites/migrations/sources/" + testSourceID + "/accounts"},
		{"POST", "/api/v1/websites/migrations"},
		{"POST", "/api/v1/websites/migrations/" + strings.Repeat("0", 32) + "/ready"},
	} {
		var body any
		if c.method == "POST" {
			body = map[string]any{}
		}
		w := clientRequest(f.handler, false, c.method, c.path, created.Token, body)
		if w.Code != 403 || problemError(t, w) != "token_not_allowed" {
			t.Fatalf("%s %s with a token: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	if spy.pinned || spy.finished != 0 {
		t.Fatal("a token reached the broker")
	}
	// The website jobs a token may read are unchanged.
	if w := clientRequest(f.handler, false, "GET", "/api/v1/websites/jobs", created.Token, nil); w.Code != 200 {
		t.Fatalf("jobs with a token: %d", w.Code)
	}
}

func TestMoveAWebsiteHereUnavailable(t *testing.T) {
	f, _, _ := sitesFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/migrations/sources", map[string]any{"host": "old.example.test", "port": 22}, cookie, csrf); w.Code != 503 {
		t.Fatalf("without the broker's migrations: %d %s", w.Code, w.Body.String())
	}
}
