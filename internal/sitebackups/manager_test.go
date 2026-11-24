package sitebackups

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
)

type fakeBroker struct {
	mu         sync.Mutex
	accounts   []hostaccounts.Account
	configured bool
	calls      []string
	backupErr  error
	drill      hostaccounts.DrillResult
	restoreIn  []hostaccounts.RestoreInput
	// hang names a site (by its id's first letter) whose backup waits until
	// its context ends; during runs before a backup is answered.
	hang   string
	during func(id string)
}

func (b *fakeBroker) record(call string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, call)
}
func (b *fakeBroker) List(context.Context) ([]hostaccounts.Account, error) {
	return slices.Clone(b.accounts), nil
}
func (b *fakeBroker) BackupStatus(context.Context) (hostaccounts.BackupStatus, error) {
	return hostaccounts.BackupStatus{Ready: true, Configured: b.configured}, nil
}
func (b *fakeBroker) SetBackupTarget(context.Context, hostaccounts.BackupTargetInput, string) (hostaccounts.BackupTargetResult, error) {
	return hostaccounts.BackupTargetResult{}, nil
}
func (b *fakeBroker) ShowBackupPassword(context.Context, hostaccounts.BackupPasswordInput, string) (hostaccounts.BackupPassword, error) {
	return hostaccounts.BackupPassword{}, hostaccounts.ErrConflict
}
func (b *fakeBroker) ConfirmBackupPassword(context.Context, hostaccounts.BackupPasswordInput, string) (hostaccounts.BackupStatus, error) {
	return hostaccounts.BackupStatus{Ready: true, Configured: b.configured, PasswordSaved: true}, nil
}
func (b *fakeBroker) BackupAccount(ctx context.Context, id string, in hostaccounts.BackupInput, actor string) (hostaccounts.Snapshot, error) {
	b.record("backup " + id[:1] + " [" + strings.Join(in.Databases, ",") + "] " + actor)
	if b.during != nil {
		b.during(id)
	}
	if b.hang == id[:1] {
		<-ctx.Done()
	}
	if ctx.Err() != nil {
		return hostaccounts.Snapshot{}, ctx.Err()
	}
	if b.backupErr != nil {
		return hostaccounts.Snapshot{}, b.backupErr
	}
	return hostaccounts.Snapshot{ID: strings.Repeat("e", 64)}, nil
}
func (b *fakeBroker) ListBackups(context.Context, string) ([]hostaccounts.Snapshot, error) {
	return nil, nil
}
func (b *fakeBroker) RestoreAccount(_ context.Context, id string, in hostaccounts.RestoreInput, _ string) (hostaccounts.RestoreResult, error) {
	b.record("restore " + id[:1])
	b.mu.Lock()
	b.restoreIn = append(b.restoreIn, in)
	b.mu.Unlock()
	return hostaccounts.RestoreResult{}, nil
}
func (b *fakeBroker) DrillAccount(_ context.Context, id string, _ hostaccounts.DrillInput, _ string) (hostaccounts.DrillResult, error) {
	b.record("drill " + id[:1])
	d := b.drill
	d.AccountID = id
	return d, nil
}
func (b *fakeBroker) PruneBackups(context.Context, hostaccounts.PruneInput, string) (hostaccounts.PruneResult, error) {
	b.record("prune")
	return hostaccounts.PruneResult{Removed: 3}, nil
}

type fakeRegistry map[string][]string

func (r fakeRegistry) ListDatabases(_ context.Context, owner string) ([]dbhost.Database, error) {
	out := []dbhost.Database{}
	for _, name := range r[owner] {
		out = append(out, dbhost.Database{Name: name, Owner: owner})
	}
	// An entry recorded for another owner is never used, whatever the
	// registry answered.
	out = append(out, dbhost.Database{Name: owner + "_stolen", Owner: "someone"})
	return out, nil
}

func site(id, user string, live bool) hostaccounts.Account {
	a := hostaccounts.Account{ID: strings.Repeat(id, 32), Username: user, Domain: user + ".example", State: "active", Revision: 3}
	if live {
		a.Web = hostaccounts.WebState{PHPVersion: "8.3", QuotaMiB: 1024}
	}
	return a
}

func testManager(t *testing.T, b *fakeBroker) (*Manager, *time.Time) {
	t.Helper()
	m, err := Open(filepath.Join(t.TempDir(), "site-backups.json"), b, fakeRegistry{"alpha": {"alpha_wp"}, "beta": {"beta_wp", "beta_shop"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC) // a Monday
	m.loc = time.UTC
	m.now = func() time.Time { return now }
	return m, &now
}

func TestNightlyBackupsPruneAndDrillRotation(t *testing.T) {
	b := &fakeBroker{configured: true, accounts: []hostaccounts.Account{site("b", "beta", true), site("a", "alpha", true), site("c", "gamma", false)}, drill: hostaccounts.DrillResult{Passed: true, Files: 9, Subset: "1/8"}}
	m, now := testManager(t, b)
	ctx := context.Background()
	m.RunDue(ctx, *now)
	if len(b.calls) != 0 {
		t.Fatalf("ran before 02:30: %q", b.calls)
	}
	*now = now.Add(31 * time.Minute)
	m.RunDue(ctx, *now)
	want := []string{"backup a [alpha_wp] scheduler", "backup b [beta_shop,beta_wp] scheduler", "prune", "drill a"}
	if !slices.Equal(b.calls, want) {
		t.Fatalf("first night:\n got %q\nwant %q", b.calls, want)
	}
	m.RunDue(ctx, now.Add(2*time.Hour))
	if len(b.calls) != len(want) {
		t.Fatalf("ran twice in one night: %q", b.calls)
	}
	server := m.Server()
	if server.LastDrill == nil || !server.LastDrill.Passed || server.LastDrill.Domain != "alpha.example" || server.LastPrune == nil || server.LastPrune.Removed != 3 {
		t.Fatalf("server results %+v %+v", server.LastDrill, server.LastPrune)
	}
	if got := m.Site(strings.Repeat("a", 32)); got.LastBackup == nil || got.LastBackup.Status != "succeeded" || got.Running != nil {
		t.Fatalf("site after the night %+v", got)
	}
	// The next night of the same week backs up only.
	b.calls = nil
	*now = now.Add(24 * time.Hour)
	m.RunDue(ctx, *now)
	if !slices.Equal(b.calls, []string{"backup a [alpha_wp] scheduler", "backup b [beta_shop,beta_wp] scheduler"}) {
		t.Fatalf("second night %q", b.calls)
	}
	// A new week prunes again and drills the next site in turn.
	b.calls = nil
	*now = now.Add(6 * 24 * time.Hour)
	m.RunDue(ctx, *now)
	if !slices.Equal(b.calls[2:], []string{"prune", "drill b"}) {
		t.Fatalf("next week %q", b.calls)
	}
	// The state survives a restart: the same night does not run again.
	again, err := Open(m.path, b, fakeRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	again.loc, again.now = time.UTC, m.now
	b.calls = nil
	again.RunDue(ctx, *now)
	if len(b.calls) != 0 || again.Server().LastDrill.AccountID != strings.Repeat("b", 32) {
		t.Fatalf("after a restart %q", b.calls)
	}
}

// A panel stopped during the night goes on with the sites not yet done
// when it is back; the weekly work waits until every site is done.
func TestANightResumesAfterARestart(t *testing.T) {
	b := &fakeBroker{configured: true, accounts: []hostaccounts.Account{site("a", "alpha", true), site("b", "beta", true)}, drill: hostaccounts.DrillResult{Passed: true}}
	m, now := testManager(t, b)
	*now = now.Add(time.Hour)
	ctx, stop := context.WithCancel(context.Background())
	b.during = func(id string) {
		if id[:1] == "b" {
			stop() // the panel stops while beta's backup runs
		}
	}
	m.RunDue(ctx, *now)
	if !slices.Equal(b.calls, []string{"backup a [alpha_wp] scheduler", "backup b [beta_shop,beta_wp] scheduler"}) {
		t.Fatalf("before the stop %q", b.calls)
	}
	again, err := Open(m.path, b, fakeRegistry{"alpha": {"alpha_wp"}, "beta": {"beta_wp", "beta_shop"}})
	if err != nil {
		t.Fatal(err)
	}
	if again.st.LastNightly != "" || again.st.Sites[strings.Repeat("a", 32)].Nightly != "2026-11-23" || again.st.Sites[strings.Repeat("b", 32)].Nightly != "" {
		t.Fatalf("state after the stop: %+v a=%+v b=%+v", again.st, again.st.Sites[strings.Repeat("a", 32)], again.st.Sites[strings.Repeat("b", 32)])
	}
	again.loc, again.now = time.UTC, m.now
	b.calls, b.during = nil, nil
	again.RunDue(context.Background(), *now)
	if !slices.Equal(b.calls, []string{"backup b [beta_shop,beta_wp] scheduler", "prune", "drill a"}) {
		t.Fatalf("after the restart %q", b.calls)
	}
	b.calls = nil
	again.RunDue(context.Background(), now.Add(time.Hour))
	if len(b.calls) != 0 || again.st.LastNightly != "2026-11-23" {
		t.Fatalf("the night ran again %q", b.calls)
	}
}

// A site whose backup hangs is given up after the site limit, counts as
// done for the night, and the next site goes on.
func TestAHangingSiteDoesNotHoldUpTheNight(t *testing.T) {
	b := &fakeBroker{configured: true, hang: "a", accounts: []hostaccounts.Account{site("a", "alpha", true), site("b", "beta", true)}, drill: hostaccounts.DrillResult{Passed: true}}
	m, now := testManager(t, b)
	m.siteLimit = 50 * time.Millisecond
	if SiteLimit <= 2*time.Hour {
		t.Fatal("the panel must wait longer than the broker's own two-hour limit")
	}
	*now = now.Add(time.Hour)
	m.RunDue(context.Background(), *now)
	if !slices.Equal(b.calls, []string{"backup a [alpha_wp] scheduler", "backup b [beta_shop,beta_wp] scheduler", "prune", "drill a"}) {
		t.Fatalf("night %q", b.calls)
	}
	if got := m.Site(strings.Repeat("a", 32)).LastBackup; got == nil || got.Status != "failed" {
		t.Fatalf("the hanging site's result %+v", got)
	}
	if got := m.Site(strings.Repeat("b", 32)).LastBackup; got == nil || got.Status != "succeeded" || m.st.LastNightly != "2026-11-23" {
		t.Fatalf("the next site's result %+v", got)
	}
}

// The next night starts with the site that waited longest: never backed up
// first, then the oldest end, so a site a long night did not reach is not
// left last again.
func TestNightlyOrderStartsWithTheLongestWaiting(t *testing.T) {
	b := &fakeBroker{configured: true, accounts: []hostaccounts.Account{site("a", "alpha", true), site("b", "beta", true), site("c", "gamma", true)}}
	m, now := testManager(t, b)
	m.st.LastPruneWeek, m.st.LastDrillWeek = isoWeek(*now), isoWeek(*now)
	m.st.Sites[strings.Repeat("a", 32)] = &siteState{Nightly: "2026-11-22", NightlyEnded: time.Date(2026, 11, 22, 3, 0, 0, 0, time.UTC)}
	m.st.Sites[strings.Repeat("b", 32)] = &siteState{Nightly: "2026-11-21", NightlyEnded: time.Date(2026, 11, 21, 4, 0, 0, 0, time.UTC)}
	m.RunDue(context.Background(), now.Add(time.Hour))
	if !slices.Equal(b.calls, []string{"backup c [] scheduler", "backup b [beta_shop,beta_wp] scheduler", "backup a [alpha_wp] scheduler"}) {
		t.Fatalf("order %q", b.calls)
	}
}

func TestNothingRunsWithoutStorage(t *testing.T) {
	b := &fakeBroker{accounts: []hostaccounts.Account{site("a", "alpha", true)}}
	m, now := testManager(t, b)
	m.RunDue(context.Background(), now.Add(time.Hour))
	if len(b.calls) != 0 || m.st.LastNightly != "2026-11-23" {
		t.Fatalf("ran without storage: %q", b.calls)
	}
}

func TestJobsOnePerSiteAndFailuresExplained(t *testing.T) {
	b := &fakeBroker{configured: true, backupErr: &hostaccounts.BackupError{Step: "connect", Detail: "ssh: connect to host backup.example.test port 22: Connection refused"}}
	m, _ := testManager(t, b)
	a := site("a", "alpha", true)
	m.mu.Lock()
	m.running[a.ID] = BackupJob{Kind: "drill"}
	m.mu.Unlock()
	if _, err := m.BackUpNow(a, "local-operator"); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second job: %v", err)
	}
	m.mu.Lock()
	delete(m.running, a.ID)
	m.mu.Unlock()
	if _, err := m.BackUpNow(a, "local-operator"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	got := m.Site(a.ID).LastBackup
	if got == nil || got.Status != "failed" || got.Step != "connect" || !strings.Contains(got.Message, "could not reach the backup storage server") || !strings.Contains(got.Detail, "Connection refused") || got.Actor != "local-operator" {
		t.Fatalf("failed backup %+v", got)
	}
	// A database restore names the backup's databases that are still the
	// site's; one with none of them is refused before the broker.
	snap := hostaccounts.Snapshot{ID: strings.Repeat("d", 64), Databases: []string{"alpha_wp", "alpha_old"}}
	if _, err := m.Restore(context.Background(), a, snap, "both", "local-operator"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if in := b.restoreIn[0]; !in.Files || !slices.Equal(in.Databases, []string{"alpha_wp"}) || in.ExpectedRevision != 3 {
		t.Fatalf("restore input %+v", in)
	}
	if got := m.Site(a.ID).LastRestore; got == nil || got.Status != "succeeded" || got.What != "both" {
		t.Fatalf("restore result %+v", got)
	}
	if _, err := m.Restore(context.Background(), a, hostaccounts.Snapshot{ID: snap.ID, Databases: []string{"alpha_old"}}, "database", "local-operator"); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("no current database in the backup: %v", err)
	}
}

func TestExplain(t *testing.T) {
	for _, c := range []struct {
		err  error
		kind string
		want string
	}{
		{&hostaccounts.BackupError{Step: "target"}, "backup", "Backup storage is not set up, so nothing was backed up."},
		{&hostaccounts.BackupError{Step: "database", Detail: "The database alpha_wp has views, triggers, stored routines or events (trigger)."}, "backup", "The database alpha_wp has views"},
		{&hostaccounts.BackupError{Step: "database", Detail: "ERROR 2002 (HY000): Can't connect"}, "backup", "MariaDB did not answer"},
		{&hostaccounts.BackupError{Step: "database", Detail: "The database alpha_wp does not exist on this server, so it cannot be restored into."}, "restore", "cannot be restored into. The site was not changed."},
		{&hostaccounts.BackupError{Step: "space", Detail: "The backup needs up to 3.0 GiB of disk to restore."}, "restore", "There is not enough free disk space on this server, so the site was not changed. The backup needs up to 3.0 GiB"},
		{&hostaccounts.BackupError{Step: "space"}, "drill", "so the drill could not finish. Free up disk space"},
		{&hostaccounts.BackupError{Step: "compare"}, "drill", "did not match the backup's own file list"},
		{&hostaccounts.BackupError{Step: "import"}, "restore", "may be partly restored"},
		{hostaccounts.ErrUnavailable, "backup", "Run the installer again"},
		{&registryError{errors.New("socket")}, "backup", "registry"},
	} {
		if got, _, _ := Explain(c.err, c.kind); !strings.Contains(got, c.want) {
			t.Errorf("%v: %q", c.err, got)
		}
	}
}
