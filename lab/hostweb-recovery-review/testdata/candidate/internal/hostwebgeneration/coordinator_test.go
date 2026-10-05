package hostwebgeneration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
)

// These executors simulate protocol state only. None launches native daemons.
type testProvider struct {
	mu                 sync.Mutex
	rows               []hostaccounts.Account
	drift, postFailure bool
}
type testLease struct {
	provider *testProvider
	ctx      context.Context
}

func (l testLease) Accounts() []hostaccounts.Account {
	return append([]hostaccounts.Account(nil), l.provider.rows...)
}
func (l testLease) Context() context.Context { return l.ctx }
func (l testLease) Verify(ctx context.Context) error {
	if l.provider.drift {
		return errors.New("native drift")
	}
	return ctx.Err()
}
func (p *testProvider) WithSnapshot(ctx context.Context, cb func(SnapshotLease) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := cb(testLease{p, ctx})
	if err == nil && p.postFailure {
		return errors.New("postverification failed")
	}
	return err
}

type testExecutor struct {
	identity                     Identity
	applies, rollbacks, observes int
	apply                        func(context.Context, Transition) error
	rollback                     func(context.Context, Transition, Generation) error
	observe                      func(context.Context) (Identity, error)
}

func (e *testExecutor) Observe(ctx context.Context) (Identity, error) {
	e.observes++
	if e.observe != nil {
		return e.observe(ctx)
	}
	return e.identity, ctx.Err()
}
func (e *testExecutor) Apply(ctx context.Context, t Transition) error {
	e.applies++
	if e.apply != nil {
		return e.apply(ctx, t)
	}
	e.identity = t.After.Identity()
	return nil
}
func (e *testExecutor) Rollback(ctx context.Context, t Transition, g Generation) error {
	e.rollbacks++
	if e.rollback != nil {
		return e.rollback(ctx, t, g)
	}
	e.identity = g.Identity()
	return nil
}

type testSetup struct {
	dir      string
	c        *Coordinator
	provider *testProvider
	executor *testExecutor
	profile  hostweb.Profile
}

func setup(t *testing.T) *testSetup {
	t.Helper()
	if guardOwner() != nil {
		t.Skip("Unix store tests require root; Windows tests use private protocol state")
	}
	profile := hostweb.Profile{Name: hostweb.RestrictedChrootV1, ManagedRoot: "/var/lib/sifruno-web", ManagedHomeRoot: "/home/sifruno-managed", FrontChroot: "/srv/sifruno-web-front", ApacheModuleRoot: "/usr/lib64/httpd/modules", BackendChrootRoot: "/srv/sifruno-web-jails", RuntimeRoot: "/run/sifruno-web-runtime", ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", TLSRoot: "/etc/sifruno-web-tls", CAFile: "/etc/sifruno-web-tls/ca.pem", FrontendIP: "127.0.0.1", FrontendPort: 18081, BackendPort: 18443, FrontUID: 48, FrontGID: 48, ControllerUID: 2000}
	stamp := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	provider := &testProvider{rows: []hostaccounts.Account{{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Username: "webalpha", Domain: "webalpha.example.test", Home: "/home/sifruno-managed/webalpha", PublicHTML: "/home/sifruno-managed/webalpha/public_html", State: "active", UID: 20000, GID: 20000, Revision: 1, CreatedAt: stamp, UpdatedAt: stamp}}}
	executor := &testExecutor{}
	dir := filepath.Join(t.TempDir(), "private-generation-state")
	c, err := Open(dir, profile, provider, executor)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := c.generation("", provider.rows, true)
	if err != nil {
		t.Fatal(err)
	}
	executor.identity = denied.Identity()
	f := &testSetup{dir, c, provider, executor, profile}
	t.Cleanup(func() {
		if f.c != nil {
			f.c.Close()
		}
	})
	return f
}
func (f *testSetup) plan(t *testing.T) Plan {
	t.Helper()
	p, e := f.c.Plan(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func (f *testSetup) apply(t *testing.T) {
	t.Helper()
	if e := f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator:fixture", "protocol apply"}); e != nil {
		t.Fatal(e)
	}
}
func (f *testSetup) reopen(t *testing.T) {
	t.Helper()
	if e := f.c.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	f.c, e = Open(f.dir, f.profile, f.provider, f.executor)
	if e != nil {
		t.Fatal(e)
	}
}
func (f *testSetup) recover(t *testing.T) {
	t.Helper()
	st, e := f.c.Status()
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.Recover(context.Background(), RecoverInput{st.Revision, st.PendingOperation, "operator:fixture", "protocol recovery"}); e != nil {
		t.Fatal(e)
	}
}

func TestCASCommitAndReplay(t *testing.T) {
	f := setup(t)
	plan := f.plan(t)
	for _, modify := range []func(*Plan){func(p *Plan) { p.Revision++ }, func(p *Plan) { p.BundleSHA256 = "bad" }, func(p *Plan) { p.SnapshotSHA256 = "bad" }, func(p *Plan) { p.ProfileSHA256 = "bad" }, func(p *Plan) { p.Current.Denied = false }} {
		bad := plan
		modify(&bad)
		if e := f.c.Apply(context.Background(), ApplyInput{bad, "operator", "CAS check"}); !errors.Is(e, ErrConflict) {
			t.Fatalf("CAS failure: %v", e)
		}
	}
	if f.executor.applies != 0 {
		t.Fatal("stale request executed")
	}
	if e := f.c.Apply(context.Background(), ApplyInput{plan, "operator", "first apply"}); e != nil {
		t.Fatal(e)
	}
	if e := f.c.Apply(context.Background(), ApplyInput{plan, "operator", "replay apply"}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale replay accepted")
	}
	st, e := f.c.Status()
	if e != nil || st.Revision != 1 || st.Phase != "idle" || st.Current == nil || st.Current.Denied {
		t.Fatalf("commit status %+v %v", st, e)
	}
	f.reopen(t)
	history, e := f.c.History()
	if e != nil || len(history) != 2 || history[0].Phase != "intended" || history[1].Phase != "committed" || history[0].Before != plan.Current || history[1].After != *st.Current {
		t.Fatal("before/after history not durable")
	}
}

func TestCrashLeavesPendingAndExplicitDeniedRecovery(t *testing.T) {
	f := setup(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		panic("simulated crash after native write")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("crash not exercised")
			}
		}()
		_ = f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "crash boundary"})
	}()
	f.reopen(t)
	if _, e := f.c.Plan(context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal("pending crash allowed plan")
	}
	st, _ := f.c.Status()
	if e := f.c.Recover(context.Background(), RecoverInput{st.Revision + 1, st.PendingOperation, "operator", "stale recovery"}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale pending revision accepted")
	}
	f.recover(t)
	st, e := f.c.Status()
	if e != nil || st.Current == nil || !st.Current.Denied || st.PendingOperation != "" || st.Revision != 1 {
		t.Fatalf("denied recovery %+v %v", st, e)
	}
}

func TestFailureChangedAccountRequiresDeniedRecovery(t *testing.T) {
	f := setup(t)
	f.apply(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		return errors.New("partial executor failure")
	}
	if e := f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "partial failure"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	f.reopen(t)
	f.provider.rows[0].State = "suspended"
	f.provider.rows[0].Revision++
	f.recover(t)
	st, e := f.c.Status()
	if e != nil || st.Current == nil || !st.Current.Denied || st.Current.SnapshotSHA256 != digest(f.provider.rows) {
		t.Fatalf("stale previous generation restored %+v %v", st, e)
	}
}

func TestFailureUnchangedSnapshotCanRestorePrevious(t *testing.T) {
	f := setup(t)
	f.apply(t)
	before, _ := f.c.Status()
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		return errors.New("partial executor failure")
	}
	_ = f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "partial failure"})
	f.recover(t)
	after, e := f.c.Status()
	if e != nil || *after.Current != *before.Current || after.Revision != 2 {
		t.Fatal("safe prior generation not restored")
	}
}

func TestUnknownObservationNeverMutates(t *testing.T) {
	f := setup(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		return errors.New("unknown response")
	}
	_ = f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "failed apply"})
	f.executor.identity.GenerationID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	st, _ := f.c.Status()
	if e := f.c.Recover(context.Background(), RecoverInput{st.Revision, st.PendingOperation, "operator", "unknown generation"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	if f.executor.rollbacks != 0 {
		t.Fatal("unknown third-party generation overwritten")
	}
}

func TestProviderPostFailureQuarantinesObservedCommit(t *testing.T) {
	f := setup(t)
	plan := f.plan(t)
	f.provider.postFailure = true
	if e := f.c.Apply(context.Background(), ApplyInput{plan, "operator", "post verification failure"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	f.provider.postFailure = false
	f.reopen(t)
	st, e := f.c.Status()
	if e != nil || st.Revision != 1 || st.PendingOperation == "" || st.Phase != "recovery_required" {
		t.Fatalf("failed lease left clean ledger %+v %v", st, e)
	}
	f.recover(t)
}

func TestExecutorCannotMutateRetainedInputs(t *testing.T) {
	f := setup(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		tr.After.Accounts[0].State = "suspended"
		tr.Before.Accounts[0].Username = "changed"
		tr.After.Bundle.Files[0].Data[0] = 'X'
		tr.Before.Bundle.Files[0].Data[0] = 'X'
		return nil
	}
	f.apply(t)
	f.reopen(t)
	if f.provider.rows[0].State != "active" || f.provider.rows[0].Username != "webalpha" {
		t.Fatal("caller snapshot mutated")
	}
	if _, e := f.c.Plan(context.Background()); e != nil {
		t.Fatal("retained bundle was aliased", e)
	}
}

func TestNativeDriftAndDeadlineCannotCommit(t *testing.T) {
	f := setup(t)
	plan := f.plan(t)
	f.provider.drift = true
	if e := f.c.Apply(context.Background(), ApplyInput{plan, "operator", "native drift"}); e == nil || f.executor.applies != 0 {
		t.Fatal("unrevised native drift ignored")
	}
	f.provider.drift = false
	f.executor.apply = func(ctx context.Context, tr Transition) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > ExecutorTimeout {
			t.Fatal("executor deadline missing")
		}
		<-ctx.Done()
		f.executor.identity = tr.After.Identity()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e := f.c.Apply(ctx, ApplyInput{plan, "operator", "expired executor"}); !errors.Is(e, ErrRecovery) {
		t.Fatal("expired success committed", e)
	}
	st, e := f.c.Status()
	if e != nil || st.Current != nil || st.PendingOperation == "" {
		t.Fatal("deadline must retain pending")
	}
}

func TestDurableCorruptionRejectedBeforeExecutor(t *testing.T) {
	for _, corrupt := range []func(*bolt.Tx) error{
		func(tx *bolt.Tx) error {
			var st state
			_ = json.Unmarshal(tx.Bucket(stateBucket).Get(stateKey), &st)
			st.Revision++
			raw, _ := json.Marshal(st)
			return tx.Bucket(stateBucket).Put(stateKey, raw)
		},
		func(tx *bolt.Tx) error { return tx.Bucket(eventBucket).Delete([]byte("00000000000000000001")) },
	} {
		f := setup(t)
		f.apply(t)
		plan := f.plan(t)
		calls := f.executor.applies
		if e := f.c.persistence.db.Update(corrupt); e != nil {
			t.Fatal(e)
		}
		if e := f.c.Apply(context.Background(), ApplyInput{plan, "operator", "damaged journal"}); !errors.Is(e, ErrRecovery) || calls != f.executor.applies {
			t.Fatal("corrupt journal executed", e)
		}
	}
}

func TestJournalDamageDuringExecutionCannotCommit(t *testing.T) {
	f := setup(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		return f.c.persistence.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(eventBucket).Delete([]byte("00000000000000000001")) })
	}
	if e := f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "concurrent journal damage"}); !errors.Is(e, ErrRecovery) {
		t.Fatal("damaged ledger committed", e)
	}
}

func TestGenerationBoundRejectsBeforeExecutor(t *testing.T) {
	f := setup(t)
	for i := 0; i < MaxGenerations-1; i++ {
		f.apply(t)
	}
	calls := f.executor.applies
	if e := f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "generation bound"}); !errors.Is(e, ErrLimit) || f.executor.applies != calls {
		t.Fatal("generation bound did not reserve recovery capacity", e)
	}
}

func TestUnsafeDatabaseHardlinkRejected(t *testing.T) {
	f := setup(t)
	if e := f.c.Close(); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(filepath.Join(f.dir, "generations.db"), filepath.Join(f.dir, "alias.db")); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(f.dir, f.profile, f.provider, f.executor); !errors.Is(e, ErrUnavailable) {
		t.Fatal("hardlinked database admitted", e)
	}
}

func TestEventBoundPreservesPendingWithoutFurtherExecutorCalls(t *testing.T) {
	f := setup(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		return errors.New("partial failure")
	}
	if e := f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "event capacity"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	f.executor.rollback = func(context.Context, Transition, Generation) error { return errors.New("rollback unavailable") }
	for i := 0; i < MaxEvents; i++ {
		st, e := f.c.Status()
		if e != nil {
			t.Fatal(e)
		}
		_ = f.c.Recover(context.Background(), RecoverInput{st.Revision, st.PendingOperation, "operator", "bounded repeated recovery"})
	}
	history, e := f.c.History()
	if e != nil || len(history) > MaxEvents || len(history) < MaxEvents-2 {
		t.Fatalf("event bound %d %v", len(history), e)
	}
	before := f.executor.rollbacks
	st, e := f.c.Status()
	if e != nil || st.PendingOperation == "" {
		t.Fatal("bound erased pending")
	}
	_ = f.c.Recover(context.Background(), RecoverInput{st.Revision, st.PendingOperation, "operator", "exhausted recovery"})
	if f.executor.rollbacks != before {
		t.Fatal("executor invoked without recovery journal capacity")
	}
}

func TestInitialEmptyInventoryRequiresObservedDeniedIdentity(t *testing.T) {
	f := setup(t)
	f.provider.rows = nil
	plan := f.plan(t)
	if e := f.c.Apply(context.Background(), ApplyInput{plan, "operator", "empty initial inventory"}); !errors.Is(e, ErrConflict) || f.executor.applies != 0 {
		t.Fatal("unobserved initial denial admitted", e)
	}
	denied, e := f.c.generation("", nil, true)
	if e != nil {
		t.Fatal(e)
	}
	f.executor.identity = denied.Identity()
	if e = f.c.Apply(context.Background(), ApplyInput{plan, "operator", "observed empty inventory"}); e != nil {
		t.Fatal(e)
	}
}

func TestWrongObservedBundleNeverCommits(t *testing.T) {
	f := setup(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		f.executor.identity.BundleSHA256 = digest("different bytes")
		return nil
	}
	if e := f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "wrong observed bundle"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	st, e := f.c.Status()
	if e != nil || st.Current != nil || st.PendingOperation == "" {
		t.Fatal("unverified bundle committed")
	}
}

func TestConcurrentCASAllowsOneCommit(t *testing.T) {
	f := setup(t)
	plan := f.plan(t)
	results := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < 2; i++ {
		go func() {
			start.Wait()
			results <- f.c.Apply(context.Background(), ApplyInput{plan, "operator", "concurrent CAS"})
		}()
	}
	start.Done()
	success, conflict := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 || f.executor.applies != 1 {
		t.Fatal("concurrent stale plans both executed")
	}
}

func TestRecoveryPostFailureRemainsQuarantined(t *testing.T) {
	f := setup(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		return errors.New("partial failure")
	}
	_ = f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "failed apply"})
	f.provider.postFailure = true
	st, e := f.c.Status()
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.Recover(context.Background(), RecoverInput{st.Revision, st.PendingOperation, "operator", "failed final recovery verification"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	f.provider.postFailure = false
	f.reopen(t)
	st, e = f.c.Status()
	if e != nil || st.Revision != 1 || st.Phase != "recovery_required" || st.PendingOperation == "" {
		t.Fatal("failed recovery lease left clean state", e)
	}
	f.recover(t)
}
