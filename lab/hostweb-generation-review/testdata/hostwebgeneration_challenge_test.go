package hostwebgeneration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
)

// These independent doubles attest only coordinator protocol behavior. They
// do not read installed daemons, mount maps, native ownership, or serving state.
type reviewProvider struct {
	accounts    []hostaccounts.Account
	postFailure bool
	callbacks   int
}
type reviewLease struct {
	p   *reviewProvider
	ctx context.Context
}

func (l reviewLease) Accounts() []hostaccounts.Account {
	return append([]hostaccounts.Account(nil), l.p.accounts...)
}
func (l reviewLease) Context() context.Context         { return l.ctx }
func (l reviewLease) Verify(ctx context.Context) error { return ctx.Err() }
func (p *reviewProvider) WithSnapshot(ctx context.Context, fn func(SnapshotLease) error) error {
	p.callbacks++
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := fn(reviewLease{p, ctx}); err != nil {
		return err
	}
	if p.postFailure {
		return errors.New("late independent native drift")
	}
	return nil
}

type reviewExecutor struct {
	identity                    Identity
	applyCalls, rollbackCalls   int
	partialFailure, mutateInput bool
	hook                        func()
}

func (e *reviewExecutor) Observe(ctx context.Context) (Identity, error) { return e.identity, ctx.Err() }
func (e *reviewExecutor) Apply(ctx context.Context, tr Transition) error {
	e.applyCalls++
	e.identity = tr.After.Identity()
	if e.mutateInput {
		tr.After.Accounts[0].Home = "/caller-mutated"
		tr.After.Bundle.Files[0].Data[0] ^= 1
	}
	if e.hook != nil {
		e.hook()
	}
	if e.partialFailure {
		return errors.New("executor failed after transition")
	}
	return ctx.Err()
}
func (e *reviewExecutor) Rollback(ctx context.Context, tr Transition, target Generation) error {
	e.rollbackCalls++
	e.identity = target.Identity()
	return ctx.Err()
}
func reviewProfile() hostweb.Profile {
	return hostweb.Profile{Name: hostweb.RestrictedChrootV1, ManagedRoot: "/var/lib/sifruno/hostweb", ManagedHomeRoot: "/srv/sifruno-managed-homes", FrontChroot: "/var/lib/sifruno/front-jail", ApacheModuleRoot: "/usr/lib64/httpd/modules", BackendChrootRoot: "/var/lib/sifruno/backend-jails", RuntimeRoot: "/run/sifruno/hostweb", ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", TLSRoot: "/etc/sifruno/tls", CAFile: "/etc/sifruno/tls/ca.pem", FrontendIP: "127.0.0.1"}
}
func reviewSetup(t *testing.T) (*Coordinator, *reviewProvider, *reviewExecutor, string) {
	t.Helper()
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	a := hostaccounts.Account{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Username: "reviewacct", Domain: "review.example.test", Home: "/srv/sifruno-managed-homes/reviewacct", PublicHTML: "/srv/sifruno-managed-homes/reviewacct/public_html", State: "active", UID: 20000, GID: 20000, Revision: 1, CreatedAt: now, UpdatedAt: now}
	p, e := &reviewProvider{accounts: []hostaccounts.Account{a}}, &reviewExecutor{}
	dir := filepath.Join(t.TempDir(), "generation-state")
	c, err := Open(dir, reviewProfile(), p, e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	plan, err := c.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e.identity = plan.Current
	return c, p, e, dir
}
func reviewApply(t *testing.T, c *Coordinator) {
	t.Helper()
	plan, err := c.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Apply(context.Background(), ApplyInput{Plan: plan, Actor: "review", Reason: "Independent generation challenge"}); err != nil {
		t.Fatal(err)
	}
}
func reviewRecovery(t *testing.T, c *Coordinator) RecoverInput {
	t.Helper()
	st, err := c.Status()
	if err != nil || st.PendingOperation == "" {
		t.Fatal("missing pending recovery", err)
	}
	return RecoverInput{ExpectedRevision: st.Revision, OperationID: st.PendingOperation, Actor: "review", Reason: "Explicit independent recovery"}
}
func TestReviewGenerationFullCASAndReplay(t *testing.T) {
	c, _, e, _ := reviewSetup(t)
	original, err := c.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changes := []func(*Plan){func(p *Plan) { p.Revision++ }, func(p *Plan) { p.ProfileSHA256 = "" }, func(p *Plan) { p.SnapshotSHA256 = "" }, func(p *Plan) { p.BundleSHA256 = "" }, func(p *Plan) { p.Current.Denied = false }, func(p *Plan) { p.Current.GenerationID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }}
	for _, change := range changes {
		plan := original
		change(&plan)
		if err := c.Apply(context.Background(), ApplyInput{Plan: plan, Actor: "review", Reason: "Stale review plan"}); err == nil {
			t.Fatal("incomplete CAS accepted")
		}
	}
	if e.applyCalls != 0 {
		t.Fatal("stale CAS invoked executor")
	}
	if err := c.Apply(context.Background(), ApplyInput{Plan: original, Actor: "review", Reason: "Valid plan"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(context.Background(), ApplyInput{Plan: original, Actor: "review", Reason: "Replay plan"}); err == nil || e.applyCalls != 1 {
		t.Fatal("replay reached executor", err)
	}
}
func TestReviewGenerationPartialFailureReopenChangedSnapshotDenied(t *testing.T) {
	c, p, e, dir := reviewSetup(t)
	e.partialFailure = true
	plan, _ := c.Plan(context.Background())
	if err := c.Apply(context.Background(), ApplyInput{Plan: plan, Actor: "review", Reason: "Partial execution"}); err == nil {
		t.Fatal("partial failure committed")
	}
	before, _ := c.Status()
	if before.PendingOperation == "" {
		t.Fatal("pending intent lost")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, reviewProfile(), p, e)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.Status()
	if err != nil || before != after {
		t.Fatal("reopen lost pending state", err)
	}
	if _, err = reopened.Plan(context.Background()); err == nil {
		t.Fatal("pending reopen admitted plan")
	}
	p.accounts[0].State = "suspended"
	p.accounts[0].Revision++
	p.accounts[0].UpdatedAt = p.accounts[0].UpdatedAt.Add(time.Second)
	if err = reopened.Recover(context.Background(), reviewRecovery(t, reopened)); err != nil {
		t.Fatal(err)
	}
	st, err := reopened.Status()
	if err != nil || st.PendingOperation != "" || st.Current == nil || !st.Current.Denied || e.rollbackCalls != 1 || e.identity != *st.Current {
		t.Fatal("changed snapshot did not recover denied", err)
	}
}
func TestReviewGenerationUnexpectedObservationNeverRollsBack(t *testing.T) {
	c, _, e, _ := reviewSetup(t)
	e.partialFailure = true
	plan, _ := c.Plan(context.Background())
	if c.Apply(context.Background(), ApplyInput{Plan: plan, Actor: "review", Reason: "Partial execution"}) == nil {
		t.Fatal("fixture failure missing")
	}
	e.identity.GenerationID = "cccccccccccccccccccccccccccccccc"
	if err := c.Recover(context.Background(), reviewRecovery(t, c)); err == nil || e.rollbackCalls != 0 {
		t.Fatal("unknown identity overwritten", err)
	}
	if st, err := c.Status(); err != nil || st.PendingOperation == "" {
		t.Fatal("unknown observation cleared pending", err)
	}
}
func TestReviewGenerationProviderFailureAfterObservedCommitQuarantines(t *testing.T) {
	c, p, e, dir := reviewSetup(t)
	plan, _ := c.Plan(context.Background())
	p.postFailure = true
	if err := c.Apply(context.Background(), ApplyInput{Plan: plan, Actor: "review", Reason: "Late lease failure"}); err == nil {
		t.Fatal("late failure reported success")
	}
	st, err := c.Status()
	if err != nil || st.PendingOperation == "" || st.Phase != "recovery_required" || st.Current == nil || *st.Current != e.identity {
		t.Fatal("observed commit left falsely clean ledger", err)
	}
	c.Close()
	reopened, err := Open(dir, reviewProfile(), p, e)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if after, err := reopened.Status(); err != nil || after.PendingOperation != st.PendingOperation {
		t.Fatal("postcallback quarantine not durable", err)
	}
}
func TestReviewGenerationCallerCannotMutateStoredTransition(t *testing.T) {
	c, _, e, _ := reviewSetup(t)
	e.mutateInput = true
	reviewApply(t, c)
	st, err := c.Status()
	if err != nil || st.Current == nil || *st.Current != e.identity {
		t.Fatal("executor input mutation corrupted generation", err)
	}
	if _, err = c.Plan(context.Background()); err != nil {
		t.Fatal("mutable executor data poisoned stored bundle", err)
	}
}
func TestReviewGenerationStateCorruptionRejectedWithoutStatusPoll(t *testing.T) {
	c, p, e, _ := reviewSetup(t)
	reviewApply(t, c)
	if err := c.persistence.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(stateBucket)
		var st state
		if err := json.Unmarshal(b.Get(stateKey), &st); err != nil {
			return err
		}
		st.Revision += 9
		raw, _ := json.Marshal(st)
		return b.Put(stateKey, raw)
	}); err != nil {
		t.Fatal(err)
	}
	callbacks, calls := p.callbacks, e.applyCalls
	if _, err := c.Plan(context.Background()); err == nil || p.callbacks != callbacks || e.applyCalls != calls {
		t.Fatal("state-only corruption admitted protocol call", err)
	}
}
func TestReviewGenerationExecutorJournalDamageCannotCommit(t *testing.T) {
	c, _, e, _ := reviewSetup(t)
	e.hook = func() {
		if err := c.persistence.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(eventBucket).Delete([]byte("00000000000000000001")) }); err != nil {
			t.Fatal(err)
		}
	}
	plan, _ := c.Plan(context.Background())
	if err := c.Apply(context.Background(), ApplyInput{Plan: plan, Actor: "review", Reason: "Journal damaged during executor"}); err == nil {
		t.Fatal("executor-time durable journal damage reported committed success")
	}
}
func TestReviewGenerationStorageBoundStopsBeforeExecutor(t *testing.T) {
	c, _, e, _ := reviewSetup(t)
	for i := 0; i < MaxGenerations-1; i++ {
		reviewApply(t, c)
	}
	calls := e.applyCalls
	plan, err := c.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Apply(context.Background(), ApplyInput{Plan: plan, Actor: "review", Reason: "Generation count boundary"}); err == nil || e.applyCalls != calls {
		t.Fatal("storage bound acted before rejection", err)
	}
	if st, err := c.Status(); err != nil || st.PendingOperation != "" {
		t.Fatal("limit poisoned idle state", err)
	}
}

func TestReviewGenerationHardlinkedDatabaseRejected(t *testing.T) {
	c, p, e, dir := reviewSetup(t)
	alias := filepath.Join(dir, "unexpected-hardlink.db")
	if err := os.Link(filepath.Join(dir, "generations.db"), alias); err != nil {
		t.Fatal("isolated filesystem did not permit hardlink challenge", err)
	}
	defer os.Remove(alias)
	callbacks, calls := p.callbacks, e.applyCalls
	if _, err := c.Plan(context.Background()); err == nil || p.callbacks != callbacks || e.applyCalls != calls {
		t.Fatal("hardlinked database admitted before identity guard", err)
	}
}
