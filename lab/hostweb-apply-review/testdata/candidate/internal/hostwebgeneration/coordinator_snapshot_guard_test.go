package hostwebgeneration

import (
	"context"
	"errors"
	"testing"

	"sifruno/internal/hostaccounts"
)

// The coordinator uses a real temporary journal; the reserved inventory and
// executor are injected protocol models of the native rollback contract.
// This test does not launch daemons or claim native recovery qualification.
func TestRecoverDeniesWhenOnlyBeforeMatchesReservedSnapshot(t *testing.T) {
	f := setup(t)
	f.apply(t)
	before, err := f.c.Status()
	if err != nil || before.Current == nil || before.Current.Denied {
		t.Fatalf("initial serving generation: %+v %v", before, err)
	}
	priorAccounts := append([]hostaccounts.Account(nil), f.provider.rows...)
	f.provider.rows[0].Domain = "changed.example.test"
	f.provider.rows[0].Revision++
	f.executor.apply = func(_ context.Context, tr Transition) error {
		if tr.Before.Identity() != *before.Current || tr.Before.SnapshotSHA256 == tr.After.SnapshotSHA256 {
			t.Fatal("fixture did not exercise distinct Before/After snapshots")
		}
		f.executor.identity = tr.After.Identity()
		return errors.New("fixture interrupted apply after native change")
	}
	if err = f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator:fixture", "changed snapshot interruption"}); !errors.Is(err, ErrRecovery) {
		t.Fatalf("interrupted apply: %v", err)
	}
	f.reopen(t)
	// Deliberately present the exact older inventory. Matching Before alone
	// cannot authorize serving rollback across a different failed After.
	f.provider.rows = priorAccounts
	f.executor.rollback = func(_ context.Context, tr Transition, target Generation) error {
		if !target.Denied {
			return errors.New("native contract refuses serving rollback across snapshots")
		}
		if target.SnapshotSHA256 != digest(priorAccounts) || target.Identity() == tr.Before.Identity() {
			t.Fatal("denial was not compiled from the reserved current inventory")
		}
		f.executor.identity = target.Identity()
		return nil
	}
	f.recover(t)
	f.reopen(t)
	after, err := f.c.Status()
	if err != nil || after.Current == nil || !after.Current.Denied || after.Current.SnapshotSHA256 != digest(priorAccounts) || after.Revision != 2 || after.PendingOperation != "" || f.executor.rollbacks != 1 {
		t.Fatalf("durable current-snapshot denial: %+v %v; rollbacks=%d", after, err, f.executor.rollbacks)
	}
}
