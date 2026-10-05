package hostwebgeneration

import (
	"context"
	"errors"
	"testing"
)

// Real temporary journal with injected inventory/executor: protocol evidence,
// never daemon execution. The three snapshots are independently varied.
func TestRecoveryReviewSnapshotGuardMatrix(t *testing.T) {
	for _, changed := range []bool{false, true} {
		name := "all_three_same"
		if changed {
			name = "before_differs_from_after_and_current"
		}
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			f.apply(t)
			initial, e := f.c.Status()
			if e != nil {
				t.Fatal(e)
			}
			if changed {
				f.provider.rows[0].Domain = "new.example.test"
				f.provider.rows[0].Revision++
			}
			f.executor.apply = func(_ context.Context, tr Transition) error {
				f.executor.identity = tr.After.Identity()
				return errors.New("interrupted")
			}
			e = f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator:review", "snapshot matrix"})
			if !errors.Is(e, ErrRecovery) {
				t.Fatal(e)
			}
			f.reopen(t)
			f.executor.rollback = func(_ context.Context, tr Transition, g Generation) error {
				if changed {
					if !g.Denied || g.SnapshotSHA256 != digest(f.provider.rows) {
						t.Fatal("changed snapshot did not compile fresh denial")
					}
				} else {
					if g.Denied || g.Identity() != *initial.Current || g.SnapshotSHA256 != tr.After.SnapshotSHA256 {
						t.Fatal("legitimate same-snapshot serving restore refused")
					}
				}
				f.executor.identity = g.Identity()
				return nil
			}
			f.recover(t)
			f.reopen(t)
			final, e := f.c.Status()
			if e != nil || final.Revision != 2 || final.PendingOperation != "" || final.Current == nil || final.Current.Denied != changed || f.executor.rollbacks != 1 {
				t.Fatalf("final=%+v err=%v rollbacks=%d", final, e, f.executor.rollbacks)
			}
		})
	}
}

func TestRecoveryReviewSnapshotGuardUnknownObservedRefused(t *testing.T) {
	f := setup(t)
	f.apply(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		return errors.New("interrupted")
	}
	if e := f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator:review", "unknown observed"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	st, e := f.c.Status()
	if e != nil {
		t.Fatal(e)
	}
	unknown := f.executor.identity
	unknown.GenerationID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	f.executor.identity = unknown
	e = f.c.Recover(context.Background(), RecoverInput{st.Revision, st.PendingOperation, "operator:review", "must refuse unknown"})
	if e == nil || f.executor.rollbacks != 0 {
		t.Fatalf("unknown identity admitted: %v rollbacks=%d", e, f.executor.rollbacks)
	}
	final, e := f.c.Status()
	if e != nil || final.Revision != st.Revision || final.PendingOperation != st.PendingOperation {
		t.Fatalf("mutated counter or pending: %+v %v", final, e)
	}
}
