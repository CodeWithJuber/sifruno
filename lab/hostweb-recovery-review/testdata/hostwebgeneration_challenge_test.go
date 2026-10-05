package hostwebgeneration

import (
	"context"
	"errors"
	"testing"
)

// Counter-bearing protocol model. It never starts a process. The actual
// coordinator journal, compiler and durable reopen are exercised below.
type recoveryReviewCounter struct {
	configured                Identity
	revision                  uint64
	last                      string
	original                  Transition
	pending                   *RecoveryPending
	completed                 *RecoveryBinding
	healthy                   bool
	repairWrites, repairCalls int
	applyMode                 string
	finishFault               func()
	corruptReceipt            bool
	repairError               bool
	actual                    *Identity
	partialHealthy            bool
	repairHook                func()
}

func (e *recoveryReviewCounter) stateSHA() string {
	return digest(struct {
		Revision   uint64
		Configured Identity
		Pending    *RecoveryPending
		Completed  *RecoveryBinding
	}{e.revision, e.configured, e.pending, e.completed})
}
func (e *recoveryReviewCounter) Observe(ctx context.Context) (Identity, error) {
	if ctx.Err() != nil {
		return Identity{}, ctx.Err()
	}
	if !e.healthy {
		return Identity{}, ErrRecovery
	}
	if e.finishFault != nil && e.original.OperationID != "" {
		fault := e.finishFault
		e.finishFault = nil
		fault()
	}
	if e.actual != nil {
		return *e.actual, nil
	}
	return e.configured, nil
}
func (e *recoveryReviewCounter) Apply(ctx context.Context, tr Transition) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if tr.Revision != e.revision || tr.Before.Identity() != e.configured {
		return ErrConflict
	}
	e.original = copiedTransition(tr)
	if e.applyMode == "committed" {
		e.revision++
		e.last = tr.OperationID
		e.configured = tr.After.Identity()
		return nil
	}
	e.pending = &RecoveryPending{OperationID: tr.OperationID, Revision: tr.Revision, Before: tr.Before.Identity(), After: tr.After.Identity(), Target: tr.After.Identity()}
	e.healthy = false
	if e.partialHealthy {
		v := tr.After.Identity()
		e.actual = &v
		e.healthy = true
	}
	return errors.New("protocol partial launch")
}
func (e *recoveryReviewCounter) Rollback(context.Context, Transition, Generation) error {
	return errors.New("legacy rollback excluded in this protocol model")
}
func (e *recoveryReviewCounter) InspectRecovery(ctx context.Context) (RecoveryInspection, error) {
	if ctx.Err() != nil {
		return RecoveryInspection{}, ctx.Err()
	}
	out := RecoveryInspection{StateSHA256: e.stateSHA(), Revision: e.revision, LastOperationID: e.last, Configured: e.configured}
	if e.pending != nil {
		v := *e.pending
		out.Pending = &v
	}
	if e.completed != nil {
		v := *e.completed
		out.Completed = &v
	}
	if e.healthy {
		v := e.configured
		if e.actual != nil {
			v = *e.actual
		}
		out.Observed = &v
	}
	return out, nil
}
func (e *recoveryReviewCounter) RepairDenied(ctx context.Context, q DeniedRepairRequest) (DeniedRepairReceipt, error) {
	e.repairCalls++
	if e.repairHook != nil {
		hook := e.repairHook
		e.repairHook = nil
		hook()
	}
	if ctx.Err() != nil {
		return DeniedRepairReceipt{}, ctx.Err()
	}
	if e.repairError {
		return DeniedRepairReceipt{}, ErrRecovery
	}
	b := recoveryBinding(q)
	if e.completed != nil && e.completed.AttemptID == q.AttemptID {
		want := b
		want.AdmittedStateSHA256 = e.completed.AdmittedStateSHA256
		if want != *e.completed || !e.healthy || (q.ExpectedStateSHA256 != e.stateSHA() && q.ExpectedStateSHA256 != e.completed.AdmittedStateSHA256) {
			return DeniedRepairReceipt{}, ErrConflict
		}
		b = *e.completed
	} else {
		if q.ExpectedStateSHA256 != e.stateSHA() || q.BaseRevision != e.revision || q.Source != e.configured || !q.Target.Denied {
			return DeniedRepairReceipt{}, ErrConflict
		}
		e.repairWrites++
		e.revision++
		e.configured = q.Target.Identity()
		e.last = q.Original.OperationID
		e.pending = nil
		e.completed = &b
		e.healthy = true
		e.actual = nil
	}
	receipt := DeniedRepairReceipt{Binding: b, ResultRevision: e.revision, Observed: e.configured}
	if e.corruptReceipt {
		receipt.ResultRevision++
	}
	return receipt, nil
}
func recoveryReviewSetup(t *testing.T) (*testSetup, *recoveryReviewCounter) {
	t.Helper()
	f := setup(t)
	g, e := f.c.generation("", f.provider.rows, true)
	if e != nil {
		t.Fatal(e)
	}
	model := &recoveryReviewCounter{configured: g.Identity(), healthy: true}
	f.c.executor = model
	return f, model
}
func recoveryReviewReopen(t *testing.T, f *testSetup, e *recoveryReviewCounter) {
	t.Helper()
	_ = f.c.Close()
	var err error
	f.c, err = Open(f.dir, f.profile, f.provider, e)
	if err != nil {
		t.Fatal(err)
	}
}
func recoveryReviewRepair(t *testing.T, f *testSetup) error {
	t.Helper()
	st, e := f.c.Status()
	if e != nil {
		t.Fatal(e)
	}
	return f.c.RepairDenied(context.Background(), RepairInput{ExpectedRevision: st.Revision, PendingOperation: st.PendingOperation, Actor: "operator:review", Reason: "counter-bearing protocol recovery"})
}
func recoveryReviewPartial(t *testing.T, f *testSetup) {
	t.Helper()
	e := f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator:review", "protocol partial launch"})
	if !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
}

func TestRecoveryReviewOriginalNativeApplyCommitCannotInventCounter(t *testing.T) {
	f, e := recoveryReviewSetup(t)
	e.applyMode = "committed"
	// Close only this temporary journal after native-model Apply committed,
	// before coordinator finish, preserving the actual intended event on disk.
	plan := f.plan(t)
	e.finishFault = func() { _ = f.c.persistence.db.Close() }
	err := f.c.Apply(context.Background(), ApplyInput{plan, "operator:review", "native commit before coordinator finish"})
	if !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	recoveryReviewReopen(t, f, e)
	st, err := f.c.Status()
	if err != nil || st.Revision != 0 || st.PendingOperation == "" || e.revision != 1 || e.completed != nil || e.pending != nil {
		t.Fatalf("wrong original commit window: %+v native=%+v err=%v", st, e, err)
	}
	if err = recoveryReviewRepair(t, f); err == nil || e.repairWrites != 0 || e.revision != 1 {
		t.Fatalf("invented counter reconciliation: %v %+v", err, e)
	}
	final, err := f.c.Status()
	if err != nil || final.Revision != 0 || final.PendingOperation != st.PendingOperation {
		t.Fatalf("counter mismatch was hidden: %+v %v", final, err)
	}
}

func TestRecoveryReviewPostCallbackReconfirmationConsumesOnce(t *testing.T) {
	f, e := recoveryReviewSetup(t)
	recoveryReviewPartial(t, f)
	f.provider.postFailure = true
	if err := recoveryReviewRepair(t, f); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	st, err := f.c.Status()
	if err != nil || st.Revision != 1 || st.PendingOperation == "" || e.revision != 1 || e.repairWrites != 1 {
		t.Fatalf("postcallback quarantine: %+v native=%+v %v", st, e, err)
	}
	f.provider.postFailure = false
	recoveryReviewReopen(t, f, e)
	if err = recoveryReviewRepair(t, f); err != nil {
		t.Fatal(err)
	}
	recoveryReviewReopen(t, f, e)
	final, err := f.c.Status()
	if err != nil || final.Revision != 1 || final.PendingOperation != "" || final.Current == nil || !final.Current.Denied || e.revision != 1 || e.repairWrites != 1 {
		t.Fatalf("double consumed counter: %+v native=%+v %v", final, e, err)
	}
}

func TestRecoveryReviewMalformedReceiptCannotCommitServing(t *testing.T) {
	f, e := recoveryReviewSetup(t)
	recoveryReviewPartial(t, f)
	e.corruptReceipt = true
	if err := recoveryReviewRepair(t, f); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	st, err := f.c.Status()
	if err != nil || st.Revision != 0 || st.PendingOperation == "" || st.Current != nil || e.revision != 1 || e.repairWrites != 1 {
		t.Fatalf("bad receipt committed: %+v native=%+v %v", st, e, err)
	}
	e.corruptReceipt = false
	recoveryReviewReopen(t, f, e)
	if err = recoveryReviewRepair(t, f); err != nil {
		t.Fatal(err)
	}
	final, err := f.c.Status()
	if err != nil || final.Revision != 1 || final.PendingOperation != "" || e.repairWrites != 1 {
		t.Fatalf("retry mutated consumed native counter: %+v native=%+v %v", final, e, err)
	}
}

func TestRecoveryReviewHistoricalDeadCompletionCheckpointIsNotServing(t *testing.T) {
	f, e := recoveryReviewSetup(t)
	recoveryReviewPartial(t, f)
	e.corruptReceipt = true
	if err := recoveryReviewRepair(t, f); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	e.corruptReceipt = false
	e.healthy = false
	// Refuse the next native mutation before its intent. A counter checkpoint
	// may persist, but must retain Pending and the prior verified Current.
	e.repairError = true
	err := recoveryReviewRepair(t, f)
	if !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	st, se := f.c.Status()
	if se != nil || st.Current != nil || st.PendingOperation == "" || st.Revision != 1 || e.revision != 1 || e.repairWrites != 1 {
		t.Fatalf("checkpoint claimed serving: %+v native=%+v %v", st, e, se)
	}
	history, se := f.c.History()
	if se != nil {
		t.Fatal(se)
	}
	checkpoints := 0
	for _, event := range history {
		if event.Phase == "repair_checkpoint" {
			checkpoints++
		}
	}
	if checkpoints != 1 {
		t.Fatalf("checkpoint count=%d", checkpoints)
	}
	recoveryReviewReopen(t, f, e)
	e.repairError = false
	if err = recoveryReviewRepair(t, f); err != nil {
		t.Fatal(err)
	}
	final, se := f.c.Status()
	if se != nil || final.Revision != 2 || final.PendingOperation != "" || final.Current == nil || !final.Current.Denied || e.revision != 2 || e.repairWrites != 2 {
		t.Fatalf("new attempt reused consumed counter: %+v native=%+v %v", final, e, se)
	}
	history, se = f.c.History()
	if se != nil {
		t.Fatal(se)
	}
	checkpoints = 0
	for _, event := range history {
		if event.Phase == "repair_checkpoint" {
			checkpoints++
		}
	}
	if checkpoints != 1 {
		t.Fatalf("checkpoint replayed: %d", checkpoints)
	}
}

func TestRecoveryReviewHonestPartialTargetAndUnknownObserved(t *testing.T) {
	for _, mode := range []string{"honest_pending_target", "wrong_pending_target", "third_observed"} {
		t.Run(mode, func(t *testing.T) {
			f, e := recoveryReviewSetup(t)
			e.partialHealthy = true
			recoveryReviewPartial(t, f)
			if e.actual == nil || *e.actual == e.configured {
				t.Fatal("partial state did not separate durable Current from actual target")
			}
			if mode == "wrong_pending_target" {
				e.pending.Target.GenerationID = "ffffffffffffffffffffffffffffffff"
			}
			if mode == "third_observed" {
				e.actual.GenerationID = "ffffffffffffffffffffffffffffffff"
			}
			err := recoveryReviewRepair(t, f)
			st, se := f.c.Status()
			if mode == "honest_pending_target" {
				if err != nil || se != nil || st.Revision != 1 || st.PendingOperation != "" || st.Current == nil || !st.Current.Denied || e.repairWrites != 1 {
					t.Fatalf("honest owned partial target rejected: %+v native=%+v %v %v", st, e, err, se)
				}
			} else if err == nil || se != nil || st.Revision != 0 || st.PendingOperation == "" || e.repairWrites != 0 {
				t.Fatalf("foreign inspection admitted: %+v native=%+v %v %v", st, e, err, se)
			}
		})
	}
}

func TestRecoveryReviewLeaseAndCancellationCannotAuthorizeReceipt(t *testing.T) {
	for _, mode := range []string{"canceled_before", "lease_drift_before", "canceled_native_call", "lease_drift_after_native_commit"} {
		t.Run(mode, func(t *testing.T) {
			f, e := recoveryReviewSetup(t)
			recoveryReviewPartial(t, f)
			st, se := f.c.Status()
			if se != nil {
				t.Fatal(se)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "canceled_before":
				cancel()
			case "lease_drift_before":
				f.provider.drift = true
			case "canceled_native_call":
				e.repairHook = cancel
			case "lease_drift_after_native_commit":
				e.repairHook = func() { f.provider.drift = true }
			}
			err := f.c.RepairDenied(ctx, RepairInput{ExpectedRevision: st.Revision, PendingOperation: st.PendingOperation, Actor: "operator:review", Reason: "lease and cancellation boundary"})
			if err == nil {
				t.Fatal("failed authority returned completion")
			}
			final, se := f.c.Status()
			if se != nil || final.Revision != 0 || final.PendingOperation != st.PendingOperation || final.Current != nil {
				t.Fatalf("failed authority committed: %+v %v", final, se)
			}
			want := 0
			if mode == "lease_drift_after_native_commit" {
				want = 1
			}
			if e.repairWrites != want || e.revision != uint64(want) {
				t.Fatalf("native mutation crossed boundary: %+v", e)
			}
			if mode == "lease_drift_after_native_commit" {
				f.provider.drift = false
				if err = recoveryReviewRepair(t, f); err != nil {
					t.Fatal(err)
				}
				final, se = f.c.Status()
				if se != nil || final.Revision != 1 || final.PendingOperation != "" || e.repairWrites != 1 {
					t.Fatalf("postlease retry double incremented: %+v %+v %v", final, e, se)
				}
			}
		})
	}
}
