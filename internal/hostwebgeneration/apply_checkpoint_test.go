package hostwebgeneration

import (
	"context"
	"errors"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"testing"
)

// Counter-bearing owned JSON/Bolt stores model the protocol only; these tests
// do not execute Linux processes or qualify actual fsync/controller-death faults.
type applyModel struct {
	*repairModel
	crashApply bool
}

func applyExecutor(t *testing.T, f *testSetup) *applyModel {
	m := &applyModel{repairModel: model(t, f)}
	f.c.executor = m
	return m
}
func (m *applyModel) Apply(ctx context.Context, tr Transition) error {
	in, e := m.InspectRecovery(ctx)
	if e != nil {
		return e
	}
	if e = m.repairModel.Apply(ctx, tr); e != nil {
		return e
	}
	b := ApplyCompletionBinding{Version: ApplyCompletionVersion, Kind: ApplyCompletionKind, OperationID: tr.OperationID, OriginalRevision: tr.Revision, NativeBaseRevision: tr.Revision, Before: tr.Before.Identity(), After: tr.After.Identity(), AdmittedStateSHA256: in.StateSHA256, InputsSHA256: digest("isolated installation inputs"), BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
	b.IntentSHA256 = ApplyIntentSHA(b)
	s := m.read()
	s.CompletedApply = &ApplyCompletion{b, tr.Revision + 1}
	m.write(s)
	if m.crashApply {
		m.crashApply = false
		panic("original apply marker persisted before coordinator finish")
	}
	return nil
}
func crashOriginal(t *testing.T, f *testSetup, m *applyModel) {
	t.Helper()
	m.crashApply = true
	in := ApplyInput{f.plan(t), "operator", "original apply crash"}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing original crash")
			}
		}()
		_ = f.c.Apply(context.Background(), in)
	}()
}
func setupConsumed(t *testing.T, alive bool) (*testSetup, *applyModel) {
	t.Helper()
	f := setup(t)
	m := applyExecutor(t, f)
	f.apply(t)
	crashOriginal(t, f, m)
	m.alive = alive
	return f, m
}
func TestApplyCheckpointHealthyOrDeadAfterKeepsCurrentAndDenies(t *testing.T) {
	for _, alive := range []bool{false, true} {
		t.Run(fmt.Sprint(alive), func(t *testing.T) {
			f, m := setupConsumed(t, alive)
			before, e := f.c.Status()
			if e != nil {
				t.Fatal(e)
			}
			a := *m.read().CompletedApply
			m.beforeMutation = func(req DeniedRepairRequest) {
				st, e := f.c.persistence.read(f.c)
				if e != nil || st.Revision != 2 || st.Current != before.Current.GenerationID || st.Pending == nil || st.Pending.ApplyCheckpoint == nil || st.Pending.ApplyCheckpoint.Completion != a {
					t.Fatal("checkpoint lost current/proof", st, e)
				}
				if req.BaseRevision != 2 || req.Source != a.Binding.After || req.Original.Revision != 1 || !req.Target.Denied {
					t.Fatal("wrong denial source/base")
				}
			}
			repair(t, f)
			s, e := f.c.Status()
			if e != nil || s.Revision != 3 || m.read().Revision != 3 || !s.Current.Denied || m.mutations != 1 {
				t.Fatal(s, e)
			}
			f.reopen(t)
			if _, e = f.c.Status(); e != nil {
				t.Fatal("replay failed", e)
			}
		})
	}
}
func TestApplyCheckpointPreNativeFailureReopenSameAttemptNoSecondAdvance(t *testing.T) {
	f, m := setupConsumed(t, false)
	wrapper := &failBeforeNative{repairModel: m.repairModel}
	f.c.executor = wrapper
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	st, e := f.c.persistence.read(f.c)
	if e != nil || st.Revision != 2 || st.Pending.ApplyCheckpoint == nil {
		t.Fatal(st, e)
	}
	saved := clonePending(st.Pending)
	f.reopen(t)
	f.c.executor = m
	m.beforeMutation = func(req DeniedRepairRequest) {
		if req.AttemptID != saved.Repair.Binding.AttemptID || req.Source != saved.Repair.Binding.Source || req.Original.Revision != saved.ApplyCheckpoint.Completion.Binding.OriginalRevision {
			t.Fatal("attempt changed")
		}
	}
	repair(t, f)
	h, e := f.c.History()
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	for _, event := range h {
		if event.Phase == "apply_checkpoint" {
			n++
		}
	}
	if n != 1 || m.read().Revision != 3 || m.mutations != 1 {
		t.Fatal("counter repeated", n)
	}
}
func TestApplyCheckpointPartialNativeRetryAndProviderReconfirm(t *testing.T) {
	f, m := setupConsumed(t, false)
	m.partial = true
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	if m.read().CompletedApply == nil || m.read().Pending == nil {
		t.Fatal("native Apply proof not retained")
	}
	f.provider.postFailure = true
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 3 {
		t.Fatal(s, e)
	}
	f.provider.postFailure = false
	f.reopen(t)
	f.c.executor = m
	repair(t, f)
	s, e = f.c.Status()
	if e != nil || s.Revision != 3 || s.PendingOperation != "" || m.mutations != 1 {
		t.Fatal(s, e)
	}
}
func TestApplyCheckpointAlreadyCommittedQuarantineNeverAdvancesTwice(t *testing.T) {
	f := setup(t)
	m := applyExecutor(t, f)
	plan := f.plan(t)
	f.provider.postFailure = true
	if e := f.c.Apply(context.Background(), ApplyInput{plan, "operator", "original postcallback"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	f.provider.postFailure = false
	m.beforeMutation = func(req DeniedRepairRequest) {
		st, e := f.c.persistence.read(f.c)
		if e != nil || st.Revision != 1 || st.Pending.ApplyCheckpoint.CounterAdvanced || req.BaseRevision != 1 {
			t.Fatal("already consumed counter advanced", st, e)
		}
	}
	repair(t, f)
	s, e := f.c.Status()
	if e != nil || s.Revision != 2 || m.read().Revision != 2 {
		t.Fatal(s, e)
	}
}
func TestApplyCheckpointChangedCurrentAccountsNeverRestoreActiveAfter(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint(remove), func(t *testing.T) {
			f, m := setupConsumed(t, true)
			a := *m.read().CompletedApply
			if remove {
				f.provider.rows = nil
			} else {
				f.provider.rows[0].State = "suspended"
				f.provider.rows[0].Revision++
			}
			expected, _ := f.c.generation("", f.provider.rows, true)
			m.beforeMutation = func(req DeniedRepairRequest) {
				if !req.Target.Denied || req.Target.SnapshotSHA256 == a.Binding.After.SnapshotSHA256 || req.Target.SnapshotSHA256 != expected.SnapshotSHA256 {
					t.Fatal("stale inventory denial")
				}
			}
			repair(t, f)
		})
	}
}
func TestApplyCheckpointMalformedMetadataAndMissingMarkerFailClosed(t *testing.T) {
	for name, change := range map[string]func(*ApplyCompletion){
		"version": func(a *ApplyCompletion) { a.Binding.Version++ }, "kind": func(a *ApplyCompletion) { a.Binding.Kind = "rollback" }, "result": func(a *ApplyCompletion) { a.ResultRevision++ }, "original": func(a *ApplyCompletion) { a.Binding.OriginalRevision++ }, "before": func(a *ApplyCompletion) { a.Binding.Before.BundleSHA256 = digest("foreign") }, "cas": func(a *ApplyCompletion) { a.Binding.AdmittedStateSHA256 = "bad" }, "inputs": func(a *ApplyCompletion) { a.Binding.InputsSHA256 = "bad" }, "boot": func(a *ApplyCompletion) { a.Binding.BootID = "bad" }, "digest": func(a *ApplyCompletion) { a.Binding.IntentSHA256 = digest("different") },
	} {
		t.Run(name, func(t *testing.T) {
			f, m := setupConsumed(t, false)
			m.inspectHook = func(i *RecoveryInspection) { a := *i.CompletedApply; change(&a); i.CompletedApply = &a }
			if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) || m.calls != 0 || m.read().Revision != 2 {
				t.Fatal("bad receipt acted", e)
			}
		})
	}
	f, m := setupConsumed(t, false)
	s := m.read()
	s.CompletedApply = nil
	m.write(s)
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) || m.calls != 0 {
		t.Fatal("marker synthesized", e)
	}
}
func TestApplyCheckpointJournalSemanticTamperRejectsBeforeMutation(t *testing.T) {
	for name, change := range map[string]func([]Event, *state){
		"counter marker": func(events []Event, _ *state) {
			for i := range events {
				if events[i].ApplyCheckpoint != nil {
					events[i].ApplyCheckpoint.CounterAdvanceOnly = false
				}
			}
		},
		"counter advanced": func(events []Event, _ *state) {
			for i := range events {
				if events[i].ApplyCheckpoint != nil {
					events[i].ApplyCheckpoint.CounterAdvanced = false
				}
			}
		},
		"completion result": func(events []Event, _ *state) {
			for i := range events {
				if events[i].ApplyCheckpoint != nil {
					events[i].ApplyCheckpoint.Completion.ResultRevision++
				}
			}
		},
		"phase": func(events []Event, _ *state) {
			for i := range events {
				if events[i].Phase == "apply_checkpoint" {
					events[i].Phase = "committed"
				}
			}
		},
		"current": func(events []Event, s *state) {
			for _, event := range events {
				if event.Phase == "apply_checkpoint" {
					s.Current = event.After.GenerationID
				}
			}
		},
		"drop retained": func(events []Event, _ *state) { events[len(events)-1].ApplyCheckpoint = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f, m := setupConsumed(t, false)
			f.c.executor = &failBeforeNative{repairModel: m.repairModel}
			_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
			in := repairInput(t, f.c)
			f.c.executor = m
			calls := m.calls
			rewriteRepairHistory(t, f.c, change)
			if e := f.c.RepairDenied(context.Background(), in); !errors.Is(e, ErrRecovery) || m.calls != calls {
				t.Fatal("corrupt checkpoint acted", e)
			}
		})
	}
}
func TestApplyCheckpointCancellationAndLeaseBeforeWrite(t *testing.T) {
	f, m := setupConsumed(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := f.c.RepairDenied(ctx, repairInput(t, f.c)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	p := &boundaryProvider{rows: f.provider.rows, failAt: 2}
	f.c.provider = p
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 1 || m.calls != 0 {
		t.Fatal("unverified checkpoint wrote", s, e)
	}
}
func TestApplyCheckpointRetainedMarkerCannotChangeOnRetry(t *testing.T) {
	f, m := setupConsumed(t, false)
	f.c.executor = &failBeforeNative{repairModel: m.repairModel}
	_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
	f.c.executor = m
	m.inspectHook = func(i *RecoveryInspection) {
		a := *i.CompletedApply
		a.Binding.InputsSHA256 = digest("different valid installation")
		a.Binding.IntentSHA256 = ApplyIntentSHA(a.Binding)
		i.CompletedApply = &a
	}
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) || m.calls != 0 {
		t.Fatal("saved proof replaced", e)
	}
}
func TestApplyCheckpointUnknownMetadataFieldsCannotExecute(t *testing.T) {
	f, m := setupConsumed(t, false)
	f.c.executor = &failBeforeNative{repairModel: m.repairModel}
	_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
	in := repairInput(t, f.c)
	f.c.executor = m
	if e := f.c.persistence.db.Update(func(tx *bolt.Tx) error {
		raw := append([]byte(nil), tx.Bucket(stateBucket).Get(stateKey)...)
		raw = append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
		return tx.Bucket(stateBucket).Put(stateKey, raw)
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.c.RepairDenied(context.Background(), in); !errors.Is(e, ErrRecovery) || m.calls != 0 {
		t.Fatal("unknown state decoded", e)
	}
}

func TestApplyCheckpointCurrentCASCanRefreshBeforeFirstDeniedIntent(t *testing.T) {
	f, m := setupConsumed(t, false)
	p := &boundaryProvider{rows: f.provider.rows, failAt: 3}
	f.c.provider = p
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	st, e := f.c.persistence.read(f.c)
	if e != nil || st.Revision != 2 || st.Pending.ApplyCheckpoint == nil || st.Pending.Repair != nil {
		t.Fatal("not checkpoint-only", st, e)
	}
	saved := *st.Pending.ApplyCheckpoint
	// Models an owned native cleanup changing state bytes/pins while the original
	// completion tuple and consumed counter remain exact. No fake serving proof.
	s := m.read()
	s.StateEpoch++
	m.write(s)
	in, e := m.InspectRecovery(context.Background())
	if e != nil || in.StateSHA256 == saved.InspectedStateSHA256 {
		t.Fatal("CAS did not change")
	}
	p.failAt = 0
	m.beforeMutation = func(req DeniedRepairRequest) {
		if req.ExpectedStateSHA256 != in.StateSHA256 || req.BaseRevision != 2 || req.Source != saved.Completion.Binding.After {
			t.Fatal("historical token reused")
		}
	}
	repair(t, f)
	if m.read().Revision != 3 || m.mutations != 1 {
		t.Fatal("wrong counter")
	}
}

func TestApplyCheckpointEveryLeaseBoundaryRetainsUncertainState(t *testing.T) {
	for at := 1; at <= 5; at++ {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			f, m := setupConsumed(t, false)
			p := &boundaryProvider{rows: f.provider.rows, failAt: at}
			f.c.provider = p
			if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
				t.Fatal(e)
			}
			s, e := f.c.Status()
			want := uint64(2)
			if at < 3 {
				want = 1
			}
			if e != nil || s.Revision != want || s.PendingOperation == "" {
				t.Fatal("lease boundary lost recovery", s, e)
			}
			if at < 5 && m.calls != 0 || at == 5 && m.mutations != 1 {
				t.Fatal("unverified native effect", at, m.calls)
			}
		})
	}
}
func TestApplyCheckpointLateCancellationCannotCommitCoordinator(t *testing.T) {
	f, m := setupConsumed(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.beforeMutation = func(DeniedRepairRequest) { cancel() }
	if e := f.c.RepairDenied(ctx, repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 2 || s.PendingOperation == "" || m.read().Revision != 3 {
		t.Fatal("expired effect committed", s, e)
	}
	m.beforeMutation = nil
	repair(t, f)
	s, e = f.c.Status()
	if e != nil || s.Revision != 3 || m.mutations != 1 {
		t.Fatal("canceled replay repeated counter", s, e)
	}
}
func TestApplyCheckpointBoundRejectsBeforeNativeAction(t *testing.T) {
	f, m := setupConsumed(t, false)
	st, e := f.c.persistence.read(f.c)
	if e != nil {
		t.Fatal(e)
	}
	for st.Sequence <= MaxEvents-5 {
		if e = f.c.persistence.markRecovery(&st, f.c); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 1 || s.PendingOperation == "" || m.calls != 0 {
		t.Fatal("no checkpoint budget acted", s, e)
	}
}
func TestApplyCheckpointCoexistenceAndUnknownObservationRefuse(t *testing.T) {
	for name, change := range map[string]func(*RecoveryInspection){
		"generic pending": func(i *RecoveryInspection) {
			b := i.CompletedApply.Binding
			i.Pending = &RecoveryPending{OperationID: b.OperationID, Revision: i.Revision, Before: b.Before, After: b.After, Target: b.After}
		},
		"completed repair": func(i *RecoveryInspection) { i.Completed = &RecoveryBinding{} },
		"foreign observed": func(i *RecoveryInspection) {
			x := i.Configured
			x.GenerationID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			i.Observed = &x
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, m := setupConsumed(t, false)
			m.inspectHook = change
			if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) || m.calls != 0 {
				t.Fatal("invalid coexistence acted", e)
			}
		})
	}
}
func TestApplyCheckpointCannotReplayDuplicateCheckpoint(t *testing.T) {
	f, m := setupConsumed(t, false)
	f.c.executor = &failBeforeNative{repairModel: m.repairModel}
	_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
	in := repairInput(t, f.c)
	f.c.executor = m
	rewriteRepairHistory(t, f.c, func(events []Event, _ *state) {
		events[len(events)-1].Phase = "apply_checkpoint"
		events[len(events)-1].After = events[len(events)-1].ApplyCheckpoint.Completion.Binding.After
	})
	if e := f.c.RepairDenied(context.Background(), in); !errors.Is(e, ErrRecovery) || m.calls != 0 {
		t.Fatal("duplicate checkpoint executed", e)
	}
}
