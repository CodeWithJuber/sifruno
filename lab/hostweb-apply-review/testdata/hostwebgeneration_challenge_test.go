package hostwebgeneration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// A counter-bearing model of durable native metadata, never a native process.
// Actual coordinator persistence, compiler and reopen are used by every test.
type applyReviewNative struct {
	configured                    Identity
	revision                      uint64
	last                          string
	original                      Transition
	marker                        *ApplyCompletion
	pending                       *RecoveryPending
	completed                     *RecoveryBinding
	healthy                       bool
	writes, calls                 int
	finishFault                   func()
	finishFaultAt                 uint64
	inspectHook                   func(*RecoveryInspection)
	repairError, malformedReceipt bool
	repairHook                    func()
	request                       *DeniedRepairRequest
	metadataEpoch                 uint64
	persistPending                bool
}

func (m *applyReviewNative) audit() any {
	return struct {
		Revision      uint64
		Configured    Identity
		Writes, Calls int
		Healthy       bool
	}{m.revision, m.configured, m.writes, m.calls, m.healthy}
}

func (m *applyReviewNative) sha() string {
	return digest(struct {
		Revision      uint64
		Configured    Identity
		Apply         *ApplyCompletion
		Pending       *RecoveryPending
		Completed     *RecoveryBinding
		MetadataEpoch uint64
	}{m.revision, m.configured, m.marker, m.pending, m.completed, m.metadataEpoch})
}
func (m *applyReviewNative) Observe(ctx context.Context) (Identity, error) {
	if ctx.Err() != nil {
		return Identity{}, ctx.Err()
	}
	if !m.healthy {
		return Identity{}, ErrRecovery
	}
	if m.finishFault != nil && m.revision == m.finishFaultAt {
		fn := m.finishFault
		m.finishFault = nil
		fn()
	}
	return m.configured, nil
}
func (m *applyReviewNative) Apply(ctx context.Context, tr Transition) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if tr.Revision != m.revision || tr.Before.Identity() != m.configured {
		return ErrConflict
	}
	b := ApplyCompletionBinding{Version: 1, Kind: "apply", OperationID: tr.OperationID, OriginalRevision: tr.Revision, NativeBaseRevision: tr.Revision, Before: tr.Before.Identity(), After: tr.After.Identity(), AdmittedStateSHA256: m.sha(), InputsSHA256: digest("fixed reviewed input"), BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
	b.IntentSHA256 = ApplyIntentSHA(b)
	m.original = copiedTransition(tr)
	m.revision++
	m.last = tr.OperationID
	m.configured = tr.After.Identity()
	m.marker = &ApplyCompletion{b, m.revision}
	m.pending = nil
	m.completed = nil
	m.healthy = true
	return nil
}
func (*applyReviewNative) Rollback(context.Context, Transition, Generation) error {
	return errors.New("legacy rollback excluded from this model")
}
func (m *applyReviewNative) InspectRecovery(ctx context.Context) (RecoveryInspection, error) {
	if ctx.Err() != nil {
		return RecoveryInspection{}, ctx.Err()
	}
	in := RecoveryInspection{StateSHA256: m.sha(), Revision: m.revision, LastOperationID: m.last, Configured: m.configured}
	if m.marker != nil {
		v := *m.marker
		in.CompletedApply = &v
	}
	if m.pending != nil {
		v := *m.pending
		if v.Repair != nil {
			b := *v.Repair
			v.Repair = &b
		}
		in.Pending = &v
	}
	if m.completed != nil {
		v := *m.completed
		in.Completed = &v
	}
	if m.healthy {
		v := m.configured
		in.Observed = &v
	}
	if m.inspectHook != nil {
		m.inspectHook(&in)
	}
	return in, nil
}
func (m *applyReviewNative) RepairDenied(ctx context.Context, q DeniedRepairRequest) (DeniedRepairReceipt, error) {
	m.calls++
	if m.repairHook != nil {
		fn := m.repairHook
		m.repairHook = nil
		fn()
	}
	if ctx.Err() != nil {
		return DeniedRepairReceipt{}, ctx.Err()
	}
	saved := copiedRepair(q)
	m.request = &saved
	if m.repairError {
		if m.persistPending {
			b := recoveryBinding(q)
			m.pending = &RecoveryPending{OperationID: q.Original.OperationID, Revision: q.BaseRevision, Before: q.Original.Before.Identity(), After: q.Original.After.Identity(), Target: q.Target.Identity(), Repair: &b}
		}
		return DeniedRepairReceipt{}, ErrRecovery
	}
	b := recoveryBinding(q)
	if m.pending != nil && m.pending.Repair != nil && m.pending.Repair.AttemptID == q.AttemptID {
		b.AdmittedStateSHA256 = m.pending.Repair.AdmittedStateSHA256
		if b != *m.pending.Repair {
			return DeniedRepairReceipt{}, ErrConflict
		}
	}
	if m.completed != nil && m.completed.AttemptID == q.AttemptID {
		b.AdmittedStateSHA256 = m.completed.AdmittedStateSHA256
		if b != *m.completed || !m.healthy || (q.ExpectedStateSHA256 != m.sha() && q.ExpectedStateSHA256 != b.AdmittedStateSHA256) {
			return DeniedRepairReceipt{}, ErrConflict
		}
	} else {
		if q.ExpectedStateSHA256 != m.sha() || q.BaseRevision != m.revision || q.Source != m.configured || !q.Target.Denied {
			return DeniedRepairReceipt{}, ErrConflict
		}
		if m.marker != nil && q.Original.OperationID == m.marker.Binding.OperationID && (q.Original.Revision != m.marker.Binding.OriginalRevision || q.Original.Before.Identity() != m.marker.Binding.Before || q.Original.After.Identity() != m.marker.Binding.After) {
			return DeniedRepairReceipt{}, ErrConflict
		}
		if m.marker != nil && q.Original.OperationID != m.marker.Binding.OperationID && (q.Original.Revision != m.revision || q.Original.Before.Identity() != m.configured || q.Original.OperationID == m.last) {
			return DeniedRepairReceipt{}, ErrConflict
		}
		m.writes++
		m.revision++
		m.configured = q.Target.Identity()
		m.last = q.Original.OperationID
		m.marker = nil
		m.pending = nil
		m.completed = &b
		m.healthy = true
	}
	r := DeniedRepairReceipt{b, m.revision, m.configured}
	if m.malformedReceipt {
		r.Binding.IntentSHA256 = digest("wrong receipt")
	}
	return r, nil
}
func applyReviewSetup(t *testing.T) (*testSetup, *applyReviewNative) {
	t.Helper()
	f := setup(t)
	denied, e := f.c.generation("", f.provider.rows, true)
	if e != nil {
		t.Fatal(e)
	}
	m := &applyReviewNative{configured: denied.Identity(), healthy: true}
	f.c.executor = m
	return f, m
}
func applyReviewReopen(t *testing.T, f *testSetup, m *applyReviewNative) {
	t.Helper()
	_ = f.c.Close()
	var e error
	f.c, e = Open(f.dir, f.profile, f.provider, m)
	if e != nil {
		t.Fatal(e)
	}
}
func applyReviewCommitWindow(t *testing.T) (*testSetup, *applyReviewNative, Status) {
	t.Helper()
	f, m := applyReviewSetup(t)
	f.apply(t)
	prior, e := f.c.Status()
	if e != nil {
		t.Fatal(e)
	}
	f.provider.rows[0].Revision++
	f.provider.rows[0].UpdatedAt = f.provider.rows[0].UpdatedAt.Add(time.Second)
	plan := f.plan(t)
	m.finishFault = func() { _ = f.c.persistence.db.Close() }
	m.finishFaultAt = m.revision + 1
	if e = f.c.Apply(context.Background(), ApplyInput{plan, "operator:review", "native Apply commit before coordinator finish"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	applyReviewReopen(t, f, m)
	s, e := f.c.Status()
	if e != nil || s.Revision != prior.Revision || s.PendingOperation == "" || m.revision != s.Revision+1 || m.marker == nil || m.pending != nil {
		t.Fatalf("wrong actual journal commit window: %+v native=%+v %v", s, m.audit(), e)
	}
	return f, m, prior
}
func applyReviewRepair(t *testing.T, f *testSetup, ctx context.Context) error {
	t.Helper()
	s, e := f.c.Status()
	if e != nil {
		t.Fatal(e)
	}
	return f.c.RepairDenied(ctx, RepairInput{ExpectedRevision: s.Revision, PendingOperation: s.PendingOperation, Actor: "operator:review", Reason: "independent Apply completion challenge"})
}
func applyReviewCheckpointCount(t *testing.T, f *testSetup) int {
	t.Helper()
	events, e := f.c.History()
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	for _, v := range events {
		if v.Phase == "apply_checkpoint" {
			n++
		}
	}
	return n
}

func TestApplyReviewCoordinatorCheckpointPreservesCurrentOnce(t *testing.T) {
	for _, inventory := range []string{"unchanged", "suspended", "removed"} {
		t.Run(inventory, func(t *testing.T) {
			f, m, prior := applyReviewCommitWindow(t)
			m.healthy = false
			m.repairError = true
			switch inventory {
			case "suspended":
				f.provider.rows[0].State = "suspended"
				f.provider.rows[0].Revision++
			case "removed":
				f.provider.rows = nil
			}
			if e := applyReviewRepair(t, f, context.Background()); !errors.Is(e, ErrRecovery) {
				t.Fatal(e)
			}
			s, e := f.c.Status()
			if e != nil || s.Revision != 2 || s.PendingOperation == "" || s.Current == nil || s.Current.GenerationID != prior.Current.GenerationID || m.revision != 2 || m.writes != 0 || applyReviewCheckpointCount(t, f) != 1 {
				t.Fatalf("checkpoint falsely claimed serving: %+v native=%+v %v", s, m.audit(), e)
			}
			applyReviewReopen(t, f, m)
			if e = applyReviewRepair(t, f, context.Background()); !errors.Is(e, ErrRecovery) || applyReviewCheckpointCount(t, f) != 1 {
				t.Fatal("checkpoint replayed", e)
			}
			m.repairError = false
			applyReviewReopen(t, f, m)
			if e = applyReviewRepair(t, f, context.Background()); e != nil {
				t.Fatal(e)
			}
			final, e := f.c.Status()
			want, e2 := f.c.generation("", f.provider.rows, true)
			if e != nil || e2 != nil || final.Revision != 3 || m.revision != 3 || m.writes != 1 || final.PendingOperation != "" || final.Current == nil || !final.Current.Denied || final.Current.SnapshotSHA256 != want.SnapshotSHA256 || applyReviewCheckpointCount(t, f) != 1 {
				t.Fatalf("saved denial retry/counter mismatch: %+v native=%+v %v %v", final, m.audit(), e, e2)
			}
		})
	}
}
func TestApplyReviewCoordinatorHealthyOriginalPendingOnly(t *testing.T) {
	f, m, _ := applyReviewCommitWindow(t)
	if !m.healthy {
		t.Fatal("fixture must be actually observed healthy in protocol model")
	}
	if e := applyReviewRepair(t, f, context.Background()); e != nil {
		t.Fatal("exact healthy pending original completion refused", e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 3 || m.writes != 1 || applyReviewCheckpointCount(t, f) != 1 || s.Current == nil || !s.Current.Denied {
		t.Fatal(s, e)
	}
	clean, n := applyReviewSetup(t)
	clean.apply(t)
	if e = applyReviewRepair(t, clean, context.Background()); e == nil || n.calls != 0 || applyReviewCheckpointCount(t, clean) != 0 {
		t.Fatal("unrelated healthy clean state admitted", e)
	}
}
func TestApplyReviewCoordinatorLegacyDivergenceNeverInferred(t *testing.T) {
	f, m, _ := applyReviewCommitWindow(t)
	m.marker = nil
	m.healthy = false
	if e := applyReviewRepair(t, f, context.Background()); e == nil || m.calls != 0 {
		t.Fatal("markerless native counter inferred", e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 1 || s.PendingOperation == "" || applyReviewCheckpointCount(t, f) != 0 {
		t.Fatal(s, e)
	}
}
func TestApplyReviewCoordinatorMalformedOriginalMarkerRefused(t *testing.T) {
	for _, mode := range []string{"kind", "version", "base", "operation", "before", "after", "boot", "input", "CAS", "result", "repair-coexist", "generic-pending"} {
		t.Run(mode, func(t *testing.T) {
			f, m, _ := applyReviewCommitWindow(t)
			m.healthy = false
			m.inspectHook = func(in *RecoveryInspection) {
				b := &in.CompletedApply.Binding
				switch mode {
				case "kind":
					b.Kind = "rollback"
				case "version":
					b.Version++
				case "base":
					b.NativeBaseRevision++
				case "operation":
					b.OperationID = "ffffffffffffffffffffffffffffffff"
					in.LastOperationID = b.OperationID
				case "before":
					b.Before = b.After
				case "after":
					b.After = b.Before
				case "boot":
					b.BootID = "bad"
				case "input":
					b.InputsSHA256 = "bad"
				case "CAS":
					b.AdmittedStateSHA256 = "bad"
				case "result":
					in.CompletedApply.ResultRevision++
				case "repair-coexist":
					in.Completed = &RecoveryBinding{}
				case "generic-pending":
					in.Pending = &RecoveryPending{OperationID: b.OperationID, Revision: in.Revision, Before: b.Before, After: b.After, Target: b.After}
				}
				b.IntentSHA256 = ApplyIntentSHA(*b)
			}
			if e := applyReviewRepair(t, f, context.Background()); e == nil || m.calls != 0 || applyReviewCheckpointCount(t, f) != 0 {
				t.Fatal("malformed marker authorized checkpoint/native mutation", mode, e)
			}
		})
	}
}
func TestApplyReviewCoordinatorSavedMarkerCannotBeReplaced(t *testing.T) {
	f, m, _ := applyReviewCommitWindow(t)
	m.healthy = false
	m.repairError = true
	_ = applyReviewRepair(t, f, context.Background())
	if applyReviewCheckpointCount(t, f) != 1 {
		t.Fatal("fixture checkpoint missing")
	}
	applyReviewReopen(t, f, m)
	m.inspectHook = func(in *RecoveryInspection) {
		in.CompletedApply.Binding.AdmittedStateSHA256 = digest("different original CAS")
		in.CompletedApply.Binding.IntentSHA256 = ApplyIntentSHA(in.CompletedApply.Binding)
	}
	calls := m.calls
	if e := applyReviewRepair(t, f, context.Background()); e == nil || m.calls != calls {
		t.Fatal("saved marker substituted despite recomputed valid digest", e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 2 || s.PendingOperation == "" || applyReviewCheckpointCount(t, f) != 1 {
		t.Fatal(s, e)
	}
}
func TestApplyReviewCoordinatorMalformedReceiptRetryAndReconfirm(t *testing.T) {
	f, m, _ := applyReviewCommitWindow(t)
	m.healthy = false
	m.malformedReceipt = true
	if e := applyReviewRepair(t, f, context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 2 || s.PendingOperation == "" || m.revision != 3 || m.writes != 1 {
		t.Fatal(s, e)
	}
	m.malformedReceipt = false
	f.provider.postFailure = true
	applyReviewReopen(t, f, m)
	if e = applyReviewRepair(t, f, context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e = f.c.Status()
	if e != nil || s.Revision != 3 || s.PendingOperation == "" || m.revision != 3 || m.writes != 1 {
		t.Fatal(s, e)
	}
	f.provider.postFailure = false
	applyReviewReopen(t, f, m)
	if e = applyReviewRepair(t, f, context.Background()); e != nil {
		t.Fatal(e)
	}
	s, e = f.c.Status()
	if e != nil || s.Revision != 3 || s.PendingOperation != "" || m.revision != 3 || m.writes != 1 || applyReviewCheckpointCount(t, f) != 1 {
		t.Fatal("reconfirm double consumed counter", s, e)
	}
}
func TestApplyReviewCoordinatorLeaseCancellationCannotFinish(t *testing.T) {
	for _, mode := range []string{"pre-cancel", "lease-before", "native-cancel", "lease-after-native"} {
		t.Run(mode, func(t *testing.T) {
			f, m, prior := applyReviewCommitWindow(t)
			m.healthy = false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "pre-cancel":
				cancel()
			case "lease-before":
				f.provider.drift = true
			case "native-cancel":
				m.repairHook = cancel
			case "lease-after-native":
				m.repairHook = func() { f.provider.drift = true }
			}
			if e := applyReviewRepair(t, f, ctx); e == nil {
				t.Fatal("failed authority reported completion")
			}
			s, e := f.c.Status()
			if e != nil || s.PendingOperation == "" || s.Current == nil || s.Current.GenerationID != prior.Current.GenerationID {
				t.Fatal("failed lease/cancel committed denial", s, e)
			}
			wantRevision := uint64(1)
			wantWrites := 0
			if mode == "native-cancel" || mode == "lease-after-native" {
				wantRevision = 2
			}
			if mode == "lease-after-native" {
				wantWrites = 1
			}
			if s.Revision != wantRevision || m.writes != wantWrites {
				t.Fatalf("authority boundary consumed wrong counters: %+v native=%+v", s, m.audit())
			}
		})
	}
}
func TestApplyReviewCoordinatorRehashedCheckpointCorruptionRefused(t *testing.T) {
	f, m, _ := applyReviewCommitWindow(t)
	m.healthy = false
	m.repairError = true
	_ = applyReviewRepair(t, f, context.Background())
	if applyReviewCheckpointCount(t, f) != 1 {
		t.Fatal("checkpoint fixture absent")
	}
	err := f.c.persistence.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(eventBucket)
		var events []Event
		if e := bucket.ForEach(func(_, raw []byte) error {
			var v Event
			if e := json.Unmarshal(raw, &v); e != nil {
				return e
			}
			events = append(events, v)
			return nil
		}); e != nil {
			return e
		}
		previous := ""
		for i := range events {
			v := &events[i]
			if v.Phase == "apply_checkpoint" {
				v.Revision++
			}
			v.PreviousSHA = previous
			v.SHA = ""
			v.SHA = digest(*v)
			previous = v.SHA
			raw, e := json.Marshal(v)
			if e != nil {
				return e
			}
			if e = bucket.Put([]byte(fmt.Sprintf("%020d", v.Sequence)), raw); e != nil {
				return e
			}
		}
		var st state
		if e := json.Unmarshal(tx.Bucket(stateBucket).Get(stateKey), &st); e != nil {
			return e
		}
		st.LastEventSHA = previous
		raw, e := json.Marshal(st)
		if e != nil {
			return e
		}
		return tx.Bucket(stateBucket).Put(stateKey, raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := m.calls
	// No Status polling is needed: the actual write entry must revalidate journal.
	if e := f.c.RepairDenied(context.Background(), RepairInput{ExpectedRevision: 2, PendingOperation: m.original.OperationID, Actor: "operator:review", Reason: "rehash does not authorize counter mutation"}); e == nil || m.calls != calls {
		t.Fatal("semantically corrupt rehashed journal authorized native call", e)
	}
	if _, e := f.c.Status(); e == nil {
		t.Fatal("corrupt checkpoint journal readable")
	}
}

func TestApplyReviewCoordinatorCheckpointAllowsFreshNativeCAS(t *testing.T) {
	f, m, prior := applyReviewCommitWindow(t)
	m.healthy = false
	st, e := f.c.read()
	if e != nil {
		t.Fatal(e)
	}
	tr, e := f.c.original(st)
	if e != nil {
		t.Fatal(e)
	}
	oldCAS := m.sha()
	// Real journal checkpoint, crash boundary before any repair intent exists.
	if e = f.c.persistence.checkpointApply(&st, *m.marker, oldCAS, tr, "operator:review", "checkpoint-only crash boundary", f.c); e != nil {
		t.Fatal(e)
	}
	if st.Pending == nil || st.Pending.Repair != nil || st.Current != prior.Current.GenerationID {
		t.Fatal("checkpoint created serving or repair authority")
	}
	// Models owned process cleanup changing native metadata while retaining the
	// exact historical original completion. It does not model kernel cleanup.
	m.metadataEpoch++
	if oldCAS == m.sha() {
		t.Fatal("CAS change fixture ineffective")
	}
	applyReviewReopen(t, f, m)
	if e = applyReviewRepair(t, f, context.Background()); e != nil {
		t.Fatal("historical inspected CAS incorrectly treated as fresh admission", e)
	}
	final, e := f.c.Status()
	if e != nil || final.Revision != 3 || final.PendingOperation != "" || m.revision != 3 || m.writes != 1 || applyReviewCheckpointCount(t, f) != 1 || m.request == nil || m.request.ExpectedStateSHA256 == oldCAS {
		t.Fatal("fresh admission/counter mismatch", final, e)
	}
}

func TestApplyReviewCoordinatorExactNativePendingDenialRetry(t *testing.T) {
	f, m, _ := applyReviewCommitWindow(t)
	m.healthy = false
	m.repairError = true
	m.persistPending = true
	if e := applyReviewRepair(t, f, context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	if m.pending == nil || m.pending.Repair == nil || m.marker == nil || m.request == nil {
		t.Fatal("same-original native pending fixture missing")
	}
	first := *m.request
	applyReviewReopen(t, f, m)
	m.repairError = false
	f.provider.postFailure = true
	if e := applyReviewRepair(t, f, context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal("reused native pending attempt lost postcallback quarantine", e)
	}
	quarantined, e := f.c.Status()
	if e != nil || quarantined.Revision != 3 || quarantined.PendingOperation == "" || m.revision != 3 || m.writes != 1 {
		t.Fatal("native pending completion/callback quarantine mismatch", quarantined, m.audit(), e)
	}
	f.provider.postFailure = false
	applyReviewReopen(t, f, m)
	if e = applyReviewRepair(t, f, context.Background()); e != nil {
		t.Fatal("quarantined pending completion reconfirm failed", e)
	}
	final, e := f.c.Status()
	if e != nil || final.Revision != 3 || m.revision != 3 || m.writes != 1 || final.PendingOperation != "" || m.request.AttemptID != first.AttemptID || m.request.Target.Identity() != first.Target.Identity() || m.request.ExpectedStateSHA256 == first.ExpectedStateSHA256 || applyReviewCheckpointCount(t, f) != 1 {
		t.Fatal("retry lost immutable attempt or refreshed CAS", final, e)
	}
}

func TestApplyReviewCoordinatorCommittedQuarantineNeverAdvancesTwice(t *testing.T) {
	f, m := applyReviewSetup(t)
	f.apply(t)
	f.provider.rows[0].Revision++
	f.provider.rows[0].UpdatedAt = f.provider.rows[0].UpdatedAt.Add(time.Second)
	plan := f.plan(t)
	f.provider.postFailure = true
	if e := f.c.Apply(context.Background(), ApplyInput{plan, "operator:review", "provider postcallback fails after both counters committed"}); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 2 || s.PendingOperation == "" || s.Current == nil || s.Current != nil && s.Current.GenerationID != m.configured.GenerationID || m.revision != 2 {
		t.Fatal("committed quarantine fixture inconsistent", s, e)
	}
	originalCurrent := s.Current.GenerationID
	f.provider.postFailure = false
	m.healthy = false
	m.repairError = true
	applyReviewReopen(t, f, m)
	if e = applyReviewRepair(t, f, context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e = f.c.Status()
	if e != nil || s.Revision != 2 || m.revision != 2 || s.PendingOperation == "" || s.Current == nil || s.Current.GenerationID != originalCurrent || m.writes != 0 || applyReviewCheckpointCount(t, f) != 1 {
		t.Fatal("already committed counter advanced in checkpoint", s, e)
	}
	m.repairError = false
	applyReviewReopen(t, f, m)
	if e = applyReviewRepair(t, f, context.Background()); e != nil {
		t.Fatal(e)
	}
	s, e = f.c.Status()
	if e != nil || s.Revision != 3 || m.revision != 3 || m.writes != 1 || s.PendingOperation != "" || applyReviewCheckpointCount(t, f) != 1 {
		t.Fatal("denial did not consume exactly one additional counter", s, e)
	}
}
