package hostwebgeneration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"sifruno/internal/hostaccounts"
	"testing"
)

// Durable protocol model: real isolated JSON/bbolt state and counters, no
// daemons, PID ownership or Linux qualification inferred from these tests.
type nativeModelState struct {
	StateEpoch     uint64
	Revision       uint64
	LastOperation  string
	Configured     Identity
	Pending        *RecoveryPending
	Completed      *RecoveryBinding
	CompletedApply *ApplyCompletion
}
type repairModel struct {
	*testExecutor
	file             string
	alive            bool
	calls, mutations int
	crash, partial   bool
	badReceipt       func(*DeniedRepairReceipt)
	inspectHook      func(*RecoveryInspection)
	beforeMutation   func(DeniedRepairRequest)
}

func model(t *testing.T, f *testSetup) *repairModel {
	t.Helper()
	m := &repairModel{testExecutor: f.executor, file: filepath.Join(t.TempDir(), "native-model.json"), alive: true}
	m.write(nativeModelState{Configured: f.executor.identity})
	f.c.executor = m
	return m
}
func (m *repairModel) read() nativeModelState {
	raw, err := os.ReadFile(m.file)
	if err != nil {
		panic(err)
	}
	var s nativeModelState
	if json.Unmarshal(raw, &s) != nil {
		panic("model json")
	}
	return s
}
func (m *repairModel) write(s nativeModelState) {
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(m.file, raw, 0600); err != nil {
		panic(err)
	}
}
func (m *repairModel) Observe(ctx context.Context) (Identity, error) {
	if ctx.Err() != nil {
		return Identity{}, ctx.Err()
	}
	if !m.alive {
		return Identity{}, ErrRecovery
	}
	return m.read().Configured, nil
}
func (m *repairModel) Apply(ctx context.Context, tr Transition) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s := m.read()
	if s.Revision != tr.Revision || s.Configured != tr.Before.Identity() {
		return ErrConflict
	}
	s.Revision++
	s.LastOperation = tr.OperationID
	s.Configured = tr.After.Identity()
	s.Completed = nil
	m.write(s)
	return nil
}
func (m *repairModel) InspectRecovery(ctx context.Context) (RecoveryInspection, error) {
	if ctx.Err() != nil {
		return RecoveryInspection{}, ctx.Err()
	}
	s := m.read()
	raw, _ := os.ReadFile(m.file)
	in := RecoveryInspection{StateSHA256: digest(json.RawMessage(raw)), Revision: s.Revision, LastOperationID: s.LastOperation, Configured: s.Configured, Pending: s.Pending, Completed: s.Completed, CompletedApply: s.CompletedApply}
	if m.alive {
		x := s.Configured
		in.Observed = &x
	}
	if m.inspectHook != nil {
		m.inspectHook(&in)
	}
	return in, nil
}
func (m *repairModel) RepairDenied(ctx context.Context, req DeniedRepairRequest) (DeniedRepairReceipt, error) {
	m.calls++
	if ctx.Err() != nil {
		return DeniedRepairReceipt{}, ctx.Err()
	}
	in, _ := m.InspectRecovery(ctx)
	s := m.read()
	if s.Completed != nil && s.Pending == nil && s.Completed.IntentSHA256 == RecoveryIntentSHA(req) && req.ExpectedStateSHA256 == in.StateSHA256 && s.Revision == req.BaseRevision+1 && s.Configured == req.Target.Identity() && s.LastOperation == req.Original.OperationID && m.alive {
		return DeniedRepairReceipt{*s.Completed, s.Revision, s.Configured}, nil
	}
	if req.ExpectedStateSHA256 != in.StateSHA256 || req.BaseRevision != s.Revision || req.Source != s.Configured || !req.Target.Denied {
		return DeniedRepairReceipt{}, ErrConflict
	}
	b := recoveryBinding(req)
	if s.Pending != nil && s.Pending.Repair != nil && s.Pending.Repair.IntentSHA256 == b.IntentSHA256 {
		b = *s.Pending.Repair
	}
	if m.beforeMutation != nil {
		m.beforeMutation(req)
	}
	if m.partial {
		m.partial = false
		s.Pending = &RecoveryPending{req.Original.OperationID, req.BaseRevision, req.Original.Before.Identity(), req.Original.After.Identity(), req.Target.Identity(), &b, nil}
		m.write(s)
		m.alive = false
		return DeniedRepairReceipt{}, ErrRecovery
	}
	s.Pending = nil
	s.Completed = &b
	s.CompletedApply = nil
	s.Revision = req.BaseRevision + 1
	s.LastOperation = req.Original.OperationID
	s.Configured = req.Target.Identity()
	m.write(s)
	m.alive = true
	m.mutations++
	if m.crash {
		m.crash = false
		panic("crash after native durable commit")
	}
	receipt := DeniedRepairReceipt{b, s.Revision, s.Configured}
	if m.badReceipt != nil {
		m.badReceipt(&receipt)
	}
	return receipt, nil
}
func repairInput(t *testing.T, c *Coordinator) RepairInput {
	t.Helper()
	s, e := c.Status()
	if e != nil {
		t.Fatal(e)
	}
	return RepairInput{s.Revision, s.PendingOperation, "operator:repair-test", "explicit denied repair"}
}
func repair(t *testing.T, f *testSetup) {
	t.Helper()
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); e != nil {
		t.Fatal(e)
	}
}
func crashRepair(t *testing.T, f *testSetup, m *repairModel) {
	t.Helper()
	m.crash = true
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing crash")
			}
		}()
		_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
	}()
}

func TestRepairCleanDeathDurableIntentAndStrictObserve(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	if _, e := m.Observe(context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	m.beforeMutation = func(req DeniedRepairRequest) {
		st, e := f.c.persistence.read(f.c)
		if e != nil || st.Pending == nil || st.Pending.Repair == nil || st.Pending.Repair.Binding.IntentSHA256 != RecoveryIntentSHA(req) {
			t.Fatal("mutation before intent", e)
		}
		if !req.Target.Denied || req.Target.SnapshotSHA256 != digest(f.provider.rows) {
			t.Fatal("not current denied snapshot")
		}
	}
	repair(t, f)
	s, e := f.c.Status()
	if e != nil || s.Revision != 2 || s.Phase != "idle" || s.Current == nil || !s.Current.Denied || m.read().Revision != s.Revision || m.mutations != 1 {
		t.Fatal(s, e)
	}
	f.reopen(t)
	if _, e = f.c.Status(); e != nil {
		t.Fatal(e)
	}
}
func TestRepairNativeCommitBeforeFinishRetriesExactAttemptWithoutMutation(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	crashRepair(t, f, m)
	st, e := f.c.Status()
	if e != nil || st.Revision != 1 || st.PendingOperation == "" || m.read().Revision != 2 {
		t.Fatal(st, e)
	}
	b := *m.read().Completed
	f.reopen(t)
	f.c.executor = m
	repair(t, f)
	if m.mutations != 1 || *m.read().Completed != b {
		t.Fatal("native retry repeated")
	}
	st, e = f.c.Status()
	if e != nil || st.Revision != 2 || m.read().Revision != 2 {
		t.Fatal(st, e)
	}
}
func TestRepairPostcallbackQuarantineReconfirmedNoCounterIncrement(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	f.provider.postFailure = true
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	s, e := f.c.Status()
	if e != nil || s.Revision != 2 || s.Phase != "recovery_required" {
		t.Fatal(s, e)
	}
	f.provider.postFailure = false
	f.reopen(t)
	f.c.executor = m
	repair(t, f)
	s, e = f.c.Status()
	if e != nil || s.Revision != 2 || s.PendingOperation != "" || m.mutations != 1 || m.read().Revision != 2 {
		t.Fatal(s, e)
	}
	h, e := f.c.History()
	if e != nil || h[len(h)-1].Phase != "reconfirmed" {
		t.Fatal(h, e)
	}
}
func TestRepairDeadCompletedCheckpointKeepsCurrentAndFreshAttemptConverges(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	before, _ := f.c.Status()
	m.alive = false
	crashRepair(t, f, m)
	m.alive = false
	old := *m.read().Completed
	m.beforeMutation = func(req DeniedRepairRequest) {
		s, e := f.c.persistence.read(f.c)
		if e != nil || s.Revision != 2 || s.Current != before.Current.GenerationID {
			t.Fatal("checkpoint exposed unobserved target", s, e)
		}
		if req.BaseRevision != 2 || req.AttemptID == old.AttemptID || req.Target.ID == old.Target.GenerationID {
			t.Fatal("consumed base reused")
		}
	}
	repair(t, f)
	s, e := f.c.Status()
	if e != nil || s.Revision != 3 || m.read().Revision != 3 || m.mutations != 2 {
		t.Fatal(s, e)
	}
	h, e := f.c.History()
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	for _, event := range h {
		if event.Phase == "repair_checkpoint" {
			n++
			if event.Repair == nil || !event.Repair.CounterAdvanceOnly {
				t.Fatal("unmarked checkpoint")
			}
		}
	}
	if n != 1 {
		t.Fatal(n)
	}
}
func TestRepairPartialRetryUsesCurrentCASTokenAndOriginalBinding(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	m.partial = true
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	original := *m.read().Pending.Repair
	repair(t, f)
	if m.read().Completed.AdmittedStateSHA256 != original.AdmittedStateSHA256 || m.read().Completed.IntentSHA256 != original.IntentSHA256 {
		t.Fatal("attempt binding changed")
	}
}
func TestRepairChangedOrRemovedInventoryAlwaysFreshDenial(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "suspended", true: "removed"}[remove], func(t *testing.T) {
			f := setup(t)
			m := model(t, f)
			f.apply(t)
			m.alive = false
			m.partial = true
			_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
			old := *m.read().Pending.Repair
			if remove {
				f.provider.rows = nil
			} else {
				f.provider.rows[0].State = "suspended"
				f.provider.rows[0].Revision++
			}
			m.beforeMutation = func(req DeniedRepairRequest) {
				if !req.Target.Denied || req.Target.SnapshotSHA256 == old.Target.SnapshotSHA256 || req.AttemptID == old.AttemptID {
					t.Fatal("stale denial")
				}
			}
			repair(t, f)
		})
	}
}
func TestRepairOriginalApplyConsumedWithoutReceiptFailsClosed(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	plan := f.plan(t)
	// Original Apply really persists the independent model counter/config then
	// dies before coordinator completion. There is no denied-repair receipt.
	base := m.testExecutor
	f.c.executor = &originalCrash{repairModel: m}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing apply crash")
			}
		}()
		_ = f.c.Apply(context.Background(), ApplyInput{plan, "operator", "apply crash"})
	}()
	f.c.executor = m
	m.testExecutor = base
	if m.read().Revision != 1 || m.read().Completed != nil {
		t.Fatal("not original completion")
	}
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	st, e := f.c.Status()
	if e != nil || st.Revision != 0 || m.read().Revision != 1 || m.calls != 0 || m.mutations != 0 {
		t.Fatal("divergent repair ran", st, e)
	}
}

type originalCrash struct{ *repairModel }

func (m *originalCrash) Apply(ctx context.Context, tr Transition) error {
	if e := m.repairModel.Apply(ctx, tr); e != nil {
		return e
	}
	panic("original apply committed")
}

func TestRepairUnavailableAndHealthyOrStaleRequestsNeverMutate(t *testing.T) {
	f := setup(t)
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	m := model(t, f)
	f.apply(t)
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	m.alive = false
	in := repairInput(t, f.c)
	in.ExpectedRevision++
	if e := f.c.RepairDenied(context.Background(), in); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := f.c.RepairDenied(ctx, repairInput(t, f.c)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if m.calls != 0 || m.mutations != 0 {
		t.Fatal("bad request acted")
	}
}
func TestRepairReceiptAndInspectionMismatchCannotComplete(t *testing.T) {
	for _, change := range []func(*DeniedRepairReceipt){func(r *DeniedRepairReceipt) { r.ResultRevision++ }, func(r *DeniedRepairReceipt) { r.Binding.AttemptID = "bad" }, func(r *DeniedRepairReceipt) { r.Binding.AdmittedStateSHA256 = "bad" }, func(r *DeniedRepairReceipt) { r.Observed.Denied = false }} {
		f := setup(t)
		m := model(t, f)
		f.apply(t)
		m.alive = false
		m.badReceipt = change
		if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
			t.Fatal(e)
		}
		s, e := f.c.Status()
		if e != nil || s.Revision != 1 || s.PendingOperation == "" {
			t.Fatal(s, e)
		}
	}
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	m.inspectHook = func(i *RecoveryInspection) { i.Configured.BundleSHA256 = "bad" }
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if m.calls != 0 {
		t.Fatal("invalid inspection acted")
	}
}

// Recompute the entire checksum chain to exercise semantic validation, rather
// than merely detecting a broken digest. These are owned isolated databases.
func rewriteRepairHistory(t *testing.T, c *Coordinator, change func([]Event, *state)) {
	t.Helper()
	if e := c.persistence.db.Update(func(tx *bolt.Tx) error {
		var events []Event
		if e := tx.Bucket(eventBucket).ForEach(func(_, raw []byte) error {
			var event Event
			if e := json.Unmarshal(raw, &event); e != nil {
				return e
			}
			events = append(events, event)
			return nil
		}); e != nil {
			return e
		}
		var st state
		if e := json.Unmarshal(tx.Bucket(stateBucket).Get(stateKey), &st); e != nil {
			return e
		}
		change(events, &st)
		previous := ""
		for _, event := range events {
			event.PreviousSHA = previous
			event.SHA = ""
			event.SHA = digest(event)
			previous = event.SHA
			raw, _ := json.Marshal(event)
			if e := tx.Bucket(eventBucket).Put([]byte(fmt.Sprintf("%020d", event.Sequence)), raw); e != nil {
				return e
			}
		}
		st.LastEventSHA = previous
		raw, _ := json.Marshal(st)
		return tx.Bucket(stateBucket).Put(stateKey, raw)
	}); e != nil {
		t.Fatal(e)
	}
}
func TestRepairSemanticCheckpointTamperRejectsBeforeExecutor(t *testing.T) {
	for name, change := range map[string]func([]Event, *state){
		"unmarked": func(events []Event, _ *state) {
			for i := range events {
				if events[i].Phase == "repair_checkpoint" {
					events[i].Repair.CounterAdvanceOnly = false
				}
			}
		},
		"revision": func(events []Event, _ *state) {
			for i := range events {
				if events[i].Phase == "repair_checkpoint" {
					events[i].Revision--
				}
			}
		},
		"binding": func(events []Event, _ *state) {
			for i := range events {
				if events[i].Phase == "repair_checkpoint" {
					events[i].Repair.Binding.AdmittedStateSHA256 = digest("different CAS")
				}
			}
		},
		"phase": func(events []Event, _ *state) {
			for i := range events {
				if events[i].Phase == "repair_checkpoint" {
					events[i].Phase = "repair_success"
				}
			}
		},
		"current": func(events []Event, st *state) {
			for _, event := range events {
				if event.Phase == "repair_checkpoint" {
					st.Current = event.After.GenerationID
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			m := model(t, f)
			f.apply(t)
			m.alive = false
			crashRepair(t, f, m)
			m.alive = false
			m.partial = true
			_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
			in := repairInput(t, f.c)
			calls := m.calls
			rewriteRepairHistory(t, f.c, change)
			if e := f.c.RepairDenied(context.Background(), in); !errors.Is(e, ErrRecovery) || m.calls != calls {
				t.Fatal("semantic corruption acted", e)
			}
		})
	}
}
func TestRepairSemanticReconfirmedRequiresPriorTerminal(t *testing.T) {
	for name, change := range map[string]func([]Event, *state){
		"false reconfirm": func(events []Event, _ *state) {
			for i := range events {
				if events[i].Phase == "repair_completed" {
					events[i].Phase = "reconfirmed"
				}
			}
		},
		"increment":       func(events []Event, st *state) { events[len(events)-1].Revision++; st.Revision++ },
		"wrong target":    func(events []Event, _ *state) { events[len(events)-1].After = events[0].After },
		"missing binding": func(events []Event, _ *state) { events[len(events)-1].Repair = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			m := model(t, f)
			f.apply(t)
			m.alive = false
			f.provider.postFailure = true
			_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
			f.provider.postFailure = false
			repair(t, f)
			calls := m.calls
			rewriteRepairHistory(t, f.c, change)
			if _, e := f.c.Status(); !errors.Is(e, ErrRecovery) {
				t.Fatal("semantic reconfirm corruption accepted", e)
			}
			if e := f.c.RepairDenied(context.Background(), RepairInput{2, "", "operator", "corrupt state"}); !errors.Is(e, ErrRecovery) || m.calls != calls {
				t.Fatal("corrupt history acted", e)
			}
		})
	}
}

type boundaryProvider struct {
	rows          []hostaccounts.Account
	calls, failAt int
	marker        any
}
type boundaryLease struct {
	p   *boundaryProvider
	ctx context.Context
}

func (l boundaryLease) Accounts() []hostaccounts.Account { return l.p.rows }
func (l boundaryLease) Context() context.Context         { return l.ctx }
func (l boundaryLease) Verify(ctx context.Context) error {
	l.p.calls++
	if l.p.calls == l.p.failAt {
		return ErrRecovery
	}
	return ctx.Err()
}
func (p *boundaryProvider) WithSnapshot(ctx context.Context, fn func(SnapshotLease) error) error {
	return fn(boundaryLease{p, context.WithValue(ctx, repairContextKey{}, p.marker)})
}

type repairContextKey struct{}

func TestRepairLeaseVerificationBoundaries(t *testing.T) {
	for at := 1; at <= 4; at++ {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			f := setup(t)
			m := model(t, f)
			f.apply(t)
			m.alive = false
			p := &boundaryProvider{rows: f.provider.rows, failAt: at}
			f.c.provider = p
			in := repairInput(t, f.c)
			if e := f.c.RepairDenied(context.Background(), in); !errors.Is(e, ErrRecovery) {
				t.Fatal(e)
			}
			s, e := f.c.Status()
			if e != nil || s.Revision != 1 {
				t.Fatal(s, e)
			}
			if at < 4 && m.calls != 0 || at == 4 && (m.mutations != 1 || s.PendingOperation == "") {
				t.Fatal("verification boundary bypass", at, m.calls, s)
			}
		})
	}
}
func TestRepairExecutorReceivesMarkedContextAndCopiedInputs(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	p := &boundaryProvider{rows: f.provider.rows, marker: "reserved"}
	f.c.provider = p
	wrapper := &contextRepairModel{repairModel: m, t: t}
	f.c.executor = wrapper
	m.beforeMutation = func(req DeniedRepairRequest) {
		req.Target.Accounts[0].Username = "mutated"
		req.Original.After.Accounts[0].State = "suspended"
		req.Target.Bundle.Files[0].Data[0] = 'X'
		req.Original.Before.Bundle.Files[0].Data[0] = 'X'
	}
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); e != nil {
		t.Fatal(e)
	}
	if p.rows[0].Username != "webalpha" || p.rows[0].State != "active" {
		t.Fatal("inventory aliased")
	}
	if _, e := f.c.Status(); e != nil {
		t.Fatal("persisted bundle aliased", e)
	}
}

type contextRepairModel struct {
	*repairModel
	t *testing.T
}

func (m *contextRepairModel) RepairDenied(ctx context.Context, req DeniedRepairRequest) (DeniedRepairReceipt, error) {
	if ctx.Value(repairContextKey{}) != "reserved" {
		m.t.Fatal("lease context not propagated")
	}
	return m.repairModel.RepairDenied(ctx, req)
}
func TestRepairUnknownOperationAndMalformedNativePendingRefuse(t *testing.T) {
	for name, hook := range map[string]func(*RecoveryInspection){
		"foreign operation":   func(i *RecoveryInspection) { i.LastOperationID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" },
		"malformed pending":   func(i *RecoveryInspection) { i.Pending = &RecoveryPending{OperationID: "bad"} },
		"malformed completed": func(i *RecoveryInspection) { i.Completed = &RecoveryBinding{OperationID: "bad"} },
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			m := model(t, f)
			f.apply(t)
			m.alive = false
			m.inspectHook = hook
			if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrConflict) || m.calls != 0 {
				t.Fatal(e)
			}
		})
	}
}
func TestRepairEventCapacityStopsFurtherNativeCalls(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	m.partial = true
	_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
	for i := 0; i < MaxEvents; i++ {
		m.partial = true
		_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
	}
	calls := m.calls
	in := repairInput(t, f.c)
	_ = f.c.RepairDenied(context.Background(), in)
	if m.calls != calls {
		t.Fatal("executor called without terminal/quarantine capacity")
	}
	s, e := f.c.Status()
	if e != nil || s.PendingOperation == "" {
		t.Fatal("bound erased recovery", s, e)
	}
}

type failBeforeNative struct {
	*repairModel
	request DeniedRepairRequest
}

func (m *failBeforeNative) RepairDenied(_ context.Context, req DeniedRepairRequest) (DeniedRepairReceipt, error) {
	m.request = req
	return DeniedRepairReceipt{}, ErrRecovery
}
func TestRepairCheckpointThenPreNativeFailureRetriesSavedSource(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	crashRepair(t, f, m)
	m.alive = false
	old := *m.read().Completed
	wrapper := &failBeforeNative{repairModel: m}
	f.c.executor = wrapper
	if e := f.c.RepairDenied(context.Background(), repairInput(t, f.c)); !errors.Is(e, ErrRecovery) {
		t.Fatal(e)
	}
	saved := wrapper.request
	s, e := f.c.Status()
	if e != nil || s.Revision != 2 || m.read().Revision != 2 || saved.Source != old.Target {
		t.Fatal("checkpoint/source missing", s, e)
	}
	f.c.executor = m
	m.beforeMutation = func(req DeniedRepairRequest) {
		if req.AttemptID != saved.AttemptID || req.Target.Identity() != saved.Target.Identity() || req.Source != saved.Source || RecoveryIntentSHA(req) != RecoveryIntentSHA(saved) {
			t.Fatal("saved retry replaced")
		}
	}
	repair(t, f)
	s, e = f.c.Status()
	if e != nil || s.Revision != 3 || m.read().Revision != 3 || m.mutations != 2 {
		t.Fatal(s, e)
	}
}
func TestRepairOwnedPendingTargetObservationIsAdmittedButUnknownRefused(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			f := setup(t)
			m := model(t, f)
			f.apply(t)
			m.alive = false
			m.partial = true
			_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
			m.inspectHook = func(i *RecoveryInspection) {
				if i.Pending != nil {
					x := i.Pending.Target
					if unknown {
						x.GenerationID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
					}
					i.Observed = &x
				}
			}
			calls := m.calls
			e := f.c.RepairDenied(context.Background(), repairInput(t, f.c))
			if unknown {
				if !errors.Is(e, ErrRecovery) || m.calls != calls {
					t.Fatal("unknown observation acted", e)
				}
			} else if e != nil {
				t.Fatal("owned pending target refused", e)
			}
		})
	}
}

func TestRepairJournalDamageDuringInspectionStopsSavedRetry(t *testing.T) {
	f := setup(t)
	m := model(t, f)
	f.apply(t)
	m.alive = false
	m.partial = true
	_ = f.c.RepairDenied(context.Background(), repairInput(t, f.c))
	in := repairInput(t, f.c)
	calls := m.calls
	m.inspectHook = func(_ *RecoveryInspection) {
		if e := f.c.persistence.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(eventBucket).Delete([]byte("00000000000000000001")) }); e != nil {
			t.Fatal(e)
		}
	}
	if e := f.c.RepairDenied(context.Background(), in); !errors.Is(e, ErrRecovery) || m.calls != calls {
		t.Fatal("damaged journal retry acted", e)
	}
}

func TestRepairAdvancedReplayPreservesLegacyRecoveryPrefix(t *testing.T) {
	f := setup(t)
	f.apply(t)
	f.executor.apply = func(_ context.Context, tr Transition) error {
		f.executor.identity = tr.After.Identity()
		return ErrRecovery
	}
	_ = f.c.Apply(context.Background(), ApplyInput{f.plan(t), "operator", "legacy failure"})
	f.recover(t)
	status, e := f.c.Status()
	if e != nil {
		t.Fatal(e)
	}
	events, e := f.c.History()
	if e != nil {
		t.Fatal(e)
	}
	m := model(t, f)
	s := m.read()
	s.Revision = status.Revision
	s.LastOperation = events[len(events)-1].OperationID
	s.Configured = *status.Current
	m.write(s)
	m.alive = false
	repair(t, f)
	f.reopen(t)
	after, e := f.c.Status()
	if e != nil || after.Revision != status.Revision+1 || !after.Current.Denied {
		t.Fatal("legacy prefix rejected", after, e)
	}
}
