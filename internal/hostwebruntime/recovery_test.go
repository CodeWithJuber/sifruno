package hostwebruntime

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

func repairFixture(t *testing.T) (Options, record, hostwebgeneration.DeniedRepairRequest) {
	t.Helper()
	o := testOptions("/srv/sifruno-runtime")
	before := testGeneration(t, o, strings.Repeat("a", 32), false)
	target := testGeneration(t, o, strings.Repeat("b", 32), true)
	q := hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: strings.Repeat("1", 64), AttemptID: strings.Repeat("c", 32), Original: hostwebgeneration.Transition{OperationID: strings.Repeat("d", 32), Revision: 4, Before: before, After: target}, BaseRevision: 4, Source: before.Identity(), Target: target}
	v := record{Version: 1, Revision: 4, LastOperation: strings.Repeat("e", 32), Current: before, BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
	return o, v, q
}
func TestDeniedRepairCanonicalAdmission(t *testing.T) {
	o, _, q := repairFixture(t)
	if !validRepairRequest(o.Profile, q) {
		t.Fatal("valid request")
	}
	for name, change := range map[string]func(*hostwebgeneration.DeniedRepairRequest){
		"active":         func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.Denied = false },
		"cas":            func(q *hostwebgeneration.DeniedRepairRequest) { q.ExpectedStateSHA256 = "" },
		"attempt":        func(q *hostwebgeneration.DeniedRepairRequest) { q.AttemptID = "../../outside" },
		"overflow":       func(q *hostwebgeneration.DeniedRepairRequest) { q.BaseRevision = ^uint64(0) },
		"originalfuture": func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.Revision = 5 },
		"source":         func(q *hostwebgeneration.DeniedRepairRequest) { q.Source.ProfileSHA256 = strings.Repeat("2", 64) },
		"snapshot":       func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.SnapshotSHA256 = strings.Repeat("0", 64) },
		"config":         func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.Bundle.Files[0].Data[0] = 'x' },
		"emptytarget":    func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.ID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			v := copyRepairRequest(q)
			change(&v)
			if validRepairRequest(o.Profile, v) {
				t.Fatal("invalid request admitted")
			}
		})
	}
}
func TestRepairCASAndOriginalApplyCounter(t *testing.T) {
	_, v, q := repairFixture(t)
	if e := repairRequestAdmission(v, q.ExpectedStateSHA256, q); e != nil {
		t.Fatal(e)
	}
	wrong := q
	wrong.ExpectedStateSHA256 = strings.Repeat("2", 64)
	if !errors.Is(repairRequestAdmission(v, q.ExpectedStateSHA256, wrong), ErrConflict) {
		t.Fatal("wrong CAS")
	}
	v.Current = q.Original.After
	v.Revision = 5
	v.LastOperation = q.Original.OperationID
	if !errors.Is(repairRequestAdmission(v, q.ExpectedStateSHA256, q), ErrConflict) {
		t.Fatal("consumed original Apply base reused")
	}
	q.BaseRevision = 5
	q.Source = v.Current.Identity()
	q.Target = testGeneration(t, testOptions("/srv/sifruno-runtime"), strings.Repeat("f", 32), true)
	// Without an existing repair binding, a caller cannot invent checkpoint
	// authority from the original operation ID alone.
	if !errors.Is(repairRequestAdmission(v, q.ExpectedStateSHA256, q), ErrConflict) {
		t.Fatal("invented counter reconciliation")
	}
}
func TestRepairPendingRetryKeepsAdmittedCAS(t *testing.T) {
	o, v, q := repairFixture(t)
	n := &nativeRepair{Request: copyRepairRequest(q), Binding: repairBinding(q)}
	v.Repair = n
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("pending admission")
	}
	refreshed := copyRepairRequest(q)
	refreshed.ExpectedStateSHA256 = strings.Repeat("2", 64)
	if !sameRepair(refreshed, n.Binding) || repairRequestAdmission(v, refreshed.ExpectedStateSHA256, refreshed) != nil {
		t.Fatal("fresh CAS retry")
	}
	if n.Binding.AdmittedStateSHA256 != q.ExpectedStateSHA256 {
		t.Fatal("admitted token mutated")
	}
	if !errors.Is(repairRequestAdmission(v, refreshed.ExpectedStateSHA256, q), ErrConflict) {
		t.Fatal("old pending CAS accepted")
	}
	n.Binding.BaseRevision++
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("future pending base")
	}
}
func completedFixture(t *testing.T) (Options, record, hostwebgeneration.DeniedRepairRequest) {
	o, v, q := repairFixture(t)
	v.Current = copyGeneration(q.Target)
	v.Revision = q.BaseRevision + 1
	v.LastOperation = q.Original.OperationID
	v.CompletedRepair = &nativeCompletion{Request: copyRepairRequest(q), Binding: repairBinding(q), ResultRevision: v.Revision}
	return o, v, q
}
func TestCompletedRepairCASIsNotObservation(t *testing.T) {
	o, v, q := completedFixture(t)
	current := strings.Repeat("2", 64)
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("completion metadata")
	}
	if completedRequestAdmission(v, current, q) != nil {
		t.Fatal("exact original token replay")
	}
	q.ExpectedStateSHA256 = current
	if completedRequestAdmission(v, current, q) != nil {
		t.Fatal("current token replay")
	}
	q.ExpectedStateSHA256 = strings.Repeat("3", 64)
	if !errors.Is(completedRequestAdmission(v, current, q), ErrConflict) {
		t.Fatal("wrong CAS same intent")
	}
	// This is protocol admission only: zero process pins prove no healthy serving.
	if len(v.Processes) != 0 {
		t.Fatal("fixture unexpectedly observed")
	}
}
func TestCompletedRepairBindingAndCausalCorruption(t *testing.T) {
	o, v, q := completedFixture(t)
	for name, change := range map[string]func(*record){
		"result":    func(v *record) { v.CompletedRepair.ResultRevision++ },
		"revision":  func(v *record) { v.Revision++ },
		"operation": func(v *record) { v.LastOperation = strings.Repeat("f", 32) },
		"intent":    func(v *record) { v.CompletedRepair.Binding.IntentSHA256 = strings.Repeat("0", 64) },
		"admission": func(v *record) { v.CompletedRepair.Binding.AdmittedStateSHA256 = strings.Repeat("0", 64) },
		"boot":      func(v *record) { v.BootID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			x := v
			n := *v.CompletedRepair
			x.CompletedRepair = &n
			change(&x)
			if validateRecord(o.Profile, x) == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
	changed := copyRepairRequest(q)
	changed.AttemptID = strings.Repeat("f", 32)
	if completedRequestAdmission(v, changed.ExpectedStateSHA256, changed) == nil {
		t.Fatal("new attempt reused old receipt")
	}
	changed = copyRepairRequest(q)
	changed.BaseRevision++
	if completedRequestAdmission(v, changed.ExpectedStateSHA256, changed) == nil {
		t.Fatal("consumed revision replay")
	}
}
func TestRepairRequestDefensiveCopy(t *testing.T) {
	_, _, q := repairFixture(t)
	x := copyRepairRequest(q)
	x.Target.Accounts[0].Domain = "mutated.test"
	x.Target.Bundle.Files[0].Data[0] = 'x'
	x.Original.Before.Bundle.Files[0].Data[0] = 'x'
	if q.Target.Accounts[0].Domain != "alpha.test" || q.Target.Bundle.Files[0].Data[0] == 'x' || q.Original.Before.Bundle.Files[0].Data[0] == 'x' {
		t.Fatal("alias")
	}
}
func TestRepairUnavailableOnOtherOS(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux capability")
	}
	r := &Runtime{}
	if _, e := r.InspectRecovery(context.Background()); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e := r.RepairDenied(context.Background(), hostwebgeneration.DeniedRepairRequest{}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
}

func TestRepairLogicalIDsAreImmutable(t *testing.T) {
	o, _, q := repairFixture(t)
	if !validRepairRequest(o.Profile, q) {
		t.Fatal("exact clean After/Target reuse rejected")
	}
	for name, change := range map[string]func(*hostwebgeneration.DeniedRepairRequest){
		"source": func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.ID = q.Source.GenerationID },
		"after": func(q *hostwebgeneration.DeniedRepairRequest) {
			q.Target.Accounts[0].Revision++
			q.Target.SnapshotSHA256 = digest(q.Target.Accounts)
		},
		"before":       func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.ID = q.Original.Before.ID },
		"source-after": func(q *hostwebgeneration.DeniedRepairRequest) { q.Source.GenerationID = q.Original.After.ID },
	} {
		t.Run(name, func(t *testing.T) {
			changed := copyRepairRequest(q)
			change(&changed)
			if validateGeneration(o.Profile, changed.Target, false) != nil {
				t.Fatal("target individually invalid")
			}
			if validRepairRequest(o.Profile, changed) {
				t.Fatal("different identities shared logical ID")
			}
		})
	}
}

func TestRecoveryRecordLogicalIDsBeforeDedup(t *testing.T) {
	o, completed, q := completedFixture(t)
	alias := copyGeneration(q.Target)
	alias.Accounts[0].Domain = "changed.test"
	alias.Accounts[0].Revision++
	alias.SnapshotSHA256 = digest(alias.Accounts)
	render := append(alias.Accounts[:0:0], alias.Accounts...)
	for i := range render {
		render[i].State = "suspended"
	}
	var err error
	alias.Bundle, err = hostweb.Compile(o.Profile, render)
	if err != nil || validateGeneration(o.Profile, alias, false) != nil || alias.Identity() == q.Target.Identity() {
		t.Fatal("independent canonical alias fixture", err)
	}
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("repair-%t", pending), func(t *testing.T) {
			_, v, request := repairFixture(t)
			if pending {
				v.Repair = &nativeRepair{Request: copyRepairRequest(request), Binding: repairBinding(request), Retained: []hostwebgeneration.Generation{copyGeneration(request.Target)}}
			} else {
				v = completed
				completion := *completed.CompletedRepair
				v.CompletedRepair = &completion
				v.CompletedRepair.Retained = []hostwebgeneration.Generation{copyGeneration(request.Target)}
			}
			if validateRecord(o.Profile, v) != nil {
				t.Fatal("exact repeated identity rejected")
			}
			if pending {
				v.Repair.Retained[0] = copyGeneration(alias)
			} else {
				v.CompletedRepair.Retained[0] = copyGeneration(alias)
			}
			if validateRecord(o.Profile, v) == nil {
				t.Fatal("retained alias concealed before deduplication")
			}
		})
	}
	// Original native pending records also cannot attach a different identity
	// to Current's ID, even when both generations compile independently.
	v := record{Version: 1, Revision: q.BaseRevision, LastOperation: strings.Repeat("e", 32), Current: copyGeneration(q.Target)}
	v.Pending = &transaction{OperationID: q.Original.OperationID, Revision: v.Revision, Before: q.Original.Before, After: q.Target, Target: alias}
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("native pending identity alias admitted")
	}
}

func TestExplicitBootAndPinMetadataMustAgree(t *testing.T) {
	o := testOptions("/srv/sifruno-runtime")
	g := testGeneration(t, o, "", true)
	boot := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	p := processPin{Role: "front", PID: 100, Start: "123", Boot: boot, Executable: o.Profile.ApacheBinary, ExecutableSHA256: strings.Repeat("a", 64), Config: o.Profile.ManagedRoot + "/" + generationPath(g) + "/apache/front.conf", Namespace: 55, ExecutableIno: 99}
	v := record{Version: 1, Current: g, Processes: []processPin{p}}
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("legacy metadata structurally rejected")
	}
	v.BootID = boot
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("matching explicit boot rejected")
	}
	v.Processes[0].Boot = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("explicit boot/pin mismatch admitted")
	}
}

func TestRecoverySocketOwnershipNeedsSameLifetime(t *testing.T) {
	before := socketLifetime{PID: 123, Start: "456", Namespace: 789}
	if !sameSocketLifetime(before, before) {
		t.Fatal("same lifetime rejected")
	}
	for name, change := range map[string]func(*socketLifetime){
		"pid":       func(s *socketLifetime) { s.PID++ },
		"reused":    func(s *socketLifetime) { s.Start = "457" },
		"namespace": func(s *socketLifetime) { s.Namespace++ },
		"vanished":  func(s *socketLifetime) { s.Start = "" },
	} {
		t.Run(name, func(t *testing.T) {
			after := before
			change(&after)
			if sameSocketLifetime(before, after) {
				t.Fatal("spliced socket evidence")
			}
		})
	}
	invalid := socketLifetime{PID: 123, Start: "not-a-start", Namespace: 789}
	if sameSocketLifetime(invalid, invalid) {
		t.Fatal("invalid same identity")
	}
}

func TestRecoveryIPv6ProtectedPortParsing(t *testing.T) {
	header := "  sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	row := func(address string, port uint16, state string) string {
		return fmt.Sprintf("0: %s:%04X %032X:0000 %s 0 0 0 0 0 123\n", address, port, 0, state)
	}
	ports := map[uint16]bool{18080: true, 18443: true}
	for name, address := range map[string]string{"wildcard": strings.Repeat("0", 32), "specific": "00000000000000000000000001000000", "mapped": "0000000000000000FFFF00000100007F"} {
		t.Run(name, func(t *testing.T) {
			found, e := protectedIPv6Listener([]byte(header+row(address, 18080, "0A")), ports)
			if e != nil || !found {
				t.Fatal("protected IPv6 admitted", e)
			}
		})
	}
	if found, e := protectedIPv6Listener([]byte(header+row(strings.Repeat("0", 32), 12345, "0A")), ports); e != nil || found {
		t.Fatal("unrelated port", e)
	}
	if found, e := protectedIPv6Listener([]byte(header+row(strings.Repeat("0", 32), 18080, "01")), ports); e != nil || found {
		t.Fatal("non-listener", e)
	}
	for name, input := range map[string]string{"header": "", "short": header + "0: 00000000000000000000000000000000:46A0 0 0A\n", "address": header + row(strings.Repeat("z", 32), 18080, "0A"), "port": header + strings.ReplaceAll(row(strings.Repeat("0", 32), 18080, "0A"), "46A0", "ZZZZ"), "inode": header + strings.ReplaceAll(row(strings.Repeat("0", 32), 18080, "0A"), "123", "bad")} {
		t.Run(name, func(t *testing.T) {
			if _, e := protectedIPv6Listener([]byte(input), ports); e == nil {
				t.Fatal("malformed proc row admitted")
			}
		})
	}
	if _, e := protectedIPv6Listener(make([]byte, (1<<20)+1), ports); !errors.Is(e, ErrLimit) {
		t.Fatal("network read bound", e)
	}
}
