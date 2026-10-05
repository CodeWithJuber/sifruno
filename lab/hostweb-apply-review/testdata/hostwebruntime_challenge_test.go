package hostwebruntime

import (
	"encoding/json"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

// Pure metadata/transition challenges. These helpers never launch daemons.
func applyReviewFixture(t *testing.T) (Options, hostwebgeneration.Transition, record) {
	t.Helper()
	o := testOptions("/srv/sifruno-runtime")
	before := testGeneration(t, o, "", true)
	after := testGeneration(t, o, strings.Repeat("b", 32), false)
	tr := hostwebgeneration.Transition{OperationID: strings.Repeat("c", 32), Before: before, After: after}
	v := record{Version: 1, InputsSHA256: strings.Repeat("1", 64), BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Current: before}
	b := applyBinding(tr, strings.Repeat("2", 64), v.InputsSHA256, v.BootID)
	tx := transaction{OperationID: tr.OperationID, Revision: tr.Revision, Before: tr.Before, After: tr.After, Target: tr.After, ApplyIntent: &b}
	v = replacementState(v, tx)
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("valid Apply completion fixture rejected")
	}
	return o, tr, v
}
func applyReviewClone(t *testing.T, v record) record {
	t.Helper()
	data, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var out record
	if e = json.Unmarshal(data, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func applyReviewDenial(t *testing.T, o Options, tr hostwebgeneration.Transition, v record) hostwebgeneration.DeniedRepairRequest {
	t.Helper()
	return hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: strings.Repeat("3", 64), AttemptID: strings.Repeat("d", 32), Original: copyTransition(tr), BaseRevision: v.Revision, Source: v.Current.Identity(), Target: testGeneration(t, o, strings.Repeat("e", 32), true)}
}

func TestApplyReviewNativeBindingIntegrity(t *testing.T) {
	_, tr, v := applyReviewFixture(t)
	original := v.CompletedApply.Completion.Binding
	for name, change := range map[string]func(*hostwebgeneration.ApplyCompletionBinding){
		"version":       func(b *hostwebgeneration.ApplyCompletionBinding) { b.Version++ },
		"kind":          func(b *hostwebgeneration.ApplyCompletionBinding) { b.Kind = "rollback" },
		"operation":     func(b *hostwebgeneration.ApplyCompletionBinding) { b.OperationID = strings.Repeat("f", 32) },
		"original-base": func(b *hostwebgeneration.ApplyCompletionBinding) { b.OriginalRevision++ },
		"native-base":   func(b *hostwebgeneration.ApplyCompletionBinding) { b.NativeBaseRevision++ },
		"before":        func(b *hostwebgeneration.ApplyCompletionBinding) { b.Before = b.After },
		"after":         func(b *hostwebgeneration.ApplyCompletionBinding) { b.After = b.Before },
		"boot":          func(b *hostwebgeneration.ApplyCompletionBinding) { b.BootID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" },
		"input":         func(b *hostwebgeneration.ApplyCompletionBinding) { b.InputsSHA256 = strings.Repeat("9", 64) },
		"invalid-cas":   func(b *hostwebgeneration.ApplyCompletionBinding) { b.AdmittedStateSHA256 = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			b := original
			change(&b)
			b.IntentSHA256 = hostwebgeneration.ApplyIntentSHA(b)
			if validApplyBinding(tr, b, v.InputsSHA256, v.BootID) {
				t.Fatal("rehashed semantic corruption admitted")
			}
		})
	}
	b := original
	b.AdmittedStateSHA256 = strings.Repeat("8", 64)
	if validApplyBinding(tr, b, v.InputsSHA256, v.BootID) {
		t.Fatal("changed original CAS with old intent admitted")
	}
}
func TestApplyReviewNativeReplacementNeverInfersMarker(t *testing.T) {
	o, tr, v := applyReviewFixture(t)
	old := applyReviewClone(t, v)
	old.CompletedApply = nil
	if validateRecord(o.Profile, old) != nil {
		t.Fatal("compatible markerless historical state rejected")
	}
	rollback := transaction{OperationID: strings.Repeat("f", 32), Revision: v.Revision, Before: tr.After, After: testGeneration(t, o, strings.Repeat("7", 32), false), Target: tr.Before}
	replaced := replacementState(v, rollback)
	if replaced.CompletedApply != nil || replaced.CompletedRepair != nil || replaced.Revision != 2 {
		t.Fatal("Rollback/common replacement synthesized or retained Apply marker")
	}
	q := applyReviewDenial(t, o, tr, old)
	if completedApplyRequestAdmission(old, q) == nil || repairRequestAdmission(old, q.ExpectedStateSHA256, q) == nil {
		t.Fatal("LastOperation/Configured synthesized historical Apply authority")
	}
}
func TestApplyReviewNativeCompletionCouplesDurableState(t *testing.T) {
	o, tr, v := applyReviewFixture(t)
	for name, change := range map[string]func(*record){
		"result":  func(x *record) { x.CompletedApply.Completion.ResultRevision++ },
		"counter": func(x *record) { x.Revision++ },
		"lastop":  func(x *record) { x.LastOperation = strings.Repeat("f", 32) },
		"current": func(x *record) { x.Current = tr.Before },
		"boot":    func(x *record) { x.BootID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" },
		"inputs":  func(x *record) { x.InputsSHA256 = strings.Repeat("9", 64) },
		"generic-pending": func(x *record) {
			x.Pending = &transaction{OperationID: tr.OperationID, Before: tr.Before, After: tr.After, Target: tr.After}
		},
		"repair-completion": func(x *record) {
			q := applyReviewDenial(t, o, tr, v)
			x.CompletedRepair = &nativeCompletion{Request: q, Binding: repairBinding(q), ResultRevision: 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := applyReviewClone(t, v)
			change(&x)
			if validateRecord(o.Profile, x) == nil {
				t.Fatal("inconsistent completed state admitted")
			}
		})
	}
}
func TestApplyReviewNativeDenialExactTupleAndCAS(t *testing.T) {
	o, tr, v := applyReviewFixture(t)
	q := applyReviewDenial(t, o, tr, v)
	if !validRepairRequest(o.Profile, q) || completedApplyRequestAdmission(v, q) != nil || repairRequestAdmission(v, q.ExpectedStateSHA256, q) != nil {
		t.Fatal("exact historical denial rejected")
	}
	for name, change := range map[string]func(*hostwebgeneration.DeniedRepairRequest){
		"base":          func(x *hostwebgeneration.DeniedRepairRequest) { x.BaseRevision++ },
		"original-base": func(x *hostwebgeneration.DeniedRepairRequest) { x.Original.Revision++ },
		"operation":     func(x *hostwebgeneration.DeniedRepairRequest) { x.Original.OperationID = strings.Repeat("f", 32) },
		"source":        func(x *hostwebgeneration.DeniedRepairRequest) { x.Source = tr.Before.Identity() },
		"before":        func(x *hostwebgeneration.DeniedRepairRequest) { x.Original.Before = tr.After },
		"after":         func(x *hostwebgeneration.DeniedRepairRequest) { x.Original.After = tr.Before },
		"CAS":           func(x *hostwebgeneration.DeniedRepairRequest) { x.ExpectedStateSHA256 = strings.Repeat("4", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			x := copyRepairRequest(q)
			change(&x)
			if repairRequestAdmission(v, q.ExpectedStateSHA256, x) == nil {
				t.Fatal("altered original/native CAS admitted")
			}
		})
	}
}
func TestApplyReviewNativeSameOriginalPendingRetainsHistory(t *testing.T) {
	o, tr, v := applyReviewFixture(t)
	q := applyReviewDenial(t, o, tr, v)
	v.Repair = &nativeRepair{Request: q, Binding: repairBinding(q), Retained: []hostwebgeneration.Generation{tr.Before, tr.After}}
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("exact same-original pending denial rejected")
	}
	for name, change := range map[string]func(*record){
		"other-op": func(x *record) {
			x.Repair.Request.Original.OperationID = strings.Repeat("f", 32)
			x.Repair.Binding = repairBinding(x.Repair.Request)
		},
		"other-base": func(x *record) { x.Repair.Request.BaseRevision = 0; x.Repair.Binding = repairBinding(x.Repair.Request) },
		"other-source": func(x *record) {
			x.Repair.Request.Source = tr.Before.Identity()
			x.Repair.Binding = repairBinding(x.Repair.Request)
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := applyReviewClone(t, v)
			change(&x)
			if validateRecord(o.Profile, x) == nil {
				t.Fatal("unrelated repair inherited Apply authority")
			}
		})
	}
}
func TestApplyReviewNativeRawMarkerAliasBeforeDedup(t *testing.T) {
	o, tr, v := applyReviewFixture(t)
	alias := copyGeneration(tr.Before)
	alias.Accounts[0].Domain = "alias.test"
	alias.SnapshotSHA256 = digest(alias.Accounts)
	rendered := append([]hostaccounts.Account(nil), alias.Accounts...)
	for i := range rendered {
		rendered[i].State = "suspended"
	}
	var e error
	alias.Bundle, e = hostweb.Compile(o.Profile, rendered)
	if e != nil || validateGeneration(o.Profile, alias, true) != nil {
		t.Fatal("alias fixture not independently valid", e)
	}
	q := applyReviewDenial(t, o, tr, v)
	v.Repair = &nativeRepair{Request: q, Binding: repairBinding(q), Retained: []hostwebgeneration.Generation{alias}}
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("retained bootstrap alias hid completed original identity")
	}
	v.Repair.Retained = []hostwebgeneration.Generation{tr.Before}
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("exact retained identity rejected")
	}
}
func TestApplyReviewNativeMarkerCopiesCompiledInputs(t *testing.T) {
	_, tr, v := applyReviewFixture(t)
	priorDomain := tr.Before.Accounts[0].Domain
	priorByte := tr.After.Bundle.Files[0].Data[0]
	v.CompletedApply.Original.Before.Accounts[0].Domain = "mutated.test"
	v.CompletedApply.Original.After.Bundle.Files[0].Data[0] ^= 1
	if tr.Before.Accounts[0].Domain != priorDomain || tr.After.Bundle.Files[0].Data[0] != priorByte {
		t.Fatal("durable marker aliases caller account/config bytes")
	}
}
func TestApplyReviewNativeStableDigestCoversAllEvidence(t *testing.T) {
	_, _, v := applyReviewFixture(t)
	b := v.CompletedApply.Completion.Binding
	original := hostwebgeneration.ApplyIntentSHA(b)
	for _, change := range []func(*hostwebgeneration.ApplyCompletionBinding){
		func(x *hostwebgeneration.ApplyCompletionBinding) { x.Version++ }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.Kind = "rollback" }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.OperationID = "other" }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.OriginalRevision++ }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.NativeBaseRevision++ }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.Before = x.After }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.After = x.Before }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.AdmittedStateSHA256 = "other" }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.InputsSHA256 = "other" }, func(x *hostwebgeneration.ApplyCompletionBinding) { x.BootID = "other" },
	} {
		x := b
		change(&x)
		if hostwebgeneration.ApplyIntentSHA(x) == original {
			t.Fatal("immutable evidence missing from intent digest")
		}
	}
	b.IntentSHA256 = "other"
	if hostwebgeneration.ApplyIntentSHA(b) != original {
		t.Fatal("intent digest includes itself")
	}
}

func TestApplyReviewNativeCleanEntryCannotInheritOriginalMarker(t *testing.T) {
	o, _, v := applyReviewFixture(t)
	target := testGeneration(t, o, strings.Repeat("e", 32), true)
	tr := hostwebgeneration.Transition{OperationID: strings.Repeat("f", 32), Revision: v.Revision, Before: v.Current, After: target}
	q := hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: strings.Repeat("3", 64), AttemptID: strings.Repeat("d", 32), Original: tr, BaseRevision: v.Revision, Source: v.Current.Identity(), Target: target}
	if completedApplyRequestAdmission(v, q) == nil {
		t.Fatal("new clean operation inherited old Apply completion")
	}
	if repairRequestAdmission(v, q.ExpectedStateSHA256, q) != nil {
		t.Fatal("legacy clean-controller-death metadata entry accidentally removed")
	}
	v.Repair = &nativeRepair{Request: q, Binding: repairBinding(q)}
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("unrelated pending repair retained old Apply marker")
	}
	v.CompletedApply = nil
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("clearing unrelated historical marker did not restore valid clean pending denial")
	}
}
