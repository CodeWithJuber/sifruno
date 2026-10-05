package hostwebruntime

import (
	"errors"
	"strings"
	"testing"

	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

func applyFixture(t *testing.T) (Options, record, transaction) {
	t.Helper()
	o, v, q := repairFixture(t)
	v.InputsSHA256 = strings.Repeat("9", 64)
	b := applyBinding(q.Original, q.ExpectedStateSHA256, v.InputsSHA256, v.BootID)
	tx := transaction{OperationID: q.Original.OperationID, Revision: q.Original.Revision, Before: q.Original.Before, After: q.Original.After, Target: q.Original.After, ApplyIntent: &b}
	return o, v, tx
}

func TestApplyIntentAndAtomicCompletionAdmission(t *testing.T) {
	o, v, tx := applyFixture(t)
	v.Pending = &tx
	if validateRecord(o.Profile, v) != nil || v.CompletedApply != nil {
		t.Fatal("pending intent")
	}
	final := replacementState(v, tx)
	if validateRecord(o.Profile, final) != nil || final.Pending != nil || final.Current.Identity() != tx.After.Identity() || final.Revision != tx.Revision+1 || final.LastOperation != tx.OperationID || final.CompletedApply == nil || final.CompletedApply.Completion.Binding != *tx.ApplyIntent {
		t.Fatal("atomic completion tuple")
	}
	if final.CompletedApply.Original.Before.Identity() != tx.Before.Identity() || final.CompletedApply.Original.After.Identity() != tx.After.Identity() {
		t.Fatal("lost original transition")
	}
}

func TestApplyBindingRejectsRehashedCorruption(t *testing.T) {
	o, v, tx := applyFixture(t)
	for name, change := range map[string]func(*hostwebgeneration.ApplyCompletionBinding){
		"kind":             func(b *hostwebgeneration.ApplyCompletionBinding) { b.Kind = "rollback" },
		"version":          func(b *hostwebgeneration.ApplyCompletionBinding) { b.Version++ },
		"operation":        func(b *hostwebgeneration.ApplyCompletionBinding) { b.OperationID = strings.Repeat("f", 32) },
		"original-counter": func(b *hostwebgeneration.ApplyCompletionBinding) { b.OriginalRevision++ },
		"native-counter":   func(b *hostwebgeneration.ApplyCompletionBinding) { b.NativeBaseRevision++ },
		"before":           func(b *hostwebgeneration.ApplyCompletionBinding) { b.Before = b.After },
		"after":            func(b *hostwebgeneration.ApplyCompletionBinding) { b.After = b.Before },
		"admission":        func(b *hostwebgeneration.ApplyCompletionBinding) { b.AdmittedStateSHA256 = "" },
		"input":            func(b *hostwebgeneration.ApplyCompletionBinding) { b.InputsSHA256 = strings.Repeat("0", 64) },
		"boot":             func(b *hostwebgeneration.ApplyCompletionBinding) { b.BootID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := tx
			b := *tx.ApplyIntent
			change(&b)
			b.IntentSHA256 = hostwebgeneration.ApplyIntentSHA(b)
			bad.ApplyIntent = &b
			pending := v
			pending.Pending = &bad
			if validateRecord(o.Profile, pending) == nil || validateRecord(o.Profile, replacementState(v, bad)) == nil {
				t.Fatal("rehashed inconsistent tuple admitted")
			}
		})
	}
	final := replacementState(v, tx)
	final.CompletedApply.Completion.ResultRevision++
	if validateRecord(o.Profile, final) == nil {
		t.Fatal("wrong result counter")
	}
}

func TestLegacyAndRollbackNeverMintApplyCompletion(t *testing.T) {
	o, v, tx := applyFixture(t)
	tx.ApplyIntent = nil
	legacy := replacementState(v, tx)
	if validateRecord(o.Profile, legacy) != nil || legacy.CompletedApply != nil {
		t.Fatal("legacy final inferred Apply")
	}
	rollback := tx
	rollback.Target = tx.Before
	rolled := replacementState(v, rollback)
	if rolled.CompletedApply != nil {
		t.Fatal("rollback minted completion")
	}
	// Even the exact original op/After/counter is insufficient without marker.
	q := hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: strings.Repeat("1", 64), AttemptID: strings.Repeat("c", 32), Original: nativeTransition(tx), BaseRevision: legacy.Revision, Source: legacy.Current.Identity(), Target: testGeneration(t, o, strings.Repeat("f", 32), true)}
	if repairRequestAdmission(legacy, q.ExpectedStateSHA256, q) == nil {
		t.Fatal("legacy marker synthesized")
	}
}

func TestApplyCheckpointExactDenialAdmission(t *testing.T) {
	o, v, tx := applyFixture(t)
	final := replacementState(v, tx)
	q := hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: strings.Repeat("2", 64), AttemptID: strings.Repeat("c", 32), Original: nativeTransition(tx), BaseRevision: final.Revision, Source: final.Current.Identity(), Target: testGeneration(t, o, strings.Repeat("f", 32), true)}
	if !validRepairRequest(o.Profile, q) || repairRequestAdmission(final, q.ExpectedStateSHA256, q) != nil {
		t.Fatal("exact checkpoint denial")
	}
	for name, change := range map[string]func(*hostwebgeneration.DeniedRepairRequest){
		"wrong-cas":         func(q *hostwebgeneration.DeniedRepairRequest) { q.ExpectedStateSHA256 = strings.Repeat("0", 64) },
		"old-base":          func(q *hostwebgeneration.DeniedRepairRequest) { q.BaseRevision-- },
		"source":            func(q *hostwebgeneration.DeniedRepairRequest) { q.Source = q.Original.Before.Identity() },
		"original-before":   func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.Before = q.Target },
		"original-after":    func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.After = q.Target },
		"original-revision": func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.Revision++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := copyRepairRequest(q)
			change(&bad)
			if repairRequestAdmission(final, q.ExpectedStateSHA256, bad) == nil {
				t.Fatal("wrong checkpoint tuple admitted")
			}
		})
	}
	final.Repair = &nativeRepair{Request: copyRepairRequest(q), Binding: repairBinding(q), Retained: []hostwebgeneration.Generation{tx.Before, tx.After}}
	if validateRecord(o.Profile, final) != nil {
		t.Fatal("historical Apply rejected during exact pending denial")
	}
	final.Repair.Request.Original.OperationID = strings.Repeat("f", 32)
	final.Repair.Binding = repairBinding(final.Repair.Request)
	if validateRecord(o.Profile, final) == nil {
		t.Fatal("unrelated repair inherited Apply marker")
	}
}

func TestApplyCompletionDeepCopiesAndGlobalAliases(t *testing.T) {
	o, v, tx := applyFixture(t)
	final := replacementState(v, tx)
	tx.Before.Accounts[0].Domain = "caller-change.test"
	tx.After.Bundle.Files[0].Data[0] = 'x'
	tx.ApplyIntent.AdmittedStateSHA256 = strings.Repeat("0", 64)
	if validateRecord(o.Profile, final) != nil {
		t.Fatal("completion aliased caller")
	}
	alias := copyGeneration(final.CompletedApply.Original.Before)
	alias.ID = final.Current.ID
	alias.Accounts[0].Domain = "alias.test"
	alias.SnapshotSHA256 = digest(alias.Accounts)
	var err error
	alias.Bundle, err = hostweb.Compile(o.Profile, alias.Accounts)
	if err != nil || validateGeneration(o.Profile, alias, false) != nil {
		t.Fatal("alias independently invalid", err)
	}
	final.CompletedApply.Original.Before = alias
	final.CompletedApply.Completion.Binding.Before = alias.Identity()
	final.CompletedApply.Completion.Binding.IntentSHA256 = hostwebgeneration.ApplyIntentSHA(final.CompletedApply.Completion.Binding)
	if !errors.Is(validateRecord(o.Profile, final), ErrRecovery) {
		t.Fatal("global logical ID alias concealed")
	}
}
