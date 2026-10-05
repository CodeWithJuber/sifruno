//go:build linux

package hostwebruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

// These exercise real temporary disk/proc admission only. Synthetic binary
// inputs from recoveryFilesystem are never executed or called serving proof.
func applyFilesystem(t *testing.T) (*Runtime, record, transaction) {
	t.Helper()
	r := recoveryFilesystem(t)
	v, q := writeRecoveryState(t, r)
	if e := r.stage(q.Original.After); e != nil {
		t.Fatal(e)
	}
	b := applyBinding(q.Original, r.stateSHA, r.inputsSHA, v.BootID)
	tx := transaction{OperationID: q.Original.OperationID, Revision: q.Original.Revision, Before: q.Original.Before, After: q.Original.After, Target: q.Original.After, ApplyIntent: &b}
	return r, v, tx
}

func TestNativeApplyReservesMaximalFuturePinBytes(t *testing.T) {
	o, v, tx := applyFixture(t)
	g := testGeneration(t, o, strings.Repeat("b", 32), false)
	first := g.Accounts[0]
	g.Accounts = nil
	for i := 0; i < MaxRuntimeAccounts; i++ {
		a := first
		a.ID = fmt.Sprintf("%032x", i+1)
		a.Username = fmt.Sprintf("tenant%d", i+1)
		a.Domain = fmt.Sprintf("tenant%d.test", i+1)
		a.UID = 20001 + i
		a.GID = a.UID
		a.Home = o.Profile.ManagedHomeRoot + "/" + a.Username
		a.PublicHTML = a.Home + "/public_html"
		g.Accounts = append(g.Accounts, a)
	}
	g.SnapshotSHA256 = digest(g.Accounts)
	var e error
	g.Bundle, e = hostweb.Compile(o.Profile, append([]hostaccounts.Account(nil), g.Accounts...))
	if e != nil || validateGeneration(o.Profile, g, false) != nil {
		t.Fatal("maximal valid target", e)
	}
	tx.After = g
	tx.Target = g
	b := applyBinding(nativeTransition(tx), tx.ApplyIntent.AdmittedStateSHA256, v.InputsSHA256, v.BootID)
	tx.ApplyIntent = &b
	pins := maxStoragePins(o.Profile, g, v.BootID)
	if len(pins) != MaxProcesses {
		t.Fatal("not all possible masters reserved")
	}
	terminal := replacementState(v, tx)
	bare, e := json.Marshal(metadataCopy(terminal))
	if e != nil {
		t.Fatal(e)
	}
	terminal.Processes = pins
	if validateRecord(o.Profile, terminal) != nil {
		t.Fatal("storage-only inventory invalid")
	}
	full, e := json.Marshal(metadataCopy(terminal))
	if e != nil || len(full) <= len(bare) {
		t.Fatal("future pins add no byte budget", e)
	}
	pending := v
	pending.Pending = &tx
	barePending, e := json.Marshal(metadataCopy(pending))
	if e != nil {
		t.Fatal(e)
	}
	pending.Processes = pins
	fullPending, e := json.Marshal(metadataCopy(pending))
	if e != nil {
		t.Fatal(e)
	}
	bareLimit := max(len(bare), len(barePending))
	reserved := max(len(full), len(fullPending))
	if reserved <= bareLimit {
		t.Fatal("test does not isolate omitted future-pin bytes")
	}
	nearLimit := bareLimit + (reserved-bareLimit)/2
	if e = replacementMetadataCapacityLimit(o.Profile, v, tx, nearLimit); !errors.Is(e, ErrLimit) {
		t.Fatal("near bound admitted without future pins", e)
	}
	if e = replacementMetadataCapacity(o.Profile, v, tx); e != nil {
		t.Fatal("fixed production bound", e)
	}
}

func TestNativeCheckpointDenialReservesFutureFrontBytes(t *testing.T) {
	r, v, tx := applyFilesystem(t)
	v = replacementState(v, tx)
	if e := r.persist(v); e != nil {
		t.Fatal(e)
	}
	q := hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: r.stateSHA, AttemptID: strings.Repeat("c", 32), Original: nativeTransition(tx), BaseRevision: v.Revision, Source: v.Current.Identity(), Target: testGeneration(t, r.opts, strings.Repeat("f", 32), true)}
	n := &nativeRepair{Request: copyRepairRequest(q), Binding: repairBinding(q), Retained: ownedGenerations(v)}
	v.Repair = n
	if len(v.Processes) != 0 || validateRecord(r.opts.Profile, v) != nil {
		t.Fatal("exact dead/no-pins checkpoint fixture")
	}
	terminal := v
	terminal.Current = copyGeneration(q.Target)
	terminal.Repair = nil
	terminal.CompletedApply = nil
	terminal.Revision = q.BaseRevision + 1
	terminal.LastOperation = q.Original.OperationID
	terminal.CompletedRepair = &nativeCompletion{Request: copyRepairRequest(q), Binding: n.Binding, ResultRevision: terminal.Revision, Retained: n.Retained}
	barePending, e := json.Marshal(metadataCopy(v))
	if e != nil {
		t.Fatal(e)
	}
	bareTerminal, e := json.Marshal(metadataCopy(terminal))
	if e != nil {
		t.Fatal(e)
	}
	maxPending := v
	maxPending.Processes = maxStoragePins(r.opts.Profile, q.Target, v.BootID)
	terminal.Processes = maxStoragePins(r.opts.Profile, q.Target, v.BootID)
	if len(terminal.Processes) != 1 {
		t.Fatal("denial must reserve its one front")
	}
	fullPending, e := json.Marshal(metadataCopy(maxPending))
	if e != nil {
		t.Fatal(e)
	}
	fullTerminal, e := json.Marshal(metadataCopy(terminal))
	if e != nil {
		t.Fatal(e)
	}
	bareLimit := max(len(barePending), len(bareTerminal))
	reserved := max(len(fullPending), len(fullTerminal))
	if reserved <= bareLimit {
		t.Fatal("fixture does not isolate future-front bytes")
	}
	limit := bareLimit + (reserved-bareLimit)/2
	before := r.stateSHA
	if e = repairMetadataCapacityLimit(r.opts.Profile, v, q, n, limit); !errors.Is(e, ErrLimit) {
		t.Fatal("near-limit no-pins denial admitted", e)
	}
	if r.stateSHA != before {
		t.Fatal("preflight mutated current CAS")
	}
	if _, e = os.Stat(filepath.Join(r.opts.Profile.ManagedRoot, generationPath(q.Target))); !os.IsNotExist(e) {
		t.Fatal("capacity refusal staged target")
	}
	if e = repairMetadataCapacity(r.opts.Profile, v, q, n); e != nil {
		t.Fatal("production fixed bound", e)
	}
}

func TestNativeApplyIntentAndCompletionDiskRoundTrip(t *testing.T) {
	r, v, tx := applyFilesystem(t)
	if e := replacementMetadataCapacity(r.opts.Profile, v, tx); e != nil {
		t.Fatal(e)
	}
	originalSHA := tx.ApplyIntent.AdmittedStateSHA256
	v.Pending = &tx
	if e := r.persist(v); e != nil {
		t.Fatal(e)
	}
	if r.stateSHA == originalSHA {
		t.Fatal("pending CAS did not change")
	}
	r.stateSHA = ""
	pending, e := r.load()
	if e != nil || pending.Pending == nil || pending.Pending.ApplyIntent == nil || pending.Pending.ApplyIntent.AdmittedStateSHA256 != originalSHA {
		t.Fatal("pending original token lost", e)
	}
	inspection, e := r.InspectRecovery(context.Background())
	if e != nil || inspection.Pending == nil || inspection.Pending.Apply == nil || inspection.CompletedApply != nil || inspection.Observed != nil {
		t.Fatal("pending inspection", e)
	}
	inspection.Pending.Apply.AdmittedStateSHA256 = "mutated"
	final := replacementState(pending, tx)
	if e = r.persist(final); e != nil {
		t.Fatal(e)
	}
	r.stateSHA = ""
	loaded, e := r.load()
	if e != nil || loaded.CompletedApply == nil || loaded.CompletedApply.Completion.Binding.AdmittedStateSHA256 != originalSHA || loaded.Pending != nil {
		t.Fatal("completion round trip", e)
	}
	inspection, e = r.InspectRecovery(context.Background())
	if e != nil || inspection.CompletedApply == nil || inspection.CompletedApply.ResultRevision != 5 || inspection.Observed != nil {
		t.Fatal("historical receipt became observed", e)
	}
	inspection.CompletedApply.Binding.IntentSHA256 = "mutated"
	again, e := r.InspectRecovery(context.Background())
	if e != nil || again.CompletedApply.Binding.IntentSHA256 != tx.ApplyIntent.IntentSHA256 {
		t.Fatal("inspection alias", e)
	}
	meta := metadataCopy(loaded)
	meta.CompletedApply.Original.Before.Accounts[0].Domain = "changed.test"
	if validateRecord(r.opts.Profile, loaded) != nil {
		t.Fatal("metadata alias")
	}
}

func TestNativeApplyFinalObserveCannotUseHistoricalCompletion(t *testing.T) {
	r, v, tx := applyFilesystem(t)
	final := replacementState(v, tx)
	if e := r.persist(final); e != nil {
		t.Fatal(e)
	}
	if e := r.finishReplacement(context.Background(), &final, tx); !errors.Is(e, ErrRecovery) {
		t.Fatal("dead processes returned cached success", e)
	}
	got, e := r.InspectRecovery(context.Background())
	if e != nil || got.CompletedApply == nil || got.Observed != nil {
		t.Fatal("historical completion erased/misreported", e)
	}
}

func TestNativeApplyPostCommitCancellationPreservesHistoricalFact(t *testing.T) {
	r, v, tx := applyFilesystem(t)
	final := replacementState(v, tx)
	if e := r.persist(final); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := r.finishReplacement(ctx, &final, tx); !errors.Is(e, context.Canceled) {
		t.Fatal("canceled completion succeeded", e)
	}
	r.stateSHA = ""
	got, e := r.load()
	if e != nil || got.CompletedApply == nil || got.Revision != 5 || got.Pending != nil {
		t.Fatal("uncertain committed tuple lost", e)
	}
}

func TestNativeApplyFailedFinalRereadDoesNotOverwriteCorruption(t *testing.T) {
	r, v, tx := applyFilesystem(t)
	final := replacementState(v, tx)
	if e := r.persist(final); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(r.opts.Profile.ManagedRoot, "state.json")
	foreign := []byte("{\"Version\":1,\"foreign\":true}")
	if e := os.WriteFile(path, foreign, 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.finishReplacement(context.Background(), &final, tx); !errors.Is(e, ErrRecovery) {
		t.Fatal("failed read succeeded", e)
	}
	bytes, e := os.ReadFile(path)
	if e != nil || string(bytes) != string(foreign) {
		t.Fatal("corrupt state overwritten", e)
	}
}

func TestNativeApplyCompletionCorruptionAndLegacyAdmission(t *testing.T) {
	for _, which := range []string{"intent", "inputs", "duplicate", "legacy"} {
		t.Run(which, func(t *testing.T) {
			r, v, tx := applyFilesystem(t)
			final := replacementState(v, tx)
			if e := r.persist(final); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(r.opts.Profile.ManagedRoot, "state.json")
			data, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if which == "duplicate" {
				data = append([]byte("{\"CompletedApply\":null,"), data[1:]...)
			} else {
				var doc record
				if e = json.Unmarshal(data, &doc); e != nil {
					t.Fatal(e)
				}
				switch which {
				case "intent":
					doc.CompletedApply.Completion.Binding.IntentSHA256 = strings.Repeat("0", 64)
				case "inputs":
					doc.CompletedApply.Completion.Binding.InputsSHA256 = strings.Repeat("0", 64)
				case "legacy":
					doc.CompletedApply = nil
				}
				data, e = json.Marshal(doc)
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			r.stateSHA = ""
			loaded, e := r.load()
			if which != "legacy" {
				if e == nil {
					t.Fatal("altered completion admitted")
				}
				return
			}
			if e != nil || loaded.CompletedApply != nil {
				t.Fatal("legacy synthesized receipt", e)
			}
			q := hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: r.stateSHA, AttemptID: strings.Repeat("c", 32), Original: nativeTransition(tx), BaseRevision: loaded.Revision, Source: loaded.Current.Identity(), Target: testGeneration(t, r.opts, strings.Repeat("f", 32), true)}
			if repairRequestAdmission(loaded, r.stateSHA, q) == nil {
				t.Fatal("legacy consumed Apply admitted")
			}
		})
	}
}
