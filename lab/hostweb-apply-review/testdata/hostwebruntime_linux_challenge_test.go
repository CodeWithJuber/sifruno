//go:build linux

package hostwebruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

// This test is cross-compiled by the Windows runner, never reported as an
// executed Linux test. It tests the production capacity helper when executed
// in a future separately admitted native gate; no process/disk is involved.
func TestApplyReviewLinuxFuturePinCapacityReserved(t *testing.T) {
	o, _, base := applyReviewFixture(t)
	seed := base.CompletedApply.Original.After
	seed.ID = "77777777777777777777777777777777"
	accounts := make([]hostaccounts.Account, 8)
	for i := range accounts {
		a := seed.Accounts[0]
		a.ID = fmt.Sprintf("%032x", i+1)
		a.Username = fmt.Sprintf("webu%d", i)
		a.Domain = fmt.Sprintf("u%d.test", i)
		a.UID = 21000 + i
		a.GID = a.UID
		a.Home = o.Profile.ManagedHomeRoot + "/" + a.Username
		a.PublicHTML = a.Home + "/public_html"
		accounts[i] = a
	}
	seed.Accounts = accounts
	seed.SnapshotSHA256 = digest(accounts)
	var err error
	seed.Bundle, err = hostweb.Compile(o.Profile, accounts)
	if err != nil || validateGeneration(o.Profile, seed, false) != nil {
		t.Fatal("eight-account fixture invalid", err)
	}
	before := copyGeneration(seed)
	before.ID = ""
	before.Denied = true
	rendered := append([]hostaccounts.Account(nil), accounts...)
	for i := range rendered {
		rendered[i].State = "suspended"
	}
	before.Bundle, err = hostweb.Compile(o.Profile, rendered)
	if err != nil {
		t.Fatal(err)
	}
	tr := hostwebgeneration.Transition{OperationID: "cccccccccccccccccccccccccccccccc", Before: before, After: seed}
	v := record{Version: 1, Current: before, BootID: base.BootID, InputsSHA256: base.InputsSHA256}
	binding := applyBinding(tr, "2222222222222222222222222222222222222222222222222222222222222222", v.InputsSHA256, v.BootID)
	tx := transaction{OperationID: tr.OperationID, Before: before, After: seed, Target: seed, ApplyIntent: &binding}
	pending := v
	pending.Pending = &tx
	terminal := replacementState(v, tx)
	pBytes, e := json.Marshal(metadataCopy(pending))
	if e != nil {
		t.Fatal(e)
	}
	tBytes, e := json.Marshal(metadataCopy(terminal))
	if e != nil {
		t.Fatal(e)
	}
	bareMax := len(pBytes)
	if len(tBytes) > bareMax {
		bareMax = len(tBytes)
	}
	pins := maxStoragePins(o.Profile, seed, v.BootID)
	if len(pins) != 17 {
		t.Fatalf("not all future masters budgeted: %d", len(pins))
	}
	terminal.Processes = pins
	if validateRecord(o.Profile, terminal) != nil {
		t.Fatal("prospective terminal pin inventory invalid")
	}
	pinned, e := json.Marshal(metadataCopy(terminal))
	if e != nil || len(pinned) <= bareMax+1 {
		t.Fatal("near-bound fixture has no omitted-pin gap", e)
	}
	if !errors.Is(replacementMetadataCapacityLimit(o.Profile, v, tx, bareMax+1), ErrLimit) {
		t.Fatal("near-bound capacity accepted records that fit only without future process pins")
	}
	if e = replacementMetadataCapacity(o.Profile, v, tx); e != nil {
		t.Fatal("normal bounded inventory incorrectly rejected", e)
	}
}

func TestApplyReviewLinuxDeniedFrontCapacityReserved(t *testing.T) {
	o, tr, v := applyReviewFixture(t)
	q := applyReviewDenial(t, o, tr, v)
	n := &nativeRepair{Request: q, Binding: repairBinding(q), Retained: []hostwebgeneration.Generation{tr.Before, tr.After}}
	v.Repair = n
	if len(v.Processes) != 0 || validateRecord(o.Profile, v) != nil {
		t.Fatal("historical dead Apply entry invalid")
	}
	terminal := v
	terminal.Current = copyGeneration(q.Target)
	terminal.Repair = nil
	terminal.Pending = nil
	terminal.Revision = q.BaseRevision + 1
	terminal.LastOperation = q.Original.OperationID
	terminal.CompletedApply = nil
	terminal.CompletedRepair = &nativeCompletion{Request: copyRepairRequest(q), Binding: n.Binding, ResultRevision: terminal.Revision, Retained: n.Retained}
	pBytes, e := json.Marshal(metadataCopy(v))
	if e != nil {
		t.Fatal(e)
	}
	tBytes, e := json.Marshal(metadataCopy(terminal))
	if e != nil {
		t.Fatal(e)
	}
	bareMax := len(pBytes)
	if len(tBytes) > bareMax {
		bareMax = len(tBytes)
	}
	maximal := v
	maximal.Processes = maxStoragePins(o.Profile, q.Target, v.BootID)
	if len(maximal.Processes) != 1 || validateRecord(o.Profile, maximal) != nil {
		t.Fatal("denied front prospective identity invalid")
	}
	withPin, e := json.Marshal(metadataCopy(maximal))
	if e != nil || len(withPin) <= bareMax+1 {
		t.Fatal("one-front near-bound fixture ineffective", e)
	}
	if !errors.Is(repairMetadataCapacityLimit(o.Profile, v, q, n, bareMax+1), ErrLimit) {
		t.Fatal("dead original Apply denial budget ignored future front pin")
	}
	if e = repairMetadataCapacity(o.Profile, v, q, n); e != nil {
		t.Fatal("normal denial capacity rejected", e)
	}
}
