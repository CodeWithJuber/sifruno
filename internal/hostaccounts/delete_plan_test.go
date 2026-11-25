package hostaccounts

import (
	"context"
	"strings"
	"testing"
)

// Journaled delete: revision-gated, purges the record, retains history,
// idempotent-missing native handling via the fake.
func TestDeleteAccountLifecycle(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a, err := s.create(ctx, CreateInput{Username: "delacct", Domain: "del.test", Reason: "fixture"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	// Wrong revision refuses.
	if _, err = s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: 99, Reason: "race check"}, "test operator"); err != ErrConflict {
		t.Fatalf("stale revision err = %v", err)
	}
	// Unknown ID refuses.
	if _, err = s.delete(ctx, "00000000000000000000000000000000", DeleteInput{ExpectedRevision: 1, Reason: "x"}, "test operator"); err != ErrNotFound {
		t.Fatalf("missing err = %v", err)
	}
	gone, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "operator removal"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if gone.Username != "delacct" {
		t.Fatalf("returned %+v", gone)
	}
	if _, exists := f.users["delacct"]; exists {
		t.Fatal("native identity still present")
	}
	items, err := s.list(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.ID == a.ID {
			t.Fatal("record not purged")
		}
	}
	// Repeat delete: not found, no error propagation to a false success.
	if _, err = s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: 1, Reason: "again"}, "test operator"); err != ErrNotFound {
		t.Fatalf("repeat delete err = %v", err)
	}
}

// Metadata-only plan change: revision-gated, journaled, no native calls.
func TestSetPlanMetadata(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a, err := s.create(ctx, CreateInput{Username: "planacct2", Domain: "plan2.test", Plan: "silver", Reason: "fixture"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	callsBefore := f.calls
	if _, err = s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", ExpectedRevision: 99, Reason: "race"}, "test operator"); err != ErrConflict {
		t.Fatalf("stale revision err = %v", err)
	}
	next, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", ExpectedRevision: a.Revision, Reason: "upgrade"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if next.Plan != "gold" || next.Revision != a.Revision+1 {
		t.Fatalf("next = %+v", next)
	}
	if f.calls != callsBefore {
		t.Fatal("metadata plan change touched the native layer")
	}
	// Same plan is an idempotent no-op.
	same, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", ExpectedRevision: next.Revision, Reason: "again"}, "test operator")
	if err != nil || same.Revision != next.Revision {
		t.Fatalf("idempotent setPlan: %+v %v", same, err)
	}
}

// A delete stopped after userdel removed the user is finished by the next
// start from the journal: the flag saved before the removal began makes the
// start skip the check of an account whose user is gone, which held up
// every account before. The drop-in goes, the journal ends the delete and
// the record is removed, and the name and UID can be created again.
func TestDeleteStoppedAfterUserdelFinishesAtStart(t *testing.T) {
	captureRecoveryLog(t)
	s, f, opts := setupStore(t)
	ctx := context.Background()
	other := createFixture(t, s)
	a, err := s.create(ctx, CreateInput{Username: "delacct", Domain: "del.test", Reason: "fixture"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	f.failure = "after-userdel"
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); err != ErrRecovery {
		t.Fatalf("a delete stopped after userdel: %v", err)
	}
	if r := recordFor(t, s, a.ID); r.Pending == nil || r.Pending.Action != "delete" || !r.UserRemoval {
		t.Fatalf("the pending delete does not say its user's removal began: %+v", r)
	}
	if _, ok := f.users["delacct"]; ok {
		t.Fatal("fixture: userdel did not run")
	}
	if _, err := s.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Held up"}, "test operator"); err != ErrRecovery {
		t.Fatalf("another account changed while the delete was unfinished: %v", err)
	}
	s.close()
	f.failure = ""
	f.full = map[string]int{}
	reopened, err := openStore(ctx, opts, f)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if f.full["delacct"] != 0 {
		t.Fatal("the start verified an account whose user was already gone")
	}
	items, err := reopened.list(ctx)
	if err != nil || len(items) != 1 || items[0].ID != other.ID {
		t.Fatalf("after the start: %+v %v", items, err)
	}
	rows := historyOf(t, reopened, a.ID)
	if len(rows) != 5 || rows[2].Status != "intended" || rows[3].Status != "recovery_required" || rows[4].Status != "reconciled" || rows[4].Action != "delete" || rows[4].OperationID != rows[2].OperationID || rows[4].Actor != "test operator" || rows[4].Reason != "Remove" {
		t.Fatalf("journal %+v", rows)
	}
	if _, ok := f.dropIns[a.UID]; ok {
		t.Fatal("the deleted account's drop-in is left")
	}
	if _, err := reopened.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Free again"}, "test operator"); err != nil {
		t.Fatalf("the other account is still held up: %v", err)
	}
	if b, err := reopened.create(ctx, CreateInput{Username: "delacct", Domain: "del.test", Reason: "Free again"}, "test operator"); err != nil || b.UID != a.UID {
		t.Fatalf("the name and UID are not free again: %+v %v", b, err)
	}
}

// Only a pending delete may carry the flag that lets a start skip the
// account's check: on any other record it is refused as damaged.
func TestUserRemovalOnlyOnAPendingDelete(t *testing.T) {
	captureRecoveryLog(t)
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	r := recordFor(t, s, a.ID)
	r.UserRemoval = true
	if s.save(r) != nil {
		t.Fatal("fixture save")
	}
	if _, err := s.records(); err != ErrRecovery {
		t.Fatalf("a settled record with the flag: %v", err)
	}
}

// The delete's last row and the record's removal are one transaction that
// reads the stored record again: a record that changed since it was read is
// neither ended nor removed.
func TestDeleteEndChecksTheStoredRecord(t *testing.T) {
	captureRecoveryLog(t)
	s, f, _ := setupStore(t)
	a := createFixture(t, s)
	f.failure = "after-userdel"
	if _, err := s.delete(context.Background(), a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); err != ErrRecovery {
		t.Fatal(err)
	}
	r := recordFor(t, s, a.ID)
	rows := len(historyOf(t, s, a.ID))
	stale := r
	stale.Account.Plan = "changed"
	other := *r.Pending
	other.OperationID = strings.Repeat("0", 32)
	for name, end := range map[string]func() error{
		"another record":    func() error { return s.endDelete(stale, *r.Pending, "succeeded", "test operator", "Remove") },
		"another operation": func() error { return s.endDelete(r, other, "succeeded", "test operator", "Remove") },
	} {
		if end() == nil {
			t.Fatalf("%s: ended", name)
		}
		if recordFor(t, s, a.ID).Pending == nil || len(historyOf(t, s, a.ID)) != rows {
			t.Fatalf("%s: the record or the journal changed", name)
		}
	}
	if err := s.endDelete(r, *r.Pending, "succeeded", "test operator", "Remove"); err != nil {
		t.Fatal(err)
	}
	if items, err := s.records(); err != nil || len(items) != 0 {
		t.Fatalf("the record is left: %+v %v", items, err)
	}
	if got := historyOf(t, s, a.ID); len(got) != rows+1 || got[rows].Status != "succeeded" {
		t.Fatalf("journal %+v", got)
	}
}
