package hostaccounts

import (
	"context"
	"errors"
	"net/http/httptest"
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

// A delete stopped right after it moved the home into the trash has that
// on its record, and the next start finishes it; a delete that ends records
// the move too, and wakes the trash remover.
func TestDeleteStoppedAfterTheMoveFinishesAtStart(t *testing.T) {
	captureRecoveryLog(t)
	s, f, opts := setupStore(t)
	ctx := context.Background()
	woken := 0
	s.trashWake = func() { woken++ }
	a := createFixture(t, s)
	f.failure = "after-move"
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); err != ErrRecovery {
		t.Fatal(err)
	}
	if r := recordFor(t, s, a.ID); !r.UserRemoval || !r.HomeInTrash || r.Pending == nil {
		t.Fatalf("the move is not on the record: %+v", r)
	}
	if len(f.trashed) != 1 || woken != 0 {
		t.Fatalf("trashed %v, woken %d", f.trashed, woken)
	}
	s.close()
	f.failure = ""
	reopened, err := openStore(ctx, opts, f)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if items, err := reopened.records(); err != nil || len(items) != 0 {
		t.Fatalf("after the start: %+v %v", items, err)
	}
	if rows := historyOf(t, reopened, a.ID); rows[len(rows)-1].Status != "reconciled" {
		t.Fatalf("journal %+v", rows)
	}
	b, err := reopened.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Next"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	reopened.trashWake = func() { woken++ }
	if _, err := reopened.delete(ctx, b.ID, DeleteInput{ExpectedRevision: b.Revision, Reason: "Remove"}, "test operator"); err != nil || woken != 1 {
		t.Fatalf("a delete that ends: %v, woken %d", err, woken)
	}
}

// A delete no start can finish holds up every account until the operator
// finishes it: refused with its reason, nothing removed or journaled, while
// something is not provably the account's; then its user and drop-in go,
// one row ends it, and every account changes again.
func TestFinishDeleteUnblocksEveryAccount(t *testing.T) {
	logged := captureRecoveryLog(t)
	s, f, opts := setupStore(t)
	ctx := context.Background()
	woken := 0
	s.trashWake = func() { woken++ }
	other := createFixture(t, s)
	a, err := s.create(ctx, CreateInput{Username: "delacct", Domain: "del.test", Reason: "fixture"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	f.failure = "delete-refused"
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); err != ErrRecovery {
		t.Fatalf("a refused delete: %v", err)
	}
	if !strings.Contains(logged.String(), `operation=delete account=`+a.ID+` user=delacct step="remove / home" error="refused: home"`) {
		t.Fatalf("the refusal was not logged: %q", logged.String())
	}
	if _, err := s.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Held up"}, "test operator"); err != ErrRecovery {
		t.Fatalf("another account changed while the delete was unfinished: %v", err)
	}
	sequence := func() uint64 { return recordFor(t, s, a.ID).HistorySequence }
	before := sequence()

	var refused *DeleteRefusedError
	if _, err := s.finishDelete(ctx, other.ID, FinishDeleteInput{"Not a delete"}, "root operator"); !errors.As(err, &refused) || refused.Reason != DeleteNoUnfinished {
		t.Fatalf("an active account was finished: %v", err)
	}
	if !strings.Contains(logged.String(), `operation=finish_delete account=`+other.ID+` user=fixtureacct step="check" error="refused: no_unfinished_delete"`) {
		t.Fatalf("the refusal was not logged: %q", logged.String())
	}
	if _, err := s.finishDelete(ctx, strings.Repeat("0", 32), FinishDeleteInput{"No such account"}, "root operator"); err != ErrNotFound {
		t.Fatal(err)
	}
	if _, err := s.finishDelete(ctx, a.ID, FinishDeleteInput{" "}, "root operator"); err != ErrInvalid {
		t.Fatal(err)
	}
	for failure, reason := range map[string]string{"delete-refused": DeleteHome, "busy": DeleteProcesses} {
		f.failure = failure
		if _, err := s.finishDelete(ctx, a.ID, FinishDeleteInput{"Try"}, "root operator"); !errors.As(err, &refused) || refused.Reason != reason {
			t.Fatalf("%s: %v", failure, err)
		}
		if _, ok := f.users["delacct"]; !ok || sequence() != before {
			t.Fatalf("%s: a refused finish removed or journaled something", failure)
		}
	}

	f.failure = ""
	done, err := s.finishDelete(ctx, a.ID, FinishDeleteInput{"Leftover of a delete"}, "root operator")
	if err != nil || done.ID != a.ID {
		t.Fatal(done, err)
	}
	if _, ok := f.users["delacct"]; ok {
		t.Fatal("the user is left")
	}
	if _, ok := f.dropIns[a.UID]; ok {
		t.Fatal("the slice drop-in is left")
	}
	if woken != 1 {
		t.Fatalf("the trash remover was woken %d times", woken)
	}
	rows := historyOf(t, s, a.ID)
	last := rows[len(rows)-1]
	if last.Status != "finished" || last.Action != "delete" || last.Actor != "root operator" || last.Reason != "Leftover of a delete" || last.OperationID != rows[len(rows)-3].OperationID || last.Sequence != before+1 {
		t.Fatalf("journal %+v", rows)
	}
	if _, err := s.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Free again"}, "test operator"); err != nil {
		t.Fatalf("the other account is still held up: %v", err)
	}
	s.close()
	reopened, err := openStore(ctx, opts, f)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if items, err := reopened.list(ctx); err != nil || len(items) != 1 || items[0].ID != other.ID {
		t.Fatal(items, err)
	}
}

// The broker answers a refused finish with its reason, which the client
// reads back as a *DeleteRefusedError.
func TestFinishDeleteRefusalIsAnswered(t *testing.T) {
	captureRecoveryLog(t)
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "http://unix/v1/accounts/"+a.ID+"/finish-delete", strings.NewReader(`{"input":{"reason":"Leftover"},"actor":"operator"}`))
	r.Header.Set("Content-Type", "application/json")
	handler(s).ServeHTTP(w, r)
	if w.Code != 409 || strings.TrimSpace(w.Body.String()) != `{"error":"delete_refused","reason":"no_unfinished_delete"}` {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, body := range []string{`{"input":{"reason":"x","expected_revision":1},"actor":"operator"}`, `{"input":{},"actor":"operator"}`} {
		w = httptest.NewRecorder()
		r = httptest.NewRequest("POST", "http://unix/v1/accounts/"+a.ID+"/finish-delete", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		handler(s).ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 422 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	var _ DeleteRecoveryService = NewClient("").(*client)
}

// Only a pending delete may carry the flag that lets a start skip the
// account's check: on any other record it is refused as damaged.
func TestUserRemovalOnlyOnAPendingDelete(t *testing.T) {
	captureRecoveryLog(t)
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	r := recordFor(t, s, a.ID)
	for name, flag := range map[string]func(*record){
		"user_removal":  func(r *record) { r.UserRemoval = true },
		"home_in_trash": func(r *record) { r.HomeInTrash = true },
	} {
		flagged := r
		flag(&flagged)
		if s.save(flagged) != nil {
			t.Fatal("fixture save")
		}
		if _, err := s.records(); err != ErrRecovery {
			t.Fatalf("a settled record with %s: %v", name, err)
		}
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
