package hostaccounts

import (
	"context"
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
