package hostaccounts

import (
	"context"
	"strings"
	"testing"
)

// Plan metadata is reserved package information: it flows from CreateInput
// to the stored account, defaults to "default", and is bounds-checked.
func TestCreatePlanMetadata(t *testing.T) {
	s, _, _ := setupStore(t)
	ctx := context.Background()
	withPlan, err := s.create(ctx, CreateInput{Username: "planacct", Domain: "plan.test", Plan: "gold", Reason: "plan metadata"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if withPlan.Plan != "gold" {
		t.Fatalf("plan = %q", withPlan.Plan)
	}
	without, err := s.create(ctx, CreateInput{Username: "plainacct", Domain: "plain.test", Reason: "plan default"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if without.Plan != "default" {
		t.Fatalf("default plan = %q", without.Plan)
	}
	if _, err = s.create(ctx, CreateInput{Username: "bigplan", Domain: "bigplan.test", Plan: strings.Repeat("p", 65), Reason: "oversize plan"}, "test operator"); err != ErrInvalid {
		t.Fatalf("oversize plan err = %v", err)
	}
	// Plan survives store reload.
	items, err := s.list(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, a := range items {
		seen[a.Username] = a.Plan
	}
	if seen["planacct"] != "gold" || seen["plainacct"] != "default" {
		t.Fatalf("listed plans = %v", seen)
	}
}
