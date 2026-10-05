package hostaccountsreview

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
)

// An empty socket is deliberately unconfigured on every OS. These tests
// exercise real exported admission without network, utilities or OS accounts.
// ErrUnavailable for an admitted request means only that validation passed.
func TestCreateAdmissionBeforeBroker(t *testing.T) {
	service := hostaccounts.NewClient("")
	good := hostaccounts.CreateInput{Username: "review_user", Domain: "review.example", Reason: "independent admission check"}
	tests := []struct {
		name  string
		input hostaccounts.CreateInput
		actor string
	}{
		{"reserved-user", hostaccounts.CreateInput{Username: "root", Domain: good.Domain, Reason: good.Reason}, "reviewer"},
		{"path-user", hostaccounts.CreateInput{Username: "../review", Domain: good.Domain, Reason: good.Reason}, "reviewer"},
		{"option-user", hostaccounts.CreateInput{Username: "-review", Domain: good.Domain, Reason: good.Reason}, "reviewer"},
		{"non-ascii-user", hostaccounts.CreateInput{Username: "rev\u0456ew", Domain: good.Domain, Reason: good.Reason}, "reviewer"},
		{"long-user", hostaccounts.CreateInput{Username: strings.Repeat("r", 33), Domain: good.Domain, Reason: good.Reason}, "reviewer"},
		{"url-domain", hostaccounts.CreateInput{Username: good.Username, Domain: "https://review.example/path", Reason: good.Reason}, "reviewer"},
		{"ip-domain", hostaccounts.CreateInput{Username: good.Username, Domain: "127.0.0.1", Reason: good.Reason}, "reviewer"},
		{"empty-domain-label", hostaccounts.CreateInput{Username: good.Username, Domain: "review..example", Reason: good.Reason}, "reviewer"},
		{"domain-case", hostaccounts.CreateInput{Username: good.Username, Domain: "Review.example", Reason: good.Reason}, "reviewer"},
		{"long-domain-label", hostaccounts.CreateInput{Username: good.Username, Domain: strings.Repeat("r", 64) + ".example", Reason: good.Reason}, "reviewer"},
		{"reason-byte-overflow", hostaccounts.CreateInput{Username: good.Username, Domain: good.Domain, Reason: strings.Repeat("é", 251)}, "reviewer"},
		{"reason-control", hostaccounts.CreateInput{Username: good.Username, Domain: good.Domain, Reason: "review\nreason"}, "reviewer"},
		{"invalid-utf8-reason", hostaccounts.CreateInput{Username: good.Username, Domain: good.Domain, Reason: string([]byte{0xff})}, "reviewer"},
		{"actor-byte-overflow", good, strings.Repeat("é", 61)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account, err := service.Create(context.Background(), test.input, test.actor)
			if !errors.Is(err, hostaccounts.ErrInvalid) || account != (hostaccounts.Account{}) {
				t.Fatal("invalid request was not rejected before the unconfigured broker")
			}
		})
	}
	good.Reason = strings.Repeat("é", 250) // exact 500-byte upper bound
	if _, err := service.Create(context.Background(), good, strings.Repeat("é", 60)); !errors.Is(err, hostaccounts.ErrUnavailable) {
		t.Fatal("bounded valid request did not reach the explicitly unavailable broker")
	}
}

func TestStateAdmissionBeforeBroker(t *testing.T) {
	service := hostaccounts.NewClient("")
	id := strings.Repeat("a", 32)
	good := hostaccounts.StateInput{State: "suspended", ExpectedRevision: 1, Reason: "review state admission"}
	tests := []struct {
		name, id string
		input    hostaccounts.StateInput
	}{
		{"path-id", "../" + id, good},
		{"uppercase-id", strings.Repeat("A", 32), good},
		{"zero-revision", id, hostaccounts.StateInput{State: "active", ExpectedRevision: 0, Reason: good.Reason}},
		{"recovery-write", id, hostaccounts.StateInput{State: "recovery_required", ExpectedRevision: 1, Reason: good.Reason}},
		{"unknown-state", id, hostaccounts.StateInput{State: "deleted", ExpectedRevision: 1, Reason: good.Reason}},
		{"reason-overflow", id, hostaccounts.StateInput{State: "active", ExpectedRevision: 1, Reason: strings.Repeat("x", 501)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account, err := service.SetState(context.Background(), test.id, test.input, "reviewer")
			if !errors.Is(err, hostaccounts.ErrInvalid) || account != (hostaccounts.Account{}) {
				t.Fatal("invalid state request was not rejected before broker access")
			}
		})
	}
	if _, err := service.SetState(context.Background(), id, good, "reviewer"); !errors.Is(err, hostaccounts.ErrUnavailable) {
		t.Fatal("bounded state request did not reach the explicitly unavailable broker")
	}
}

func TestUnavailableBrokerIsExplicit(t *testing.T) {
	service := hostaccounts.NewClient("")
	capability, err := service.Capability(context.Background())
	if err != nil || capability.Available || capability.Backend != "unavailable" || len(capability.Restrictions) == 0 {
		t.Fatal("unconfigured broker was represented as available or restrictions were omitted")
	}
	if _, err := service.List(context.Background()); !errors.Is(err, hostaccounts.ErrUnavailable) {
		t.Fatal("unconfigured broker returned an account list")
	}
	if _, err := service.Capability(nil); !errors.Is(err, hostaccounts.ErrInvalid) {
		t.Fatal("nil context was not rejected")
	}
}
