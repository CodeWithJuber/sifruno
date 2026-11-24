package wizard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
)

// A new website cannot take a domain another website serves as an alias.
func TestStartRefusesAnotherWebsitesAlias(t *testing.T) {
	f := newFixture(t)
	f.acc.accounts = append(f.acc.accounts, hostaccounts.Account{ID: strings.Repeat("a", 32), Username: "shopacct", Domain: "shop.example", State: "active", Revision: 3,
		SiteDomains: &hostaccounts.SiteDomainsSummary{Aliases: []string{"www.shop.example", "shop.example.net"}}})
	_, err := f.runner.Start(context.Background(), input("shop.example.net"), "local-operator")
	var refusal *Refusal
	if !errors.As(err, &refusal) || !errors.Is(err, ErrConflict) || refusal.Detail != "shop.example.net is already a domain of the website shop.example. Use another domain, or remove it from that website first." {
		t.Fatalf("alias of another website: %v", err)
	}
	if got := len(f.runner.List()); got != 0 {
		t.Fatalf("a refused start was recorded: %d jobs", got)
	}
}
