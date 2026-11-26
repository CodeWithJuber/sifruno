package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
)

// The renewal loop sees a site's aliases and what its certificate names,
// as the broker's account list reports them.
func TestCertificateSiteCarriesAliasesAndNames(t *testing.T) {
	id := strings.Repeat("a", 32)
	a := hostaccounts.Account{
		ID: id, Domain: "example.com", Revision: 6, State: "active",
		Certificate: hostaccounts.CertificateState{NotAfter: 1800000000, Fingerprint: strings.Repeat("ab", 32), Names: "example.com,www.example.com"},
		SiteDomains: &hostaccounts.SiteDomainsSummary{Aliases: []string{"shop.example.com", "www.example.com"}, Redirects: 2},
	}
	s := certificateSite(a)
	if s.AccountID != id || s.Domain != "example.com" || s.Revision != 6 || !s.Active || s.Live || !s.NotAfter.Equal(time.Unix(1800000000, 0)) {
		t.Fatalf("site %+v", s)
	}
	if !slices.Equal(s.Aliases, []string{"shop.example.com", "www.example.com"}) || !slices.Equal(s.Covered, []string{"example.com", "www.example.com"}) {
		t.Fatalf("aliases %q, covered %q", s.Aliases, s.Covered)
	}
	// A suspended account with no certificate and no aliases.
	bare := certificateSite(hostaccounts.Account{ID: id, Domain: "example.com", Revision: 2, State: "suspended"})
	if bare.Active || bare.Live || bare.Aliases != nil || bare.Covered != nil || !bare.NotAfter.IsZero() {
		t.Fatalf("bare site %+v", bare)
	}
}

// A site is live, so the renewal loop may ask its first certificate, only
// when the broker would install one: the account is active, its PHP is on
// and its site folder is as the broker recorded it.
func TestCertificateSiteIsLiveOnlyWhenTheBrokerTakesACertificate(t *testing.T) {
	live := hostaccounts.Account{ID: strings.Repeat("b", 32), Domain: "example.com", Revision: 3, State: "active", Web: hostaccounts.WebState{PHPVersion: "8.3", QuotaMiB: 1024}}
	if s := certificateSite(live); !s.Active || !s.Live {
		t.Fatalf("live site %+v", s)
	}
	for name, change := range map[string]func(*hostaccounts.Account){
		"suspended":      func(a *hostaccounts.Account) { a.State = "suspended" },
		"recovery":       func(a *hostaccounts.Account) { a.State = "recovery_required" },
		"no PHP":         func(a *hostaccounts.Account) { a.Web = hostaccounts.WebState{} },
		"folder changed": func(a *hostaccounts.Account) { a.SiteFolderChanged = true },
	} {
		a := live
		change(&a)
		if s := certificateSite(a); s.Live {
			t.Errorf("%s: live %+v", name, s)
		}
	}
}
