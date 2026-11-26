package acme

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// A live site the panel never tried, such as one made before certificates
// were set up or one moved from another server, gets its first certificate
// from the renewal loop once its domain answers here.
func TestRenewalCheckAsksAFirstCertificateForALiveSite(t *testing.T) {
	f := newManagerFixture(t)
	live, idle, suspended := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	f.issuer.unreachable = map[string]bool{"nodns.example": true}
	f.sites.sites = []Site{
		{AccountID: live, Domain: "old.example", Aliases: []string{"www.old.example", "nodns.example"}, Revision: 4, Active: true, Live: true},
		// Active, but its site is not served (no PHP): the broker would
		// refuse the certificate, so nothing is asked.
		{AccountID: idle, Domain: "idle.example", Revision: 5, Active: true},
		{AccountID: suspended, Domain: "suspended.example", Revision: 6},
	}
	f.m.check(context.Background())
	if !slices.Equal(f.issuer.domains, []string{"old.example,www.old.example"}) {
		t.Fatalf("issued for %q", f.issuer.domains)
	}
	if !slices.Equal(f.installer.calls, []string{live + " rev=4 chain old.example,www.old.example"}) {
		t.Fatalf("installed %q", f.installer.calls)
	}
	// The site's own domain is probed before anything is asked for.
	if !slices.Contains(f.issuer.probes, "old.example") || slices.Contains(f.issuer.probes, "idle.example") || slices.Contains(f.issuer.probes, "suspended.example") {
		t.Fatalf("probes %q", f.issuer.probes)
	}
	// Recorded as the wizard's attempts are, so the Domains tab shows it.
	r, ok := f.m.records.get(live)
	if !ok || r.Domain != "old.example" || r.LastResult != "installed" || !r.NotAfter.Equal(f.installer.notAfter) || !slices.Equal(r.Waiting, []string{"nodns.example"}) {
		t.Fatalf("record %+v %v", r, ok)
	}
	if !slices.Equal(f.m.Waiting(live), []string{"nodns.example"}) {
		t.Fatalf("waiting %q", f.m.Waiting(live))
	}
	for _, id := range []string{idle, suspended} {
		if _, ok := f.m.records.get(id); ok {
			t.Errorf("account %s recorded", id)
		}
	}
}

// A live site whose domain does not point here yet (a moved site before
// its DNS changes) is not ordered for, not recorded, logged once, and
// looked at again within the hour; once its DNS points here it is ordered.
func TestFirstCertificateWaitsForTheDomainToPointHere(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("4", 32)
	f.issuer.unreachable = map[string]bool{"moved.example": true}
	f.sites.sites = []Site{{AccountID: id, Domain: "moved.example", Revision: 3, Active: true, Live: true}}
	for range 2 {
		if wait := f.m.check(context.Background()); wait != firstLookEvery {
			t.Fatalf("next check in %v", wait)
		}
		f.now = f.now.Add(firstLookEvery)
	}
	if len(f.issuer.domains) != 0 || len(f.installer.calls) != 0 {
		t.Fatalf("ordered %q, installed %q", f.issuer.domains, f.installer.calls)
	}
	if _, ok := f.m.records.get(id); ok {
		t.Fatal("a site that does not point here was recorded")
	}
	want := "acme: moved.example (account " + id + "): no certificate yet: the domain does not reach this server on port 80, usually because its DNS points elsewhere; the panel looks again every hour and asks for one once it does"
	if got := f.lines(); !slices.Equal(got, []string{want}) {
		t.Fatalf("log %q", got)
	}

	// The DNS now points here.
	f.issuer.unreachable = nil
	f.log.Reset()
	if wait := f.m.check(context.Background()); wait != checkEvery {
		t.Fatalf("next check in %v", wait)
	}
	if !slices.Equal(f.issuer.domains, []string{"moved.example"}) || len(f.installer.calls) != 1 {
		t.Fatalf("ordered %q, installed %q", f.issuer.domains, f.installer.calls)
	}
	if r, ok := f.m.records.get(id); !ok || r.LastResult != "installed" {
		t.Fatalf("record %+v %v", r, ok)
	}
}

// After an install on a server with many sites and no certificates, one
// check asks for firstOrders of them and comes back within the hour for the
// rest; sites tried before are not held back by the bound.
func TestFirstCertificatesAreBoundedPerCheck(t *testing.T) {
	f := newManagerFixture(t)
	var ids []string
	for i := range firstOrders + 2 {
		id := fmt.Sprintf("%032x", i+1)
		ids = append(ids, id)
		f.sites.sites = append(f.sites.sites, Site{AccountID: id, Domain: fmt.Sprintf("site%d.example", i), Revision: 2, Active: true, Live: true})
	}
	// One site the panel tried before, with 10 days left: renewed as ever.
	known := strings.Repeat("e", 32)
	f.m.records.change(known, func(r *record) {
		r.Domain, r.NotAfter, r.LastAttempt = "known.example", f.now.Add(10*24*time.Hour), f.now.Add(-80*24*time.Hour)
	})
	f.sites.sites = append(f.sites.sites, Site{AccountID: known, Domain: "known.example", Revision: 9, Active: true, Live: true})

	if wait := f.m.check(context.Background()); wait != firstLookEvery {
		t.Fatalf("next check in %v", wait)
	}
	want := []string{"site0.example", "site1.example", "site2.example", "known.example"}
	if !slices.Equal(f.issuer.domains, want) {
		t.Fatalf("first check issued for %q", f.issuer.domains)
	}
	// The sites over the bound were not even probed.
	for _, domain := range []string{"site3.example", "site4.example"} {
		if slices.Contains(f.issuer.probes, domain) {
			t.Fatalf("%s probed: %q", domain, f.issuer.probes)
		}
	}

	f.now = f.now.Add(firstLookEvery)
	f.issuer.domains = nil
	if wait := f.m.check(context.Background()); wait != checkEvery {
		t.Fatalf("next check in %v", wait)
	}
	if !slices.Equal(f.issuer.domains, []string{"site3.example", "site4.example"}) {
		t.Fatalf("second check issued for %q", f.issuer.domains)
	}
	for _, id := range ids {
		if r, ok := f.m.records.get(id); !ok || r.LastResult != "installed" {
			t.Fatalf("%s: record %+v %v", id, r, ok)
		}
	}
}

// A first order that fails is recorded, and the site then waits the loop's
// 6 hours like any other failed attempt.
func TestFailedFirstCertificateKeepsTheBackoff(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("5", 32)
	f.sites.sites = []Site{{AccountID: id, Domain: "v6.example", Revision: 2, Active: true, Live: true}}
	f.issuer.err = ErrValidation
	if wait := f.m.check(context.Background()); wait != retryEvery {
		t.Fatalf("next check in %v", wait)
	}
	if r, ok := f.m.records.get(id); !ok || r.LastResult != ErrValidation.Error() || !r.LastAttempt.Equal(f.now) {
		t.Fatalf("record %+v %v", r, ok)
	}
	f.now = f.now.Add(retryEvery - time.Minute)
	f.m.check(context.Background())
	if len(f.issuer.domains) != 1 {
		t.Fatalf("asked again within 6 hours: %q", f.issuer.domains)
	}
	f.now = f.now.Add(time.Minute)
	f.issuer.err = nil
	f.m.check(context.Background())
	if !slices.Equal(f.issuer.domains, []string{"v6.example", "v6.example"}) {
		t.Fatalf("issued for %q", f.issuer.domains)
	}
}

// A site that someone else asked a certificate for while the check probed
// it (the wizard's https step, or a domain change) is not ordered again.
func TestFirstCertificateIsNotAskedTwice(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("6", 32)
	f.sites.sites = []Site{{AccountID: id, Domain: "new.example", Revision: 2, Active: true, Live: true}}
	f.issuer.onProbe = func(domain string) {
		if domain == "new.example" {
			f.m.records.attempt(id, domain, f.now)
			f.m.records.installed(id, f.now.Add(90*24*time.Hour))
		}
	}
	f.m.check(context.Background())
	if len(f.issuer.domains) != 0 {
		t.Fatalf("ordered %q", f.issuer.domains)
	}
}
