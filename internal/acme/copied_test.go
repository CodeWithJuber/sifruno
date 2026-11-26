package acme

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// A certificate copied from the old server when the site moved here is
// recorded as such. It is left alone while more than 30 days are left; then
// it is replaced with one from the certificate authority, but only once the
// domain points here: until then nothing is ordered (an order would fail
// validation and count against the authority's limits), the loop looks
// again within the hour, and says so once.
func TestCopiedCertificateIsReplacedOnceTheDomainPointsHere(t *testing.T) {
	f := newManagerFixture(t)
	ctx := context.Background()
	id := strings.Repeat("7", 32)
	until := f.now.Add(60 * 24 * time.Hour).Truncate(time.Second)
	f.m.Copied(id, "moved.example", until)
	if got, ok := f.m.CopiedUntil(id); !ok || !got.Equal(until) {
		t.Fatalf("copied until %v %v", got, ok)
	}
	// The record is on disk: the next start knows it too.
	again, err := NewManager(f.issuer, f.installer, f.sites, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := again.CopiedUntil(id); !ok || !got.Equal(until) {
		t.Fatalf("after a restart: %v %v", got, ok)
	}
	f.issuer.unreachable = map[string]bool{"moved.example": true}
	f.sites.sites = []Site{{AccountID: id, Domain: "moved.example", Revision: 5, Active: true, Live: true, NotAfter: until,
		Covered: []string{"mail.moved.example", "moved.example", "www.moved.example"}}}

	f.m.check(ctx)
	if len(f.issuer.domains) != 0 || len(f.installer.calls) != 0 {
		t.Fatalf("60 days left: ordered %q", f.issuer.domains)
	}

	f.now = until.Add(-20 * 24 * time.Hour)
	f.log.Reset()
	for range 2 {
		if wait := f.m.check(ctx); wait != firstLookEvery {
			t.Fatalf("next check in %v", wait)
		}
		f.now = f.now.Add(firstLookEvery)
	}
	if len(f.issuer.domains) != 0 || len(f.installer.calls) != 0 {
		t.Fatalf("ordered %q while the domain points elsewhere", f.issuer.domains)
	}
	want := "acme: moved.example (account " + id + "): the certificate copied from the old server runs out on " + until.UTC().Format(time.DateOnly) + "; the domain does not reach this server on port 80 yet, so the panel looks again every hour and asks for a new certificate once it does"
	if got := f.lines(); !slices.Equal(got, []string{want}) {
		t.Fatalf("log %q", got)
	}
	if _, ok := f.m.CopiedUntil(id); !ok {
		t.Fatal("the copied certificate is no longer recorded")
	}

	// The DNS now points here: the authority's certificate replaces it.
	f.issuer.unreachable = nil
	f.m.check(ctx)
	if !slices.Equal(f.issuer.domains, []string{"moved.example"}) || len(f.installer.calls) != 1 {
		t.Fatalf("ordered %q, installed %q", f.issuer.domains, f.installer.calls)
	}
	if r, ok := f.m.records.get(id); !ok || r.LastResult != "installed" || !r.NotAfter.Equal(f.installer.notAfter) {
		t.Fatalf("record %+v %v", r, ok)
	}
	if _, ok := f.m.CopiedUntil(id); ok {
		t.Fatal("still said to be copied after the replacement")
	}
}

// A failed order for a copied certificate keeps it recorded as copied, as
// it is still the one installed, with the loop's usual backoff.
func TestCopiedCertificateStaysRecordedAfterAFailedOrder(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("8", 32)
	until := f.now.Add(10 * 24 * time.Hour).Truncate(time.Second)
	f.m.Copied(id, "moved.example", until)
	f.sites.sites = []Site{{AccountID: id, Domain: "moved.example", Revision: 5, Active: true, Live: true, NotAfter: until}}
	f.issuer.err = ErrRateLimited
	if wait := f.m.check(context.Background()); wait != retryEvery {
		t.Fatalf("next check in %v", wait)
	}
	if got, ok := f.m.CopiedUntil(id); !ok || !got.Equal(until) {
		t.Fatalf("copied until %v %v", got, ok)
	}
	// Another domain on the account is another site: its record is not
	// the copied one's.
	f.m.Copied(id, "other.example", until)
	f.sites.sites[0].Domain = "renamed.example"
	f.m.check(context.Background())
	if _, ok := f.m.CopiedUntil(id); ok {
		t.Fatal("a record for a domain the account no longer has is kept")
	}
}
