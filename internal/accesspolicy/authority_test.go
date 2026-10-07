package accesspolicy

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAuthorityMatrix(t *testing.T) {
	p, actors, _ := fixture(t)
	a, err := NewAuthority(p)
	if err != nil {
		t.Fatal(err)
	}
	r := a.Revision()
	for _, id := range append(actors, ActorBinding{Actor: actor("unknown")}, ActorBinding{}) {
		for n := 0; n <= 255; n++ {
			for _, resource := range []Resource{{}, ServerResource(), AccountResource(account(1)), AccountResource(account(2)), AccountResource(account(3)), AccountResource(account(99))} {
				if a.AuthorizeAt(r, id.Actor, Action(n), resource) != p.Authorize(id.Actor, Action(n), resource) {
					t.Fatal("matrix changed")
				}
			}
		}
	}
	if got := testing.AllocsPerRun(100, func() { a.AuthorizeAt(r, actor("admin"), ReadCapability, ServerResource()) }); got != 0 {
		t.Fatalf("allocations: %v", got)
	}
}

func TestAuthorityReplacement(t *testing.T) {
	p, actors, accounts := fixture(t)
	a, _ := NewAuthority(p)
	original := a.Revision()
	// Reassign ownership and reduce the former owner's permissions.
	accounts[0].Owner = actor("reseller-b")
	actors[1] = ActorBinding{Actor: actor("reseller-a"), Role: AccountUser, Assigned: account(2)}
	next, err := NewPolicy(actors, accounts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.Replace(original, next)
	if err != nil || r == original {
		t.Fatalf("replace: %v", err)
	}
	if a.AuthorizeAt(original, actor("admin"), ReadCapability, ServerResource()) || a.AuthorizeAt(r, actor("reseller-a"), ReadAccount, AccountResource(account(1))) || !a.AuthorizeAt(r, actor("reseller-b"), SetAccountState, AccountResource(account(1))) {
		t.Fatal("stale or reassigned permission")
	}
	if _, err := a.Replace(original, p); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	// Removing then restoring an actor cannot revive a prior token.
	removed, _ := NewPolicy([]ActorBinding{{Actor: actor("admin"), Role: ServerAdmin}}, nil)
	r2, err := a.Replace(r, removed)
	if err != nil {
		t.Fatal(err)
	}
	r3, err := a.Replace(r2, p)
	if err != nil || r3 == original || r3 == r || r3 == r2 {
		t.Fatal("ABA")
	}
	if a.AuthorizeAt(original, actor("user-a"), ReadAccount, AccountResource(account(1))) || !a.AuthorizeAt(r3, actor("user-a"), ReadAccount, AccountResource(account(1))) {
		t.Fatal("restored permissions")
	}
}

func TestAuthorityForeignAndCopiedHandles(t *testing.T) {
	p, _, _ := fixture(t)
	a, _ := NewAuthority(p)
	b, _ := NewAuthority(p)
	r := a.Revision()
	if r == b.Revision() || b.AuthorizeAt(r, actor("admin"), ReadCapability, ServerResource()) {
		t.Fatal("foreign token admitted")
	}
	if _, err := b.Replace(r, p); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	copy := *a
	r2, err := copy.Replace(r, p)
	if err != nil || a.Revision() != r2 || a.AuthorizeAt(r, actor("admin"), ReadCapability, ServerResource()) {
		t.Fatal("copied handle diverged")
	}
}

func TestAuthorityInvalidAndOverflow(t *testing.T) {
	p, _, _ := fixture(t)
	for _, a := range []*Authority{nil, {}} {
		if a.Revision() != (Revision{}) || a.AuthorizeAt(Revision{}, actor("admin"), ReadCapability, ServerResource()) {
			t.Fatal("uninitialized admitted")
		}
		if _, err := a.Replace(Revision{}, p); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	a, _ := NewAuthority(p)
	r := a.Revision()
	badKey := &Policy{actors: map[ActorID]ActorBinding{actor("wrong"): {Actor: actor("admin"), Role: ServerAdmin}}}
	badRole := &Policy{actors: map[ActorID]ActorBinding{actor("admin"): {Actor: actor("admin"), Role: 255}}}
	badOwner := &Policy{actors: p.actors, accounts: map[AccountID]ActorID{account(1): actor("absent")}}
	for _, invalid := range []*Policy{nil, {}, badKey, badRole, badOwner} {
		if got, err := NewAuthority(invalid); got != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid constructor accepted")
		}
		if got, err := a.Replace(r, invalid); got != (Revision{}) || !errors.Is(err, ErrInvalid) || a.Revision() != r {
			t.Fatal("invalid replacement changed state")
		}
	}
	if a.AuthorizeAt(Revision{}, actor("admin"), ReadCapability, ServerResource()) {
		t.Fatal("zero token")
	}
	a.state.revision = ^uint64(0)
	last := a.Revision()
	if got, err := a.Replace(last, p); got != (Revision{}) || !errors.Is(err, ErrExhausted) || a.Revision() != last || !a.AuthorizeAt(last, actor("admin"), ReadCapability, ServerResource()) {
		t.Fatal("overflow changed state")
	}
}

func TestAuthorityCopiesSnapshots(t *testing.T) {
	p, _, _ := fixture(t)
	a, _ := NewAuthority(p)
	delete(p.actors, actor("admin")) // Package-local adversarial mutation; no public mutator exists.
	if !a.AuthorizeAt(a.Revision(), actor("admin"), ReadCapability, ServerResource()) {
		t.Fatal("constructor retained map")
	}
	next, _, _ := fixture(t)
	r, err := a.Replace(a.Revision(), next)
	if err != nil {
		t.Fatal(err)
	}
	delete(next.accounts, account(1))
	if !a.AuthorizeAt(r, actor("user-a"), ReadAccount, AccountResource(account(1))) {
		t.Fatal("replacement retained map")
	}
}

func TestAuthorityConcurrentCAS(t *testing.T) {
	p, _, _ := fixture(t)
	a, _ := NewAuthority(p)
	removed, _ := NewPolicy([]ActorBinding{{Actor: actor("admin"), Role: ServerAdmin}}, nil)
	r := a.Revision()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				a.AuthorizeAt(r, actor("user-a"), ReadAccount, AccountResource(account(1)))
				a.Revision()
			}
			if _, err := a.Replace(r, removed); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 || a.AuthorizeAt(r, actor("user-a"), ReadAccount, AccountResource(account(1))) || a.AuthorizeAt(a.Revision(), actor("user-a"), ReadAccount, AccountResource(account(1))) {
		t.Fatal("CAS/revocation failed")
	}
}
