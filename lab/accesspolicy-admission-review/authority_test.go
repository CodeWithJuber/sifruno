package admissionreview_test

import (
	p "sifruno/internal/accesspolicy"
	"sync"
	"testing"
)

func ids(t *testing.T) (p.ActorID, p.ActorID, p.AccountID) {
	t.Helper()
	a, e := p.ParseActorID("reviewer")
	if e != nil {
		t.Fatal(e)
	}
	b, e := p.ParseActorID("keeper")
	if e != nil {
		t.Fatal(e)
	}
	id, e := p.ParseAccountID("0123456789abcdef0123456789abcdef")
	if e != nil {
		t.Fatal(e)
	}
	return a, b, id
}
func policy(t *testing.T, role p.Role, own bool) *p.Policy {
	t.Helper()
	a, b, id := ids(t)
	owner := b
	if own {
		owner = a
	}
	v, e := p.NewPolicy([]p.ActorBinding{{Actor: a, Role: role}, {Actor: b, Role: p.ServerAdmin}}, []p.AccountBinding{{Account: id, Owner: owner}})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func authority(t *testing.T, v *p.Policy) *p.Authority {
	t.Helper()
	a, e := p.NewAuthority(v)
	if e != nil {
		t.Fatal(e)
	}
	return a
}

func TestReviewReplacementRevokesRoleAndOwner(t *testing.T) {
	a, _, id := ids(t)
	r := p.AccountResource(id)
	auth := authority(t, policy(t, p.ServerAdmin, true))
	old := auth.Revision()
	if !auth.AuthorizeAt(old, a, p.CreateAccount, p.ServerResource()) {
		t.Fatal("initial admin denied")
	}
	alias := *auth
	next, e := alias.Replace(old, policy(t, p.Reseller, true))
	if e != nil {
		t.Fatal(e)
	}
	if auth.Revision() != next {
		t.Fatal("copied authority did not share revision")
	}
	if auth.AuthorizeAt(old, a, p.ReadAccount, r) || auth.AuthorizeAt(next, a, p.CreateAccount, p.ServerResource()) {
		t.Fatal("stale role grants survived")
	}
	if !auth.AuthorizeAt(next, a, p.SetAccountState, r) {
		t.Fatal("current owner denied")
	}
	last, e := auth.Replace(next, policy(t, p.Reseller, false))
	if e != nil {
		t.Fatal(e)
	}
	if auth.AuthorizeAt(last, a, p.SetAccountState, r) || auth.AuthorizeAt(next, a, p.SetAccountState, r) {
		t.Fatal("old ownership survived replacement")
	}
}
func TestReviewRevisionForeignAndABADenial(t *testing.T) {
	a, _, id := ids(t)
	v := policy(t, p.Reseller, true)
	x, y := authority(t, v), authority(t, v)
	old := x.Revision()
	foreign := y.Revision()
	if old == foreign || x.AuthorizeAt(foreign, a, p.ReadAccount, p.AccountResource(id)) {
		t.Fatal("foreign revision admitted")
	}
	middle, e := x.Replace(old, policy(t, p.Reseller, false))
	if e != nil {
		t.Fatal(e)
	}
	last, e := x.Replace(middle, v)
	if e != nil {
		t.Fatal(e)
	}
	if last == old || x.AuthorizeAt(old, a, p.ReadAccount, p.AccountResource(id)) {
		t.Fatal("ABA revived old revision")
	}
	if !x.AuthorizeAt(last, a, p.ReadAccount, p.AccountResource(id)) {
		t.Fatal("newly admitted owner denied")
	}
	if _, e = x.Replace(old, v); e == nil {
		t.Fatal("stale replacement accepted")
	}
}
func TestReviewConcurrentCASSingleWinner(t *testing.T) {
	auth := authority(t, policy(t, p.ServerAdmin, true))
	old := auth.Revision()
	start := make(chan struct{})
	results := make(chan bool, 16)
	var wg sync.WaitGroup
	next := policy(t, p.Reseller, false)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, e := auth.Replace(old, next); results <- e == nil }()
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for ok := range results {
		if ok {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("CAS winners=%d", wins)
	}
	a, _, id := ids(t)
	if auth.AuthorizeAt(old, a, p.ReadAccount, p.AccountResource(id)) {
		t.Fatal("stale admission after winner")
	}
}
func TestReviewZeroNilAndInvalidFailClosed(t *testing.T) {
	a, _, id := ids(t)
	var nilAuth *p.Authority
	var zero p.Authority
	var revision p.Revision
	for _, auth := range []*p.Authority{nilAuth, &zero} {
		if auth.AuthorizeAt(revision, a, p.ReadAccount, p.AccountResource(id)) {
			t.Fatal("uninitialized authority admitted")
		}
	}
	for _, v := range []*p.Policy{nil, new(p.Policy)} {
		if auth, e := p.NewAuthority(v); e == nil || auth != nil {
			t.Fatal("invalid initial policy accepted")
		}
	}
	auth := authority(t, policy(t, p.ServerAdmin, true))
	before := auth.Revision()
	for _, v := range []*p.Policy{nil, new(p.Policy)} {
		if _, e := auth.Replace(before, v); e == nil {
			t.Fatal("invalid replacement accepted")
		}
		if auth.Revision() != before {
			t.Fatal("invalid replacement changed revision")
		}
	}
	for _, action := range []p.Action{0, 255} {
		if auth.AuthorizeAt(before, a, action, p.ServerResource()) {
			t.Fatal("unknown action admitted")
		}
	}
	if auth.AuthorizeAt(revision, a, p.ReadAccount, p.AccountResource(id)) || auth.AuthorizeAt(before, a, p.ReadAccount, p.Resource{}) {
		t.Fatal("invalid revision/resource admitted")
	}
}
