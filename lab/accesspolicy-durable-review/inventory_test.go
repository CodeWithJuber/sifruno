package durablereview_test

import (
	"bytes"
	"errors"
	bolt "go.etcd.io/bbolt"
	"reflect"
	p "sifruno/internal/accesspolicy"
	"sync"
	"testing"
)

func inventoryPolicy(t *testing.T, transfer bool) (*p.Policy, p.ActorID, p.ActorID, p.ActorID, []p.AccountID) {
	t.Helper()
	seller, admin, _ := ids()
	user, _ := p.ParseActorID("member")
	x, _ := p.ParseAccountID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	y, _ := p.ParseAccountID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	z, _ := p.ParseAccountID("cccccccccccccccccccccccccccccccc")
	owner := seller
	if transfer {
		owner = admin
	}
	v, e := p.NewPolicy([]p.ActorBinding{{Actor: seller, Role: p.Reseller}, {Actor: admin, Role: p.ServerAdmin}, {Actor: user, Role: p.AccountUser, Assigned: z}}, []p.AccountBinding{{Account: x, Owner: owner}, {Account: z, Owner: admin}, {Account: y, Owner: owner}})
	if e != nil {
		t.Fatal(e)
	}
	return v, seller, admin, user, []p.AccountID{y, x, z}
}
func TestReviewInventoryExactRolesOrderAndOwnedOutput(t *testing.T) {
	_, s, old, _ := setup(t)
	next, seller, admin, user, all := inventoryPolicy(t, false)
	v, e := s.Replace(old, next)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		actor p.ActorID
		want  []p.AccountID
	}{{admin, all}, {seller, all[:2]}, {user, all[2:]}} {
		got, e := s.VisibleAccountsAt(v, c.actor)
		if cap(got) != len(got) {
			t.Fatal("hidden inventory capacity exposed")
		}
		if e != nil || !reflect.DeepEqual(got, c.want) {
			t.Fatal("role inventory mismatch")
		}
		got[0] = p.AccountID{}
		again, e := s.VisibleAccountsAt(v, c.actor)
		if e != nil || !reflect.DeepEqual(again, c.want) {
			t.Fatal("output mutation escaped")
		}
	}
	if ok, e := s.AuthorizeAt(v, seller, p.ListAccounts, p.ServerResource()); ok || e != nil {
		t.Fatal("scoped listing broadened global action")
	}
}
func TestReviewInventoryTransferStaleAndEmpty(t *testing.T) {
	db, s, old, name := setup(t)
	next, seller, _, _, _ := inventoryPolicy(t, false)
	v, e := s.Replace(old, next)
	if e != nil {
		t.Fatal(e)
	}
	transferred, _, _, _, _ := inventoryPolicy(t, true)
	current, e := s.Replace(v, transferred)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := s.VisibleAccountsAt(v, seller); got != nil || !errors.Is(e, p.ErrConflict) {
		t.Fatal("stale enumeration returned IDs")
	}
	got, e := s.VisibleAccountsAt(current, seller)
	if e != nil || got == nil || len(got) != 0 {
		t.Fatal("empty ownership not nonnil empty")
	}
	db.Close()
	db, e = bolt.Open(name, 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s, e = p.NewStore(db)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := s.VisibleAccountsAt(v, seller); got != nil || !errors.Is(e, p.ErrConflict) {
		t.Fatal("reopen admitted stale inventory")
	}
	if got, e := s.VisibleAccountsAt(current, seller); e != nil || got == nil || len(got) != 0 {
		t.Fatal("reopen lost empty result")
	}
}
func TestReviewInventoryErrorsReturnNilAndPreserveState(t *testing.T) {
	db, s, v, _ := setup(t)
	seller, _, _ := ids()
	unknown, _ := p.ParseActorID("outsider")
	before := record(t, db)
	for _, actor := range []p.ActorID{unknown, {}} {
		if got, e := s.VisibleAccountsAt(v, actor); got != nil || !errors.Is(e, p.ErrDenied) {
			t.Fatal("unknown actor inventory leak")
		}
	}
	var zero p.StoreVersion
	if got, e := s.VisibleAccountsAt(zero, seller); got != nil || !errors.Is(e, p.ErrConflict) {
		t.Fatal("zero version misclassified")
	}
	_, _, foreign, _ := setup(t)
	if got, e := s.VisibleAccountsAt(foreign, seller); got != nil || !errors.Is(e, p.ErrConflict) {
		t.Fatal("foreign version admitted")
	}
	if !bytes.Equal(before, record(t, db)) {
		t.Fatal("denial changed state")
	}
	raw := []byte("corrupt")
	if e := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("accesspolicy-v1")).Put([]byte("snapshot"), raw) }); e != nil {
		t.Fatal(e)
	}
	if got, e := s.VisibleAccountsAt(zero, unknown); got != nil || !errors.Is(e, p.ErrStore) {
		t.Fatal("corruption must precede token/actor check")
	}
	if !bytes.Equal(raw, record(t, db)) {
		t.Fatal("implicit corruption repair")
	}
	db.Close()
	if got, e := s.VisibleAccountsAt(v, seller); got != nil || !errors.Is(e, p.ErrStore) {
		t.Fatal("closed store admitted")
	}
}
func TestReviewInventoryPostCommitCompleteOrConflict(t *testing.T) {
	_, s, old, _ := setup(t)
	next, seller, admin, _, all := inventoryPolicy(t, false)
	v, e := s.Replace(old, next)
	if e != nil {
		t.Fatal(e)
	}
	transferred, _, _, _, _ := inventoryPolicy(t, true)
	current, e := s.Replace(v, transferred)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errch := make(chan string, 48)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, e := s.VisibleAccountsAt(v, admin); got != nil || !errors.Is(e, p.ErrConflict) {
				errch <- "stale"
			}
			if got, e := s.VisibleAccountsAt(current, admin); e != nil || !reflect.DeepEqual(got, all) {
				errch <- "partial admin"
			}
			if got, e := s.VisibleAccountsAt(current, seller); e != nil || got == nil || len(got) != 0 {
				errch <- "revoked owner"
			}
		}()
	}
	wg.Wait()
	close(errch)
	for e := range errch {
		t.Error(e)
	}
}
