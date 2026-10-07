package durablereview_test

import (
	"bytes"
	"errors"
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	p "sifruno/internal/accesspolicy"
	"sync"
	"testing"
)

func ids() (p.ActorID, p.ActorID, p.AccountID) {
	a, _ := p.ParseActorID("seller")
	b, _ := p.ParseActorID("admin")
	id, _ := p.ParseAccountID("0123456789abcdef0123456789abcdef")
	return a, b, id
}
func policy(t *testing.T, owned bool) *p.Policy {
	t.Helper()
	a, b, id := ids()
	owner := b
	if owned {
		owner = a
	}
	v, e := p.NewPolicy([]p.ActorBinding{{Actor: a, Role: p.Reseller}, {Actor: b, Role: p.ServerAdmin}}, []p.AccountBinding{{Account: id, Owner: owner}})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func setup(t *testing.T) (*bolt.DB, *p.Store, p.StoreVersion, string) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "policy.db")
	db, e := bolt.Open(name, 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	s, e := p.NewStore(db)
	if e != nil {
		t.Fatal(e)
	}
	v, e := s.Initialize(policy(t, true))
	if e != nil {
		t.Fatal(e)
	}
	return db, s, v, name
}
func TestReviewRevocationRegrantAndReopen(t *testing.T) {
	db, s, old, name := setup(t)
	a, _, id := ids()
	removed, e := s.Replace(old, policy(t, false))
	if e != nil {
		t.Fatal(e)
	}
	current, e := s.Replace(removed, policy(t, true))
	if e != nil {
		t.Fatal(e)
	}
	wrapped, e := p.NewStore(db)
	if e != nil {
		t.Fatal(e)
	}
	for _, store := range []*p.Store{s, wrapped} {
		if ok, e := store.AuthorizeAt(old, a, p.SetAccountState, p.AccountResource(id)); ok || !errors.Is(e, p.ErrConflict) {
			t.Fatal("old grant revived")
		}
		if ok, e := store.AuthorizeAt(current, a, p.SetAccountState, p.AccountResource(id)); !ok || e != nil {
			t.Fatal("current grant denied")
		}
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
	if ok, e := s.AuthorizeAt(old, a, p.ReadAccount, p.AccountResource(id)); ok || !errors.Is(e, p.ErrConflict) {
		t.Fatal("reopen revived stale token")
	}
	if ok, e := s.AuthorizeAt(current, a, p.ReadAccount, p.AccountResource(id)); !ok || e != nil {
		t.Fatal("reopen lost current token")
	}
}
func TestReviewDeniedMatrixDistinctFromConflict(t *testing.T) {
	_, s, v, _ := setup(t)
	a, b, id := ids()
	for _, action := range []p.Action{p.ListAccounts, p.CreateAccount, 0, 255} {
		if ok, e := s.AuthorizeAt(v, a, action, p.ServerResource()); ok || e != nil {
			t.Fatal("matrix denial misclassified")
		}
	}
	if ok, e := s.AuthorizeAt(v, b, p.ReadAccount, p.AccountResource(id)); !ok || e != nil {
		t.Fatal("admin read denied")
	}
	var zero p.StoreVersion
	if ok, e := s.AuthorizeAt(zero, a, p.ReadAccount, p.AccountResource(id)); ok || !errors.Is(e, p.ErrConflict) {
		t.Fatal("zero token misclassified")
	}
	_, other, foreign, _ := setup(t)
	_ = other
	if ok, e := s.AuthorizeAt(foreign, a, p.ReadAccount, p.AccountResource(id)); ok || !errors.Is(e, p.ErrConflict) {
		t.Fatal("foreign token admitted")
	}
}
func TestReviewCorruptionClosedNoRepair(t *testing.T) {
	db, s, v, _ := setup(t)
	a, _, id := ids()
	raw := []byte("invalid-json")
	e := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("accesspolicy-v1")).Put([]byte("snapshot"), raw) })
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := s.AuthorizeAt(v, a, p.ReadAccount, p.AccountResource(id)); ok || !errors.Is(e, p.ErrStore) {
		t.Fatal("corrupt grant or wrong error")
	}
	e = db.View(func(tx *bolt.Tx) error {
		if !bytes.Equal(tx.Bucket([]byte("accesspolicy-v1")).Get([]byte("snapshot")), raw) {
			t.Fatal("implicit repair")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	db.Close()
	if ok, e := s.AuthorizeAt(v, a, p.ReadAccount, p.AccountResource(id)); ok || !errors.Is(e, p.ErrStore) {
		t.Fatal("closed handle admitted")
	}
	var nilStore *p.Store
	if ok, e := nilStore.AuthorizeAt(v, a, p.ReadAccount, p.AccountResource(id)); ok || !errors.Is(e, p.ErrStore) {
		t.Fatal("nil store admitted")
	}
}
func TestReviewPostCommitConcurrentChecks(t *testing.T) {
	_, s, old, _ := setup(t)
	a, _, id := ids()
	current, e := s.Replace(old, policy(t, false))
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errs := make(chan string, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, e := s.AuthorizeAt(old, a, p.ReadAccount, p.AccountResource(id)); ok || !errors.Is(e, p.ErrConflict) {
				errs <- "stale"
			}
			if ok, e := s.AuthorizeAt(current, a, p.ReadAccount, p.AccountResource(id)); ok || e != nil {
				errs <- "revoked"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
