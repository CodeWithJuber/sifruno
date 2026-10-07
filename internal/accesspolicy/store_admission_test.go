package accesspolicy

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestStoreAdmissionMatrix(t *testing.T) {
	s, _, _ := testStore(t)
	p, actors, _ := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range append(actors, ActorBinding{Actor: actor("unknown")}, ActorBinding{}) {
		for n := 0; n < 256; n++ {
			for _, r := range []Resource{{}, ServerResource(), AccountResource(account(1)), AccountResource(account(2)), AccountResource(account(3)), AccountResource(account(99)), {kind: 255}} {
				got, err := s.AuthorizeAt(v, a.Actor, Action(n), r)
				if err != nil || got != p.Authorize(a.Actor, Action(n), r) {
					t.Fatalf("actor=%s action=%d resource=%v got=%v err=%v", a.Actor, n, r, got, err)
				}
			}
		}
	}
}

func TestStoreAdmissionRevocationAndReopen(t *testing.T) {
	s, db, path := testStore(t)
	p, _, _ := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := NewPolicy([]ActorBinding{{Actor: actor("admin"), Role: ServerAdmin}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := other.Replace(v, revoked)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrapper := range []*Store{s, other} {
		if ok, err := wrapper.AuthorizeAt(v, actor("user-a"), ReadAccount, AccountResource(account(1))); ok || !errors.Is(err, ErrConflict) {
			t.Fatal("old version survived revocation", err)
		}
		if ok, err := wrapper.AuthorizeAt(v2, actor("user-a"), ReadAccount, AccountResource(account(1))); ok || err != nil {
			t.Fatal("revoked actor", err)
		}
	}
	v3, err := s.Replace(v2, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s, err = NewStore(reopened)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range []StoreVersion{v, v2} {
		if ok, err := s.AuthorizeAt(old, actor("user-a"), ReadAccount, AccountResource(account(1))); ok || !errors.Is(err, ErrConflict) {
			t.Fatal("ABA/reopen", err)
		}
	}
	if ok, err := s.AuthorizeAt(v3, actor("user-a"), ReadAccount, AccountResource(account(1))); !ok || err != nil {
		t.Fatal("current regrant", err)
	}
}

func TestStoreAdmissionInvalidState(t *testing.T) {
	p, _, _ := fixture(t)
	for _, s := range []*Store{nil, {}} {
		if ok, err := s.AuthorizeAt(StoreVersion{}, ActorID{}, Action(0), Resource{}); ok || !errors.Is(err, ErrStore) {
			t.Fatal("uninitialized", err)
		}
	}
	s, db, _ := testStore(t)
	if ok, err := s.AuthorizeAt(StoreVersion{}, actor("admin"), ListAccounts, ServerResource()); ok || !errors.Is(err, ErrStore) {
		t.Fatal("missing", err)
	}
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, _ := testStore(t)
	foreignVersion, err := foreign.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []StoreVersion{{}, foreignVersion} {
		if ok, err := s.AuthorizeAt(bad, actor("admin"), ListAccounts, ServerResource()); ok || !errors.Is(err, ErrConflict) {
			t.Fatal("version", err)
		}
	}
	corrupt := []byte(`{"schema":99}`)
	if err = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(policyBucket).Put(snapshotKey, corrupt) }); err != nil {
		t.Fatal(err)
	}
	for _, version := range []StoreVersion{v, {}} {
		if ok, err := s.AuthorizeAt(version, actor("admin"), ListAccounts, ServerResource()); ok || !errors.Is(err, ErrStore) {
			t.Fatal("corruption precedence", err)
		}
	}
	if !bytes.Equal(rawStore(t, db), corrupt) {
		t.Fatal("admission repaired corruption")
	}
	db.Close()
	if ok, err := s.AuthorizeAt(v, actor("admin"), ListAccounts, ServerResource()); ok || !errors.Is(err, ErrStore) {
		t.Fatal("closed", err)
	}
}

func TestStoreAdmissionConcurrentReplacement(t *testing.T) {
	s, db, _ := testStore(t)
	p, _, _ := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := NewPolicy([]ActorBinding{{Actor: actor("admin"), Role: ServerAdmin}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	committed := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 32; j++ {
				ok, err := s.AuthorizeAt(v, actor("user-a"), ReadAccount, AccountResource(account(1)))
				if !((ok && err == nil) || (!ok && errors.Is(err, ErrConflict))) {
					t.Errorf("mixed snapshot: %v %v", ok, err)
				}
			}
			<-committed
			if ok, err := s.AuthorizeAt(v, actor("user-a"), ReadAccount, AccountResource(account(1))); ok || !errors.Is(err, ErrConflict) {
				t.Errorf("postcommit stale grant: %v %v", ok, err)
			}
		}()
	}
	close(start)
	if _, err = writer.Replace(v, revoked); err != nil {
		t.Fatal(err)
	}
	close(committed)
	wg.Wait()
}
