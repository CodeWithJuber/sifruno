package accesspolicy

import (
	"bytes"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestStoreInventoryRolesAndOwnership(t *testing.T) {
	s, _, _ := testStore(t)
	p, _, _ := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name string
		want []AccountID
	}{
		{"admin", []AccountID{account(1), account(2), account(3)}},
		{"reseller-a", []AccountID{account(1)}},
		{"reseller-b", []AccountID{account(2)}},
		{"user-a", []AccountID{account(1)}},
		{"user-b", []AccountID{account(2)}},
	} {
		t.Run(row.name, func(t *testing.T) {
			first, err := s.VisibleAccountsAt(v, actor(row.name))
			if err != nil || !reflect.DeepEqual(first, row.want) || cap(first) != len(first) {
				t.Fatalf("got %v, %v; want %v", first, err, row.want)
			}
			second, err := s.VisibleAccountsAt(v, actor(row.name))
			if err != nil {
				t.Fatal(err)
			}
			first[0] = account(99)
			if !reflect.DeepEqual(second, row.want) {
				t.Fatal("results share mutable storage")
			}
			third, err := s.VisibleAccountsAt(v, actor(row.name))
			if err != nil || !reflect.DeepEqual(third, row.want) {
				t.Fatal("caller mutation changed inventory", third, err)
			}
			loaded, current, err := s.Load()
			if err != nil || current != v || !loaded.Authorize(actor(row.name), ReadAccount, AccountResource(row.want[0])) || loaded.Authorize(actor(row.name), ReadAccount, AccountResource(account(99))) {
				t.Fatal("caller mutation changed policy", err)
			}
			if row.name != "admin" && loaded.Authorize(actor(row.name), ListAccounts, ServerResource()) {
				t.Fatal("inventory broadened ListAccounts")
			}
		})
	}
}

func TestStoreInventoryEmptyAndDenied(t *testing.T) {
	s, _, _ := testStore(t)
	p, actors, accounts := fixture(t)
	actors = append(actors, ActorBinding{Actor: actor("empty-reseller"), Role: Reseller})
	p, err := NewPolicy(actors, accounts)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.VisibleAccountsAt(v, actor("empty-reseller")); got == nil || len(got) != 0 || cap(got) != 0 || err != nil {
		t.Fatal("registered actor empty result", got, err)
	}
	for _, id := range []ActorID{{}, actor("unknown")} {
		if got, err := s.VisibleAccountsAt(v, id); got != nil || !errors.Is(err, ErrDenied) {
			t.Fatal("unknown actor", got, err)
		}
	}
	empty, err := NewPolicy([]ActorBinding{{Actor: actor("admin"), Role: ServerAdmin}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err = s.Replace(v, empty)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.VisibleAccountsAt(v, actor("admin")); got == nil || len(got) != 0 || cap(got) != 0 || err != nil {
		t.Fatal("empty repository", got, err)
	}
}

func TestStoreInventoryCapacityAndOrder(t *testing.T) {
	s, _, _ := testStore(t)
	actors := []ActorBinding{{Actor: actor("admin"), Role: ServerAdmin}, {Actor: actor("reseller"), Role: Reseller}}
	accounts := make([]AccountBinding, 0, MaxAccounts)
	want := make([]AccountID, 0, MaxAccounts)
	for n := MaxAccounts; n > 0; n-- {
		accounts = append(accounts, AccountBinding{Account: account(n), Owner: actor("reseller")})
	}
	for n := 1; n <= MaxAccounts; n++ {
		want = append(want, account(n))
	}
	p, err := NewPolicy(actors, accounts)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []ActorID{actor("admin"), actor("reseller")} {
		if got, err := s.VisibleAccountsAt(v, id); err != nil || !reflect.DeepEqual(got, want) || cap(got) != len(got) {
			t.Fatal("capacity/order", got, err)
		}
	}
}

func TestStoreInventoryReassignmentRevocationAndReopen(t *testing.T) {
	s, db, path := testStore(t)
	p, actors, accounts := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	accounts[0].Owner = actor("reseller-b")
	reassigned, err := NewPolicy(actors, accounts)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.Replace(v, reassigned)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.VisibleAccountsAt(v, actor("reseller-a")); got != nil || !errors.Is(err, ErrConflict) {
		t.Fatal("stale ownership", got, err)
	}
	if got, err := s.VisibleAccountsAt(v2, actor("reseller-a")); got == nil || len(got) != 0 || err != nil {
		t.Fatal("former owner", got, err)
	}
	if got, err := s.VisibleAccountsAt(v2, actor("reseller-b")); err != nil || !reflect.DeepEqual(got, []AccountID{account(1), account(2)}) {
		t.Fatal("new owner", got, err)
	}
	// A user's explicit assignment survives an ownership change.
	if got, err := s.VisibleAccountsAt(v2, actor("user-a")); err != nil || !reflect.DeepEqual(got, []AccountID{account(1)}) {
		t.Fatal("assigned user", got, err)
	}
	revoked, err := NewPolicy([]ActorBinding{{Actor: actor("admin"), Role: ServerAdmin}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v3, err := s.Replace(v2, revoked)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.VisibleAccountsAt(v3, actor("user-a")); got != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("revoked actor", got, err)
	}
	v4, err := s.Replace(v3, p)
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
	for _, old := range []StoreVersion{v, v2, v3} {
		if got, err := s.VisibleAccountsAt(old, actor("unknown")); got != nil || !errors.Is(err, ErrConflict) {
			t.Fatal("ABA/reopen precedence", got, err)
		}
	}
	if got, err := s.VisibleAccountsAt(v4, actor("user-a")); err != nil || !reflect.DeepEqual(got, []AccountID{account(1)}) {
		t.Fatal("current regrant", got, err)
	}
}

func TestStoreInventoryRefusalPrecedenceAndNoRepair(t *testing.T) {
	for _, s := range []*Store{nil, {}} {
		if got, err := s.VisibleAccountsAt(StoreVersion{}, ActorID{}); got != nil || !errors.Is(err, ErrStore) {
			t.Fatal("unavailable", got, err)
		}
	}
	s, db, _ := testStore(t)
	if got, err := s.VisibleAccountsAt(StoreVersion{}, ActorID{}); got != nil || !errors.Is(err, ErrStore) {
		t.Fatal("missing storage precedence", got, err)
	}
	p, _, _ := fixture(t)
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
		if got, err := s.VisibleAccountsAt(bad, ActorID{}); got != nil || !errors.Is(err, ErrConflict) {
			t.Fatal("version precedence", got, err)
		}
	}
	for _, option := range []*bool{&db.NoSync, &db.NoGrowSync} {
		*option = true
		got, err := s.VisibleAccountsAt(StoreVersion{}, ActorID{})
		*option = false
		if got != nil || !errors.Is(err, ErrStore) {
			t.Fatal("unsafe handle precedence", got, err)
		}
	}
	corrupt := []byte(`{"schema":99}`)
	if err = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(policyBucket).Put(snapshotKey, corrupt) }); err != nil {
		t.Fatal(err)
	}
	for _, version := range []StoreVersion{v, {}, foreignVersion} {
		if got, err := s.VisibleAccountsAt(version, actor("unknown")); got != nil || !errors.Is(err, ErrStore) {
			t.Fatal("corruption precedence", got, err)
		}
	}
	if !bytes.Equal(rawStore(t, db), corrupt) {
		t.Fatal("inventory repaired corruption")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := s.VisibleAccountsAt(v, actor("admin")); got != nil || !errors.Is(err, ErrStore) {
		t.Fatal("closed", got, err)
	}
}

func TestStoreInventoryConcurrentReplacement(t *testing.T) {
	s, _, _ := testStore(t)
	p, actors, accounts := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	accounts[0].Owner, accounts[1].Owner = actor("reseller-b"), actor("reseller-a")
	next, err := NewPolicy(actors, accounts)
	if err != nil {
		t.Fatal(err)
	}
	start, committed := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 32; j++ {
				got, err := s.VisibleAccountsAt(v, actor("reseller-a"))
				if !((err == nil && reflect.DeepEqual(got, []AccountID{account(1)})) || (got == nil && errors.Is(err, ErrConflict))) {
					t.Errorf("mixed snapshot: %v %v", got, err)
				}
			}
			<-committed
			if got, err := s.VisibleAccountsAt(v, actor("reseller-a")); got != nil || !errors.Is(err, ErrConflict) {
				t.Errorf("postcommit stale inventory: %v %v", got, err)
			}
		}()
	}
	close(start)
	v2, err := s.Replace(v, next)
	close(committed)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.VisibleAccountsAt(v2, actor("reseller-a")); err != nil || !reflect.DeepEqual(got, []AccountID{account(2)}) {
		t.Fatal("committed ownership", got, err)
	}
}
