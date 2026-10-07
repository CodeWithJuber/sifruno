package accesspolicy

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestStoreAuthorizedUpdateRoles(t *testing.T) {
	for _, name := range []string{"reseller-a", "user-a", "unknown", ""} {
		t.Run(name, func(t *testing.T) {
			s, db, _ := testStore(t)
			p, _, _ := fixture(t)
			v, err := s.Initialize(p)
			if err != nil {
				t.Fatal(err)
			}
			id := ActorID{}
			if name != "" {
				id = actor(name)
			}
			promoted := p
			if name != "" {
				promoted, err = NewPolicy([]ActorBinding{{Actor: id, Role: ServerAdmin}}, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			before := rawStore(t, db)
			for _, candidate := range []*Policy{promoted, nil} {
				got, err := s.ReplaceAuthorized(v, id, candidate)
				if got != (StoreVersion{}) || !errors.Is(err, ErrDenied) || !bytes.Equal(before, rawStore(t, db)) {
					t.Fatal("unauthorized update", err)
				}
			}
		})
	}
	s, _, _ := testStore(t)
	p, _, _ := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	// Self-demotion is valid, but the demoted actor cannot restore itself.
	demoted, err := NewPolicy([]ActorBinding{{Actor: actor("admin"), Role: Reseller}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.ReplaceAuthorized(v, actor("admin"), demoted)
	if err != nil || next == v {
		t.Fatal("admin update", err)
	}
	if got, err := s.ReplaceAuthorized(next, actor("admin"), p); got != (StoreVersion{}) || !errors.Is(err, ErrDenied) {
		t.Fatal("self promotion", err)
	}
	// The separate trusted recovery API deliberately keeps its original behavior.
	if _, err := s.Replace(next, p); err != nil {
		t.Fatal("trusted recovery", err)
	}
}

func TestStoreAuthorizedUpdateRefusals(t *testing.T) {
	s, db, _ := testStore(t)
	p, _, _ := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := testStore(t)
	foreign, err := other.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	before := rawStore(t, db)
	for _, bad := range []StoreVersion{{}, foreign} {
		got, err := s.ReplaceAuthorized(bad, actor("unknown"), nil)
		if got != (StoreVersion{}) || !errors.Is(err, ErrConflict) || !bytes.Equal(before, rawStore(t, db)) {
			t.Fatal("version precedence", err)
		}
	}
	if got, err := s.ReplaceAuthorized(v, actor("admin"), nil); got != (StoreVersion{}) || !errors.Is(err, ErrInvalid) || !bytes.Equal(before, rawStore(t, db)) {
		t.Fatal("invalid", err)
	}
	current, err := s.ReplaceAuthorized(v, actor("admin"), p)
	if err != nil {
		t.Fatal(err)
	}
	before = rawStore(t, db)
	if got, err := s.ReplaceAuthorized(v, actor("admin"), p); got != (StoreVersion{}) || !errors.Is(err, ErrConflict) || !bytes.Equal(before, rawStore(t, db)) {
		t.Fatal("stale", err)
	}
	max := StoreVersion{current.repository, ^uint64(0)}
	data, err := encodeSnapshot(p, max)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(policyBucket).Put(snapshotKey, data) }); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ReplaceAuthorized(max, actor("user-a"), p); got != (StoreVersion{}) || !errors.Is(err, ErrDenied) {
		t.Fatal("denial before overflow", err)
	}
	if got, err := s.ReplaceAuthorized(max, actor("admin"), nil); got != (StoreVersion{}) || !errors.Is(err, ErrExhausted) || !bytes.Equal(data, rawStore(t, db)) {
		t.Fatal("overflow", err)
	}
}

func TestStoreAuthorizedUpdateUnavailable(t *testing.T) {
	for _, s := range []*Store{nil, {}} {
		if got, err := s.ReplaceAuthorized(StoreVersion{}, ActorID{}, nil); got != (StoreVersion{}) || !errors.Is(err, ErrStore) {
			t.Fatal(err)
		}
	}
	s, db, _ := testStore(t)
	p, _, _ := fixture(t)
	if _, err := s.ReplaceAuthorized(StoreVersion{}, actor("admin"), p); !errors.Is(err, ErrStore) {
		t.Fatal("missing", err)
	}
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"schema":99}`)
	if err = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(policyBucket).Put(snapshotKey, data) }); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ReplaceAuthorized(StoreVersion{}, ActorID{}, nil); got != (StoreVersion{}) || !errors.Is(err, ErrStore) || !bytes.Equal(data, rawStore(t, db)) {
		t.Fatal("corruption precedence", err)
	}
	db.Close()
	if got, err := s.ReplaceAuthorized(v, actor("admin"), p); got != (StoreVersion{}) || !errors.Is(err, ErrStore) {
		t.Fatal("closed", err)
	}
}

func TestStoreAuthorizedUpdateConcurrent(t *testing.T) {
	s, _, _ := testStore(t)
	p, _, _ := fixture(t)
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := s.ReplaceAuthorized(v, actor("admin"), p); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal(winners.Load())
	}
}
