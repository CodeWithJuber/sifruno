package accesspolicy

import (
	"bytes"
	"errors"
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, *bolt.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.db")
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s, db, path
}
func rawStore(t *testing.T, db *bolt.DB) []byte {
	t.Helper()
	var data []byte
	if err := db.View(func(tx *bolt.Tx) error { data = bytes.Clone(tx.Bucket(policyBucket).Get(snapshotKey)); return nil }); err != nil {
		t.Fatal(err)
	}
	return data
}
func TestStoreLifecycle(t *testing.T) {
	s, db, path := testStore(t)
	p, _, _ := fixture(t)
	if got, v, err := s.Load(); got != nil || v != (StoreVersion{}) || !errors.Is(err, ErrStore) {
		t.Fatal("uninitialized")
	}
	v, err := s.Initialize(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Initialize(p); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	loaded, actual, err := s.Load()
	if err != nil || actual != v {
		t.Fatal(err)
	}
	for _, id := range []ActorID{actor("admin"), actor("reseller-a"), actor("user-a"), {}} {
		for n := 0; n < 256; n++ {
			for _, r := range []Resource{ServerResource(), AccountResource(account(1)), AccountResource(account(2)), AccountResource(account(99)), {}} {
				if loaded.Authorize(id, Action(n), r) != p.Authorize(id, Action(n), r) {
					t.Fatal("matrix")
				}
			}
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err = NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	loaded, actual, err = s.Load()
	if err != nil || actual != v || !loaded.Authorize(actor("admin"), ListAccounts, ServerResource()) {
		t.Fatal("reopen")
	}
}
func TestStoreReplacement(t *testing.T) {
	s, db, _ := testStore(t)
	p, actors, accounts := fixture(t)
	v, _ := s.Initialize(p)
	other, _, _ := testStore(t)
	foreign, _ := other.Initialize(p)
	if _, err := s.Replace(foreign, p); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign")
	}
	original := rawStore(t, db)
	for _, bad := range []*Policy{nil, {}} {
		if got, err := s.Replace(v, bad); got != (StoreVersion{}) || !errors.Is(err, ErrInvalid) || !bytes.Equal(original, rawStore(t, db)) {
			t.Fatal("invalid replacement")
		}
	}
	accounts[0].Owner = actor("reseller-b")
	actors[1] = ActorBinding{Actor: actor("reseller-a"), Role: AccountUser, Assigned: account(2)}
	next, _ := NewPolicy(actors, accounts)
	v2, err := s.Replace(v, next)
	if err != nil || v2 == v {
		t.Fatal(err)
	}
	loaded, _, _ := s.Load()
	if loaded.Authorize(actor("reseller-a"), ReadAccount, AccountResource(account(1))) || !loaded.Authorize(actor("reseller-b"), SetAccountState, AccountResource(account(1))) {
		t.Fatal("ownership")
	}
	if _, err = s.Replace(v, p); !errors.Is(err, ErrConflict) {
		t.Fatal("stale")
	}
	v3, err := s.Replace(v2, p)
	if err != nil || v3 == v || v3 == v2 {
		t.Fatal("ABA")
	}
	if _, err = s.Replace(v, p); !errors.Is(err, ErrConflict) {
		t.Fatal("revived")
	}
}
func TestStoreCorruption(t *testing.T) {
	cases := map[string]func(*bolt.Bucket, []byte) error{
		"unknown": func(b *bolt.Bucket, d []byte) error {
			return b.Put(snapshotKey, append([]byte(`{"extra":1,`), d[1:]...))
		},
		"duplicate": func(b *bolt.Bucket, d []byte) error {
			return b.Put(snapshotKey, append([]byte(`{"schema":1,`), d[1:]...))
		},
		"case-alias": func(b *bolt.Bucket, d []byte) error {
			return b.Put(snapshotKey, bytes.Replace(d, []byte(`"schema"`), []byte(`"Schema"`), 1))
		},
		"schema": func(b *bolt.Bucket, d []byte) error {
			return b.Put(snapshotKey, bytes.Replace(d, []byte(`"schema":1`), []byte(`"schema":2`), 1))
		},
		"extra-record":  func(b *bolt.Bucket, d []byte) error { return b.Put([]byte("extra"), []byte("x")) },
		"nested-bucket": func(b *bolt.Bucket, d []byte) error { _, err := b.CreateBucket([]byte("extra")); return err },
		"oversize": func(b *bolt.Bucket, d []byte) error {
			return b.Put(snapshotKey, bytes.Repeat([]byte(" "), maxSnapshotBytes+1))
		},
		"malformed": func(b *bolt.Bucket, d []byte) error { return b.Put(snapshotKey, []byte("{")) },
		"empty":     func(b *bolt.Bucket, d []byte) error { return b.Delete(snapshotKey) },
		"bad-owner": func(b *bolt.Bucket, d []byte) error {
			return b.Put(snapshotKey, bytes.Replace(d, []byte(`"owner":"reseller-a"`), []byte(`"owner":"absent"`), 1))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, db, _ := testStore(t)
			p, _, _ := fixture(t)
			v, _ := s.Initialize(p)
			data := rawStore(t, db)
			if err := db.Update(func(tx *bolt.Tx) error { return mutate(tx.Bucket(policyBucket), data) }); err != nil {
				t.Fatal(err)
			}
			before := rawStore(t, db)
			if got, version, err := s.Load(); got != nil || version != (StoreVersion{}) || !errors.Is(err, ErrStore) {
				t.Fatal("corrupt load")
			}
			if got, err := s.Replace(v, p); got != (StoreVersion{}) || !errors.Is(err, ErrStore) {
				t.Fatal("corrupt replace")
			}
			if _, err := s.Initialize(p); !errors.Is(err, ErrConflict) {
				t.Fatal("repair")
			}
			if !bytes.Equal(before, rawStore(t, db)) {
				t.Fatal("changed corrupt record")
			}
		})
	}
}
func TestStoreUnavailable(t *testing.T) {
	p, _, _ := fixture(t)
	for _, s := range []*Store{nil, {}} {
		if _, _, err := s.Load(); !errors.Is(err, ErrStore) {
			t.Fatal(err)
		}
		if _, err := s.Initialize(p); !errors.Is(err, ErrStore) {
			t.Fatal(err)
		}
		if _, err := s.Replace(StoreVersion{}, p); !errors.Is(err, ErrStore) {
			t.Fatal(err)
		}
	}
	if s, err := NewStore(nil); s != nil || !errors.Is(err, ErrStore) {
		t.Fatal(err)
	}
	s, db, path := testStore(t)
	s.Initialize(p)
	db.NoSync = true
	if _, err := NewStore(db); !errors.Is(err, ErrStore) {
		t.Fatal("NoSync")
	}
	if _, _, err := s.Load(); !errors.Is(err, ErrStore) {
		t.Fatal("NoSync load")
	}
	db.NoSync = false
	db.NoGrowSync = true
	if _, err := s.Replace(StoreVersion{}, p); !errors.Is(err, ErrStore) {
		t.Fatal("NoGrowSync")
	}
	db.NoGrowSync = false
	db.Close()
	if _, _, err := s.Load(); !errors.Is(err, ErrStore) {
		t.Fatal("closed")
	}
	if _, err := NewStore(db); !errors.Is(err, ErrStore) {
		t.Fatal("closed constructor")
	}
	ro, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := NewStore(ro); !errors.Is(err, ErrStore) {
		t.Fatal("readonly")
	}
}
func TestStoreOverflowAndIsolation(t *testing.T) {
	s, db, _ := testStore(t)
	p, _, _ := fixture(t)
	v, _ := s.Initialize(p)
	max := StoreVersion{v.repository, ^uint64(0)}
	data, _ := encodeSnapshot(p, max)
	if err := db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket([]byte("unrelated"))
		if e != nil {
			return e
		}
		if e = b.Put([]byte("keep"), []byte("unchanged")); e != nil {
			return e
		}
		return tx.Bucket(policyBucket).Put(snapshotKey, data)
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Replace(max, p); got != (StoreVersion{}) || !errors.Is(err, ErrExhausted) || !bytes.Equal(data, rawStore(t, db)) {
		t.Fatal("overflow")
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if !bytes.Equal(tx.Bucket([]byte("unrelated")).Get([]byte("keep")), []byte("unchanged")) {
			t.Fatal("unrelated change")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestStoreConcurrentCAS(t *testing.T) {
	s, _, _ := testStore(t)
	p, _, _ := fixture(t)
	v, _ := s.Initialize(p)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := s.Replace(v, p); err == nil {
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
