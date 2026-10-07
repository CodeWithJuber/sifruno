package storereview_test

import (
	"bytes"
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	p "sifruno/internal/accesspolicy"
	"sync"
	"testing"
)

func bindings(t *testing.T, owned bool) *p.Policy {
	t.Helper()
	a, _ := p.ParseActorID("reseller")
	b, _ := p.ParseActorID("admin")
	id, _ := p.ParseAccountID("0123456789abcdef0123456789abcdef")
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
func open(t *testing.T) (*bolt.DB, string) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "review.db")
	db, e := bolt.Open(name, 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return db, name
}
func store(t *testing.T, db *bolt.DB) *p.Store {
	t.Helper()
	s, e := p.NewStore(db)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func allowed(t *testing.T, v *p.Policy) bool {
	t.Helper()
	a, _ := p.ParseActorID("reseller")
	id, _ := p.ParseAccountID("0123456789abcdef0123456789abcdef")
	return v.Authorize(a, p.SetAccountState, p.AccountResource(id))
}
func TestReviewDurableReopenAndForeignVersion(t *testing.T) {
	db, name := open(t)
	s := store(t, db)
	r, e := s.Initialize(bindings(t, true))
	if e != nil {
		t.Fatal(e)
	}
	next, e := s.Replace(r, bindings(t, false))
	if e != nil {
		t.Fatal(e)
	}
	if next == r {
		t.Fatal("revision did not advance")
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = bolt.Open(name, 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s = store(t, db)
	v, loaded, e := s.Load()
	if e != nil || loaded != next || allowed(t, v) {
		t.Fatal("durable replacement not recovered")
	}
	if _, e = s.Replace(r, bindings(t, true)); e == nil {
		t.Fatal("stale reopened token accepted")
	}
	other, _ := open(t)
	foreign, e := store(t, other).Initialize(bindings(t, true))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Replace(foreign, bindings(t, true)); e == nil {
		t.Fatal("foreign persisted token accepted")
	}
}
func TestReviewConcurrentCASAndABA(t *testing.T) {
	db, _ := open(t)
	s := store(t, db)
	r, e := s.Initialize(bindings(t, true))
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	results := make(chan bool, 16)
	var wg sync.WaitGroup
	v := bindings(t, false)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, e := s.Replace(r, v); results <- e == nil }()
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for yes := range results {
		if yes {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("winners=%d", wins)
	}
	v, current, e := s.Load()
	if e != nil || allowed(t, v) {
		t.Fatal("owner transfer lost")
	}
	last, e := s.Replace(current, bindings(t, true))
	if e != nil || last == r {
		t.Fatal("ABA version revived")
	}
	if _, e = s.Replace(r, bindings(t, false)); e == nil {
		t.Fatal("ABA old version accepted")
	}
}
func snapshot(t *testing.T, db *bolt.DB) []byte {
	t.Helper()
	var data []byte
	e := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("accesspolicy-v1"))
		return b.ForEach(func(k, v []byte) error {
			data = append(data, k...)
			data = append(data, 0)
			data = append(data, v...)
			data = append(data, 0)
			return nil
		})
	})
	if e != nil {
		t.Fatal(e)
	}
	return data
}
func TestReviewUnknownRecordRefusesWithoutRepair(t *testing.T) {
	db, _ := open(t)
	s := store(t, db)
	r, e := s.Initialize(bindings(t, true))
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("accesspolicy-v1")).Put([]byte("unexpected"), []byte("untrusted"))
	})
	if e != nil {
		t.Fatal(e)
	}
	before := snapshot(t, db)
	if v, _, e := s.Load(); e == nil || v != nil {
		t.Fatal("unknown record admitted")
	}
	if _, e := s.Replace(r, bindings(t, false)); e == nil {
		t.Fatal("corrupt store replaced")
	}
	if !bytes.Equal(before, snapshot(t, db)) {
		t.Fatal("refusal repaired or changed records")
	}
}
func TestReviewUnrelatedBucketAndHandleRefusals(t *testing.T) {
	db, name := open(t)
	e := db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket([]byte("unrelated"))
		if e != nil {
			return e
		}
		return b.Put([]byte("sentinel"), []byte("preserve"))
	})
	if e != nil {
		t.Fatal(e)
	}
	s := store(t, db)
	if _, _, e := s.Load(); e == nil {
		t.Fatal("missing snapshot admitted")
	}
	if _, e = s.Initialize(bindings(t, true)); e != nil {
		t.Fatal(e)
	}
	e = db.View(func(tx *bolt.Tx) error {
		if !bytes.Equal(tx.Bucket([]byte("unrelated")).Get([]byte("sentinel")), []byte("preserve")) {
			t.Fatal("unrelated bucket changed")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.NewStore(nil); e == nil {
		t.Fatal("nil DB admitted")
	}
	db.Close()
	if _, _, e = s.Load(); e == nil {
		t.Fatal("closed DB admitted")
	}
	ro, e := bolt.Open(name, 0600, &bolt.Options{ReadOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	if _, e = p.NewStore(ro); e == nil {
		t.Fatal("readonly handle admitted")
	}
}
