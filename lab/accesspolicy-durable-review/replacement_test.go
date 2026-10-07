package durablereview_test

import (
	"bytes"
	"errors"
	bolt "go.etcd.io/bbolt"
	p "sifruno/internal/accesspolicy"
	"sync"
	"testing"
)

func promoted(t *testing.T) *p.Policy {
	t.Helper()
	a, b, id := ids()
	v, e := p.NewPolicy([]p.ActorBinding{{Actor: a, Role: p.ServerAdmin}, {Actor: b, Role: p.ServerAdmin}}, []p.AccountBinding{{Account: id, Owner: a}})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func demoted(t *testing.T) *p.Policy {
	t.Helper()
	a, b, id := ids()
	v, e := p.NewPolicy([]p.ActorBinding{{Actor: a, Role: p.Reseller}, {Actor: b, Role: p.Reseller}}, []p.AccountBinding{{Account: id, Owner: a}})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func record(t *testing.T, db *bolt.DB) []byte {
	t.Helper()
	var out []byte
	if e := db.View(func(tx *bolt.Tx) error {
		out = append(out, tx.Bucket([]byte("accesspolicy-v1")).Get([]byte("snapshot"))...)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	return out
}
func TestReviewCandidateCannotGrantUpdateAuthority(t *testing.T) {
	db, s, v, _ := setup(t)
	a, _, id := ids()
	unknown, _ := p.ParseActorID("unknown")
	before := record(t, db)
	for _, actor := range []p.ActorID{a, unknown, {}} {
		if got, e := s.ReplaceAuthorized(v, actor, promoted(t)); got != (p.StoreVersion{}) || !errors.Is(e, p.ErrDenied) {
			t.Fatal("candidate privilege escalation admitted")
		}
	}
	if !bytes.Equal(before, record(t, db)) {
		t.Fatal("denied update modified record")
	}
	if ok, e := s.AuthorizeAt(v, a, p.ManagePolicy, p.AccountResource(id)); ok || e != nil {
		t.Fatal("account scoped manage admitted")
	}
}
func TestReviewAdminDemotionAndTrustedReplace(t *testing.T) {
	_, s, v, _ := setup(t)
	_, admin, id := ids()
	current, e := s.ReplaceAuthorized(v, admin, demoted(t))
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := s.AuthorizeAt(current, admin, p.ManagePolicy, p.ServerResource()); ok || e != nil {
		t.Fatal("demoted actor still manages")
	}
	if _, e = s.ReplaceAuthorized(current, admin, promoted(t)); !errors.Is(e, p.ErrDenied) {
		t.Fatal("demoted actor could restore privilege")
	}
	if ok, e := s.AuthorizeAt(current, admin, p.ManagePolicy, p.AccountResource(id)); ok || e != nil {
		t.Fatal("wrong scope admitted")
	}
	if _, e = s.Replace(current, promoted(t)); e != nil {
		t.Fatal("trusted replacement changed")
	}
}
func TestReviewReplacementRefusalsPreserveRecord(t *testing.T) {
	for _, kind := range []string{"stale", "invalid", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			db, s, v, _ := setup(t)
			_, admin, _ := ids()
			next := policy(t, false)
			expected := v
			want := p.ErrConflict
			switch kind {
			case "stale":
				if _, e := s.Replace(v, policy(t, true)); e != nil {
					t.Fatal(e)
				}
			case "invalid":
				next = new(p.Policy)
				want = p.ErrInvalid
			case "corrupt":
				want = p.ErrStore
				if e := db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte("accesspolicy-v1")).Put([]byte("snapshot"), []byte("broken"))
				}); e != nil {
					t.Fatal(e)
				}
			}
			before := record(t, db)
			got, e := s.ReplaceAuthorized(expected, admin, next)
			if got != (p.StoreVersion{}) || !errors.Is(e, want) {
				t.Fatal("refusal misclassified or returned token")
			}
			if !bytes.Equal(before, record(t, db)) {
				t.Fatal("refusal changed persisted record")
			}
		})
	}
}
func TestReviewConcurrentRevocationAndUpdateSingleWinner(t *testing.T) {
	_, s, v, _ := setup(t)
	_, admin, _ := ids()
	candidates := []*p.Policy{demoted(t), promoted(t)}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, next := range candidates {
		wg.Add(1)
		go func(next *p.Policy) {
			defer wg.Done()
			<-start
			_, e := s.ReplaceAuthorized(v, admin, next)
			results <- e
		}(next)
	}
	close(start)
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for e := range results {
		if e == nil {
			wins++
		} else if errors.Is(e, p.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("same-token writers not single winner")
	}
	if _, e := s.ReplaceAuthorized(v, admin, promoted(t)); !errors.Is(e, p.ErrConflict) {
		t.Fatal("consumed token reused")
	}
}
