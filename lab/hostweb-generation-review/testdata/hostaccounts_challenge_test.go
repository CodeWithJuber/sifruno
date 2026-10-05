package hostaccounts

import (
	"context"
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Injected through a Go overlay. Existing fakeNative is a journal test double,
// not shadow-utils, filesystem ownership, or daemon isolation evidence.
func TestReviewSnapshotCopiesAndLeaseExpiry(t *testing.T) {
	s, _, _ := setupStore(t)
	want := createFixture(t, s)
	p := s.SnapshotProvider()
	var retained SnapshotLease
	if err := p.WithSnapshot(context.Background(), func(lease SnapshotLease) error {
		retained = lease
		items := lease.Accounts()
		if len(items) != 1 || items[0] != want {
			t.Fatal("wrong admitted snapshot")
		}
		items[0].Home = "/caller-mutated"
		items[0].Revision = 900
		if lease.Accounts()[0] != want {
			t.Fatal("Accounts returned aliased state")
		}
		return lease.Verify(lease.Context())
	}); err != nil {
		t.Fatal(err)
	}
	if retained.Verify(context.Background()) == nil {
		t.Fatal("expired lease accepted verification outside reservation")
	}
	items, err := s.list(context.Background())
	if err != nil || len(items) != 1 || items[0] != want {
		t.Fatal("caller mutation changed broker record", err)
	}
}

func TestReviewSnapshotCancellationAndCallbackError(t *testing.T) {
	s, _, _ := setupStore(t)
	createFixture(t, s)
	p := s.SnapshotProvider()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := p.WithSnapshot(ctx, func(SnapshotLease) error { called = true; return nil }); err == nil || called {
		t.Fatal("canceled request admitted callback")
	}
	sentinel := errors.New("independent callback failure")
	if err := p.WithSnapshot(context.Background(), func(SnapshotLease) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal("callback error was replaced", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if err := p.WithSnapshot(ctx, func(lease SnapshotLease) error {
		cancel()
		return nil
	}); err == nil {
		t.Fatal("cancellation during callback reported success")
	}
	if err := p.WithSnapshot(context.Background(), func(lease SnapshotLease) error {
		if deadline, ok := lease.Context().Deadline(); !ok || time.Until(deadline) > time.Minute {
			t.Fatal("lease lacks bounded context")
		}
		return nil
	}); err != nil {
		t.Fatal("callback failure poisoned healthy broker", err)
	}
}

func TestReviewSnapshotScopedReentry(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	p := s.SnapshotProvider()
	if err := p.WithSnapshot(context.Background(), func(lease SnapshotLease) error {
		ctx := lease.Context()
		if _, err := s.list(ctx); err == nil {
			t.Fatal("reentrant list accepted")
		}
		if _, err := s.capability(ctx); err == nil {
			t.Fatal("reentrant capability accepted")
		}
		if _, err := s.create(ctx, CreateInput{"nestedacct", "nested.test", "Nested mutation"}, "review"); err == nil {
			t.Fatal("reentrant create accepted")
		}
		if _, err := s.setState(ctx, a.ID, StateInput{"suspended", a.Revision, "Nested mutation"}, "review"); err == nil {
			t.Fatal("reentrant state mutation accepted")
		}
		if err := p.WithSnapshot(ctx, func(SnapshotLease) error { t.Fatal("nested callback ran"); return nil }); err == nil {
			t.Fatal("reentrant reservation accepted")
		}
		return lease.Verify(ctx)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReviewSnapshotExcludesConcurrentBrokerMutation(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	reservationDone := make(chan error, 1)
	go func() {
		reservationDone <- s.SnapshotProvider().WithSnapshot(context.Background(), func(lease SnapshotLease) error {
			close(entered)
			<-release
			if lease.Accounts()[0].Revision != a.Revision {
				return errors.New("reservation changed")
			}
			return lease.Verify(lease.Context())
		})
	}()
	<-entered
	mutationDone := make(chan error, 1)
	go func() {
		_, err := s.setState(context.Background(), a.ID, StateInput{"suspended", a.Revision, "Concurrent snapshot challenge"}, "review")
		mutationDone <- err
	}()
	select {
	case err := <-mutationDone:
		close(release)
		<-reservationDone
		t.Fatal("mutation completed inside reservation", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-reservationDone; err != nil {
		t.Fatal(err)
	}
	if err := <-mutationDone; err != nil {
		t.Fatal(err)
	}
	items, err := s.list(context.Background())
	if err != nil || items[0].State != "suspended" || items[0].Revision != a.Revision+1 {
		t.Fatal("mutation lost", err)
	}
}

func TestReviewSnapshotPostCallbackNativeDriftQuarantines(t *testing.T) {
	s, native, _ := setupStore(t)
	createFixture(t, s)
	err := s.SnapshotProvider().WithSnapshot(context.Background(), func(lease SnapshotLease) error {
		native.changed = true
		return nil
	})
	if err == nil {
		t.Fatal("late native identity drift accepted")
	}
	items, err := s.list(context.Background())
	if err != nil || len(items) != 1 || items[0].State != "recovery_required" {
		t.Fatal("drift was not durable recovery state", err)
	}
	called := false
	if err = s.SnapshotProvider().WithSnapshot(context.Background(), func(SnapshotLease) error { called = true; return nil }); err == nil || called {
		t.Fatal("recovery state admitted subsequent callback")
	}
}

func TestReviewSnapshotPendingMutationRejected(t *testing.T) {
	s, native, _ := setupStore(t)
	a := createFixture(t, s)
	native.failure = "state-after"
	if _, err := s.setState(context.Background(), a.ID, StateInput{"suspended", a.Revision, "Interrupted state change"}, "review"); err == nil {
		t.Fatal("failure fixture did not leave pending state")
	}
	called := false
	if err := s.SnapshotProvider().WithSnapshot(context.Background(), func(SnapshotLease) error { called = true; return nil }); err == nil || called {
		t.Fatal("pending operation admitted callback")
	}
}

func TestReviewSnapshotRequiresDurableHistoryValidation(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(historyBucket).Delete(eventKey(a.ID, 2)) }); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := s.SnapshotProvider().WithSnapshot(context.Background(), func(SnapshotLease) error { called = true; return nil }); err == nil || called {
		t.Fatal("corrupt durable history admitted callback without Status polling")
	}
}

type reviewCancelNative struct {
	*fakeNative
	block           bool
	sawCancellation bool
}

func (n *reviewCancelNative) Verify(ctx context.Context, r record) error {
	if n.block {
		<-ctx.Done()
		n.sawCancellation = true
		return ErrUnavailable
	}
	return n.fakeNative.Verify(ctx, r)
}

func TestReviewSnapshotVerifyHonorsShorterCallerCancellation(t *testing.T) {
	s, native, _ := setupStore(t)
	createFixture(t, s)
	blocking := &reviewCancelNative{fakeNative: native}
	s.native = blocking
	if err := s.SnapshotProvider().WithSnapshot(context.Background(), func(lease SnapshotLease) error {
		blocking.block = true
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		err := lease.Verify(ctx)
		blocking.block = false
		if !blocking.sawCancellation || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("explicit caller deadline was lost in native verification", err)
		}
		return nil
	}); err != nil {
		t.Fatal("canceled explicit verification poisoned healthy reservation", err)
	}
}
