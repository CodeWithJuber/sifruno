package hostaccounts

import (
	"context"
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// These isolated journal tests use the existing typed native seam; they do not
// qualify real Linux shadow-utils, root ownership or web activation.
func TestSnapshotReservesConcurrentCreateAndSetState(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	guardDone, createDone, stateDone := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() {
		guardDone <- s.SnapshotProvider().WithSnapshot(context.Background(), func(l SnapshotLease) error {
			close(entered)
			<-release
			if got := l.Accounts(); len(got) != 1 || got[0] != a {
				return errors.New("reserved inventory changed")
			}
			return l.Verify(l.Context())
		})
	}()
	<-entered
	started := make(chan struct{}, 2)
	go func() {
		started <- struct{}{}
		_, err := s.create(context.Background(), CreateInput{"secondacct", "second.test", "Concurrent create"}, "test operator")
		createDone <- err
	}()
	go func() {
		started <- struct{}{}
		_, err := s.setState(context.Background(), a.ID, StateInput{"suspended", a.Revision, "Concurrent state"}, "test operator")
		stateDone <- err
	}()
	<-started
	<-started
	select {
	case err := <-createDone:
		close(release)
		t.Fatalf("create escaped reservation: %v", err)
	case err := <-stateDone:
		close(release)
		t.Fatalf("state escaped reservation: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	close(release)
	for _, done := range []chan error{guardDone, createDone, stateDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("reservation was not released")
		}
	}
	items, err := s.list(context.Background())
	if err != nil || len(items) != 2 {
		t.Fatal(items, err)
	}
	for _, item := range items {
		if item.ID == a.ID && (item.Revision != 2 || item.State != "suspended") {
			t.Fatal(item)
		}
	}
}

func TestSnapshotCopiesAndExpires(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	var captured SnapshotLease
	err := s.WithSnapshot(context.Background(), func(l SnapshotLease) error {
		captured = l
		deadline, ok := l.Context().Deadline()
		if !ok || time.Until(deadline) > MaxSnapshotDuration {
			t.Fatal("missing bounded context")
		}
		items := l.Accounts()
		items[0].Username, items[0].UID, items[0].Revision = "changed", 9, 99
		if got := l.Accounts(); got[0] != a {
			t.Fatal("snapshot alias", got)
		}
		return l.Verify(context.Background())
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.Accounts() != nil || !errors.Is(captured.Verify(context.Background()), ErrConflict) || !errors.Is(captured.Context().Err(), context.Canceled) {
		t.Fatal("lease did not expire")
	}
	items, err := s.list(context.Background())
	if err != nil || len(items) != 1 || items[0] != a {
		t.Fatal("persisted state changed", items, err)
	}
}

func TestSnapshotScopedReentryFailsFast(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	err := s.WithSnapshot(context.Background(), func(l SnapshotLease) error {
		ctx, cancel := context.WithCancel(l.Context())
		defer cancel()
		_, createErr := s.create(ctx, CreateInput{"secondacct", "second.test", "Reentry"}, "test operator")
		_, stateErr := s.setState(ctx, a.ID, StateInput{"suspended", 1, "Reentry"}, "test operator")
		_, listErr := s.list(ctx)
		_, capabilityErr := s.capability(ctx)
		nestedErr := s.WithSnapshot(ctx, func(SnapshotLease) error { t.Fatal("nested callback"); return nil })
		for _, got := range []error{createErr, stateErr, listErr, capabilityErr, nestedErr} {
			if !errors.Is(got, ErrConflict) {
				t.Fatal("reentry not rejected", got)
			}
		}
		return l.Verify(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotNativeDriftClosesAndJournalsRecovery(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "postcallback"
		if explicit {
			name = "explicit"
		}
		t.Run(name, func(t *testing.T) {
			s, native, _ := setupStore(t)
			a := createFixture(t, s)
			err := s.WithSnapshot(context.Background(), func(l SnapshotLease) error {
				native.changed = true // external native identity edit; no persisted record edit
				if explicit && !errors.Is(l.Verify(l.Context()), ErrRecovery) {
					t.Fatal("drift was accepted")
				}
				return nil // forgetting Verify must not permit success either
			})
			if !errors.Is(err, ErrRecovery) {
				t.Fatal(err)
			}
			items, err := s.list(context.Background())
			if err != nil || len(items) != 1 || items[0].State != "recovery_required" {
				t.Fatal(items, err)
			}
			_, err = s.setState(context.Background(), a.ID, StateInput{"suspended", 1, "After drift"}, "test operator")
			if !errors.Is(err, ErrRecovery) {
				t.Fatal("recovery failed to close mutation", err)
			}
			if err = s.WithSnapshot(context.Background(), func(SnapshotLease) error { t.Fatal("recovery callback"); return nil }); !errors.Is(err, ErrRecovery) {
				t.Fatal(err)
			}
		})
	}
}

func TestSnapshotPendingCorruptAndUnavailableLockOut(t *testing.T) {
	for _, scenario := range []string{"pending", "corrupt", "closed", "initial-drift"} {
		t.Run(scenario, func(t *testing.T) {
			s, native, _ := setupStore(t)
			expected := ErrRecovery
			switch scenario {
			case "pending":
				native.failure = "after"
				_, err := s.create(context.Background(), CreateInput{"fixtureacct", "fixture.test", "Pending synthetic failure"}, "test operator")
				if !errors.Is(err, ErrRecovery) {
					t.Fatal(err)
				}
			case "corrupt":
				if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(accountBucket).Put([]byte("invalid"), []byte("{}")) }); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := s.close(); err != nil {
					t.Fatal(err)
				}
				expected = ErrUnavailable
			case "initial-drift":
				createFixture(t, s)
				native.changed = true
			}
			err := s.WithSnapshot(context.Background(), func(SnapshotLease) error { t.Fatal("unsafe callback admitted"); return nil })
			if !errors.Is(err, expected) {
				t.Fatal(err)
			}
		})
	}
}

func TestSnapshotCancellationCallbackErrorAndPanicRelease(t *testing.T) {
	s, _, _ := setupStore(t)
	createFixture(t, s)
	if !errors.Is(s.WithSnapshot(nil, func(SnapshotLease) error { return nil }), ErrInvalid) || !errors.Is(s.WithSnapshot(context.Background(), nil), ErrInvalid) {
		t.Fatal("invalid input accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.WithSnapshot(ctx, func(SnapshotLease) error { t.Fatal("canceled callback"); return nil })
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	err = s.WithSnapshot(ctx, func(l SnapshotLease) error { cancel(); return nil })
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatal("postcallback cancellation", err)
	}
	sentinel := errors.New("executor rejected operation")
	if err = s.WithSnapshot(context.Background(), func(l SnapshotLease) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	var captured SnapshotLease
	func() {
		defer func() {
			if recover() != sentinel {
				t.Fatal("panic changed")
			}
		}()
		_ = s.WithSnapshot(context.Background(), func(l SnapshotLease) error { captured = l; panic(sentinel) })
	}()
	if captured.Accounts() != nil || !errors.Is(captured.Verify(context.Background()), ErrConflict) {
		t.Fatal("panic retained lease")
	}
	if _, err = s.list(context.Background()); err != nil {
		t.Fatal("lock not released", err)
	}
}

type snapshotWaitingNative struct {
	nativeSystem
	wait bool
}

func (n *snapshotWaitingNative) Verify(ctx context.Context, r record) error {
	if !n.wait {
		return n.nativeSystem.Verify(ctx, r)
	}
	<-ctx.Done()
	return errors.Join(ErrUnavailable, ctx.Err())
}

func TestSnapshotVerifyHonorsShorterCallerDeadline(t *testing.T) {
	s, _, _ := setupStore(t)
	createFixture(t, s)
	n := &snapshotWaitingNative{nativeSystem: s.native}
	s.native = n
	err := s.WithSnapshot(context.Background(), func(l SnapshotLease) error {
		n.wait = true
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
		defer cancel()
		err := l.Verify(ctx)
		n.wait = false
		if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("caller deadline ignored", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotCanceledWhileWaitingCannotEnterCallback(t *testing.T) {
	s, _, _ := setupStore(t)
	entered, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- s.WithSnapshot(context.Background(), func(SnapshotLease) error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() {
		second <- s.WithSnapshot(ctx, func(SnapshotLease) error { return errors.New("canceled callback admitted") })
	}()
	cancel()
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
