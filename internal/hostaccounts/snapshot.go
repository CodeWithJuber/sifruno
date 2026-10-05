package hostaccounts

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// MaxSnapshotDuration bounds the cooperative callback context, including time
// waiting for the store mutex. Mutex acquisition itself is not preemptible;
// cancellation is checked after acquisition, before callback admission. A
// callback must honor Context(); it cannot be forcibly stopped safely while it
// may still be acting on the reserved accounts. This is not a strict return-time
// guarantee for an uncooperative callback or store operation.
const MaxSnapshotDuration = 45 * time.Second

type SnapshotProvider interface {
	WithSnapshot(context.Context, func(SnapshotLease) error) error
}

// Actor/reason validation, full-inventory revision CAS and operation auditing
// belong to the separate operation coordinator and trusted broker composition.
// This read reservation does not invent an account mutation or audit event.

// SnapshotLease reserves broker account mutations/reconciliation until the
// callback returns. External root edits bypass the mutex: Verify must be called
// immediately before external mutation and again before committing its journal.
// Even these checks cannot eliminate an external OS edit between check and act.
// WithSnapshot also verifies after the callback; a composition must quarantine
// its own operation if that final verification fails after its journal commit.
// Callbacks must not call store methods with captured, unmarked contexts (those
// calls are indistinguishable from legitimate concurrent callers and deadlock).
// Use Context() for downstream work; marked reentry fails with ErrConflict.
type SnapshotLease interface {
	Accounts() []Account
	Context() context.Context
	Verify(context.Context) error
}

type snapshotContextKey struct{}

type guardedSnapshot struct {
	mu       sync.Mutex // serializes explicit verification and lease expiration
	store    *store
	ctx      context.Context
	baseline []record
	active   bool
}

// SnapshotProvider is deliberately available only on the broker-owned store.
// It adds no Service method, HTTP route or controller-side List/apply bridge.
func (s *store) SnapshotProvider() SnapshotProvider { return s }

func snapshotReentry(ctx context.Context, s *store) bool {
	if ctx == nil {
		return false
	}
	owner, _ := ctx.Value(snapshotContextKey{}).(*store)
	return owner == s
}

func snapshotContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

// snapshotRecords is called only while store.mu is held. Reusing refresh
// preserves durable recovery closure when native identity has drifted.
func (s *store) snapshotRecords(ctx context.Context) ([]record, error) {
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	if err := s.healthy(); err != nil {
		return nil, ErrUnavailable
	}
	if err := s.refresh(ctx, false); err != nil {
		return nil, errors.Join(err, snapshotContextError(ctx))
	}
	items, err := s.records()
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.Pending != nil {
			return nil, ErrRecovery
		}
	}
	return items, snapshotContextError(ctx)
}

func (s *store) WithSnapshot(ctx context.Context, fn func(SnapshotLease) error) error {
	if ctx == nil || fn == nil {
		return ErrInvalid
	}
	if snapshotReentry(ctx, s) {
		return ErrConflict
	}
	bounded, cancel := context.WithTimeout(ctx, MaxSnapshotDuration)
	defer cancel()
	if err := snapshotContextError(bounded); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.snapshotRecords(bounded)
	if err != nil {
		return err
	}
	lease := &guardedSnapshot{store: s, ctx: context.WithValue(bounded, snapshotContextKey{}, s), baseline: items, active: true}
	defer func() { lease.mu.Lock(); lease.active = false; lease.mu.Unlock() }()
	callbackErr := fn(lease)
	lease.mu.Lock()
	lease.active = false
	// Mandatory verification is independent of whether the callback remembered
	// Verify or returned an error. It never accepts success after native drift.
	verifyErr := lease.verify(bounded)
	lease.mu.Unlock()
	return errors.Join(callbackErr, verifyErr)
}

func (l *guardedSnapshot) Context() context.Context { return l.ctx }

func (l *guardedSnapshot) Accounts() []Account {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.active {
		return nil
	}
	out := make([]Account, 0, len(l.baseline))
	for _, item := range l.baseline {
		out = append(out, item.Account)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func (l *guardedSnapshot) Verify(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.active {
		return ErrConflict
	}
	if ctx == nil {
		return ErrInvalid
	}
	if err := snapshotContextError(ctx); err != nil {
		return err
	}
	// Both the caller's cancellation and the reservation deadline remain binding.
	merged, cancel := context.WithCancel(l.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer cancel()
	defer stop()
	return errors.Join(l.verify(merged), snapshotContextError(ctx))
}

func (l *guardedSnapshot) verify(ctx context.Context) error {
	items, err := l.store.snapshotRecords(ctx)
	if err != nil {
		return err
	}
	if len(items) != len(l.baseline) {
		return ErrRecovery
	}
	for i, item := range items {
		// records() has deterministic bbolt key order. Compare the entire private
		// identity, ownership and journal sequence, not just public revisions.
		if item != l.baseline[i] {
			return ErrRecovery
		}
	}
	return nil
}
