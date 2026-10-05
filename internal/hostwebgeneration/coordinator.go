// Package hostwebgeneration journals configuration transitions. It contains
// no native executor, transport, daemon activation, or runtime certification.
package hostwebgeneration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
)

var (
	ErrInvalid     = errors.New("invalid generation request")
	ErrConflict    = errors.New("generation or snapshot changed")
	ErrRecovery    = errors.New("generation recovery required")
	ErrUnavailable = errors.New("generation coordinator unavailable")
	ErrLimit       = errors.New("generation journal bound reached")
)

const ExecutorTimeout = 30 * time.Second

// SnapshotProvider reserves broker account mutations during the callback.
// Callbacks must not reenter the provider/account service. The provider verifies
// native identities on admission and after the callback; external root writers
// are outside this reservation. Alias the real broker seam, without an adapter
// that would weaken its callback or native verification contract.
type SnapshotProvider = hostaccounts.SnapshotProvider
type SnapshotLease = hostaccounts.SnapshotLease

// Executor is a trusted, separately qualified implementation. Observe reads
// actual installed/serving identity, never merely echoes the requested target.
// Denied observations attest no tenant serving plus the exact denied bundle.
// Each method must stop/reap owned work on context cancellation. This package
// cannot preempt arbitrary non-cooperative Go code safely.
type Executor interface {
	Observe(context.Context) (Identity, error)
	Apply(context.Context, Transition) error
	Rollback(context.Context, Transition, Generation) error
}

type Identity struct {
	GenerationID   string `json:"generation_id"`
	ProfileSHA256  string `json:"profile_sha256"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	BundleSHA256   string `json:"bundle_sha256"`
	Denied         bool   `json:"denied"`
}

type Generation struct {
	ID             string                 `json:"id"`
	ProfileSHA256  string                 `json:"profile_sha256"`
	SnapshotSHA256 string                 `json:"snapshot_sha256"`
	Denied         bool                   `json:"denied"`
	Accounts       []hostaccounts.Account `json:"accounts"`
	Bundle         hostweb.Bundle         `json:"bundle"`
}

func (g Generation) Identity() Identity {
	return Identity{g.ID, g.ProfileSHA256, g.SnapshotSHA256, g.Bundle.SHA256, g.Denied}
}

type Transition struct {
	OperationID string
	Revision    uint64
	Before      Generation
	After       Generation
}

// Plan contains only review/CAS metadata, never caller-supplied config bytes.
type Plan struct {
	Revision       uint64   `json:"revision"`
	Current        Identity `json:"current"`
	ProfileSHA256  string   `json:"profile_sha256"`
	SnapshotSHA256 string   `json:"snapshot_sha256"`
	BundleSHA256   string   `json:"bundle_sha256"`
}

type ApplyInput struct {
	Plan          Plan
	Actor, Reason string
}
type RecoverInput struct {
	ExpectedRevision           uint64
	OperationID, Actor, Reason string
}
type Status struct {
	Revision         uint64    `json:"revision"`
	Current          *Identity `json:"current,omitempty"`
	PendingOperation string    `json:"pending_operation,omitempty"`
	Phase            string    `json:"phase"`
}

type Coordinator struct {
	mu          sync.Mutex
	persistence *persistence
	profile     hostweb.Profile
	profileSHA  string
	provider    SnapshotProvider
	executor    Executor
	closed      bool
}

func digest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func newID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(data[:]), nil
}

func validText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func copied(g Generation) Generation {
	g.Accounts = append([]hostaccounts.Account{}, g.Accounts...)
	g.Bundle.Files = append([]hostweb.File(nil), g.Bundle.Files...)
	for i := range g.Bundle.Files {
		g.Bundle.Files[i].Data = append([]byte(nil), g.Bundle.Files[i].Data...)
	}
	return g
}

func copiedTransition(t Transition) Transition {
	t.Before = copied(t.Before)
	t.After = copied(t.After)
	return t
}

func (c *Coordinator) generation(id string, accounts []hostaccounts.Account, denied bool) (Generation, error) {
	accounts = append([]hostaccounts.Account{}, accounts...)
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	for _, account := range accounts {
		if account.Revision == 0 || account.CreatedAt.IsZero() || account.UpdatedAt.Before(account.CreatedAt) {
			return Generation{}, ErrInvalid
		}
	}
	render := append([]hostaccounts.Account{}, accounts...)
	if denied {
		for i := range render {
			render[i].State = "suspended"
		}
	}
	bundle, err := hostweb.Compile(c.profile, render)
	if err != nil {
		return Generation{}, ErrInvalid
	}
	if err = bundle.Validate(); err != nil {
		return Generation{}, ErrInvalid
	}
	return Generation{id, c.profileSHA, digest(accounts), denied, accounts, bundle}, nil
}

func (c *Coordinator) current(st state, accounts []hostaccounts.Account) (Generation, error) {
	if st.Current == "" {
		return c.generation("", accounts, true)
	}
	return c.persistence.generation(st.Current, c)
}

func (c *Coordinator) read() (state, error) {
	if c.closed {
		return state{}, ErrUnavailable
	}
	return c.persistence.read(c)
}

func (c *Coordinator) Status() (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.read()
	if err != nil {
		return Status{}, err
	}
	out := Status{Revision: st.Revision, Phase: "idle"}
	if st.Current != "" {
		g, e := c.persistence.generation(st.Current, c)
		if e != nil {
			return Status{}, e
		}
		identity := g.Identity()
		out.Current = &identity
	}
	if st.Pending != nil {
		out.PendingOperation = st.Pending.OperationID
		out.Phase = st.Pending.Phase
	}
	return out, nil
}

func (c *Coordinator) Plan(ctx context.Context) (Plan, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil {
		return Plan{}, ErrInvalid
	}
	st, err := c.read()
	if err != nil {
		return Plan{}, err
	}
	if st.Pending != nil {
		return Plan{}, ErrRecovery
	}
	var plan Plan
	err = c.provider.WithSnapshot(ctx, func(lease SnapshotLease) error {
		ctx = lease.Context()
		if ctx == nil {
			return ErrUnavailable
		}
		if e := lease.Verify(ctx); e != nil {
			return ErrUnavailable
		}
		accounts := append([]hostaccounts.Account(nil), lease.Accounts()...)
		g, e := c.generation("", accounts, false)
		if e != nil {
			return e
		}
		before, e := c.current(st, accounts)
		if e != nil {
			return e
		}
		plan = Plan{st.Revision, before.Identity(), c.profileSHA, g.SnapshotSHA256, g.Bundle.SHA256}
		return ctx.Err()
	})
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	return plan, nil
}

func (c *Coordinator) observe(ctx context.Context) (Identity, error) {
	bounded, cancel := context.WithTimeout(ctx, ExecutorTimeout)
	defer cancel()
	identity, err := c.executor.Observe(bounded)
	if err != nil || bounded.Err() != nil {
		return Identity{}, ErrRecovery
	}
	return identity, nil
}

func (c *Coordinator) run(ctx context.Context, call func(context.Context) error) error {
	bounded, cancel := context.WithTimeout(ctx, ExecutorTimeout)
	defer cancel()
	err := call(bounded)
	if err != nil || bounded.Err() != nil {
		return ErrRecovery
	}
	return nil
}

func (c *Coordinator) Apply(ctx context.Context, in ApplyInput) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil || !validText(in.Actor, 120) || !validText(in.Reason, 500) {
		return ErrInvalid
	}
	st, err := c.read()
	if err != nil {
		return err
	}
	if st.Pending != nil {
		return ErrRecovery
	}
	if st.Revision == math.MaxUint64 || in.Plan.Revision != st.Revision {
		return ErrConflict
	}
	var begun, committed bool
	var intent *pending
	err = c.provider.WithSnapshot(ctx, func(lease SnapshotLease) error {
		ctx = lease.Context()
		if ctx == nil {
			return ErrUnavailable
		}
		if e := lease.Verify(ctx); e != nil {
			return ErrUnavailable
		}
		accounts := append([]hostaccounts.Account(nil), lease.Accounts()...)
		after, e := c.generation("", accounts, false)
		if e != nil {
			return e
		}
		before, e := c.current(st, accounts)
		if e != nil {
			return e
		}
		want := Plan{st.Revision, before.Identity(), c.profileSHA, after.SnapshotSHA256, after.Bundle.SHA256}
		if want != in.Plan {
			return ErrConflict
		}
		observed, e := c.observe(ctx)
		if e != nil {
			return e
		}
		if observed != before.Identity() {
			return ErrConflict
		}
		if e = lease.Verify(ctx); e != nil {
			return ErrUnavailable
		}
		after.ID, e = newID()
		if e != nil {
			return e
		}
		op, e := newID()
		if e != nil {
			return e
		}
		intent = &pending{OperationID: op, AtRevision: st.Revision, Before: before.Identity(), After: after.ID, Phase: "applying", Actor: in.Actor, Reason: in.Reason}
		if e = c.persistence.begin(&st, intent, after, c); e != nil {
			return e
		}
		begun = true
		t := Transition{op, st.Revision, before, after}
		if e = c.run(ctx, func(bounded context.Context) error { return c.executor.Apply(bounded, copiedTransition(t)) }); e != nil {
			return e
		}
		observed, e = c.observe(ctx)
		if e != nil || observed != after.Identity() {
			return ErrRecovery
		}
		if e = lease.Verify(ctx); e != nil || ctx.Err() != nil {
			return ErrRecovery
		}
		if e = c.persistence.finish(&st, after.ID, "committed", in.Actor, in.Reason, c); e != nil {
			return e
		}
		committed = true
		return nil
	})
	if err != nil && begun {
		// Provider postverification can fail after the callback committed. Reopen
		// the intent at the now-current revision; failure never leaves idle status.
		if committed {
			intent.AtRevision = st.Revision
			st.Pending = intent
		}
		if e := c.persistence.markRecovery(&st, c); e != nil {
			return ErrRecovery
		}
		return ErrRecovery
	}
	return err
}

func (c *Coordinator) Recover(ctx context.Context, in RecoverInput) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil || !validText(in.Actor, 120) || !validText(in.Reason, 500) {
		return ErrInvalid
	}
	st, err := c.read()
	if err != nil {
		return err
	}
	if st.Pending == nil || in.ExpectedRevision != st.Revision || in.OperationID != st.Pending.OperationID || st.Revision == math.MaxUint64 {
		return ErrConflict
	}
	var committed bool
	intent := *st.Pending
	err = c.provider.WithSnapshot(ctx, func(lease SnapshotLease) error {
		ctx = lease.Context()
		if ctx == nil {
			return ErrUnavailable
		}
		if e := lease.Verify(ctx); e != nil {
			return ErrRecovery
		}
		accounts := append([]hostaccounts.Account(nil), lease.Accounts()...)
		current, e := c.generation("", accounts, true)
		if e != nil {
			return e
		}
		after, e := c.persistence.generation(intent.After, c)
		if e != nil {
			return e
		}
		observed, e := c.observe(ctx)
		if e != nil {
			return e
		}
		known := observed == intent.Before || observed == after.Identity()
		if intent.Recovery != "" {
			prior, e := c.persistence.generation(intent.Recovery, c)
			if e != nil {
				return e
			}
			known = known || observed == prior.Identity()
		}
		if !known {
			return ErrConflict
		}
		var before Generation
		if intent.Before.GenerationID == "" {
			before, e = c.generation("", after.Accounts, true)
		} else {
			before, e = c.persistence.generation(intent.Before.GenerationID, c)
		}
		if e != nil || before.Identity() != intent.Before {
			return ErrRecovery
		}
		target := before
		if target.ID == "" || target.SnapshotSHA256 != current.SnapshotSHA256 || target.SnapshotSHA256 != after.SnapshotSHA256 {
			target = current
			if intent.Recovery != "" {
				prior, e := c.persistence.generation(intent.Recovery, c)
				if e != nil {
					return e
				}
				if prior.Denied && prior.SnapshotSHA256 == current.SnapshotSHA256 {
					target = prior
				}
			}
			if target.ID == "" {
				target.ID, e = newID()
				if e != nil {
					return e
				}
			}
		}
		if e = lease.Verify(ctx); e != nil {
			return ErrRecovery
		}
		if e = c.persistence.recovering(&st, target, in.Actor, in.Reason, c); e != nil {
			return e
		}
		intent = *st.Pending
		t := Transition{intent.OperationID, st.Revision, before, after}
		if e = c.run(ctx, func(bounded context.Context) error {
			return c.executor.Rollback(bounded, copiedTransition(t), copied(target))
		}); e != nil {
			return e
		}
		observed, e = c.observe(ctx)
		if e != nil || observed != target.Identity() {
			return ErrRecovery
		}
		if e = lease.Verify(ctx); e != nil || ctx.Err() != nil {
			return ErrRecovery
		}
		if e = c.persistence.finish(&st, target.ID, "recovered", in.Actor, in.Reason, c); e != nil {
			return e
		}
		committed = true
		return nil
	})
	if err != nil {
		if committed {
			intent.AtRevision = st.Revision
			st.Pending = &intent
		}
		if e := c.persistence.markRecovery(&st, c); e != nil {
			return ErrRecovery
		}
		return ErrRecovery
	}
	return nil
}

func (c *Coordinator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.persistence.db.Close()
}
