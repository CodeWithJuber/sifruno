package hostaccounts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/securestate"
)

type fileIdentity struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
}
type ownership struct {
	Home   fileIdentity `json:"home"`
	Public fileIdentity `json:"public"`
	Marker fileIdentity `json:"marker"`
}
type pending struct {
	Action      string `json:"action"`
	Target      string `json:"target"`
	Actor       string `json:"actor"`
	Reason      string `json:"reason"`
	OperationID string `json:"operation_id"`
}
type record struct {
	Version         int       `json:"version"`
	Account         Account   `json:"account"`
	Tag             string    `json:"tag"`
	Ownership       ownership `json:"ownership"`
	Pending         *pending  `json:"pending,omitempty"`
	Actor           string    `json:"actor"`
	Reason          string    `json:"reason"`
	HistorySequence uint64    `json:"history_sequence"`
}
type nativeSystem interface {
	Plan(context.Context, string) (int, int, error)
	Create(context.Context, record, func(ownership) error) (ownership, error)
	RecoverCreate(context.Context, record, func(ownership) error) (ownership, error)
	Verify(context.Context, record) error
	SetState(context.Context, record, string) error
	GuardState(string) error
	GuardHomes([]record) error
}
type store struct {
	mu     sync.Mutex
	db     *bolt.DB
	opts   BrokerOptions
	native nativeSystem
	closed bool
}

var accountBucket = []byte("hostaccounts-v1")
var configBucket = []byte("hostbroker-config-v1")

func openStore(ctx context.Context, opts BrokerOptions, system nativeSystem) (*store, error) {
	if ctx == nil || system == nil {
		return nil, ErrInvalid
	}
	if ensureBrokerDir(opts.StateDir) != nil {
		return nil, ErrUnavailable
	}
	dir, err := securestate.Dir(opts.StateDir)
	if err != nil {
		return nil, ErrUnavailable
	}
	opts.StateDir = dir
	if system.GuardState(dir) != nil {
		return nil, ErrUnavailable
	}
	db, err := bolt.Open(filepath.Join(dir, "hostaccounts.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, ErrUnavailable
	}
	s := &store{db: db, opts: opts, native: system}
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	err = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(accountBucket)
		if e != nil {
			return e
		}
		if b.Stats().KeyN > MaxAccounts {
			return ErrRecovery
		}
		cfg, e := tx.CreateBucketIfNotExists(configBucket)
		if e != nil {
			return e
		}
		if _, e = tx.CreateBucketIfNotExists(historyBucket); e != nil {
			return e
		}
		want, _ := json.Marshal(opts)
		if old := cfg.Get([]byte("options")); old != nil {
			var actual BrokerOptions
			if json.Unmarshal(old, &actual) != nil || actual != opts {
				return ErrRecovery
			}
		} else {
			if b.Stats().KeyN != 0 {
				return ErrRecovery
			}
			if e = cfg.Put([]byte("options"), want); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return nil, ErrRecovery
	}
	if system.GuardState(dir) != nil {
		return nil, ErrUnavailable
	}
	if err = s.refresh(ctx, true); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}
func (s *store) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.db.Close() != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *store) healthy() error {
	if s.closed || s.native.GuardState(s.opts.StateDir) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *store) records() ([]record, error) {
	out := []record{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(accountBucket)
		if b == nil {
			return ErrRecovery
		}
		return b.ForEach(func(key, value []byte) error {
			if len(out) >= MaxAccounts || value == nil || len(value) > 32<<10 {
				return ErrRecovery
			}
			var r record
			if json.Unmarshal(value, &r) != nil || r.Version != 1 || !idPattern.MatchString(r.Account.ID) || string(key) != r.Account.ID || !validUsername(r.Account.Username) || !validDomain(r.Account.Domain) || r.Account.UID < 20000 || r.Account.UID > 60000 || r.Account.GID != r.Account.UID || r.Account.Revision == 0 || r.Tag != "sifruno-managed-"+r.Account.ID || r.Account.Home != filepath.Join(s.opts.HomesDir, r.Account.Username) || r.Account.PublicHTML != filepath.Join(r.Account.Home, "public_html") || r.Account.CreatedAt.IsZero() || r.Account.UpdatedAt.IsZero() || (r.Account.State != "active" && r.Account.State != "suspended" && r.Account.State != "recovery_required") {
				return ErrRecovery
			}
			if r.Pending != nil && (!idPattern.MatchString(r.Pending.OperationID) || !validText(r.Pending.Actor, 120) || !validText(r.Pending.Reason, 500) || (r.Pending.Action != "create" && r.Pending.Action != "state" && r.Pending.Action != "conflict") || (r.Pending.Target != "active" && r.Pending.Target != "suspended")) {
				return ErrRecovery
			}
			if verifyHistory(tx, r) != nil {
				return ErrRecovery
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, ErrRecovery
	}
	return out, nil
}
func (s *store) save(r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return ErrRecovery
	}
	if s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(accountBucket).Put([]byte(r.Account.ID), b) }) != nil {
		return ErrRecovery
	}
	return nil
}
func (s *store) refresh(ctx context.Context, reconcile bool) error {
	items, err := s.records()
	if err != nil {
		return err
	}
	if s.native.GuardHomes(items) != nil {
		return ErrRecovery
	}
	seenNames, seenDomains, seenUID := map[string]bool{}, map[string]bool{}, map[int]bool{}
	for _, r := range items {
		if seenNames[r.Account.Username] || seenDomains[r.Account.Domain] || seenUID[r.Account.UID] {
			return ErrRecovery
		}
		seenNames[r.Account.Username] = true
		seenDomains[r.Account.Domain] = true
		seenUID[r.Account.UID] = true
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if r.Pending != nil {
			if !reconcile || r.Pending.Action == "conflict" {
				continue
			}
			if r.Pending.Action == "create" {
				owned, e := s.native.RecoverCreate(ctx, r, func(owned ownership) error { r.Ownership = owned; return s.save(r) })
				if e != nil {
					continue
				}
				r.Ownership = owned
			} else if s.native.Verify(ctx, targetRecord(r, r.Pending.Target)) != nil {
				continue
			}
			operation := *r.Pending
			r.Account.State = r.Pending.Target
			r.Account.UpdatedAt = time.Now().UTC()
			if r.Pending.Action == "state" {
				r.Account.Revision++
			}
			r.Actor, r.Reason = r.Pending.Actor, r.Pending.Reason
			r.Pending = nil
			if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
				return ErrRecovery
			}
			continue
		}
		if e := s.native.Verify(ctx, r); e != nil {
			if errors.Is(e, ErrUnavailable) {
				return ErrUnavailable
			}
			before := r.Account
			r.Pending = &pending{Action: "conflict", Target: r.Account.State, Actor: "broker-reconcile", Reason: "Managed operating system identity changed"}
			r, e = s.beginOperation(r, &before)
			if e != nil {
				return ErrRecovery
			}
			if _, e = s.resultEvent(r, *r.Pending, "recovery_required"); e != nil {
				return ErrRecovery
			}
		}
	}
	return nil
}
func targetRecord(r record, state string) record { r.Account.State = state; return r }
func (s *store) capability(ctx context.Context) (Capability, error) {
	if snapshotReentry(ctx, s) {
		return Capability{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		return Capability{}, ErrInvalid
	}
	if s.healthy() != nil {
		return unavailable("broker_state_unavailable"), nil
	}
	if s.refresh(ctx, false) != nil {
		return unavailable("broker_state_unavailable"), nil
	}
	items, err := s.records()
	if err != nil {
		return unavailable("broker_recovery_required"), nil
	}
	for _, r := range items {
		if r.Pending != nil {
			return Capability{Reason: "managed_account_recovery_required", Backend: "linux_shadow_utils", Restrictions: restrictions()}, nil
		}
	}
	return Capability{Available: true, Backend: "linux_shadow_utils", Restrictions: restrictions()}, nil
}
func (s *store) list(ctx context.Context) ([]Account, error) {
	if snapshotReentry(ctx, s) {
		return nil, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		return nil, ErrInvalid
	}
	if s.healthy() != nil {
		return nil, ErrUnavailable
	}
	if s.refresh(ctx, false) != nil {
		return nil, ErrRecovery
	}
	items, err := s.records()
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(items))
	for _, r := range items {
		a := r.Account
		if r.Pending != nil {
			a.State = "recovery_required"
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}
func (s *store) mutationReady(ctx context.Context) ([]record, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if s.healthy() != nil {
		return nil, ErrUnavailable
	}
	if s.refresh(ctx, false) != nil {
		return nil, ErrRecovery
	}
	items, e := s.records()
	if e != nil {
		return nil, e
	}
	for _, r := range items {
		if r.Pending != nil {
			return nil, ErrRecovery
		}
	}
	return items, nil
}
func planOrDefault(plan string) string {
	if plan == "" {
		return "default"
	}
	return plan
}

func (s *store) create(ctx context.Context, in CreateInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !validCreate(in, actor) {
		return Account{}, ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return Account{}, err
	}
	if len(items) >= MaxAccounts {
		return Account{}, ErrConflict
	}
	for _, r := range items {
		if r.Account.Username == in.Username || r.Account.Domain == in.Domain {
			return Account{}, ErrConflict
		}
	}
	uid, gid, err := s.native.Plan(ctx, in.Username)
	if err != nil {
		return Account{}, err
	}
	if uid < 20000 || uid > 60000 || gid != uid || uid == int(s.opts.ControllerUID) {
		return Account{}, ErrRecovery
	}
	for _, r := range items {
		if r.Account.UID == uid || r.Account.GID == gid {
			return Account{}, ErrRecovery
		}
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return Account{}, ErrUnavailable
	}
	key := hex.EncodeToString(id[:])
	now := time.Now().UTC()
	home := filepath.Join(s.opts.HomesDir, in.Username)
	r := record{Version: 1, Tag: "sifruno-managed-" + key, Account: Account{ID: key, Username: in.Username, Domain: in.Domain, Plan: planOrDefault(in.Plan), Home: home, PublicHTML: filepath.Join(home, "public_html"), State: "recovery_required", UID: uid, GID: gid, Revision: 1, CreatedAt: now, UpdatedAt: now}, Pending: &pending{Action: "create", Target: "active", Actor: actor, Reason: in.Reason}}
	r, err = s.beginOperation(r, nil)
	if err != nil {
		return Account{}, ErrRecovery
	}
	owned, err := s.native.Create(ctx, r, func(owned ownership) error { r.Ownership = owned; return s.save(r) })
	if err != nil {
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return Account{}, ErrRecovery
	}
	r.Ownership = owned
	r.Account.State = "active"
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
	operation := *r.Pending
	if s.native.Verify(ctx, r) != nil {
		_, _ = s.resultEvent(r, operation, "recovery_required")
		return Account{}, ErrRecovery
	}
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return Account{}, ErrRecovery
	}
	return r.Account, nil
}
func (s *store) setState(ctx context.Context, id string, in StateInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) || !validState(in, actor) {
		return Account{}, ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return Account{}, err
	}
	var r record
	found := false
	for _, item := range items {
		if item.Account.ID == id {
			r = item
			found = true
			break
		}
	}
	if !found {
		return Account{}, ErrNotFound
	}
	if r.Account.Revision != in.ExpectedRevision {
		return Account{}, ErrConflict
	}
	if r.Account.State == in.State {
		return r.Account, nil
	}
	if r.Account.Revision == ^uint64(0) {
		return Account{}, ErrRecovery
	}
	r.Pending = &pending{Action: "state", Target: in.State, Actor: actor, Reason: in.Reason}
	before := r.Account
	r, err = s.beginOperation(r, &before)
	if err != nil {
		return Account{}, ErrRecovery
	}
	if s.native.SetState(ctx, r, in.State) != nil {
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return Account{}, ErrRecovery
	}
	next := targetRecord(r, in.State)
	if s.native.Verify(ctx, next) != nil {
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return Account{}, ErrRecovery
	}
	next.Account.Revision++
	next.Account.UpdatedAt = time.Now().UTC()
	next.Actor, next.Reason = actor, in.Reason
	operation := *next.Pending
	next.Pending = nil
	if _, e := s.resultEvent(next, operation, "succeeded"); e != nil {
		return Account{}, ErrRecovery
	}
	return next.Account, nil
}

// A fresh dedicated broker directory has its own marker in addition to the
// shared private-state guard. No unrelated nonempty directory can be adopted.
func ensureBrokerDir(path string) error {
	if securestate.CheckPath(path) != nil {
		return ErrUnavailable
	}
	if _, e := securestate.Dir(path); e != nil {
		return ErrUnavailable
	}
	marker := filepath.Join(path, ".sifruno-hostbroker")
	if _, e := os.Lstat(marker); errors.Is(e, os.ErrNotExist) {
		entries, e := os.ReadDir(path)
		if e != nil || len(entries) != 1 || entries[0].Name() != ".sifruno-state" {
			return ErrUnavailable
		}
		f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return ErrUnavailable
		}
		_, e = f.Write([]byte("native Linux account broker v1\n"))
		if e == nil {
			e = f.Sync()
		}
		c := f.Close()
		if e != nil || c != nil {
			return ErrUnavailable
		}
	} else if e != nil {
		return ErrUnavailable
	}
	raw, e := os.ReadFile(marker)
	if e != nil || string(raw) != "native Linux account broker v1\n" {
		return ErrUnavailable
	}
	return nil
}
