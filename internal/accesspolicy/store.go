package accesspolicy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	bolt "go.etcd.io/bbolt"
)

var ErrStore = errors.New("access policy store unavailable or invalid")

var ErrDenied = errors.New("access policy management denied")

var policyBucket = []byte("accesspolicy-v1")
var snapshotKey = []byte("snapshot")

const maxSnapshotBytes = 96 << 10

// StoreVersion is a durable repository-bound CAS token, not an Authority revision
// or a credential. Copies of the database retain its repository identity.
type StoreVersion struct {
	repository string
	sequence   uint64
}

// Store borrows a database. The caller owns path admission and lifetime, and
// must not modify its options or this store's reserved bucket concurrently.
type Store struct{ db *bolt.DB }

// NewStore never initializes storage or grants permissions.
func NewStore(db *bolt.DB) (*Store, error) {
	s := &Store{db: db}
	if !s.usable() {
		return nil, ErrStore
	}
	if err := db.View(func(*bolt.Tx) error { return nil }); err != nil {
		return nil, ErrStore
	}
	return s, nil
}
func (s *Store) usable() bool {
	return s != nil && s.db != nil && !s.db.IsReadOnly() && !s.db.NoSync && !s.db.NoGrowSync
}

type storedActor struct {
	ID       string `json:"id"`
	Role     Role   `json:"role"`
	Assigned string `json:"assigned"`
}
type storedAccount struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
}
type storedSnapshot struct {
	Schema     int             `json:"schema"`
	Repository string          `json:"repository"`
	Sequence   uint64          `json:"sequence"`
	Actors     []storedActor   `json:"actors"`
	Accounts   []storedAccount `json:"accounts"`
}

func encodeSnapshot(p *Policy, v StoreVersion) ([]byte, error) {
	p, err := copyPolicy(p)
	if err != nil {
		return nil, err
	}
	d := storedSnapshot{Schema: 1, Repository: v.repository, Sequence: v.sequence, Actors: make([]storedActor, 0, len(p.actors)), Accounts: make([]storedAccount, 0, len(p.accounts))}
	for _, a := range p.actors {
		d.Actors = append(d.Actors, storedActor{a.Actor.String(), a.Role, a.Assigned.String()})
	}
	for id, owner := range p.accounts {
		d.Accounts = append(d.Accounts, storedAccount{id.String(), owner.String()})
	}
	sort.Slice(d.Actors, func(i, j int) bool { return d.Actors[i].ID < d.Actors[j].ID })
	sort.Slice(d.Accounts, func(i, j int) bool { return d.Accounts[i].ID < d.Accounts[j].ID })
	return json.Marshal(d)
}
func readSnapshot(tx *bolt.Tx) (*Policy, StoreVersion, error) {
	fail := func() (*Policy, StoreVersion, error) { return nil, StoreVersion{}, ErrStore }
	b := tx.Bucket(policyBucket)
	if b == nil {
		return fail()
	}
	c := b.Cursor()
	k, data := c.First()
	if !bytes.Equal(k, snapshotKey) || data == nil || len(data) > maxSnapshotBytes {
		return fail()
	}
	if k, _ = c.Next(); k != nil {
		return fail()
	}
	var d storedSnapshot
	if json.Unmarshal(data, &d) != nil || d.Schema != 1 || d.Sequence == 0 || len(d.Actors) == 0 || len(d.Actors) > MaxActors || len(d.Accounts) > MaxAccounts {
		return fail()
	}
	if _, err := ParseAccountID(d.Repository); err != nil {
		return fail()
	}
	actors := make([]ActorBinding, 0, len(d.Actors))
	accounts := make([]AccountBinding, 0, len(d.Accounts))
	for _, a := range d.Actors {
		id, err := ParseActorID(a.ID)
		if err != nil {
			return fail()
		}
		var assigned AccountID
		if a.Assigned != "" {
			assigned, err = ParseAccountID(a.Assigned)
			if err != nil {
				return fail()
			}
		}
		actors = append(actors, ActorBinding{id, a.Role, assigned})
	}
	for _, a := range d.Accounts {
		id, err := ParseAccountID(a.ID)
		if err != nil {
			return fail()
		}
		owner, err := ParseActorID(a.Owner)
		if err != nil {
			return fail()
		}
		accounts = append(accounts, AccountBinding{id, owner})
	}
	p, err := NewPolicy(actors, accounts)
	if err != nil {
		return fail()
	}
	v := StoreVersion{d.Repository, d.Sequence}
	canonical, err := encodeSnapshot(p, v)
	if err != nil || !bytes.Equal(data, canonical) {
		return fail()
	}
	return p, v, nil
}

// Initialize creates only a previously absent reserved bucket, with no default
// actors. An existing empty or corrupt bucket is never repaired automatically.
func (s *Store) Initialize(p *Policy) (StoreVersion, error) {
	if !s.usable() {
		return StoreVersion{}, ErrStore
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return StoreVersion{}, ErrStore
	}
	v := StoreVersion{hex.EncodeToString(id[:]), 1}
	data, err := encodeSnapshot(p, v)
	if err != nil {
		return StoreVersion{}, err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(policyBucket) != nil {
			return ErrConflict
		}
		b, e := tx.CreateBucket(policyBucket)
		if e != nil {
			return e
		}
		return b.Put(snapshotKey, data)
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return StoreVersion{}, ErrConflict
		}
		return StoreVersion{}, ErrStore
	}
	return v, nil
}

// Load returns a separately validated immutable policy and its durable version.
// It does not publish the policy into an Authority.
func (s *Store) Load() (*Policy, StoreVersion, error) {
	if !s.usable() {
		return nil, StoreVersion{}, ErrStore
	}
	var p *Policy
	var v StoreVersion
	err := s.db.View(func(tx *bolt.Tx) error { var e error; p, v, e = readSnapshot(tx); return e })
	if err != nil {
		return nil, StoreVersion{}, ErrStore
	}
	return p, v, nil
}

// Replace validates the existing record and atomically replaces the entire
// snapshot only when expected matches. Any failure returns a zero version.
// This privileged bootstrap/recovery API does not authorize an actor.
func (s *Store) Replace(expected StoreVersion, next *Policy) (StoreVersion, error) {
	return s.replace(expected, next, nil)
}

// ReplaceAuthorized authorizes an independently authenticated actor against the
// current stored policy, never the candidate, in the replacement transaction.
// It does not authenticate identity or authorize effects outside this database.
func (s *Store) ReplaceAuthorized(expected StoreVersion, actor ActorID, next *Policy) (StoreVersion, error) {
	return s.replace(expected, next, &actor)
}

func (s *Store) replace(expected StoreVersion, next *Policy, actor *ActorID) (StoreVersion, error) {
	if !s.usable() {
		return StoreVersion{}, ErrStore
	}
	var result StoreVersion
	err := s.db.Update(func(tx *bolt.Tx) error {
		policy, current, e := readSnapshot(tx)
		if e != nil {
			return e
		}
		if expected != current {
			return ErrConflict
		}
		if actor != nil && !policy.Authorize(*actor, ManagePolicy, ServerResource()) {
			return ErrDenied
		}
		if current.sequence == ^uint64(0) {
			return ErrExhausted
		}
		result = StoreVersion{current.repository, current.sequence + 1}
		data, e := encodeSnapshot(next, result)
		if e != nil {
			return e
		}
		return tx.Bucket(policyBucket).Put(snapshotKey, data)
	})
	if err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrDenied) || errors.Is(err, ErrExhausted) || errors.Is(err, ErrInvalid) {
			return StoreVersion{}, err
		}
		return StoreVersion{}, ErrStore
	}
	return result, nil
}
