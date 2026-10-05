package hostwebgeneration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/hostweb"
	"sifruno/internal/securestate"
)

const (
	MaxGenerations     = 16
	MaxEvents          = 128
	MaxGenerationBytes = 16 << 20
	MaxDatabaseBytes   = 512 << 20
	maxMetadataBytes   = 64 << 10
)

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var stateBucket = []byte("web-generation-state-v1")
var generationBucket = []byte("web-generations-v1")
var eventBucket = []byte("web-generation-events-v1")
var stateKey = []byte("current")

type pending struct {
	OperationID string   `json:"operation_id"`
	AtRevision  uint64   `json:"at_revision"`
	Before      Identity `json:"before"`
	After       string   `json:"after"`
	Recovery    string   `json:"recovery,omitempty"`
	Phase       string   `json:"phase"`
	Actor       string   `json:"actor"`
	Reason      string   `json:"reason"`
}

type state struct {
	Version      int      `json:"version"`
	ProfileSHA   string   `json:"profile_sha256"`
	Revision     uint64   `json:"revision"`
	Current      string   `json:"current"`
	Pending      *pending `json:"pending,omitempty"`
	Sequence     uint64   `json:"sequence"`
	LastEventSHA string   `json:"last_event_sha256"`
}

// Event records Ponytrail-inspired before/after metadata, not file checkpoint
// contents or host backups. Hash chaining detects accidental journal damage;
// it is not authentication against the root owner of this database.
type Event struct {
	Sequence    uint64    `json:"sequence"`
	OperationID string    `json:"operation_id"`
	Phase       string    `json:"phase"`
	Revision    uint64    `json:"revision"`
	Before      Identity  `json:"before"`
	After       Identity  `json:"after"`
	Actor       string    `json:"actor"`
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
	PreviousSHA string    `json:"previous_sha256"`
	SHA         string    `json:"sha256"`
}

type persistence struct {
	db   *bolt.DB
	file os.FileInfo
}

func Open(dir string, profile hostweb.Profile, provider SnapshotProvider, executor Executor) (*Coordinator, error) {
	if provider == nil || executor == nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrInvalid
	}
	if _, err := hostweb.Compile(profile, nil); err != nil {
		return nil, ErrInvalid
	}
	if err := guardOwner(); err != nil {
		return nil, err
	}
	if _, err := securestate.Dir(dir); err != nil {
		return nil, ErrUnavailable
	}
	if err := guardDirectory(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "generations.db")
	if err := securestate.CheckPath(path); err != nil {
		return nil, ErrUnavailable
	}
	if info, err := os.Lstat(path); err == nil {
		if guardFile(path, info) != nil || info.Size() > MaxDatabaseBytes {
			return nil, ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || guardFile(path, info) != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	c := &Coordinator{persistence: &persistence{db: db, file: info}, profile: profile, profileSHA: digest(profile), provider: provider, executor: executor}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{stateBucket, generationBucket, eventBucket} {
			if _, e := tx.CreateBucketIfNotExists(name); e != nil {
				return e
			}
		}
		b := tx.Bucket(stateBucket)
		if b.Get(stateKey) == nil {
			if tx.Bucket(generationBucket).Stats().KeyN != 0 || tx.Bucket(eventBucket).Stats().KeyN != 0 {
				return ErrRecovery
			}
			raw, _ := json.Marshal(state{Version: 1, ProfileSHA: c.profileSHA})
			return b.Put(stateKey, raw)
		}
		return nil
	})
	if err == nil {
		_, err = c.persistence.read(c)
	}
	if err != nil {
		db.Close()
		return nil, ErrRecovery
	}
	return c, nil
}

func decode(raw []byte, out any, bound int) error {
	if len(raw) == 0 || len(raw) > bound {
		return ErrRecovery
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrRecovery
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrRecovery
	}
	return nil
}

func (p *persistence) healthy() error {
	if securestate.CheckPath(p.db.Path()) != nil {
		return ErrRecovery
	}
	info, err := os.Lstat(p.db.Path())
	if err != nil || !os.SameFile(p.file, info) || guardFile(p.db.Path(), info) != nil || info.Size() > MaxDatabaseBytes {
		return ErrRecovery
	}
	return nil
}

func loadGeneration(tx *bolt.Tx, id string, c *Coordinator) (Generation, error) {
	var g Generation
	if !idPattern.MatchString(id) || decode(tx.Bucket(generationBucket).Get([]byte(id)), &g, MaxGenerationBytes) != nil || g.ID != id {
		return g, ErrRecovery
	}
	want, err := c.generation(g.ID, g.Accounts, g.Denied)
	if err != nil || g.ProfileSHA256 != c.profileSHA || g.SnapshotSHA256 != want.SnapshotSHA256 || g.Bundle.Validate() != nil || digest(g.Bundle) != digest(want.Bundle) {
		return g, ErrRecovery
	}
	return g, nil
}

func (p *persistence) generation(id string, c *Coordinator) (Generation, error) {
	var g Generation
	err := p.db.View(func(tx *bolt.Tx) error { var e error; g, e = loadGeneration(tx, id, c); return e })
	return g, err
}

func (p *persistence) read(c *Coordinator) (state, error) {
	var st state
	if err := p.healthy(); err != nil {
		return st, err
	}
	err := p.db.View(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{stateBucket, generationBucket, eventBucket} {
			if tx.Bucket(name) == nil {
				return ErrRecovery
			}
		}
		if tx.Bucket(stateBucket).Stats().KeyN != 1 || decode(tx.Bucket(stateBucket).Get(stateKey), &st, maxMetadataBytes) != nil || st.Version != 1 || st.ProfileSHA != c.profileSHA {
			return ErrRecovery
		}
		if tx.Bucket(generationBucket).Stats().KeyN > MaxGenerations || tx.Bucket(eventBucket).Stats().KeyN > MaxEvents {
			return ErrRecovery
		}
		identities := map[string]Identity{}
		if err := tx.Bucket(generationBucket).ForEach(func(k, v []byte) error {
			g, e := loadGeneration(tx, string(k), c)
			if e == nil {
				identities[g.ID] = g.Identity()
			}
			return e
		}); err != nil {
			return err
		}
		if st.Current != "" {
			if _, e := loadGeneration(tx, st.Current, c); e != nil {
				return e
			}
		}
		if st.Pending != nil {
			in := st.Pending
			if !idPattern.MatchString(in.OperationID) || in.AtRevision != st.Revision || !validText(in.Actor, 120) || !validText(in.Reason, 500) || (in.Phase != "applying" && in.Phase != "recovering" && in.Phase != "recovery_required") {
				return ErrRecovery
			}
			after, e := loadGeneration(tx, in.After, c)
			if e != nil {
				return e
			}
			var before Generation
			if in.Before.GenerationID == "" {
				before, e = c.generation("", after.Accounts, true)
			} else {
				before, e = loadGeneration(tx, in.Before.GenerationID, c)
			}
			if e != nil || before.Identity() != in.Before {
				return ErrRecovery
			}
			if in.Recovery != "" {
				if _, e = loadGeneration(tx, in.Recovery, c); e != nil {
					return e
				}
			}
		}
		return verifyEvents(tx, st, identities, c)
	})
	return st, err
}

func verifyEvents(tx *bolt.Tx, st state, identities map[string]Identity, c *Coordinator) error {
	var seq, revision uint64
	previous, current := "", ""
	var last Event
	var operation string
	var before, desired, recovering Identity
	seen := map[string]bool{}
	var intentActor, intentReason string
	completed := true
	err := tx.Bucket(eventBucket).ForEach(func(k, v []byte) error {
		var event Event
		if decode(v, &event, maxMetadataBytes) != nil {
			return ErrRecovery
		}
		seq++
		if string(k) != fmt.Sprintf("%020d", seq) || event.Sequence != seq || event.PreviousSHA != previous || !idPattern.MatchString(event.OperationID) || !validText(event.Actor, 120) || !validText(event.Reason, 500) || event.At.IsZero() {
			return ErrRecovery
		}
		if event.Phase != "intended" && event.Phase != "recovering" && event.Phase != "committed" && event.Phase != "recovered" && event.Phase != "recovery_required" {
			return ErrRecovery
		}
		if event.After.GenerationID == "" || identities[event.After.GenerationID] != event.After {
			return ErrRecovery
		}
		if event.Before.GenerationID != "" && identities[event.Before.GenerationID] != event.Before {
			return ErrRecovery
		}
		if event.Phase == "intended" {
			if !completed || seen[event.OperationID] || event.Before.GenerationID != current || event.After.GenerationID == current {
				return ErrRecovery
			}
			seen[event.OperationID] = true
			intentActor, intentReason = event.Actor, event.Reason
			if current == "" {
				g, e := loadGeneration(tx, event.After.GenerationID, c)
				if e != nil {
					return e
				}
				denied, e := c.generation("", g.Accounts, true)
				if e != nil || denied.Identity() != event.Before {
					return ErrRecovery
				}
			}
			operation, before, desired = event.OperationID, event.Before, event.After
			completed = false
		} else {
			if operation != event.OperationID || event.Before != before {
				return ErrRecovery
			}
			switch event.Phase {
			case "committed":
				if completed || last.Phase != "intended" || event.After != desired {
					return ErrRecovery
				}
				completed = true
			case "recovered":
				if completed || last.Phase != "recovering" || event.After != recovering {
					return ErrRecovery
				}
				completed = true
			case "recovering":
				if completed {
					return ErrRecovery
				}
				recovering = event.After
			case "recovery_required":
				if event.After != desired {
					return ErrRecovery
				}
				completed = false
			}
		}
		if event.Phase == "committed" || event.Phase == "recovered" {
			revision++
			current = event.After.GenerationID
		}
		if event.Revision != revision {
			return ErrRecovery
		}
		if !validIdentity(event.Before) || !validIdentity(event.After) {
			return ErrRecovery
		}
		sha := event.SHA
		event.SHA = ""
		if digest(event) != sha {
			return ErrRecovery
		}
		previous = sha
		last = event
		return nil
	})
	if err != nil || seq != st.Sequence || previous != st.LastEventSHA || revision != st.Revision || current != st.Current {
		return ErrRecovery
	}
	if st.Pending != nil {
		if seq == 0 || last.OperationID != st.Pending.OperationID || last.Phase == "committed" || last.Phase == "recovered" || st.Pending.Before != before || st.Pending.After != desired.GenerationID {
			return ErrRecovery
		}
		if st.Pending.Recovery != "" && st.Pending.Recovery != recovering.GenerationID {
			return ErrRecovery
		}
		if st.Pending.Actor != intentActor || st.Pending.Reason != intentReason {
			return ErrRecovery
		}
		if (st.Pending.Phase == "applying" && last.Phase != "intended") || (st.Pending.Phase == "recovering" && last.Phase != "recovering") || (st.Pending.Phase == "recovery_required" && last.Phase != "recovery_required") {
			return ErrRecovery
		}
	} else if seq != 0 && last.Phase != "committed" && last.Phase != "recovered" {
		return ErrRecovery
	}
	return nil
}

func validIdentity(in Identity) bool {
	if in.GenerationID == "" && !in.Denied {
		return false
	}
	if in.GenerationID != "" && !idPattern.MatchString(in.GenerationID) {
		return false
	}
	for _, hash := range []string{in.ProfileSHA256, in.SnapshotSHA256, in.BundleSHA256} {
		if len(hash) != 64 {
			return false
		}
		for _, c := range hash {
			if (c < 'a' || c > 'f') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

func putGeneration(tx *bolt.Tx, g Generation) error {
	b := tx.Bucket(generationBucket)
	if old := b.Get([]byte(g.ID)); old != nil {
		raw, _ := json.Marshal(g)
		if !bytes.Equal(old, raw) {
			return ErrRecovery
		}
		return nil
	}
	if b.Stats().KeyN >= MaxGenerations {
		return ErrLimit
	}
	raw, err := json.Marshal(g)
	if err != nil || len(raw) > MaxGenerationBytes {
		return ErrLimit
	}
	return b.Put([]byte(g.ID), raw)
}

func writeState(tx *bolt.Tx, st *state, phase string, actor, reason string, after Identity) error {
	if st.Pending == nil || st.Sequence >= MaxEvents {
		return ErrLimit
	}
	event := Event{Sequence: st.Sequence + 1, OperationID: st.Pending.OperationID, Phase: phase, Revision: st.Revision, Before: st.Pending.Before, After: after, Actor: actor, Reason: reason, At: time.Now().UTC(), PreviousSHA: st.LastEventSHA}
	event.SHA = digest(event)
	raw, _ := json.Marshal(event)
	if len(raw) > maxMetadataBytes {
		return ErrLimit
	}
	if err := tx.Bucket(eventBucket).Put([]byte(fmt.Sprintf("%020d", event.Sequence)), raw); err != nil {
		return err
	}
	st.Sequence = event.Sequence
	st.LastEventSHA = event.SHA
	if phase == "committed" || phase == "recovered" {
		st.Pending = nil
	}
	raw, _ = json.Marshal(st)
	return tx.Bucket(stateBucket).Put(stateKey, raw)
}

func (p *persistence) begin(st *state, in *pending, g Generation, c *Coordinator) error {
	if st.Sequence > MaxEvents-8 {
		return ErrLimit
	}
	return p.update(st, c, false, func(tx *bolt.Tx, next *state) error {
		if tx.Bucket(generationBucket).Stats().KeyN > MaxGenerations-2 {
			return ErrLimit
		}
		if e := putGeneration(tx, g); e != nil {
			return e
		}
		next.Pending = in
		return writeState(tx, next, "intended", in.Actor, in.Reason, g.Identity())
	})
}

func (p *persistence) recovering(st *state, target Generation, actor, reason string, c *Coordinator) error {
	if st.Sequence > MaxEvents-3 {
		return ErrLimit
	}
	return p.update(st, c, false, func(tx *bolt.Tx, next *state) error {
		if e := putGeneration(tx, target); e != nil {
			return e
		}
		next.Pending.Recovery = target.ID
		next.Pending.Phase = "recovering"
		return writeState(tx, next, "recovering", actor, reason, target.Identity())
	})
}

func (p *persistence) finish(st *state, id, phase, actor, reason string, c *Coordinator) error {
	if st.Sequence >= MaxEvents-1 {
		return ErrLimit
	}
	return p.update(st, c, false, func(tx *bolt.Tx, next *state) error {
		g, e := loadGeneration(tx, id, c)
		if e != nil {
			return e
		}
		next.Current = id
		next.Revision++
		return writeState(tx, next, phase, actor, reason, g.Identity())
	})
}

func (p *persistence) markRecovery(st *state, c *Coordinator) error {
	return p.update(st, c, true, func(tx *bolt.Tx, next *state) error {
		if next.Pending == nil {
			return ErrRecovery
		}
		next.Pending.Phase = "recovery_required"
		g, e := loadGeneration(tx, next.Pending.After, c)
		if e != nil {
			return e
		}
		return writeState(tx, next, "recovery_required", next.Pending.Actor, next.Pending.Reason, g.Identity())
	})
}

func (p *persistence) update(st *state, c *Coordinator, allowReopen bool, mutate func(*bolt.Tx, *state) error) error {
	if e := p.healthy(); e != nil {
		return e
	}
	actual, e := p.read(c)
	if e != nil {
		return e
	}
	if digest(actual) != digest(st) {
		if !allowReopen || actual.Pending != nil || st.Pending == nil {
			return ErrRecovery
		}
		want := *st
		want.Pending = nil
		if digest(actual) != digest(want) || st.Pending.AtRevision != st.Revision || (st.Current != st.Pending.After && st.Current != st.Pending.Recovery) {
			return ErrRecovery
		}
	}
	next := *st
	if st.Pending != nil {
		in := *st.Pending
		next.Pending = &in
	}
	err := p.db.Update(func(tx *bolt.Tx) error { return mutate(tx, &next) })
	if err != nil {
		if errors.Is(err, ErrLimit) {
			return ErrLimit
		}
		return ErrRecovery
	}
	*st = next
	return nil
}

func (c *Coordinator) History() ([]Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, e := c.read(); e != nil {
		return nil, e
	}
	var events []Event
	err := c.persistence.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(eventBucket).ForEach(func(k, v []byte) error {
			var event Event
			if e := decode(v, &event, maxMetadataBytes); e != nil {
				return e
			}
			events = append(events, event)
			return nil
		})
	})
	return events, err
}
