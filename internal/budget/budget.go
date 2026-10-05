// Package budget is the local development AI spending guard. It does not call
// providers. Production adapters must reserve a verified worst-case price and
// reconcile provider billing; a filesystem backup is not a billing authority.
package budget

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"sifruno/internal/securestate"
)

const DefaultCap int64 = 10_000_000
const maxRecords = 10000
const maxLedgerBytes = 8 << 20

var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Approval struct {
	ID              string    `json:"id"`
	OperationSHA256 string    `json:"operation_sha256"`
	Revision        string    `json:"revision"`
	Actor           string    `json:"actor"`
	MaxCost         int64     `json:"max_cost_usd_micros"`
	Expires         time.Time `json:"expires"`
	Used            bool      `json:"used"`
}
type Reservation struct {
	ID              string    `json:"id"`
	ApprovalID      string    `json:"approval_id"`
	OperationSHA256 string    `json:"operation_sha256"`
	Revision        string    `json:"revision"`
	Month           string    `json:"month"`
	Reserved        int64     `json:"reserved_usd_micros"`
	Actual          int64     `json:"actual_usd_micros"`
	State           string    `json:"state"`
	Created         time.Time `json:"created"`
}
type Status struct {
	Month                  string `json:"month"`
	Cap                    int64  `json:"cap_usd_micros"`
	Reserved               int64  `json:"reserved_usd_micros"`
	Spent                  int64  `json:"spent_usd_micros"`
	Remaining              int64  `json:"remaining_usd_micros"`
	ApprovalRequired       bool   `json:"approval_required"`
	OverCap                bool   `json:"over_cap"`
	ReconciliationRequired bool   `json:"reconciliation_required"`
}
type ledger struct {
	Version                int                    `json:"version"`
	Cap                    int64                  `json:"cap"`
	Approvals              map[string]Approval    `json:"approvals"`
	Reservations           map[string]Reservation `json:"reservations"`
	MAC                    string                 `json:"mac"`
	ReconciliationRequired bool                   `json:"reconciliation_required"`
}
type Store struct {
	dir  string
	cap  int64
	key  []byte
	mu   sync.Mutex
	lock *flock.Flock
	now  func() time.Time
}

func Open(dir string, cap int64) (*Store, error) { return openClock(dir, cap, time.Now) }
func openClock(dir string, cap int64, now func() time.Time) (*Store, error) {
	if cap <= 0 || cap > DefaultCap {
		return nil, errors.New("cap must be positive and at most $10")
	}
	dir, err := securestate.Dir(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, cap: cap, lock: flock.New(filepath.Join(dir, "writer.lock")), now: now}
	if err = s.checkPaths(); err != nil {
		return nil, err
	}
	if err = s.lock.Lock(); err != nil {
		return nil, err
	}
	defer s.lock.Unlock()
	createdKey := false
	s.key, err = readKey(filepath.Join(dir, "key"))
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Stat(filepath.Join(dir, "ledger.json")); e == nil {
			return nil, errors.New("budget key missing; cannot reset existing spend")
		}
		s.key = make([]byte, 32)
		if _, err = rand.Read(s.key); err == nil {
			err = atomicWrite(filepath.Join(dir, "key"), s.key)
			createdKey = err == nil
		}
	}
	if err != nil {
		return nil, err
	}
	if len(s.key) != 32 {
		return nil, errors.New("invalid budget key")
	}
	if _, err = s.read(); errors.Is(err, os.ErrNotExist) {
		if !createdKey {
			return nil, errors.New("budget ledger missing; refusing to reset existing spend")
		}
		err = s.write(ledger{Version: 1, Cap: cap, Approvals: map[string]Approval{}, Reservations: map[string]Reservation{}})
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}
func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".budget-write-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func (s *Store) sign(l ledger) string {
	l.MAC = ""
	raw, _ := json.Marshal(l)
	h := hmac.New(sha256.New, s.key)
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) read() (ledger, error) {
	if err := s.checkPaths(); err != nil {
		return ledger{}, err
	}
	key, err := readKey(filepath.Join(s.dir, "key"))
	if err != nil {
		return ledger{}, err
	}
	if !hmac.Equal(key, s.key) {
		return ledger{}, errors.New("budget key changed; refusing cached-key operations")
	}
	var l ledger
	f, err := os.Open(filepath.Join(s.dir, "ledger.json"))
	if err != nil {
		return l, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxLedgerBytes+1))
	if err != nil {
		return l, err
	}
	if len(raw) > maxLedgerBytes {
		return l, errors.New("budget ledger too large")
	}
	if err = json.Unmarshal(raw, &l); err != nil {
		return l, err
	}
	if l.Version != 1 || l.Cap != s.cap || l.Approvals == nil || l.Reservations == nil || len(l.Approvals) > maxRecords || len(l.Reservations) > maxRecords {
		return l, errors.New("budget ledger schema or cap mismatch")
	}
	if !hmac.Equal([]byte(l.MAC), []byte(s.sign(l))) {
		return l, errors.New("budget ledger integrity failure")
	}
	return l, nil
}

func readKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, errors.New("invalid budget key size")
	}
	return raw, nil
}
func (s *Store) write(l ledger) error {
	l.MAC = s.sign(l)
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if len(raw) > maxLedgerBytes {
		return errors.New("budget ledger size limit reached; prior state preserved")
	}
	return atomicWrite(filepath.Join(s.dir, "ledger.json"), raw)
}
func (s *Store) locked(fn func(*ledger) error, mutate bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkPaths(); err != nil {
		return err
	}
	if err := s.lock.Lock(); err != nil {
		return err
	}
	defer s.lock.Unlock()
	l, err := s.read()
	if err != nil {
		return err
	}
	if err = fn(&l); err != nil {
		return err
	}
	if mutate {
		return s.write(l)
	}
	return nil
}

func (s *Store) checkPaths() error {
	for _, name := range []string{"writer.lock", "key", "ledger.json"} {
		path := filepath.Join(s.dir, name)
		if err := securestate.CheckPath(path); err != nil {
			return err
		}
		if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
			return errors.New("budget state files must be regular files")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func randomID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func status(l *ledger, month string) Status {
	st := Status{Month: month, Cap: l.Cap, ApprovalRequired: true, ReconciliationRequired: l.ReconciliationRequired}
	for _, r := range l.Reservations {
		if r.State == "reserved" {
			st.Reserved += r.Reserved
		}
		if r.Month == month && r.State == "settled" {
			st.Spent += r.Actual
		}
	}
	st.Remaining = st.Cap - st.Reserved - st.Spent
	st.OverCap = st.Remaining < 0
	if st.Remaining < 0 || st.ReconciliationRequired {
		st.Remaining = 0
	}
	return st
}
func (s *Store) Status() (Status, error) {
	var st Status
	err := s.locked(func(l *ledger) error { st = status(l, s.now().UTC().Format("2006-01")); return nil }, false)
	return st, err
}

// Approve records a local operator grant bound to an operation digest, relevant
// state revision, price ceiling and short expiration. No remote approval API.
func (s *Store) Approve(operation, revision, actor string, maxCost int64, ttl time.Duration) (Approval, error) {
	var a Approval
	if !shaPattern.MatchString(operation) || !regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`).MatchString(revision) || len(actor) < 1 || len(actor) > 100 || maxCost <= 0 || maxCost > s.cap || ttl <= 0 || ttl > 20*time.Minute {
		return a, errors.New("invalid bounded operator approval")
	}
	err := s.locked(func(l *ledger) error {
		if len(l.Approvals) >= maxRecords {
			return errors.New("approval ledger limit reached")
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		a = Approval{ID: id, OperationSHA256: operation, Revision: revision, Actor: actor, MaxCost: maxCost, Expires: s.now().UTC().Add(ttl)}
		l.Approvals[id] = a
		return nil
	}, true)
	return a, err
}
func (s *Store) Reserve(id, approvalID, operation, currentRevision string, amount int64) (Reservation, error) {
	var r Reservation
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`).MatchString(id) || amount <= 0 || amount > s.cap {
		return r, errors.New("invalid reservation id or amount")
	}
	err := s.locked(func(l *ledger) error {
		if len(l.Reservations) >= maxRecords {
			return errors.New("reservation ledger limit reached")
		}
		if _, ok := l.Reservations[id]; ok {
			return errors.New("reservation replay rejected")
		}
		a, ok := l.Approvals[approvalID]
		if !ok || a.Used || !s.now().UTC().Before(a.Expires) || a.OperationSHA256 != operation || a.Revision != currentRevision || amount > a.MaxCost {
			return errors.New("approval missing, stale, replayed or bound to different operation/state/cost")
		}
		month := s.now().UTC().Format("2006-01")
		if status(l, month).Remaining < amount {
			return errors.New("monthly AI/JEV cap exhausted")
		}
		a.Used = true
		l.Approvals[a.ID] = a
		r = Reservation{ID: id, ApprovalID: a.ID, OperationSHA256: operation, Revision: currentRevision, Month: month, Reserved: amount, State: "reserved", Created: s.now().UTC()}
		l.Reservations[id] = r
		return nil
	}, true)
	return r, err
}

// Settle must receive reconciled provider usage. Unresolved calls stay reserved
// even across UTC month changes. Under-estimate failures are recorded as spend,
// block further work, and return an error; they are never silently discarded.
func (s *Store) Settle(id string, actual int64) (Reservation, error) {
	var r Reservation
	if actual < 0 || actual > 1_000_000_000_000 {
		return r, errors.New("invalid actual cost")
	}
	over := false
	err := s.locked(func(l *ledger) error {
		var ok bool
		r, ok = l.Reservations[id]
		if !ok || r.State != "reserved" {
			return errors.New("unknown or already settled reservation")
		}
		over = actual > r.Reserved
		if over {
			l.ReconciliationRequired = true
		}
		r.Actual = actual
		r.Month = s.now().UTC().Format("2006-01")
		r.State = "settled"
		l.Reservations[id] = r
		return nil
	}, true)
	if err == nil && over {
		return r, fmt.Errorf("actual usage exceeded reserved maximum: provider reconciliation required")
	}
	return r, err
}
