package whmapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// SessionRecord is one issued one-time login session. The session token is
// stored as a SHA-256 digest; plaintext appears only in the create response.
type SessionRecord struct {
	ID        string `json:"id"`
	User      string `json:"user"`
	Service   string `json:"service"`
	Locale    string `json:"locale,omitempty"`
	SHA256    string `json:"sha256"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

type sessionFile struct {
	Sessions map[string]SessionRecord `json:"sessions"`
}

// SessionStore persists one-time login sessions (0600, locked, atomic),
// mirroring the observed reference TTL of 300 seconds.
type SessionStore struct {
	mu       sync.RWMutex
	path     string
	sessions map[string]SessionRecord
}

// SessionTTL is the observed reference session lifetime (300s, batch-3/6
// captures).
const SessionTTL = 300 * time.Second

// OpenSessionStore loads path; a missing file is an empty store.
func OpenSessionStore(path string) (*SessionStore, error) {
	if path == "" {
		return nil, errors.New("whmapi: session store path required")
	}
	s := &SessionStore{path: path, sessions: map[string]SessionRecord{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f sessionFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("whmapi: session store parse: %w", err)
	}
	for id, rec := range f.Sessions {
		if rec.ID != id || rec.User == "" || len(rec.SHA256) != 64 || rec.ExpiresAt <= rec.CreatedAt {
			return nil, fmt.Errorf("whmapi: session record %q invalid", id)
		}
		s.sessions[id] = rec
	}
	return s, nil
}

// NewMemorySessionStore returns a non-persistent store for tests.
func NewMemorySessionStore() *SessionStore {
	return &SessionStore{sessions: map[string]SessionRecord{}}
}

var validSessionServices = map[string]string{
	// service -> observed port used in the login URL
	"cpaneld":   "2083",
	"webmaild":  "2096",
	"whostmgrd": "2087",
}

const tokenLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randomLetters(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	out := make([]byte, n)
	for i, v := range raw {
		out[i] = tokenLetters[int(v)%len(tokenLetters)]
	}
	return string(out)
}

func randomDigits(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	out := make([]byte, n)
	for i, v := range raw {
		out[i] = '0' + v%10
	}
	return string(out)
}

// IssuedSession carries the plaintext pieces returned once at creation.
type IssuedSession struct {
	Record       SessionRecord
	SessionToken string // <user>:<letters>:create_user_session,<32hex>
	SecToken     string // /cpsess<digits>
}

// Create issues a session for user. The caller must have verified the user
// exists; expiry is 300s (observed).
func (s *SessionStore) Create(user, service, locale string) (IssuedSession, error) {
	if user == "" {
		return IssuedSession{}, errors.New("whmapi: session user required")
	}
	if _, ok := validSessionServices[service]; !ok {
		return IssuedSession{}, errors.New("whmapi: invalid session service")
	}
	letters := randomLetters(16)
	hexraw := make([]byte, 16)
	if _, err := rand.Read(hexraw); err != nil {
		return IssuedSession{}, err
	}
	token := fmt.Sprintf("%s:%s:create_user_session,%s", user, letters, hex.EncodeToString(hexraw))
	now := time.Now()
	rec := SessionRecord{
		ID:        "cpsess" + randomDigits(10),
		User:      user,
		Service:   service,
		Locale:    locale,
		SHA256:    fmt.Sprintf("%x", sha256.Sum256([]byte(token))),
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(SessionTTL).Unix(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[rec.ID] = rec
	if err := s.persistLocked(); err != nil {
		delete(s.sessions, rec.ID)
		return IssuedSession{}, err
	}
	return IssuedSession{Record: rec, SessionToken: token, SecToken: "/" + rec.ID}, nil
}

// Validate checks a presented session token against the store. Expired
// sessions are purged and refused.
func (s *SessionStore) Validate(token string) (SessionRecord, bool) {
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for id, rec := range s.sessions {
		if rec.ExpiresAt <= now {
			delete(s.sessions, id)
			continue
		}
		if rec.SHA256 == digest {
			return rec, true
		}
	}
	return SessionRecord{}, false
}

// PurgeExpired drops expired records; called on writes.
func (s *SessionStore) PurgeExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	n := 0
	for id, rec := range s.sessions {
		if rec.ExpiresAt <= now {
			delete(s.sessions, id)
			n++
		}
	}
	if n > 0 {
		_ = s.persistLocked()
	}
	return n
}

// List returns metadata of live sessions, sorted by creation time.
func (s *SessionStore) List() []SessionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SessionRecord, 0, len(s.sessions))
	now := time.Now().Unix()
	for _, rec := range s.sessions {
		if rec.ExpiresAt > now {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

func (s *SessionStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	lock := flock.New(s.path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	raw, err := json.Marshal(sessionFile{Sessions: s.sessions})
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
