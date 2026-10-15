package whmapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// TokenInfo is the public metadata of an issued API token. The token value
// itself is never stored in clear and never listed.
type TokenInfo struct {
	Name       string `json:"name"`
	User       string `json:"user"`
	CreateTime int64  `json:"create_time"`
}

type tokenRecord struct {
	User       string `json:"user"`
	SHA256     string `json:"sha256"`
	CreateTime int64  `json:"create_time"`
}

type tokenFile struct {
	Tokens map[string]tokenRecord `json:"tokens"`
}

var (
	ErrTokenConflict    = errors.New("whmapi: token name already exists")
	ErrInvalidTokenName = errors.New("whmapi: invalid token name")
)

// Observed on the reference: names are ≤50 chars from a-z A-Z 0-9 _ -
var tokenNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,50}$`)

// TokenStore is a persistent, hashed WHM API token store. Tokens are stored
// as SHA-256 digests; the plaintext is returned exactly once at creation.
// An absent backing file denies every credential (fail closed).
type TokenStore struct {
	mu      sync.RWMutex
	path    string // empty = in-memory (tests)
	tokens  map[string]tokenRecord
	lastMod time.Time // last loaded file mtime; zero = never loaded from disk
}

// reloadIfChanged picks up tokens issued by panelctl while the panel runs —
// the operator issuance flow must not require a panel restart. Callers hold
// the write lock.
func (s *TokenStore) reloadIfChanged() {
	if s.path == "" {
		return
	}
	info, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) || err != nil {
		return
	}
	if !info.ModTime().After(s.lastMod) {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f tokenFile
	if json.Unmarshal(raw, &f) != nil {
		return // keep the last good state on a torn/invalid write
	}
	fresh := map[string]tokenRecord{}
	for name, rec := range f.Tokens {
		if tokenNamePattern.MatchString(name) && rec.User != "" && len(rec.SHA256) == 64 {
			fresh[name] = rec
		}
	}
	s.tokens = fresh
	s.lastMod = info.ModTime()
}

// OpenTokenStore loads the root-only token file at path. A missing file is
// an empty store, not an error.
func OpenTokenStore(path string) (*TokenStore, error) {
	if path == "" {
		return nil, errors.New("whmapi: token store path required")
	}
	s := &TokenStore{path: path, tokens: map[string]tokenRecord{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f tokenFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("whmapi: token store parse: %w", err)
	}
	for name, rec := range f.Tokens {
		if !tokenNamePattern.MatchString(name) || rec.User == "" || len(rec.SHA256) != 64 {
			return nil, fmt.Errorf("whmapi: token store entry %q invalid", name)
		}
		s.tokens[name] = rec
	}
	return s, nil
}

// NewMemoryTokenStore returns a non-persistent store for tests.
func NewMemoryTokenStore() *TokenStore {
	return &TokenStore{tokens: map[string]tokenRecord{}}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Authenticate implements Authenticator: constant-time digest comparison.
func (s *TokenStore) Authenticate(user, credential string) bool {
	if user == "" || credential == "" {
		return false
	}
	digest := hashToken(credential)
	s.mu.Lock()
	s.reloadIfChanged()
	s.mu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rec := range s.tokens {
		if rec.User == user && subtle.ConstantTimeCompare([]byte(rec.SHA256), []byte(digest)) == 1 {
			return true
		}
	}
	return false
}

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Create issues a new 64-character token, stores only its digest and returns
// the plaintext once. Duplicate names and invalid names are refused with the
// observed reference error wording handled by the caller.
func (s *TokenStore) Create(user, name string) (string, TokenInfo, error) {
	if user == "" {
		return "", TokenInfo{}, errors.New("whmapi: token user required")
	}
	if !tokenNamePattern.MatchString(name) {
		return "", TokenInfo{}, ErrInvalidTokenName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tokens[name]; exists {
		return "", TokenInfo{}, ErrTokenConflict
	}
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		return "", TokenInfo{}, err
	}
	out := make([]byte, 64)
	for i, v := range raw {
		out[i] = tokenAlphabet[int(v)%len(tokenAlphabet)]
	}
	token := string(out)
	info := TokenInfo{Name: name, User: user, CreateTime: time.Now().Unix()}
	s.tokens[name] = tokenRecord{User: user, SHA256: hashToken(token), CreateTime: info.CreateTime}
	if err := s.persistLocked(); err != nil {
		delete(s.tokens, name)
		return "", TokenInfo{}, err
	}
	return token, info, nil
}

// Revoke removes a token by name. It is idempotent, matching the observed
// reference behavior (repeat revoke returns success).
func (s *TokenStore) Revoke(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, name)
	return s.persistLocked()
}

// List returns public metadata for every issued token, names sorted for
// stable output. No digests or plaintext are exposed.
func (s *TokenStore) List() []TokenInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TokenInfo, 0, len(s.tokens))
	for name, rec := range s.tokens {
		out = append(out, TokenInfo{Name: name, User: rec.User, CreateTime: rec.CreateTime})
	}
	return out
}

// persistLocked writes the store atomically (0600, tmp+rename, locked).
// Callers must hold mu.
func (s *TokenStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	lock := flock.New(s.path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	raw, err := json.Marshal(tokenFile{Tokens: s.tokens})
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
	// Root-only directory entry; best-effort tighten on existing files.
	_ = os.Chmod(filepath.Clean(s.path), 0600)
	return nil
}
