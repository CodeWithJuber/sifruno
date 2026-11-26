// Package hostpkgs persists hosting packages (WHM "packages" / plan
// templates) as a root-only JSON store. The default key set and value types
// mirror cPanel 138's getpkginfo output: mixed string/null/number values are
// preserved as given for envelope fidelity.
package hostpkgs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"sync"

	"github.com/gofrs/flock"
)

var (
	ErrConflict = errors.New("hostpkgs: package already exists")
	ErrNotFound = errors.New("hostpkgs: package does not exist")
	ErrInvalid  = errors.New("hostpkgs: invalid package name")
)

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_ -]{0,63}$`)

// Store is a locked, atomically-written package store.
type Store struct {
	mu   sync.RWMutex
	path string
	pkgs map[string]map[string]any
}

// Open loads path; a missing file is an empty store (not an error).
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("hostpkgs: store path required")
	}
	s := &Store{path: path, pkgs: map[string]map[string]any{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.pkgs); err != nil {
		return nil, fmt.Errorf("hostpkgs: parse: %w", err)
	}
	for name := range s.pkgs {
		if !namePattern.MatchString(name) {
			return nil, fmt.Errorf("hostpkgs: invalid stored name %q", name)
		}
	}
	return s, nil
}

// NewMemory returns a non-persistent store for tests.
func NewMemory() *Store { return &Store{pkgs: map[string]map[string]any{}} }

// defaults returns the observed cPanel 138 package key set. Overridable
// parameters map quota→QUOTA, bwlimit→BWLIMIT, maxpop→MAXPOP,
// maxaddon→MAXADDON, featurelist→FEATURELIST (observed param names).
func defaults() map[string]any {
	return map[string]any{
		"HASSHELL": 0, "CPMOD": "jupiter", "MAXADDON": nil, "BWLIMIT": nil,
		"MAXLST": nil, "FRONTPAGE": 0, "MAX_EMAILACCT_QUOTA": "unlimited",
		"MAXFTP": nil, "MAXPASSENGERAPPS": "unlimited", "MAXTEAMUSERS": nil,
		"QUOTA": nil, "PACKAGE_TYPE": "standard", "MAX_TEAM_USERS": "7",
		"FEATURELIST": "default", "MAX_DEFER_FAIL_PERCENTAGE": "unlimited",
		"MAXSUB": nil, "CGI": 0, "_PACKAGE_EXTENSIONS": "", "MAXPARK": nil,
		"IP": 0, "DIGESTAUTH": "n", "MAX_EMAIL_PER_HOUR": "unlimited",
		"MAXPOP": nil, "LANG": "en", "MAXSQL": nil,
	}
}

// paramToKey maps observed WHM addpkg parameters to stored keys.
var paramToKey = map[string]string{
	"quota": "QUOTA", "bwlimit": "BWLIMIT", "maxpop": "MAXPOP",
	"maxaddon": "MAXADDON", "maxpark": "MAXPARK", "maxsub": "MAXSUB",
	"maxftp": "MAXFTP", "maxsql": "MAXSQL", "maxlst": "MAXLST",
	"featurelist": "FEATURELIST", "cgi": "CGI", "hasshell": "HASSHELL",
	"ip": "IP", "lang": "LANG",
}

// Create stores a new package with the observed default key set plus caller
// overrides (WHM parameter names). Values are stored as strings, matching
// the observed serialization ("1024", "unlimited").
func (s *Store) Create(name string, overrides map[string]string) error {
	if !namePattern.MatchString(name) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pkgs[name]; exists {
		return ErrConflict
	}
	pkg := defaults()
	for k, v := range overrides {
		key, ok := paramToKey[k]
		if !ok {
			return fmt.Errorf("hostpkgs: unsupported parameter %q", k)
		}
		pkg[key] = v
	}
	pkg["name"] = name // present in listpkgs entries (observed)
	s.pkgs[name] = pkg
	if err := s.persistLocked(); err != nil {
		delete(s.pkgs, name)
		return err
	}
	return nil
}

// Delete removes a package or returns ErrNotFound.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pkgs[name]; !exists {
		return ErrNotFound
	}
	delete(s.pkgs, name)
	return s.persistLocked()
}

// Get returns a copy of one package (without the list-only name key),
// matching the observed getpkginfo data.pkg object.
func (s *Store) Get(name string) (map[string]any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pkg, ok := s.pkgs[name]
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(pkg))
	for k, v := range pkg {
		if k == "name" {
			continue
		}
		out[k] = v
	}
	return out, true
}

// Has reports whether a package exists.
func (s *Store) Has(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.pkgs[name]
	return ok
}

// List returns every package including the name key, sorted by name for
// stable output (listpkgs data.pkg array entries, observed).
func (s *Store) List() []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.pkgs))
	for name := range s.pkgs {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		pkg := make(map[string]any, len(s.pkgs[name]))
		for k, v := range s.pkgs[name] {
			pkg[k] = v
		}
		out = append(out, pkg)
	}
	return out
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	lock := flock.New(s.path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	raw, err := json.Marshal(s.pkgs)
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
