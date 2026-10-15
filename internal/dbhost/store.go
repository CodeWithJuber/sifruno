package dbhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Registry is the dbmap: which panel account owns which prefixed database
// and user. JSON file with atomic replace; the reference keeps this in
// /var/cpanel/databases — sifruno keeps it in the panel state dir.
type Registry struct {
	path string
	mu   sync.Mutex
	data registryData
}

type registryData struct {
	Databases map[string]Database `json:"databases"`
	Users     map[string]User     `json:"users"`
}

func OpenRegistry(path string) (*Registry, error) {
	r := &Registry{path: path, data: registryData{
		Databases: map[string]Database{}, Users: map[string]User{},
	}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &r.data); err != nil {
		return nil, err
	}
	if r.data.Databases == nil {
		r.data.Databases = map[string]Database{}
	}
	if r.data.Users == nil {
		r.data.Users = map[string]User{}
	}
	return r, nil
}

func (r *Registry) flush() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

func (r *Registry) putDatabase(d Database) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data.Databases[d.Name] = d
	return r.flush()
}

func (r *Registry) dropDatabase(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.data.Databases, name)
	return r.flush()
}

func (r *Registry) putUser(u User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data.Users[u.Name] = u
	return r.flush()
}

func (r *Registry) dropUser(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.data.Users, name)
	return r.flush()
}

func (r *Registry) databases(owner string) []Database {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Database{}
	for _, d := range r.data.Databases {
		if owner == "" || d.Owner == owner {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *Registry) users(owner string) []User {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []User{}
	for _, u := range r.data.Users {
		if owner == "" || u.Owner == owner {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *Registry) ownerOf(name string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.data.Databases[name]; ok {
		return d.Owner, true
	}
	if u, ok := r.data.Users[name]; ok {
		return u.Owner, true
	}
	return "", false
}
