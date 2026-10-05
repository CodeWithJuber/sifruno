// Package trail implements scoped, encrypted file checkpoints inspired by
// Ponytrail. It is a development recovery tool, not a database/host snapshot.
// Callers must quiesce external writers: the trail lock serializes trail
// clients, not arbitrary editors or services writing the declared scope.
package trail

import (
	"crypto/aes"
	"crypto/cipher"
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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

const maxFile = 2 << 20
const maxFiles = 64

type Image struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Hash   string `json:"hash"`
	Mode   uint32 `json:"mode"`
	Data   []byte `json:"data,omitempty"`
}
type Change struct {
	ID      string    `json:"id"`
	Root    string    `json:"root"`
	Reason  string    `json:"reason"`
	Actor   string    `json:"actor"`
	Parent  string    `json:"parent,omitempty"`
	Created time.Time `json:"created"`
	State   string    `json:"state"`
	Before  []Image   `json:"before"`
	After   []Image   `json:"after,omitempty"`
}
type Summary struct {
	ID      string    `json:"id"`
	Reason  string    `json:"reason"`
	Actor   string    `json:"actor"`
	Parent  string    `json:"parent,omitempty"`
	Created time.Time `json:"created"`
	State   string    `json:"state"`
	Files   int       `json:"files"`
}
type event struct {
	ChangeID     string    `json:"change_id"`
	State        string    `json:"state"`
	At           time.Time `json:"at"`
	Previous     string    `json:"previous"`
	ManifestHash string    `json:"manifest_hash"`
	Signature    string    `json:"signature"`
}
type Store struct {
	dir  string
	key  []byte
	mu   sync.Mutex
	lock *flock.Flock
}

func Open(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = rejectLinks(abs); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, err
	}
	if err = protectStore(abs); err != nil {
		return nil, err
	}
	for _, name := range []string{"writer.lock", "key", "changes", "events.jsonl"} {
		if err = rejectLinks(filepath.Join(abs, name)); err != nil {
			return nil, err
		}
	}
	lock := flock.New(filepath.Join(abs, "writer.lock"))
	if err = lock.Lock(); err != nil {
		return nil, err
	}
	defer lock.Unlock()
	keyPath := filepath.Join(abs, "key")
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Stat(filepath.Join(abs, "events.jsonl")); !errors.Is(e, os.ErrNotExist) {
			return nil, errors.New("trail key is missing from an existing journal")
		}
		if entries, e := os.ReadDir(filepath.Join(abs, "changes")); e == nil && len(entries) > 0 {
			return nil, errors.New("trail key is missing from existing checkpoints")
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		err = writeAtomic(keyPath, key, 0600)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("invalid trail encryption key")
	}
	if err = os.MkdirAll(filepath.Join(abs, "changes"), 0700); err != nil {
		return nil, err
	}
	if err = protectExistingEntries(abs); err != nil {
		return nil, err
	}
	s := &Store{dir: abs, key: key, lock: lock}
	if _, err = s.verifyLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// flock.Lock is reentrant on the same instance, so it needs this mutex as
// well as the OS lock to serialize goroutines and separate processes.
func (s *Store) acquire() error {
	s.mu.Lock()
	if e := s.lock.Lock(); e != nil {
		s.mu.Unlock()
		return e
	}
	return nil
}
func (s *Store) release()    { _ = s.lock.Unlock(); s.mu.Unlock() }
func digest(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func id() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
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
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func (s *Store) seal(b []byte) ([]byte, error) {
	block, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return g.Seal(nonce, nonce, b, []byte("sifruno-trail-v1")), nil
}
func (s *Store) unseal(b []byte) ([]byte, error) {
	block, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if len(b) < g.NonceSize() {
		return nil, errors.New("truncated encrypted checkpoint")
	}
	return g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], []byte("sifruno-trail-v1"))
}
func safePath(p string) (string, error) {
	for _, part := range strings.Split(strings.ReplaceAll(p, "\\", "/"), "/") {
		if part == ".." {
			return "", errors.New("traversal is excluded from checkpoints")
		}
	}
	p = filepath.Clean(filepath.FromSlash(p))
	if !filepath.IsLocal(p) || p == "." || strings.Contains(p, ":") {
		return "", errors.New("checkpoint paths must be relative files inside the declared root")
	}
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		low := strings.ToLower(part)
		if strings.HasPrefix(low, ".") || low == "node_modules" || low == "credentials" || low == "kubeconfig" || low == "key" || low == "writer.lock" || low == "events.jsonl" || strings.HasPrefix(low, "id_rsa") || strings.HasPrefix(low, "id_ed25519") || strings.HasSuffix(low, ".key") || strings.HasSuffix(low, ".pem") || strings.HasSuffix(low, ".p12") || strings.HasSuffix(low, ".pfx") {
			return "", errors.New("sensitive or private path excluded from checkpoints")
		}
	}
	return p, nil
}
func readImage(r *os.Root, p string, withData bool) (Image, error) {
	img := Image{Path: p, Hash: "absent"}
	// Reject all symlink components, even links pointing inside the root.
	var pathInfo os.FileInfo
	parts := strings.Split(filepath.ToSlash(p), "/")
	for n := range parts {
		name := filepath.Join(parts[:n+1]...)
		info, err := r.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			if n == len(parts)-1 {
				return img, nil
			}
			return img, fmt.Errorf("missing parent directory: %s", name)
		}
		if err != nil {
			return img, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return img, errors.New("symlinks are excluded from checkpoints")
		}
		if n < len(parts)-1 && !info.IsDir() {
			return img, errors.New("checkpoint parent must be a directory")
		}
		pathInfo = info
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Size() > maxFile {
		return img, errors.New("only regular files up to 2 MiB can be checkpointed")
	}
	f, err := r.Open(p)
	if err != nil {
		return img, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return img, err
	}
	if !os.SameFile(pathInfo, info) || !info.Mode().IsRegular() || info.Size() > maxFile {
		return img, errors.New("file changed while opening checkpoint")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return img, err
	}
	if len(data) > maxFile {
		return img, errors.New("file grew beyond snapshot limit")
	}
	afterInfo, err := f.Stat()
	if err != nil {
		return img, err
	}
	lastInfo, err := r.Lstat(p)
	if err != nil {
		return img, err
	}
	if lastInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, lastInfo) || info.Size() != afterInfo.Size() || !info.ModTime().Equal(afterInfo.ModTime()) || info.Mode() != afterInfo.Mode() {
		return img, errors.New("file changed while reading checkpoint")
	}
	img.Exists = true
	img.Hash = digest(data)
	img.Mode = uint32(info.Mode().Perm())
	if withData {
		img.Data = data
	}
	return img, nil
}
func (s *Store) read(changeID string) (Change, error) {
	var c Change
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(changeID) {
		return c, errors.New("invalid checkpoint id")
	}
	path := filepath.Join(s.dir, "changes", changeID+".enc")
	info, e := os.Lstat(path)
	if e != nil {
		return c, e
	}
	if !info.Mode().IsRegular() || info.Size() > maxManifest {
		return c, errors.New("invalid encrypted checkpoint file")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	b, e = s.unseal(b)
	if e != nil {
		return c, e
	}
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if c.ID != changeID {
		return c, errors.New("checkpoint identity differs from filename")
	}
	return c, validateChange(c)
}
func (s *Store) events() ([]event, error) {
	if e := rejectLinks(filepath.Join(s.dir, "events.jsonl")); e != nil {
		return nil, e
	}
	raw, e := os.ReadFile(filepath.Join(s.dir, "events.jsonl"))
	if errors.Is(e, os.ErrNotExist) {
		return []event{}, nil
	}
	if e != nil {
		return nil, e
	}
	events := []event{}
	previous := ""
	states := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var item event
		if e = json.Unmarshal([]byte(line), &item); e != nil {
			return nil, e
		}
		sig := item.Signature
		item.Signature = ""
		b, _ := json.Marshal(item)
		mac := hmac.New(sha256.New, s.key)
		mac.Write(b)
		if item.Previous != previous || !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			return nil, errors.New("trail event chain failed integrity verification")
		}
		state := states[item.ChangeID]
		valid := (state == "" && item.State == "checkpointed") || (state == "checkpointed" && item.State == "applied") || (state == "applied" && item.State == "recovering") || (state == "recovering" && item.State == "rolled_back")
		if !changeIDPattern.MatchString(item.ChangeID) || !hashPattern.MatchString(item.ManifestHash) || item.At.IsZero() || !valid {
			return nil, errors.New("invalid trail event state transition")
		}
		states[item.ChangeID] = item.State
		item.Signature = sig
		events = append(events, item)
		previous = sig
	}
	return events, nil
}
func (s *Store) persist(c Change) error {
	events, e := s.events()
	if e != nil {
		return e
	}
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	encrypted, e := s.seal(b)
	if e != nil {
		return e
	}
	if e = writeAtomic(filepath.Join(s.dir, "changes", c.ID+".enc"), encrypted, 0600); e != nil {
		return e
	}
	previous := ""
	if len(events) > 0 {
		previous = events[len(events)-1].Signature
	}
	ev := event{ChangeID: c.ID, State: c.State, At: time.Now().UTC(), Previous: previous, ManifestHash: digest(b)}
	raw, _ := json.Marshal(ev)
	mac := hmac.New(sha256.New, s.key)
	mac.Write(raw)
	ev.Signature = hex.EncodeToString(mac.Sum(nil))
	raw, _ = json.Marshal(ev)
	f, e := os.OpenFile(filepath.Join(s.dir, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(append(raw, '\n')); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return syncDirectory(s.dir)
}
func summary(c Change) Summary {
	return Summary{ID: c.ID, Reason: c.Reason, Actor: c.Actor, Parent: c.Parent, Created: c.Created, State: c.State, Files: len(c.Before)}
}
func (s *Store) Checkpoint(root string, paths []string, reason, actor string) (Summary, error) {
	if strings.TrimSpace(reason) == "" || strings.TrimSpace(actor) == "" || len(reason) > 500 || len(actor) > 100 {
		return Summary{}, errors.New("bounded reason and actor are required")
	}
	if len(paths) == 0 || len(paths) > maxFiles {
		return Summary{}, errors.New("checkpoint needs 1 to 64 explicit files")
	}
	if regexp.MustCompile(`(?i)(bearer\s+\S+|password\s*[:=]|api[_-]?key\s*[:=]|token\s*[:=]|-----BEGIN .*PRIVATE KEY)`).MatchString(reason + " " + actor) {
		return Summary{}, errors.New("secret-shaped metadata is not accepted")
	}
	if e := s.acquire(); e != nil {
		return Summary{}, e
	}
	defer s.release()
	events, e := s.verifyLocked()
	if e != nil {
		return Summary{}, e
	}
	root, e = filepath.Abs(root)
	if e != nil {
		return Summary{}, e
	}
	if e = rejectLinks(root); e != nil {
		return Summary{}, e
	}
	r, e := os.OpenRoot(root)
	if e != nil {
		return Summary{}, e
	}
	defer r.Close()
	changeID, e := id()
	if e != nil {
		return Summary{}, e
	}
	c := Change{ID: changeID, Root: root, Reason: reason, Actor: actor, Created: time.Now().UTC(), State: "checkpointed", Before: []Image{}}
	if len(events) > 0 {
		c.Parent = events[len(events)-1].ChangeID
	}
	seen := map[string]bool{}
	for _, p := range paths {
		p, e = safePath(p)
		if e != nil {
			return Summary{}, e
		}
		if seen[pathKey(p)] {
			return Summary{}, errors.New("duplicate checkpoint path")
		}
		seen[pathKey(p)] = true
		img, e := readImage(r, p, true)
		if e != nil {
			return Summary{}, e
		}
		c.Before = append(c.Before, img)
	}
	if e = s.persist(c); e != nil {
		return Summary{}, e
	}
	return summary(c), nil
}
func (s *Store) Seal(changeID string) (Summary, error) {
	if e := s.acquire(); e != nil {
		return Summary{}, e
	}
	defer s.release()
	if _, e := s.verifyLocked(); e != nil {
		return Summary{}, e
	}
	c, e := s.read(changeID)
	if e != nil {
		return Summary{}, e
	}
	if c.State != "checkpointed" {
		return Summary{}, errors.New("only checkpointed changes can be sealed")
	}
	if e = rejectLinks(c.Root); e != nil {
		return Summary{}, e
	}
	r, e := os.OpenRoot(c.Root)
	if e != nil {
		return Summary{}, e
	}
	defer r.Close()
	c.After = []Image{}
	for _, img := range c.Before {
		after, e := readImage(r, img.Path, false)
		if e != nil {
			return Summary{}, e
		}
		c.After = append(c.After, after)
	}
	c.State = "applied"
	if e = s.persist(c); e != nil {
		return Summary{}, e
	}
	return summary(c), nil
}
func restore(r *os.Root, img Image) error {
	if !img.Exists {
		e := r.Remove(img.Path)
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		return syncRootDirectory(r, filepath.Dir(img.Path))
	}
	restoreID, e := id()
	if e != nil {
		return e
	}
	tmp := filepath.Join(filepath.Dir(img.Path), "sifruno-restore-"+restoreID)
	f, e := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(img.Mode))
	if e != nil {
		return e
	}
	defer r.Remove(tmp)
	if _, e = f.Write(img.Data); e != nil {
		f.Close()
		return e
	}
	if e = f.Chmod(os.FileMode(img.Mode)); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = replaceRootedFile(r, tmp, img.Path); e != nil {
		return e
	}
	return syncRootDirectory(r, filepath.Dir(img.Path))
}
func same(a, b Image) bool {
	return a.Exists == b.Exists && a.Hash == b.Hash && (!a.Exists || a.Mode == b.Mode)
}
func (s *Store) Rollback(changeID string) (Summary, error) {
	if e := s.acquire(); e != nil {
		return Summary{}, e
	}
	defer s.release()
	if _, e := s.verifyLocked(); e != nil {
		return Summary{}, e
	}
	c, e := s.read(changeID)
	if e != nil {
		return Summary{}, e
	}
	if c.State != "applied" && c.State != "recovering" {
		return Summary{}, errors.New("rollback needs a sealed checkpoint")
	}
	if e = rejectLinks(c.Root); e != nil {
		return Summary{}, e
	}
	r, e := os.OpenRoot(c.Root)
	if e != nil {
		return Summary{}, e
	}
	defer r.Close()
	// Preflight every path before writing any path. Later edits are conflicts.
	for n, img := range c.Before {
		now, e := readImage(r, img.Path, false)
		if e != nil {
			return Summary{}, e
		}
		if !same(now, c.After[n]) && !(c.State == "recovering" && same(now, img)) {
			return Summary{}, fmt.Errorf("rollback conflict: %s changed after seal", img.Path)
		}
	}
	if c.State != "recovering" {
		c.State = "recovering"
		if e = s.persist(c); e != nil {
			return Summary{}, e
		}
	}
	for n, img := range c.Before {
		now, e := readImage(r, img.Path, false)
		if e != nil {
			return Summary{}, e
		}
		if same(now, img) {
			continue
		}
		if !same(now, c.After[n]) {
			return Summary{}, fmt.Errorf("rollback conflict: %s changed during recovery", img.Path)
		}
		if e = restore(r, img); e != nil {
			return Summary{}, e
		}
	}
	for _, img := range c.Before {
		now, e := readImage(r, img.Path, false)
		if e != nil {
			return Summary{}, e
		}
		if !same(now, img) {
			return Summary{}, errors.New("rollback verification failed")
		}
	}
	c.State = "rolled_back"
	if e = s.persist(c); e != nil {
		return Summary{}, e
	}
	return summary(c), nil
}
func (s *Store) verifyLocked() ([]event, error) {
	keyPath := filepath.Join(s.dir, "key")
	if e := rejectLinks(keyPath); e != nil {
		return nil, e
	}
	keyInfo, e := os.Lstat(keyPath)
	if e != nil {
		return nil, e
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Size() != 32 {
		return nil, errors.New("invalid trail encryption key file")
	}
	currentKey, e := os.ReadFile(keyPath)
	if e != nil {
		return nil, e
	}
	if !hmac.Equal(s.key, currentKey) {
		return nil, errors.New("trail encryption key changed after opening")
	}
	if e := rejectLinks(s.dir); e != nil {
		return nil, e
	}
	if e := rejectLinks(filepath.Join(s.dir, "changes")); e != nil {
		return nil, e
	}
	events, e := s.events()
	if e != nil {
		return nil, e
	}
	latest := map[string]event{}
	parents := map[string]string{}
	previous := ""
	for _, ev := range events {
		if _, exists := latest[ev.ChangeID]; !exists {
			parents[ev.ChangeID] = previous
		}
		latest[ev.ChangeID] = ev
		previous = ev.ChangeID
	}
	entries, e := os.ReadDir(filepath.Join(s.dir, "changes"))
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".write-") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".enc") || !entry.Type().IsRegular() {
			return nil, errors.New("unexpected entry in private checkpoint directory")
		}
		if _, exists := latest[strings.TrimSuffix(entry.Name(), ".enc")]; !exists {
			return nil, errors.New("orphan checkpoint has no committed event; recovery required")
		}
	}
	for changeID, ev := range latest {
		c, e := s.read(changeID)
		if e != nil {
			return nil, e
		}
		raw, _ := json.Marshal(c)
		if digest(raw) != ev.ManifestHash || c.State != ev.State || c.Parent != parents[changeID] {
			return nil, errors.New("checkpoint differs from its committed event; recovery required")
		}
	}
	return events, nil
}
func (s *Store) Verify() error {
	if e := s.acquire(); e != nil {
		return e
	}
	defer s.release()
	_, e := s.verifyLocked()
	return e
}
func (s *Store) List() ([]Summary, error) {
	if e := s.acquire(); e != nil {
		return nil, e
	}
	defer s.release()
	events, e := s.verifyLocked()
	if e != nil {
		return nil, e
	}
	items := []Summary{}
	seen := map[string]bool{}
	for _, ev := range events {
		if seen[ev.ChangeID] {
			continue
		}
		seen[ev.ChangeID] = true
		c, e := s.read(ev.ChangeID)
		if e != nil {
			return nil, e
		}
		items = append(items, summary(c))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Created.After(items[j].Created) })
	return items, nil
}
