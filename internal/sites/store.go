package sites

import (
	"bytes"
	"encoding/json"
	"errors"
	"html"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/securestate"
	"sifruno/internal/trail"
)

type pendingChange struct {
	Action      string   `json:"action"`
	Checkpoints []string `json:"checkpoints"`
}
type record struct {
	Version                  int            `json:"version"`
	Site                     Site           `json:"site"`
	Owner                    string         `json:"owner"`
	Files                    []FileInfo     `json:"files"`
	Backups                  []BackupInfo   `json:"backups"`
	ChangeIDs                []string       `json:"change_ids"`
	Pending                  *pendingChange `json:"pending,omitempty"`
	RemovedBackup            *backupRemoval `json:"removed_backup,omitempty"` // signed last explicit removal, not a ZIP restore checkpoint
	RetiredScheduledBackupID string         `json:"retired_scheduled_backup_id,omitempty"`
}
type Store struct {
	mu                sync.Mutex
	dir               string
	root              *os.Root
	rootInfo          os.FileInfo
	dbInfo            os.FileInfo
	db                *bolt.DB
	journal           *trail.Store
	closed            bool
	siteRemovalStep   func(string) error // isolated website removal failure injection
	backupRemovalStep func(string) error // isolated failure injection, never configured by production
}

var bucket = []byte("sites-v1")

func Open(dir string, journal *trail.Store) (*Store, error) {
	if journal == nil || journal.Verify() != nil {
		return nil, ErrUnavailable
	}
	abs, err := securestate.Dir(dir)
	if err != nil {
		return nil, ErrUnavailable
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, ErrUnavailable
	}
	ok := false
	defer func() {
		if !ok {
			root.Close()
		}
	}()
	rootInfo, err := root.Lstat(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	if err = root.Mkdir("data", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrUnavailable
	}
	if checkParents(root, "data") != nil || securestate.CheckPath(filepath.Join(abs, "sites.db")) != nil {
		return nil, ErrUnavailable
	}
	f, err := root.OpenFile("sites.db", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	dbInfo, err := f.Stat()
	if err == nil {
		err = guardHandle(f, dbInfo)
	}
	f.Close()
	if err != nil {
		return nil, ErrUnavailable
	}
	db, err := bolt.Open(filepath.Join(abs, "sites.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, ErrUnavailable
	}
	s := &Store{dir: abs, root: root, rootInfo: rootInfo, dbInfo: dbInfo, db: db, journal: journal}
	if err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(backupScheduleBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(backupRemovalBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(siteRemovalBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	items, err := s.records()
	if err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	if _, err = s.backupSchedules(); err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	if err = s.validateSiteRemovals(); err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	if err = s.validateBackupRemovals(); err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	for _, r := range items {
		removal, removalErr := s.loadSiteRemoval(r.Site.ID)
		if removalErr != nil {
			db.Close()
			return nil, ErrUnavailable
		}
		if removal != nil {
			_ = s.finishSiteRemoval(*removal)
			continue
		}
		if r.Pending == nil {
			if err = s.verify(r); err != nil {
				db.Close()
				return nil, ErrUnavailable
			}
		}
		v, e := s.loadBackupRemoval(r.Site.ID)
		if e != nil {
			db.Close()
			return nil, ErrUnavailable
		}
		if v != nil {
			_ = s.finishBackupRemoval(*v)
		}
	}
	d, err := root.Open("data")
	if err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	entries, err := d.ReadDir(MaxSites + 1)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		db.Close()
		return nil, ErrUnavailable
	}
	known := map[string]bool{}
	for _, r := range items {
		known[r.Site.ID] = true
	}
	for _, e := range entries {
		if !known[e.Name()] || !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			db.Close()
			return nil, ErrUnavailable
		}
	}
	ok = true
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	e := s.db.Close()
	r := s.root.Close()
	if e != nil || r != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) healthy() error {
	if s.closed || securestate.CheckPath(s.dir) != nil || checkParents(s.root, "sites.db") != nil {
		return ErrUnavailable
	}
	root, err := os.Lstat(s.dir)
	if err != nil || !os.SameFile(root, s.rootInfo) {
		return ErrUnavailable
	}
	f, err := s.root.Open("sites.db")
	if err != nil {
		return ErrUnavailable
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !os.SameFile(i, s.dbInfo) || i.Size() < 4096 || guardHandle(f, i) != nil {
		return ErrUnavailable
	}
	return nil
}
func validateRecord(r record) error {
	if r.RetiredScheduledBackupID != "" && !identifier.MatchString(r.RetiredScheduledBackupID) {
		return ErrUnavailable
	}
	if r.RemovedBackup != nil && (!validBackupRemoval(*r.RemovedBackup) || r.RemovedBackup.SiteID != r.Site.ID || r.RemovedBackup.Revision >= r.Site.Revision) {
		return ErrUnavailable
	}
	if r.Version != 1 || r.Owner != "local-operator" || !identifier.MatchString(r.Site.ID) || r.Site.Revision == 0 || !validName(r.Site.Name) || r.Site.PreviewHost != "site-"+r.Site.ID+".localhost" || r.Site.CreatedAt.IsZero() || r.Site.UpdatedAt.IsZero() || (r.Site.State != "active" && r.Site.State != "suspended") {
		return ErrUnavailable
	}
	d, err := canonicalDomain(r.Site.Domain)
	if err != nil || d != r.Site.Domain {
		return ErrUnavailable
	}
	if len(r.Files) > MaxFiles || len(r.Backups) > MaxBackups || len(r.ChangeIDs) > 3 {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	var size int64
	for _, f := range r.Files {
		k := strings.ToLower(f.Path)
		if safeFile(f.Path) != nil || seen[k] || f.Bytes < 0 || f.Bytes > MaxFileBytes || !hashPattern.MatchString(f.SHA256) {
			return ErrUnavailable
		}
		seen[k] = true
		size += f.Bytes
	}
	if size > MaxSiteBytes {
		return ErrUnavailable
	}
	seen = map[string]bool{}
	size = 0
	for _, b := range r.Backups {
		if !identifier.MatchString(b.ID) || seen[b.ID] || b.SiteID != r.Site.ID || b.CreatedAt.IsZero() || b.Revision == 0 || b.Revision > r.Site.Revision || b.Files < 1 || b.Files > MaxFiles || b.Bytes < 1 || b.Bytes > MaxBackupBytes || !hashPattern.MatchString(b.SHA256) {
			return ErrUnavailable
		}
		seen[b.ID] = true
		size += b.Bytes
	}
	if size > MaxBackupStorage {
		return ErrUnavailable
	}
	for _, id := range r.ChangeIDs {
		if !identifier.MatchString(id) {
			return ErrUnavailable
		}
	}
	if r.Pending != nil && (len(r.Pending.Checkpoints) > 3 || r.Pending.Action == "") {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) records() ([]record, error) {
	items := []record{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return ErrUnavailable
		}
		return b.ForEach(func(k, v []byte) error {
			if len(items) >= MaxSites || v == nil || len(v) > MaxFileBytes {
				return ErrUnavailable
			}
			var r record
			if json.Unmarshal(v, &r) != nil || string(k) != r.Site.ID || validateRecord(r) != nil {
				return ErrUnavailable
			}
			items = append(items, r)
			return nil
		})
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return items, nil
}
func (s *Store) load(id string) (record, error) {
	if !identifier.MatchString(id) {
		return record{}, ErrNotFound
	}
	var r record
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return ErrUnavailable
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		if len(v) > MaxFileBytes || json.Unmarshal(v, &r) != nil || r.Site.ID != id {
			return ErrUnavailable
		}
		return validateRecord(r)
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return r, ErrNotFound
		}
		return r, ErrUnavailable
	}
	return r, nil
}
func (s *Store) save(r record) error {
	if validateRecord(r) != nil {
		return ErrUnavailable
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxFileBytes {
		return ErrUnavailable
	}
	if s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put([]byte(r.Site.ID), raw) }) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) siteRoot(id string) (*os.Root, error) {
	p := "data/" + id
	if checkParents(s.root, p) != nil || securestate.CheckPath(filepath.Join(s.dir, filepath.FromSlash(p))) != nil {
		return nil, ErrUnavailable
	}
	r, err := s.root.OpenRoot(p)
	if err != nil {
		return nil, ErrUnavailable
	}
	return r, nil
}
func (s *Store) verify(r record) error {
	if removal, err := s.loadSiteRemoval(r.Site.ID); err != nil || removal != nil {
		return ErrUnavailable
	}
	if r.Pending != nil || len(r.ChangeIDs) == 0 || s.journal.Verify() != nil {
		return ErrUnavailable
	}
	rt, err := s.siteRoot(r.Site.ID)
	if err != nil {
		return err
	}
	defer rt.Close()
	raw, err := readRoot(rt, "state.json", MaxFileBytes)
	if err != nil {
		return ErrUnavailable
	}
	expected, _ := json.Marshal(r)
	if !bytes.Equal(raw, expected) {
		return ErrUnavailable
	}
	for _, id := range r.ChangeIDs {
		if s.journal.VerifyCurrent(id) != nil {
			return ErrUnavailable
		}
	}
	return nil
}
func (s *Store) checked(id string) (record, error) {
	if s.healthy() != nil {
		return record{}, ErrUnavailable
	}
	r, err := s.load(id)
	if err != nil {
		return r, err
	}
	if v, e := s.loadBackupRemoval(id); e != nil || v != nil {
		return r, ErrUnavailable
	}
	return r, s.verify(r)
}
func exposed(r record) Site {
	v := r.Site
	if r.Pending != nil {
		v.State = "recovery_required"
	}
	return v
}
func (s *Store) List() ([]Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.healthy() != nil {
		return nil, ErrUnavailable
	}
	rs, err := s.records()
	if err != nil {
		return nil, err
	}
	result := []Site{}
	for _, r := range rs {
		removal, e := s.loadSiteRemoval(r.Site.ID)
		if e != nil {
			return nil, e
		}
		if removal == nil && r.Pending == nil && s.verify(r) != nil {
			return nil, ErrUnavailable
		}
		v := exposed(r)
		if removal != nil {
			v.State = "recovery_required"
		}
		if pending, e := s.loadBackupRemoval(r.Site.ID); e != nil {
			return nil, e
		} else if pending != nil {
			v.State = "recovery_required"
		}
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result, nil
}
func (s *Store) Get(id string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.healthy() != nil {
		return Site{}, ErrUnavailable
	}
	r, err := s.load(id)
	if err != nil {
		return Site{}, err
	}
	removal, e := s.loadSiteRemoval(id)
	if e != nil {
		return Site{}, e
	}
	if removal == nil && r.Pending == nil && s.verify(r) != nil {
		return Site{}, ErrUnavailable
	}
	v := exposed(r)
	if removal != nil {
		v.State = "recovery_required"
	}
	if pending, e := s.loadBackupRemoval(id); e != nil {
		return Site{}, e
	} else if pending != nil {
		v.State = "recovery_required"
	}
	return v, nil
}

func (s *Store) Create(input CreateInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || !validName(input.Name) {
		return Site{}, ErrInvalid
	}
	data := map[string][]byte{"index.html": []byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.EscapeString(input.Name) + "</title></head><body><h1>" + html.EscapeString(input.Name) + "</h1><p>This app-owned static website is being served by Sifruno.</p></body></html>")}
	return s.create(input, data, "create", actor)
}

// create installs a complete prevalidated catalog with one pending operation.
// The caller holds s.mu; this shared path never commits files one at a time.
func (s *Store) create(input CreateInput, data map[string][]byte, action, actor string) (Site, error) {
	if !validActor(actor) || !validName(input.Name) {
		return Site{}, ErrInvalid
	}
	domain, err := canonicalDomain(input.Domain)
	if err != nil {
		return Site{}, err
	}
	files, err := fileCatalog(data)
	if err != nil {
		return Site{}, err
	}
	if s.healthy() != nil {
		return Site{}, ErrUnavailable
	}
	rs, err := s.records()
	if err != nil {
		return Site{}, err
	}
	if len(rs) >= MaxSites {
		return Site{}, ErrInvalid
	}
	for _, r := range rs {
		if r.Site.Domain == domain {
			return Site{}, ErrDomainTaken
		}
	}
	id, err := newID()
	if err != nil {
		return Site{}, err
	}
	now := time.Now().UTC()
	r := record{Version: 1, Owner: "local-operator", Site: Site{ID: id, Name: input.Name, Domain: domain, PreviewHost: "site-" + id + ".localhost", State: "active", Revision: 1, CreatedAt: now, UpdatedAt: now}, Files: []FileInfo{}, Backups: []BackupInfo{}, ChangeIDs: []string{}, Pending: &pendingChange{Action: action, Checkpoints: []string{}}}
	if s.save(r) != nil {
		return Site{}, ErrUnavailable
	}
	if _, err = securestate.Dir(filepath.Join(s.dir, "data", id)); err != nil {
		return Site{}, ErrUnavailable
	}
	rt, err := s.siteRoot(id)
	if err != nil {
		return Site{}, err
	}
	defer rt.Close()
	if err = rt.Mkdir("content", 0700); err != nil {
		return Site{}, ErrUnavailable
	}
	if err = rt.Mkdir("backups", 0700); err != nil {
		return Site{}, ErrUnavailable
	}
	next := r
	next.Pending = nil
	next.Files = files
	if s.change(r, next, data, action, actor) != nil {
		return Site{}, ErrUnavailable
	}
	return next.Site, nil
}
func (s *Store) Files(id string) ([]FileInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.checked(id)
	if err != nil {
		return nil, err
	}
	if _, err = s.snapshot(r); err != nil {
		return nil, err
	}
	return append([]FileInfo{}, r.Files...), nil
}
func (s *Store) ReadFile(id, p string) (FileContent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if safeFile(p) != nil {
		return FileContent{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return FileContent{}, err
	}
	var expected *FileInfo
	for i := range r.Files {
		if r.Files[i].Path == p {
			expected = &r.Files[i]
		}
	}
	if expected == nil {
		return FileContent{}, ErrNotFound
	}
	rt, err := s.siteRoot(id)
	if err != nil {
		return FileContent{}, err
	}
	defer rt.Close()
	data, err := readRoot(rt, "content/"+p, MaxFileBytes)
	if err != nil {
		return FileContent{}, ErrUnavailable
	}
	if sum(data) != expected.SHA256 || int64(len(data)) != expected.Bytes {
		return FileContent{}, ErrConflict
	}
	if !utf8.Valid(data) {
		return FileContent{}, ErrInvalid
	}
	return FileContent{Path: p, Content: string(data), SHA256: expected.SHA256, Revision: r.Site.Revision}, nil
}
func (s *Store) WriteFile(id string, input WriteInput, actor string) (Site, error) {
	if len(input.Content) > MaxFileBytes || !utf8.ValidString(input.Content) {
		return Site{}, ErrInvalid
	}
	return s.writeFile(id, input.Path, []byte(input.Content), input.ExpectedSHA256, input.ExpectedRevision, actor)
}

// UploadFile requires an absent destination and reuses signed writes and recovery.
// Even an existing empty file has a nonempty hash, so it cannot be overwritten.
func (s *Store) UploadFile(id string, input UploadInput, actor string) (Site, error) {
	return s.writeFile(id, input.Path, input.Content, "", input.ExpectedRevision, actor)
}

// ReplaceFile never creates a missing destination; its nonempty hash requires
// the exact existing bytes through the same signed write and recovery path.
func (s *Store) ReplaceFile(id string, input ReplaceInput, actor string) (Site, error) {
	if !hashPattern.MatchString(input.ExpectedSHA256) || input.ExpectedRevision == 0 {
		return Site{}, ErrInvalid
	}
	return s.writeFile(id, input.Path, input.Content, input.ExpectedSHA256, input.ExpectedRevision, actor)
}

func (s *Store) writeFile(id, path string, content []byte, expectedSHA256 string, expectedRevision uint64, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || safeFile(path) != nil || len(content) > MaxFileBytes || (expectedSHA256 != "" && !hashPattern.MatchString(expectedSHA256)) {
		return Site{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision != expectedRevision || r.Site.Revision == math.MaxUint64 {
		return Site{}, ErrConflict
	}
	data, err := s.snapshot(r)
	if err != nil {
		return Site{}, err
	}
	existing, found := data[path]
	if (!found && expectedSHA256 != "") || (found && sum(existing) != expectedSHA256) {
		return Site{}, ErrConflict
	}
	for p := range data {
		if p != path && strings.EqualFold(p, path) {
			return Site{}, ErrInvalid
		}
	}
	data[path] = content
	files, err := fileCatalog(data)
	if err != nil {
		return Site{}, err
	}
	next := r
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	next.Files = files
	if err = s.change(r, next, data, "write", actor); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}

// DeleteInput binds a deletion to the exact saved file and site revision.
type DeleteInput struct {
	Path             string `json:"path"`
	ExpectedSHA256   string `json:"expected_sha256"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

// DeleteFile removes one existing regular static-site file through the same
// signed checkpoints and interruption recovery used by writes and restores.
// It never recursively removes directories; an empty site remains valid.
func (s *Store) DeleteFile(id string, input DeleteInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || safeFile(input.Path) != nil || !hashPattern.MatchString(input.ExpectedSHA256) {
		return Site{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision != input.ExpectedRevision || r.Site.Revision == math.MaxUint64 {
		return Site{}, ErrConflict
	}
	data, err := s.snapshot(r)
	if err != nil {
		return Site{}, err
	}
	existing, found := data[input.Path]
	if !found {
		return Site{}, ErrNotFound
	}
	if sum(existing) != input.ExpectedSHA256 {
		return Site{}, ErrConflict
	}
	delete(data, input.Path)
	files := []FileInfo{}
	if len(data) != 0 {
		files, err = fileCatalog(data)
		if err != nil {
			return Site{}, err
		}
	}
	next := r
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	next.Files = files
	if err = s.change(r, next, data, "delete", actor); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}

func (s *Store) SetState(id string, input StateInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || (input.State != "active" && input.State != "suspended") {
		return Site{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision != input.ExpectedRevision || r.Site.Revision == math.MaxUint64 {
		return Site{}, ErrConflict
	}
	if _, err = s.snapshot(r); err != nil {
		return Site{}, err
	}
	next := r
	next.Site.State = input.State
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	if err = s.change(r, next, nil, "state", actor); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}

func (s *Store) snapshot(r record) (map[string][]byte, error) {
	rt, err := s.siteRoot(r.Site.ID)
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	if checkParents(rt, "content") != nil {
		return nil, ErrUnavailable
	}
	result := map[string][]byte{}
	expected := map[string]FileInfo{}
	for _, f := range r.Files {
		expected[f.Path] = f
	}
	nodes := 0
	var walk func(string) error
	walk = func(dir string) error {
		if checkParents(rt, "content/"+dir) != nil {
			return ErrUnavailable
		}
		f, err := rt.Open("content/" + dir)
		if err != nil {
			return ErrUnavailable
		}
		entries, err := f.ReadDir(MaxFiles*9 + 1)
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return ErrUnavailable
		}
		if len(entries) > MaxFiles*9 {
			return ErrUnavailable
		}
		for _, e := range entries {
			nodes++
			if nodes > MaxFiles*9 {
				return ErrUnavailable
			}
			name := e.Name()
			p := name
			if dir != "." {
				p = dir + "/" + name
			}
			if e.Type()&os.ModeSymlink != 0 {
				return ErrUnavailable
			}
			if e.IsDir() {
				if !segmentPattern.MatchString(name) {
					return ErrUnavailable
				}
				if err = walk(p); err != nil {
					return err
				}
				continue
			}
			info, ok := expected[p]
			if !ok || safeFile(p) != nil {
				return ErrUnavailable
			}
			data, err := readRoot(rt, "content/"+p, MaxFileBytes)
			if err != nil {
				return ErrUnavailable
			}
			if int64(len(data)) != info.Bytes || sum(data) != info.SHA256 {
				return ErrConflict
			}
			result[p] = data
		}
		return nil
	}
	if err = walk("."); err != nil {
		return nil, err
	}
	if len(result) != len(r.Files) {
		return nil, ErrConflict
	}
	return result, nil
}

// change records an interruption marker in bbolt before touching files. The
// scoped signed before/after checkpoints reuse trail; failures roll back only
// after the actual partial result has been sealed. Unrecoverable interruptions
// remain visible as recovery_required and are never served as success.
func (s *Store) change(current, next record, data map[string][]byte, action, actor string) error {
	rt, err := s.siteRoot(current.Site.ID)
	if err != nil {
		return err
	}
	defer rt.Close()
	pending := current
	pending.Pending = &pendingChange{Action: action, Checkpoints: []string{}}
	if s.save(pending) != nil {
		return ErrUnavailable
	}
	paths := []string{"state.json"}
	if data != nil {
		seen := map[string]bool{}
		for _, f := range current.Files {
			seen[f.Path] = true
		}
		for p := range data {
			seen[p] = true
		}
		for p := range seen {
			paths = append(paths, "content/"+p)
		}
		sort.Strings(paths[1:])
	}
	for _, p := range paths {
		if makeParents(rt, p) != nil {
			return ErrUnavailable
		}
	}
	for i := 0; i < len(paths); i += 64 {
		end := i + 64
		if end > len(paths) {
			end = len(paths)
		}
		cp, e := s.journal.Checkpoint(filepath.Join(s.dir, "data", current.Site.ID), paths[i:end], "site "+action+" "+current.Site.ID, actor)
		if e != nil {
			return ErrUnavailable
		}
		pending.Pending.Checkpoints = append(pending.Pending.Checkpoints, cp.ID)
		if s.save(pending) != nil {
			return ErrUnavailable
		}
	}
	next.Pending = nil
	next.ChangeIDs = append([]string{}, pending.Pending.Checkpoints...)
	failed := false
	if data != nil {
		for _, p := range paths[1:] {
			name := strings.TrimPrefix(p, "content/")
			if b, ok := data[name]; ok {
				if atomicRoot(rt, p, b) != nil {
					failed = true
					break
				}
			} else {
				if checkParents(rt, p) != nil || rt.Remove(p) != nil || syncRoot(rt, filepath.Dir(p)) != nil {
					failed = true
					break
				}
			}
		}
	}
	if !failed {
		raw, _ := json.Marshal(next)
		failed = atomicRoot(rt, "state.json", raw) != nil
	}
	// A crash here leaves the signed state transition incomplete. Explicit ZIP
	// removal retains its intent and bytes; reopening does not infer a commit.
	if action == "remove-backup" && !failed && s.removalStep("after_state_write") != nil {
		return ErrUnavailable
	}
	for _, id := range pending.Pending.Checkpoints {
		if _, e := s.journal.Seal(id); e != nil {
			return ErrUnavailable
		}
	}
	if !failed {
		if s.save(next) == nil {
			return nil
		}
		failed = true
	}
	if failed {
		for i := len(pending.Pending.Checkpoints) - 1; i >= 0; i-- {
			if _, e := s.journal.Rollback(pending.Pending.Checkpoints[i]); e != nil {
				return ErrUnavailable
			}
		}
		if current.Pending == nil && s.save(current) == nil {
			return ErrUnavailable
		}
	}
	return ErrUnavailable
}
