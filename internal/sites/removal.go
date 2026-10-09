package sites

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	bolt "go.etcd.io/bbolt"
)

var siteRemovalBucket = []byte("native-site-removals-v1")

type RemoveInput struct {
	ExpectedRevision   uint64 `json:"expected_revision"`
	ConfirmationDomain string `json:"confirmation_domain"`
	Confirmed          bool   `json:"confirmed"`
}
type RemovedSite struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Revision uint64 `json:"revision"`
	Removed  bool   `json:"removed"`
}

// The immutable signed manifest lives outside the removed site's directory.
// Only hashes/metadata enter trail; archives can exceed its file size limit.
// A pending row gates serving and mutations before any unlink. Records/domain
// reservation remain until all exact owned bytes and empty directories are gone.
type siteRemoval struct {
	SiteID       string `json:"site_id"`
	AuditID      string `json:"audit_id"`
	CheckpointID string `json:"checkpoint_id"`
}
type siteRemovalManifest struct {
	Record         record   `json:"record"`
	ScheduleSHA256 string   `json:"schedule_sha256"`
	Directories    []string `json:"directories"`
}

func (s *Store) siteRemovalStepAt(phase string) error {
	if s.siteRemovalStep != nil {
		return s.siteRemovalStep(phase)
	}
	return nil
}
func (s *Store) loadSiteRemoval(id string) (*siteRemoval, error) {
	var result *siteRemoval
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(siteRemovalBucket)
		if b == nil {
			return ErrUnavailable
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		var v siteRemoval
		if len(raw) > 4096 || json.Unmarshal(raw, &v) != nil || v.SiteID != id || !identifier.MatchString(v.SiteID) || !identifier.MatchString(v.AuditID) || !identifier.MatchString(v.CheckpointID) {
			return ErrUnavailable
		}
		canonical, _ := json.Marshal(v)
		if !bytes.Equal(raw, canonical) {
			return ErrUnavailable
		}
		result = &v
		return nil
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}
func (s *Store) validateSiteRemovals() error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(siteRemovalBucket)
		if b == nil || b.Stats().KeyN > MaxSites {
			return ErrUnavailable
		}
		return b.ForEach(func(k, raw []byte) error {
			var v siteRemoval
			if raw == nil || len(raw) > 4096 || tx.Bucket(bucket).Get(k) == nil || json.Unmarshal(raw, &v) != nil || v.SiteID != string(k) || !identifier.MatchString(v.SiteID) || !identifier.MatchString(v.AuditID) || !identifier.MatchString(v.CheckpointID) {
				return ErrUnavailable
			}
			canonical, _ := json.Marshal(v)
			if !bytes.Equal(raw, canonical) {
				return ErrUnavailable
			}
			return nil
		})
	})
}
func (s *Store) removalScheduleSHA(id string) (string, error) {
	job, _, err := s.loadBackupSchedule(id)
	if err != nil || job.Run != nil {
		return "", ErrUnavailable
	}
	var digest string
	err = s.db.View(func(tx *bolt.Tx) error { digest = sum(tx.Bucket(backupScheduleBucket).Get([]byte(id))); return nil })
	return digest, err
}
func removalFiles(r record) (map[string]FileInfo, map[string]bool) {
	raw, _ := json.Marshal(r)
	files := map[string]FileInfo{"state.json": {Path: "state.json", Bytes: int64(len(raw)), SHA256: sum(raw)}}
	// securestate.Dir creates this exact ownership marker for each site root.
	marker := []byte("private Sifruno application state\n")
	files[".sifruno-state"] = FileInfo{Path: ".sifruno-state", Bytes: int64(len(marker)), SHA256: sum(marker)}
	dirs := map[string]bool{".": true, "content": true, "backups": true}
	for _, f := range r.Files {
		f.Path = "content/" + f.Path
		files[f.Path] = f
		for p := path.Dir(f.Path); p != "."; p = path.Dir(p) {
			dirs[p] = true
		}
	}
	for _, b := range r.Backups {
		p := "backups/" + b.ID + ".zip"
		files[p] = FileInfo{Path: p, Bytes: b.Bytes, SHA256: b.SHA256}
	}
	return files, dirs
}

// Enumerate the entire bounded tree before touching any bytes. Unknown entries,
// links, hardlinks and changed bytes all refuse. Ordinary bounded empty content
// directories left by supported moves/deletes are admitted into the signed intent.
// After commitment only missing known entries are accepted for crash recovery.
func (s *Store) inspectRemoval(r record, partial bool, admitted []string) ([]string, []string, error) {
	base := "data/" + r.Site.ID
	if checkParents(s.root, "data") != nil {
		return nil, nil, ErrUnavailable
	}
	if _, err := s.root.Lstat(base); errors.Is(err, os.ErrNotExist) && partial {
		return nil, nil, nil
	}
	rt, err := s.siteRoot(r.Site.ID)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer rt.Close()
	expected, expectedDirs := removalFiles(r)
	if partial {
		expectedDirs = map[string]bool{}
		for _, dir := range admitted {
			expectedDirs[dir] = true
		}
	}
	files, dirs := []string{}, []string{}
	var walk func(string) error
	walk = func(dir string) error {
		if len(files)+len(dirs) > MaxFiles*9+MaxBackups+3 || checkParents(rt, dir) != nil {
			return ErrUnavailable
		}
		if !expectedDirs[dir] && (partial || !strings.HasPrefix(dir, "content/") || safeFile(strings.TrimPrefix(dir, "content/")+"/probe.html") != nil) {
			return ErrUnavailable
		}
		dirs = append(dirs, dir)
		f, e := rt.Open(dir)
		if e != nil {
			return ErrUnavailable
		}
		entries, e := f.ReadDir(MaxFiles*9 + MaxBackups + 4)
		f.Close()
		if e != nil && !errors.Is(e, io.EOF) {
			return ErrUnavailable
		}
		if len(entries) > MaxFiles*9+MaxBackups+3 {
			return ErrUnavailable
		}
		for _, entry := range entries {
			name := path.Join(dir, entry.Name())
			if entry.Type()&os.ModeSymlink != 0 {
				return ErrUnavailable
			}
			if entry.IsDir() {
				if e = walk(name); e != nil {
					return e
				}
				continue
			}
			want, ok := expected[name]
			if !ok {
				return ErrUnavailable
			}
			raw, e := readRoot(rt, name, want.Bytes)
			if e != nil || int64(len(raw)) != want.Bytes || sum(raw) != want.SHA256 {
				return ErrUnavailable
			}
			files = append(files, name)
		}
		return nil
	}
	if err = walk("."); err != nil {
		return nil, nil, err
	}
	if !partial && (len(files) != len(expected) || len(dirs) < len(expectedDirs)) {
		return nil, nil, ErrUnavailable
	}
	sort.Strings(files)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	return files, dirs, nil
}

func (s *Store) removalManifest(v siteRemoval) (siteRemovalManifest, error) {
	var m siteRemovalManifest
	raw, err := readRoot(s.root, "removals/"+v.AuditID+".json", MaxFileBytes)
	if err != nil || json.Unmarshal(raw, &m) != nil || validateRecord(m.Record) != nil || m.Record.Pending != nil || m.Record.Site.ID != v.SiteID || !hashPattern.MatchString(m.ScheduleSHA256) {
		return m, ErrUnavailable
	}
	canonical, _ := json.Marshal(m)
	if !bytes.Equal(raw, canonical) || len(m.Directories) < 3 || len(m.Directories) > MaxFiles*9+MaxBackups+3 {
		return m, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, dir := range m.Directories {
		if seen[dir] || (dir != "." && dir != "content" && dir != "backups" && (!strings.HasPrefix(dir, "content/") || safeFile(strings.TrimPrefix(dir, "content/")+"/probe.html") != nil)) {
			return m, ErrUnavailable
		}
		seen[dir] = true
	}
	_, required := removalFiles(m.Record)
	for dir := range required {
		if !seen[dir] {
			return m, ErrUnavailable
		}
	}
	// The signed reason binds the manifest hash as well as identity, so an
	// unrelated applied checkpoint cannot authorize a substituted manifest.
	history, err := s.journal.List()
	if err != nil {
		return m, ErrUnavailable
	}
	matched := false
	for _, cp := range history {
		if cp.ID == v.CheckpointID && cp.Reason == "site remove "+v.SiteID+" "+sum(raw) && cp.Actor == "local-operator" && cp.State == "applied" && cp.Files == 1 {
			matched = true
			break
		}
	}
	if !matched || s.journal.VerifyCurrent(v.CheckpointID) != nil {
		return m, ErrUnavailable
	}
	r, err := s.load(v.SiteID)
	before, _ := json.Marshal(r)
	expected, _ := json.Marshal(m.Record)
	digest, e := s.removalScheduleSHA(v.SiteID)
	if err != nil || e != nil || !bytes.Equal(before, expected) || digest != m.ScheduleSHA256 {
		return m, ErrUnavailable
	}
	return m, nil
}

func (s *Store) finishSiteRemoval(v siteRemoval) error {
	m, err := s.removalManifest(v)
	if err != nil {
		return err
	}
	files, dirs, err := s.inspectRemoval(m.Record, true, m.Directories)
	if err != nil {
		return err
	}
	if len(dirs) != 0 {
		rt, e := s.siteRoot(v.SiteID)
		if e != nil {
			return e
		}
		expected, _ := removalFiles(m.Record)
		for _, name := range files {
			want := expected[name]
			if s.siteRemovalStepAt("before_unlink") != nil {
				rt.Close()
				return ErrUnavailable
			}
			raw, e := readRoot(rt, name, want.Bytes)
			if e != nil || int64(len(raw)) != want.Bytes || sum(raw) != want.SHA256 || checkParents(rt, name) != nil || rt.Remove(name) != nil || syncRoot(rt, path.Dir(name)) != nil {
				rt.Close()
				return ErrUnavailable
			}
			if s.siteRemovalStepAt("after_unlink") != nil {
				rt.Close()
				return ErrUnavailable
			}
		}
		for _, dir := range dirs {
			if dir == "." {
				continue
			}
			if checkParents(rt, dir) != nil || rt.Remove(dir) != nil || syncRoot(rt, path.Dir(dir)) != nil {
				rt.Close()
				return ErrUnavailable
			}
		}
		rt.Close()
		if checkParents(s.root, "data/"+v.SiteID) != nil || s.root.Remove("data/"+v.SiteID) != nil || syncRoot(s.root, "data") != nil {
			return ErrUnavailable
		}
	}
	if syncRoot(s.root, "data") != nil || s.siteRemovalStepAt("after_directory") != nil {
		return ErrUnavailable
	}
	// Parent, schedule and pending intent leave in the same durable transaction.
	if err = s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{backupScheduleBucket, backupRemovalBucket, bucket, siteRemovalBucket} {
			if err := tx.Bucket(name).Delete([]byte(v.SiteID)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) Remove(id string, in RemoveInput, actor string) (RemovedSite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || !identifier.MatchString(id) || !in.Confirmed || in.ExpectedRevision == 0 || in.ExpectedRevision > maxScheduleRevision || len(in.ConfirmationDomain) > 253 {
		return RemovedSite{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return RemovedSite{}, err
	}
	if r.Site.Revision != in.ExpectedRevision || r.Site.Domain != in.ConfirmationDomain {
		return RemovedSite{}, ErrConflict
	}
	digest, err := s.removalScheduleSHA(id)
	if err != nil {
		return RemovedSite{}, err
	}
	_, dirs, err := s.inspectRemoval(r, false, nil)
	if err != nil {
		return RemovedSite{}, err
	}
	auditID, err := newID()
	if err != nil {
		return RemovedSite{}, err
	}
	if makeParents(s.root, "removals/"+auditID+".json") != nil || syncRoot(s.root, ".") != nil {
		return RemovedSite{}, ErrUnavailable
	}
	raw, _ := json.Marshal(siteRemovalManifest{Record: r, ScheduleSHA256: digest, Directories: dirs})
	if atomicRoot(s.root, "removals/"+auditID+".json", raw) != nil || s.siteRemovalStepAt("before_seal") != nil {
		return RemovedSite{}, ErrUnavailable
	}
	cp, err := s.journal.Checkpoint(s.dir, []string{"removals/" + auditID + ".json"}, "site remove "+id+" "+sum(raw), actor)
	if err != nil {
		return RemovedSite{}, ErrUnavailable
	}
	if _, err = s.journal.Seal(cp.ID); err != nil {
		return RemovedSite{}, ErrUnavailable
	}
	if s.siteRemovalStepAt("before_intent") != nil {
		return RemovedSite{}, ErrUnavailable
	}
	v := siteRemoval{SiteID: id, AuditID: auditID, CheckpointID: cp.ID}
	intent, _ := json.Marshal(v)
	if s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(siteRemovalBucket).Put([]byte(id), intent) }) != nil || s.siteRemovalStepAt("after_intent") != nil {
		return RemovedSite{}, ErrUnavailable
	}
	if err = s.finishSiteRemoval(v); err != nil {
		return RemovedSite{}, err
	}
	return RemovedSite{ID: id, Domain: r.Site.Domain, Revision: r.Site.Revision, Removed: true}, nil
}
