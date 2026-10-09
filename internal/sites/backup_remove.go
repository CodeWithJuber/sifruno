package sites

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

var backupRemovalBucket = []byte("native-backup-removals-v1")

func (s *Store) validateBackupRemovals() error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(backupRemovalBucket)
		if b.Stats().KeyN > MaxSites {
			return ErrUnavailable
		}
		return b.ForEach(func(k, raw []byte) error {
			var v backupRemoval
			if raw == nil || len(raw) > 4096 || tx.Bucket(bucket).Get(k) == nil || json.Unmarshal(raw, &v) != nil || string(k) != v.SiteID || !validBackupRemoval(v) {
				return ErrUnavailable
			}
			return nil
		})
	})
}

// Only identity/metadata is persisted. ZIPs exceed trail's file limit. Signed
// catalog removal must commit before unlink, and is never rolled back afterward.
type backupRemoval struct {
	SiteID       string     `json:"site_id"`
	Revision     uint64     `json:"revision"`
	Backup       BackupInfo `json:"backup"`
	BeforeSHA256 string     `json:"before_sha256"`
	AfterSHA256  string     `json:"after_sha256"`
}

func removalCatalogSHA(r record) string {
	r.Pending = nil
	r.ChangeIDs = []string{}
	r.RemovedBackup = nil
	raw, _ := json.Marshal(r)
	return sum(raw)
}

func validBackupRemoval(v backupRemoval) bool {
	b := v.Backup
	return identifier.MatchString(v.SiteID) && v.Revision > 0 && v.Revision < maxScheduleRevision && b.SiteID == v.SiteID && identifier.MatchString(b.ID) && hashPattern.MatchString(b.SHA256) && b.Bytes > 0 && b.Bytes <= MaxBackupBytes && b.Files > 0 && b.Files <= MaxFiles && !b.CreatedAt.IsZero() && b.Revision > 0 && b.Revision <= v.Revision && hashPattern.MatchString(v.BeforeSHA256) && hashPattern.MatchString(v.AfterSHA256)
}

func (s *Store) loadBackupRemoval(id string) (*backupRemoval, error) {
	var result *backupRemoval
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(backupRemovalBucket).Get([]byte(id))
		if raw == nil {
			return nil
		}
		var v backupRemoval
		if len(raw) > 4096 || json.Unmarshal(raw, &v) != nil || v.SiteID != id || !validBackupRemoval(v) {
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

func (s *Store) clearBackupRemoval(id string) error {
	if s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(backupRemovalBucket).Delete([]byte(id)) }) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) removalStep(phase string) error {
	if s.backupRemovalStep != nil {
		return s.backupRemovalStep(phase)
	}
	return nil
}

// Reopen resolves only a proven signed before/after catalog. Uncertain state is
// kept as recovery_required, never treated as permission to remove other bytes.
func (s *Store) finishBackupRemoval(v backupRemoval) error {
	r, err := s.load(v.SiteID)
	if err != nil || s.verify(r) != nil {
		return ErrUnavailable
	}
	found := false
	for _, b := range r.Backups {
		if b.ID == v.Backup.ID {
			if b != v.Backup {
				return ErrUnavailable
			}
			found = true
		}
	}
	if r.Site.Revision == v.Revision && found && removalCatalogSHA(r) == v.BeforeSHA256 {
		return s.clearBackupRemoval(v.SiteID)
	}
	if r.Site.Revision != v.Revision+1 || found || r.RemovedBackup == nil || *r.RemovedBackup != v || removalCatalogSHA(r) != v.AfterSHA256 {
		return ErrUnavailable
	}
	if _, err = s.snapshot(r); err != nil {
		return ErrUnavailable
	}
	rt, err := s.siteRoot(v.SiteID)
	if err != nil {
		return err
	}
	defer rt.Close()
	name := "backups/" + v.Backup.ID + ".zip"
	if checkParents(rt, "backups") != nil {
		return ErrUnavailable
	}
	_, err = rt.Lstat(name)
	if !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return ErrUnavailable
		}
		raw, e := readRoot(rt, name, MaxBackupBytes)
		if e != nil || int64(len(raw)) != v.Backup.Bytes || sum(raw) != v.Backup.SHA256 {
			return ErrUnavailable
		}
		if s.removalStep("before_unlink") != nil || checkParents(rt, name) != nil || rt.Remove(name) != nil {
			return ErrUnavailable
		}
	}
	if s.removalStep("after_unlink") != nil || syncRoot(rt, "backups") != nil {
		return ErrUnavailable
	}
	return s.clearBackupRemoval(v.SiteID)
}

func (s *Store) RemoveBackup(id string, in RemoveBackupInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || !identifier.MatchString(id) || !identifier.MatchString(in.BackupID) || !hashPattern.MatchString(in.ExpectedBackupSHA256) || !in.Confirmed || in.ExpectedRevision == 0 || in.ExpectedRevision >= maxScheduleRevision {
		return Site{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision != in.ExpectedRevision {
		return Site{}, ErrConflict
	}
	job, _, err := s.loadBackupSchedule(id)
	if err != nil {
		return Site{}, err
	}
	if job.Run != nil {
		return Site{}, ErrUnavailable
	}
	index := -1
	for i, b := range r.Backups {
		if b.ID == in.BackupID {
			index = i
		}
	}
	if index < 0 {
		return Site{}, ErrNotFound
	}
	b := r.Backups[index]
	if b.SHA256 != in.ExpectedBackupSHA256 {
		return Site{}, ErrConflict
	}
	if _, err = s.snapshot(r); err != nil {
		return Site{}, err
	}
	rt, err := s.siteRoot(id)
	if err != nil {
		return Site{}, err
	}
	raw, err := readRoot(rt, "backups/"+b.ID+".zip", MaxBackupBytes)
	rt.Close()
	if err != nil {
		return Site{}, ErrUnavailable
	}
	if _, err = parseArchive(raw, b); err != nil {
		return Site{}, ErrUnavailable
	}
	next := r
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	next.Backups = append(append([]BackupInfo{}, r.Backups[:index]...), r.Backups[index+1:]...)
	if job.Schedule.LastStatus == "completed" && job.Schedule.LastBackupID == b.ID {
		next.RetiredScheduledBackupID = b.ID
	}
	v := backupRemoval{SiteID: id, Revision: r.Site.Revision, Backup: b, BeforeSHA256: removalCatalogSHA(r), AfterSHA256: removalCatalogSHA(next)}
	next.RemovedBackup = &v
	intent, _ := json.Marshal(v)
	if s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(backupRemovalBucket).Put([]byte(id), intent) }) != nil {
		return Site{}, ErrUnavailable
	}
	if s.removalStep("before_metadata") != nil {
		return Site{}, ErrUnavailable
	}
	if err = s.change(r, next, nil, "remove-backup", actor); err != nil {
		return Site{}, err
	}
	if s.removalStep("after_metadata") != nil {
		return Site{}, ErrUnavailable
	}
	if err = s.finishBackupRemoval(v); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}
