package sites

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

const maxScheduleRevision uint64 = 9007199254740991

var backupScheduleBucket = []byte("native-backup-schedules-v1")

// BackupSchedule is native static-site metadata, never a host/cPanel backup.
type BackupSchedule struct {
	SiteID       string     `json:"site_id"`
	Revision     uint64     `json:"revision"`
	Interval     string     `json:"interval"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	NextRunAt    time.Time  `json:"next_run_at"`
	LastRunAt    *time.Time `json:"last_run_at"`
	LastStatus   string     `json:"last_status"`
	LastBackupID string     `json:"last_backup_id"`
	LastError    string     `json:"last_error"`
	Pending      bool       `json:"pending"`
}

type BackupScheduleInput struct {
	ExpectedRevision         uint64 `json:"expected_revision"`
	ExpectedScheduleRevision uint64 `json:"expected_schedule_revision"`
	Interval                 string `json:"interval"`
	Enabled                  *bool  `json:"enabled"`
}

// The constructed archive's exact identity is durable before filesystem writes.
// An uncertain or absent result is never automatically replayed on reopen.
type pendingBackupRun struct {
	BackupID string    `json:"backup_id"`
	Revision uint64    `json:"revision"`
	SHA256   string    `json:"sha256"`
	Bytes    int64     `json:"bytes"`
	Files    int       `json:"files"`
	DueAt    time.Time `json:"due_at"`
	RunAt    time.Time `json:"run_at"`
}

type backupScheduleRecord struct {
	Version  int               `json:"version"`
	Actor    string            `json:"actor"`
	Schedule BackupSchedule    `json:"schedule"`
	Run      *pendingBackupRun `json:"run"`
}

func backupInterval(name string) time.Duration {
	switch name {
	case "hourly":
		return time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

func scheduleTime(t time.Time) bool {
	return t.Location() == time.UTC && t.Nanosecond() == 0 && t.Year() >= 1970 && t.Year() <= 9998
}

func validateBackupSchedule(r backupScheduleRecord) error {
	v := r.Schedule
	if r.Version != 1 || !validActor(r.Actor) || !identifier.MatchString(v.SiteID) || v.Revision == 0 || v.Revision > maxScheduleRevision || backupInterval(v.Interval) == 0 ||
		!scheduleTime(v.CreatedAt) || !scheduleTime(v.UpdatedAt) || !scheduleTime(v.NextRunAt) || v.UpdatedAt.Before(v.CreatedAt) || v.NextRunAt.Before(v.CreatedAt) || v.Pending != (r.Run != nil) {
		return ErrUnavailable
	}
	if v.LastRunAt != nil && (!scheduleTime(*v.LastRunAt) || v.LastRunAt.Before(v.CreatedAt) || v.LastRunAt.After(v.UpdatedAt)) {
		return ErrUnavailable
	}
	switch v.LastStatus {
	case "never":
		if v.LastRunAt != nil || v.LastBackupID != "" || v.LastError != "" {
			return ErrUnavailable
		}
	case "completed":
		if v.LastRunAt == nil || !identifier.MatchString(v.LastBackupID) || v.LastError != "" {
			return ErrUnavailable
		}
	case "failed":
		if v.LastRunAt == nil || v.LastBackupID != "" || (v.LastError != "archive_capacity" && v.LastError != "backup_failed") {
			return ErrUnavailable
		}
	case "interrupted":
		if v.LastRunAt == nil || v.LastBackupID != "" || v.LastError != "interrupted" {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	if r.Run != nil {
		p := r.Run
		if (!v.Enabled && v.LastStatus != "interrupted") || !identifier.MatchString(p.BackupID) || p.Revision == 0 || !hashPattern.MatchString(p.SHA256) || p.Bytes < 1 || p.Bytes > MaxBackupBytes || p.Files < 1 || p.Files > MaxFiles ||
			!scheduleTime(p.DueAt) || !scheduleTime(p.RunAt) || !p.DueAt.Equal(v.NextRunAt) || p.RunAt.Before(p.DueAt) || p.RunAt.After(v.UpdatedAt) ||
			(!v.Enabled && (v.LastRunAt == nil || !v.LastRunAt.Equal(p.RunAt))) {
			return ErrUnavailable
		}
	}
	return nil
}

func decodeBackupSchedule(raw []byte, key string) (backupScheduleRecord, error) {
	var r backupScheduleRecord
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal(raw, &r) != nil || r.Schedule.SiteID != key || validateBackupSchedule(r) != nil {
		return r, ErrUnavailable
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return r, ErrUnavailable
	}
	return r, nil
}

func backupScheduleParent(r backupScheduleRecord, raw []byte) error {
	var parent record
	if len(raw) == 0 || json.Unmarshal(raw, &parent) != nil || parent.Site.ID != r.Schedule.SiteID ||
		(r.Run != nil && r.Run.Revision > parent.Site.Revision) {
		return ErrUnavailable
	}
	if r.Schedule.LastStatus == "completed" {
		for _, archive := range parent.Backups {
			if archive.ID == r.Schedule.LastBackupID {
				return nil // Historical membership, not a claim of current ZIP health.
			}
		}
		// The signed catalog retains the explicit retirement of this historical
		// result even after other removals. Pending Run verification is unchanged.
		if parent.RetiredScheduledBackupID == r.Schedule.LastBackupID {
			return nil
		}
		return ErrUnavailable
	}
	return nil
}

// Caller owns Store.mu, except during initial Open before exposing the store.
func (s *Store) backupSchedules() ([]backupScheduleRecord, error) {
	rows := []backupScheduleRecord{}
	err := s.db.View(func(tx *bolt.Tx) error {
		jobs, parents := tx.Bucket(backupScheduleBucket), tx.Bucket(bucket)
		if jobs == nil || parents == nil {
			return ErrUnavailable
		}
		return jobs.ForEach(func(k, raw []byte) error {
			if len(rows) >= MaxSites || raw == nil || parents.Get(k) == nil {
				return ErrUnavailable
			}
			r, err := decodeBackupSchedule(raw, string(k))
			if err != nil {
				return err
			}
			if backupScheduleParent(r, parents.Get(k)) != nil {
				return ErrUnavailable
			}
			rows = append(rows, r)
			return nil
		})
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return rows, nil
}

func (s *Store) loadBackupSchedule(id string) (backupScheduleRecord, bool, error) {
	var r backupScheduleRecord
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(backupScheduleBucket)
		if b == nil {
			return ErrUnavailable
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		var err error
		r, err = decodeBackupSchedule(raw, id)
		if err == nil {
			err = backupScheduleParent(r, tx.Bucket(bucket).Get([]byte(id)))
		}
		found = err == nil
		return err
	})
	if err != nil {
		return r, false, ErrUnavailable
	}
	return r, found, nil
}

func (s *Store) saveBackupSchedule(r backupScheduleRecord) error {
	if validateBackupSchedule(r) != nil {
		return ErrUnavailable
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 4096 {
		return ErrUnavailable
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		jobs, parents := tx.Bucket(backupScheduleBucket), tx.Bucket(bucket)
		if jobs == nil || parents == nil || parents.Get([]byte(r.Schedule.SiteID)) == nil {
			return ErrUnavailable
		}
		if backupScheduleParent(r, parents.Get([]byte(r.Schedule.SiteID))) != nil {
			return ErrUnavailable
		}
		if jobs.Get([]byte(r.Schedule.SiteID)) == nil && jobs.Stats().KeyN >= MaxSites {
			return ErrUnavailable
		}
		return jobs.Put([]byte(r.Schedule.SiteID), raw)
	})
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// BackupSchedule reads the intent even if a site requires separate recovery.
func (s *Store) BackupSchedule(id string) (*BackupSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.healthy() != nil {
		return nil, ErrUnavailable
	}
	if _, err := s.load(id); err != nil {
		return nil, err
	}
	r, exists, err := s.loadBackupSchedule(id)
	if err != nil || !exists {
		return nil, err
	}
	return &r.Schedule, nil
}

func (s *Store) SetBackupSchedule(id string, in BackupScheduleInput, actor string) (BackupSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || in.Enabled == nil || backupInterval(in.Interval) == 0 || in.ExpectedRevision == 0 || in.ExpectedRevision > maxScheduleRevision || in.ExpectedScheduleRevision > maxScheduleRevision {
		return BackupSchedule{}, ErrInvalid
	}
	parent, err := s.checked(id)
	if err != nil {
		return BackupSchedule{}, err
	}
	if parent.Site.Revision != in.ExpectedRevision {
		return BackupSchedule{}, ErrConflict
	}
	r, exists, err := s.loadBackupSchedule(id)
	if err != nil {
		return BackupSchedule{}, err
	}
	if (!exists && in.ExpectedScheduleRevision != 0) || (exists && (r.Schedule.Revision != in.ExpectedScheduleRevision || r.Schedule.Revision == maxScheduleRevision)) {
		return BackupSchedule{}, ErrConflict
	}
	now := time.Now().UTC().Truncate(time.Second)
	if !scheduleTime(now) || (exists && now.Before(r.Schedule.UpdatedAt)) {
		return BackupSchedule{}, ErrConflict
	}
	if exists && r.Run != nil {
		if r.Schedule.Enabled {
			return BackupSchedule{}, ErrUnavailable
		}
		archive, completed, resolved := s.scheduledRunOutcome(r)
		if !resolved {
			return BackupSchedule{}, ErrUnavailable
		}
		if completed {
			r.Schedule.LastStatus, r.Schedule.LastBackupID, r.Schedule.LastError = "completed", archive.ID, ""
		}
		r.Schedule.Pending, r.Run = false, nil
	}
	if !exists {
		r = backupScheduleRecord{Version: 1, Schedule: BackupSchedule{SiteID: id, CreatedAt: now, LastStatus: "never"}}
	}
	r.Actor = actor
	r.Schedule.Revision++
	r.Schedule.Interval, r.Schedule.Enabled = in.Interval, *in.Enabled
	r.Schedule.UpdatedAt, r.Schedule.NextRunAt = now, now.Add(backupInterval(in.Interval))
	if err := s.saveBackupSchedule(r); err != nil {
		return BackupSchedule{}, err
	}
	return r.Schedule, nil
}

func (s *Store) verifyScheduledArchive(r backupScheduleRecord) (BackupInfo, bool) {
	parent, err := s.checked(r.Schedule.SiteID)
	if err != nil {
		return BackupInfo{}, false
	}
	p := r.Run
	for _, b := range parent.Backups {
		if b.ID != p.BackupID || b.SiteID != r.Schedule.SiteID || b.Revision != p.Revision || b.SHA256 != p.SHA256 || b.Bytes != p.Bytes || b.Files != p.Files {
			continue
		}
		rt, err := s.siteRoot(r.Schedule.SiteID)
		if err != nil {
			return BackupInfo{}, false
		}
		raw, err := readRoot(rt, "backups/"+b.ID+".zip", MaxBackupBytes)
		rt.Close()
		if err != nil {
			return BackupInfo{}, false
		}
		if _, err := parseArchive(raw, b); err != nil {
			return BackupInfo{}, false
		}
		return b, true
	}
	return BackupInfo{}, false
}

// Resolution requires exact bytes/catalog verification, or proven current
// absence on a checked ready site. Unknown files and recovery state are retained.
func (s *Store) scheduledRunOutcome(r backupScheduleRecord) (BackupInfo, bool, bool) {
	if archive, ok := s.verifyScheduledArchive(r); ok {
		return archive, true, true
	}
	parent, err := s.checked(r.Schedule.SiteID)
	if err != nil {
		return BackupInfo{}, false, false
	}
	for _, archive := range parent.Backups {
		if archive.ID == r.Run.BackupID {
			return BackupInfo{}, false, false
		}
	}
	rt, err := s.siteRoot(r.Schedule.SiteID)
	if err != nil {
		return BackupInfo{}, false, false
	}
	defer rt.Close()
	if checkParents(rt, "backups") != nil {
		return BackupInfo{}, false, false
	}
	_, err = rt.Lstat("backups/" + r.Run.BackupID + ".zip")
	return BackupInfo{}, false, errors.Is(err, os.ErrNotExist)
}

func (s *Store) finishBackupRun(r backupScheduleRecord, now time.Time) error {
	if r.Run == nil || r.Schedule.Revision == maxScheduleRevision || now.Before(r.Schedule.UpdatedAt) {
		return ErrUnavailable
	}
	runAt := r.Run.RunAt
	r.Schedule.LastRunAt = &runAt
	archive, completed, resolved := s.scheduledRunOutcome(r)
	if completed {
		r.Schedule.LastStatus, r.Schedule.LastBackupID, r.Schedule.LastError = "completed", archive.ID, ""
	} else {
		r.Schedule.LastStatus, r.Schedule.LastBackupID, r.Schedule.LastError = "interrupted", "", "interrupted"
		r.Schedule.Enabled = false
	}
	r.Schedule.Revision++
	r.Schedule.UpdatedAt = now
	if resolved {
		r.Schedule.NextRunAt = now.Add(backupInterval(r.Schedule.Interval))
		r.Schedule.Pending, r.Run = false, nil
	}
	return s.saveBackupSchedule(r)
}

func (s *Store) failBackupRun(r backupScheduleRecord, now time.Time, code string) error {
	if r.Schedule.Revision == maxScheduleRevision {
		return ErrUnavailable
	}
	r.Schedule.Revision++
	r.Schedule.Enabled = false
	r.Schedule.LastStatus, r.Schedule.LastError, r.Schedule.LastBackupID = "failed", code, ""
	r.Schedule.LastRunAt = &now
	r.Schedule.UpdatedAt, r.Schedule.NextRunAt = now, now.Add(backupInterval(r.Schedule.Interval))
	return s.saveBackupSchedule(r)
}

// RunDueBackups consumes at most one pending/due row. The injected clock is for
// internal deterministic tests; no HTTP/CLI route permits setting worker time.
// Config, claim, archive creation and reconciliation share Store.mu.
func (s *Store) RunDueBackups(now time.Time) (bool, error) {
	now = now.UTC().Truncate(time.Second)
	if !scheduleTime(now) {
		return false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.healthy() != nil {
		return false, ErrUnavailable
	}
	rows, err := s.backupSchedules()
	if err != nil {
		return false, err
	}
	sort.Slice(rows, func(i, j int) bool {
		if (rows[i].Run != nil) != (rows[j].Run != nil) {
			return rows[i].Run != nil
		}
		if rows[i].Schedule.NextRunAt.Equal(rows[j].Schedule.NextRunAt) {
			return rows[i].Schedule.SiteID < rows[j].Schedule.SiteID
		}
		return rows[i].Schedule.NextRunAt.Before(rows[j].Schedule.NextRunAt)
	})
	for _, row := range rows {
		if removal, err := s.loadBackupRemoval(row.Schedule.SiteID); err != nil {
			return false, err
		} else if removal != nil {
			continue
		}
		if now.Before(row.Schedule.UpdatedAt) {
			continue // A backward clock never rewrites an already observed time.
		}
		if row.Run != nil {
			if !row.Schedule.Enabled {
				continue // Stopped uncertainty needs explicit reviewed configuration.
			}
			return true, s.finishBackupRun(row, now)
		}
		if !row.Schedule.Enabled || now.Before(row.Schedule.NextRunAt) {
			continue
		}
		if row.Schedule.Revision >= maxScheduleRevision-1 {
			return false, ErrUnavailable // Reserve both durable revision advances.
		}
		parent, err := s.checked(row.Schedule.SiteID)
		if err != nil {
			return true, s.failBackupRun(row, now, "backup_failed")
		}
		_, err = s.backupLocked(parent.Site.ID, parent.Site.Revision, "native-backup-scheduler", func(info BackupInfo) error {
			row.Run = &pendingBackupRun{info.ID, info.Revision, info.SHA256, info.Bytes, info.Files, row.Schedule.NextRunAt, now}
			row.Schedule.Pending = true
			row.Schedule.Revision++
			row.Schedule.UpdatedAt = now
			return s.saveBackupSchedule(row)
		})
		if row.Run != nil {
			// A callback may have failed before its transaction committed. Consult
			// durable state, never the speculative in-memory reservation.
			durable, exists, loadErr := s.loadBackupSchedule(row.Schedule.SiteID)
			if loadErr != nil || !exists {
				return true, ErrUnavailable
			}
			if durable.Run != nil {
				return true, s.finishBackupRun(durable, now)
			}
			return true, ErrUnavailable
		}
		code := "backup_failed"
		if errors.Is(err, ErrInvalid) {
			code = "archive_capacity"
		}
		return true, s.failBackupRun(row, now, code)
	}
	return false, nil
}

// RunBackupScheduler is opt-in at the process entrypoint. It performs at most
// four sequential jobs per 30-second cycle; no missed-interval catch-up burst.
// Callers cancel and wait for it before closing Store.
func (s *Store) RunBackupScheduler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		for i := 0; i < 4 && ctx.Err() == nil; i++ {
			processed, err := s.RunDueBackups(time.Now())
			if !processed || err != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
