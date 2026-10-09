package sites

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestRemoveBackupLargeZIPDoesNotUseTrailForArchiveBytes(t *testing.T) {
	s, _, base := fixture(t)
	site := makeSite(t, s)
	for _, name := range []string{"one.png", "two.png"} {
		raw := make([]byte, MaxFileBytes)
		if _, e := rand.Read(raw); e != nil {
			t.Fatal(e)
		}
		var e error
		site, e = s.UploadFile(site.ID, UploadInput{Path: name, Content: raw, ExpectedRevision: site.Revision}, "local-operator")
		if e != nil {
			t.Fatal(e)
		}
	}
	b, e := s.Backup(site.ID, site.Revision, "local-operator")
	if e != nil || b.Bytes <= MaxFileBytes {
		t.Fatal("large ZIP", b.Bytes, e)
	}
	site, _ = s.Get(site.ID)
	if _, e = s.RemoveBackup(site.ID, removalInput(site, b), "local-operator"); e != nil {
		t.Fatal("ZIP removal exceeds trail limit", e)
	}
	if _, e = os.Stat(filepath.Join(base, "sites", "data", site.ID, "backups", b.ID+".zip")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("large ZIP still stored", e)
	}
}

func TestRemoveBackupIncompleteSignedTransitionKeepsBytesOnReopen(t *testing.T) {
	s, j, base := fixture(t)
	site, backups := removalSite(t, s, 1)
	s.backupRemovalStep = func(phase string) error {
		if phase == "after_state_write" {
			return ErrUnavailable
		}
		return nil
	}
	if _, e := s.RemoveBackup(site.ID, removalInput(site, backups[0]), "local-operator"); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	s.Close()
	reopened, e := Open(filepath.Join(base, "sites"), j)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	current, e := reopened.Get(site.ID)
	if e != nil || current.State != "recovery_required" {
		t.Fatal("incomplete transition should require owned recovery", e)
	}
	raw, e := os.ReadFile(filepath.Join(base, "sites", "data", site.ID, "backups", backups[0].ID+".zip"))
	if e != nil || sum(raw) != backups[0].SHA256 {
		t.Fatal("uncommitted ZIP removed", e)
	}
	if _, e = reopened.Backup(site.ID, current.Revision, "local-operator"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("mutations not blocked", e)
	}
}

func removalInput(site Site, b BackupInfo) RemoveBackupInput {
	return RemoveBackupInput{BackupID: b.ID, ExpectedBackupSHA256: b.SHA256, ExpectedRevision: site.Revision, Confirmed: true}
}
func removalSite(t *testing.T, s *Store, n int) (Site, []BackupInfo) {
	t.Helper()
	site := makeSite(t, s)
	backups := []BackupInfo{}
	for i := 0; i < n; i++ {
		b, e := s.Backup(site.ID, site.Revision, "local-operator")
		if e != nil {
			t.Fatal(e)
		}
		backups = append(backups, b)
		site, e = s.Get(site.ID)
		if e != nil {
			t.Fatal(e)
		}
	}
	return site, backups
}

func TestRemoveBackupFreesExactCapacityPreservesContentAndSchedule(t *testing.T) {
	s, j, base := fixture(t)
	site, backups := removalSite(t, s, 8)
	enabled := true
	schedule, e := s.SetBackupSchedule(site.ID, BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "daily", Enabled: &enabled}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RunDueBackups(schedule.NextRunAt); e != nil {
		t.Fatal(e)
	}
	savedSchedule, e := s.BackupSchedule(site.ID)
	if e != nil || savedSchedule.Enabled || savedSchedule.LastError != "archive_capacity" {
		t.Fatal("capacity pause", e)
	}
	before, e := s.load(site.ID)
	if e != nil {
		t.Fatal(e)
	}
	servedBefore := served(s, site.Domain, "/", "GET")
	exports := map[string]string{}
	for _, b := range backups {
		raw, _, e := s.ExportBackup(site.ID, b.ID)
		if e != nil {
			t.Fatal(e)
		}
		exports[b.ID] = sum(raw)
	}
	if _, e = s.Backup(site.ID, site.Revision, "local-operator"); !errors.Is(e, ErrInvalid) {
		t.Fatal("full capacity", e)
	}
	next, e := s.RemoveBackup(site.ID, removalInput(site, backups[3]), "local-operator")
	if e != nil || next.Revision != site.Revision+1 {
		t.Fatal("remove", e)
	}
	if _, e = os.Stat(filepath.Join(base, "sites", "data", site.ID, "backups", backups[3].ID+".zip")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("storage not freed", e)
	}
	remaining, e := s.Backups(site.ID)
	if e != nil || len(remaining) != 7 {
		t.Fatal("7 snapshots", e)
	}
	if _, _, e = s.ExportBackup(site.ID, backups[3].ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("removed export", e)
	}
	for _, b := range remaining {
		raw, _, e := s.ExportBackup(site.ID, b.ID)
		if e != nil || sum(raw) != exports[b.ID] {
			t.Fatal("retained SHA", e)
		}
	}
	after, e := s.load(site.ID)
	if e != nil || !reflect.DeepEqual(after.Files, before.Files) || after.Site.Domain != before.Site.Domain || after.Site.PreviewHost != before.Site.PreviewHost || after.Site.Name != before.Site.Name || after.Site.State != before.Site.State || after.Site.CreatedAt != before.Site.CreatedAt {
		t.Fatal("site preservation", e)
	}
	servedAfter := served(s, site.Domain, "/", "GET")
	if servedAfter.Code != 200 || servedBefore.Code != 200 || !reflect.DeepEqual(servedBefore.Body.Bytes(), servedAfter.Body.Bytes()) {
		t.Fatal("HTTP bytes")
	}
	actualSchedule, e := s.BackupSchedule(site.ID)
	if e != nil || !reflect.DeepEqual(savedSchedule, actualSchedule) {
		t.Fatal("schedule changed", e)
	}
	if _, e = s.Backup(site.ID, next.Revision, "local-operator"); e != nil {
		t.Fatal("capacity not reusable", e)
	}
	remaining, e = s.Backups(site.ID)
	if e != nil || len(remaining) != 8 {
		t.Fatal("8 snapshots again", e)
	}
	history, e := j.List()
	if e != nil || j.Verify() != nil {
		t.Fatal("signed history", e)
	}
	found := false
	for _, cp := range history {
		if strings.Contains(cp.Reason, "site remove-backup "+site.ID) && cp.State == "applied" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing signed removal")
	}
}

func TestRemoveBackupRefusalsDoNotMutate(t *testing.T) {
	s, j, _ := fixture(t)
	site, backups := removalSite(t, s, 2)
	other, e := s.Create(CreateInput{Name: "Other", Domain: "other.test"}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	before, _ := s.load(site.ID)
	history, _ := j.List()
	schedule, _ := s.BackupSchedule(site.ID)
	for _, tc := range []struct {
		name, id, actor string
		in              RemoveBackupInput
		want            error
	}{
		{"wrong hash", site.ID, "local-operator", RemoveBackupInput{backups[0].ID, strings.Repeat("f", 64), site.Revision, true}, ErrConflict},
		{"stale", site.ID, "local-operator", RemoveBackupInput{backups[0].ID, backups[0].SHA256, site.Revision - 1, true}, ErrConflict},
		{"unconfirmed", site.ID, "local-operator", RemoveBackupInput{backups[0].ID, backups[0].SHA256, site.Revision, false}, ErrInvalid},
		{"bad id", site.ID, "local-operator", RemoveBackupInput{"../outside", backups[0].SHA256, site.Revision, true}, ErrInvalid},
		{"cross site", other.ID, "local-operator", removalInput(other, backups[0]), ErrNotFound},
		{"actor", site.ID, "native-backup-scheduler", removalInput(site, backups[0]), ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := s.RemoveBackup(tc.id, tc.in, tc.actor); !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
			after, _ := s.load(site.ID)
			h, _ := j.List()
			job, _ := s.BackupSchedule(site.ID)
			pending, _ := s.loadBackupRemoval(site.ID)
			if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(history, h) || !reflect.DeepEqual(schedule, job) || pending != nil {
				t.Fatal("refusal mutated")
			}
			for _, b := range backups {
				if _, _, e := s.ExportBackup(site.ID, b.ID); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestRemoveBackupFailureReopenNeverResurrectsDeletedZIP(t *testing.T) {
	for _, phase := range []string{"before_metadata", "after_metadata", "before_unlink", "after_unlink"} {
		t.Run(phase, func(t *testing.T) {
			s, j, base := fixture(t)
			site, backups := removalSite(t, s, 2)
			b := backups[0]
			enabled := true
			job, e := s.SetBackupSchedule(site.ID, BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "daily", Enabled: &enabled}, "local-operator")
			if e != nil {
				t.Fatal(e)
			}
			s.backupRemovalStep = func(p string) error {
				if p == phase {
					return ErrUnavailable
				}
				return nil
			}
			if _, e := s.RemoveBackup(site.ID, removalInput(site, b), "local-operator"); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			current, e := s.Get(site.ID)
			if e != nil || current.State != "recovery_required" {
				t.Fatal("recovery exposure", e)
			}
			if _, e = s.Backup(site.ID, current.Revision, "local-operator"); !errors.Is(e, ErrUnavailable) {
				t.Fatal("orphan accumulation allowed", e)
			}
			if served(s, site.Domain, "/", "GET").Code != 503 {
				t.Fatal("uncertain site served")
			}
			if processed, e := s.RunDueBackups(job.NextRunAt); e != nil || processed {
				t.Fatal("cleanup site scheduled", e)
			}
			retained, e := s.BackupSchedule(site.ID)
			if e != nil || !reflect.DeepEqual(job, *retained) {
				t.Fatal("cleanup changed schedule", e)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(filepath.Join(base, "sites"), j)
			if e != nil {
				t.Fatal("reopen", e)
			}
			defer reopened.Close()
			items, e := reopened.Backups(site.ID)
			want := 1
			if phase == "before_metadata" {
				want = 2
			}
			if e != nil || len(items) != want {
				t.Fatal("reopen inventory", len(items), e)
			}
			if phase != "before_metadata" {
				if _, _, e = reopened.ExportBackup(site.ID, b.ID); !errors.Is(e, ErrNotFound) {
					t.Fatal("deleted metadata resurrected", e)
				}
				if _, e = os.Stat(filepath.Join(base, "sites", "data", site.ID, "backups", b.ID+".zip")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("not unlinked", e)
				}
			}
			if served(reopened, site.Domain, "/", "GET").Code != 200 {
				t.Fatal("recovered content")
			}
		})
	}
}

func TestRemoveBackupForgedCleanupIntentCannotDeleteRetainedArchive(t *testing.T) {
	s, j, base := fixture(t)
	site, backups := removalSite(t, s, 2)
	s.backupRemovalStep = func(p string) error {
		if p == "after_metadata" {
			return ErrUnavailable
		}
		return nil
	}
	_, _ = s.RemoveBackup(site.ID, removalInput(site, backups[0]), "local-operator")
	v, e := s.loadBackupRemoval(site.ID)
	if e != nil || v == nil {
		t.Fatal(e)
	}
	v.Backup = backups[1]
	raw, _ := json.Marshal(v)
	if e = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(backupRemovalBucket).Put([]byte(site.ID), raw) }); e != nil {
		t.Fatal(e)
	}
	s.Close()
	reopened, e := Open(filepath.Join(base, "sites"), j)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	current, e := reopened.Get(site.ID)
	if e != nil || current.State != "recovery_required" {
		t.Fatal("forged marker admitted", e)
	}
	for _, b := range backups {
		raw, e := os.ReadFile(filepath.Join(base, "sites", "data", site.ID, "backups", b.ID+".zip"))
		if e != nil || sum(raw) != b.SHA256 {
			t.Fatal("forged deletion", e)
		}
	}
}

func TestRemoveScheduledLastBackupRetainsHistoryAndPendingRunRefuses(t *testing.T) {
	s, j, base := fixture(t)
	site, backups := removalSite(t, s, 1)
	enabled := true
	job, e := s.SetBackupSchedule(site.ID, BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "daily", Enabled: &enabled}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RunDueBackups(job.NextRunAt); e != nil {
		t.Fatal(e)
	}
	schedule, e := s.BackupSchedule(site.ID)
	if e != nil {
		t.Fatal(e)
	}
	all, e := s.Backups(site.ID)
	if e != nil {
		t.Fatal(e)
	}
	var last BackupInfo
	for _, b := range all {
		if b.ID == schedule.LastBackupID {
			last = b
		}
	}
	site, _ = s.Get(site.ID)
	site, e = s.RemoveBackup(site.ID, removalInput(site, last), "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	site, e = s.RemoveBackup(site.ID, removalInput(site, backups[0]), "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	actual, e := s.BackupSchedule(site.ID)
	if e != nil || !reflect.DeepEqual(schedule, actual) {
		t.Fatal("history", e)
	}
	s.Close()
	reopened, e := Open(filepath.Join(base, "sites"), j)
	if e != nil {
		t.Fatal("schedule reopen", e)
	}
	defer reopened.Close()
	b, e := reopened.Backup(site.ID, site.Revision, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	site, _ = reopened.Get(site.ID)
	r, _, e := reopened.loadBackupSchedule(site.ID)
	if e != nil {
		t.Fatal(e)
	}
	runAt := r.Schedule.NextRunAt
	r.Run = &pendingBackupRun{b.ID, b.Revision, b.SHA256, b.Bytes, b.Files, r.Schedule.NextRunAt, runAt}
	r.Schedule.Pending = true
	r.Schedule.UpdatedAt = runAt
	r.Schedule.Revision++
	if e = reopened.saveBackupSchedule(r); e != nil {
		t.Fatal(e)
	}
	before, _ := reopened.load(site.ID)
	if _, e = reopened.RemoveBackup(site.ID, removalInput(site, b), "local-operator"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("pending removal", e)
	}
	after, _ := reopened.load(site.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("pending mutation")
	}
}
