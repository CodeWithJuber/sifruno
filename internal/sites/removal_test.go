package sites

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func removeSiteInput(site Site) RemoveInput { return RemoveInput{site.Revision, site.Domain, true} }

func TestWebsiteRemovalExactScopeAndReopen(t *testing.T) {
	s, j, base := fixture(t)
	site, backups := removalSite(t, s, 2)
	other, e := s.Create(CreateInput{Name: "Other", Domain: "other.test"}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	otherBackup, e := s.Backup(other.ID, other.Revision, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	other, _ = s.Get(other.ID)
	enabled := true
	for _, v := range []Site{site, other} {
		if _, e = s.SetBackupSchedule(v.ID, BackupScheduleInput{ExpectedRevision: v.Revision, Interval: "daily", Enabled: &enabled}, "local-operator"); e != nil {
			t.Fatal(e)
		}
	}
	otherSchedule, _ := s.BackupSchedule(other.ID)
	beforeOther, _ := s.load(other.ID)
	beforeHTTP := served(s, other.Domain, "/", "GET").Body.String()
	beforeArchive, _, _ := s.ExportBackup(other.ID, otherBackup.ID)
	// Supported file deletes leave ordinary empty content directories behind.
	site, e = s.UploadFile(site.ID, UploadInput{Path: "old/nested/file.txt", Content: []byte("old"), ExpectedRevision: site.Revision}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	site, e = s.DeleteFile(site.ID, DeleteInput{Path: "old/nested/file.txt", ExpectedSHA256: sum([]byte("old")), ExpectedRevision: site.Revision}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.Remove(site.ID, removeSiteInput(site), "local-operator")
	if e != nil || !result.Removed || result.ID != site.ID || result.Revision != site.Revision || result.Domain != site.Domain {
		t.Fatal("remove result", result, e)
	}
	if _, e = os.Stat(filepath.Join(base, "sites", "data", site.ID)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("owned directory remains", e)
	}
	if _, e = s.Get(site.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("record remains", e)
	}
	if _, e = s.BackupSchedule(site.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("schedule remains", e)
	}
	for _, host := range []string{site.Domain, site.PreviewHost} {
		if served(s, host, "/", "GET").Code != 404 {
			t.Fatal("routing remains")
		}
	}
	for _, b := range backups {
		if _, _, e = s.ExportBackup(site.ID, b.ID); !errors.Is(e, ErrNotFound) {
			t.Fatal("archive remains", e)
		}
	}
	if _, e = s.Remove(site.ID, removeSiteInput(site), "local-operator"); !errors.Is(e, ErrNotFound) {
		t.Fatal("replay", e)
	}
	afterOther, _ := s.load(other.ID)
	afterSchedule, _ := s.BackupSchedule(other.ID)
	afterArchive, _, _ := s.ExportBackup(other.ID, otherBackup.ID)
	if !reflect.DeepEqual(beforeOther, afterOther) || !reflect.DeepEqual(otherSchedule, afterSchedule) || !reflect.DeepEqual(beforeArchive, afterArchive) || served(s, other.Domain, "/", "GET").Body.String() != beforeHTTP {
		t.Fatal("unrelated site changed")
	}
	if j.Verify() != nil {
		t.Fatal("audit invalid")
	}
	history, _ := j.List()
	found := false
	for _, cp := range history {
		if strings.HasPrefix(cp.Reason, "site remove "+site.ID+" ") && cp.State == "applied" && j.VerifyCurrent(cp.ID) == nil {
			found = true
		}
	}
	if !found {
		t.Fatal("immutable signed removal audit missing")
	}
	s.Close()
	reopened, e := Open(filepath.Join(base, "sites"), j)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if _, e = reopened.Get(site.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("revived", e)
	}
	if _, e = reopened.Create(CreateInput{Name: "Reuse domain", Domain: site.Domain}, "local-operator"); e != nil {
		t.Fatal("domain reserved after complete", e)
	}
}

func TestWebsiteRemovalFailurePhasesAndReopen(t *testing.T) {
	for _, phase := range []string{"before_seal", "before_intent", "after_intent", "before_unlink", "after_unlink", "after_directory"} {
		t.Run(phase, func(t *testing.T) {
			s, j, base := fixture(t)
			site, _ := removalSite(t, s, 1)
			s.siteRemovalStep = func(p string) error {
				if p == phase {
					return ErrUnavailable
				}
				return nil
			}
			if _, e := s.Remove(site.ID, removeSiteInput(site), "local-operator"); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			committed := phase != "before_seal" && phase != "before_intent"
			current, e := s.Get(site.ID)
			if e != nil {
				t.Fatal(e)
			}
			if committed {
				if current.State != "recovery_required" || served(s, site.Domain, "/", "GET").Code != 503 {
					t.Fatal("partial site served")
				}
				if _, e = s.Remove(site.ID, removeSiteInput(site), "local-operator"); !errors.Is(e, ErrUnavailable) {
					t.Fatal("retry allowed", e)
				}
				if _, e = s.Create(CreateInput{Name: "Reuse", Domain: site.Domain}, "local-operator"); !errors.Is(e, ErrConflict) {
					t.Fatal("domain freed early", e)
				}
			} else if current.State != "active" || served(s, site.Domain, "/", "GET").Code != 200 {
				t.Fatal("uncommitted site altered")
			}
			s.Close()
			reopened, e := Open(filepath.Join(base, "sites"), j)
			if e != nil {
				t.Fatal("reopen", e)
			}
			defer reopened.Close()
			_, e = reopened.Get(site.ID)
			if committed && !errors.Is(e, ErrNotFound) {
				t.Fatal("exact cleanup did not finish", e)
			}
			if !committed && e != nil {
				t.Fatal("uncommitted removal replayed", e)
			}
		})
	}
}

func TestWebsiteRemovalPreflightRefusesWithoutMutation(t *testing.T) {
	for _, kind := range []string{"unknown root", "unknown backup", "unknown content", "changed content", "changed backup", "missing file", "hardlink", "symlink", "changed marker"} {
		t.Run(kind, func(t *testing.T) {
			s, j, base := fixture(t)
			site, backups := removalSite(t, s, 1)
			root := filepath.Join(base, "sites", "data", site.ID)
			var e error
			switch kind {
			case "unknown root":
				e = os.WriteFile(filepath.Join(root, "extra.txt"), []byte("keep"), 0600)
			case "unknown backup":
				e = os.WriteFile(filepath.Join(root, "backups", "extra.zip"), []byte("keep"), 0600)
			case "unknown content":
				e = os.WriteFile(filepath.Join(root, "content", "extra.txt"), []byte("keep"), 0600)
			case "changed content":
				e = os.WriteFile(filepath.Join(root, "content", "index.html"), []byte("changed"), 0600)
			case "changed backup":
				e = os.WriteFile(filepath.Join(root, "backups", backups[0].ID+".zip"), []byte("changed"), 0600)
			case "missing file":
				e = os.Remove(filepath.Join(root, "content", "index.html"))
			case "changed marker":
				e = os.WriteFile(filepath.Join(root, ".sifruno-state"), []byte("changed"), 0600)
			case "symlink":
				outside := filepath.Join(base, "outside.html")
				if e = os.WriteFile(outside, []byte("outside"), 0600); e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(filepath.Join(root, "content", "index.html")); e != nil {
					t.Fatal(e)
				}
				e = os.Symlink(outside, filepath.Join(root, "content", "index.html"))
				if e != nil {
					t.Skip("fixture symlink privilege unavailable")
				}
			case "hardlink":
				e = os.Link(filepath.Join(root, "content", "index.html"), filepath.Join(base, "outside.html"))
			}
			if e != nil {
				t.Fatal(e)
			}
			before, _ := s.load(site.ID)
			history, _ := j.List()
			if _, e = s.Remove(site.ID, removeSiteInput(site), "local-operator"); !errors.Is(e, ErrUnavailable) {
				t.Fatal("unsafe preflight", e)
			}
			after, _ := s.load(site.ID)
			historyAfter, _ := j.List()
			if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(history, historyAfter) {
				t.Fatal("refusal mutated")
			}
			if v, _ := s.loadSiteRemoval(site.ID); v != nil {
				t.Fatal("refusal committed")
			}
		})
	}
}

func TestWebsiteRemovalUnknownRecoveryBytesAndSchedulerRefuse(t *testing.T) {
	for _, kind := range []string{"extra", "changed", "new directory", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			s, j, base := fixture(t)
			site, _ := removalSite(t, s, 1)
			enabled := true
			job, e := s.SetBackupSchedule(site.ID, BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "daily", Enabled: &enabled}, "local-operator")
			if e != nil {
				t.Fatal(e)
			}
			s.siteRemovalStep = func(phase string) error {
				if phase == "after_intent" {
					return ErrUnavailable
				}
				return nil
			}
			if _, e = s.Remove(site.ID, removeSiteInput(site), "local-operator"); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			if ran, e := s.RunDueBackups(job.NextRunAt); e != nil || ran {
				t.Fatal("scheduler touched removing site", e)
			}
			root := filepath.Join(base, "sites", "data", site.ID)
			switch kind {
			case "extra":
				e = os.WriteFile(filepath.Join(root, "content", "extra.txt"), []byte("keep"), 0600)
			case "changed":
				e = os.WriteFile(filepath.Join(root, "content", "index.html"), []byte("keep changed"), 0600)
			case "new directory":
				e = os.Mkdir(filepath.Join(root, "content", "new"), 0700)
			case "manifest":
				v, _ := s.loadSiteRemoval(site.ID)
				p := filepath.Join(base, "sites", "removals", v.AuditID+".json")
				raw, _ := os.ReadFile(p)
				var manifest siteRemovalManifest
				json.Unmarshal(raw, &manifest)
				manifest.Record.Site.Name = "forged"
				raw, _ = json.Marshal(manifest)
				e = os.WriteFile(p, raw, 0600)
			}
			if e != nil {
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
				t.Fatal("unknown cleanup accepted", e)
			}
			if _, e = os.Stat(filepath.Join(root, "state.json")); e != nil {
				t.Fatal("cleanup began despite unknown bytes", e)
			}
		})
	}
}

func TestWebsiteRemovalRejectsPendingScheduleAndForgedReference(t *testing.T) {
	s, _, _ := fixture(t)
	site := makeSite(t, s)
	enabled := true
	job, e := s.SetBackupSchedule(site.ID, BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "daily", Enabled: &enabled}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	row, _, _ := s.loadBackupSchedule(site.ID)
	row.Run = &pendingBackupRun{BackupID: strings.Repeat("a", 32), Revision: site.Revision, SHA256: strings.Repeat("b", 64), Bytes: 1, Files: 1, DueAt: job.NextRunAt, RunAt: job.NextRunAt}
	row.Schedule.Pending = true
	row.Schedule.UpdatedAt = job.NextRunAt
	if e = s.saveBackupSchedule(row); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Remove(site.ID, removeSiteInput(site), "local-operator"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("running schedule removed", e)
	}
	row.Run = nil
	row.Schedule.Pending = false
	if e = s.saveBackupSchedule(row); e != nil {
		t.Fatal(e)
	}
	s.siteRemovalStep = func(phase string) error {
		if phase == "after_intent" {
			return ErrUnavailable
		}
		return nil
	}
	if _, e = s.Remove(site.ID, removeSiteInput(site), "local-operator"); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	v, _ := s.loadSiteRemoval(site.ID)
	r, _ := s.load(site.ID)
	v.CheckpointID = r.ChangeIDs[0]
	raw, _ := json.Marshal(v)
	s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(siteRemovalBucket).Put([]byte(site.ID), raw) })
	if e = s.finishSiteRemoval(*v); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unrelated signed checkpoint accepted", e)
	}
}
