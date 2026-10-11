package sites

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestChangeNamePreservesContentRoutingBackupsScheduleAndReopens(t *testing.T) {
	s, journal, base := fixture(t)
	site := makeSite(t, s)
	original, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	png := []byte{0x89, 'P', 'N', 'G', 0, 255, 128, 10}
	site, err = s.UploadFile(site.ID, UploadInput{Path: "assets/pixel.png", Content: png, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	schedule, err := s.SetBackupSchedule(site.ID, BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "daily", Enabled: &enabled}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, err := s.Files(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := site
	site, err = s.ChangeName(site.ID, NameInput{Name: strings.Repeat("名", 26) + "AB", ExpectedRevision: site.Revision}, "local-operator")
	if err != nil || site.Revision != before.Revision+1 || !site.UpdatedAt.After(before.UpdatedAt) {
		t.Fatal("80 UTF-8 byte name mutation", site, err)
	}
	expected := before
	expected.Name, expected.Revision, expected.UpdatedAt = site.Name, site.Revision, site.UpdatedAt
	if site != expected {
		t.Fatal("name changed unrelated metadata", site)
	}
	if got, err := s.Files(site.ID); err != nil || !reflect.DeepEqual(got, files) {
		t.Fatal("files changed", err)
	}
	if got, err := s.Backups(site.ID); err != nil || len(got) != 1 || got[0] != backup {
		t.Fatal("backups changed", err)
	}
	if got, err := s.BackupSchedule(site.ID); err != nil || got == nil || !reflect.DeepEqual(*got, schedule) {
		t.Fatal("schedule changed", err)
	}
	for _, host := range []string{site.Domain, site.PreviewHost} {
		if w := served(s, host, "/", "GET"); w.Code != 200 || w.Body.String() != original.Content {
			t.Fatal("text routing changed", w.Code)
		}
		if w := served(s, host, "/assets/pixel.png", "GET"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), png) {
			t.Fatal("PNG routing changed", w.Code)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), journal)
	if err != nil {
		t.Fatal("reopen", err)
	}
	defer again.Close()
	if got, err := again.Get(site.ID); err != nil || got != site {
		t.Fatal("name not durable", got, err)
	}
	if got, err := again.BackupSchedule(site.ID); err != nil || got == nil || !reflect.DeepEqual(*got, schedule) {
		t.Fatal("reopened schedule changed", err)
	}
	// A prior native content backup must not restore its old display name.
	site, err = again.Restore(site.ID, RestoreInput{BackupID: backup.ID, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil || site.Name != expected.Name || site.Domain != before.Domain || site.PreviewHost != before.PreviewHost {
		t.Fatal("restore changed name/routing", site, err)
	}
	if w := served(again, site.PreviewHost, "/assets/pixel.png", "GET"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), png) {
		t.Fatal("restore lost PNG", w.Code)
	}
	if journal.Verify() != nil {
		t.Fatal("name journal invalid")
	}
}

func TestChangeNameNoOpAndRefusals(t *testing.T) {
	s, journal, base := fixture(t)
	site := makeSite(t, s)
	entries, err := journal.List()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.ChangeName(site.ID, NameInput{Name: site.Name, ExpectedRevision: site.Revision}, "local-operator"); err != nil || got != site {
		t.Fatal("same-name no-op", got, err)
	}
	for _, name := range []string{"", " leading", "trailing ", "bad\nname", "bad\x7fname", strings.Repeat("x", 81), strings.Repeat("名", 27), string([]byte{255})} {
		if got, err := s.ChangeName(site.ID, NameInput{Name: name, ExpectedRevision: site.Revision}, "local-operator"); got != (Site{}) || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid name accepted", err)
		}
	}
	for _, name := range []string{site.Name, "New name"} {
		if _, err := s.ChangeName(site.ID, NameInput{Name: name, ExpectedRevision: 0}, "local-operator"); !errors.Is(err, ErrConflict) {
			t.Fatal("stale accepted", err)
		}
	}
	if _, err := s.ChangeName(site.ID, NameInput{Name: "New name", ExpectedRevision: site.Revision}, "root"); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid actor accepted", err)
	}
	if _, err := s.ChangeName(strings.Repeat("a", 32), NameInput{Name: "New name", ExpectedRevision: site.Revision}, "local-operator"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown site accepted", err)
	}
	if got, err := s.Get(site.ID); err != nil || got != site {
		t.Fatal("refusal changed site", got, err)
	}
	if got, err := journal.List(); err != nil || !reflect.DeepEqual(got, entries) {
		t.Fatal("no-op/refusal wrote audit", err)
	}
	if err := os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "content", "index.html"), []byte("external change"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeName(site.ID, NameInput{Name: site.Name, ExpectedRevision: site.Revision}, "local-operator"); err == nil {
		t.Fatal("no-op skipped content validation")
	}
}

func TestChangeNameSuspendedRecoveryUnknownStateAndExhaustion(t *testing.T) {
	for _, state := range []string{"suspended", "pending", "unknown", "exhausted"} {
		t.Run(state, func(t *testing.T) {
			s, journal, _ := fixture(t)
			site := makeSite(t, s)
			if state == "suspended" {
				var err error
				site, err = s.SetState(site.ID, StateInput{State: state, ExpectedRevision: site.Revision}, "local-operator")
				if err != nil {
					t.Fatal(err)
				}
				got, err := s.ChangeName(site.ID, NameInput{Name: "Suspended name", ExpectedRevision: site.Revision}, "local-operator")
				if err != nil || got.State != state || served(s, got.Domain, "/", "GET").Code != 503 {
					t.Fatal("suspended rename", got, err)
				}
				return
			}
			r, err := s.load(site.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := ErrUnavailable
			switch state {
			case "pending":
				r.Pending = &pendingChange{Action: "interrupted", Checkpoints: []string{}}
				if err = s.save(r); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				r.Site.State = "unknown"
				raw, _ := json.Marshal(r)
				if err = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put([]byte(site.ID), raw) }); err != nil {
					t.Fatal(err)
				}
			case "exhausted":
				next := r
				next.Site.Revision = math.MaxUint64
				if err = s.change(r, next, nil, "test exhaustion", "local-operator"); err != nil {
					t.Fatal(err)
				}
				site.Revision, want = math.MaxUint64, ErrConflict
			}
			entries, err := journal.List()
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{site.Name, "Refused name"} {
				if got, err := s.ChangeName(site.ID, NameInput{Name: name, ExpectedRevision: site.Revision}, "local-operator"); got != (Site{}) || !errors.Is(err, want) {
					t.Fatal("unsafe state accepted", got, err)
				}
			}
			if got, err := journal.List(); err != nil || !reflect.DeepEqual(got, entries) {
				t.Fatal("refusal wrote journal", err)
			}
		})
	}
}
