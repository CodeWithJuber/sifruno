package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"sifruno/internal/api"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
	"sifruno/internal/trail"
)

// Real local HTTP plus real private native state; no credentials enter output.
func TestBackupScheduleCLIConfigConflictAndDueArchive(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	journal, err := trail.Open(filepath.Join(state, "trail"))
	if err != nil {
		t.Fatal(err)
	}
	op, err := operator.Open(filepath.Join(state, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := sites.Open(filepath.Join(state, "sites"), journal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error("owned store cleanup", err)
		}
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + listener.Addr().String()
	server := httptest.NewUnstartedServer(api.New(api.Options{Sites: store, Operator: op, BackupSchedulerEnabled: true, AllowedOrigins: []string{base}}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	call := func(wantError string, args ...string) []byte {
		t.Helper()
		var out, errs bytes.Buffer
		all := append([]string{"--state", state, "--panel-url", base, "sites"}, args...)
		err := run(all, &out, &errs)
		if (wantError == "" && err != nil) || (wantError != "" && (err == nil || !strings.Contains(err.Error(), wantError))) {
			t.Fatalf("CLI result did not match expected outcome: %v", err)
		}
		key, err := readOperatorKey(state)
		if err != nil {
			t.Fatal("fixture key unavailable")
		}
		if strings.Contains(out.String()+errs.String(), key) || strings.Contains(out.String(), "csrf_token") {
			t.Fatal("CLI exposed an operator credential")
		}
		return append([]byte{}, out.Bytes()...)
	}
	var site sites.Site
	if json.Unmarshal(call("", "create", "--name", "Scheduled CLI fixture", "--domain", "schedule-cli.example"), &site) != nil || site.ID == "" {
		t.Fatal("create DTO")
	}
	type envelope struct {
		Schedule      *sites.BackupSchedule `json:"schedule"`
		RunnerEnabled bool                  `json:"runner_enabled"`
	}
	var job envelope
	if json.Unmarshal(call("", "backup-schedule", "--id", site.ID), &job) != nil || job.Schedule != nil || !job.RunnerEnabled {
		t.Fatal("absent schedule")
	}
	flags := []string{"backup-schedule-set", "--id", site.ID, "--revision", fmt.Sprint(site.Revision), "--schedule-revision", "0", "--interval", "hourly", "--enabled", "true"}
	if json.Unmarshal(call("", flags...), &job) != nil || job.Schedule == nil || !job.Schedule.Enabled || job.Schedule.Revision != 1 {
		t.Fatal("configured schedule")
	}
	before, err := store.Get(site.ID)
	if err != nil || before.Revision != site.Revision {
		t.Fatal("configuration changed site revision")
	}
	call("HTTP 409", flags...) // A stale absent revision cannot overwrite the row.
	call("explicit --enabled", "backup-schedule-set", "--id", site.ID, "--revision", "1", "--schedule-revision", "1", "--interval", "hourly")
	call("explicit --schedule-revision", "backup-schedule-set", "--id", site.ID, "--revision", "1", "--interval", "hourly", "--enabled", "false")
	processed, err := store.RunDueBackups(job.Schedule.NextRunAt)
	if err != nil || !processed {
		t.Fatal("internal injected-clock due dispatch", err)
	}
	if json.Unmarshal(call("", "backup-schedule", "--id", site.ID), &job) != nil || job.Schedule.LastStatus != "completed" || job.Schedule.Pending || job.Schedule.LastBackupID == "" {
		t.Fatal("completed schedule DTO")
	}
	raw, backup, err := store.ExportBackup(site.ID, job.Schedule.LastBackupID)
	if err != nil || len(raw) != int(backup.Bytes) || backup.Revision != before.Revision {
		t.Fatal("real native ZIP export", err)
	}
	call("HTTP 409", "backup-schedule-set", "--id", site.ID, "--revision", fmt.Sprint(site.Revision), "--schedule-revision", fmt.Sprint(job.Schedule.Revision), "--interval", "daily", "--enabled", "false")
	// Synthetic future dispatch intentionally makes wall-clock edits conflict.
	if again, err := store.RunDueBackups(job.Schedule.LastRunAt.UTC()); err != nil || again {
		t.Fatal("same due run replayed", err)
	}
}
