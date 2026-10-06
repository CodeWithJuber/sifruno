package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/operator"
	"sifruno/internal/securestate"
	"sifruno/internal/sites"
	"sifruno/internal/trail"
)

// The due time is explicitly seeded synthetic metadata. Dispatch, the opt-in
// flag, HTTP admission and ZIP effects use the actual newly built entrypoint.
func TestOptInScheduleRunnerProcess(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "sifruno")
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		bin += ".exe"
		goTool += ".exe"
	}
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer buildCancel()
	build := exec.CommandContext(buildCtx, goTool, "build", "-mod=readonly", "-trimpath", "-o", bin, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("owned entrypoint build failed (%d bounded diagnostic bytes)", len(output))
	}
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("runner_%t", enabled), func(t *testing.T) {
			base := t.TempDir()
			if runtime.GOOS != "windows" {
				var err error
				base, err = filepath.EvalSymlinks(base)
				if err != nil {
					t.Fatal(err)
				}
			}
			state, err := securestate.Dir(filepath.Join(base, "state"))
			if err != nil {
				t.Fatal("owned state admission", err)
			}
			journal, err := trail.Open(filepath.Join(state, "trail"))
			if err != nil {
				t.Fatal(err)
			}
			access, err := operator.Open(filepath.Join(state, "operator"))
			if err != nil {
				t.Fatal(err)
			}
			key, err := os.ReadFile(access.AccessKeyPath())
			if err != nil {
				t.Fatal("fixture key unavailable")
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
			site, err := store.Create(sites.CreateInput{Name: "Process schedule fixture", Domain: "schedule-process.example"}, "local-operator")
			if err != nil {
				t.Fatal(err)
			}
			active := true
			job, err := store.SetBackupSchedule(site.ID, sites.BackupScheduleInput{ExpectedRevision: site.Revision, Interval: "hourly", Enabled: &active}, "local-operator")
			if err != nil {
				t.Fatal(err)
			}
			if store.Close() != nil {
				t.Fatal("fixture close")
			}
			// Canonical field order matches the durable native record, no live DB.
			past := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)
			job.CreatedAt, job.UpdatedAt, job.NextRunAt = past, past, past.Add(time.Hour)
			seed := struct {
				Version  int                  `json:"version"`
				Actor    string               `json:"actor"`
				Schedule sites.BackupSchedule `json:"schedule"`
				Run      any                  `json:"run"`
			}{1, "local-operator", job, nil}
			raw, err := json.Marshal(seed)
			if err != nil {
				t.Fatal(err)
			}
			db, err := bolt.Open(filepath.Join(state, "sites", "sites.db"), 0600, &bolt.Options{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			err = db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("native-backup-schedules-v1")).Put([]byte(site.ID), raw)
			})
			closeErr := db.Close()
			if err != nil || closeErr != nil {
				t.Fatal("seeded due metadata")
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			if listener.Close() != nil {
				t.Fatal("ephemeral reservation close")
			}
			origin := "http://" + address
			args := []string{"--listen", address, "--sites-listen=", "--state", state, "--ui", filepath.Join(base, "absent-ui")}
			if enabled {
				args = append(args, "--backup-scheduler")
			}
			child := exec.Command(bin, args...)
			var diagnostics bytes.Buffer
			child.Stdout, child.Stderr = &diagnostics, &diagnostics
			for _, name := range []string{"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "ComSpec", "PATHEXT", "USERPROFILE", "LOCALAPPDATA"} {
				if value, ok := os.LookupEnv(name); ok {
					child.Env = append(child.Env, name+"="+value)
				}
			}
			// Default discarded output; no credentials or private response logging.
			child.Dir = filepath.Clean(filepath.Join("..", ".."))
			if child.Start() != nil {
				t.Fatal("owned entrypoint start")
			}
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			stopped := false
			stop := func() {
				if stopped {
					return
				}
				stopped = true
				_ = child.Process.Kill()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("owned process cleanup timed out")
				}
			}
			defer stop()
			jar, _ := cookiejar.New(nil)
			client := &http.Client{Timeout: 2 * time.Second, Jar: jar, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			defer client.CloseIdleConnections()
			deadline := time.Now().Add(10 * time.Second)
			for {
				response, err := client.Get(origin + "/api/v1/status")
				if err == nil {
					response.Body.Close()
					if response.StatusCode == 200 {
						break
					}
				}
				if time.Now().After(deadline) {
					stop()
					message := strings.ReplaceAll(diagnostics.String(), string(bytes.TrimSpace(key)), "[fixture credential]")
					message = strings.ReplaceAll(message, base, "[owned fixture]")
					if len(message) > 512 {
						message = message[:512]
					}
					t.Fatalf("owned entrypoint did not become healthy: %s", message)
				}
				time.Sleep(20 * time.Millisecond)
			}
			request := func(method, path string, value any, out any) {
				t.Helper()
				body, err := json.Marshal(value)
				if err != nil {
					t.Fatal("fixture JSON")
				}
				req, _ := http.NewRequest(method, origin+path, bytes.NewReader(body))
				req.Header.Set("Origin", origin)
				req.Header.Set("Content-Type", "application/json")
				response, err := client.Do(req)
				if err != nil {
					t.Fatal("owned HTTP operation")
				}
				defer response.Body.Close()
				if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(out) != nil {
					t.Fatal("owned HTTP result")
				}
			}
			var session operator.Session
			request("POST", "/api/v1/session/login", map[string]string{"access_key": string(bytes.TrimSpace(key))}, &session)
			if !session.Authenticated {
				t.Fatal("fixture authentication")
			}
			var envelope struct {
				Schedule *sites.BackupSchedule `json:"schedule"`
				Runner   bool                  `json:"runner_enabled"`
			}
			for i := 0; i < 20; i++ {
				request("GET", "/api/v1/sites/"+site.ID+"/backup-schedule", nil, &envelope)
				if envelope.Schedule == nil || envelope.Runner != enabled {
					t.Fatal("actual process capability")
				}
				if enabled && envelope.Schedule.LastStatus == "completed" {
					break
				}
				if !enabled && envelope.Schedule.LastStatus != "never" {
					t.Fatal("default-off process dispatched a job")
				}
				time.Sleep(25 * time.Millisecond)
			}
			if enabled && (envelope.Schedule.LastStatus != "completed" || envelope.Schedule.Pending || envelope.Schedule.LastBackupID == "") {
				t.Fatal("opted-in entrypoint did not complete real archive")
			}
			stop()
			reopened, err := sites.Open(filepath.Join(state, "sites"), journal)
			if err != nil {
				t.Fatal("process state reopen", err)
			}
			defer func() {
				if err := reopened.Close(); err != nil {
					t.Error("reopened store cleanup", err)
				}
			}()
			backups, err := reopened.Backups(site.ID)
			want := 0
			if enabled {
				want = 1
			}
			if err != nil || len(backups) != want {
				t.Fatal("unexpected actual process archive count", err)
			}
			if enabled {
				zip, info, err := reopened.ExportBackup(site.ID, envelope.Schedule.LastBackupID)
				if err != nil || len(zip) != int(info.Bytes) || info.Revision != site.Revision {
					t.Fatal("actual entrypoint ZIP verification", err)
				}
			}
		})
	}
}
