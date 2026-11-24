package api

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/sitebackups"
)

// backupBroker adds the broker's backup operations to the sites fake.
type backupBroker struct {
	*sitesBroker
	bmu        sync.Mutex
	configured bool
	password   string
	targetErr  error
	targets    []hostaccounts.BackupTargetInput
	snapshots  []hostaccounts.Snapshot
	backups    []hostaccounts.BackupInput
	restores   []hostaccounts.RestoreInput
	gate       chan struct{}
}

func (b *backupBroker) BackupStatus(context.Context) (hostaccounts.BackupStatus, error) {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	s := hostaccounts.BackupStatus{Ready: true, PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl sifruno-backup", Configured: b.configured}
	if b.configured {
		s.Target = &hostaccounts.BackupTarget{Host: "backup.example.test", Port: 22, User: "sifbackup", Path: "/srv/restic", HostKeys: []string{"ssh-ed25519 AAAA"}}
	}
	return s, nil
}
func (b *backupBroker) SetBackupTarget(_ context.Context, in hostaccounts.BackupTargetInput, _ string) (hostaccounts.BackupTargetResult, error) {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	b.targets = append(b.targets, in)
	if b.targetErr != nil {
		return hostaccounts.BackupTargetResult{}, b.targetErr
	}
	b.configured = true
	res := hostaccounts.BackupTargetResult{Initialized: true, Password: b.password, Status: hostaccounts.BackupStatus{Ready: true, Configured: true, Target: &hostaccounts.BackupTarget{Host: in.Host, Port: in.Port, User: in.User, Path: in.Path, HostKeys: []string{"ssh-ed25519 AAAA"}}}}
	b.password = ""
	return res, nil
}
func (b *backupBroker) BackupAccount(_ context.Context, _ string, in hostaccounts.BackupInput, _ string) (hostaccounts.Snapshot, error) {
	if b.gate != nil {
		<-b.gate
	}
	b.bmu.Lock()
	defer b.bmu.Unlock()
	b.backups = append(b.backups, in)
	return hostaccounts.Snapshot{ID: strings.Repeat("e", 64)}, nil
}
func (b *backupBroker) ListBackups(context.Context, string) ([]hostaccounts.Snapshot, error) {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	return slices.Clone(b.snapshots), nil
}
func (b *backupBroker) RestoreAccount(_ context.Context, _ string, in hostaccounts.RestoreInput, _ string) (hostaccounts.RestoreResult, error) {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	b.restores = append(b.restores, in)
	return hostaccounts.RestoreResult{}, &hostaccounts.BackupError{Step: "import", Detail: "ERROR 1064 (42000) at line 3"}
}
func (b *backupBroker) DrillAccount(_ context.Context, id string, _ hostaccounts.DrillInput, _ string) (hostaccounts.DrillResult, error) {
	return hostaccounts.DrillResult{AccountID: id, Passed: true, CheckedAt: time.Now(), Files: 4}, nil
}
func (b *backupBroker) PruneBackups(context.Context, hostaccounts.PruneInput, string) (hostaccounts.PruneResult, error) {
	return hostaccounts.PruneResult{}, nil
}

// siteRegistry reads the wizard fake's databases as dbhost's registry.
type siteRegistry struct{ d *sitesDatabases }

func (r siteRegistry) ListDatabases(_ context.Context, owner string) ([]dbhost.Database, error) {
	r.d.mu.Lock()
	defer r.d.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(r.d.databases), func(x dbhost.Database) bool { return x.Owner != owner }), nil
}

func backupsFixture(t *testing.T) (siteFixture, *backupBroker, *sitebackups.Manager, Website) {
	t.Helper()
	f, runner, broker, databases, site := actionsFixture(t)
	b := &backupBroker{sitesBroker: broker, password: "repository-password-shown-once-0123456789ab"}
	m, err := sitebackups.Open(filepath.Join(realTempDir(t), "site-backups.json"), b, siteRegistry{databases})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Wait)
	f.handler = New(Options{Operator: f.manager, Accounts: b, Wizard: runner, Backups: m, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return f, b, m, site
}

func storageBody() map[string]any {
	return map[string]any{"host": "backup.example.test", "port": 22, "user": "sifbackup", "path": "/srv/restic", "known_hosts": "# backup.example.test:22 SSH-2.0-OpenSSH_8.7\nbackup.example.test ssh-ed25519 AAAA\n"}
}

func TestBackupStorageShowsThePasswordOnce(t *testing.T) {
	f, b, _, _ := backupsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "GET", "/api/v1/websites/backup-storage", nil, cookie, "")
	var storage BackupStorage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &storage) != nil || storage.Configured || !strings.HasPrefix(storage.PublicKey, "ssh-ed25519 ") || storage.NightlyAt != "02:30" {
		t.Fatalf("storage before a target %d: %s", w.Code, w.Body)
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/backup-storage", storageBody(), cookie, ""); w.Code != 403 || len(b.targets) != 0 {
		t.Fatalf("a save without CSRF: %d", w.Code)
	}
	extra := storageBody()
	extra["command"] = "x"
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/backup-storage", extra, cookie, csrf); w.Code != 422 || len(b.targets) != 0 {
		t.Fatalf("an unknown field: %d %s", w.Code, w.Body)
	}
	text := storageBody()
	text["port"] = "22"
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/backup-storage", text, cookie, csrf); w.Code != 422 || len(b.targets) != 0 {
		t.Fatalf("a port as text: %d %s", w.Code, w.Body)
	}
	w = websiteRequest(f.handler, "POST", "/api/v1/websites/backup-storage", storageBody(), cookie, csrf)
	var saved BackupStorageSaved
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Password != "repository-password-shown-once-0123456789ab" || !saved.Configured || saved.Target.Host != "backup.example.test" {
		t.Fatalf("first save %d: %s", w.Code, w.Body)
	}
	if got := b.targets[0]; got.Port != 22 || !strings.Contains(got.KnownHosts, "\n") || got.Reason == "" {
		t.Fatalf("target sent %+v", got)
	}
	w = websiteRequest(f.handler, "POST", "/api/v1/websites/backup-storage", storageBody(), cookie, csrf)
	if w.Code != 200 || strings.Contains(w.Body.String(), "repository-password") {
		t.Fatalf("second save %d: %s", w.Code, w.Body)
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/websites/backup-storage", nil, cookie, ""); strings.Contains(w.Body.String(), "password") {
		t.Fatalf("the page read carries a password: %s", w.Body)
	}
	b.targetErr = &hostaccounts.BackupError{Step: "connect", Detail: "Host key verification failed."}
	w = websiteRequest(f.handler, "POST", "/api/v1/websites/backup-storage", storageBody(), cookie, csrf)
	detail, technical := problemTexts(t, w)
	if w.Code != 422 || !strings.Contains(detail, "could not reach the backup storage server") || !slices.Contains(technical, "step: connect") || !slices.Contains(technical, "Host key verification failed.") {
		t.Fatalf("refused target %d: %s", w.Code, w.Body)
	}
	b.targetErr = hostaccounts.ErrConflict
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/backup-storage", storageBody(), cookie, csrf); w.Code != 409 || problemDetail(t, w) != backupStorageBusy {
		t.Fatalf("a target change during a backup %d: %s", w.Code, w.Body)
	}
	b.targetErr = hostaccounts.ErrInvalid
	w = websiteRequest(f.handler, "POST", "/api/v1/websites/backup-storage", storageBody(), cookie, csrf)
	if detail, _ := problemTexts(t, w); w.Code != 422 || detail != backupStorageRule {
		t.Fatalf("invalid target %d: %s", w.Code, w.Body)
	}
}

func TestSiteBackupsBackUpNowAndList(t *testing.T) {
	f, b, m, site := backupsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	path := "/api/v1/websites/sites/" + site.AccountID + "/backups"
	if w := websiteRequest(f.handler, "POST", path, map[string]any{}, cookie, csrf); w.Code != 409 || problemDetail(t, w) != backupsNoStorage {
		t.Fatalf("back up without storage %d: %s", w.Code, w.Body)
	}
	b.configured = true
	b.snapshots = []hostaccounts.Snapshot{{ID: strings.Repeat("d", 64), Time: time.Date(2026, 11, 23, 2, 30, 0, 0, time.UTC), Bytes: 2048, Files: 10, Databases: []string{"example_wp"}}}
	b.gate = make(chan struct{})
	w := websiteRequest(f.handler, "POST", path, map[string]any{}, cookie, csrf)
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"kind":"backup"`) {
		t.Fatalf("back up now %d: %s", w.Code, w.Body)
	}
	if w := websiteRequest(f.handler, "POST", path, map[string]any{}, cookie, csrf); w.Code != 409 || problemDetail(t, w) != backupsBusy {
		t.Fatalf("a second job %d: %s", w.Code, w.Body)
	}
	var running SiteBackups
	if w := websiteRequest(f.handler, "GET", path, nil, cookie, ""); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &running) != nil || running.Running == nil || running.Running.Kind != "backup" {
		t.Fatalf("while running %d: %s", w.Code, w.Body)
	}
	close(b.gate)
	m.Wait()
	var got SiteBackups
	w = websiteRequest(f.handler, "GET", path, nil, cookie, "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("list %d: %s", w.Code, w.Body)
	}
	if !got.Configured || got.Running != nil || got.LastBackup == nil || got.LastBackup.Status != "succeeded" || len(got.Snapshots) != 1 || got.Domain != "example.com" || got.Revision != site.Revision {
		t.Fatalf("site backups %+v", got)
	}
	// The site's own registry databases were named, nothing else.
	if len(b.backups) != 1 || !slices.Equal(b.backups[0].Databases, []string{"example_wp"}) {
		t.Fatalf("backup input %+v", b.backups)
	}
	if w := websiteRequest(f.handler, "POST", path+"/drill", map[string]any{}, cookie, csrf); w.Code != 202 {
		t.Fatalf("drill now %d: %s", w.Code, w.Body)
	}
	m.Wait()
	if w := websiteRequest(f.handler, "GET", path, nil, cookie, ""); !strings.Contains(w.Body.String(), `"last_drill":{"account_id":"`+site.AccountID) {
		t.Fatalf("drill result %s", w.Body)
	}
	if w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+strings.Repeat("f", 32)+"/backups", nil, cookie, ""); w.Code != 404 {
		t.Fatalf("an unknown site %d", w.Code)
	}
}

func TestSiteBackupRestoreNeedsTheTypedDomain(t *testing.T) {
	f, b, m, site := backupsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	b.configured = true
	snap := strings.Repeat("d", 64)
	b.snapshots = []hostaccounts.Snapshot{{ID: snap, Databases: []string{"example_wp"}}}
	path := "/api/v1/websites/sites/" + site.AccountID + "/backups/restore"
	body := func(what, domain string, revision uint64, id string) map[string]any {
		return map[string]any{"snapshot": id, "what": what, "confirm_domain": domain, "expected_revision": revision}
	}
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"wrong domain":     {body("both", "example.org", site.Revision, snap), 422},
		"domain in caps":   {body("both", "EXAMPLE.COM", site.Revision, snap), 422},
		"unknown what":     {body("everything", "example.com", site.Revision, snap), 422},
		"stale revision":   {body("both", "example.com", site.Revision+1, snap), 409},
		"short snapshot":   {body("both", "example.com", site.Revision, "dddddddd"), 422},
		"unknown snapshot": {body("both", "example.com", site.Revision, strings.Repeat("c", 64)), 404},
	} {
		if w := websiteRequest(f.handler, "POST", path, c.body, cookie, csrf); w.Code != c.code {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if len(b.restores) != 0 {
		t.Fatal("a refused restore reached the broker")
	}
	w := websiteRequest(f.handler, "POST", path, body("both", "example.com", site.Revision, snap), cookie, csrf)
	if w.Code != 202 {
		t.Fatalf("restore %d: %s", w.Code, w.Body)
	}
	m.Wait()
	if in := b.restores[0]; !in.Files || !slices.Equal(in.Databases, []string{"example_wp"}) || in.ExpectedRevision != site.Revision || in.Snapshot != snap {
		t.Fatalf("restore input %+v", in)
	}
	var got SiteBackups
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.AccountID+"/backups", nil, cookie, "")
	if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.LastRestore == nil || got.LastRestore.Status != "failed" || got.LastRestore.Step != "import" || !strings.Contains(got.LastRestore.Message, "may be partly restored") {
		t.Fatalf("failed restore %s", w.Body)
	}
	b.snapshots = []hostaccounts.Snapshot{{ID: snap, Databases: []string{"example_old"}}}
	if w := websiteRequest(f.handler, "POST", path, body("database", "example.com", site.Revision, snap), cookie, csrf); w.Code != 422 || !strings.Contains(problemDetail(t, w), "none of this site's current databases") {
		t.Fatalf("a backup without the site's database %d: %s", w.Code, w.Body)
	}
}

func TestBackupsNotSetUp(t *testing.T) {
	f, _, _, _, site := actionsFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/websites/backup-storage"},
		{"GET", "/api/v1/websites/sites/" + site.AccountID + "/backups"},
		{"POST", "/api/v1/websites/sites/" + site.AccountID + "/backups"},
	} {
		var body any
		if c.method == "POST" {
			body = map[string]any{}
		}
		if w := websiteRequest(f.handler, c.method, c.path, body, cookie, csrf); w.Code != 503 || problemDetail(t, w) != backupsNotSetUp {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
}
