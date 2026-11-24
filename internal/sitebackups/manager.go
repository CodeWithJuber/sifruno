// Package sitebackups is the panel's side of website backups. The broker
// does the work (restic, the database tools, the restore); this package
// decides when: a nightly backup of every live site at a fixed time in the
// server's timezone, a weekly prune and a weekly restore drill of one site
// in turn. It also runs the jobs a person starts (back up now, restore,
// drill now), one job per site at a time, and keeps the last results.
package sitebackups

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
)

// Broker is the part of the broker client backups use.
type Broker interface {
	List(ctx context.Context) ([]hostaccounts.Account, error)
	hostaccounts.BackupService
}

// Databases names a site's databases: dbhost's registry is the authority.
type Databases interface {
	ListDatabases(ctx context.Context, owner string) ([]dbhost.Database, error)
}

// The nightly backup starts at 02:30 server time; the weekly prune and
// drill follow the first nightly run of each ISO week.
const (
	NightlyHour   = 2
	NightlyMinute = 30
)

// BackupJob is the job a site has in progress.
type BackupJob struct {
	Kind      string    `json:"kind" enum:"backup,restore,drill"`
	StartedAt time.Time `json:"started_at"`
	Actor     string    `json:"actor"`
}

// BackupResult is a finished backup, restore or drill of one site. Message says
// what happened, why and what to do next; Step and Detail are the broker's
// words for "Technical details".
type BackupResult struct {
	Kind       string    `json:"kind" enum:"backup,restore,drill"`
	Status     string    `json:"status" enum:"succeeded,failed"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Actor      string    `json:"actor"`
	Snapshot   string    `json:"snapshot,omitempty"`
	What       string    `json:"what,omitempty" doc:"For a restore: files, database or both."`
	Message    string    `json:"message"`
	Step       string    `json:"step,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

// RestoreDrill is the server's last restore drill.
type RestoreDrill struct {
	AccountID    string    `json:"account_id"`
	Domain       string    `json:"domain"`
	Passed       bool      `json:"passed"`
	CheckedAt    time.Time `json:"checked_at"`
	Snapshot     string    `json:"snapshot,omitempty"`
	SnapshotTime time.Time `json:"snapshot_time,omitzero"`
	Files        uint64    `json:"files"`
	Subset       string    `json:"subset,omitempty"`
	Message      string    `json:"message"`
	Step         string    `json:"step,omitempty"`
	Detail       string    `json:"detail,omitempty"`
}

// BackupPrune is the last weekly prune.
type BackupPrune struct {
	At      time.Time `json:"at"`
	Passed  bool      `json:"passed"`
	Removed int       `json:"removed"`
	Message string    `json:"message"`
	Step    string    `json:"step,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

type siteState struct {
	LastBackup  *BackupResult `json:"last_backup,omitempty"`
	LastRestore *BackupResult `json:"last_restore,omitempty"`
}

type state struct {
	Version       int                   `json:"version"`
	LastNightly   string                `json:"last_nightly"`
	LastPruneWeek string                `json:"last_prune_week"`
	LastDrillWeek string                `json:"last_drill_week"`
	DrillAfter    string                `json:"drill_after"`
	LastDrill     *RestoreDrill         `json:"last_drill,omitempty"`
	LastPrune     *BackupPrune          `json:"last_prune,omitempty"`
	Sites         map[string]*siteState `json:"sites"`
}

// Site is what a site's Backups section shows besides its snapshots.
type Site struct {
	Running     *BackupJob    `json:"running"`
	LastBackup  *BackupResult `json:"last_backup"`
	LastRestore *BackupResult `json:"last_restore"`
	LastDrill   *RestoreDrill `json:"last_drill" doc:"The server's last restore drill, of whichever site it was."`
}

// Server is what the Backup storage page shows besides the broker's status.
type Server struct {
	NightlyAt string        `json:"nightly_at" doc:"When the nightly backup starts, HH:MM in the server's timezone."`
	Timezone  string        `json:"timezone"`
	LastDrill *RestoreDrill `json:"last_drill"`
	LastPrune *BackupPrune  `json:"last_prune"`
}

var (
	// ErrBusy means the site already has a backup, restore or drill running.
	ErrBusy = errors.New("this site already has a backup job running")
	// ErrNoDatabase means a database restore found none of the site's
	// databases in the backup.
	ErrNoDatabase = errors.New("the backup holds none of this site's databases")
)

// Manager keeps the state file and the running jobs.
type Manager struct {
	broker Broker
	dbs    Databases
	path   string
	now    func() time.Time
	loc    *time.Location

	mu      sync.Mutex
	st      state
	running map[string]BackupJob
	jobs    sync.WaitGroup
}

// Open reads the state file (0600) or starts an empty one.
func Open(path string, broker Broker, dbs Databases) (*Manager, error) {
	if broker == nil || dbs == nil {
		return nil, errors.New("site backups need the broker and the database registry")
	}
	m := &Manager{broker: broker, dbs: dbs, path: path, now: time.Now, loc: time.Local, running: map[string]BackupJob{}, st: state{Version: 1, Sites: map[string]*siteState{}}}
	raw, err := os.ReadFile(path)
	if err == nil {
		var st state
		if json.Unmarshal(raw, &st) != nil || st.Version != 1 {
			return nil, errors.New("the site backup state file " + path + " cannot be read")
		}
		if st.Sites == nil {
			st.Sites = map[string]*siteState{}
		}
		m.st = st
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return m, nil
}

// save writes the state beside itself and renames it into place. The
// caller holds mu.
func (m *Manager) save() error {
	raw, err := json.Marshal(m.st)
	if err != nil {
		return err
	}
	tmp := m.path + ".new"
	if err = os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// Status is the broker's backup status: its key, readiness and target.
func (m *Manager) Status(ctx context.Context) (hostaccounts.BackupStatus, error) {
	return m.broker.BackupStatus(ctx)
}

// SetTarget points backups at an SFTP storage server.
func (m *Manager) SetTarget(ctx context.Context, in hostaccounts.BackupTargetInput, actor string) (hostaccounts.BackupTargetResult, error) {
	return m.broker.SetBackupTarget(ctx, in, actor)
}

// Snapshots lists one site's backups, newest first.
func (m *Manager) Snapshots(ctx context.Context, id string) ([]hostaccounts.Snapshot, error) {
	return m.broker.ListBackups(ctx, id)
}

// Schedule names when the nightly backup runs, and the server's timezone.
func (m *Manager) Schedule() (string, string) {
	return twoDigits(NightlyHour) + ":" + twoDigits(NightlyMinute), zoneName(m.loc, m.now())
}

// zoneName names the server's timezone: Go calls the system zone "Local",
// so its name comes from TZ or from the /etc/localtime link, else the
// zone's abbreviation and offset.
func zoneName(loc *time.Location, now time.Time) string {
	if loc != time.Local {
		return loc.String()
	}
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); tz != "" && !strings.HasPrefix(tz, "/") {
		return tz
	}
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if _, name, ok := strings.Cut(target, "zoneinfo/"); ok && name != "" {
			return name
		}
	}
	return now.In(loc).Format("MST (UTC-07:00)")
}

// Server returns the server-wide results.
func (m *Manager) Server() Server {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, zone := m.Schedule()
	return Server{NightlyAt: at, Timezone: zone, LastDrill: m.st.LastDrill, LastPrune: m.st.LastPrune}
}

// Site returns one site's running job and last results.
func (m *Manager) Site(id string) Site {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := Site{LastDrill: m.st.LastDrill}
	if r, ok := m.running[id]; ok {
		out.Running = &r
	}
	if s := m.st.Sites[id]; s != nil {
		out.LastBackup, out.LastRestore = s.LastBackup, s.LastRestore
	}
	return out
}

// begin marks the site busy, or answers ErrBusy.
func (m *Manager) begin(id, kind, actor string) (BackupJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, busy := m.running[id]; busy {
		return BackupJob{}, ErrBusy
	}
	r := BackupJob{Kind: kind, StartedAt: m.now().UTC(), Actor: actor}
	m.running[id] = r
	return r, nil
}

func (m *Manager) end(id string, record func(*state)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.running, id)
	if record != nil {
		record(&m.st)
		_ = m.save()
	}
}

func (m *Manager) site(st *state, id string) *siteState {
	if st.Sites[id] == nil {
		st.Sites[id] = &siteState{}
	}
	return st.Sites[id]
}

// siteDatabases names the site's databases from the registry, keeping only
// entries recorded for that owner.
func (m *Manager) siteDatabases(ctx context.Context, owner string) ([]string, error) {
	items, err := m.dbs.ListDatabases(ctx, owner)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, d := range items {
		if d.Owner == owner && strings.HasPrefix(d.Name, owner+"_") {
			names = append(names, d.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// backup runs one site's backup and records it. The caller has marked the
// site busy.
func (m *Manager) backup(ctx context.Context, a hostaccounts.Account, actor, reason string, started BackupJob) {
	result := BackupResult{Kind: "backup", StartedAt: started.StartedAt, Actor: actor}
	dbs, err := m.siteDatabases(ctx, a.Username)
	var snap hostaccounts.Snapshot
	if err == nil {
		snap, err = m.broker.BackupAccount(ctx, a.ID, hostaccounts.BackupInput{Databases: dbs, Reason: reason}, actor)
	} else {
		err = &registryError{err}
	}
	result.FinishedAt = m.now().UTC()
	if err != nil {
		result.Status = "failed"
		result.Message, result.Step, result.Detail = Explain(err, "backup")
	} else {
		result.Status, result.Snapshot = "succeeded", snap.ID
		result.Message = "The site and its databases were backed up."
	}
	m.end(a.ID, func(st *state) { m.site(st, a.ID).LastBackup = &result })
}

// BackUpNow starts a backup of one site in the background.
func (m *Manager) BackUpNow(a hostaccounts.Account, actor string) (BackupJob, error) {
	started, err := m.begin(a.ID, "backup", actor)
	if err != nil {
		return BackupJob{}, err
	}
	m.jobs.Add(1)
	go func() {
		defer m.jobs.Done()
		m.backup(context.Background(), a, actor, "Back up now on the website's page", started)
	}()
	return started, nil
}

// Restore starts a restore of one site from one of its snapshots: what is
// files, database or both. A database restore names the snapshot's
// databases that are still the site's.
func (m *Manager) Restore(ctx context.Context, a hostaccounts.Account, snap hostaccounts.Snapshot, what, actor string) (BackupJob, error) {
	in := hostaccounts.RestoreInput{ExpectedRevision: a.Revision, Snapshot: snap.ID, Files: what == "files" || what == "both", Databases: []string{}, Reason: "Restored on the website's page"}
	if what == "database" || what == "both" {
		own, err := m.siteDatabases(ctx, a.Username)
		if err != nil {
			return BackupJob{}, &registryError{err}
		}
		for _, db := range snap.Databases {
			if slices.Contains(own, db) {
				in.Databases = append(in.Databases, db)
			}
		}
		if len(in.Databases) == 0 {
			return BackupJob{}, ErrNoDatabase
		}
	}
	started, err := m.begin(a.ID, "restore", actor)
	if err != nil {
		return BackupJob{}, err
	}
	m.jobs.Add(1)
	go func() {
		defer m.jobs.Done()
		result := BackupResult{Kind: "restore", StartedAt: started.StartedAt, Actor: actor, Snapshot: snap.ID, What: what}
		_, err := m.broker.RestoreAccount(context.Background(), a.ID, in, actor)
		result.FinishedAt = m.now().UTC()
		if err != nil {
			result.Status = "failed"
			result.Message, result.Step, result.Detail = Explain(err, "restore")
		} else {
			result.Status = "succeeded"
			result.Message = restoredMessage(what)
		}
		m.end(a.ID, func(st *state) { m.site(st, a.ID).LastRestore = &result })
	}()
	return started, nil
}

func restoredMessage(what string) string {
	switch what {
	case "files":
		return "The site's files were restored from the backup. Files added since the backup were kept."
	case "database":
		return "The site's database was restored from the backup."
	default:
		return "The site's files and database were restored from the backup. Files added since the backup were kept."
	}
}

// drill runs one site's restore drill and records it as the server's last.
func (m *Manager) drill(ctx context.Context, a hostaccounts.Account, actor, reason string) {
	d := RestoreDrill{AccountID: a.ID, Domain: a.Domain}
	got, err := m.broker.DrillAccount(ctx, a.ID, hostaccounts.DrillInput{Reason: reason}, actor)
	switch {
	case err != nil:
		d.CheckedAt = m.now().UTC()
		d.Message, d.Step, d.Detail = Explain(err, "drill")
	case got.Passed:
		d.Passed, d.CheckedAt, d.Snapshot, d.SnapshotTime, d.Files, d.Subset = true, got.CheckedAt, got.Snapshot, got.SnapshotTime, got.Files, got.Subset
		d.Message = "The latest backup restored completely and matched its file list, and the checked part of the stored data was sound."
	default:
		d.CheckedAt, d.Snapshot, d.SnapshotTime, d.Subset = got.CheckedAt, got.Snapshot, got.SnapshotTime, got.Subset
		d.Message, d.Step, d.Detail = Explain(&hostaccounts.BackupError{Step: got.Step, Detail: got.Detail}, "drill")
	}
	m.end(a.ID, func(st *state) { st.LastDrill = &d })
}

// DrillNow starts a restore drill of one site in the background.
func (m *Manager) DrillNow(a hostaccounts.Account, actor string) (BackupJob, error) {
	started, err := m.begin(a.ID, "drill", actor)
	if err != nil {
		return BackupJob{}, err
	}
	m.jobs.Add(1)
	go func() {
		defer m.jobs.Done()
		m.drill(context.Background(), a, actor, "Restore drill on the website's page")
	}()
	return started, nil
}

// Wait waits for the jobs started so far.
func (m *Manager) Wait() { m.jobs.Wait() }

// Run checks once a minute whether the nightly or weekly work is due.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		m.RunDue(ctx, m.now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func isoWeek(t time.Time) string {
	year, week := t.ISOWeek()
	return time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006") + "-W" + twoDigits(week)
}

func twoDigits(n int) string {
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}

// liveSites are the accounts with a site, in ID order.
func liveSites(accounts []hostaccounts.Account) []hostaccounts.Account {
	out := []hostaccounts.Account{}
	for _, a := range accounts {
		if a.Web.PHPVersion != "" && (a.State == "active" || a.State == "suspended") {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RunDue runs the nightly backups once a day after 02:30 server time, then,
// once per ISO week, the prune and a drill of the next site in turn. A day
// counts as done when it starts, so a panel restarted during the night
// does not start it again. Nothing runs until backup storage is set up.
func (m *Manager) RunDue(ctx context.Context, now time.Time) {
	local := now.In(m.loc)
	today := local.Format("2006-01-02")
	m.mu.Lock()
	due := local.Hour()*60+local.Minute() >= NightlyHour*60+NightlyMinute && m.st.LastNightly != today
	m.mu.Unlock()
	if !due || ctx.Err() != nil {
		return
	}
	status, err := m.broker.BackupStatus(ctx)
	if err != nil {
		return // the broker did not answer: try again next minute
	}
	if !status.Configured {
		// Nothing to back up to: the night counts as done, so the broker
		// is asked once a day, not once a minute.
		m.mu.Lock()
		m.st.LastNightly = today
		_ = m.save()
		m.mu.Unlock()
		return
	}
	accounts, err := m.broker.List(ctx)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.st.LastNightly = today
	_ = m.save()
	m.mu.Unlock()
	sites := liveSites(accounts)
	for _, a := range sites {
		if ctx.Err() != nil {
			return
		}
		started, err := m.begin(a.ID, "backup", "scheduler")
		if err != nil {
			continue // a job a person started is running for this site
		}
		m.backup(ctx, a, "scheduler", "Nightly backup", started)
	}
	week := isoWeek(local)
	m.mu.Lock()
	prune := m.st.LastPruneWeek != week
	if prune {
		m.st.LastPruneWeek = week
		_ = m.save()
	}
	m.mu.Unlock()
	if prune {
		p := BackupPrune{}
		got, err := m.broker.PruneBackups(ctx, hostaccounts.PruneInput{Reason: "Weekly prune: keep 7 daily and 4 weekly"}, "scheduler")
		p.At = m.now().UTC()
		if err != nil {
			p.Message, p.Step, p.Detail = Explain(err, "prune")
		} else {
			p.Passed, p.Removed = true, got.Removed
			p.Message = "Old backups beyond 7 daily and 4 weekly were removed."
		}
		m.mu.Lock()
		m.st.LastPrune = &p
		_ = m.save()
		m.mu.Unlock()
	}
	m.mu.Lock()
	drill := m.st.LastDrillWeek != week && len(sites) > 0
	var next hostaccounts.Account
	if drill {
		next = sites[0]
		for _, a := range sites {
			if a.ID > m.st.DrillAfter {
				next = a
				break
			}
		}
		m.st.LastDrillWeek, m.st.DrillAfter = week, next.ID
		_ = m.save()
	}
	m.mu.Unlock()
	if drill {
		if _, err := m.begin(next.ID, "drill", "scheduler"); err == nil {
			m.drill(ctx, next, "scheduler", "Weekly restore drill")
		}
	}
}

// StatePath is where the panel keeps the state file.
func StatePath(stateDir string) string { return filepath.Join(stateDir, "site-backups.json") }
