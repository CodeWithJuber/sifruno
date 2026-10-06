package native_backup_schedule_review_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/api"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
	"sifruno/internal/trail"
)

const local = "http://127.0.0.1:8181"

type admission struct {
	cookie *http.Cookie
	csrf   string
}
type fixture struct {
	dir     string
	store   *sites.Store
	journal *trail.Store
	manager *operator.Manager
	handler http.Handler
	site    sites.Site
	auth    admission
}
type schedule struct {
	SiteID   string     `json:"site_id"`
	Revision uint64     `json:"revision"`
	Interval string     `json:"interval"`
	Enabled  bool       `json:"enabled"`
	Created  time.Time  `json:"created_at"`
	Updated  time.Time  `json:"updated_at"`
	Next     time.Time  `json:"next_run_at"`
	Last     *time.Time `json:"last_run_at"`
	Status   string     `json:"last_status"`
	BackupID string     `json:"last_backup_id"`
	Error    string     `json:"last_error"`
	Pending  bool       `json:"pending"`
}
type envelope struct {
	Schedule    *schedule `json:"schedule"`
	Intervals   []string  `json:"intervals"`
	MaxArchives int       `json:"max_archives"`
	Runner      bool      `json:"runner_enabled"`
}

func isolated(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir()}
	var err error
	f.dir, err = filepath.EvalSymlinks(f.dir)
	if err != nil {
		t.Fatal("temporary directory admission failed")
	}
	f.journal, err = trail.Open(filepath.Join(f.dir, "journal"))
	if err != nil {
		t.Fatal("isolated journal unavailable")
	}
	f.store, err = sites.Open(filepath.Join(f.dir, "sites"), f.journal)
	if err != nil {
		t.Fatal("isolated sites unavailable")
	}
	t.Cleanup(func() {
		if f.store != nil && f.store.Close() != nil {
			t.Error("owned store cleanup failed")
		}
	})
	f.manager, err = operator.Open(filepath.Join(f.dir, "operator"))
	if err != nil {
		t.Fatal("isolated operator unavailable")
	}
	f.site, err = f.store.Create(sites.CreateInput{Name: "Schedule review", Domain: "schedule.test"}, "local-operator")
	if err != nil {
		t.Fatal("isolated site creation failed")
	}
	f.handler = api.New(api.Options{Sites: f.store, Trail: f.journal, Operator: f.manager, AllowedOrigins: []string{local}})
	key, err := os.ReadFile(f.manager.AccessKeyPath())
	if err != nil {
		t.Fatal("isolated login unavailable")
	}
	body, _ := json.Marshal(map[string]string{"access_key": strings.TrimSpace(string(key))})
	w := request(f, "POST", "/api/v1/session/login", string(body), admission{}, nil)
	status(t, w, 200)
	var s operator.Session
	decode(t, w.Body.Bytes(), &s)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !s.Authenticated || s.CSRFToken == "" {
		t.Fatal("isolated admission failed")
	}
	f.auth = admission{cookies[0], s.CSRFToken}
	return f
}
func request(f *fixture, method, path, body string, a admission, adjust func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, local+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:43111"
	r.Header.Set("Origin", local)
	r.Header.Set("Content-Type", "application/json")
	if a.cookie != nil {
		r.AddCookie(a.cookie)
	}
	if a.csrf != "" {
		r.Header.Set("X-CSRF-Token", a.csrf)
	}
	if adjust != nil {
		adjust(r)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}
func status(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("HTTP status=%d want=%d; body withheld", w.Code, want)
	}
}
func decode(t *testing.T, raw []byte, dst any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(&struct{}{}) != io.EOF {
		t.Fatal("exact response DTO violated")
	}
}
func keys(t *testing.T, raw []byte, want ...string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) != len(want) {
		t.Fatal("response field inventory differs")
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Fatal("response field missing or aliased")
		}
	}
	return m
}
func path(f *fixture) string { return "/api/v1/sites/" + f.site.ID + "/backup-schedule" }
func inspect(t *testing.T, f *fixture) envelope {
	t.Helper()
	w := request(f, "GET", path(f), "", f.auth, nil)
	status(t, w, 200)
	m := keys(t, w.Body.Bytes(), "schedule", "intervals", "max_archives", "runner_enabled")
	var e envelope
	decode(t, w.Body.Bytes(), &e)
	if !reflect.DeepEqual(e.Intervals, []string{"hourly", "daily", "weekly"}) || e.MaxArchives != 8 {
		t.Fatal("preset/cap contract differs")
	}
	if e.Schedule != nil {
		keys(t, m["schedule"], "site_id", "revision", "interval", "enabled", "created_at", "updated_at", "next_run_at", "last_run_at", "last_status", "last_backup_id", "last_error", "pending")
		if e.Schedule.SiteID != f.site.ID || e.Schedule.Revision == 0 || e.Schedule.Created.IsZero() || e.Schedule.Updated.IsZero() {
			t.Fatal("schedule identity/revision/time invalid")
		}
	}
	for _, secret := range []string{f.auth.csrf, f.auth.cookie.Value} {
		if secret != "" && bytes.Contains(w.Body.Bytes(), []byte(secret)) {
			t.Fatal("schedule response contains private admission")
		}
	}
	return e
}
func input(siteRevision, scheduleRevision uint64, interval string, enabled bool) string {
	b, _ := json.Marshal(map[string]any{"expected_revision": siteRevision, "expected_schedule_revision": scheduleRevision, "interval": interval, "enabled": enabled})
	return string(b)
}

func TestExactAbsentAndOffRunnerContract(t *testing.T) {
	f := isolated(t)
	e := inspect(t, f)
	if e.Schedule != nil || e.Runner {
		t.Fatal("new store must have absent schedule and disabled runner")
	}
	status(t, request(f, "PUT", path(f), input(f.site.Revision, 0, "hourly", true), f.auth, nil), 503)
	if inspect(t, f).Schedule != nil {
		t.Fatal("off-runner enable changed persistent schedule")
	}
	status(t, request(f, "PUT", path(f), input(f.site.Revision, 0, "daily", false), f.auth, nil), 200)
	e = inspect(t, f)
	if e.Schedule == nil || e.Schedule.Enabled || e.Schedule.Pending || e.Schedule.Status != "never" || e.Schedule.Last != nil || e.Schedule.BackupID != "" || e.Schedule.Error != "" {
		t.Fatal("paused new schedule state invalid")
	}
	status(t, request(f, "PUT", path(f), input(f.site.Revision, 0, "weekly", false), f.auth, nil), 409)
	saved := *e.Schedule
	if f.store.Close() != nil {
		t.Fatal("owned close failed")
	}
	var err error
	f.store, err = sites.Open(filepath.Join(f.dir, "sites"), f.journal)
	if err != nil {
		t.Fatal("paused schedule reopen failed")
	}
	f.handler = api.New(api.Options{Sites: f.store, Trail: f.journal, Operator: f.manager, AllowedOrigins: []string{local}})
	reopened := inspect(t, f)
	if reopened.Schedule == nil || !reflect.DeepEqual(saved, *reopened.Schedule) || reopened.Runner {
		t.Fatal("paused schedule persistence changed")
	}
}

func TestHTTPRefusalsLeaveAbsentSchedule(t *testing.T) {
	f := isolated(t)
	valid := input(f.site.Revision, 0, "hourly", false)
	cases := []struct {
		name, body string
		adjust     func(*http.Request)
		want       int
	}{
		{"empty", "", nil, 400}, {"null", "null", nil, 400}, {"array", "[]", nil, 400},
		{"unknown", strings.TrimSuffix(valid, "}") + `,"secret_field":"withheld"}`, nil, 400},
		{"duplicate", strings.TrimSuffix(valid, "}") + `,"enabled":true}`, nil, 400},
		{"case alias", strings.Replace(valid, `"interval"`, `"Interval"`, 1), nil, 400},
		{"trailing", valid + `{}`, nil, 400}, {"oversize", valid + strings.Repeat(" ", 5000), nil, 413},
		{"wrong content", valid, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"no origin", valid, func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"wrong origin", valid, func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:8182") }, 403},
		{"no csrf", valid, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
		{"wrong csrf", valid, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "invalid") }, 403},
		{"nonlocal peer", valid, func(r *http.Request) {
			r.RemoteAddr = "198.51.100.11:1234"
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
		}, 403},
		{"foreign host", valid, func(r *http.Request) { r.Host = "foreign.test" }, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status(t, request(f, "PUT", path(f), tc.body, f.auth, tc.adjust), tc.want)
			if inspect(t, f).Schedule != nil {
				t.Fatal("refusal mutated schedule")
			}
		})
	}
	status(t, request(f, "GET", path(f), "", admission{}, nil), 401)
	status(t, request(f, "PUT", path(f), valid, admission{}, nil), 401)
	status(t, request(f, "GET", "/api/v1/sites/"+strings.Repeat("a", 32)+"/backup-schedule", "", f.auth, nil), 404)
}

func enabledHandler(f *fixture) {
	f.handler = api.New(api.Options{Sites: f.store, Trail: f.journal, Operator: f.manager, AllowedOrigins: []string{local}, BackupSchedulerEnabled: true})
}
func dueSchedule(t *testing.T, f *fixture, interval string) schedule {
	t.Helper()
	enabledHandler(f)
	status(t, request(f, "PUT", path(f), input(f.site.Revision, 0, interval, true), f.auth, nil), 200)
	e := inspect(t, f)
	if e.Schedule == nil || !e.Runner || !e.Schedule.Enabled || e.Schedule.Next.IsZero() || !e.Schedule.Next.After(e.Schedule.Created) {
		t.Fatal("enabled schedule not admitted")
	}
	return *e.Schedule
}
func backups(t *testing.T, f *fixture) []sites.BackupInfo {
	t.Helper()
	b, err := f.store.Backups(f.site.ID)
	if err != nil {
		t.Fatal("actual archive catalog invalid")
	}
	return b
}
func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func TestDueConsumptionAndNoCatchup(t *testing.T) {
	for _, preset := range []string{"hourly", "daily", "weekly"} {
		t.Run(preset, func(t *testing.T) {
			f := isolated(t)
			before := f.site.Revision
			s := dueSchedule(t, f, preset)
			if changed, err := f.store.RunDueBackups(s.Next.Add(-time.Second)); err != nil || changed {
				t.Fatal("future due point consumed")
			}
			if len(backups(t, f)) != 0 {
				t.Fatal("archive created early")
			}
			if changed, err := f.store.RunDueBackups(s.Next); err != nil || !changed {
				t.Fatal("due point not consumed")
			}
			e := inspect(t, f)
			b := backups(t, f)
			if len(b) != 1 || e.Schedule.Status != "completed" || e.Schedule.Pending || e.Schedule.Last == nil || !e.Schedule.Last.Equal(s.Next) || e.Schedule.BackupID != b[0].ID || e.Schedule.Error != "" || b[0].Revision != before {
				t.Fatal("actual completion/catalog proof differs")
			}
			raw, info, err := f.store.ExportBackup(f.site.ID, b[0].ID)
			if err != nil || digest(raw) != info.SHA256 || info.Bytes != int64(len(raw)) || info.Files < 1 {
				t.Fatal("actual ZIP hash/catalog verification failed")
			}
			current, err := f.store.Get(f.site.ID)
			if err != nil || current.Revision != before+1 {
				t.Fatal("backup site revision not advanced exactly once")
			}
			if changed, err := f.store.RunDueBackups(s.Next); err != nil || changed || len(backups(t, f)) != 1 {
				t.Fatal("same due point duplicated")
			}
			late := e.Schedule.Next.Add(10 * 7 * 24 * time.Hour)
			if changed, err := f.store.RunDueBackups(late); err != nil || !changed {
				t.Fatal("overdue point not consumed")
			}
			if len(backups(t, f)) != 2 || !inspect(t, f).Schedule.Next.After(late) {
				t.Fatal("overdue run created catch-up schedule")
			}
			if changed, err := f.store.RunDueBackups(late); err != nil || changed || len(backups(t, f)) != 2 {
				t.Fatal("overdue point replayed")
			}
		})
	}
}

func TestConcurrentRunAndPauseSerialize(t *testing.T) {
	f := isolated(t)
	s := ageNeverSchedule(t, f, dueSchedule(t, f, "hourly"))
	start := make(chan struct{})
	var wg sync.WaitGroup
	counts := make(chan bool, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			changed, err := f.store.RunDueBackups(s.Next)
			counts <- changed
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(counts)
	close(errs)
	consumed := 0
	for changed := range counts {
		if changed {
			consumed++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent actual run failed")
		}
	}
	if consumed != 1 || len(backups(t, f)) != 1 {
		t.Fatal("concurrent run duplicated consumed point")
	}
	current, err := f.store.Get(f.site.ID)
	if err != nil {
		t.Fatal("current site missing")
	}
	sch := inspect(t, f).Schedule
	status(t, request(f, "PUT", path(f), input(f.site.Revision, sch.Revision, "hourly", false), f.auth, nil), 409)
	status(t, request(f, "PUT", path(f), input(current.Revision, sch.Revision-1, "hourly", false), f.auth, nil), 409)
	status(t, request(f, "PUT", path(f), input(current.Revision, sch.Revision, "hourly", false), f.auth, nil), 200)
	paused := inspect(t, f).Schedule
	if paused.Enabled || paused.Status != "completed" || paused.BackupID != sch.BackupID || paused.Last == nil || !paused.Last.Equal(*sch.Last) {
		t.Fatal("pause discarded historical completion")
	}
	if changed, err := f.store.RunDueBackups(paused.Next.Add(24 * time.Hour)); err != nil || changed || len(backups(t, f)) != 1 {
		t.Fatal("paused schedule ran")
	}
}

func TestArchiveCountCapacityPreservesExistingBytes(t *testing.T) {
	f := isolated(t)
	for i := 0; i < sites.MaxBackups; i++ {
		_, err := f.store.Backup(f.site.ID, f.site.Revision, "local-operator")
		if err != nil {
			t.Fatal("quota fixture backup failed")
		}
		f.site, err = f.store.Get(f.site.ID)
		if err != nil {
			t.Fatal("quota fixture current state failed")
		}
	}
	old := backups(t, f)
	hashes := map[string]string{}
	for _, b := range old {
		raw, _, err := f.store.ExportBackup(f.site.ID, b.ID)
		if err != nil {
			t.Fatal("quota fixture ZIP unavailable")
		}
		hashes[b.ID] = digest(raw)
	}
	s := dueSchedule(t, f, "hourly")
	processed, _ := f.store.RunDueBackups(s.Next)
	e := inspect(t, f)
	if !processed || e.Schedule.Status != "failed" || e.Schedule.Error != "archive_capacity" || e.Schedule.BackupID != "" || e.Schedule.Pending || e.Schedule.Last == nil {
		t.Fatal("quota failure not bounded/recorded")
	}
	if len(backups(t, f)) != 8 {
		t.Fatal("quota pruned or added archive")
	}
	for _, b := range backups(t, f) {
		raw, _, err := f.store.ExportBackup(f.site.ID, b.ID)
		if err != nil || digest(raw) != hashes[b.ID] {
			t.Fatal("quota changed retained archive bytes")
		}
	}
	if processed, err := f.store.RunDueBackups(s.Next); err != nil || processed {
		t.Fatal("quota point automatically retried")
	}
}

func TestRequiredTypedInputsRefuseWithoutMutation(t *testing.T) {
	f := isolated(t)
	valid := input(f.site.Revision, 0, "hourly", false)
	for _, tc := range []struct{ name, body string }{
		{"missing enabled", strings.Replace(valid, `"enabled":false,`, "", 1)},
		{"null enabled", strings.Replace(valid, `"enabled":false`, `"enabled":null`, 1)},
		{"missing absent revision", strings.Replace(valid, `"expected_schedule_revision":0,`, "", 1)},
		{"null absent revision", strings.Replace(valid, `"expected_schedule_revision":0`, `"expected_schedule_revision":null`, 1)},
		{"missing site revision", strings.Replace(valid, `"expected_revision":1,`, "", 1)},
		{"null site revision", strings.Replace(valid, `"expected_revision":1`, `"expected_revision":null`, 1)},
		{"null interval", strings.Replace(valid, `"interval":"hourly"`, `"interval":null`, 1)},
		{"unknown interval", strings.Replace(valid, `"interval":"hourly"`, `"interval":"monthly"`, 1)},
		{"cron not a preset", strings.Replace(valid, `"interval":"hourly"`, `"interval":"* * * * *"`, 1)},
		{"boolean string", strings.Replace(valid, `"enabled":false`, `"enabled":"false"`, 1)},
		{"numeric string", strings.Replace(valid, `"expected_schedule_revision":0`, `"expected_schedule_revision":"0"`, 1)},
		{"uint overflow", strings.Replace(valid, `"expected_schedule_revision":0`, `"expected_schedule_revision":18446744073709551616`, 1)},
		{"unsafe site revision", strings.Replace(valid, `"expected_revision":1`, `"expected_revision":9007199254740992`, 1)},
		{"unsafe schedule revision", strings.Replace(valid, `"expected_schedule_revision":0`, `"expected_schedule_revision":9007199254740992`, 1)},
		{"negative revision", strings.Replace(valid, `"expected_schedule_revision":0`, `"expected_schedule_revision":-1`, 1)},
		{"fractional revision", strings.Replace(valid, `"expected_schedule_revision":0`, `"expected_schedule_revision":0.5`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.body == valid {
				t.Fatal("challenge mutation was not applied")
			}
			w := request(f, "PUT", path(f), tc.body, f.auth, nil)
			if w.Code != 400 && w.Code != 422 {
				t.Fatalf("malformed input status=%d; response withheld", w.Code)
			}
			if inspect(t, f).Schedule != nil || len(backups(t, f)) != 0 {
				t.Fatal("malformed input mutated scheduler/archive state")
			}
		})
	}
}

func TestPauseRacesWithDueConsumption(t *testing.T) {
	f := isolated(t)
	s := ageNeverSchedule(t, f, dueSchedule(t, f, "hourly"))
	start := make(chan struct{})
	var wg sync.WaitGroup
	var ran bool
	var runErr, pauseErr error
	wg.Add(2)
	go func() { defer wg.Done(); <-start; ran, runErr = f.store.RunDueBackups(s.Next) }()
	go func() {
		defer wg.Done()
		<-start
		_, pauseErr = f.store.SetBackupSchedule(f.site.ID, sites.BackupScheduleInput{ExpectedRevision: f.site.Revision, ExpectedScheduleRevision: s.Revision, Interval: "hourly", Enabled: boolPointer(false)}, "local-operator")
	}()
	close(start)
	wg.Wait()
	if runErr != nil {
		t.Fatal("actual due race run failed")
	}
	e := inspect(t, f)
	b := backups(t, f)
	if pauseErr == nil {
		if ran || len(b) != 0 || e.Schedule.Enabled || e.Schedule.Status != "never" {
			t.Fatal("successful pause raced after due mutation")
		}
	} else {
		if !errors.Is(pauseErr, sites.ErrConflict) || !ran || len(b) != 1 || e.Schedule.Status != "completed" {
			t.Fatal("pause/run serialized outcome invalid")
		}
		current, err := f.store.Get(f.site.ID)
		if err != nil {
			t.Fatal("post-race site unavailable")
		}
		status(t, request(f, "PUT", path(f), input(current.Revision, e.Schedule.Revision, "hourly", false), f.auth, nil), 200)
	}
	paused := inspect(t, f).Schedule
	if changed, err := f.store.RunDueBackups(paused.Next.Add(24 * time.Hour)); err != nil || changed || len(backups(t, f)) != len(b) {
		t.Fatal("successful paused state admitted later due run")
	}
}

func boolPointer(v bool) *bool { return &v }

func TestPublicActorAdmissionCannotBorrowSchedulerPrivilege(t *testing.T) {
	f := isolated(t)
	if _, err := f.store.Backup(f.site.ID, f.site.Revision, "native-backup-scheduler"); !errors.Is(err, sites.ErrInvalid) {
		t.Fatal("public Backup accepted internal scheduler actor")
	}
	if _, err := f.store.SetBackupSchedule(f.site.ID, sites.BackupScheduleInput{ExpectedRevision: f.site.Revision, Interval: "hourly", Enabled: boolPointer(true)}, "native-backup-scheduler"); !errors.Is(err, sites.ErrInvalid) {
		t.Fatal("public schedule config accepted internal scheduler actor")
	}
	if inspect(t, f).Schedule != nil || len(backups(t, f)) != 0 {
		t.Fatal("rejected public actor changed actual state")
	}
}

func TestOwnedRunnerImmediateCycleAndCancellation(t *testing.T) {
	f := isolated(t)
	ageNeverSchedule(t, f, dueSchedule(t, f, "hourly"))
	alreadyCanceled, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := make(chan struct{})
	go func() { f.store.RunBackupScheduler(alreadyCanceled); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("pre-canceled owned runner did not stop")
	}
	if len(backups(t, f)) != 0 {
		t.Fatal("pre-canceled runner consumed due job")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.store.RunBackupScheduler(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned runner cleanup did not complete")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := f.store.BackupSchedule(f.site.ID)
		if err != nil {
			t.Fatal("owned runner observation failed")
		}
		if s != nil && s.LastStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned runner immediate cycle did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owned runner cancellation did not stop")
	}
	if len(backups(t, f)) != 1 || inspect(t, f).Schedule.Pending {
		t.Fatal("owned runner duplicated due point or retained active intent")
	}
}

// These are explicit synthetic durable-state fixtures, not observed crashes.
// Field order is part of the admitted canonical storage encoding.
type runMarker struct {
	BackupID string    `json:"backup_id"`
	Revision uint64    `json:"revision"`
	SHA256   string    `json:"sha256"`
	Bytes    int64     `json:"bytes"`
	Files    int       `json:"files"`
	Due      time.Time `json:"due_at"`
	RunAt    time.Time `json:"run_at"`
}
type durableRow struct {
	Version  int        `json:"version"`
	Actor    string     `json:"actor"`
	Schedule schedule   `json:"schedule"`
	Run      *runMarker `json:"run"`
}

func mutateRow(t *testing.T, f *fixture, edit func(*durableRow)) {
	t.Helper()
	if f.store.Close() != nil {
		t.Fatal("owned store close before fixture failed")
	}
	db, err := bolt.Open(filepath.Join(f.dir, "sites", "sites.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal("owned fixture DB unavailable")
	}
	closed := false
	defer func() {
		if !closed && db.Close() != nil {
			t.Error("owned fixture DB cleanup failed")
		}
	}()
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("native-backup-schedules-v1"))
		if b == nil {
			return errors.New("schedule bucket absent")
		}
		var row durableRow
		if err := json.Unmarshal(b.Get([]byte(f.site.ID)), &row); err != nil {
			return err
		}
		edit(&row)
		raw, err := json.Marshal(row)
		if err != nil {
			return err
		}
		return b.Put([]byte(f.site.ID), raw)
	})
	closeErr := db.Close()
	closed = true
	if err != nil || closeErr != nil {
		t.Fatal("owned durable fixture mutation failed")
	}
	f.store, err = sites.Open(filepath.Join(f.dir, "sites"), f.journal)
	if err != nil {
		f.store = nil
		t.Fatal("owned durable fixture reopen failed")
	}
	enabledHandler(f)
}
func ageNeverSchedule(t *testing.T, f *fixture, s schedule) schedule {
	t.Helper()
	if s.Status != "never" {
		t.Fatal("age fixture needs never state")
	}
	now := time.Now().UTC().Truncate(time.Second)
	mutateRow(t, f, func(r *durableRow) {
		r.Schedule.Created = now.Add(-14 * 24 * time.Hour)
		r.Schedule.Updated = r.Schedule.Created
		r.Schedule.Next = now
	})
	aged := inspect(t, f).Schedule
	if aged == nil || aged.Revision != s.Revision || !aged.Next.Equal(now) {
		t.Fatal("durable past-time fixture mismatch")
	}
	return *aged
}

func readMarker(t *testing.T, f *fixture) *runMarker {
	t.Helper()
	if f.store.Close() != nil {
		t.Fatal("owned close before marker inspection failed")
	}
	db, err := bolt.Open(filepath.Join(f.dir, "sites", "sites.db"), 0600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		t.Fatal("owned marker DB unavailable")
	}
	var row durableRow
	err = db.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte("native-backup-schedules-v1")).Get([]byte(f.site.ID)), &row)
	})
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		t.Fatal("owned marker inspection/cleanup failed")
	}
	f.store, err = sites.Open(filepath.Join(f.dir, "sites"), f.journal)
	if err != nil {
		f.store = nil
		t.Fatal("owned marker inspection reopen failed")
	}
	enabledHandler(f)
	return row.Run
}

func TestSyntheticDurableAdmissionRejectsCorruption(t *testing.T) {
	for _, kind := range []string{"unknown field", "duplicate field", "case alias", "orphan row", "pending without marker", "completed absent catalog", "bad UTC", "oversized revision"} {
		t.Run(kind, func(t *testing.T) {
			f := isolated(t)
			status(t, request(f, "PUT", path(f), input(f.site.Revision, 0, "daily", false), f.auth, nil), 200)
			if f.store.Close() != nil {
				t.Fatal("owned close before corrupt fixture failed")
			}
			db, err := bolt.Open(filepath.Join(f.dir, "sites", "sites.db"), 0600, &bolt.Options{Timeout: time.Second})
			if err != nil {
				t.Fatal("owned corrupt fixture DB unavailable")
			}
			err = db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("native-backup-schedules-v1"))
				raw := append([]byte(nil), b.Get([]byte(f.site.ID))...)
				switch kind {
				case "unknown field":
					raw = append(raw[:len(raw)-1], []byte(`,"unknown":1}`)...)
				case "duplicate field":
					raw = append(raw[:len(raw)-1], []byte(`,"version":1}`)...)
				case "case alias":
					raw = bytes.Replace(raw, []byte(`"version"`), []byte(`"Version"`), 1)
				case "orphan row":
					return b.Put([]byte(strings.Repeat("e", 32)), raw)
				default:
					var r durableRow
					if err := json.Unmarshal(raw, &r); err != nil {
						return err
					}
					switch kind {
					case "pending without marker":
						r.Schedule.Pending = true
					case "completed absent catalog":
						r.Schedule.Status = "completed"
						r.Schedule.BackupID = strings.Repeat("e", 32)
						r.Schedule.Last = &r.Schedule.Updated
					case "bad UTC":
						r.Schedule.Next = r.Schedule.Next.In(time.FixedZone("offset", 3600))
					case "oversized revision":
						r.Schedule.Revision = 9007199254740992
					}
					var err error
					raw, err = json.Marshal(r)
					if err != nil {
						return err
					}
				}
				return b.Put([]byte(f.site.ID), raw)
			})
			closeErr := db.Close()
			if err != nil || closeErr != nil {
				t.Fatal("owned corrupt fixture write/cleanup failed")
			}
			opened, err := sites.Open(filepath.Join(f.dir, "sites"), f.journal)
			if opened != nil {
				if opened.Close() != nil {
					t.Error("unexpected admitted store cleanup failed")
				}
			}
			f.store = nil
			if !errors.Is(err, sites.ErrUnavailable) {
				t.Fatal("corrupt schedule admitted on reopen")
			}
		})
	}
}

func TestSyntheticPendingReconciliationUsesExactArchive(t *testing.T) {
	for _, kind := range []string{"exact committed", "absent reserved ID", "untracked reserved file", "wrong source revision", "wrong hash", "wrong byte count", "wrong file count", "tampered actual ZIP"} {
		t.Run(kind, func(t *testing.T) {
			f := isolated(t)
			s := ageNeverSchedule(t, f, dueSchedule(t, f, "hourly"))
			if processed, err := f.store.RunDueBackups(s.Next); err != nil || !processed {
				t.Fatal("real archive preparation failed")
			}
			catalog := backups(t, f)
			if len(catalog) != 1 {
				t.Fatal("real archive fixture count differs")
			}
			b := catalog[0]
			raw, _, err := f.store.ExportBackup(f.site.ID, b.ID)
			if err != nil || digest(raw) != b.SHA256 {
				t.Fatal("real archive fixture hash differs")
			}
			if kind == "tampered actual ZIP" {
				if f.store.Close() != nil {
					t.Fatal("owned close before tamper failed")
				}
				raw[len(raw)/2] ^= 1
				if os.WriteFile(filepath.Join(f.dir, "sites", "data", f.site.ID, "backups", b.ID+".zip"), raw, 0600) != nil {
					t.Fatal("owned archive tamper fixture failed")
				}
			}
			if kind == "untracked reserved file" {
				if f.store.Close() != nil {
					t.Fatal("owned close before untracked fixture failed")
				}
				if os.WriteFile(filepath.Join(f.dir, "sites", "data", f.site.ID, "backups", strings.Repeat("e", 32)+".zip"), raw, 0600) != nil {
					t.Fatal("owned untracked archive fixture failed")
				}
			}
			mutateRow(t, f, func(r *durableRow) {
				r.Schedule.Pending = true
				r.Schedule.Revision++
				r.Schedule.Next = s.Next
				r.Schedule.Updated = s.Next
				r.Schedule.Last = nil
				r.Schedule.Status = "never"
				r.Schedule.BackupID = ""
				r.Schedule.Error = ""
				r.Run = &runMarker{BackupID: b.ID, Revision: b.Revision, SHA256: b.SHA256, Bytes: b.Bytes, Files: b.Files, Due: s.Next, RunAt: s.Next}
				switch kind {
				case "absent reserved ID", "untracked reserved file":
					r.Run.BackupID = strings.Repeat("e", 32)
				case "wrong source revision":
					r.Run.Revision++
				case "wrong hash":
					r.Run.SHA256 = strings.Repeat("0", 64)
				case "wrong byte count":
					r.Run.Bytes++
				case "wrong file count":
					r.Run.Files++
				}
			})
			pending := inspect(t, f).Schedule
			if pending == nil || !pending.Pending || pending.Status != "never" {
				t.Fatal("GET failed to expose synthetic pending without reconciliation")
			}
			if inspect(t, f).Schedule.Revision != pending.Revision {
				t.Fatal("GET reconciled durable intent")
			}
			ready, err := f.store.Get(f.site.ID)
			if err != nil {
				t.Fatal("active intent ready site unavailable")
			}
			status(t, request(f, "PUT", path(f), input(ready.Revision, pending.Revision, "daily", false), f.auth, nil), 503)
			// No new archive is produced by pending reconciliation.
			now := s.Next
			if processed, err := f.store.RunDueBackups(now); err != nil || !processed {
				t.Fatal("pending reconciliation failed")
			}
			e := inspect(t, f).Schedule
			if e.Last == nil || !e.Last.Equal(s.Next) || e.Revision != pending.Revision+1 {
				t.Fatal("pending consumption metadata differs")
			}
			if kind == "exact committed" {
				if e.Pending || e.Status != "completed" || e.BackupID != b.ID || e.Error != "" || !e.Enabled {
					t.Fatal("exact committed proof not adopted")
				}
			} else {
				retained := kind != "absent reserved ID"
				if e.Pending != retained || (retained && !e.Next.Equal(pending.Next)) || e.Status != "interrupted" || e.BackupID != "" || e.Error != "interrupted" || e.Enabled {
					t.Fatal("unproven result adopted or not paused with correct evidence retention")
				}
			}
			entries, err := os.ReadDir(filepath.Join(f.dir, "sites", "data", f.site.ID, "backups"))
			wantCount := 1
			if kind == "untracked reserved file" {
				wantCount = 2
			}
			if err != nil || len(entries) != wantCount {
				t.Fatal("reconciliation retried/changed archive inventory")
			}
			foundOriginal := false
			for _, entry := range entries {
				if entry.Name() == b.ID+".zip" {
					foundOriginal = true
				} else if kind != "untracked reserved file" || entry.Name() != strings.Repeat("e", 32)+".zip" {
					t.Fatal("reconciliation changed exact inventory names")
				}
			}
			if !foundOriginal {
				t.Fatal("reconciliation removed original archive")
			}
			if processed, err := f.store.RunDueBackups(now); err != nil || processed {
				t.Fatal("pending marker consumed twice")
			}
			if kind != "exact committed" {
				marker := readMarker(t, f)
				if f.store.Close() != nil {
					t.Fatal("owned stopped marker close failed")
				}
				f.store, err = sites.Open(filepath.Join(f.dir, "sites"), f.journal)
				if err != nil {
					f.store = nil
					t.Fatal("stopped marker reopen failed")
				}
				enabledHandler(f)
				if !reflect.DeepEqual(*e, *inspect(t, f).Schedule) || !reflect.DeepEqual(marker, readMarker(t, f)) {
					t.Fatal("stopped uncertainty evidence changed after reopen")
				}
				if changed, err := f.store.RunDueBackups(now.Add(24 * time.Hour)); err != nil || changed {
					t.Fatal("stopped marker automatically retried")
				}
				current, err := f.store.Get(f.site.ID)
				if err != nil {
					t.Fatal("ready site unavailable for explicit recovery")
				}
				want := 503
				if kind == "absent reserved ID" {
					want = 200
				}
				status(t, request(f, "PUT", path(f), input(current.Revision, e.Revision, "daily", false), f.auth, nil), want)
				after := inspect(t, f).Schedule
				if want == 200 {
					if after.Pending || after.Enabled || after.Revision != e.Revision+1 || !after.Next.After(now) {
						t.Fatal("explicit absence recovery was not future/paused")
					}
				} else if !reflect.DeepEqual(*after, *e) || !reflect.DeepEqual(marker, readMarker(t, f)) {
					t.Fatal("refused recovery discarded uncertainty evidence")
				}
			}
		})
	}
}
