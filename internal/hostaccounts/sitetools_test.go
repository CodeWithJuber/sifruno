package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// fakeSiteTools models the crontab directory, the logs, the quota report
// and the traffic counters for the store's tests. It runs nothing.
type fakeSiteTools struct {
	crontabs   map[string][]byte
	cronWrites int
	// failCron "before" fails SetCron with nothing written, as every
	// SetCron failure is. cronDirGone makes the crontab directory unusable;
	// cronObjectBad stands for something at the crontab's name that SetCron
	// would not replace.
	failCron      string
	cronDirGone   bool
	cronObjectBad bool
	logs          map[string]LogTail
	quota         map[int]quotaUsage
	quotaCalls    [][]int
	dirs          map[string]*memLogDir
	states        map[string][]byte
}

func (f *fakeNative) tools() *fakeSiteTools {
	if f.siteTools == nil {
		f.siteTools = &fakeSiteTools{crontabs: map[string][]byte{}, logs: map[string]LogTail{}, quota: map[int]quotaUsage{}, dirs: map[string]*memLogDir{}, states: map[string][]byte{}}
	}
	return f.siteTools
}

func (f *fakeNative) SetCron(_ context.Context, r record, content []byte) error {
	t := f.tools()
	if t.cronDirGone || t.failCron == "before" {
		return ErrUnavailable
	}
	t.cronWrites++
	if content == nil {
		delete(t.crontabs, r.Account.Username)
	} else {
		t.crontabs[r.Account.Username] = append([]byte(nil), content...)
	}
	return nil
}

func (f *fakeNative) VerifyCron(r record, content []byte) error {
	t := f.tools()
	if t.cronDirGone {
		return ErrUnavailable
	}
	if t.cronObjectBad {
		return ErrConflict
	}
	got, ok := t.crontabs[r.Account.Username]
	if content == nil && !ok || ok && bytes.Equal(got, content) {
		return nil
	}
	return ErrRecovery
}

func (f *fakeNative) TailLog(_ context.Context, site, kind string) (LogTail, error) {
	if l, ok := f.tools().logs[site+"/"+kind]; ok {
		return l, nil
	}
	return LogTail{Kind: kind, Lines: []string{}, Missing: true}, nil
}

func (f *fakeNative) QuotaUsage(_ context.Context, uids []int) (map[int]quotaUsage, error) {
	t := f.tools()
	t.quotaCalls = append(t.quotaCalls, uids)
	return t.quota, nil
}

func (f *fakeNative) SiteLogDir(site string) (siteLogDir, error) {
	if d, ok := f.tools().dirs[site]; ok {
		return d, nil
	}
	return nil, errNoLogs
}

func (f *fakeNative) LoadUsageState(id string) ([]byte, error) { return f.tools().states[id], nil }
func (f *fakeNative) SaveUsageState(id string, b []byte) error {
	f.tools().states[id] = append([]byte(nil), b...)
	return nil
}
func (f *fakeNative) RemoveUsageState(id string) error {
	delete(f.tools().states, id)
	return nil
}

// memLogDir is a log directory in memory: files by name, each with an
// inode, so a rotation is a rename that keeps it.
type memLogDir struct {
	files   map[string]*memLogFile
	nextIno uint64
	clock   int64
	opens   int
}
type memLogFile struct {
	ino   uint64
	mtime int64
	data  []byte
}

// Its clock starts in November 2026, the month the tests count.
func newMemLogDir() *memLogDir {
	return &memLogDir{files: map[string]*memLogFile{}, nextIno: 100, clock: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC).UnixNano()}
}

func (d *memLogDir) write(name, text string) {
	d.clock++
	f, ok := d.files[name]
	if !ok {
		d.nextIno++
		f = &memLogFile{ino: d.nextIno}
		d.files[name] = f
	}
	f.data = append(f.data, text...)
	f.mtime = d.clock
}

// rotate moves access.log aside as OpenLiteSpeed does: the file keeps its
// inode under a dated name, and the next write starts a new access.log.
func (d *memLogDir) rotate(name string) {
	d.files[name] = d.files["access.log"]
	delete(d.files, "access.log")
}

func (d *memLogDir) AccessLogs() ([]logFile, error) {
	var out []logFile
	for name, f := range d.files {
		if accessLogName.MatchString(name) {
			out = append(out, logFile{Name: name, Dev: 1, Ino: f.ino, MTime: f.mtime, Size: int64(len(f.data))})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type memReader struct{ *bytes.Reader }

func (memReader) Close() error { return nil }

func (d *memLogDir) Open(lf logFile) (io.ReadCloser, error) {
	d.opens++
	f, ok := d.files[lf.Name]
	if !ok || f.ino != lf.Ino {
		return nil, ErrUnavailable
	}
	return memReader{bytes.NewReader(append([]byte(nil), f.data...))}, nil
}
func (d *memLogDir) Close() error { return nil }

// ---- Cron grammar -------------------------------------------------------------

func TestCronScheduleGrammar(t *testing.T) {
	valid := []string{
		"* * * * *", "*/5 * * * *", "0 3 * * 1-5", "0,30 9-17 * * 1,3,5", "0 0 1 1 *", "59 23 31 12 7",
		"0 0 * * 0", "1-59/2 * * * *", "05 * * * *", "0 */6 * * *", "*/7 * * * */7", "0 0 1-31/10 1-12/3 0-7",
	}
	for _, s := range valid {
		if p := CronJobProblem(CronJob{Schedule: s, Command: "true"}); p != "" {
			t.Errorf("valid %q refused: %s", s, p)
		}
	}
	invalid := []string{
		"", "* * * *", "* * * * * *", "*  * * * *", " * * * * *", "* * * * * ", "60 * * * *", "* 24 * * *",
		"* * 0 * *", "* * 32 * *", "* * * 0 *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "*/60 * * * *",
		"* * * * */8", "5/10 * * * *", "5-1 * * * *", "1,,2 * * * *", ",1 * * * *", "1- * * * *", "*/ * * * *",
		"-1 * * * *", "100 * * * *", "@hourly", "@reboot * * * *", "* * * jan *", "* * * * mon", "0~30 * * * *",
		"* * * * *\n", "\t* * * * *", "*\t* * * *", "* * * * *%", "１ * * * *", "1-2-3 * * * *", "** * * * *",
		"*/5/2 * * * *", strings.Repeat("1,", 50) + "1 * * * *",
	}
	for _, s := range invalid {
		if CronJobProblem(CronJob{Schedule: s, Command: "true"}) == "" {
			t.Errorf("invalid %q admitted", s)
		}
	}
}

func TestCronCommandRefusesInjection(t *testing.T) {
	ok := []string{
		"php /home/site/public_html/wp-cron.php > /dev/null 2>&1",
		"cd ~/public_html && php artisan schedule:run >> ~/cron.log 2>&1",
		`curl -fsS "https://example.com/?a=1&b=2" -o /dev/null`,
		"echo ünïcode",
		strings.Repeat("x", maxCronCommand),
	}
	for _, c := range ok {
		if p := CronJobProblem(CronJob{Schedule: "* * * * *", Command: c}); p != "" {
			t.Errorf("command %q refused: %s", c, p)
		}
	}
	bad := []string{
		"", " true", "true ", "-n true", "-x", "* true", "echo ok\n* * * * * rm -rf ~", "echo ok\r* * * * * id", "date +%s",
		"echo 100\\%", "a\x00b", "a\tb", "a\x1bb", "a\u2028b", "a\u0085b", "\xff\xfe",
		// Format characters: bidi overrides, embeddings and isolates, marks,
		// zero-width characters and the byte order mark.
		"rm -rf ~/tmp/\u202ecod.exe", "echo \u2066a\u2069", "echo a\u200bb", "echo \u200fa", "echo a\u2060b", "\ufeffecho a", "echo a\u00adb",
		strings.Repeat("x", maxCronCommand+1),
	}
	for _, c := range bad {
		if CronJobProblem(CronJob{Schedule: "* * * * *", Command: c}) == "" {
			t.Errorf("command %q admitted", c)
		}
	}
	// A newline in the schedule is refused as well: it would start a line
	// of its own.
	if CronJobProblem(CronJob{Schedule: "* * * * *\n* * * * * id #", Command: "true"}) == "" {
		t.Fatal("schedule with a newline admitted")
	}
	many := make([]CronJob, MaxCronJobs+1)
	for i := range many {
		many[i] = CronJob{Schedule: "* * * * *", Command: "true"}
	}
	if validCronJobs(many) || !validCronJobs(many[:MaxCronJobs]) {
		t.Fatal("job count bound")
	}
	// The job text as a whole is bounded too.
	long := make([]CronJob, 20)
	for i := range long {
		long[i] = CronJob{Schedule: "* * * * *", Command: strings.Repeat("y", maxCronCommand)}
	}
	if validCronJobs(long) {
		t.Fatal("20 KiB of jobs admitted")
	}
}

// TestStoredCronWithFormatCharactersStillReads: a set an earlier broker
// stored before format characters were refused still reads, so neither its
// account's job list nor a change left pending across the upgrade gets stuck.
func TestStoredCronWithFormatCharactersStillReads(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	jobs := []CronJob{{Schedule: "0 3 * * *", Command: "echo a​b"}}
	if CronJobProblem(jobs[0]) == "" {
		t.Fatal("a command with a zero-width space admitted")
	}
	digest := cronDigest(jobs)
	if err := s.putCronSets(a.ID, map[string][]CronJob{digest: jobs}); err != nil {
		t.Fatal(err)
	}
	r := recordFor(t, s, a.ID)
	r.Cron = digest
	if err := s.save(r); err != nil {
		t.Fatal(err)
	}
	got, err := s.cron(context.Background(), a.ID)
	if err != nil || len(got.Jobs) != 1 || got.Jobs[0].Command != jobs[0].Command {
		t.Fatalf("the stored set does not read: %v %+v", err, got)
	}
}

func TestCrontabContent(t *testing.T) {
	jobs := []CronJob{{Schedule: "*/5 * * * *", Command: "php ~/public_html/wp-cron.php > /dev/null 2>&1"}, {Schedule: "0 3 * * 1-5", Command: "~/bin/report.sh"}}
	want := "# Managed by Sifruno. The panel rewrites this file from its list of scheduled jobs.\n" +
		"MAILTO=\"\"\n" +
		"*/5 * * * * php ~/public_html/wp-cron.php > /dev/null 2>&1\n" +
		"0 3 * * 1-5 ~/bin/report.sh\n"
	if got := string(renderCrontab(jobs)); got != want {
		t.Fatalf("crontab\n%s\nwant\n%s", got, want)
	}
	if renderCrontab(nil) != nil || renderCrontab([]CronJob{}) != nil {
		t.Fatal("no jobs must be no file")
	}
	// Every line ends with a newline, and the file has exactly the job
	// lines and the two fixed lines: no variable a tenant could set.
	lines := strings.Split(strings.TrimSuffix(want, "\n"), "\n")
	if len(lines) != 4 || strings.Count(want, "=") != 1 {
		t.Fatalf("lines %q", lines)
	}
	if cronDigest(jobs) == cronDigest([]CronJob{jobs[1], jobs[0]}) || !cronDigestPattern.MatchString(cronDigest(jobs)) || cronDigest(nil) != emptyCronDigest {
		t.Fatal("digest")
	}
}

func TestNextCronRun(t *testing.T) {
	// Tuesday 24 November 2026, 10:07:30 at UTC+4.
	zone := time.FixedZone("UTC+4", 4*3600)
	now := time.Date(2026, 11, 24, 10, 7, 30, 0, zone)
	cases := map[string]string{
		"*/5 * * * *":   "2026-11-24T10:10:00+04:00",
		"7 10 * * *":    "2026-11-25T10:07:00+04:00",
		"8 10 * * *":    "2026-11-24T10:08:00+04:00",
		"0 3 * * *":     "2026-11-25T03:00:00+04:00",
		"0 0 1 * *":     "2026-12-01T00:00:00+04:00",
		"0 0 29 2 *":    "2028-02-29T00:00:00+04:00",
		"0 0 * * 7":     "2026-11-29T00:00:00+04:00",
		"0 0 * * 0":     "2026-11-29T00:00:00+04:00",
		"0 0 1 * 1":     "2026-11-30T00:00:00+04:00", // both day fields set: either
		"0 0 */2 * 1":   "2026-12-07T00:00:00+04:00", // one starts with *: both
		"30 23 31 12 *": "2026-12-31T23:30:00+04:00",
	}
	for schedule, want := range cases {
		s, problem := parseCronSchedule(schedule)
		if problem != "" {
			t.Fatalf("%s: %s", schedule, problem)
		}
		got, ok := nextCronRun(s, now)
		if !ok || got.Format(time.RFC3339) != want {
			t.Errorf("%s: %v %v, want %s", schedule, got, ok, want)
		}
	}
	s, _ := parseCronSchedule("0 0 31 2 *")
	if _, ok := nextCronRun(s, now); ok {
		t.Fatal("31 February ran")
	}
	entries := cronEntries([]CronJob{{Schedule: "0 0 31 2 *", Command: "true"}, {Schedule: "*/5 * * * *", Command: "true"}}, now)
	if entries[0].NextRun != "" || entries[1].NextRun != "2026-11-24T10:10:00+04:00" {
		t.Fatalf("entries %+v", entries)
	}
}

// ---- Cron operation and journal ----------------------------------------------

func historyRows(t *testing.T, s *store, id string) []operationEvent {
	t.Helper()
	var rows []operationEvent
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(historyBucket).Cursor()
		prefix := []byte(id + "/")
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var e operationEvent
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			rows = append(rows, e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestSetCronJournalsAndWritesTheCrontab(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	jobs := []CronJob{{Schedule: "*/5 * * * *", Command: "curl -fsS https://fixture.test/cron?token=s3cr3t-token"}, {Schedule: "0 3 * * *", Command: "~/bin/nightly.sh"}}
	res, err := s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: a.Revision, Reason: "Scheduled jobs changed"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if res.Account.Revision != a.Revision+1 || len(res.Jobs) != 2 || res.Jobs[0].NextRun == "" || res.ServerTime == "" {
		t.Fatalf("result %+v", res)
	}
	if got := f.tools().crontabs[a.Username]; !bytes.Equal(got, renderCrontab(jobs)) {
		t.Fatalf("crontab %q", got)
	}
	rows := historyRows(t, s, a.ID)
	last, intent := rows[len(rows)-1], rows[len(rows)-2]
	if intent.Action != "cron" || intent.Status != "intended" || last.Status != "succeeded" || last.After.Revision != a.Revision+1 || intent.Before.Revision != a.Revision {
		t.Fatalf("journal %+v %+v", intent, last)
	}
	// The journal names the set by digest; no command reaches it.
	var raw []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(historyBucket).ForEach(func(_, v []byte) error { raw = append(raw, v...); return nil })
	})
	if bytes.Contains(raw, []byte("s3cr3t-token")) {
		t.Fatal("a command reached the journal")
	}
	r := recordFor(t, s, a.ID)
	if r.Cron != cronDigest(jobs) || r.Pending != nil {
		t.Fatalf("record %+v", r)
	}
	listed, err := s.cron(ctx, a.ID)
	if err != nil || len(listed.Jobs) != 2 || listed.Jobs[1].Command != "~/bin/nightly.sh" || listed.Account.Revision != res.Account.Revision {
		t.Fatalf("list %+v %v", listed, err)
	}

	// The same set again is a no-op while the crontab still holds it.
	writes := f.tools().cronWrites
	again, err := s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: res.Account.Revision, Reason: "Same jobs"}, "test operator")
	if err != nil || again.Account.Revision != res.Account.Revision || f.tools().cronWrites != writes {
		t.Fatalf("no-op %+v %v", again, err)
	}
	// Edited outside the broker: the same set is written again, journaled.
	f.tools().crontabs[a.Username] = []byte("* * * * * evil\n")
	again, err = s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: res.Account.Revision, Reason: "Repair"}, "test operator")
	if err != nil || again.Account.Revision != res.Account.Revision+1 || !bytes.Equal(f.tools().crontabs[a.Username], renderCrontab(jobs)) {
		t.Fatalf("repair %+v %v", again, err)
	}

	// Refusals change nothing.
	for name, in := range map[string]CronInput{
		"stale":    {Jobs: jobs, ExpectedRevision: a.Revision, Reason: "Stale"},
		"percent":  {Jobs: []CronJob{{Schedule: "* * * * *", Command: "date +%s"}}, ExpectedRevision: again.Account.Revision, Reason: "r"},
		"newline":  {Jobs: []CronJob{{Schedule: "* * * * *", Command: "a\nb"}}, ExpectedRevision: again.Account.Revision, Reason: "r"},
		"schedule": {Jobs: []CronJob{{Schedule: "@reboot", Command: "true"}}, ExpectedRevision: again.Account.Revision, Reason: "r"},
		"reason":   {Jobs: jobs, ExpectedRevision: again.Account.Revision, Reason: ""},
	} {
		_, err := s.setCron(ctx, a.ID, in, "test operator")
		want := ErrInvalid
		if name == "stale" {
			want = ErrConflict
		}
		if !errors.Is(err, want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if recordFor(t, s, a.ID).Account.Revision != again.Account.Revision {
		t.Fatal("a refusal changed the account")
	}

	// No jobs removes the crontab.
	none, err := s.setCron(ctx, a.ID, CronInput{Jobs: nil, ExpectedRevision: again.Account.Revision, Reason: "Remove all"}, "test operator")
	if err != nil || len(none.Jobs) != 0 || recordFor(t, s, a.ID).Cron != "" {
		t.Fatalf("remove %+v %v", none, err)
	}
	if _, ok := f.tools().crontabs[a.Username]; ok {
		t.Fatal("crontab left after removing every job")
	}
	sets, _ := s.cronSets(a.ID)
	if len(sets) != 0 {
		t.Fatalf("stale sets %v", sets)
	}
	if _, err := s.cron(ctx, strings.Repeat("0", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestSetCronFailures(t *testing.T) {
	s, f, opts := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	other, err := s.create(ctx, CreateInput{Username: "otheracct", Domain: "other.test", Reason: "Second account"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	jobs := []CronJob{{Schedule: "0 * * * *", Command: "~/hourly.sh"}}
	rowsBefore := len(historyRows(t, s, a.ID))

	// An unusable crontab directory refuses before anything is journaled.
	f.tools().cronDirGone = true
	if _, err := s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: a.Revision, Reason: "r"}, "op"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if len(historyRows(t, s, a.ID)) != rowsBefore {
		t.Fatal("journaled without a crontab directory")
	}
	f.tools().cronDirGone = false

	// A write that fails with the old crontab in place ends rejected: the
	// account is unchanged and every other account can still change.
	f.tools().failCron = "before"
	if _, err := s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: a.Revision, Reason: "r"}, "op"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	rows := historyRows(t, s, a.ID)
	if rows[len(rows)-1].Status != "rejected" || recordFor(t, s, a.ID).Account.Revision != a.Revision || recordFor(t, s, a.ID).Pending != nil {
		t.Fatalf("rejected %+v", rows[len(rows)-1])
	}
	f.tools().failCron = ""
	if _, err := s.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Still free"}, "op"); err != nil {
		t.Fatalf("other account after a rejected cron change: %v", err)
	}

	// Something at the crontab's name the write would not replace refuses
	// the change before anything is journaled.
	rowsBefore = len(historyRows(t, s, a.ID))
	f.tools().cronObjectBad = true
	if _, err := s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: a.Revision, Reason: "r"}, "op"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if len(historyRows(t, s, a.ID)) != rowsBefore {
		t.Fatal("journaled over an object the write refuses")
	}
	f.tools().cronObjectBad = false

	// A crash after the intent leaves the change pending: every mutation
	// waits, reads do not, and the next start finishes it.
	pendingCron(t, s, a.ID, jobs)
	if _, err := s.setState(ctx, a.ID, StateInput{State: "suspended", ExpectedRevision: a.Revision, Reason: "r"}, "op"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("mutation while pending: %v", err)
	}
	if listed, err := s.cron(ctx, a.ID); err != nil || listed.Account.State != "recovery_required" || len(listed.Jobs) != 0 {
		t.Fatalf("read while pending %+v %v", listed, err)
	}
	if listed, err := s.cron(ctx, other.ID); err != nil || listed.Account.State != "suspended" {
		t.Fatalf("other read while pending %+v %v", listed, err)
	}
	s.close()
	f.tools().crontabs = map[string][]byte{}
	reopened, err := openStore(ctx, opts, f)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	r := recordFor(t, reopened, a.ID)
	if r.Pending != nil || r.Cron != cronDigest(jobs) || r.Account.Revision != a.Revision+1 || !bytes.Equal(f.tools().crontabs[a.Username], renderCrontab(jobs)) {
		t.Fatalf("reconciled %+v", r)
	}
	rows = historyRows(t, reopened, a.ID)
	if rows[len(rows)-1].Status != "reconciled" || rows[len(rows)-1].Action != "cron" {
		t.Fatalf("journal %+v", rows[len(rows)-1])
	}
}

// pendingCron journals a cron change's intent and stops there, as a crash
// right after the intent would leave it.
func pendingCron(t *testing.T, s *store, id string, jobs []CronJob) {
	t.Helper()
	r := recordFor(t, s, id)
	digest := cronDigest(jobs)
	if err := s.putCronSets(id, map[string][]CronJob{digest: jobs}); err != nil {
		t.Fatal(err)
	}
	r.Pending = &pending{Action: "cron", Target: digest, Actor: "op", Reason: "r", OperationID: strings.Repeat("9", 32)}
	before, after := r.Account, r.Account
	after.Revision++
	if _, err := s.appendEvent(r, operationEvent{OperationID: r.Pending.OperationID, Action: "cron", Status: "intended", Actor: "op", Reason: "r", Before: &before, After: after}); err != nil {
		t.Fatal(err)
	}
}

// The account's own user can rewrite its crontab with cronie's setuid
// crontab. That never leaves a change pending: the next save writes the
// list again, journaled like any change.
func TestCronAfterTheTenantRewroteItsCrontab(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	jobs := []CronJob{{Schedule: "0 * * * *", Command: "~/hourly.sh"}}
	res, err := s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: a.Revision, Reason: "r"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	f.tools().crontabs[a.Username] = []byte("XDG_SESSION_CLASS=background-light\n* * * * * ~/mine.sh\n")
	if listed, err := s.cron(ctx, a.ID); err != nil || len(listed.Jobs) != 1 || listed.Jobs[0].Command != "~/hourly.sh" {
		t.Fatalf("list %+v %v", listed, err)
	}
	again, err := s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: res.Account.Revision, Reason: "Write the list again"}, "op")
	if err != nil || again.Account.Revision != res.Account.Revision+1 || !bytes.Equal(f.tools().crontabs[a.Username], renderCrontab(jobs)) {
		t.Fatalf("rewrite %+v %v", again, err)
	}
	if recordFor(t, s, a.ID).Pending != nil {
		t.Fatal("left pending")
	}
}

func TestDeleteTakesTheCrontabAndTheCounter(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	res, err := s.setCron(ctx, a.ID, CronInput{Jobs: []CronJob{{Schedule: "* * * * *", Command: "true"}}, ExpectedRevision: a.Revision, Reason: "r"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	f.tools().states[a.ID] = []byte(`{"version":1}`)
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: res.Account.Revision, Reason: "Remove"}, "op"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.tools().crontabs[a.Username]; ok {
		t.Fatal("crontab outlived the account")
	}
	if _, ok := f.tools().states[a.ID]; ok {
		t.Fatal("traffic counter outlived the account")
	}
	if sets, err := s.cronSets(a.ID); err != nil || len(sets) != 0 {
		t.Fatalf("cron bucket %v %v", sets, err)
	}
}

// ---- Logs ---------------------------------------------------------------------

func TestTailBounds(t *testing.T) {
	var log strings.Builder
	for i := range 300 {
		fmt.Fprintf(&log, "line %d\n", i)
	}
	lines, truncated := tailLines([]byte(log.String()), true)
	if len(lines) != MaxLogTailLines || lines[0] != "line 100" || lines[199] != "line 299" || !truncated {
		t.Fatalf("%d lines, first %q, truncated %v", len(lines), lines[0], truncated)
	}
	lines, truncated = tailLines([]byte("a\nb\n"), true)
	if strings.Join(lines, "|") != "a|b" || truncated {
		t.Fatal(lines, truncated)
	}
	// Started mid-file: the first piece is part of a line. A last piece
	// without a newline is still being written.
	lines, truncated = tailLines([]byte("rt of a line\nwhole\nbeing writ"), false)
	if strings.Join(lines, "|") != "whole" || !truncated {
		t.Fatal(lines, truncated)
	}
	if lines, _ = tailLines(nil, true); lines == nil || len(lines) != 0 {
		t.Fatal("empty log")
	}
	// Text a visitor sent stays text: invalid UTF-8 is replaced, markup is
	// not touched (the panel escapes it).
	lines, _ = tailLines([]byte("GET /\xff\xfe <script>alert(1)</script>\n"), true)
	if lines[0] != "GET /\uFFFD <script>alert(1)</script>" {
		t.Fatalf("%q", lines[0])
	}

	// readTail reads at most the last 256 KiB, whatever the file's size.
	big := bytes.Repeat([]byte(strings.Repeat("x", 99)+"\n"), 20000) // 2 MB
	r := &countingReaderAt{data: big}
	lines, truncated, err := readTail(r, int64(len(big)))
	if err != nil || r.read > maxLogTailBytes || len(lines) != MaxLogTailLines || !truncated {
		t.Fatalf("read %d bytes, %d lines, %v %v", r.read, len(lines), truncated, err)
	}
	small := []byte("one\ntwo\n")
	lines, truncated, _ = readTail(bytes.NewReader(small), int64(len(small)))
	if strings.Join(lines, "|") != "one|two" || truncated {
		t.Fatal(lines, truncated)
	}
}

type countingReaderAt struct {
	data []byte
	read int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := bytes.NewReader(c.data).ReadAt(p, off)
	c.read += n
	return n, err
}

// ---- Traffic ------------------------------------------------------------------

// accessLogLine is an access log line as OpenLiteSpeed 1.9.4 writes it.
func accessLogLine(when time.Time, request string, status int, body string) string {
	return fmt.Sprintf("203.0.113.9 - - [%s] \"%s\" %d %s \"-\" \"Mozilla/5.0\"\n", when.Format("02/Jan/2006:15:04:05 -0700"), request, status, body)
}

func TestParseAccessLine(t *testing.T) {
	when := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	cases := map[string]int64{
		accessLogLine(when, "GET / HTTP/1.1", 200, "1234"):                                   1234,
		accessLogLine(when, "GET /missing HTTP/1.1", 404, "-"):                               0,
		accessLogLine(when, `GET /\" 200 999999999 \"x HTTP/1.1`, 200, "10"):                 10,
		accessLogLine(when, `GET /a\\ HTTP/1.1`, 200, "7"):                                   7,
		"[24/Nov/2026:09:00:00 +0000] \"GET / HTTP/1.1\" 200 5":                              5,
		"203.0.113.9 - \"user\" [24/Nov/2026:09:00:00 +0000] \"GET / HTTP/1.1\" 304 - \"-\"": 0,
	}
	for line, want := range cases {
		_, n, ok := parseAccessLine([]byte(line))
		if !ok || n != want {
			t.Errorf("%q: %d %v, want %d", line, n, ok, want)
		}
	}
	for _, line := range []string{
		"", "garbage", "[24/Nov/2026:09:00:00 +0000] \"GET / HTTP/1.1\" 2x0 5", "[24/Nov/2026:09:00:00 +0000] \"GET / HTTP/1.1 200 5",
		"[24/Nov/2026:09:00:00 +0000] \"GET\" 200 -5", "[24/Nov/2026:09:00:00 +0000] \"GET\" 200 99999999999999999",
	} {
		if _, _, ok := parseAccessLine([]byte(line)); ok {
			t.Errorf("%q parsed", line)
		}
	}
}

func TestCountTrafficFollowsRotation(t *testing.T) {
	zone := time.FixedZone("UTC+4", 4*3600)
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, zone)
	nov := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	oct := time.Date(2026, 10, 31, 19, 59, 0, 0, time.UTC) // 23:59 at UTC+4: still October
	d := newMemLogDir()
	d.write("access.log", accessLogLine(oct, "GET / HTTP/1.1", 200, "5000"))
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "100"))
	d.write("access.log", accessLogLine(nov, "GET /x HTTP/1.1", 404, "-"))
	d.write("access.log", accessLogLine(nov, "POST /y HTTP/1.1", 200, "200"))
	// A line still being written is not counted yet.
	d.write("access.log", "203.0.113.9 - - [20/Nov/2026:08:00:00 +0000] \"GET /half")

	st, _, complete, err := countTraffic(trafficState{}, d, now, trafficBudget)
	if err != nil || !complete || st.Bytes != 300 || st.Month != "2026-11" {
		t.Fatalf("first read %+v %v %v", st, complete, err)
	}
	// The rest of the line arrives, then more; OpenLiteSpeed rotates; more
	// lines go to the new file. Nothing is counted twice or lost.
	d.write("access.log", " HTTP/1.1\" 200 1000 \"-\" \"-\"\n")
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "20"))
	d.rotate("access.log.2026_11_24")
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "3"))
	st, _, complete, err = countTraffic(st, d, now, trafficBudget)
	if err != nil || !complete || st.Bytes != 1323 {
		t.Fatalf("after rotation %+v %v %v", st, complete, err)
	}
	// Two rotations between reads.
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "1"))
	d.rotate("access.log.2026_11_24.01")
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "2"))
	d.rotate("access.log.2026_11_24.02")
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "4"))
	st, _, complete, _ = countTraffic(st, d, now, trafficBudget)
	if !complete || st.Bytes != 1330 {
		t.Fatalf("two rotations %+v", st)
	}
	// The file read last is gone (keepDays): reading goes on with the files
	// written after it, from their start.
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "10"))
	d.rotate("access.log.2026_11_24.03")
	delete(d.files, "access.log.2026_11_24.03")
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "50"))
	st, _, _, _ = countTraffic(st, d, now, trafficBudget)
	if st.Bytes != 1380 {
		t.Fatalf("after a lost file %+v", st)
	}
	// Nothing new: nothing changes and nothing is opened.
	opens := d.opens
	again, read, complete, _ := countTraffic(st, d, now, trafficBudget)
	if again != st || read != 0 || !complete || d.opens != opens {
		t.Fatalf("idle read %+v read %d opens %d", again, read, d.opens-opens)
	}
	// A new month starts at 0 and skips what is left of the old one.
	dec := time.Date(2026, 12, 1, 0, 5, 0, 0, zone)
	d.write("access.log", accessLogLine(nov, "GET / HTTP/1.1", 200, "999"))
	d.write("access.log", accessLogLine(dec, "GET / HTTP/1.1", 200, "7"))
	st, _, _, _ = countTraffic(st, d, dec.Add(time.Hour), trafficBudget)
	if st.Month != "2026-12" || st.Bytes != 7 {
		t.Fatalf("new month %+v", st)
	}
}

func TestCountTrafficIsBounded(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	nov := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	d := newMemLogDir()
	line := accessLogLine(nov, "GET / HTTP/1.1", 200, "10")
	for range 1000 {
		d.write("access.log", line)
	}
	// A line longer than maxLogLine is skipped, not counted, not stuck on.
	d.write("access.log", "203.0.113.9 - - [02/Nov/2026:00:00:00 +0000] \"GET /"+strings.Repeat("a", maxLogLine+10)+" HTTP/1.1\" 200 777777 \"-\" \"-\"\n")
	d.write("access.log", line)
	// A budget larger than any line the counter parses, so the over-long
	// line is skipped, and small enough to need several reads.
	budget := int64(maxLogLine + 1024)
	st := trafficState{}
	reads := 0
	for {
		var read int64
		var complete bool
		var err error
		st, read, complete, err = countTraffic(st, d, now, budget)
		reads++
		if err != nil || read > budget {
			t.Fatalf("read %d of %d: %v", read, budget, err)
		}
		if complete {
			break
		}
		if reads > 100 {
			t.Fatal("never completed")
		}
	}
	if st.Bytes != 10010 || reads < 3 {
		t.Fatalf("bytes %d after %d reads", st.Bytes, reads)
	}
}

// What is left of the budget after one file may be less than the next
// file's first line: the read stops before that line and the next read
// counts it, losing nothing.
func TestCountTrafficKeepsALineAtTheBudgetsEdge(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	nov := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	line := accessLogLine(nov, "GET / HTTP/1.1", 200, "10")
	d := newMemLogDir()
	for range 3 {
		d.write("access.log", line)
	}
	d.rotate("access.log.2026_11_24")
	for range 3 {
		d.write("access.log", line)
	}
	st, _, complete, err := countTraffic(trafficState{}, d, now, int64(3*len(line)+len(line)/2))
	if err != nil || complete || st.Bytes != 30 || st.Offset != 0 {
		t.Fatalf("first read %+v %v %v", st, complete, err)
	}
	st, _, complete, _ = countTraffic(st, d, now, trafficBudget)
	if !complete || st.Bytes != 60 {
		t.Fatalf("second read %+v %v", st, complete)
	}
}

func TestParseQuotaReport(t *testing.T) {
	// As xfsprogs 6.3 report_mount prints with -n -N -b: "#%-10u" then
	// " %10llu %10llu %10llu     %02d %9s".
	out := fmt.Sprintf("#%-10d %10d %10d %10d     %02d %9s\n#%-10d %10d %10d %10d     %02d %9s\n#%-10d %10d %10d %10d     %02d %9s\n\n",
		20000, 1536, 58982, 65536, 0, "[--------]",
		20001, 70000, 58982, 65536, 1, "[6 days]",
		0, 99, 0, 0, 0, "[--------]")
	got := parseQuotaReport([]byte("User quota on /home (/dev/vdb)\n" + out))
	if len(got) != 2 || got[20000] != (quotaUsage{1536, 58982, 65536}) || got[20001].UsedKiB != 70000 {
		t.Fatalf("%+v", got)
	}
	if len(parseQuotaReport([]byte("#20000 x 1 2\n#abc 1 2 3\n"))) != 0 {
		t.Fatal("junk parsed")
	}
}

// ---- Usage and logs through the store ---------------------------------------

func TestUsageReadsAreNotBlockedByPendingRecords(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	b, err := s.create(ctx, CreateInput{Username: "otheracct", Domain: "other.test", Reason: "Second"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	f.tools().quota[a.UID] = quotaUsage{UsedKiB: 2048, SoftKiB: 184320, HardKiB: 204800}
	d := newMemLogDir()
	d.write("access.log", accessLogLine(time.Now(), "GET / HTTP/1.1", 200, "4096"))
	f.tools().dirs[siteName(a.ID)] = d
	f.tools().logs[siteName(a.ID)+"/access"] = LogTail{Kind: "access", Lines: []string{"x"}, Size: 2}

	// Another account's change stays pending.
	pendingCron(t, s, b.ID, []CronJob{{Schedule: "* * * * *", Command: "true"}})
	u, err := s.siteUsage(ctx, a.ID)
	if err != nil || u.DiskUsedKiB != 2048 || u.DiskLimitKiB != 204800 || u.TrafficBytes != 4096 || !u.TrafficComplete || u.TrafficMonth != time.Now().Format("2006-01") {
		t.Fatalf("usage %+v %v", u, err)
	}
	if calls := f.tools().quotaCalls; !slices.Equal(calls[len(calls)-1], []int{a.UID}) {
		t.Fatalf("quota asked for %v", calls)
	}
	if _, ok := f.tools().states[a.ID]; !ok {
		t.Fatal("counter not saved")
	}
	all, err := s.usageAll(ctx)
	if calls := f.tools().quotaCalls; err != nil || len(all) != 2 || !slices.Equal(slices.Sorted(slices.Values(calls[len(calls)-1])), []int{a.UID, b.UID}) {
		t.Fatalf("all %+v %v", all, err)
	}
	for _, u := range all {
		if u.AccountID == b.ID && (u.TrafficBytes != 0 || !u.TrafficComplete) {
			t.Fatalf("site without logs %+v", u)
		}
	}
	tail, err := s.siteLog(ctx, a.ID, "access")
	if err != nil || len(tail.Lines) != 1 {
		t.Fatal(tail, err)
	}
	if tail, err := s.siteLog(ctx, b.ID, "error"); err != nil || !tail.Missing {
		t.Fatal(tail, err)
	}
	if _, err := s.siteLog(ctx, a.ID, "../../etc/shadow"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := s.siteUsage(ctx, strings.Repeat("0", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// Without the web operation there is no xfs_quota and no web user.
	s.web = nil
	if _, err := s.siteUsage(ctx, a.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := s.siteLog(ctx, a.ID, "access"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

// ---- The broker's routes -------------------------------------------------------

func TestSiteToolsRoutes(t *testing.T) {
	s, f := webStore(t)
	a := createFixture(t, s)
	h := handler(s)
	call := func(method, path, body string) (int, string) {
		req := httptest.NewRequest(method, "http://unix"+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	body := func(jobs string, revision uint64) string {
		return fmt.Sprintf(`{"input":{"jobs":%s,"expected_revision":%d,"reason":"Scheduled jobs changed"},"actor":"admin"}`, jobs, revision)
	}
	code, out := call("POST", "/v1/accounts/"+a.ID+"/cron", body(`[{"schedule":"*/5 * * * *","command":"php ~/public_html/wp-cron.php > /dev/null 2>&1"}]`, a.Revision))
	var res CronResult
	if code != 200 || json.Unmarshal([]byte(out), &res) != nil || len(res.Jobs) != 1 || res.Account.Revision != a.Revision+1 {
		t.Fatalf("set %d %s", code, out)
	}
	if !bytes.Contains(f.tools().crontabs[a.Username], []byte("*/5 * * * * php ~/public_html/wp-cron.php > /dev/null 2>&1\n")) {
		t.Fatalf("crontab %q", f.tools().crontabs[a.Username])
	}
	rev := res.Account.Revision
	for name, jobs := range map[string]string{
		"null":          `null`,
		"object":        `{"schedule":"* * * * *","command":"true"}`,
		"duplicate key": `[{"schedule":"* * * * *","command":"true","command":"id"}]`,
		"case alias":    `[{"Schedule":"* * * * *","command":"true"}]`,
		"extra key":     `[{"schedule":"* * * * *","command":"true","user":"root"}]`,
		"missing key":   `[{"schedule":"* * * * *"}]`,
		"number":        `[{"schedule":"* * * * *","command":1}]`,
		"newline":       `[{"schedule":"* * * * *","command":"true\n* * * * * id"}]`,
		"percent":       `[{"schedule":"* * * * *","command":"date +%s"}]`,
		"too many":      "[" + strings.TrimSuffix(strings.Repeat(`{"schedule":"* * * * *","command":"true"},`, MaxCronJobs+1), ",") + "]",
	} {
		if code, out := call("POST", "/v1/accounts/"+a.ID+"/cron", body(jobs, rev)); code != 400 {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	if code, _ := call("POST", "/v1/accounts/"+a.ID+"/cron", `{"input":{"jobs":[],"expected_revision":1,"reason":"r","extra":1},"actor":"a"}`); code != 400 {
		t.Fatalf("unknown input key %d", code)
	}
	if code, out := call("GET", "/v1/accounts/"+a.ID+"/cron", ""); code != 200 || !strings.Contains(out, `"next_run"`) {
		t.Fatalf("get %d %s", code, out)
	}
	if code, _ := call("GET", "/v1/accounts/"+a.ID+"/cron", "{}"); code != 400 {
		t.Fatalf("GET with a body %d", code)
	}
	f.tools().logs[siteName(a.ID)+"/error"] = LogTail{Kind: "error", Lines: []string{`<b>"x"</b>`}, Size: 10}
	// Returned as JSON text, markup escaped by the encoder.
	if code, out := call("GET", "/v1/accounts/"+a.ID+"/logs/error", ""); code != 200 || strings.Contains(out, "<b>") || !strings.Contains(out, "\\"+"u003cb") {
		t.Fatalf("log %d %s", code, out)
	}
	for _, path := range []string{"/v1/accounts/" + a.ID + "/logs/other", "/v1/accounts/" + a.ID + "/logs/../cron", "/v1/accounts/" + strings.ToUpper(a.ID) + "/usage"} {
		if code, _ := call("GET", path, ""); code != 404 {
			t.Errorf("%s: %d", path, code)
		}
	}
	if code, out := call("GET", "/v1/accounts/"+a.ID+"/usage", ""); code != 200 || !strings.Contains(out, `"traffic_month"`) {
		t.Fatalf("usage %d %s", code, out)
	}
	if code, out := call("GET", "/v1/usage", ""); code != 200 || !strings.Contains(out, `"items":[{`) {
		t.Fatalf("all usage %d %s", code, out)
	}
	if code, _ := call("POST", "/v1/usage", "{}"); code != 404 {
		t.Fatalf("POST usage %d", code)
	}
	if code, _ := call("DELETE", "/v1/accounts/"+a.ID+"/cron", ""); code != 404 {
		t.Fatalf("DELETE cron %d", code)
	}
}
