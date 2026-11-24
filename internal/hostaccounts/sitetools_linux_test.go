//go:build linux

package hostaccounts

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestQuotaReportArgs(t *testing.T) {
	got := quotaReportArgs(20001, 20001, "/home")
	want := []string{"-x", "-c", "report -u -b -n -N -L 20001 -U 20001", "/home"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv %q", got)
	}
	// Accounts go in reports of at most quotaReportUIDs UIDs each.
	uids := []int{20001}
	for uid := 20002; uid < 21202; uid++ {
		uids = append(uids, uid)
	}
	uids = append(uids, 20001, 59999)
	ranges := quotaRanges(uids)
	if len(ranges) != 3 || ranges[0] != [2]int{20001, 20500} || ranges[1] != [2]int{20501, 21000} || ranges[2] != [2]int{21001, 59999} {
		t.Fatalf("ranges %v", ranges)
	}
	if quotaRanges(nil) != nil {
		t.Fatal("no accounts, no report")
	}
	n := &linuxSystem{}
	if _, e := n.QuotaUsage(t.Context(), []int{20000}); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("without the web operation: %v", e)
	}
	n.webUID = 65534
	if _, e := n.QuotaUsage(t.Context(), []int{20000, 1000}); !errors.Is(e, ErrInvalid) {
		t.Fatalf("UID outside the account range: %v", e)
	}
}

// Non-root: SetCron needs a root-owned crontab directory and refuses
// anything else before it writes.
func TestCronNeedsTheRootDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("covered by the root test")
	}
	dir := filepath.Join(t.TempDir(), "cron")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture")
	}
	n := &linuxSystem{cronDir: dir}
	r := record{Account: Account{ID: strings.Repeat("a", 32), Username: "fixtureacct", UID: 20000, GID: 20000}}
	if e := n.SetCron(t.Context(), r, renderCrontab([]CronJob{{Schedule: "* * * * *", Command: "true"}})); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("directory not root's: %v", e)
	}
	if e := n.VerifyCron(r, nil); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("verify in a directory not root's: %v", e)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("wrote into an unadmitted directory")
	}
}

// Root-only: the crontab's real file effects. Run on the dev VM with:
// go test -c ./internal/hostaccounts && sudo ./hostaccounts.test -test.run RootOnly
func TestRootOnlyCrontabFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: checks the owner and mode of the installed crontab")
	}
	base, e := os.MkdirTemp("/var/lib", "sifruno-cron-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "cron")
	if os.Chmod(base, 0755) != nil || os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture")
	}
	n := &linuxSystem{cronDir: dir}
	r := record{Account: Account{ID: strings.Repeat("c", 32), Username: "fixtureacct", UID: 54321, GID: 54321}}
	target := filepath.Join(dir, "fixtureacct")
	first := renderCrontab([]CronJob{{Schedule: "*/5 * * * *", Command: "touch ~/cron-ran"}})
	check := func(want []byte) {
		t.Helper()
		info, e := os.Lstat(target)
		if e != nil {
			t.Fatal(e)
		}
		st := info.Sys().(*syscall.Stat_t)
		// What crond's check_open accepts and cronie's crontab leaves when
		// root runs it: regular, one link, root's, 0600.
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 {
			t.Fatalf("crontab is %v uid %d gid %d links %d", info.Mode(), st.Uid, st.Gid, st.Nlink)
		}
		if got, _ := os.ReadFile(target); !bytes.Equal(got, want) {
			t.Fatalf("crontab %q", got)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Fatalf("temporary file left behind: %v", entries)
		}
	}
	if e := n.SetCron(t.Context(), r, first); e != nil {
		t.Fatal(e)
	}
	check(first)
	if n.VerifyCron(r, first) != nil || !errors.Is(n.VerifyCron(r, nil), ErrRecovery) {
		t.Fatal("verify")
	}
	second := renderCrontab([]CronJob{{Schedule: "0 3 * * *", Command: "true"}, {Schedule: "*/5 * * * *", Command: "touch ~/cron-ran"}})
	if e := n.SetCron(t.Context(), r, second); e != nil {
		t.Fatal(e)
	}
	check(second)
	// Something root did not write there is left alone.
	if os.Remove(target) != nil || os.Symlink("/etc/shadow", target) != nil {
		t.Fatal("fixture")
	}
	if e := n.SetCron(t.Context(), r, first); !errors.Is(e, ErrRecovery) {
		t.Fatalf("over a link: %v", e)
	}
	if info, _ := os.Lstat(target); info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link replaced")
	}
	if os.Remove(target) != nil {
		t.Fatal("fixture")
	}
	// No jobs: no file.
	if e := n.SetCron(t.Context(), r, nil); e != nil || n.VerifyCron(r, nil) != nil {
		t.Fatalf("remove: %v", e)
	}
	// A directory others may enter is not cronie's.
	if os.Chmod(dir, 0755) != nil {
		t.Fatal("fixture")
	}
	if e := n.SetCron(t.Context(), r, first); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("loosened directory: %v", e)
	}
}

// logFixture is a site's log directory owned by the test's own user, who
// stands for the web server's user.
func logFixture(t *testing.T) (*linuxSystem, string) {
	t.Helper()
	dir := t.TempDir()
	return &linuxSystem{webUID: os.Getuid()}, dir
}

func TestLinuxLogDirFollowsRotation(t *testing.T) {
	n, path := logFixture(t)
	d, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	dir := linuxLogDir{n: n, dir: d}
	defer dir.Close()
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	nov := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	appendLine := func(name, body string) {
		t.Helper()
		f, e := os.OpenFile(filepath.Join(path, name), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := f.WriteString(accessLogLine(nov, "GET / HTTP/1.1", 200, body)); e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	appendLine("access.log", "100")
	appendLine("access.log", "200")
	// Names that are not logs, a link, a FIFO and a second link to a log
	// are never read.
	os.WriteFile(filepath.Join(path, "error.log"), []byte(accessLogLine(nov, "GET / HTTP/1.1", 200, "999")), 0644)
	os.Symlink("/etc/passwd", filepath.Join(path, "access.log.2026_11_01"))
	syscall.Mkfifo(filepath.Join(path, "access.log.2026_11_02"), 0644)
	os.WriteFile(filepath.Join(path, "access.log.2026_11_03"), []byte(accessLogLine(nov, "GET / HTTP/1.1", 200, "999")), 0644)
	os.Link(filepath.Join(path, "access.log.2026_11_03"), filepath.Join(path, "access.log.2026_11_04"))

	files, e := dir.AccessLogs()
	if e != nil || len(files) != 1 || files[0].Name != "access.log" {
		t.Fatalf("listed %+v %v", files, e)
	}
	st, _, complete, e := countTraffic(trafficState{}, dir, now, trafficBudget)
	if e != nil || !complete || st.Bytes != 300 {
		t.Fatalf("first %+v %v %v", st, complete, e)
	}
	// OpenLiteSpeed's rotation: a rename, then a new file.
	appendLine("access.log", "30")
	if os.Rename(filepath.Join(path, "access.log"), filepath.Join(path, "access.log.2026_11_24")) != nil {
		t.Fatal("rotate")
	}
	appendLine("access.log", "4")
	st, _, complete, e = countTraffic(st, dir, now, trafficBudget)
	if e != nil || !complete || st.Bytes != 334 {
		t.Fatalf("after rotation %+v %v %v", st, complete, e)
	}
	// A file swapped under a listed name is refused, not read.
	files, _ = dir.AccessLogs()
	var live logFile
	for _, f := range files {
		if f.Name == "access.log" {
			live = f
		}
	}
	// Made while the old one exists, so it cannot reuse its inode.
	os.WriteFile(filepath.Join(path, "swap"), []byte("other"), 0644)
	os.Rename(filepath.Join(path, "swap"), filepath.Join(path, "access.log"))
	if _, e := dir.Open(live); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("swapped file opened: %v", e)
	}
}

func TestUsageStateFiles(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if os.Mkdir(state, 0700) != nil {
		t.Fatal("fixture")
	}
	n := &linuxSystem{opts: BrokerOptions{StateDir: state}}
	id := strings.Repeat("d", 32)
	if b, e := n.LoadUsageState(id); b != nil || e != nil {
		t.Fatalf("no counter yet: %q %v", b, e)
	}
	if e := n.SaveUsageState(id, []byte(`{"version":1}`)); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(filepath.Join(state, "usage"))
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("usage directory %v %v", info, e)
	}
	if info, e := os.Lstat(filepath.Join(state, "usage", id+".json")); e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("counter file %v %v", info, e)
	}
	if b, e := n.LoadUsageState(id); string(b) != `{"version":1}` || e != nil {
		t.Fatalf("load %q %v", b, e)
	}
	if e := n.RemoveUsageState(id); e != nil {
		t.Fatal(e)
	}
	if e := n.RemoveUsageState(id); e != nil {
		t.Fatalf("removing twice: %v", e)
	}
	for _, bad := range []string{"../../etc/x", "", strings.Repeat("D", 32)} {
		if e := n.SaveUsageState(bad, nil); !errors.Is(e, ErrInvalid) {
			t.Fatalf("%q: %v", bad, e)
		}
	}
	// A link in place of the counters' directory is refused.
	if os.Remove(filepath.Join(state, "usage")) != nil || os.Symlink(t.TempDir(), filepath.Join(state, "usage")) != nil {
		t.Fatal("fixture")
	}
	if e := n.SaveUsageState(id, []byte("{}")); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("through a link: %v", e)
	}
}

// Root-only: a site's log tail through the real directory checks.
func TestRootOnlyTailLog(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the log root must be root's")
	}
	base, e := os.MkdirTemp("/var/lib", "sifruno-logs-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	site := "u" + strings.Repeat("e", 31)
	if os.Chmod(base, 0755) != nil || os.Mkdir(filepath.Join(base, site), 0750) != nil {
		t.Fatal("fixture")
	}
	n := &linuxSystem{webUID: 65534, logRoot: base}
	if tail, e := n.TailLog(t.Context(), site, "access"); e != nil || !tail.Missing {
		t.Fatalf("no log yet: %+v %v", tail, e)
	}
	var log bytes.Buffer
	for range 5000 {
		log.WriteString(strings.Repeat("y", 120) + "\n")
	}
	if os.WriteFile(filepath.Join(base, site, "error.log"), log.Bytes(), 0644) != nil {
		t.Fatal("fixture")
	}
	tail, e := n.TailLog(t.Context(), site, "error")
	if e != nil || len(tail.Lines) != MaxLogTailLines || !tail.Truncated || tail.Size != int64(log.Len()) {
		t.Fatalf("tail %d lines %v %v", len(tail.Lines), tail.Truncated, e)
	}
	// A link where the log should be is not followed.
	os.Symlink("/etc/shadow", filepath.Join(base, site, "access.log"))
	if _, e := n.TailLog(t.Context(), site, "access"); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("through a link: %v", e)
	}
	if _, e := n.TailLog(t.Context(), "../etc", "access"); !errors.Is(e, ErrInvalid) {
		t.Fatalf("bad site name: %v", e)
	}
}
