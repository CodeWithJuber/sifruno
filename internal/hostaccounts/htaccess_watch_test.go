package hostaccounts

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeRestarts stands in for the web server's graceful restart: each call
// records when it started and ended, takes took, and answers the next
// error of fail (nil once fail is used up).
type fakeRestarts struct {
	mu     sync.Mutex
	took   time.Duration
	fail   []error
	starts []time.Time
	ends   []time.Time
}

func (f *fakeRestarts) restart(context.Context) error {
	f.mu.Lock()
	f.starts = append(f.starts, time.Now())
	var e error
	if len(f.fail) > 0 {
		e, f.fail = f.fail[0], f.fail[1:]
	}
	f.mu.Unlock()
	time.Sleep(f.took)
	f.mu.Lock()
	f.ends = append(f.ends, time.Now())
	f.mu.Unlock()
	return e
}

func (f *fakeRestarts) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.starts)
}

func (f *fakeRestarts) times() ([]time.Time, []time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.starts...), append([]time.Time(nil), f.ends...)
}

// runReloader starts h in the current bubble and returns a stop function
// that ends it and waits until it has returned.
func runReloader(t *testing.T, h *htaccessReloader) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		h.run(ctx)
		close(done)
	}()
	return func() {
		cancel()
		<-done
	}
}

// logged reads the captured recovery log under its lock.
func logged(buf interface{ String() string }) string {
	recoveryLogMu.Lock()
	defer recoveryLogMu.Unlock()
	return buf.String()
}

var restartLine = regexp.MustCompile(`sifruno broker: htaccess: OpenLiteSpeed restarted gracefully for (\d+) \.htaccess changes`)

// restartCounts is the change count of each restart line in log.
func restartCounts(t *testing.T, log string) []uint64 {
	t.Helper()
	var out []uint64
	for _, m := range restartLine.FindAllStringSubmatch(log, -1) {
		n, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func TestHtaccessChangeRestartsOnceAfterTheQuietPeriod(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := captureRecoveryLog(t)
		f := &fakeRestarts{}
		h := newHtaccessReloader(f.restart)
		stop := runReloader(t, h)
		defer stop()
		synctest.Wait()
		if f.count() != 0 {
			t.Fatal("restarted with no change")
		}
		changed := time.Now()
		h.changed(1)
		time.Sleep(htaccessQuiet - time.Millisecond)
		synctest.Wait()
		if f.count() != 0 {
			t.Fatal("restarted before the quiet period ended")
		}
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		starts, _ := f.times()
		if len(starts) != 1 || starts[0].Sub(changed) != htaccessQuiet {
			t.Fatalf("one restart %s after the change, got %v", htaccessQuiet, starts)
		}
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if f.count() != 1 {
			t.Fatalf("one change restarted %d times", f.count())
		}
		if got := restartCounts(t, logged(log)); len(got) != 1 || got[0] != 1 {
			t.Fatalf("log %q", logged(log))
		}
	})
}

// A tenant who writes .htaccess without pause gets one restart per window
// for every account: each restart starts at least htaccessWindow after the
// one before ended, a change never waits more than htaccessMaxWait plus a
// window, and the last change is still covered.
func TestHtaccessFloodRestartsOncePerWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := captureRecoveryLog(t)
		// A slow restart, as on a busy host, which the window must outlast.
		f := &fakeRestarts{took: 20 * time.Second}
		h := newHtaccessReloader(f.restart)
		stop := runReloader(t, h)
		defer stop()
		begin := time.Now()
		const flood = 5 * time.Minute
		writes := uint64(0)
		var last time.Time
		for time.Since(begin) < flood {
			h.changed(1)
			writes++
			last = time.Now()
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		stop()
		starts, ends := f.times()
		if len(starts) == 0 || len(ends) != len(starts) {
			t.Fatalf("starts %d, ends %d", len(starts), len(ends))
		}
		if wait := starts[0].Sub(begin); wait > htaccessMaxWait {
			t.Fatalf("the first restart waited %s for changes that kept coming", wait)
		}
		for i := 1; i < len(starts); i++ {
			if gap := starts[i].Sub(ends[i-1]); gap < htaccessWindow {
				t.Fatalf("restart %d started %s after the one before ended", i, gap)
			}
		}
		// Each restart takes the window plus its own time at least.
		bound := 1 + int(ends[len(ends)-1].Sub(begin)/(htaccessWindow+f.took))
		if len(starts) > bound {
			t.Fatalf("%d restarts, more than %d", len(starts), bound)
		}
		if !starts[len(starts)-1].After(last) {
			t.Fatal("the last change was not covered by a restart that started after it")
		}
		counts := restartCounts(t, logged(log))
		if len(counts) != len(starts) {
			t.Fatalf("%d restart lines for %d restarts", len(counts), len(starts))
		}
		sum := uint64(0)
		for _, n := range counts {
			sum += n
		}
		if sum != writes {
			t.Fatalf("the restart lines count %d changes, the flood made %d", sum, writes)
		}
		t.Logf("%d changes over %s: %d restarts", writes, flood, len(starts))
	})
}

func TestHtaccessChangeDuringARestartGetsTheNextWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeRestarts{took: 10 * time.Second}
		h := newHtaccessReloader(f.restart)
		stop := runReloader(t, h)
		defer stop()
		h.changed(1)
		time.Sleep(htaccessQuiet + time.Second)
		synctest.Wait()
		if f.count() != 1 {
			t.Fatalf("%d restarts after the first change", f.count())
		}
		// OpenLiteSpeed may already have read this .htaccess: another
		// restart must follow.
		h.changed(1)
		time.Sleep(time.Hour)
		synctest.Wait()
		starts, ends := f.times()
		if len(starts) != 2 || starts[1].Sub(ends[0]) != htaccessWindow {
			t.Fatalf("a second restart one window after the first ended: %v %v", starts, ends)
		}
	})
}

func TestHtaccessFailedRestartIsLoggedAndTriedAgainAtTheNextWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := captureRecoveryLog(t)
		f := &fakeRestarts{took: time.Second, fail: []error{ErrWebRejected, ErrRecovery}}
		h := newHtaccessReloader(f.restart)
		stop := runReloader(t, h)
		defer stop()
		h.changed(3)
		time.Sleep(time.Hour)
		synctest.Wait()
		starts, ends := f.times()
		if len(starts) != 3 {
			t.Fatalf("two failures and a success: %d restarts", len(starts))
		}
		for i := 1; i < 3; i++ {
			if gap := starts[i].Sub(ends[i-1]); gap != htaccessWindow {
				t.Fatalf("attempt %d came %s after the failure, not one window", i, gap)
			}
		}
		out := logged(log)
		for _, want := range []string{
			`sifruno broker: recovery: operation=htaccess account=- user=- step="graceful restart for .htaccess changes" error="the web server's config test failed"`,
			`sifruno broker: recovery: operation=htaccess account=- user=- step="graceful restart for .htaccess changes" error="differs from what the broker recorded"`,
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("log lacks %q:\n%s", want, out)
			}
		}
		if got := restartCounts(t, out); len(got) != 1 || got[0] != 3 {
			t.Fatalf("the restart that worked must count the 3 changes: %q", out)
		}
	})
}

func TestHtaccessUnseenChangesRestartToo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := captureRecoveryLog(t)
		f := &fakeRestarts{}
		h := newHtaccessReloader(f.restart)
		stop := runReloader(t, h)
		defer stop()
		h.lost(2)
		time.Sleep(time.Minute)
		synctest.Wait()
		if f.count() != 1 {
			t.Fatalf("%d restarts for a full event queue", f.count())
		}
		want := "sifruno broker: htaccess: OpenLiteSpeed restarted gracefully for 0 .htaccess changes and 2 times changes may have gone unseen (the watcher started, or its event queue was full)\n"
		if got := logged(log); got != want {
			t.Fatalf("log %q", got)
		}
	})
}

func TestHtaccessReloaderStopsWithItsContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeRestarts{}
		h := newHtaccessReloader(f.restart)
		stop := runReloader(t, h)
		h.changed(1)
		stop()
		time.Sleep(time.Hour)
		synctest.Wait()
		if f.count() != 0 {
			t.Fatal("restarted after its context ended")
		}
	})
}

// A restart the broker's shutdown cut short is not a failure to log.
func TestHtaccessRestartStoppedByShutdownIsNotLogged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := captureRecoveryLog(t)
		started := make(chan struct{})
		h := newHtaccessReloader(func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ErrUnavailable
		})
		stop := runReloader(t, h)
		h.changed(1)
		<-started
		stop()
		if got := logged(log); got != "" {
			t.Fatalf("log %q", got)
		}
	})
}

// A change costs the watcher no allocation: a flood cannot grow its memory.
func TestHtaccessChangeAllocatesNothing(t *testing.T) {
	h := newHtaccessReloader(func(context.Context) error { return nil })
	if n := testing.AllocsPerRun(1000, func() { h.changed(1); h.lost(1) }); n != 0 {
		t.Fatalf("%v allocations per change", n)
	}
}

func TestHtaccessRestartInstallsTheSiteListAgain(t *testing.T) {
	s, f := webStore(t)
	r := liveFixture(t, s)
	before := f.siteApplies
	if err := s.reloadWebServer(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.siteApplies != before+1 || len(f.sites) != 1 || f.sites[0].Name != siteName(r.Account.ID) {
		t.Fatalf("applies %d, sites %+v", f.siteApplies-before, f.sites)
	}
	if after := recordFor(t, s, r.Account.ID); after.Account.Revision != r.Account.Revision || after.Pending != nil {
		t.Fatal("a restart for .htaccess changes must change no account")
	}
}

func TestHtaccessRestartWaitsForTheStoreLock(t *testing.T) {
	s, f := webStore(t)
	liveFixture(t, s)
	before := f.siteApplies
	s.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- s.reloadWebServer(context.Background()) }()
	select {
	case err := <-done:
		s.mu.Unlock()
		t.Fatalf("the restart ran while a web operation held the store lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	s.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.siteApplies != before+1 {
		t.Fatalf("%d installs after the lock was free", f.siteApplies-before)
	}
}

// An unfinished operation may have half-written the config: the restart
// is refused, as every change is, and nothing is installed. The refusal
// names no account: the watcher logs it, by its class, every window.
func TestHtaccessRestartIsRefusedWhileAnOperationIsUnfinished(t *testing.T) {
	s, f := webStore(t)
	a := createFixture(t, s)
	f.failure = "web-after"
	if _, err := s.setWeb(context.Background(), a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	f.failure = ""
	logs := captureRecoveryLog(t)
	before := f.siteApplies
	err := s.reloadWebServer(context.Background())
	if !errors.Is(err, errHoldsEveryChange) {
		t.Fatalf("restart with an unfinished web operation: %v", err)
	}
	if f.siteApplies != before {
		t.Fatal("the config was installed while an operation was unfinished")
	}
	if out := logged(logs); strings.Contains(out, a.ID) || strings.Contains(out, a.Username) {
		t.Fatalf("the refusal named the account: %q", out)
	}
	if got := errorClass(err); got != "an unfinished operation holds up every change" {
		t.Fatalf("logged as %q", got)
	}
}

func TestHtaccessRestartNeedsTheWebOperation(t *testing.T) {
	s, f, _ := setupStore(t)
	if err := s.reloadWebServer(context.Background()); !errors.Is(err, ErrUnavailable) || f.siteApplies != 0 {
		t.Fatalf("restart without --web-user: %v, %d installs", err, f.siteApplies)
	}
}
