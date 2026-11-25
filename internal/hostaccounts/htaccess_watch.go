package hostaccounts

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// OpenLiteSpeed reads a site's .htaccess only when it starts or restarts
// gracefully (internal/htaccess doc.go has the sources): a .htaccess that
// WordPress, WP-CLI, the file manager, a restore or the tenant over SFTP
// writes later is not acted on until then, and one that was missing at the
// last restart stays unread. The broker watches the homes filesystem for
// changes to names exactly ".htaccess" (htaccess_watch_linux.go) and turns
// them into graceful restarts here: coalesced, and limited so that a tenant
// who changes .htaccess without pause costs every account at most one
// restart per window.
//
// The timing:
//   - htaccessQuiet: one action (a permalink save, a plugin's activation, a
//     file manager upload, a restore's copy) writes its .htaccess within a
//     second or two, so 5 s without a further change makes its writes one
//     restart, and the person who saved sees the change take effect soon
//     after. The window, not this, is what bounds a flood.
//   - htaccessMaxWait: changes that never pause still get a restart at most
//     30 s after the first of them, so a tenant writing .htaccess in a loop
//     cannot hold back another site's change.
//   - htaccessWindow: the next restart starts at least 30 s after the one
//     before ended. A restart holds the store lock, as a web change does, for
//     the config test and the graceful restart, which took about 20 s on a
//     busy dev VM; counting the window from its end leaves the lock free for
//     at least 30 s between two restarts however long each takes.
const (
	htaccessQuiet   = 5 * time.Second
	htaccessMaxWait = 30 * time.Second
	htaccessWindow  = 30 * time.Second
)

// errFanotifyEvent: an event that does not have the layout fanotify(7)
// gives; the watcher stops rather than guess.
var errFanotifyEvent = errors.New("an fanotify event the broker cannot read")

// htaccessReloader coalesces .htaccess changes into graceful restarts of
// the web server. The watcher records changes with changed and lost, which
// never wait and allocate nothing: a flood of events only adds to two
// counters and finds the wakeup already full. run restarts at most once per
// window; a restart covers every change recorded before it started, and a
// change recorded while one runs (OpenLiteSpeed may already have read that
// .htaccess) gets the next. A failed restart is logged and tried again one
// window after it ended; it changes no account, so it holds up no other
// operation beyond the time it holds the lock.
type htaccessReloader struct {
	restart                func(context.Context) error
	quiet, maxWait, window time.Duration
	// seen counts .htaccess changes, missed the times changes may have
	// gone unseen, since run last took them.
	seen, missed atomic.Uint64
	wakeup       chan struct{}
}

func newHtaccessReloader(restart func(context.Context) error) *htaccessReloader {
	return &htaccessReloader{restart: restart, quiet: htaccessQuiet, maxWait: htaccessMaxWait, window: htaccessWindow, wakeup: make(chan struct{}, 1)}
}

// changed records n changes of a .htaccess; it never waits.
func (h *htaccessReloader) changed(n uint64) {
	h.seen.Add(n)
	h.wake()
}

// lost records n times that changes may have gone unseen (the watcher
// started, or the kernel's event queue was full); each restarts like a
// change.
func (h *htaccessReloader) lost(n uint64) {
	h.missed.Add(n)
	h.wake()
}

func (h *htaccessReloader) wake() {
	select {
	case h.wakeup <- struct{}{}:
	default:
	}
}

// due is when the next restart may start: once the changes have been quiet
// for quiet, or maxWait after the first of them, and never sooner than
// window after the last restart ended (none yet: ended is zero).
func (h *htaccessReloader) due(first, last, ended time.Time) time.Time {
	at := last.Add(h.quiet)
	if limit := first.Add(h.maxWait); limit.Before(at) {
		at = limit
	}
	if next := ended.Add(h.window); !ended.IsZero() && next.After(at) {
		at = next
	}
	return at
}

// run restarts the web server for the recorded changes until ctx ends. A
// restart already running when ctx ends finishes first: it works under the
// web operation's own limit (webContext).
func (h *htaccessReloader) run(ctx context.Context) {
	var (
		dirty        bool
		first, last  time.Time // the first and latest change the next restart covers
		ended        time.Time // when the last restart ended
		seen, missed uint64    // what the next restart covers
		timer        *time.Timer
		fire         <-chan time.Time
	)
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	take := func() bool {
		s, m := h.seen.Swap(0), h.missed.Swap(0)
		seen, missed = seen+s, missed+m
		return s+m > 0
	}
	for {
		if dirty && fire == nil {
			timer = time.NewTimer(time.Until(h.due(first, last, ended)))
			fire = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-h.wakeup:
			// Counts a restart already took leave nothing to do: those
			// changes came before it started.
			if !take() {
				continue
			}
			now := time.Now()
			if !dirty {
				dirty, first = true, now
			}
			last = now
		case <-fire:
			fire = nil
			if time.Now().Before(h.due(first, last, ended)) {
				// A later change moved it; the loop sets the timer again.
				continue
			}
			// Changes recorded until now come before the restart reads
			// any .htaccess, so it covers them too.
			take()
			dirty = false
			e := h.restart(ctx)
			ended = time.Now()
			if ctx.Err() != nil {
				// The broker is stopping; what it cut short is no failure.
				return
			}
			if e != nil {
				logRecovery("htaccess", record{}, "graceful restart for .htaccess changes", e)
				dirty, first, last = true, ended, ended
				continue
			}
			logHtaccessRestart(seen, missed)
			seen, missed = 0, 0
		}
	}
}

// logHtaccessRestart says that a restart covered seen .htaccess changes and
// missed notices of unseen ones. It names counts only: never a path, a
// name or an account, which all come from tenants' files.
func logHtaccessRestart(seen, missed uint64) {
	recoveryLogMu.Lock()
	defer recoveryLogMu.Unlock()
	if missed == 0 {
		fmt.Fprintf(recoveryLog, "sifruno broker: htaccess: OpenLiteSpeed restarted gracefully for %d .htaccess changes\n", seen)
		return
	}
	fmt.Fprintf(recoveryLog, "sifruno broker: htaccess: OpenLiteSpeed restarted gracefully for %d .htaccess changes and %d times changes may have gone unseen (the watcher started, or its event queue was full)\n", seen, missed)
}

// logHtaccessOff says once that the watcher is not running, and why, by the
// class of the error alone.
func logHtaccessOff(what string, cause error) {
	recoveryLogMu.Lock()
	defer recoveryLogMu.Unlock()
	fmt.Fprintf(recoveryLog, "sifruno broker: htaccess: the .htaccess watcher %s (error=%q); a .htaccess change now takes effect at the next web change or OpenLiteSpeed restart\n", what, errorClass(cause))
}
