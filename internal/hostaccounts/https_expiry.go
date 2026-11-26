package hostaccounts

import (
	"context"
	"time"
)

// "Always use HTTPS" is decided when the config is rendered: webSites gives
// a site the redirect while its certificate is before its NotAfter. Nothing
// else renders the config when a certificate expires, so if its renewal
// kept failing, plain http would go on to an expired https until the next
// change. The expiry loop renders it again at that second: one timer, for
// the earliest NotAfter of a redirect the last render put in the config,
// set again after every change the store journals. The render is
// reloadWebServer's, the one .htaccess changes use: under the store lock,
// never while an operation is unfinished, tested before it is loaded, and
// it changes no account and journals nothing, as the account's record does
// not change; only the time does.

// httpsExpiryRetry is how long the loop waits to try again after a render
// that failed: an unfinished operation holds up every change, or the
// config test failed. It does not wait for a change to come first.
const httpsExpiryRetry = time.Minute

// httpsExpiry renders the web server's config again when a certificate
// with "Always use HTTPS" in force passes its NotAfter.
type httpsExpiry struct {
	// next is the earliest NotAfter later than a render made at its
	// argument put in force (store.httpsExpiresAfter); false: none.
	next func(time.Time) (time.Time, bool)
	// render renders the config from the records, tests and loads it
	// (store.reloadWebServer).
	render func(context.Context) error
	retry  time.Duration
	wakeup chan struct{}
}

func newHTTPSExpiry(next func(time.Time) (time.Time, bool), render func(context.Context) error) *httpsExpiry {
	return &httpsExpiry{next: next, render: render, retry: httpsExpiryRetry, wakeup: make(chan struct{}, 1)}
}

// wake says that a record changed, so the earliest NotAfter may have; it
// never waits.
func (h *httpsExpiry) wake() {
	select {
	case h.wakeup <- struct{}{}:
	default:
	}
}

// run renders the config at each NotAfter until ctx ends. rendered is when
// the config was last rendered before it started: a render made then has
// the redirects whose certificates were in force at that time. Zero means
// no render is known, so a redirect whose certificate has already expired
// is rendered away at once. A render already running when ctx ends
// finishes first: it works under the web operation's own limit.
func (h *httpsExpiry) run(ctx context.Context, rendered time.Time) {
	var retryAt time.Time // after a failed render: not again before this
	for {
		due, ok := h.next(rendered)
		if ok && due.Before(retryAt) {
			due = retryAt
		}
		if ok && !time.Now().Before(due) {
			started := time.Now()
			e := h.render(ctx)
			if ctx.Err() != nil {
				// The broker is stopping; what it cut short is no failure.
				return
			}
			if e != nil {
				logRecovery("https_expiry", record{}, "render the web server config at a certificate's NotAfter", e)
				retryAt = time.Now().Add(h.retry)
				continue
			}
			// A certificate that expired while the render ran may still
			// count as in force: it gets one more render, at once.
			rendered, retryAt = started, time.Time{}
			continue
		}
		var timer *time.Timer
		var fire <-chan time.Time
		if ok {
			timer = time.NewTimer(time.Until(due))
			fire = timer.C
		}
		select {
		case <-ctx.Done():
		case <-h.wakeup:
		case <-fire:
		}
		if timer != nil {
			timer.Stop()
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// httpsExpiresAfter is the earliest NotAfter of a site that a render made
// at after put in the config with "Always use HTTPS" on, as the records
// are now; false when there is none, or the records cannot be read (a
// change that repairs them wakes the loop).
func (s *store) httpsExpiresAfter(after time.Time) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.records()
	if err != nil {
		return time.Time{}, false
	}
	return firstHTTPSExpiry(items, after)
}

// firstHTTPSExpiry is the earliest NotAfter, later than after's second,
// among the sites webSites lists with "Always use HTTPS" on while their
// certificate is valid: webSites renders the redirect while the time's
// Unix second is before NotAfter.
func firstHTTPSExpiry(items []record, after time.Time) (time.Time, bool) {
	var first int64
	for _, r := range items {
		if _, served := servedWeb(r); !served {
			continue
		}
		if until := httpsUntil(r); until > after.Unix() && (first == 0 || until < first) {
			first = until
		}
	}
	if first == 0 {
		return time.Time{}, false
	}
	return time.Unix(first, 0), true
}

// wakeHTTPSExpiry tells the expiry loop, if there is one, that a record
// changed.
func (s *store) wakeHTTPSExpiry() {
	if s.httpsWake != nil {
		s.httpsWake()
	}
}
