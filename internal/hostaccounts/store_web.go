package hostaccounts

import (
	"context"
	"errors"
	"time"

	"sifruno/internal/olsweb"
)

// ErrWebRejected means the new OpenLiteSpeed config failed its test (or the
// homes filesystem does not enforce quotas) and the old files went back:
// the site is as it was.
var ErrWebRejected = errors.New("web configuration rejected")

// webApplyTimeout bounds the native work after the intent is journaled. It
// does not follow the caller's context, so a client that gives up does not
// leave a half-finished apply behind.
// Its four minutes cover the quota commands, the config test and the
// graceful restart, each with its own limit.
const webApplyTimeout = 4 * time.Minute

func webContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), webApplyTimeout)
}

// setWeb makes an account's site live.
//
// The step that depends on the tenant's own files (web server access on the
// home and public_html) runs first and is idempotent: if the tenant changed
// those directories the request is refused before anything is journaled, so
// a tenant cannot leave an unfinished operation that blocks every account.
// After the intent is journaled, the broker sets the quota and installs the
// config: written, tested, then reloaded, or restored and journaled as
// rejected, which leaves the account unchanged.
func (s *store) setWeb(ctx context.Context, id string, in WebInput, actor string) (WebResult, error) {
	if snapshotReentry(ctx, s) {
		return WebResult{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	want := WebState{PHPVersion: in.PHPVersion, QuotaMiB: in.QuotaMiB}
	if !idPattern.MatchString(id) || !validWebState(want) || in.ExpectedRevision == 0 || !validText(in.Reason, 500) || !validText(actor, 120) {
		return WebResult{}, ErrInvalid
	}
	if s.web == nil {
		return WebResult{}, ErrUnavailable
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return WebResult{}, err
	}
	index := -1
	for i, item := range items {
		if item.Account.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return WebResult{}, ErrNotFound
	}
	r := items[index]
	// A running WordPress install uses the site's current PHP.
	if r.Account.Revision != in.ExpectedRevision || r.Account.State != "active" || s.installing[id] {
		return WebResult{}, ErrConflict
	}
	if r.Account.Revision == ^uint64(0) {
		return WebResult{}, recovery("web", r, "revision at its limit", ErrConflict)
	}
	// Two history rows, with room left as historyRoom leaves it for the
	// operations a tenant can reach, so the result can always be journaled.
	if !historyRoom(r, operationRows, false) {
		return WebResult{}, ErrConflict
	}
	if s.native.Verify(ctx, r) != nil || s.native.GrantWebAccess(ctx, r) != nil {
		return WebResult{}, ErrConflict
	}
	previous := r.Web
	r.Pending = &pending{Action: "web", Target: webDigest(want), Actor: actor, Reason: in.Reason}
	r.WebNext = want
	next := append([]record(nil), items...)
	next[index] = r
	sites := webSites(next, "")
	operationID, e := randomID()
	if e != nil {
		return WebResult{}, e
	}
	r.Pending.OperationID = operationID
	before := r.Account
	after := r.Account
	after.Revision++
	intent := operationEvent{OperationID: operationID, Action: "web", Status: "intended", Actor: actor, Reason: in.Reason, Before: &before, After: after}
	r, err = s.appendEvent(r, intent)
	if err != nil {
		return WebResult{}, ErrRecovery
	}
	applyCtx, cancel := webContext(ctx)
	defer cancel()
	switch e := s.native.ApplyWeb(applyCtx, r, previous, want, sites, s.tenantBroken(next, id)); {
	case errors.Is(e, ErrWebRejected):
		operation := *r.Pending
		r.Pending, r.WebNext = nil, WebState{}
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return WebResult{}, ErrRecovery
		}
		return WebResult{}, ErrWebRejected
	case e != nil:
		s.recoveryRequired(r, *r.Pending, "apply", e)
		return WebResult{}, ErrRecovery
	}
	r.Web, r.WebNext = want, WebState{}
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
	operation := *r.Pending
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return WebResult{}, ErrRecovery
	}
	return WebResult{Account: r.Account, Web: want}, nil
}

// applySitesWithout installs every live site except the given account's,
// for a change to that account.
func (s *store) applySitesWithout(ctx context.Context, items []record, id string) error {
	applyCtx, cancel := webContext(ctx)
	defer cancel()
	return s.native.ApplySites(applyCtx, webSites(items, id), s.tenantBroken(items, id))
}

// applySites installs every live site, each as its account's state says,
// for a change to the account named by subject.
func (s *store) applySites(ctx context.Context, items []record, subject string) error {
	applyCtx, cancel := webContext(ctx)
	defer cancel()
	return s.native.ApplySites(applyCtx, webSites(items, ""), s.tenantBroken(items, subject))
}

// tenantBroken names the vhosts (by their directory name, as the config
// test reports them) of live, served sites whose tenant changed what the
// broker recorded in its home, other than the site of the account the
// change is about. OpenLiteSpeed warns for a vhost whose public_html is
// gone, and what it reports for these comes from their tenant's own files,
// so it must not decide another account's change. The config test already
// skips a vhost whose config the change did not rewrite; this also covers a
// render that rewrites every vhost, which happens once after an upgrade
// changes the rendered form, and would otherwise reject every change for
// every account until that tenant put its folder back. A suspended site
// names no tenant path, so it is judged as always, and so is the subject's
// own site.
func (s *store) tenantBroken(items []record, subject string) map[string]bool {
	byName := make(map[string]record, len(items))
	for _, r := range items {
		byName[siteName(r.Account.ID)] = r
	}
	out := map[string]bool{}
	for _, site := range webSites(items, subject) {
		r := byName[site.Name]
		if !site.Suspended && s.native.VerifySiteFiles(r) != nil {
			out[olsweb.NamePrefix+site.Name] = true
		}
	}
	return out
}

// undoState puts an account back into the state it had before the state
// change still pending on r, under the web operation's limit. The native
// call checks that the account is in the pending state first and in the
// earlier one afterwards.
func (s *store) undoState(ctx context.Context, r record) error {
	undoCtx, cancel := webContext(ctx)
	defer cancel()
	return s.native.SetState(undoCtx, targetRecord(r, r.Pending.Target), r.Account.State)
}
