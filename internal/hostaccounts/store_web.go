package hostaccounts

import (
	"context"
	"errors"
	"time"
)

// ErrWebRejected means the new OpenLiteSpeed config failed its test (or the
// homes filesystem does not enforce quotas) and the old files went back:
// the site is as it was.
var ErrWebRejected = errors.New("web configuration rejected")

// webApplyTimeout bounds the native work after the intent is journaled. It
// does not follow the caller's context, so a client that gives up does not
// leave a half-finished apply behind.
const webApplyTimeout = 2 * time.Minute

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
	if r.Account.Revision != in.ExpectedRevision || r.Account.State != "active" {
		return WebResult{}, ErrConflict
	}
	if r.Account.Revision == ^uint64(0) {
		return WebResult{}, ErrRecovery
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
	applyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), webApplyTimeout)
	defer cancel()
	switch e := s.native.ApplyWeb(applyCtx, r, previous, want, sites); {
	case errors.Is(e, ErrWebRejected):
		operation := *r.Pending
		r.Pending, r.WebNext = nil, WebState{}
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return WebResult{}, ErrRecovery
		}
		return WebResult{}, ErrWebRejected
	case e != nil:
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
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
