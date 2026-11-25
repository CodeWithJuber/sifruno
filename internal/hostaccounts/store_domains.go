package hostaccounts

import (
	"context"
	"errors"
	"time"
)

// siteDomains reads an account's recorded aliases and redirects.
func (s *store) siteDomains(ctx context.Context, id string) (SiteDomainsResult, error) {
	if snapshotReentry(ctx, s) {
		return SiteDomainsResult{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || !idPattern.MatchString(id) {
		return SiteDomainsResult{}, ErrInvalid
	}
	if s.healthy() != nil {
		return SiteDomainsResult{}, ErrUnavailable
	}
	if s.refreshed(ctx) != nil {
		return SiteDomainsResult{}, ErrRecovery
	}
	items, err := s.records()
	if err != nil {
		return SiteDomainsResult{}, err
	}
	for _, r := range items {
		if r.Account.ID != id {
			continue
		}
		d, ok := decodeSiteDomains(r.Domains)
		if !ok {
			return SiteDomainsResult{}, recovery("domains", r, "stored domains", ErrInvalid)
		}
		a := withWeb(r)
		if r.Pending != nil {
			a.State = "recovery_required"
		}
		return SiteDomainsResult{Account: a, Domains: d}, nil
	}
	return SiteDomainsResult{}, ErrNotFound
}

// setSiteDomains replaces a live site's aliases and redirects.
//
// Everything about the input is checked before anything is journaled: its
// form and the site's domains, with olsweb's own redirect rules (400),
// whether another account has one of the aliases (409 domain_taken), and
// the account's state and revision (409). The step that depends on the tenant's
// own files is the identity check, so a tenant who changed its folders gets
// a refusal for its own account only. After the intent is journaled with
// the new set, the site list is written, tested and reloaded under the web
// operation's own limit, or restored and journaled as rejected, which
// leaves the account unchanged.
func (s *store) setSiteDomains(ctx context.Context, id string, in SiteDomainsInput, actor string) (SiteDomainsResult, error) {
	if snapshotReentry(ctx, s) {
		return SiteDomainsResult{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Aliases == nil || in.Redirects == nil {
		return SiteDomainsResult{}, ErrInvalid
	}
	want := normalizeSiteDomains(SiteDomains{Aliases: in.Aliases, Redirects: in.Redirects})
	encoded := encodeSiteDomains(want)
	if !idPattern.MatchString(id) || in.ExpectedRevision == 0 || !validText(in.Reason, 500) || !validText(actor, 120) || !siteDomainsSized(encoded) {
		return SiteDomainsResult{}, ErrInvalid
	}
	if s.web == nil {
		return SiteDomainsResult{}, ErrUnavailable
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return SiteDomainsResult{}, err
	}
	index := -1
	for i, item := range items {
		if item.Account.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return SiteDomainsResult{}, ErrNotFound
	}
	r := items[index]
	if !validSiteDomains(r.Account.Domain, want) {
		return SiteDomainsResult{}, ErrInvalid
	}
	// A running WordPress install is left alone, as the web operation
	// leaves it; a suspended site keeps its suspended config.
	if r.Account.Revision != in.ExpectedRevision || r.Account.State != "active" || !r.Web.enabled() || s.installing[id] {
		return SiteDomainsResult{}, ErrConflict
	}
	for _, alias := range want.Aliases {
		if domainTaken(items, id, alias) {
			return SiteDomainsResult{}, ErrDomainTaken
		}
	}
	// An unchanged set changes nothing; SetWeb repairs a drifted config.
	if r.Domains == encoded {
		return SiteDomainsResult{Account: withWeb(r), Domains: want}, nil
	}
	if r.Account.Revision == ^uint64(0) {
		return SiteDomainsResult{}, recovery("domains", r, "revision at its limit", ErrConflict)
	}
	// Two history rows, with room left as historyRoom leaves it for the
	// operations a tenant can reach, so the result can always be journaled.
	if !historyRoom(r, operationRows, false) {
		return SiteDomainsResult{}, ErrConflict
	}
	if s.native.Verify(ctx, r) != nil {
		return SiteDomainsResult{}, ErrConflict
	}
	r.Pending = &pending{Action: "domains", Target: domainsDigest(encoded), Actor: actor, Reason: in.Reason}
	r.DomainsNext = encoded
	next := append([]record(nil), items...)
	next[index] = r
	// The set passed olsweb's own redirect checks above; a site list the
	// renderer still refuses ends rejected, as a failed config test does.
	sites := webSites(next, "")
	operationID, e := randomID()
	if e != nil {
		return SiteDomainsResult{}, e
	}
	r.Pending.OperationID = operationID
	before := r.Account
	after := r.Account
	after.Revision++
	intent := operationEvent{OperationID: operationID, Action: "domains", Status: "intended", Actor: actor, Reason: in.Reason, Before: &before, After: after}
	r, err = s.appendEvent(r, intent)
	if err != nil {
		return SiteDomainsResult{}, ErrRecovery
	}
	applyCtx, cancel := webContext(ctx)
	defer cancel()
	switch e := s.native.ApplySites(applyCtx, sites, s.tenantBroken(next, id)); {
	case errors.Is(e, ErrWebRejected):
		operation := *r.Pending
		r.Pending, r.DomainsNext = nil, ""
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return SiteDomainsResult{}, ErrRecovery
		}
		return SiteDomainsResult{}, ErrWebRejected
	case e != nil:
		s.recoveryRequired(r, *r.Pending, "site list", e)
		return SiteDomainsResult{}, ErrRecovery
	}
	r.Domains, r.DomainsNext = encoded, ""
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
	operation := *r.Pending
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return SiteDomainsResult{}, ErrRecovery
	}
	return SiteDomainsResult{Account: withWeb(r), Domains: want}, nil
}

// finishDomains finishes an interrupted domains operation at start: the new
// set was durable before the config changed, and installing the site list
// is idempotent. A config that now fails its test ends it rejected,
// unchanged; any other failure leaves it pending for the next start.
func (s *store) finishDomains(ctx context.Context, items []record, r record) error {
	operation := *r.Pending
	applyCtx, cancel := webContext(ctx)
	e := s.native.ApplySites(applyCtx, webSites(items, ""), s.tenantBroken(items, r.Account.ID))
	cancel()
	switch {
	case errors.Is(e, ErrWebRejected):
		r.Pending, r.DomainsNext = nil, ""
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return ErrRecovery
		}
		return nil
	case e != nil:
		logRecovery(operation.Action, r, "finish at start", e)
		return nil
	}
	r.Domains, r.DomainsNext = r.DomainsNext, ""
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = operation.Actor, operation.Reason
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
		return ErrRecovery
	}
	return nil
}
