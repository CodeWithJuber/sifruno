package hostaccounts

import (
	"context"
	"errors"
	"time"
)

// adoptPublicHTML records the account's current public_html as its site
// folder. A tenant who renamed or replaced public_html, or changed the mode
// of its home or public_html, leaves the account with site_folder_changed:
// its web, certificate and WordPress changes are refused until the folder
// is back. When the old folder is gone, an operator adopts the new one.
//
// Checked before anything is journaled: the revision, no WordPress install
// running, the account's identity as only root can change it (VerifyAccount),
// and then, through handles that follow no link, that public_html is a
// directory the account owns on the home's filesystem. The native step sets
// the home and public_html to mode 0750 and, for a live site, grants the web
// server access to the new folder; both are idempotent and touch only the
// tenant's own directories. Then the intent (action adopt, the target naming
// the directory) and the result are journaled, and the revision goes up.
//
// An account with a conflict journaled by an earlier broker, which made one
// for these folder changes too, may be adopted while what root controls
// verifies again: that conflict ends reconciled, unchanged, before the adopt.
func (s *store) adoptPublicHTML(ctx context.Context, id string, in AdoptInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) || !validAdopt(in, actor) {
		return Account{}, ErrInvalid
	}
	items, err := s.adoptReady(ctx, id)
	if err != nil {
		return Account{}, err
	}
	var r record
	found := false
	for _, item := range items {
		if item.Account.ID == id {
			r, found = item, true
			break
		}
	}
	if !found {
		return Account{}, ErrNotFound
	}
	// A running WordPress install writes into public_html as the account.
	if r.Account.Revision != in.ExpectedRevision || s.installing[id] {
		return Account{}, ErrConflict
	}
	conflict := r.Pending != nil
	if !conflict && s.native.VerifySiteFiles(r) == nil {
		// Nothing to adopt: the recorded folder is in place.
		return withWeb(r), nil
	}
	// Room for the adopt's two rows, the conflict's end when there is one,
	// and a spare. An adopt is an operation a tenant can reach and stops
	// where historyRoom stops those; one that ends a conflict, which holds
	// up every account, may use the operator's room.
	room := uint64(operationRows)
	if conflict {
		room++
	}
	if r.Account.Revision == ^uint64(0) || !historyRoom(r, room, conflict) {
		return Account{}, ErrConflict
	}
	// A live site's folder gets the web server's access, which needs the web
	// operation.
	if r.Web.enabled() && s.web == nil {
		return Account{}, ErrUnavailable
	}
	current := r
	current.Pending = nil
	if e := s.native.VerifyAccount(ctx, current); e != nil {
		return Account{}, recovery("adopt", r, "check of what only root changes", e)
	}
	public, err := s.native.AdoptPublicHTML(ctx, r)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return Account{}, ErrConflict
		}
		return Account{}, ErrUnavailable
	}
	next := r
	next.Ownership.Public = public
	// A folder that changed again before the grant is the tenant's doing, a
	// conflict; an ACL the host could not write is unavailable.
	if r.Web.enabled() {
		switch err := s.native.GrantWebAccess(ctx, next); {
		case errors.Is(err, ErrUnavailable):
			return Account{}, ErrUnavailable
		case err != nil:
			return Account{}, ErrConflict
		}
	}

	if conflict {
		operation := *r.Pending
		r.Pending = nil
		if r, err = s.resultEvent(r, operation, "reconciled"); err != nil {
			return Account{}, ErrRecovery
		}
	}
	operationID, err := randomID()
	if err != nil {
		return Account{}, err
	}
	r.Pending = &pending{Action: "adopt", Target: publicTarget(public), Actor: actor, Reason: in.Reason, OperationID: operationID}
	before := r.Account
	after := r.Account
	after.Revision++
	intent := operationEvent{OperationID: operationID, Action: "adopt", Status: "intended", Actor: actor, Reason: in.Reason, Before: &before, After: after}
	if r, err = s.appendEvent(r, intent); err != nil {
		return Account{}, ErrRecovery
	}
	r.Ownership.Public = public
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
	operation := *r.Pending
	r.Pending = nil
	if _, err := s.resultEvent(r, operation, "succeeded"); err != nil {
		return Account{}, ErrRecovery
	}
	a := withWeb(r)
	a.SiteFolderChanged = s.native.VerifySiteFiles(r) != nil
	return a, nil
}

// adoptReady is mutationReady, except that a conflict of the account being
// adopted does not refuse it; adoptPublicHTML resolves that conflict itself.
func (s *store) adoptReady(ctx context.Context, id string) ([]record, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil || s.healthy() != nil {
		return nil, ErrUnavailable
	}
	if s.refreshed(ctx) != nil {
		return nil, ErrRecovery
	}
	items, err := s.records()
	if err != nil {
		return nil, err
	}
	for _, r := range items {
		if r.Pending != nil && !(r.Account.ID == id && r.Pending.Action == "conflict") {
			return nil, recovery(r.Pending.Action, r, "unfinished, so this change is refused", errHoldsEveryChange)
		}
	}
	return s.compactHistories(items), nil
}

// finishAdopt completes an adopt interrupted between its intent and its
// result: metadata only, from the directory the intent named.
func (s *store) finishAdopt(r record) error {
	public, ok := parsePublicTarget(r.Pending.Target)
	if !ok {
		return recovery(r.Pending.Action, r, "finish at start: the journaled folder", ErrInvalid)
	}
	operation := *r.Pending
	r.Ownership.Public = public
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = operation.Actor, operation.Reason
	r.Pending = nil
	if _, err := s.resultEvent(r, operation, "reconciled"); err != nil {
		return ErrRecovery
	}
	return nil
}
