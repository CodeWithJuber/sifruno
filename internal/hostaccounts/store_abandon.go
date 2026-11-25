package hostaccounts

import (
	"context"
	"errors"
)

// abandonCreate ends a create that cannot be finished, so every other
// account can change again: the operator's way out of a create left
// recovery_required (README, Interrupted operations). Only an account whose
// pending operation is a create may be abandoned. The native step removes
// exactly what the create made, after checking all of it, on the
// operation's own limit; anything it cannot prove the create's own is
// refused with its reason and nothing removed. Then the slice drop-in goes
// and, in one transaction, the create's last row is journaled and its
// record removed. A run stopped half way leaves the create unfinished; the
// operator runs it again.
func (s *store) abandonCreate(ctx context.Context, id string, in AbandonCreateInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || !idPattern.MatchString(id) || !validAbandon(in, actor) {
		return Account{}, ErrInvalid
	}
	if ctx.Err() != nil || s.healthy() != nil {
		return Account{}, ErrUnavailable
	}
	if s.refreshed(ctx) != nil {
		return Account{}, ErrRecovery
	}
	items, err := s.records()
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
	if r.Pending == nil || r.Pending.Action != "create" || r.Account.State != "recovery_required" {
		err = abandonRefused(AbandonNoCreate)
		logRecovery("abandon_create", r, "check", err)
		return Account{}, err
	}
	removeCtx, cancel := webContext(ctx)
	defer cancel()
	err = s.native.AbandonCreate(removeCtx, r, func(owned ownership) error { r.Ownership = owned; return s.save(r) })
	switch {
	case errors.Is(err, ErrAbandonRefused):
		logRecovery("abandon_create", r, "check", err)
		var refused *AbandonRefusedError
		if !errors.As(err, &refused) {
			return Account{}, ErrRecovery
		}
		return Account{}, refused
	case errors.Is(err, errNothingRemoved):
		// Ending the user's processes failed or ran out of time before
		// userdel: nothing was removed.
		logRecovery("abandon_create", r, "remove user", err)
		return Account{}, ErrUnavailable
	case err != nil:
		logRecovery("abandon_create", r, "remove", err)
		return Account{}, ErrRecovery
	}
	s.removeLimits(ctx, r.Account.UID)
	if err = s.endAbandonedCreate(r, *r.Pending, actor, in.Reason); err != nil {
		return Account{}, ErrRecovery
	}
	s.removeUsageState(r.Account.ID)
	return r.Account, nil
}
