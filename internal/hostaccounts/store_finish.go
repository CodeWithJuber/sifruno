package hostaccounts

import (
	"context"
	"errors"
)

// finishDelete ends a delete that no start could finish, so every other
// account can change again: the operator's way out of a delete left
// recovery_required (README, Interrupted operations). Only an account whose
// pending operation is a delete can be finished. If the delete had not yet
// taken the site out of the config, that comes first, and the record says
// the user's removal began. The native delete then runs as at a start,
// without checking the account first, on the operation's own limit:
// anything it cannot prove the account's is refused with its reason and
// nothing removed. Then the slice drop-in goes and, in one transaction, the
// delete's last row (status finished, the operator's actor and reason) is
// journaled and its record removed. A run stopped half way leaves the
// delete unfinished; the operator runs it again.
func (s *store) finishDelete(ctx context.Context, id string, in FinishDeleteInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || !idPattern.MatchString(id) || !validFinish(in, actor) {
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
	index := -1
	for i, item := range items {
		if item.Account.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return Account{}, ErrNotFound
	}
	r := items[index]
	if r.Pending == nil || r.Pending.Action != "delete" {
		err = deleteRefused(DeleteNoUnfinished)
		logRecovery("finish_delete", r, "check", err)
		return Account{}, err
	}
	operation := *r.Pending
	if !r.UserRemoval {
		// The site leaves the config before its user goes, as in delete.
		if r.Web.enabled() {
			if s.web == nil {
				return Account{}, ErrUnavailable
			}
			switch e := s.applySitesWithout(ctx, items, id); {
			case errors.Is(e, ErrWebRejected):
				logRecovery("finish_delete", r, "site list without the account", e)
				return Account{}, ErrWebRejected
			case e != nil:
				logRecovery("finish_delete", r, "site list without the account", e)
				return Account{}, ErrUnavailable
			}
		}
		r.UserRemoval = true
		if s.save(r) != nil {
			return Account{}, ErrRecovery
		}
	}
	removeCtx, cancel := webContext(ctx)
	defer cancel()
	err = s.native.Delete(removeCtx, r, s.homeMoved(&r))
	var refused *DeleteRefusedError
	switch {
	case errors.As(err, &refused):
		logRecovery("finish_delete", r, "check", err)
		return Account{}, refused
	case errors.Is(err, errAccountBusy):
		err = deleteRefused(DeleteProcesses)
		logRecovery("finish_delete", r, "remove user", err)
		return Account{}, err
	case errors.Is(err, errNothingRemoved):
		// Ending the user's processes failed or ran out of time before
		// userdel: nothing was removed.
		logRecovery("finish_delete", r, "remove user", err)
		return Account{}, ErrUnavailable
	case err != nil:
		logRecovery("finish_delete", r, "remove", err)
		return Account{}, ErrRecovery
	}
	s.removeLimits(ctx, r.Account.UID)
	s.removeSiteCache(ctx, r.Account.ID)
	s.removeSiteRealms(ctx, r.Account.ID)
	if s.endDelete(r, operation, finishedStatus, actor, in.Reason) != nil {
		return Account{}, ErrRecovery
	}
	s.removeUsageState(r.Account.ID)
	s.wakeTrash()
	return r.Account, nil
}
