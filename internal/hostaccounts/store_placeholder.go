package hostaccounts

import "context"

// installPlaceholder puts the placeholder page into an account's live site,
// as the account's user, if its public_html is empty. It runs like the
// WordPress install: checked under the broker lock, run outside it with the
// account marked busy, on its own time limit, and nothing is journaled,
// because it changes only the tenant's own folder with the tenant's rights.
func (s *store) installPlaceholder(ctx context.Context, id string, in PlaceholderInput, actor string) (PlaceholderResult, error) {
	if snapshotReentry(ctx, s) {
		return PlaceholderResult{}, ErrConflict
	}
	r, err := s.beginSiteRun(ctx, id, in.ExpectedRevision, actor, func(record) bool { return true })
	if err != nil {
		return PlaceholderResult{}, err
	}
	defer s.endInstall(id)
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), placeholderTimeout)
	defer cancel()
	written, err := s.native.InstallPlaceholder(runCtx, r)
	if err != nil {
		return PlaceholderResult{}, err
	}
	return PlaceholderResult{Written: written}, nil
}
