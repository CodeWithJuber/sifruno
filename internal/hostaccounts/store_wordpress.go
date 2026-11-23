package hostaccounts

import "context"

// installWordPress installs WordPress into an account's live site with
// WP-CLI, as the account's user. The checks run under the broker lock; the
// install does not, so a slow download holds no other account. The account
// is marked busy meanwhile. Nothing is journaled: the install changes only
// the tenant's own files, with the tenant's own rights, and the panel's job
// log records who asked for it.
func (s *store) installWordPress(ctx context.Context, id string, in WordPressInput, actor string) (WordPressResult, error) {
	if snapshotReentry(ctx, s) {
		return WordPressResult{}, ErrConflict
	}
	r, err := s.beginInstall(ctx, id, in, actor)
	if err != nil {
		return WordPressResult{}, err
	}
	defer s.endInstall(id)
	installCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wordpressTimeout)
	defer cancel()
	return s.native.InstallWordPress(installCtx, r, in)
}

func (s *store) beginInstall(ctx context.Context, id string, in WordPressInput, actor string) (record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) || !validText(actor, 120) {
		return record{}, ErrInvalid
	}
	if s.web == nil {
		return record{}, ErrUnavailable
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return record{}, err
	}
	for _, r := range items {
		if r.Account.ID != id {
			continue
		}
		if !validWordPress(in, r.Account.Username) {
			return record{}, ErrInvalid
		}
		// The site must be live first: the install runs the site's PHP.
		if r.Account.Revision != in.ExpectedRevision || r.Account.State != "active" || !r.Web.enabled() || s.installing[id] {
			return record{}, ErrConflict
		}
		if s.native.Verify(ctx, r) != nil {
			return record{}, ErrConflict
		}
		if s.installing == nil {
			s.installing = map[string]bool{}
		}
		s.installing[id] = true
		return r, nil
	}
	return record{}, ErrNotFound
}

func (s *store) endInstall(id string) {
	s.mu.Lock()
	delete(s.installing, id)
	s.mu.Unlock()
}
