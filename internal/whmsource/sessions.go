package whmsource

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
)

// Sessions holds each WHM-connected migration's client, with root's WHM
// login, in this panel's memory only: from the connection until the move
// ends, is stopped, or its 24 hours are over. Nothing is written to disk; a
// panel restart forgets them, and such a migration must be connected again.
// A nil *Sessions holds none.
type Sessions struct {
	mu sync.Mutex
	m  map[string]*session
}

type session struct {
	client  *Client
	keyLine string
	expires time.Time
}

// NewSessions makes an empty store.
func NewSessions() *Sessions { return &Sessions{m: map[string]*session{}} }

// errNoLogin means this panel holds no WHM login for the migration.
var errNoLogin = &hostaccounts.MigrationError{Step: "whm_session", Detail: "This panel holds no WHM login for that connection."}

// Put keeps the client for the migration id, whose broker key line it
// authorized, until expires.
func (s *Sessions) Put(id string, c *Client, keyLine string, expires time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	s.m[id] = &session{client: c, keyLine: keyLine, expires: expires}
}

// sweep drops sessions past their day. Callers hold mu.
func (s *Sessions) sweep() {
	now := time.Now()
	for id, v := range s.m {
		if !now.Before(v.expires) {
			delete(s.m, id)
		}
	}
}

func (s *Sessions) get(id string) (*session, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	v, ok := s.m[id]
	return v, ok
}

// Has reports whether the panel holds a WHM login for the migration.
func (s *Sessions) Has(id string) bool {
	_, ok := s.get(id)
	return ok
}

// Forget drops the migration's login.
func (s *Sessions) Forget(id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// Accounts lists the old server's accounts through WHM.
func (s *Sessions) Accounts(ctx context.Context, id string) ([]cpsource.Account, error) {
	v, ok := s.get(id)
	if !ok {
		return nil, errNoLogin
	}
	return v.client.Accounts(ctx)
}

// Answers fetches, through WHM, what the copy of user asks of cPanel.
func (s *Sessions) Answers(ctx context.Context, id, user string) (*hostaccounts.CPanelAnswers, error) {
	v, ok := s.get(id)
	if !ok {
		return nil, errNoLogin
	}
	return v.client.Answers(ctx, user)
}

// Finisher is the broker's end of a migration.
type Finisher interface {
	FinishMigration(context.Context, string, hostaccounts.MigrationFinishInput, string) (hostaccounts.MigrationFinishResult, error)
	ClearStaleMigrationKey(context.Context, string, hostaccounts.MigrationFinishInput, string) error
}

// Finish ends a migration's key on the old server (D-0005, step 5). The
// broker removes the line over SSH and proves it with a sign-in that is
// then refused, and deletes its private key either way. For a WHM
// migration, WHM's API then deletes the key's file; when SSH did not
// remove the line, WHM's API removes it, and only a WHM that no longer
// lists it authorized for root counts as gone; the broker's stale line is
// then cleared. The answer says plainly whether the key is gone. The login
// is forgotten once the broker has answered.
func (s *Sessions) Finish(ctx context.Context, id string, b Finisher, in hostaccounts.MigrationFinishInput, actor string) (hostaccounts.MigrationFinishResult, error) {
	res, err := b.FinishMigration(ctx, id, in, actor)
	v, ok := s.get(id)
	if err != nil || !ok {
		return res, err
	}
	defer s.Forget(id)
	removed, werr := v.client.RemoveKey(ctx, v.keyLine, id)
	file := "/root/.ssh/" + keyName(id) + ".pub"
	switch {
	case res.RemovedFromSource && removed:
		res.Detail = strings.TrimSpace(res.Detail + " WHM's API also deleted the key's file " + file + ".")
	case res.RemovedFromSource:
		res.Detail = strings.TrimSpace(res.Detail + " The key's public file " + file + " may remain there; without the line it opens nothing.")
	case removed:
		if cerr := b.ClearStaleMigrationKey(ctx, id, hostaccounts.MigrationFinishInput{Reason: "WHM's API removed the key line"}, actor); cerr != nil && !errors.Is(cerr, hostaccounts.ErrNotFound) {
			res.Detail = "The key is gone from the old server: WHM's API removed it, and WHM no longer lists it for root. This panel could not take it off its list of lines to remove, so mark it removed there. Removing it over SSH had failed: " + res.Detail
			res.RemovedFromSource = true
			return res, nil
		}
		res.RemovedFromSource = true
		res.Detail = "The key is gone from the old server: WHM's API removed it, and WHM no longer lists it for root. Removing it over SSH had failed: " + res.Detail
	default:
		why := "WHM did not answer"
		var failed *hostaccounts.MigrationError
		if errors.As(werr, &failed) {
			why = failed.Detail
			if failed.Output != "" {
				why += " (" + failed.Output + ")"
			}
		}
		res.Detail = strings.TrimSpace(res.Detail + " Removing it through WHM's API failed too: " + why + " The key may still be there.")
	}
	return res, nil
}
