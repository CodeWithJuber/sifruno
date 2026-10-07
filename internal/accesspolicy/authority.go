package accesspolicy

import (
	"errors"
	"sync"
)

var (
	ErrConflict  = errors.New("access policy revision conflict")
	ErrExhausted = errors.New("access policy revision exhausted")
)

// Revision is an opaque, comparable token bound to one authority. Its zero
// value is invalid. It is neither an identity nor an authentication credential.
type Revision struct {
	owner *authorityState
	value uint64
}

// Authority synchronizes policy replacement and individual admission checks.
// Copies share the same authority. Nil and zero authorities deny admission.
// A successful check does not reserve permission for subsequent work: replacing
// a policy cannot cancel or synchronize effects performed after the check.
type Authority struct{ state *authorityState }

type authorityState struct {
	mu       sync.RWMutex
	policy   *Policy
	revision uint64
}

// NewAuthority validates and copies a trusted policy, starting at revision one.
func NewAuthority(p *Policy) (*Authority, error) {
	copy, err := copyPolicy(p)
	if err != nil {
		return nil, err
	}
	return &Authority{state: &authorityState{policy: copy, revision: 1}}, nil
}

// Revision captures the current token, or zero for an uninitialized authority.
func (a *Authority) Revision() Revision {
	if a == nil || a.state == nil {
		return Revision{}
	}
	s := a.state
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Revision{owner: s, value: s.revision}
}

// Replace installs a complete trusted snapshot only if expected is current.
// Failure returns a zero token and leaves the current policy and revision intact.
// Even replacing with identical bindings advances the token; it never wraps.
func (a *Authority) Replace(expected Revision, next *Policy) (Revision, error) {
	if a == nil || a.state == nil {
		return Revision{}, ErrInvalid
	}
	s := a.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected.owner != s || expected.value == 0 || expected.value != s.revision {
		return Revision{}, ErrConflict
	}
	if s.revision == ^uint64(0) {
		return Revision{}, ErrExhausted
	}
	copy, err := copyPolicy(next)
	if err != nil {
		return Revision{}, err
	}
	s.policy = copy
	s.revision++
	return Revision{owner: s, value: s.revision}, nil
}

// AuthorizeAt checks freshness and permission together. The caller must still
// establish authenticated identity independently; see Policy.Authorize. No
// callback or execution lock is provided, and no policy snapshot escapes.
func (a *Authority) AuthorizeAt(expected Revision, actor ActorID, action Action, resource Resource) bool {
	if a == nil || a.state == nil {
		return false
	}
	s := a.state
	s.mu.RLock()
	defer s.mu.RUnlock()
	return expected.owner == s && expected.value != 0 && expected.value == s.revision && s.policy.Authorize(actor, action, resource)
}

func copyPolicy(p *Policy) (*Policy, error) {
	if p == nil || len(p.actors) == 0 || len(p.actors) > MaxActors || len(p.accounts) > MaxAccounts {
		return nil, ErrInvalid
	}
	actors := make([]ActorBinding, 0, len(p.actors))
	accounts := make([]AccountBinding, 0, len(p.accounts))
	for key, binding := range p.actors {
		if key != binding.Actor {
			return nil, ErrInvalid
		}
		actors = append(actors, binding)
	}
	for account, owner := range p.accounts {
		accounts = append(accounts, AccountBinding{Account: account, Owner: owner})
	}
	return NewPolicy(actors, accounts)
}
