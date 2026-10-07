// Package accesspolicy defines an immutable authorization policy for native
// hosting accounts. It does not authenticate callers or change existing APIs.
package accesspolicy

import "errors"

const (
	MaxActors   = 256
	MaxAccounts = 100 // Matches the native hostaccounts capacity.
)

var ErrInvalid = errors.New("invalid access policy input")

// ActorID is an opaque canonical identifier, not an authentication credential.
// Parsing a request-supplied ID never establishes the caller's identity.
type ActorID struct{ value string }
type AccountID struct{ value string }

func ParseActorID(s string) (ActorID, error) {
	if len(s) < 1 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return ActorID{}, ErrInvalid
	}
	for i := range s {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return ActorID{}, ErrInvalid
		}
	}
	return ActorID{value: s}, nil
}

// ParseAccountID preserves the native hostaccounts ID format without trimming,
// case folding, alias expansion, or interpreting usernames as account IDs.
func ParseAccountID(s string) (AccountID, error) {
	if len(s) != 32 {
		return AccountID{}, ErrInvalid
	}
	for i := range s {
		c := s[i]
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return AccountID{}, ErrInvalid
		}
	}
	return AccountID{value: s}, nil
}

func (id ActorID) String() string   { return id.value }
func (id AccountID) String() string { return id.value }

type Role uint8

const (
	ServerAdmin Role = iota + 1
	Reseller
	AccountUser
)

// ActorBinding must come from a trusted identity/assignment authority. Assigned
// is required only for AccountUser and must be empty for other roles.
type ActorBinding struct {
	Actor    ActorID
	Role     Role
	Assigned AccountID
}

// AccountBinding must come from a trusted account ownership authority, never a
// request body. Owner must identify a registered ServerAdmin or Reseller.
type AccountBinding struct {
	Account AccountID
	Owner   ActorID
}

type Action uint8

const (
	ReadCapability Action = iota + 1
	ListAccounts
	CreateAccount
	ReadAccount
	SetAccountState
	ManagePolicy
)

type Resource struct {
	kind    uint8
	account AccountID
}

func ServerResource() Resource              { return Resource{kind: 1} }
func AccountResource(id AccountID) Resource { return Resource{kind: 2, account: id} }

// Policy is immutable after construction and supports concurrent reads. Its
// zero value and nil pointer deny every request.
type Policy struct {
	actors   map[ActorID]ActorBinding
	accounts map[AccountID]ActorID
}

// NewPolicy copies a complete, bounded trusted snapshot. Duplicate identities,
// even identical duplicates, and incomplete references invalidate the whole
// snapshot. Errors return nil; there is no partially usable policy.
func NewPolicy(actors []ActorBinding, accounts []AccountBinding) (*Policy, error) {
	if len(actors) == 0 || len(actors) > MaxActors || len(accounts) > MaxAccounts {
		return nil, ErrInvalid
	}
	p := &Policy{actors: make(map[ActorID]ActorBinding, len(actors)), accounts: make(map[AccountID]ActorID, len(accounts))}
	for _, a := range actors {
		if _, err := ParseActorID(a.Actor.value); err != nil {
			return nil, ErrInvalid
		}
		if _, exists := p.actors[a.Actor]; exists {
			return nil, ErrInvalid
		}
		switch a.Role {
		case ServerAdmin, Reseller:
			if a.Assigned != (AccountID{}) {
				return nil, ErrInvalid
			}
		case AccountUser:
			if _, err := ParseAccountID(a.Assigned.value); err != nil {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
		p.actors[a.Actor] = a
	}
	for _, a := range accounts {
		if _, err := ParseAccountID(a.Account.value); err != nil {
			return nil, ErrInvalid
		}
		if _, exists := p.accounts[a.Account]; exists {
			return nil, ErrInvalid
		}
		owner, exists := p.actors[a.Owner]
		if !exists || (owner.Role != ServerAdmin && owner.Role != Reseller) {
			return nil, ErrInvalid
		}
		p.accounts[a.Account] = a.Owner
	}
	for _, a := range p.actors {
		if a.Role == AccountUser {
			if _, exists := p.accounts[a.Assigned]; !exists {
				return nil, ErrInvalid
			}
		}
	}
	return p, nil
}

// Authorize requires an actor ID obtained from independently verified
// authentication. The policy resolves its role and assignments exclusively
// from its trusted snapshot. It cannot detect a caller that lies about which
// identity was authenticated. Never pass a body/header/route-claimed actor,
// cookie content, operator key, or existing audit actor string as identity.
//
// This method performs bounded map lookups, allocates no memory, and has no
// side effects. Authorization must be rechecked with current trusted ownership
// and authentication at the protected operation's admission boundary.
func (p *Policy) Authorize(actor ActorID, action Action, resource Resource) bool {
	if p == nil {
		return false
	}
	a, exists := p.actors[actor]
	if !exists {
		return false
	}
	switch action {
	case ReadCapability, ListAccounts, CreateAccount, ManagePolicy:
		return resource == ServerResource() && a.Role == ServerAdmin
	case ReadAccount, SetAccountState:
		if resource.kind != 2 {
			return false
		}
		owner, admitted := p.accounts[resource.account]
		if !admitted {
			return false
		}
		switch a.Role {
		case ServerAdmin:
			return true
		case Reseller:
			return owner == actor
		case AccountUser:
			return action == ReadAccount && a.Assigned == resource.account
		}
	}
	return false
}
