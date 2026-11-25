package hostaccounts

import (
	"context"
	"errors"
	"regexp"
)

// AbandonCreateInput asks the broker to end an unfinished create by
// removing what it made, so every other account can change again. It is the
// operator's: the panel serves it to signed-in admins only, never to an API
// token.
type AbandonCreateInput struct {
	Reason string `json:"reason"`
}

// CreateRecoveryService is implemented by the client; the broker serves it
// from the store.
type CreateRecoveryService interface {
	AbandonCreate(ctx context.Context, id string, in AbandonCreateInput, actor string) (Account, error)
}

func validAbandon(in AbandonCreateInput, actor string) bool {
	return validText(in.Reason, 500) && validText(actor, 120)
}

// ErrAbandonRefused means the broker removed nothing: the account has no
// unfinished create, or what is there is not provably only what the create
// made. An *AbandonRefusedError says which.
var ErrAbandonRefused = errors.New("abandon create refused")

// AbandonRefusedError names why an abandon was refused, as one of the fixed
// reasons below.
type AbandonRefusedError struct {
	Reason string `json:"reason"`
}

func (e *AbandonRefusedError) Error() string        { return "abandon create refused: " + e.Reason }
func (e *AbandonRefusedError) Is(target error) bool { return target == ErrAbandonRefused }

// The reasons an abandon is refused.
const (
	// AbandonNoCreate: the account's pending operation is not an
	// unfinished create.
	AbandonNoCreate = "no_unfinished_create"
	// AbandonMarker: the ownership marker is missing, or is not the one the
	// journal recorded, while something the create would have made is there.
	AbandonMarker = "marker"
	// AbandonUser: a user has the account's name or UID but not the
	// journaled UID, GID, tag, home and shell.
	AbandonUser = "user"
	// AbandonGroup: a group has the account's name or GID but is not its
	// private group alone.
	AbandonGroup = "group"
	// AbandonHome: the home is not the one the journal recorded, nor one
	// useradd made for this user.
	AbandonHome = "home"
	// AbandonHomeNotEmpty: the home holds something other than the empty
	// public_html the broker made.
	AbandonHomeNotEmpty = "home_not_empty"
	// AbandonMailSpool: the mail spool is not a regular file of the
	// account's (or root's, as useradd makes it).
	AbandonMailSpool = "mail_spool"
	// AbandonProcesses: the user's processes kept running after the broker
	// ended them, so userdel refused it.
	AbandonProcesses = "processes"
)

var abandonReasonPattern = regexp.MustCompile(`^[a-z_]{1,32}$`)

func abandonRefused(reason string) error { return &AbandonRefusedError{Reason: reason} }
