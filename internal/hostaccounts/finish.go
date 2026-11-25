package hostaccounts

import (
	"context"
	"errors"
)

// FinishDeleteInput asks the broker to finish a delete that no start could
// finish, so every other account can change again. It is the operator's:
// the panel serves it to signed-in admins only, never to an API token.
type FinishDeleteInput struct {
	Reason string `json:"reason"`
}

// DeleteRecoveryService is implemented by the client; the broker serves it
// from the store.
type DeleteRecoveryService interface {
	FinishDelete(ctx context.Context, id string, in FinishDeleteInput, actor string) (Account, error)
}

func validFinish(in FinishDeleteInput, actor string) bool {
	return validText(in.Reason, 500) && validText(actor, 120)
}

// ErrDeleteRefused means a delete removed nothing: the account has no
// unfinished delete, or what is there is not provably the account's. A
// *DeleteRefusedError says which.
var ErrDeleteRefused = errors.New("delete refused")

// DeleteRefusedError names why a delete, or its finish, removed nothing, as
// one of the fixed reasons below.
type DeleteRefusedError struct {
	Reason string `json:"reason"`
}

func (e *DeleteRefusedError) Error() string        { return "delete refused: " + e.Reason }
func (e *DeleteRefusedError) Is(target error) bool { return target == ErrDeleteRefused }

// The reasons a delete is refused. Each is checked before anything is
// removed.
const (
	// DeleteNoUnfinished: the account's pending operation is not a delete.
	DeleteNoUnfinished = "no_unfinished_delete"
	// DeleteMarker: the ownership marker is not the recorded one, the
	// markers folder is not the broker's, or the marker is missing while a
	// user or group of the account is there.
	DeleteMarker = "marker"
	// DeleteUser: a user has the account's name or UID but not the
	// journaled UID, GID, tag, home and shell.
	DeleteUser = "user"
	// DeleteGroup: a group has the account's name or GID but is not its
	// private group alone.
	DeleteGroup = "group"
	// DeleteHome: the home is not the recorded directory of the account's.
	DeleteHome = "home"
	// DeleteTrash: the trash folder is not the broker's own (a link,
	// another owner or mode, another filesystem).
	DeleteTrash = "trash"
	// DeleteProcesses: the user's processes kept running after the broker
	// ended them, so userdel refused it.
	DeleteProcesses = "processes"
)

func deleteRefused(reason string) error { return &DeleteRefusedError{Reason: reason} }
