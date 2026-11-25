package hostaccounts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

// The broker says why an account needs recovery, in one line on its
// standard error, which journald keeps for the broker's unit: every
// operation that journals recovery_required, and every ErrRecovery the
// broker answers, logs the operation, the account's ID and username, the
// step and the class of the error. A line names no path in a tenant's home,
// no file content, key or password: a step is a fixed word, an account ID
// and a username are validated, and an error class is a fixed word, a fixed
// program's exit status or an errno's name.
var (
	recoveryLogMu sync.Mutex
	recoveryLog   io.Writer = os.Stderr
)

// errHoldsEveryChange is the cause logged for a change refused because an
// account's operation is unfinished.
var errHoldsEveryChange = errors.New("an unfinished operation holds up every change")

// logRecovery writes the line for operation on r's account; r may be empty
// when the broker's state as a whole is what failed. A step the cause names
// (atStep) follows the caller's.
func logRecovery(operation string, r record, step string, cause error) {
	var inner *stepError
	if errors.As(cause, &inner) {
		if step == "" {
			step = inner.step
		} else {
			step += " / " + inner.step
		}
	}
	account, user := r.Account.ID, r.Account.Username
	if account == "" {
		account = "-"
	}
	if user == "" {
		user = "-"
	}
	recoveryLogMu.Lock()
	defer recoveryLogMu.Unlock()
	fmt.Fprintf(recoveryLog, "sifruno broker: recovery: operation=%s account=%s user=%s step=%q error=%q\n", operation, account, user, step, errorClass(cause))
}

// recovery logs why an operation answers ErrRecovery, and answers it.
func recovery(operation string, r record, step string, cause error) error {
	logRecovery(operation, r, step, cause)
	return ErrRecovery
}

// recoveryRequired journals that r's pending operation p needs recovery,
// and logs why. A journal row that cannot be written is logged by
// appendEvent; the caller answers ErrRecovery either way.
func (s *store) recoveryRequired(r record, p pending, step string, cause error) {
	logRecovery(p.Action, r, step, cause)
	_, _ = s.resultEvent(r, p, "recovery_required")
}

// refreshed is refresh for an operation that answers ErrRecovery whenever
// refresh fails. What refresh refused it logged where it refused; a refresh
// that could not finish its checks (the time ran out, or a check's program
// failed) is logged here.
func (s *store) refreshed(ctx context.Context) error {
	e := s.refresh(ctx, false)
	if e == nil {
		return nil
	}
	if !errors.Is(e, ErrRecovery) {
		logRecovery("check", record{}, "check every account", e)
	}
	return ErrRecovery
}

// errorClass is the fixed description of err the recovery log gives. It
// never prints an error's own text, which may name a tenant's path.
func errorClass(err error) string {
	var command *commandError
	var errno syscall.Errno
	switch {
	case err == nil:
		return "none"
	case errors.As(err, &command):
		return command.class()
	case errors.Is(err, errHoldsEveryChange):
		return errHoldsEveryChange.Error()
	case errors.Is(err, errAccountBusy):
		return "the account's processes kept running"
	case errors.Is(err, errNothingRemoved):
		return "stopped before anything was removed"
	case errors.Is(err, ErrWebRejected):
		return "the web server's config test failed"
	case errors.Is(err, errLimitsRejected):
		return "the limits could not be applied"
	case errors.Is(err, ErrRecovery):
		return "differs from what the broker recorded"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrNotFound):
		return "not found"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.As(err, &errno):
		return errno.Error()
	default:
		return "unexpected error"
	}
}

// stepError names the step of a native operation that failed, for the
// recovery log. errors.Is and errors.As see the error it wraps.
type stepError struct {
	step string
	err  error
}

func (e *stepError) Error() string { return e.step + ": " + e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

// atStep names err's step, unless a step inside it already does; nil stays
// nil.
func atStep(step string, err error) error {
	var inner *stepError
	if err == nil || errors.As(err, &inner) {
		return err
	}
	return &stepError{step, err}
}

// commandError is a fixed utility that did not end with status 0. It is an
// unavailable answer: errors.Is(err, ErrUnavailable) holds.
type commandError struct {
	program string // the fixed binary's base name
	status  int    // its exit status; -1 when it did not end by itself
	stopped bool   // its time limit or its operation's context ended it
}

func (e *commandError) Error() string        { return e.class() }
func (e *commandError) Is(target error) bool { return target == ErrUnavailable }
func (e *commandError) class() string {
	switch {
	case e.stopped:
		return e.program + " was stopped at its time limit"
	case e.status >= 0:
		return fmt.Sprintf("%s exited with status %d", e.program, e.status)
	default:
		return e.program + " did not run"
	}
}
