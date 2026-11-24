package wizard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
)

// ErrNotFound is a delete of a site the wizard does not list.
var ErrNotFound = errors.New("website not found")

const (
	// A delete rewrites the web server's config (the broker allows 4 minutes)
	// and then removes the user and home on a second limit of 4.
	removeLimit  = 10 * time.Minute
	removeReason = "Deleted from the website's page"
)

// Removal is a finished site delete. Removed names what went, in order. Kept
// names a database or database user that has the site's name but is not
// registered to it, which the delete therefore left alone.
type Removal struct {
	Domain   string
	Username string
	Removed  []string
	Kept     []string
}

// RemoveFailure is a site delete that was refused or stopped. Reason is
// ErrInvalid, ErrConflict, ErrNotFound or ErrUnavailable. Why is plain
// English for the person and ends with what was removed and what is still on
// the server; Technical is the error text for "Technical details".
type RemoveFailure struct {
	Reason    error
	Why       string
	Technical string
	Removed   []string
	Left      []string
}

func (e *RemoveFailure) Error() string { return e.Why }
func (e *RemoveFailure) Unwrap() error { return e.Reason }

// removal is one thing a site delete removes. failed explains an error from
// remove; unsure means the panel cannot tell whether the thing went.
type removal struct {
	label  string
	remove func(context.Context) error
	failed func(error) (why string, unsure bool, reason error)
}

// RemoveSite deletes a site the wizard made: its database user and database,
// if the registry lists them for the site's account, then the hosting account
// with its files and its site on the web server, each through dbhost or one of
// the broker's typed operations. Then the site's job is marked, so the site
// leaves Websites.
//
// The typed domain must be the site's, and revision the account's current
// one. Everything that can be checked is checked before the first removal,
// because a removed database does not come back. The delete then runs to its
// end on its own limit, detached from ctx: closing the page does not stop it
// half-way. It stops at the first removal that fails, and the failure says
// what went and what is left; asking again carries on from there. One delete
// runs at a time.
func (r *Runner) RemoveSite(ctx context.Context, accountID, confirmDomain string, revision uint64, actor string) (Removal, error) {
	nothing := func(reason error, why string, err error) (Removal, error) {
		f := &RemoveFailure{Reason: reason, Why: why + " Nothing was removed."}
		if err != nil {
			f.Technical = scrub(err.Error())
		}
		return Removal{}, f
	}
	if !validText(actor, 120) {
		return nothing(ErrInvalid, "The signed-in admin could not be identified.", nil)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), removeLimit)
	defer cancel()
	r.removing.Lock()
	defer r.removing.Unlock()

	if !slices.ContainsFunc(r.Succeeded(), func(j Job) bool { return j.Result.AccountID == accountID }) {
		return nothing(ErrNotFound, "That website was not found. It may have been removed already, or it was not made with New website.", nil)
	}
	accounts, err := r.accounts.List(ctx)
	if err != nil {
		return nothing(ErrUnavailable, "The account service did not answer.", err)
	}
	i := slices.IndexFunc(accounts, func(a hostaccounts.Account) bool { return a.ID == accountID })
	if i < 0 {
		return nothing(ErrNotFound, "That website's hosting account is no longer on this server.", nil)
	}
	a := accounts[i]
	if confirmDomain != a.Domain {
		return nothing(ErrInvalid, "The domain you typed is not this website's domain, "+a.Domain+".", nil)
	}
	if a.Revision != revision {
		return nothing(ErrConflict, "This website changed after the page loaded it.", nil)
	}
	// The broker refuses every change while any account has an unfinished
	// one, and the list shows that account as needing recovery.
	if stuck := slices.IndexFunc(accounts, func(a hostaccounts.Account) bool { return a.State == "recovery_required" }); stuck >= 0 {
		return nothing(ErrUnavailable, "The account service has an unfinished change on the hosting account "+accounts[stuck].Username+" and refuses every other change until someone has checked it.", nil)
	}

	owner := a.Username
	name := dbhost.PrefixedName(owner, strings.TrimPrefix(dbSuffix, "_"))
	users, err := r.databases.AllUsers(ctx)
	if err != nil {
		return nothing(ErrUnavailable, "The panel could not read its list of database users.", err)
	}
	databases, err := r.databases.AllDatabases(ctx)
	if err != nil {
		return nothing(ErrUnavailable, "The panel could not read its list of databases.", err)
	}
	out := Removal{Domain: a.Domain, Username: owner}
	notDropped := func(what string) func(error) (string, bool, error) {
		return func(error) (string, bool, error) {
			return "The database server did not remove " + what + ".", false, ErrUnavailable
		}
	}
	var plan []removal
	// Only what the registry lists under this account's name for this
	// account: the wizard registered exactly that. Anything else with the
	// name is someone else's and stays.
	user, database := "the database user "+name, "the database "+name
	if slices.ContainsFunc(users, func(u dbhost.User) bool { return u.Name == name && u.Owner == owner }) {
		plan = append(plan, removal{user, func(ctx context.Context) error { return r.databases.DropUser(ctx, owner, name) }, notDropped(user)})
	} else if has, err := r.databases.ServerHas(ctx, "user", name); err == nil && has {
		out.Kept = append(out.Kept, user)
	}
	if slices.ContainsFunc(databases, func(d dbhost.Database) bool { return d.Name == name && d.Owner == owner }) {
		plan = append(plan, removal{database, func(ctx context.Context) error { return r.databases.DropDatabase(ctx, owner, name) }, notDropped(database)})
	} else if has, err := r.databases.ServerHas(ctx, "database", name); err == nil && has {
		out.Kept = append(out.Kept, database)
	}
	plan = append(plan, removal{"the hosting account " + owner + " with its files and its site on the web server", func(ctx context.Context) error {
		_, err := r.accounts.Delete(ctx, a.ID, hostaccounts.DeleteInput{ExpectedRevision: revision, Reason: removeReason}, actor)
		if errors.Is(err, hostaccounts.ErrNotFound) {
			return nil // already gone
		}
		return err
	}, accountNotDeleted})

	for i, step := range plan {
		err := step.remove(ctx)
		if err == nil {
			out.Removed = append(out.Removed, step.label)
			continue
		}
		f := &RemoveFailure{Removed: out.Removed, Technical: scrub(err.Error())}
		why, unsure, reason := step.failed(err)
		f.Reason = reason
		if len(f.Removed) == 0 {
			why += " Nothing was removed before that."
		} else {
			why += " Removed before that: " + strings.Join(f.Removed, ", ") + "."
		}
		rest := plan[i:]
		for _, left := range rest {
			f.Left = append(f.Left, left.label)
		}
		if unsure {
			why += " May still be on the server: " + step.label + "."
			rest = rest[1:]
		}
		if len(rest) > 0 {
			labels := make([]string, len(rest))
			for k, left := range rest {
				labels[k] = left.label
			}
			why += " Still on the server: " + strings.Join(labels, ", ") + "."
		}
		f.Why = why
		return Removal{}, f
	}
	// The site is gone whether or not this is saved: the broker no longer has
	// the account, so Websites does not list it. Memory is marked either way.
	if err := r.store.markRemoved(a.ID, timestamp(time.Now())); err != nil {
		fmt.Fprintf(logOutput, "website %s: marking its job as removed could not be saved: %v\n", a.Domain, err)
	}
	return out, nil
}

// accountNotDeleted explains the broker's answer to a delete that failed.
func accountNotDeleted(err error) (why string, unsure bool, reason error) {
	switch {
	case errors.Is(err, hostaccounts.ErrConflict):
		return "The hosting account changed or was busy, so the account service did not delete it.", false, ErrConflict
	case errors.Is(err, hostaccounts.ErrWebRejected):
		return "The web server's configuration test failed without this site, so the server kept its old configuration and the hosting account was not deleted. Ask whoever runs this server to check the web server.", false, ErrUnavailable
	case errors.Is(err, hostaccounts.ErrInvalid):
		return "The account service refused the delete as invalid.", false, ErrInvalid
	case errors.Is(err, hostaccounts.ErrRecovery):
		return "The account service stopped part-way through deleting the hosting account and needs a check before anything else changes.", true, ErrUnavailable
	default:
		return "The account service did not answer, so the panel cannot tell whether the hosting account was deleted.", true, ErrUnavailable
	}
}
