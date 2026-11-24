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
	// and then removes the user and home on a second limit of 4. The suspend
	// and second ask after a busy refusal share what is left of it.
	removeLimit   = 10 * time.Minute
	removeReason  = "Deleted from the website's page"
	suspendReason = "Suspended to delete it from the website's page: its processes kept running"
)

// Removal is a finished site delete. Removed names what went, in order. Kept
// names a database or database user that has the site's name but is not
// registered to it, which the delete therefore left alone. SuspendedFirst:
// the account service refused the delete because the site's processes kept
// running, so the panel suspended the site and asked again.
type Removal struct {
	Domain         string
	Username       string
	Removed        []string
	Kept           []string
	SuspendedFirst bool
}

// RemoveFailure is a site delete that was refused or stopped. Reason is
// ErrInvalid, ErrConflict, ErrNotFound or ErrUnavailable. Why is plain
// English for the person and ends with what was removed and what is still on
// the server, or, for a delete refused because the account's processes kept
// running, says nothing was removed and what to do next; Technical is the
// error text for "Technical details".
type RemoveFailure struct {
	Reason    error
	Why       string
	Technical string
	Removed   []string
	Left      []string
}

func (e *RemoveFailure) Error() string { return e.Why }
func (e *RemoveFailure) Unwrap() error { return e.Reason }

// What a delete says when the account service refused it because the
// account's processes kept running.
var (
	busyNothingRemoved = fmt.Sprintf("The account still had running processes after %d attempts, so nothing was removed.", hostaccounts.DeleteAttempts)
	busySuspendFirst   = "Suspend the site first (that stops its processes and keeps the site off), then delete it again."
)

// busyRefusal is the account step's answer when the account service refused
// the delete because the account's processes kept running. Nothing was
// removed, so why is the whole message: what happened, why, what next.
type busyRefusal struct {
	why string
	err error
}

func (e *busyRefusal) Error() string { return e.err.Error() }
func (e *busyRefusal) Unwrap() error { return e.err }

// removal is one thing a site delete removes. failed explains an error from
// remove; unsure means the panel cannot tell whether the thing went. account
// marks the hosting account's removal.
type removal struct {
	label   string
	remove  func(context.Context) error
	failed  func(error) (why string, unsure bool, reason error)
	account bool
}

// RemoveSite deletes a site the wizard made: the hosting account with its
// files and its site on the web server, through the broker's typed delete,
// then its database user and database, if the registry lists them for the
// site's account, through dbhost. Then the site's job is marked, so the site
// leaves Websites.
//
// The account goes first: while the broker can still refuse it (a changed
// revision, a running install, a config that fails its test), the site is
// whole and its database is still there. Before the broker is asked, the
// site's job records the revision it is asked at. If the account is gone
// and a database step then fails, the job still names the site: Websites
// lists it as partly deleted with that revision, and asking again removes
// what is left.
//
// The typed domain must be the site's, and revision the account's current
// one, or the recorded one once the account is gone. Everything that can be
// checked is checked before the first removal. The delete then runs to its
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

	sites := r.Succeeded()
	k := slices.IndexFunc(sites, func(j Job) bool { return j.Result.AccountID == accountID })
	if k < 0 {
		return nothing(ErrNotFound, "That website was not found. It may have been removed already, or it was not made with New website.", nil)
	}
	job := sites[k]
	accounts, err := r.accounts.List(ctx)
	if err != nil {
		return nothing(ErrUnavailable, "The account service did not answer.", err)
	}
	i := slices.IndexFunc(accounts, func(a hostaccounts.Account) bool { return a.ID == accountID })
	owner, domain := job.Username, job.Domain
	// taken: the account is gone and a later one has its user name, so the
	// databases registered under that name are the later account's now.
	taken := false
	if i >= 0 {
		a := accounts[i]
		owner, domain = a.Username, a.Domain
		if confirmDomain != a.Domain {
			return nothing(ErrInvalid, "The domain you typed is not this website's domain, "+a.Domain+".", nil)
		}
		if a.Revision != revision {
			return nothing(ErrConflict, "This website changed after the page loaded it.", nil)
		}
		// The broker refuses every change while any account has an
		// unfinished one, and the list shows that account as needing recovery.
		if stuck := slices.IndexFunc(accounts, func(a hostaccounts.Account) bool { return a.State == "recovery_required" }); stuck >= 0 {
			return nothing(ErrUnavailable, "The account service has an unfinished change on the hosting account "+accounts[stuck].Username+" and refuses every other change until someone has checked it.", nil)
		}
	} else {
		// Only a delete from this page that got as far as asking the broker
		// leaves a site whose account is gone; anything else is not a site
		// this page can finish.
		if job.DeleteRevision == 0 || owner == "" {
			return nothing(ErrNotFound, "That website's hosting account is no longer on this server.", nil)
		}
		if confirmDomain != job.Domain {
			return nothing(ErrInvalid, "The domain you typed is not this website's domain, "+job.Domain+".", nil)
		}
		if job.DeleteRevision != revision {
			return nothing(ErrConflict, "This website changed after the page loaded it.", nil)
		}
		taken = slices.ContainsFunc(accounts, func(a hostaccounts.Account) bool { return a.Username == owner })
	}

	name := dbhost.PrefixedName(owner, strings.TrimPrefix(dbSuffix, "_"))
	users, err := r.databases.AllUsers(ctx)
	if err != nil {
		return nothing(ErrUnavailable, "The panel could not read its list of database users.", err)
	}
	databases, err := r.databases.AllDatabases(ctx)
	if err != nil {
		return nothing(ErrUnavailable, "The panel could not read its list of databases.", err)
	}
	out := Removal{Domain: domain, Username: owner}
	notDropped := func(what string) func(error) (string, bool, error) {
		return func(error) (string, bool, error) {
			return "The database server did not remove " + what + ".", false, ErrUnavailable
		}
	}
	var plan []removal
	suspendedFirst := false
	if i >= 0 {
		active := accounts[i].State == "active"
		plan = append(plan, removal{"the hosting account " + owner + " with its files and its site on the web server", func(ctx context.Context) error {
			err := r.deleteAccount(ctx, accountID, revision, actor)
			if !errors.Is(err, hostaccounts.ErrDeleteBusy) {
				return err
			}
			if !active {
				return &busyRefusal{why: busyNothingRemoved + " " + busySuspendFirst, err: err}
			}
			// The safe order, done once for the person: suspended, the site
			// is off, nothing new starts for the account and its processes
			// end again. The job keeps the revision the delete was first
			// asked at, which a partly deleted site is listed and asked
			// again with.
			next, suspendErr := r.suspendForDelete(ctx, accountID, revision, actor)
			if suspendErr != nil {
				return &busyRefusal{why: busyNothingRemoved + " The panel tried to suspend the site first, but the account service did not confirm that it was suspended. " + busySuspendFirst, err: fmt.Errorf("%w; suspend: %v", err, suspendErr)}
			}
			suspendedFirst = true
			err = r.deleteAccount(ctx, accountID, next, actor)
			if errors.Is(err, hostaccounts.ErrDeleteBusy) {
				return &busyRefusal{why: busyNothingRemoved + " The panel then suspended the site (that stops its processes and keeps the site off) and asked again, but processes were still running, so the site stays suspended. Delete it again in a few minutes; if it is refused again, ask whoever runs this server to check what runs as the user " + owner + ".", err: err}
			}
			return err
		}, accountNotDeleted, true})
	}
	// Only what the registry lists under this account's name for this
	// account: the wizard registered exactly that. Anything else with the
	// name is someone else's and stays.
	user, database := "the database user "+name, "the database "+name
	if !taken && slices.ContainsFunc(users, func(u dbhost.User) bool { return u.Name == name && u.Owner == owner }) {
		plan = append(plan, removal{user, func(ctx context.Context) error { return r.databases.DropUser(ctx, owner, name) }, notDropped(user), false})
	} else if has, err := r.databases.ServerHas(ctx, "user", name); err == nil && has {
		out.Kept = append(out.Kept, user)
	}
	if !taken && slices.ContainsFunc(databases, func(d dbhost.Database) bool { return d.Name == name && d.Owner == owner }) {
		plan = append(plan, removal{database, func(ctx context.Context) error { return r.databases.DropDatabase(ctx, owner, name) }, notDropped(database), false})
	} else if has, err := r.databases.ServerHas(ctx, "database", name); err == nil && has {
		out.Kept = append(out.Kept, database)
	}
	// Recorded before the broker is asked, so a site whose account goes
	// stays listed until its database is gone too.
	if i >= 0 {
		if err := r.store.markDeleting(accountID, revision, timestamp(time.Now())); err != nil {
			return nothing(ErrUnavailable, "The panel could not save its record of this delete, so it did not start. Check that the panel's state directory can be written, then try again.", err)
		}
	}

	accountGone := i < 0
	for n, step := range plan {
		err := step.remove(ctx)
		if err == nil {
			out.Removed = append(out.Removed, step.label)
			accountGone = accountGone || step.account
			continue
		}
		f := &RemoveFailure{Removed: out.Removed, Technical: scrub(err.Error())}
		// The account goes first, so a busy refusal comes before anything
		// was removed, and its message already says so and ends with what
		// to do next.
		var busy *busyRefusal
		if errors.As(err, &busy) && len(out.Removed) == 0 {
			f.Reason, f.Why = ErrConflict, busy.why
			for _, left := range plan[n:] {
				f.Left = append(f.Left, left.label)
			}
			return Removal{}, f
		}
		why, unsure, reason := step.failed(err)
		if step.account && suspendedFirst {
			why = "The account's processes kept running, so the panel suspended the site and asked for the delete again. " + why
		}
		f.Reason = reason
		if len(f.Removed) == 0 {
			why += " Nothing was removed before that."
		} else {
			why += " Removed before that: " + strings.Join(f.Removed, ", ") + "."
		}
		rest := plan[n:]
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
		if accountGone {
			why += " The hosting account is gone, so Websites lists this website as partly deleted. Delete it again to remove the rest."
		}
		f.Why = why
		return Removal{}, f
	}
	// Memory is marked whether or not this is saved. If the file keeps the
	// job unmarked, Websites lists the site as partly deleted after a restart,
	// and a second delete, with nothing left to remove, marks it.
	if err := r.store.markRemoved(accountID, timestamp(time.Now())); err != nil {
		fmt.Fprintf(logOutput, "website %s: marking its job as removed could not be saved: %v\n", domain, err)
	}
	out.SuspendedFirst = suspendedFirst
	return out, nil
}

// deleteAccount asks the account service to delete the site's hosting
// account at revision. An account that is already gone counts as deleted.
func (r *Runner) deleteAccount(ctx context.Context, accountID string, revision uint64, actor string) error {
	_, err := r.accounts.Delete(ctx, accountID, hostaccounts.DeleteInput{ExpectedRevision: revision, Reason: removeReason}, actor)
	if errors.Is(err, hostaccounts.ErrNotFound) {
		return nil
	}
	return err
}

// suspendForDelete suspends an active site whose delete was refused because
// its processes kept running, and answers the account's revision after it.
// A suspension stands even when some processes outlive it, and the account
// service then answers unavailable; so after an error the account list says
// whether this suspension took: the account suspended, one revision on.
func (r *Runner) suspendForDelete(ctx context.Context, accountID string, revision uint64, actor string) (uint64, error) {
	changed, err := r.accounts.SetState(ctx, accountID, hostaccounts.StateInput{State: "suspended", ExpectedRevision: revision, Reason: suspendReason}, actor)
	if err == nil {
		return changed.Revision, nil
	}
	accounts, listErr := r.accounts.List(ctx)
	if listErr != nil {
		return 0, err
	}
	k := slices.IndexFunc(accounts, func(a hostaccounts.Account) bool { return a.ID == accountID })
	if k < 0 || accounts[k].State != "suspended" || accounts[k].Revision != revision+1 {
		return 0, err
	}
	return accounts[k].Revision, nil
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
	case errors.Is(err, hostaccounts.ErrDeleteStopped):
		return "The account service stopped the delete before anything was removed, because ending the account's running processes failed or took too long. The hosting account and its website are as they were. Try the delete again.", false, ErrUnavailable
	default:
		return "The account service did not answer, so the panel cannot tell whether the hosting account was deleted.", true, ErrUnavailable
	}
}
