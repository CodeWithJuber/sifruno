package wizard

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
)

const (
	siteUser    = "the database user example_wp"
	siteDB      = "the database example_wp"
	siteAccount = "the hosting account example with its files and its site on the web server"
)

// removable is a finished site with its database and user in the registry,
// as dbhost keeps them (the fakes keep no registry of their own).
func removable(t *testing.T) (fixture, Job, hostaccounts.Account) {
	t.Helper()
	f := newFixture(t)
	done := f.runJob(t, input("example.com"))
	if done.State != StateSucceeded {
		t.Fatalf("job: %+v", done)
	}
	f.dbs.existing = []dbhost.Database{{Name: "example_wp", Owner: "example"}}
	f.dbs.users = []dbhost.User{{Name: "example_wp", Owner: "example"}}
	f.acc.calls, f.dbs.calls = nil, nil
	return f, done, f.acc.accounts[0]
}

func removeFailure(t *testing.T, err error, reason error) *RemoveFailure {
	t.Helper()
	var failure *RemoveFailure
	if !errors.As(err, &failure) || !errors.Is(err, reason) {
		t.Fatalf("error %v, want a RemoveFailure for %v", err, reason)
	}
	return failure
}

func TestRemoveSiteDropsTheDatabaseThenTheAccount(t *testing.T) {
	f, done, a := removable(t)
	// The caller going away does not stop the delete half-way.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := f.runner.RemoveSite(ctx, a.ID, "example.com", a.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != "example.com" || got.Username != "example" || !slices.Equal(got.Removed, []string{siteUser, siteDB, siteAccount}) || len(got.Kept) != 0 {
		t.Fatalf("removal %+v", got)
	}
	want := []string{"list", "drop-user example example_wp", "drop-db example example_wp", fmt.Sprintf("delete 0001 rev=%d", a.Revision)}
	if !slices.Equal(f.order.all[len(f.order.all)-len(want):], want) || f.acc.delCtx != nil {
		t.Fatalf("calls %q, delete context %v", f.order.all, f.acc.delCtx)
	}
	// The job is kept, marked, and no longer names a site; also after a restart.
	if sites := f.runner.Succeeded(); len(sites) != 0 {
		t.Fatalf("the removed site is still listed: %+v", sites)
	}
	marked, _ := f.runner.Get(done.ID)
	if marked.RemovedAt == "" || marked.State != StateSucceeded {
		t.Fatalf("job after the delete %+v", marked)
	}
	store, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if again, ok := store.Get(done.ID); !ok || again.RemovedAt != marked.RemovedAt {
		t.Fatalf("reopened job %+v", again)
	}
	// Asking again finds no site.
	_, err = f.runner.RemoveSite(context.Background(), a.ID, "example.com", a.Revision, "local-operator")
	removeFailure(t, err, ErrNotFound)
}

func TestRemoveSiteChecksBeforeItRemovesAnything(t *testing.T) {
	f, _, a := removable(t)
	ctx := context.Background()
	other := hostaccounts.Account{ID: strings.Repeat("e", 32), Username: "manual", Domain: "manual.example", State: "active", Revision: 1}
	f.acc.accounts = append(f.acc.accounts, other)
	refused := func(name string, reason error, why string, id, domain string, revision uint64, actor string) {
		t.Helper()
		_, err := f.runner.RemoveSite(ctx, id, domain, revision, actor)
		failure := removeFailure(t, err, reason)
		if !strings.Contains(failure.Why, why) || !strings.HasSuffix(failure.Why, " Nothing was removed.") || len(failure.Removed) != 0 {
			t.Fatalf("%s: %+v", name, failure)
		}
		if len(f.dbs.calls) != 0 || slices.ContainsFunc(f.acc.calls, func(c string) bool { return strings.HasPrefix(c, "delete") }) {
			t.Fatalf("%s: something was removed: %q %q", name, f.dbs.calls, f.acc.calls)
		}
	}
	refused("wrong domain", ErrInvalid, "is not this website's domain, example.com.", a.ID, "example.org", a.Revision, "local-operator")
	refused("domain in another case", ErrInvalid, "is not this website's domain", a.ID, "Example.com", a.Revision, "local-operator")
	refused("stale revision", ErrConflict, "changed after the page loaded it", a.ID, "example.com", a.Revision-1, "local-operator")
	refused("an account the wizard did not make", ErrNotFound, "was not found", other.ID, "manual.example", 1, "local-operator")
	refused("no actor", ErrInvalid, "could not be identified", a.ID, "example.com", a.Revision, "")

	f.acc.accounts[1].State = "recovery_required"
	refused("the broker is waiting for a recovery", ErrUnavailable, "unfinished change on the hosting account manual", a.ID, "example.com", a.Revision, "local-operator")
	f.acc.accounts[1].State = "active"

	f.dbs.listErr = errors.New("registry unreadable")
	refused("registry unreadable", ErrUnavailable, "could not read its list of database users", a.ID, "example.com", a.Revision, "local-operator")
	f.dbs.listErr = nil

	f.acc.listErr = hostaccounts.ErrUnavailable
	refused("broker down", ErrUnavailable, "The account service did not answer.", a.ID, "example.com", a.Revision, "local-operator")
	f.acc.listErr = nil

	if sites := f.runner.Succeeded(); len(sites) != 1 {
		t.Fatalf("the site left the list after refusals: %+v", sites)
	}
}

func TestRemoveSiteSaysWhatIsLeftAndCarriesOn(t *testing.T) {
	f, _, a := removable(t)
	ctx := context.Background()
	remove := func() (Removal, error) {
		return f.runner.RemoveSite(ctx, a.ID, "example.com", a.Revision, "local-operator")
	}

	// The database server refuses the first removal: nothing went.
	f.dbs.dropErr = errors.New("ERROR 2002: server gone near 'DROP USER'")
	_, err := remove()
	failure := removeFailure(t, err, ErrUnavailable)
	if failure.Why != "The database server did not remove "+siteUser+". Nothing was removed before that. Still on the server: "+siteUser+", "+siteDB+", "+siteAccount+"." ||
		failure.Technical != "ERROR 2002: server gone near [statement removed]" || !slices.Equal(failure.Left, []string{siteUser, siteDB, siteAccount}) {
		t.Fatalf("first removal failed: %+v", failure)
	}
	f.dbs.dropErr = nil

	// The user goes, the database does not: the account is not touched.
	f.dbs.dropDBErr = errors.New("ERROR 1010: database directory not empty")
	_, err = remove()
	failure = removeFailure(t, err, ErrUnavailable)
	if failure.Why != "The database server did not remove "+siteDB+". Removed before that: "+siteUser+". Still on the server: "+siteDB+", "+siteAccount+"." ||
		!slices.Equal(failure.Removed, []string{siteUser}) || !slices.Equal(failure.Left, []string{siteDB, siteAccount}) {
		t.Fatalf("second removal failed: %+v", failure)
	}
	if slices.ContainsFunc(f.acc.calls, func(c string) bool { return strings.HasPrefix(c, "delete") }) {
		t.Fatalf("the account was deleted although its database was not: %q", f.acc.calls)
	}
	f.dbs.dropDBErr = nil
	f.dbs.users = nil // dbhost took the user out of its registry

	// The broker's answers, with the database gone.
	for _, c := range []struct {
		err    error
		reason error
		why    string
	}{
		{hostaccounts.ErrConflict, ErrConflict, "The hosting account changed or was busy, so the account service did not delete it. Removed before that: " + siteDB + ". Still on the server: " + siteAccount + "."},
		{hostaccounts.ErrWebRejected, ErrUnavailable, "configuration test failed without this site, so the server kept its old configuration and the hosting account was not deleted. Ask whoever runs this server to check the web server. Nothing was removed before that. Still on the server: " + siteAccount + "."},
		{hostaccounts.ErrUnavailable, ErrUnavailable, "cannot tell whether the hosting account was deleted. Nothing was removed before that. May still be on the server: " + siteAccount + "."},
		{hostaccounts.ErrRecovery, ErrUnavailable, "stopped part-way through deleting the hosting account and needs a check before anything else changes. Nothing was removed before that. May still be on the server: " + siteAccount + "."},
	} {
		f.acc.delErr = c.err
		_, err = remove()
		failure = removeFailure(t, err, c.reason)
		if !strings.HasSuffix(failure.Why, c.why) || !slices.Equal(failure.Left, []string{siteAccount}) {
			t.Fatalf("broker answered %v: %+v", c.err, failure)
		}
		// dbhost took the database out of its registry the first time.
		f.dbs.existing = nil
	}
	if sites := f.runner.Succeeded(); len(sites) != 1 {
		t.Fatal("a site whose account is still on the server left the list")
	}

	// Asking again carries on from what is left.
	f.acc.delErr = nil
	f.dbs.calls = nil
	got, err := remove()
	if err != nil || !slices.Equal(got.Removed, []string{siteAccount}) || len(f.dbs.calls) != 0 || len(f.runner.Succeeded()) != 0 {
		t.Fatalf("delete after the failures: %+v %v, database calls %q", got, err, f.dbs.calls)
	}
}

func TestRemoveSiteLeavesWhatIsNotRegisteredToIt(t *testing.T) {
	f, _, a := removable(t)
	// The names exist on the server, but the registry lists them for another
	// account, or not at all: they are not this site's to remove.
	f.dbs.existing = []dbhost.Database{{Name: "example_wp", Owner: "someoneelse"}}
	f.dbs.users = nil
	got, err := f.runner.RemoveSite(context.Background(), a.ID, "example.com", a.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Removed, []string{siteAccount}) || !slices.Equal(got.Kept, []string{siteUser, siteDB}) || len(f.dbs.calls) != 0 {
		t.Fatalf("removal %+v, database calls %q", got, f.dbs.calls)
	}
}

// A deleted site's job counts with the failed ones, so deleted sites do not
// push live sites out of the store.
func TestRemovedSitesDoNotUseUpTheSiteLimit(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "wizard"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		s.jobs = append(s.jobs, Job{ID: fmt.Sprintf("%032x", i+1), State: StateSucceeded, Steps: make([]Step, len(stepTitles)), Result: &Result{AccountID: fmt.Sprintf("%032x", 1000+i)}})
	}
	for i := 0; i < 55; i++ {
		if err := s.markRemoved(fmt.Sprintf("%032x", 1000+i), "2026-11-24T10:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	live, removed := 0, 0
	for _, j := range s.jobs {
		if j.namesSite() {
			live++
		} else {
			removed++
		}
	}
	if live != 5 || removed != maxJobs {
		t.Fatalf("kept %d live and %d removed jobs", live, removed)
	}
}
