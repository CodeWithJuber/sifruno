package hostaccounts

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/olsweb"
)

// A tenant's own actions in its home (here: public_html renamed away and a
// new one made) may make its own account's operations fail and mark that
// account as needing attention. They must never block another account's
// mutations, make another account's web change end rejected, or stop an
// operator from suspending or deleting the tenant's account.

// liveAccount is a second account with a live site.
func liveAccount(t *testing.T, s *store, username, domain string) record {
	t.Helper()
	a, err := s.create(context.Background(), CreateInput{Username: username, Domain: domain, Reason: "Synthetic core verification"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.setWeb(context.Background(), a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	return recordFor(t, s, a.ID)
}

func listedAccount(t *testing.T, s *store, id string) Account {
	t.Helper()
	items, err := s.list(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range items {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("account %s is not listed", id)
	return Account{}
}

func noConflictJournaled(t *testing.T, s *store, id string) {
	t.Helper()
	for _, row := range historyActions(t, s, id) {
		if strings.HasPrefix(row, "conflict:") {
			t.Fatalf("a tenant's own folder change was journaled as a conflict: %v", historyActions(t, s, id))
		}
	}
}

// (a) Nothing another account does is held up.
func TestTenantFolderChangeBlocksNoOtherAccount(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	tenant := liveFixture(t, s)
	other := liveAccount(t, s, "secondacct", "second.test")
	tenantMovesPublicHTML(f, tenant.Account.Username)

	got := listedAccount(t, s, tenant.Account.ID)
	if got.State != "active" || !got.SiteFolderChanged || got.Revision != tenant.Account.Revision {
		t.Fatalf("the tenant's account is listed as %+v", got)
	}
	if a := listedAccount(t, s, other.Account.ID); a.State != "active" || a.SiteFolderChanged {
		t.Fatalf("another account is listed as %+v", a)
	}
	if c, err := s.capability(ctx); err != nil || !c.Available {
		t.Fatalf("capability with a tenant's folder changed: %+v %v", c, err)
	}

	created, err := s.create(ctx, CreateInput{Username: "thirdacct", Domain: "third.test", Reason: "Created while a tenant's folder is changed"}, "test operator")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created, err = s.setPlan(ctx, created.ID, PlanInput{Plan: "larger", ExpectedRevision: created.Revision, Reason: "Plan change"}, "test operator"); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if _, err := s.setSSHKeys(ctx, other.Account.ID, SSHKeysInput{Keys: []string{testEd25519Line(t, "laptop")}, ExpectedRevision: other.Account.Revision, Reason: "Key"}, "test operator"); err != nil {
		t.Fatalf("ssh keys: %v", err)
	}
	other = recordFor(t, s, other.Account.ID)
	if _, err := s.setWeb(ctx, other.Account.ID, WebInput{PHPVersion: "8.2", QuotaMiB: 200, ExpectedRevision: other.Account.Revision, Reason: "PHP change"}, "test operator"); err != nil {
		t.Fatalf("web: %v", err)
	}
	other = recordFor(t, s, other.Account.ID)
	suspended, err := suspend(s, other)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := s.setState(ctx, other.Account.ID, StateInput{State: "active", ExpectedRevision: suspended.Revision, Reason: "Paid"}, "test operator"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := s.delete(ctx, created.ID, DeleteInput{ExpectedRevision: created.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// The tenant's own changes that write into its folders are refused,
	// before anything is journaled.
	before := recordFor(t, s, tenant.Account.ID)
	if _, err := s.setWeb(ctx, tenant.Account.ID, WebInput{PHPVersion: "8.2", QuotaMiB: 200, ExpectedRevision: before.Account.Revision, Reason: "PHP change"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("the tenant's own web change: %v", err)
	}
	if after := recordFor(t, s, tenant.Account.ID); after.HistorySequence != before.HistorySequence || after.Pending != nil {
		t.Fatalf("a refused web change journaled something: %+v", after)
	}
	noConflictJournaled(t, s, tenant.Account.ID)

	// What only root can change still stops everything.
	f.changed = true
	if _, err := s.create(ctx, CreateInput{Username: "fourthacct", Domain: "fourth.test", Reason: "Blocked"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("create while an identity changed outside the broker: %v", err)
	}
}

// (b) A web change of another account does not end rejected, even when the
// render rewrites every vhost (the fake's model), which is what an upgrade
// that changes the rendered form does once.
func TestBrokenTenantDoesNotRejectOtherAccountsWebChanges(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	tenant := liveFixture(t, s)
	other := liveAccount(t, s, "secondacct", "second.test")
	tenantMovesPublicHTML(f, tenant.Account.Username)
	tenantVhost := olsweb.NamePrefix + siteName(tenant.Account.ID)

	// Judged as a whole, this site list fails the test: the tenant's vhost
	// names the public_html that is gone.
	items, err := s.records()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ApplySites(ctx, webSites(items, ""), nil); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("the fake's model does not reject a broken tenant's vhost: %v", err)
	}

	if _, err := s.setWeb(ctx, other.Account.ID, WebInput{PHPVersion: "8.2", QuotaMiB: 300, ExpectedRevision: other.Account.Revision, Reason: "PHP change"}, "test operator"); err != nil {
		t.Fatalf("another account's web change: %v", err)
	}
	if !f.broken[tenantVhost] || len(f.broken) != 1 {
		t.Fatalf("the web change judged the broken tenant's vhost: %v", f.broken)
	}
	other = recordFor(t, s, other.Account.ID)
	if got, err := suspend(s, other); err != nil || got.State != "suspended" {
		t.Fatalf("another account's suspend: %+v %v", got, err)
	}
	other = recordFor(t, s, other.Account.ID)
	if _, err := s.setState(ctx, other.Account.ID, StateInput{State: "active", ExpectedRevision: other.Account.Revision, Reason: "Paid"}, "test operator"); err != nil {
		t.Fatalf("another account's resume: %v", err)
	}

	// An interrupted web change of another account is finished, not
	// rejected, on the next start.
	other = recordFor(t, s, other.Account.ID)
	f.failure = "web-before"
	if _, err := s.setWeb(ctx, other.Account.ID, WebInput{PHPVersion: "8.4", QuotaMiB: 300, ExpectedRevision: other.Account.Revision, Reason: "PHP change"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("interrupted web change: %v", err)
	}
	f.failure = ""
	s.mu.Lock()
	err = s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if after := recordFor(t, s, other.Account.ID); after.Pending != nil || after.Web.PHPVersion != "8.4" {
		t.Fatalf("the interrupted change was not finished: %+v", after)
	}
	if rows := historyActions(t, s, other.Account.ID); rows[len(rows)-1] != "web:reconciled" {
		t.Fatalf("history %v", rows)
	}

	// The tenant's own changes are judged on its own vhost.
	tenant = recordFor(t, s, tenant.Account.ID)
	held, err := suspend(s, tenant)
	if err != nil {
		t.Fatalf("suspend of the tenant: %v", err)
	}
	if len(f.broken) != 0 {
		t.Fatalf("the tenant's own suspend left its vhost out of the test: %v", f.broken)
	}
	if _, err := s.setState(ctx, tenant.Account.ID, StateInput{State: "active", ExpectedRevision: held.Revision, Reason: "Paid"}, "test operator"); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("resume of the tenant while its public_html is gone: %v", err)
	}
	// A suspended site names no tenant path, so it is judged as always.
	other = recordFor(t, s, other.Account.ID)
	if _, err := s.setWeb(ctx, other.Account.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 300, ExpectedRevision: other.Account.Revision, Reason: "PHP change"}, "test operator"); err != nil || len(f.broken) != 0 {
		t.Fatalf("web change beside a suspended broken tenant: %v, left out %v", err, f.broken)
	}
}

// (c) The operator can suspend, suspend again and delete the account.
func TestOperatorCanSuspendAndDeleteAChangedAccount(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	tenant := liveFixture(t, s)
	other := liveAccount(t, s, "secondacct", "second.test")
	tenantMovesPublicHTML(f, tenant.Account.Username)

	got, err := suspend(s, tenant)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if got.State != "suspended" || f.users[tenant.Account.Username].Account.State != "suspended" || !siteOf(t, f.sites, tenant.Account.ID).Suspended || siteOf(t, f.sites, other.Account.ID).Suspended {
		t.Fatalf("after suspend: %+v, sites %+v", got, f.sites)
	}
	again, err := suspend(s, recordFor(t, s, tenant.Account.ID))
	if err != nil || again.Revision != got.Revision+1 || !siteOf(t, f.sites, tenant.Account.ID).Suspended {
		t.Fatalf("suspend again: %+v %v", again, err)
	}
	if a := listedAccount(t, s, tenant.Account.ID); a.State != "suspended" || !a.SiteFolderChanged {
		t.Fatalf("listed %+v", a)
	}
	noConflictJournaled(t, s, tenant.Account.ID)

	held := recordFor(t, s, tenant.Account.ID)
	if _, err := s.delete(ctx, tenant.Account.ID, DeleteInput{ExpectedRevision: held.Account.Revision, Reason: "Abuse"}, "test operator"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := f.users[tenant.Account.Username]; ok {
		t.Fatal("the user is still there")
	}
	if len(f.sites) != 1 || f.sites[0].Name != siteName(other.Account.ID) {
		t.Fatalf("sites after the delete %+v", f.sites)
	}
	if items, err := s.list(ctx); err != nil || len(items) != 1 || items[0].ID != other.Account.ID {
		t.Fatalf("accounts after the delete %+v %v", items, err)
	}
}

// The next start finishes an interrupted change of an account whose tenant
// changed its folder since: those checks read only what root controls, so
// the tenant cannot keep the change pending and every account blocked.
func TestInterruptedChangesOfAChangedAccountAreFinished(t *testing.T) {
	ctx := context.Background()
	restart := func(t *testing.T, s *store) {
		t.Helper()
		s.mu.Lock()
		err := s.refresh(ctx, true)
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("suspend", func(t *testing.T) {
		s, f := webStore(t)
		tenant := liveFixture(t, s)
		f.failure = "sites"
		if _, err := suspend(s, tenant); !errors.Is(err, ErrRecovery) {
			t.Fatalf("interrupted suspend: %v", err)
		}
		f.failure = ""
		tenantMovesPublicHTML(f, tenant.Account.Username)
		restart(t, s)
		after := recordFor(t, s, tenant.Account.ID)
		if after.Pending != nil || after.Account.State != "suspended" || !siteOf(t, f.sites, tenant.Account.ID).Suspended {
			t.Fatalf("the suspend was not finished: %+v", after)
		}
	})
	t.Run("ssh keys", func(t *testing.T) {
		s, f := webStore(t)
		tenant := liveFixture(t, s)
		f.failure = "keys-after"
		key := testEd25519Line(t, "laptop")
		if _, err := s.setSSHKeys(ctx, tenant.Account.ID, SSHKeysInput{Keys: []string{key}, ExpectedRevision: tenant.Account.Revision, Reason: "Key"}, "test operator"); !errors.Is(err, ErrRecovery) {
			t.Fatalf("interrupted key write: %v", err)
		}
		f.failure = ""
		tenantMovesPublicHTML(f, tenant.Account.Username)
		restart(t, s)
		if after := recordFor(t, s, tenant.Account.ID); after.Pending != nil || after.SSHKeys != key {
			t.Fatalf("the key write was not finished: %+v", after)
		}
	})
	t.Run("delete", func(t *testing.T) {
		s, f := webStore(t)
		tenant := liveFixture(t, s)
		f.failure = "sites"
		if _, err := s.delete(ctx, tenant.Account.ID, DeleteInput{ExpectedRevision: tenant.Account.Revision, Reason: "Abuse"}, "test operator"); !errors.Is(err, ErrRecovery) {
			t.Fatalf("interrupted delete: %v", err)
		}
		f.failure = ""
		tenantMovesPublicHTML(f, tenant.Account.Username)
		restart(t, s)
		if items, err := s.records(); err != nil || slices.ContainsFunc(items, func(r record) bool { return r.Account.ID == tenant.Account.ID }) {
			t.Fatalf("the delete was not finished: %+v %v", items, err)
		}
	})
}

// (d) A process the tenant keeps alive through every pass makes userdel
// refuse its user. That delete ends rejected with the site back and the
// account unchanged, so it blocks no other account, and it can be deleted
// once its processes end.
func TestBusyDeleteBlocksNoOtherAccount(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	tenant := liveFixture(t, s)
	other := liveAccount(t, s, "secondacct", "second.test")

	f.failure = "busy"
	if _, err := s.delete(ctx, tenant.Account.ID, DeleteInput{ExpectedRevision: tenant.Account.Revision, Reason: "Abuse"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a delete userdel refused: %v", err)
	}
	f.failure = ""
	busyDeleteRejected(t, s, f, tenant)

	if _, err := suspend(s, other); err != nil {
		t.Fatalf("another account's suspend after the refused delete: %v", err)
	}
	if _, err := s.create(ctx, CreateInput{Username: "thirdacct", Domain: "third.test", Reason: "Created after the refused delete"}, "test operator"); err != nil {
		t.Fatalf("create after the refused delete: %v", err)
	}
	held := recordFor(t, s, tenant.Account.ID)
	if _, err := s.delete(ctx, tenant.Account.ID, DeleteInput{ExpectedRevision: held.Account.Revision, Reason: "Abuse"}, "test operator"); err != nil {
		t.Fatalf("delete once the processes ended: %v", err)
	}
	if _, ok := f.users[tenant.Account.Username]; ok {
		t.Fatal("the user is still there")
	}
}

// The next start ends an interrupted delete the same way when userdel
// still refuses the user.
func TestBusyDeleteAtRestartBlocksNoOtherAccount(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	tenant := liveFixture(t, s)
	other := liveAccount(t, s, "secondacct", "second.test")

	f.failure = "sites"
	if _, err := s.delete(ctx, tenant.Account.ID, DeleteInput{ExpectedRevision: tenant.Account.Revision, Reason: "Abuse"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("interrupted delete: %v", err)
	}
	f.failure = "busy"
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.failure = ""
	busyDeleteRejected(t, s, f, tenant)
	if _, err := s.setWeb(ctx, other.Account.ID, WebInput{PHPVersion: "8.2", QuotaMiB: 200, ExpectedRevision: other.Account.Revision, Reason: "PHP change"}, "test operator"); err != nil {
		t.Fatalf("another account's web change after the refused delete: %v", err)
	}
}

func busyDeleteRejected(t *testing.T, s *store, f *fakeNative, tenant record) {
	t.Helper()
	after := recordFor(t, s, tenant.Account.ID)
	if after.Pending != nil || after.Account != tenant.Account || after.Web != tenant.Web {
		t.Fatalf("the refused delete changed the account: %+v", after)
	}
	if _, ok := f.users[tenant.Account.Username]; !ok {
		t.Fatal("the user went although userdel refused it")
	}
	if site := siteOf(t, f.sites, tenant.Account.ID); site.Suspended {
		t.Fatalf("the site came back as %+v", site)
	}
	if rows := historyActions(t, s, tenant.Account.ID); rows[len(rows)-1] != "delete:rejected" {
		t.Fatalf("journal %v", rows)
	}
	if c, err := s.capability(context.Background()); err != nil || !c.Available {
		t.Fatalf("capability after the refused delete: %+v %v", c, err)
	}
}

// A suspend ends the account's processes after the suspension is journaled;
// a resume does not. When some outlive the passes the suspension stands and
// the answer is 503, and a suspend again ends them again without a journal
// row (the account has no site, so its record does not change).
func TestSuspendEndsTheAccountsProcesses(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)

	suspended, err := suspend(s, recordFor(t, s, a.ID))
	if err != nil || f.ended[a.Username] != 1 {
		t.Fatalf("suspend: %v, processes ended %d times", err, f.ended[a.Username])
	}
	resumed, err := s.setState(ctx, a.ID, StateInput{State: "active", ExpectedRevision: suspended.Revision, Reason: "Paid"}, "test operator")
	if err != nil || f.ended[a.Username] != 1 {
		t.Fatalf("resume: %v, processes ended %d times", err, f.ended[a.Username])
	}

	f.failure = "busy"
	if _, err := s.setState(ctx, a.ID, StateInput{State: "suspended", ExpectedRevision: resumed.Revision, Reason: "Unpaid"}, "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("suspend with a process left: %v", err)
	}
	f.failure = ""
	held := recordFor(t, s, a.ID)
	if held.Pending != nil || held.Account.State != "suspended" || f.users[a.Username].Account.State != "suspended" {
		t.Fatalf("the suspension did not stand: %+v", held)
	}
	rows := len(historyActions(t, s, a.ID))
	if again, err := suspend(s, held); err != nil || again.Revision != held.Account.Revision || f.ended[a.Username] != 3 || len(historyActions(t, s, a.ID)) != rows {
		t.Fatalf("suspend again: %+v %v, processes ended %d times", again, err, f.ended[a.Username])
	}
	if _, err := s.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Created after the suspend"}, "test operator"); err != nil {
		t.Fatalf("create after the suspend: %v", err)
	}
}
