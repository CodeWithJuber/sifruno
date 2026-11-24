package hostaccounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sifruno/internal/olsweb"
)

// liveFixture is an account with a live site.
func liveFixture(t *testing.T, s *store) record {
	t.Helper()
	a := createFixture(t, s)
	if _, err := s.setWeb(context.Background(), a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	return recordFor(t, s, a.ID)
}

func siteOf(t *testing.T, sites []olsweb.Site, id string) olsweb.Site {
	t.Helper()
	for _, site := range sites {
		if site.Name == siteName(id) {
			return site
		}
	}
	t.Fatalf("site %s is not in the list: %+v", siteName(id), sites)
	return olsweb.Site{}
}

func suspend(s *store, r record) (Account, error) {
	return s.setState(context.Background(), r.Account.ID, StateInput{State: "suspended", ExpectedRevision: r.Account.Revision, Reason: "Unpaid"}, "test operator")
}

func TestSuspendStopsTheLiveSiteAndResumeServesIt(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	r := liveFixture(t, s)
	other, err := s.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Synthetic core verification"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if siteOf(t, f.sites, r.Account.ID).Suspended {
		t.Fatal("a live site of an active account is marked suspended")
	}

	// An account without a site changes state without touching the web server.
	if _, err := s.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Unpaid"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if f.siteApplies != 0 {
		t.Fatalf("a state change without a site installed the site list %d times", f.siteApplies)
	}

	got, err := suspend(s, r)
	if err != nil {
		t.Fatal(err)
	}
	// The answer shows the live site's settings, as the account list does.
	if got.State != "suspended" || got.Revision != r.Account.Revision+1 || got.Web != r.Web || f.users[r.Account.Username].Account.State != "suspended" {
		t.Fatalf("suspended account %+v", got)
	}
	site := siteOf(t, f.sites, r.Account.ID)
	if f.siteApplies != 1 || !site.Suspended || site.PHPVersion != "8.3" || len(f.sites) != 1 {
		t.Fatalf("after suspend: %d installs, sites %+v", f.siteApplies, f.sites)
	}
	after := recordFor(t, s, r.Account.ID)
	if after.Pending != nil || withWeb(after) != got || after.Account.Web != (WebState{}) || after.Web != r.Web || after.HistorySequence != r.HistorySequence+2 {
		t.Fatalf("record after suspend %+v", after)
	}
	// Rendered, that site refuses every request and names no path under the
	// homes root, so its config test depends on nothing the tenant controls.
	files := renderAtHomeRoot([]olsweb.Site{site})
	if !strings.Contains(string(files[olsweb.VhostConfigPath(site.Name)]), "RewriteRule .* - [F,L]\n") {
		t.Fatal("the suspended site's config does not refuse every request")
	}
	for path, data := range files {
		if strings.Contains(string(data), olsweb.HomeRoot+"/") {
			t.Fatalf("the suspended site's %s names a path under the homes root:\n%s", path, data)
		}
	}

	// A suspended site stays suspended when another account's site goes live.
	third, err := s.create(ctx, CreateInput{Username: "thirdacct", Domain: "third.test", Reason: "Synthetic core verification"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.setWeb(ctx, third.ID, WebInput{PHPVersion: "8.2", QuotaMiB: 200, ExpectedRevision: third.Revision, Reason: "Go live"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if len(f.sites) != 2 || !siteOf(t, f.sites, r.Account.ID).Suspended || siteOf(t, f.sites, third.ID).Suspended {
		t.Fatalf("sites after another account went live %+v", f.sites)
	}

	resumed, err := s.setState(ctx, r.Account.ID, StateInput{State: "active", ExpectedRevision: got.Revision, Reason: "Paid"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != "active" || resumed.Revision != got.Revision+1 || resumed.Web != r.Web || siteOf(t, f.sites, r.Account.ID).Suspended || f.siteApplies != 2 {
		t.Fatalf("after resume: %+v, %d installs, sites %+v", resumed, f.siteApplies, f.sites)
	}
}

// A tenant who moves public_html away cannot defeat their own suspension:
// the suspended vhost does not name it, so the config test passes. A resume
// names it again and ends rejected, leaving the site suspended.
func TestSuspendSucceedsWhilePublicHTMLIsMissing(t *testing.T) {
	s, f := webStore(t)
	before := liveFixture(t, s)
	f.missingPath = olsweb.HomeRoot + "/" + before.Account.Username + "/public_html"
	got, err := suspend(s, before)
	if err != nil {
		t.Fatalf("suspend while public_html is missing: %v", err)
	}
	after := recordFor(t, s, before.Account.ID)
	if got.State != "suspended" || after.Pending != nil || f.users[before.Account.Username].Account.State != "suspended" || !siteOf(t, f.sites, before.Account.ID).Suspended {
		t.Fatalf("suspend while public_html is missing did not stop the site: %+v", after)
	}
	if _, err := s.setState(context.Background(), before.Account.ID, StateInput{State: "active", ExpectedRevision: got.Revision, Reason: "Paid"}, "test operator"); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("resume while public_html is missing: %v", err)
	}
	if f.users[before.Account.Username].Account.State != "suspended" || !siteOf(t, f.sites, before.Account.ID).Suspended || recordFor(t, s, before.Account.ID).Account != after.Account {
		t.Fatal("a rejected resume served the site or changed the account")
	}
}

// A suspend of a suspended account with a live site installs the site list
// again, journaled like any change, so a suspension made before the list
// followed the account can be enforced. Without a live site, or for a resume
// of an active account, the same state changes nothing.
func TestSuspendAgainInstallsTheSiteList(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	before := liveFixture(t, s)
	same, err := s.setState(ctx, before.Account.ID, StateInput{State: "active", ExpectedRevision: before.Account.Revision, Reason: "Paid"}, "test operator")
	if err != nil || same.Revision != before.Account.Revision || recordFor(t, s, before.Account.ID).HistorySequence != before.HistorySequence || f.siteApplies != 0 {
		t.Fatalf("a resume of an active account changed something: %+v %v", same, err)
	}
	first, err := suspend(s, before)
	if err != nil {
		t.Fatal(err)
	}
	// The broker before this rule left the installed list serving the site.
	for i := range f.sites {
		f.sites[i].Suspended = false
	}
	suspended := recordFor(t, s, before.Account.ID)
	again, err := suspend(s, suspended)
	if err != nil {
		t.Fatal(err)
	}
	after := recordFor(t, s, before.Account.ID)
	if again.State != "suspended" || again.Revision != first.Revision+1 || after.Pending != nil || after.HistorySequence != suspended.HistorySequence+2 || f.siteApplies != 2 || !siteOf(t, f.sites, before.Account.ID).Suspended {
		t.Fatalf("a second suspend did not install the site list again: %+v, %d installs, sites %+v", again, f.siteApplies, f.sites)
	}
	if got := historyActions(t, s, before.Account.ID); got[len(got)-2] != "state:intended" || got[len(got)-1] != "state:succeeded" {
		t.Fatalf("history %v", got)
	}

	// An account without a site has nothing to install.
	other, err := s.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Synthetic core verification"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if other, err = s.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Unpaid"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if same, err := s.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Unpaid"}, "test operator"); err != nil || same.Revision != other.Revision || f.siteApplies != 2 {
		t.Fatalf("a second suspend without a site changed something: %+v %v", same, err)
	}
}

func TestSuspendEndsRejectedWhenTheConfigFailsItsTest(t *testing.T) {
	s, f := webStore(t)
	before := liveFixture(t, s)
	f.failure = "sites-reject"
	if _, err := suspend(s, before); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("suspend with a rejected config: %v", err)
	}
	// The old files went back, so the account went back too: journaled as
	// rejected, unchanged and nothing left pending.
	after := recordFor(t, s, before.Account.ID)
	if after.Pending != nil || after.Account != before.Account || after.Web != before.Web || after.HistorySequence != before.HistorySequence+2 {
		t.Fatalf("a rejected suspend changed the account or left it pending: %+v", after)
	}
	if f.users[before.Account.Username].Account.State != "active" || siteOf(t, f.sites, before.Account.ID).Suspended {
		t.Fatal("a rejected suspend left the user suspended or the site refused")
	}
	// Nothing is pending, so the same request works later.
	f.failure = ""
	if got, err := suspend(s, before); err != nil || got.State != "suspended" || !siteOf(t, f.sites, before.Account.ID).Suspended {
		t.Fatalf("suspend after the rejection: %+v %v", got, err)
	}
}

func TestRejectedSuspendThatCannotGoBackNeedsRecovery(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	before := liveFixture(t, s)
	f.failure, f.refuseState = "sites-reject", "active"
	if _, err := suspend(s, before); !errors.Is(err, ErrRecovery) {
		t.Fatalf("a rejected suspend whose account could not be put back: %v", err)
	}
	pending := recordFor(t, s, before.Account.ID)
	if pending.Pending == nil || pending.Pending.Action != "state" || pending.Pending.Target != "suspended" || pending.Account.State != "active" {
		t.Fatalf("the half-done suspend is not pending: %+v", pending)
	}
	// The next start finds the account suspended and finishes the site.
	f.failure, f.refuseState = "", ""
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after := recordFor(t, s, before.Account.ID)
	if after.Pending != nil || after.Account.State != "suspended" || after.Account.Revision != before.Account.Revision+1 || !siteOf(t, f.sites, before.Account.ID).Suspended {
		t.Fatalf("refresh did not finish the suspend: %+v", after)
	}
}

func TestInterruptedSuspendIsFinishedByRefresh(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	before := liveFixture(t, s)
	f.failure = "sites"
	if _, err := suspend(s, before); !errors.Is(err, ErrRecovery) {
		t.Fatalf("suspend whose site list could not be installed: %v", err)
	}
	pending := recordFor(t, s, before.Account.ID)
	if pending.Pending == nil || pending.Pending.Action != "state" || f.users[before.Account.Username].Account.State != "suspended" || siteOf(t, f.sites, before.Account.ID).Suspended {
		t.Fatalf("expected a pending suspend with the user suspended and the site still served: %+v", pending)
	}
	// Still failing: it stays pending.
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil || recordFor(t, s, before.Account.ID).Pending == nil {
		t.Fatalf("a suspend whose site list still cannot be installed must stay pending: %v", err)
	}
	f.failure = ""
	s.mu.Lock()
	err = s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after := recordFor(t, s, before.Account.ID)
	if after.Pending != nil || after.Account.State != "suspended" || after.Account.Revision != before.Account.Revision+1 || !siteOf(t, f.sites, before.Account.ID).Suspended {
		t.Fatalf("refresh did not finish the suspend: %+v", after)
	}
}

func TestInterruptedSuspendCanEndRejected(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	before := liveFixture(t, s)
	f.failure = "sites"
	if _, err := suspend(s, before); !errors.Is(err, ErrRecovery) {
		t.Fatalf("interrupted suspend: %v", err)
	}
	// While the account cannot be put back, a rejected config stays pending.
	f.failure, f.refuseState = "sites-reject", "active"
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil || recordFor(t, s, before.Account.ID).Pending == nil {
		t.Fatalf("a rejected recovery whose account cannot be put back must stay pending: %v", err)
	}
	f.refuseState = ""
	s.mu.Lock()
	err = s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after := recordFor(t, s, before.Account.ID)
	if after.Pending != nil || after.Account != before.Account || f.users[before.Account.Username].Account.State != "active" {
		t.Fatalf("a recovered suspend whose config failed its test must end rejected and unchanged: %+v", after)
	}
}

// A crash after a rejected site list put the account back, and before the
// rejection was journaled, leaves the suspend pending with the account in
// its old state. The next start ends it rejected, unchanged, so it no
// longer blocks every account.
func TestSuspendInterruptedAfterUndoEndsRejected(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	before := liveFixture(t, s)
	// What setState does up to the crash: the intent, the account change,
	// a rejected site list, and the account put back.
	r := before
	r.Pending = &pending{Action: "state", Target: "suspended", Actor: "test operator", Reason: "Unpaid"}
	account := before.Account
	s.mu.Lock()
	r, err := s.beginOperation(r, &account)
	if err == nil {
		err = f.SetState(ctx, r, "suspended")
	}
	if err == nil {
		f.failure = "sites-reject"
		if e := s.applySites(ctx, []record{r}, r.Account.ID); !errors.Is(e, ErrWebRejected) {
			err = e
		}
		f.failure = ""
	}
	if err == nil {
		err = s.undoState(ctx, r)
	}
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	pending := recordFor(t, s, before.Account.ID)
	if pending.Pending == nil || f.users[before.Account.Username].Account.State != "active" {
		t.Fatalf("the crash fixture is not a pending suspend of an active account: %+v", pending)
	}

	s.mu.Lock()
	err = s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after := recordFor(t, s, before.Account.ID)
	if after.Pending != nil || after.Account != before.Account || after.HistorySequence != before.HistorySequence+2 {
		t.Fatalf("refresh did not end the suspend rejected and unchanged: %+v", after)
	}
	if got := historyActions(t, s, before.Account.ID); got[len(got)-1] != "state:rejected" {
		t.Fatalf("history %v", got)
	}
	// Nothing is pending, so the same request works now.
	if got, err := suspend(s, before); err != nil || got.State != "suspended" || !siteOf(t, f.sites, before.Account.ID).Suspended {
		t.Fatalf("suspend after the recovered crash: %+v %v", got, err)
	}
}

func TestStateChangeOfALiveSiteNeedsTheWebOperation(t *testing.T) {
	s, f := webStore(t)
	before := liveFixture(t, s)
	s.web = nil
	if _, err := suspend(s, before); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("suspend of a live site without the web operation: %v", err)
	}
	if after := recordFor(t, s, before.Account.ID); after != before || f.users[before.Account.Username].Account.State != "active" || f.siteApplies != 0 {
		t.Fatal("a refused suspend journaled or changed something")
	}
}
