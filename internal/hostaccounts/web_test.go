package hostaccounts

import (
	"context"
	"errors"
	"testing"
)

func webStore(t *testing.T) (*store, *fakeNative) {
	t.Helper()
	s, f, _ := setupStore(t)
	s.web = &WebOptions{ServerUser: "nobody"}
	return s, f
}

func recordFor(t *testing.T, s *store, id string) record {
	t.Helper()
	items, err := s.records()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range items {
		if r.Account.ID == id {
			return r
		}
	}
	t.Fatal("record missing")
	return record{}
}

func TestWebOperationOffByDefault(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	if _, err := s.setWeb(context.Background(), a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("web without --web-user: %v", err)
	}
}

func TestWebOperationGoesLiveAndJournals(t *testing.T) {
	s, f := webStore(t)
	a := createFixture(t, s)
	ctx := context.Background()
	for _, bad := range []WebInput{
		{PHPVersion: "7.4", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"},
		{PHPVersion: "8.3", QuotaMiB: 10, ExpectedRevision: a.Revision, Reason: "Go live"},
		{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: 0, Reason: "Go live"},
		{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: ""},
	} {
		if _, err := s.setWeb(ctx, a.ID, bad, "test operator"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	if _, err := s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision + 1, Reason: "Go live"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	got, err := s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if got.Web != (WebState{PHPVersion: "8.3", QuotaMiB: 200}) || got.Account.Revision != a.Revision+1 {
		t.Fatalf("result %+v", got)
	}
	if f.webGrants != 1 || f.webApply != 1 || len(f.sites) != 1 {
		t.Fatalf("grant %d, apply %d, sites %d", f.webGrants, f.webApply, len(f.sites))
	}
	site := f.sites[0]
	if site.Name != siteName(a.ID) || site.Username != a.Username || site.Group != a.Username || site.DocRoot != a.PublicHTML || site.PHPVersion != "8.3" || len(site.Domains) != 1 || site.Domains[0] != a.Domain || !site.Isolation.Namespace {
		t.Fatalf("site %+v", site)
	}
	r := recordFor(t, s, a.ID)
	if r.Web != got.Web || r.WebNext != (WebState{}) || r.Pending != nil {
		t.Fatal("record not updated")
	}
}

func TestWebRefusalsLeaveNothingPending(t *testing.T) {
	s, f := webStore(t)
	a := createFixture(t, s)
	ctx := context.Background()
	in := WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}

	// The tenant changed its own directories: refused before the journal.
	before := recordFor(t, s, a.ID)
	f.failure = "grant"
	if _, err := s.setWeb(ctx, a.ID, in, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("grant refused: %v", err)
	}
	if after := recordFor(t, s, a.ID); after != before || f.webApply != 0 {
		t.Fatal("a refused grant journaled or applied something")
	}

	// The config test failed and the old files went back: journaled as
	// rejected, the account unchanged and nothing left pending.
	f.failure = "web-reject"
	if _, err := s.setWeb(ctx, a.ID, in, "test operator"); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("rejected config: %v", err)
	}
	after := recordFor(t, s, a.ID)
	if after.Pending != nil || after.Account != before.Account || after.Web != (WebState{}) || after.WebNext != (WebState{}) || after.HistorySequence != before.HistorySequence+2 {
		t.Fatalf("a rejected config changed the account: %+v", after)
	}
	// Other operations are not blocked, and the same request works later.
	f.failure = ""
	if _, err := s.setWeb(ctx, a.ID, in, "test operator"); err != nil {
		t.Fatalf("retry after rejection: %v", err)
	}
}

func TestWebInterruptedApplyIsFinishedByRefresh(t *testing.T) {
	s, f := webStore(t)
	a := createFixture(t, s)
	ctx := context.Background()
	f.failure = "web-after"
	if _, err := s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.2", QuotaMiB: 500, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	r := recordFor(t, s, a.ID)
	if r.Pending == nil || r.Pending.Action != "web" || r.WebNext != (WebState{PHPVersion: "8.2", QuotaMiB: 500}) {
		t.Fatalf("pending web op not durable: %+v", r.Pending)
	}
	f.failure = ""
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r = recordFor(t, s, a.ID)
	if r.Pending != nil || r.Web != (WebState{PHPVersion: "8.2", QuotaMiB: 500}) || r.WebNext != (WebState{}) || r.Account.Revision != a.Revision+1 {
		t.Fatalf("refresh did not finish the web op: %+v %+v", r.Web, r.Pending)
	}
}

func TestWebRecoveryCanEndRejected(t *testing.T) {
	s, f := webStore(t)
	a := createFixture(t, s)
	ctx := context.Background()
	f.failure = "web-before"
	if _, err := s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	f.failure = "web-reject"
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r := recordFor(t, s, a.ID)
	if r.Pending != nil || r.Web != (WebState{}) || r.Account.Revision != a.Revision {
		t.Fatalf("recovery that failed its test must end rejected and unchanged: %+v", r)
	}
}

func TestDeleteRemovesTheSiteFirst(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	b, err := s.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Synthetic core verification"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	for _, acct := range []Account{a, b} {
		if _, err := s.setWeb(ctx, acct.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: acct.Revision, Reason: "Go live"}, "test operator"); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.sites) != 2 {
		t.Fatalf("both sites must be listed, got %d", len(f.sites))
	}
	// A normal delete takes only that site out of the server config.
	second := recordFor(t, s, b.ID)
	if _, err := s.delete(ctx, b.ID, DeleteInput{ExpectedRevision: second.Account.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if len(f.sites) != 1 || f.sites[0].Username != a.Username {
		t.Fatalf("remaining sites %+v", f.sites)
	}
	if _, ok := f.users[b.Username]; ok {
		t.Fatal("the deleted user is still there")
	}
	// If the site cannot be taken out, the user and home are not deleted.
	current := recordFor(t, s, a.ID)
	f.failure = "sites"
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: current.Account.Revision, Reason: "Remove"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("delete when the site cannot be removed: %v", err)
	}
	if _, ok := f.users[a.Username]; !ok || len(f.sites) != 1 {
		t.Fatal("the user was deleted although its site is still configured")
	}
}

func TestDeleteEndsRejectedWhenTheConfigFailsItsTest(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	if _, err := s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	before := recordFor(t, s, a.ID)
	f.failure = "sites-reject"
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: before.Account.Revision, Reason: "Remove"}, "test operator"); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("delete with a rejected config: %v", err)
	}
	after := recordFor(t, s, a.ID)
	if after.Pending != nil || after.Account != before.Account || after.Web != before.Web || after.HistorySequence != before.HistorySequence+2 {
		t.Fatalf("a rejected delete changed the account or left it pending: %+v", after)
	}
	if _, ok := f.users[a.Username]; !ok {
		t.Fatal("the user went although its site could not be taken out")
	}
	// Nothing is pending, so the next request works.
	f.failure = ""
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: before.Account.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatalf("delete after the rejection: %v", err)
	}
}

func TestInterruptedDeleteCanEndRejected(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	if _, err := s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	before := recordFor(t, s, a.ID)
	f.failure = "sites"
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: before.Account.Revision, Reason: "Remove"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("interrupted delete: %v", err)
	}
	f.failure = "sites-reject"
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after := recordFor(t, s, a.ID)
	if after.Pending != nil || after.Account != before.Account {
		t.Fatalf("a recovered delete whose config failed its test must end rejected: %+v", after)
	}
	if _, ok := f.users[a.Username]; !ok {
		t.Fatal("the user went although its site could not be taken out")
	}
}

func TestWebLeavesRoomInTheHistory(t *testing.T) {
	s, _ := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	revision := a.Revision
	var err error
	for i := 0; i < MaxHistoryRows; i++ {
		var got WebResult
		got, err = s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200 + i%2, ExpectedRevision: revision, Reason: "Resize"}, "test operator")
		if err != nil {
			break
		}
		revision = got.Account.Revision
	}
	r := recordFor(t, s, a.ID)
	if !errors.Is(err, ErrConflict) || r.Pending != nil || r.HistorySequence > MaxHistoryRows-1 || r.HistorySequence <= MaxHistoryRows-3 {
		t.Fatalf("a full history must refuse before journaling: %v, sequence %d, pending %v", err, r.HistorySequence, r.Pending)
	}
}
