package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func adopt(s *store, id string, revision uint64) (Account, error) {
	return s.adoptPublicHTML(context.Background(), id, AdoptInput{ExpectedRevision: revision, Reason: "The owner replaced public_html"}, "test operator")
}

func TestAdoptPublicHTMLRecordsTheTenantsFolder(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	tenant := liveFixture(t, s)
	tenantMovesPublicHTML(f, tenant.Account.Username)
	if a := listedAccount(t, s, tenant.Account.ID); !a.SiteFolderChanged {
		t.Fatalf("listed %+v", a)
	}
	grants := f.webGrants

	got, err := adopt(s, tenant.Account.ID, tenant.Account.Revision)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	after := recordFor(t, s, tenant.Account.ID)
	if got.Revision != tenant.Account.Revision+1 || got.SiteFolderChanged || got.Web != tenant.Web || got.State != "active" {
		t.Fatalf("answer %+v", got)
	}
	if after.Pending != nil || after.Ownership.Public != f.users[tenant.Account.Username].Ownership.Public || after.Ownership.Home != tenant.Ownership.Home || after.Ownership.Marker != tenant.Ownership.Marker {
		t.Fatalf("record %+v", after)
	}
	if f.adopts != 1 || f.webGrants != grants+1 {
		t.Fatalf("adopts %d, grants %d", f.adopts, f.webGrants-grants)
	}
	if rows := historyActions(t, s, tenant.Account.ID); !slices.Equal(rows[len(rows)-2:], []string{"adopt:intended", "adopt:succeeded"}) {
		t.Fatalf("history %v", rows)
	}
	if a := listedAccount(t, s, tenant.Account.ID); a.SiteFolderChanged || a.Revision != got.Revision {
		t.Fatalf("listed after adopt %+v", a)
	}
	// The site's own changes work again.
	f.missingPath = ""
	if _, err := s.setWeb(ctx, tenant.Account.ID, WebInput{PHPVersion: "8.2", QuotaMiB: 200, ExpectedRevision: got.Revision, Reason: "PHP change"}, "test operator"); err != nil {
		t.Fatalf("web change after adopt: %v", err)
	}

	// With the recorded folder in place there is nothing to adopt.
	again := recordFor(t, s, tenant.Account.ID)
	if same, err := adopt(s, tenant.Account.ID, again.Account.Revision); err != nil || same.Revision != again.Account.Revision || recordFor(t, s, tenant.Account.ID).HistorySequence != again.HistorySequence || f.adopts != 1 {
		t.Fatalf("adopt with nothing changed: %+v %v", same, err)
	}

	// An account without a site needs no web server access.
	plain := createFixtureNamed(t, s, "plainacct", "plain.test")
	tenantMovesPublicHTML(f, plain.Username)
	grants = f.webGrants
	if _, err := adopt(s, plain.ID, plain.Revision); err != nil || f.webGrants != grants {
		t.Fatalf("adopt without a site: %v, grants %d", err, f.webGrants-grants)
	}
}

func createFixtureNamed(t *testing.T, s *store, username, domain string) Account {
	t.Helper()
	a, err := s.create(context.Background(), CreateInput{Username: username, Domain: domain, Reason: "Synthetic core verification"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAdoptRefusalsJournalNothing(t *testing.T) {
	s, f := webStore(t)
	tenant := liveFixture(t, s)
	tenantMovesPublicHTML(f, tenant.Account.Username)
	unchanged := func(name string) {
		t.Helper()
		if after := recordFor(t, s, tenant.Account.ID); after.HistorySequence != tenant.HistorySequence || after.Pending != nil || after.Ownership != tenant.Ownership {
			t.Fatalf("%s: a refused adopt changed the record: %+v", name, after)
		}
	}
	for name, tc := range map[string]struct {
		id       string
		in       AdoptInput
		actor    string
		want     error
		setup    func()
		teardown func()
	}{
		"bad id":         {id: "x", in: AdoptInput{ExpectedRevision: tenant.Account.Revision, Reason: "r"}, actor: "op", want: ErrInvalid},
		"no revision":    {in: AdoptInput{Reason: "r"}, actor: "op", want: ErrInvalid},
		"no reason":      {in: AdoptInput{ExpectedRevision: tenant.Account.Revision}, actor: "op", want: ErrInvalid},
		"no actor":       {in: AdoptInput{ExpectedRevision: tenant.Account.Revision, Reason: "r"}, want: ErrInvalid},
		"stale revision": {in: AdoptInput{ExpectedRevision: tenant.Account.Revision + 1, Reason: "r"}, actor: "op", want: ErrConflict},
		"unknown":        {id: strings.Repeat("0", 32), in: AdoptInput{ExpectedRevision: 1, Reason: "r"}, actor: "op", want: ErrNotFound},
		"not a folder":   {in: AdoptInput{ExpectedRevision: tenant.Account.Revision, Reason: "r"}, actor: "op", want: ErrConflict, setup: func() { f.failure = "adopt" }, teardown: func() { f.failure = "" }},
		"installing":     {in: AdoptInput{ExpectedRevision: tenant.Account.Revision, Reason: "r"}, actor: "op", want: ErrConflict, setup: func() { s.installing = map[string]bool{tenant.Account.ID: true} }, teardown: func() { s.installing = nil }},
		"web off":        {in: AdoptInput{ExpectedRevision: tenant.Account.Revision, Reason: "r"}, actor: "op", want: ErrUnavailable, setup: func() { s.web = nil }, teardown: func() { s.web = &WebOptions{ServerUser: "nobody"} }},
		// The folder changed again before the grant: the tenant's, a conflict.
		"folder changed again": {in: AdoptInput{ExpectedRevision: tenant.Account.Revision, Reason: "r"}, actor: "op", want: ErrConflict, setup: func() { f.failure = "grant" }, teardown: func() { f.failure = "" }},
		// The ACL could not be written: the host's, unavailable.
		"acl not written": {in: AdoptInput{ExpectedRevision: tenant.Account.Revision, Reason: "r"}, actor: "op", want: ErrUnavailable, setup: func() { f.failure = "grant-acl" }, teardown: func() { f.failure = "" }},
	} {
		id := tc.id
		if id == "" {
			id = tenant.Account.ID
		}
		if tc.setup != nil {
			tc.setup()
		}
		_, err := s.adoptPublicHTML(context.Background(), id, tc.in, tc.actor)
		if tc.teardown != nil {
			tc.teardown()
		}
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v, want %v", name, err, tc.want)
		}
		unchanged(name)
	}
	// What only root controls changed too: adopting would not fix it.
	actual := f.users[tenant.Account.Username]
	actual.Ownership.Marker.Ino++
	f.users[tenant.Account.Username] = actual
	s.mu.Lock()
	r, err := s.records()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.adoptPublicHTML(context.Background(), tenant.Account.ID, AdoptInput{ExpectedRevision: r[0].Account.Revision, Reason: "r"}, "op"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("adopt while the marker changed: %v", err)
	}
}

// An earlier broker journaled a conflict for a tenant's folder change and
// refused every mutation because of it. That conflict still refuses them,
// as the journal says; adopting the folder ends it once what only root
// controls verifies, and nothing else is needed.
func TestAdoptEndsAConflictAnEarlierBrokerJournaled(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	tenant := liveFixture(t, s)
	other := createFixtureNamed(t, s, "secondacct", "second.test")
	tenantMovesPublicHTML(f, tenant.Account.Username)
	// What the earlier refresh journaled.
	r := recordFor(t, s, tenant.Account.ID)
	before := r.Account
	r.Pending = &pending{Action: "conflict", Target: r.Account.State, Actor: "broker-reconcile", Reason: "Managed operating system identity changed"}
	s.mu.Lock()
	r, err := s.beginOperation(r, &before)
	if err == nil {
		_, err = s.resultEvent(r, *r.Pending, "recovery_required")
	}
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.setPlan(ctx, other.ID, PlanInput{Plan: "larger", ExpectedRevision: other.Revision, Reason: "Plan"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("a journaled conflict no longer refuses mutations: %v", err)
	}
	// Another account cannot be adopted past it.
	tenantMovesPublicHTML(f, other.Username)
	if _, err := adopt(s, other.ID, other.Revision); !errors.Is(err, ErrRecovery) {
		t.Fatalf("adopt of another account past a conflict: %v", err)
	}

	got, err := adopt(s, tenant.Account.ID, tenant.Account.Revision)
	if err != nil {
		t.Fatalf("adopt of the conflicted account: %v", err)
	}
	if got.Revision != tenant.Account.Revision+1 || got.State != "active" || got.SiteFolderChanged {
		t.Fatalf("answer %+v", got)
	}
	want := []string{"conflict:intended", "conflict:recovery_required", "conflict:reconciled", "adopt:intended", "adopt:succeeded"}
	if rows := historyActions(t, s, tenant.Account.ID); !slices.Equal(rows[len(rows)-5:], want) {
		t.Fatalf("history %v", rows)
	}
	if _, err := s.setPlan(ctx, other.ID, PlanInput{Plan: "larger", ExpectedRevision: other.Revision, Reason: "Plan"}, "test operator"); err != nil {
		t.Fatalf("mutation after the conflict ended: %v", err)
	}
}

// The adopt's intent names the directory, so a restart between the intent
// and the result records it; until then the pending adopt refuses other
// mutations like any unfinished operation.
func TestInterruptedAdoptIsFinishedOnRestart(t *testing.T) {
	s, f, opts := setupStore(t)
	ctx := context.Background()
	tenant := createFixture(t, s)
	tenantMovesPublicHTML(f, tenant.Username)
	public := f.users[tenant.Username].Ownership.Public
	r := recordFor(t, s, tenant.ID)
	r.Pending = &pending{Action: "adopt", Target: publicTarget(public), Actor: "test operator", Reason: "The owner replaced public_html", OperationID: strings.Repeat("e", 32)}
	before, after := r.Account, r.Account
	after.Revision++
	s.mu.Lock()
	_, err := s.appendEvent(r, operationEvent{OperationID: r.Pending.OperationID, Action: "adopt", Status: "intended", Actor: r.Pending.Actor, Reason: r.Pending.Reason, Before: &before, After: after})
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Blocked"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("create beside a pending adopt: %v", err)
	}
	if a := listedAccount(t, s, tenant.ID); a.State != "recovery_required" {
		t.Fatalf("listed %+v", a)
	}
	s.close()
	reopened, err := openStore(ctx, opts, f)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	done := recordFor(t, reopened, tenant.ID)
	if done.Pending != nil || done.Ownership.Public != public || done.Account.Revision != tenant.Revision+1 || done.Actor != "test operator" {
		t.Fatalf("restart did not finish the adopt: %+v", done)
	}
	if rows := historyActions(t, reopened, tenant.ID); rows[len(rows)-1] != "adopt:reconciled" {
		t.Fatalf("history %v", rows)
	}
	if a := listedAccount(t, reopened, tenant.ID); a.State != "active" || a.SiteFolderChanged {
		t.Fatalf("listed after restart %+v", a)
	}

	// A pending adopt whose target is not a directory identity is refused,
	// though its journal is in order.
	bad := recordFor(t, reopened, tenant.ID)
	bad.Pending = &pending{Action: "adopt", Target: "007:12", Actor: "test operator", Reason: "r", OperationID: strings.Repeat("f", 32)}
	before, after = bad.Account, bad.Account
	after.Revision++
	reopened.mu.Lock()
	bad, err = reopened.appendEvent(bad, operationEvent{OperationID: bad.Pending.OperationID, Action: "adopt", Status: "intended", Actor: "test operator", Reason: "r", Before: &before, After: after})
	reopened.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.records(); !errors.Is(err, ErrRecovery) {
		t.Fatalf("a malformed adopt target was admitted: %v", err)
	}
	bad.Pending.Target = publicTarget(public)
	if reopened.save(bad) != nil {
		t.Fatal("fixture save")
	}
	if _, err := reopened.records(); err != nil {
		t.Fatalf("the same record with a good target: %v", err)
	}
}

func TestPublicTargetRoundTrip(t *testing.T) {
	for _, id := range []fileIdentity{{1, 1}, {64768, 131}, {^uint64(0), ^uint64(0)}} {
		if got, ok := parsePublicTarget(publicTarget(id)); !ok || got != id {
			t.Fatalf("%+v: %+v %v", id, got, ok)
		}
	}
	for _, bad := range []string{"", "1", "1:", ":1", "1:0", "01:2", "1:02", "1:2:3", "-1:2", "18446744073709551616:1", " 1:2"} {
		if _, ok := parsePublicTarget(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestAdoptHTTPAnswers(t *testing.T) {
	s, f := webStore(t)
	tenant := liveFixture(t, s)
	tenantMovesPublicHTML(f, tenant.Account.Username)
	post := func(id, body string) (int, string) {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+id+"/public-html", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(s).ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	body := func(revision uint64) string {
		b, err := json.Marshal(struct {
			Input AdoptInput `json:"input"`
			Actor string     `json:"actor"`
		}{AdoptInput{ExpectedRevision: revision, Reason: "The owner replaced public_html"}, "test operator"})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	id := tenant.Account.ID
	for name, tc := range map[string]struct {
		id, body string
		code     int
		answer   string
	}{
		"unknown key":    {id, strings.Replace(body(tenant.Account.Revision), `"reason"`, `"comment"`, 1), 400, `"invalid"`},
		"missing reason": {id, `{"actor":"test operator","input":{"expected_revision":2}}`, 400, `"invalid"`},
		"bad id":         {"not-an-id", body(tenant.Account.Revision), 400, `"invalid"`},
		"stale revision": {id, body(tenant.Account.Revision + 1), 409, `"conflict"`},
	} {
		if code, out := post(tc.id, tc.body); code != tc.code || !strings.Contains(out, tc.answer) {
			t.Fatalf("%s: %d %s", name, code, out)
		}
	}
	f.failure = "adopt"
	if code, out := post(id, body(tenant.Account.Revision)); code != 409 || !strings.Contains(out, `"conflict"`) {
		t.Fatalf("not a folder: %d %s", code, out)
	}
	f.failure = ""
	if f.adopts != 1 || recordFor(t, s, id).HistorySequence != tenant.HistorySequence {
		t.Fatal("a refused request journaled something or reached the native step")
	}
	code, out := post(id, body(tenant.Account.Revision))
	var got Account
	if code != 200 || json.Unmarshal([]byte(out), &got) != nil || got.ID != id || got.Revision != tenant.Account.Revision+1 || got.SiteFolderChanged || got.Web != tenant.Web {
		t.Fatalf("adopt: %d %s", code, out)
	}
	if strings.Contains(out, "site_folder_changed") {
		t.Fatalf("the answer names a folder change that is gone: %s", out)
	}
}

func TestAdoptClientChecksBeforeSending(t *testing.T) {
	c := NewClient("").(SiteFolderService)
	id := strings.Repeat("a", 32)
	if _, err := c.AdoptPublicHTML(context.Background(), id, AdoptInput{ExpectedRevision: 2, Reason: "r"}, "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unconfigured client: %v", err)
	}
	for name, tc := range map[string]struct {
		id    string
		in    AdoptInput
		actor string
	}{
		"bad id":      {"x", AdoptInput{ExpectedRevision: 2, Reason: "r"}, "op"},
		"no revision": {id, AdoptInput{Reason: "r"}, "op"},
		"no reason":   {id, AdoptInput{ExpectedRevision: 2}, "op"},
		"no actor":    {id, AdoptInput{ExpectedRevision: 2, Reason: "r"}, ""},
	} {
		if _, err := c.AdoptPublicHTML(context.Background(), tc.id, tc.in, tc.actor); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
