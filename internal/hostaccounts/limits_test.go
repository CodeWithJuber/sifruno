package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/olsweb"
)

// The fake's slice drop-ins: ApplyLimits writes (unless told to fail first)
// and reloads, RemoveLimits removes, SyncLimits writes the wanted set and
// removes the rest, each validating the UID as the native system does.
func (f *fakeNative) ApplyLimits(ctx context.Context, uid int, l AccountLimits) error {
	f.limitsLog = append(f.limitsLog, fmt.Sprintf("apply %d %+v", uid, l))
	if !validLimitUID(uid) || !validLimits(l) {
		return ErrInvalid
	}
	// limitsDelay is a slow systemd reload: the native system gives up, as
	// its commands do, when its context ends first.
	if f.limitsDelay > 0 {
		select {
		case <-time.After(f.limitsDelay):
		case <-ctx.Done():
			return ErrUnavailable
		}
	}
	if f.failLimits > 0 {
		f.failLimits--
		return ErrUnavailable
	}
	if f.dropIns == nil {
		f.dropIns = map[int]AccountLimits{}
	}
	f.dropIns[uid] = l
	if f.failLimitsAfter > 0 {
		f.failLimitsAfter--
		return ErrUnavailable
	}
	f.reloads++
	return nil
}
func (f *fakeNative) VerifyLimits(uid int, l AccountLimits) error {
	if got, ok := f.dropIns[uid]; !ok || got != l {
		return ErrRecovery
	}
	return nil
}
func (f *fakeNative) RemoveLimits(_ context.Context, uid int) error {
	f.limitsLog = append(f.limitsLog, fmt.Sprintf("remove %d", uid))
	if !validLimitUID(uid) {
		return ErrInvalid
	}
	if f.failure == "limits-remove" {
		return ErrUnavailable
	}
	delete(f.dropIns, uid)
	f.reloads++
	return nil
}
func (f *fakeNative) RemoveSiteCache(_ context.Context, id string) error {
	if !idPattern.MatchString(id) {
		return ErrInvalid
	}
	if f.failure == "cache-remove" {
		return ErrUnavailable
	}
	f.cachesRemoved = append(f.cachesRemoved, id)
	return nil
}
func (f *fakeNative) WriteSiteRealms(_ context.Context, site string, files map[string][]byte) error {
	if !siteDirPattern.MatchString(site) || len(files) == 0 {
		return ErrInvalid
	}
	if f.failure == "realms-write" {
		return ErrUnavailable
	}
	if f.realms == nil {
		f.realms = map[string]map[string][]byte{}
	}
	f.realms[site] = files
	return nil
}
func (f *fakeNative) RemoveSiteRealms(_ context.Context, site string) error {
	if !siteDirPattern.MatchString(site) {
		return ErrInvalid
	}
	delete(f.realms, site)
	f.realmsRemoved = append(f.realmsRemoved, site)
	return nil
}
func (f *fakeNative) SyncLimits(_ context.Context, want map[int]AccountLimits) error {
	f.limitsLog = append(f.limitsLog, fmt.Sprintf("sync %d", len(want)))
	f.dropIns = map[int]AccountLimits{}
	for uid, l := range want {
		if !validLimitUID(uid) || !validLimits(l) {
			return ErrInvalid
		}
		f.dropIns[uid] = l
	}
	f.reloads++
	return nil
}

// limitRows is the account's journal rows of one action, oldest first.
func limitRows(t *testing.T, s *store, id, action string) []operationEvent {
	t.Helper()
	var rows []operationEvent
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(historyBucket).Cursor()
		prefix := []byte(id + "/")
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var e operationEvent
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Action == action {
				rows = append(rows, e)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

var bigger = AccountLimits{Processes: 200, MemoryMiB: 2048, CPUPercent: 200}

func TestSliceDropInContentAndPath(t *testing.T) {
	got, err := renderSliceLimits(DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Written by the Sifruno broker for one hosting account. Do not edit:\n# the broker rewrites it when the account's plan changes and at its start.\n[Slice]\nTasksMax=100\nMemoryMax=1024M\nCPUQuota=100%\n"
	if string(got) != want {
		t.Fatalf("drop-in:\n%s", got)
	}
	if dir, err := sliceDropInDir(20000); err != nil || dir != "user-20000.slice.d" {
		t.Fatalf("dir %q %v", dir, err)
	}
	if dir, err := sliceDropInDir(60000); err != nil || dir != "user-60000.slice.d" {
		t.Fatalf("dir %q %v", dir, err)
	}
	// Root, system users, the nobody UID and anything outside the account
	// range never name a drop-in.
	for _, uid := range []int{0, 1, 48, 999, 1000, 19999, 60001, 65534, -1, -20000, 1 << 31} {
		if dir, err := sliceDropInDir(uid); err == nil || dir != "" {
			t.Fatalf("UID %d gave %q", uid, dir)
		}
	}
	for _, l := range []AccountLimits{{}, {Processes: 31, MemoryMiB: 1024, CPUPercent: 100}, {Processes: 100, MemoryMiB: 255, CPUPercent: 100}, {Processes: 100, MemoryMiB: 1024, CPUPercent: 9}, {Processes: 4097, MemoryMiB: 1024, CPUPercent: 100}, {Processes: 100, MemoryMiB: 65537, CPUPercent: 100}, {Processes: 100, MemoryMiB: 1024, CPUPercent: 6401}} {
		if _, err := renderSliceLimits(l); err == nil {
			t.Fatalf("limits %+v rendered", l)
		}
	}
	if !validLimits(DefaultLimits) || !validLimits(AccountLimits{Processes: 32, MemoryMiB: 256, CPUPercent: 10}) || !validLimits(AccountLimits{Processes: 4096, MemoryMiB: 65536, CPUPercent: 6400}) {
		t.Fatal("bounds refuse their own edges")
	}
}

func TestCreateAppliesDefaultLimitsFirst(t *testing.T) {
	s, f, _ := setupStore(t)
	a := createFixture(t, s)
	if a.Limits != DefaultLimits || f.dropIns[a.UID] != DefaultLimits || f.reloads != 1 {
		t.Fatalf("account %+v drop-ins %+v reloads %d", a.Limits, f.dropIns, f.reloads)
	}
	rows := limitRows(t, s, a.ID, "create")
	if len(rows) != 2 || rows[0].After.Limits != DefaultLimits || rows[1].After.Limits != DefaultLimits {
		t.Fatalf("create rows do not record the limits: %+v", rows)
	}
	if listedAccount(t, s, a.ID).Limits != DefaultLimits {
		t.Fatal("the list does not show the limits")
	}
}

func TestCreateRefusedWhenLimitsFail(t *testing.T) {
	s, f, _ := setupStore(t)
	f.failLimits = 1
	if _, err := s.create(context.Background(), CreateInput{Username: "limitless", Domain: "limitless.test", Reason: "No limits"}, "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("create without its limits: %v", err)
	}
	if items, err := s.list(context.Background()); err != nil || len(items) != 0 || len(f.users) != 0 {
		t.Fatalf("a refused create left %d accounts, %d users: %v", len(items), len(f.users), err)
	}
	// Nothing was journaled, so nothing holds up the next create.
	a := createFixture(t, s)
	if a.State != "active" || f.dropIns[a.UID] != DefaultLimits {
		t.Fatalf("next create: %+v", a)
	}
}

func TestPlanChangeAppliesAndJournalsLimits(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	got, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: bigger, ExpectedRevision: a.Revision, Reason: "Bigger plan"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if got.Plan != "gold" || got.Limits != bigger || got.Revision != a.Revision+1 || f.dropIns[a.UID] != bigger {
		t.Fatalf("after: %+v drop-in %+v", got, f.dropIns[a.UID])
	}
	rows := limitRows(t, s, a.ID, "plan")
	if len(rows) != 2 || rows[0].Status != "intended" || rows[1].Status != "succeeded" || rows[0].Before.Limits != DefaultLimits || rows[0].After.Limits != bigger || rows[1].After.Limits != bigger {
		t.Fatalf("plan rows: %+v", rows)
	}
	// The same plan and limits again change nothing while the drop-in holds them.
	same, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: bigger, ExpectedRevision: got.Revision, Reason: "Again"}, "test operator")
	if err != nil || same.Revision != got.Revision || len(limitRows(t, s, a.ID, "plan")) != 2 {
		t.Fatalf("unchanged plan: %+v %v", same, err)
	}
	// Leaving the limits out keeps them; only the name changes.
	renamed, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold-2", ExpectedRevision: got.Revision, Reason: "Rename"}, "test operator")
	if err != nil || renamed.Limits != bigger || renamed.Plan != "gold-2" {
		t.Fatalf("rename: %+v %v", renamed, err)
	}
	// A drop-in changed outside the broker is written again, journaled.
	f.dropIns[a.UID] = DefaultLimits
	again, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold-2", ExpectedRevision: renamed.Revision, Reason: "Repair"}, "test operator")
	if err != nil || again.Revision != renamed.Revision+1 || f.dropIns[a.UID] != bigger {
		t.Fatalf("repair: %+v %v drop-in %+v", again, err, f.dropIns[a.UID])
	}
	if _, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: AccountLimits{Processes: 1}, ExpectedRevision: again.Revision, Reason: "Too small"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("out-of-bounds limits: %v", err)
	}
}

// A drop-in that cannot be written or loaded ends the plan change rejected:
// the old drop-in goes back, the account is unchanged, and every account
// can still change, this one included.
func TestPlanLimitsRejectedChangesNothing(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	other, err := s.create(ctx, CreateInput{Username: "otheracct", Domain: "other.test", Reason: "Other"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(){
		"write fails":  func() { f.failLimits = 1 },
		"reload fails": func() { f.failLimitsAfter = 1 },
	} {
		setup()
		if _, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: bigger, ExpectedRevision: a.Revision, Reason: "Bigger"}, "test operator"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
		listed := listedAccount(t, s, a.ID)
		if listed.Plan != "default" || listed.Limits != DefaultLimits || listed.Revision != a.Revision || listed.State != "active" || f.dropIns[a.UID] != DefaultLimits {
			t.Fatalf("%s: account %+v drop-in %+v", name, listed, f.dropIns[a.UID])
		}
		rows := limitRows(t, s, a.ID, "plan")
		if last := rows[len(rows)-1]; last.Status != "rejected" || last.After != *last.Before {
			t.Fatalf("%s: last plan row %+v", name, last)
		}
	}
	if _, err := s.setState(ctx, other.ID, StateInput{State: "suspended", ExpectedRevision: other.Revision, Reason: "Others go on"}, "test operator"); err != nil {
		t.Fatalf("another account is held up: %v", err)
	}
	if got, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: bigger, ExpectedRevision: a.Revision, Reason: "Bigger"}, "test operator"); err != nil || got.Limits != bigger {
		t.Fatalf("the account itself is held up: %+v %v", got, err)
	}
}

// A live site's PHP gets the plan's limits through the site list; a config
// that fails its test puts the old drop-in back and ends rejected.
func TestPlanLimitsReachLiveSitePHP(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := liveSite(t, s, createFixture(t, s))
	want := olsweb.Limits{PHPChildren: 4, MemoryMiB: 1024, Processes: olsweb.ProcessFloor(4, 0)}
	if len(f.sites) != 1 || f.sites[0].Limits != want || f.sites[0].Isolation != (olsweb.Isolation{Namespace: true, CGroups: true}) {
		t.Fatalf("site with the default limits: %+v", f.sites)
	}
	f.failure = "sites-reject"
	if _, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: bigger, ExpectedRevision: a.Revision, Reason: "Bigger"}, "test operator"); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("rejected config: %v", err)
	}
	if f.dropIns[a.UID] != DefaultLimits || listedAccount(t, s, a.ID).Limits != DefaultLimits {
		t.Fatal("a rejected config left the new limits")
	}
	f.failure = ""
	huge := AccountLimits{Processes: 1000, MemoryMiB: 4096, CPUPercent: 400}
	got, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: huge, ExpectedRevision: a.Revision, Reason: "Bigger"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	want = olsweb.Limits{PHPChildren: 4, MemoryMiB: 4096, Processes: 1000}
	if got.Limits != huge || f.sites[0].Limits != want {
		t.Fatalf("site after the plan change: %+v", f.sites[0].Limits)
	}
	// A plan rename keeps the limits and does not rewrite the site list.
	applies := f.siteApplies
	if _, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold-2", ExpectedRevision: got.Revision, Reason: "Rename"}, "test operator"); err != nil || f.siteApplies != applies {
		t.Fatalf("rename rewrote the site list: %v", err)
	}
	// Without the web operation, new limits for a live site are refused
	// before anything is journaled.
	s.web = nil
	rows := len(limitRows(t, s, a.ID, "plan"))
	if _, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold-2", Limits: bigger, ExpectedRevision: got.Revision + 1, Reason: "No web"}, "test operator"); !errors.Is(err, ErrUnavailable) || len(limitRows(t, s, a.ID, "plan")) != rows {
		t.Fatalf("limits without the web operation: %v", err)
	}
}

// A plan change whose site list did not finish stays pending; the next
// start applies its limits and finishes it.
func TestPlanLimitsRecoveredAtStart(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := liveSite(t, s, createFixture(t, s))
	f.failure = "sites"
	if _, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: bigger, ExpectedRevision: a.Revision, Reason: "Bigger"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("unfinished site list: %v", err)
	}
	if r := recordFor(t, s, a.ID); r.Pending == nil || r.Pending.Action != "plan" || r.LimitsNext != bigger {
		t.Fatalf("pending record: %+v", r)
	}
	f.failure = ""
	if err := s.refresh(ctx, true); err != nil {
		t.Fatal(err)
	}
	r := recordFor(t, s, a.ID)
	if r.Pending != nil || r.Account.Limits != bigger || r.Account.Plan != "gold" || r.LimitsNext != (AccountLimits{}) || f.dropIns[a.UID] != bigger || f.sites[0].Limits.MemoryMiB != 2048 {
		t.Fatalf("after the start: %+v drop-in %+v", r, f.dropIns[a.UID])
	}
	rows := limitRows(t, s, a.ID, "plan")
	if last := rows[len(rows)-1]; last.Status != "reconciled" || last.After.Limits != bigger {
		t.Fatalf("last plan row %+v", last)
	}
}

func TestDeleteRemovesLimits(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.dropIns[a.UID]; ok {
		t.Fatal("the deleted account's drop-in is still there")
	}
	// A removal that fails does not undo or fail the delete: the next start
	// removes the leftover, because no account holds its UID.
	b, err := s.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Second"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	f.failure = "limits-remove"
	if _, err := s.delete(ctx, b.ID, DeleteInput{ExpectedRevision: b.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatalf("delete with a failed drop-in removal: %v", err)
	}
	if _, ok := f.dropIns[b.UID]; !ok {
		t.Fatal("the fake removed a drop-in it was told to keep")
	}
	f.failure = ""
	if err := s.syncLimitsAtStart(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.dropIns[b.UID]; ok || len(f.dropIns) != 0 {
		t.Fatalf("drop-ins after the start: %+v", f.dropIns)
	}
}

// A delete whose drop-in removal failed leaves the drop-in of a freed UID
// with the deleted account's limits. The next account given that UID never
// runs under them: create writes the default drop-in for its UID before
// useradd makes the user.
func TestLeftoverDropInNeverReachesTheNextAccount(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	bigger := AccountLimits{Processes: 400, MemoryMiB: 4096, CPUPercent: 300}
	a, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", Limits: bigger, ExpectedRevision: a.Revision, Reason: "Bigger"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	f.failure = "limits-remove"
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	f.failure = ""
	if f.dropIns[a.UID] != bigger {
		t.Fatalf("fixture: the leftover drop-in is %+v", f.dropIns[a.UID])
	}
	b, err := s.create(ctx, CreateInput{Username: "nextacct", Domain: "next.test", Reason: "Same UID"}, "test operator")
	if err != nil || b.UID != a.UID {
		t.Fatalf("the freed UID was not given again: %+v %v", b, err)
	}
	if got := f.createdWith[b.UID]; got != DefaultLimits {
		t.Fatalf("the user was made under the drop-in %+v, not the defaults", got)
	}
	if f.dropIns[b.UID] != DefaultLimits || b.Limits != DefaultLimits {
		t.Fatalf("the new account's limits: drop-in %+v, account %+v", f.dropIns[b.UID], b.Limits)
	}
}

// A slow limits step (a systemd reload on a busy host) does not make a
// create fail at the caller's limit: the slice limits and the user's
// creation run on the web operation's own limit, and the account is made.
func TestSlowLimitsDoNotFailCreateAtTheRequestLimit(t *testing.T) {
	s, f, _ := setupStore(t)
	f.limitsDelay = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	a, err := s.create(ctx, CreateInput{Username: "slowlimits", Domain: "slow.test", Reason: "Slow reload"}, "test operator")
	if err != nil || a.State != "active" || a.Limits != DefaultLimits {
		t.Fatalf("create with a slow limits step: %+v %v", a, err)
	}
	if ctx.Err() == nil {
		t.Fatal("the caller's limit did not pass during the create")
	}
	if got, ok := f.dropIns[a.UID]; !ok || got != DefaultLimits {
		t.Fatalf("drop-in %+v %v", got, ok)
	}
	accounts, err := s.list(context.Background())
	if err != nil || len(accounts) != 1 || accounts[0].ID != a.ID || accounts[0].State != "active" {
		t.Fatalf("list after the create: %+v %v", accounts, err)
	}
}

// A delete takes the site's LSCache store away with the web operation on,
// after the user is gone; a removal that fails does not fail the delete, and
// the broker logs the store it left. Without the web operation there is no
// store to remove.
func TestDeleteRemovesTheSiteCache(t *testing.T) {
	logged := captureRecoveryLog(t)
	s, f := webStore(t)
	ctx := context.Background()
	a := liveFixture(t, s)
	if _, err := s.delete(ctx, a.Account.ID, DeleteInput{ExpectedRevision: a.Account.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.cachesRemoved, []string{a.Account.ID}) {
		t.Fatalf("stores removed: %q", f.cachesRemoved)
	}
	if strings.Contains(logged.String(), "cleanup:") {
		t.Fatalf("a removed store was logged as left: %s", logged)
	}
	b := liveAccount(t, s, "secondacct", "second.test")
	f.failure = "cache-remove"
	if _, err := s.delete(ctx, b.Account.ID, DeleteInput{ExpectedRevision: b.Account.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatalf("delete with a failed store removal: %v", err)
	}
	if len(f.cachesRemoved) != 1 {
		t.Fatalf("stores removed: %q", f.cachesRemoved)
	}
	want := "sifruno broker: cleanup: account=" + b.Account.ID + ` step="remove the site's page cache ` +
		olsweb.CacheRoot + "/sifruno-u" + b.Account.ID[:31] + `" error="unavailable"` + "\n"
	if logged.String() != want {
		t.Fatalf("log:\n%s\nwant:\n%s", logged, want)
	}

	plain, g, _ := setupStore(t)
	c := createFixture(t, plain)
	if _, err := plain.delete(ctx, c.ID, DeleteInput{ExpectedRevision: c.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if len(g.cachesRemoved) != 0 {
		t.Fatalf("a broker without the web operation removed a store: %q", g.cachesRemoved)
	}
}

// At start every account gets its recorded limits, and one recorded before
// limits were gets the defaults; the list shows them either way.
func TestSyncLimitsAtStart(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	b, err := s.create(ctx, CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Second"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if b, err = s.setPlan(ctx, b.ID, PlanInput{Plan: "gold", Limits: bigger, ExpectedRevision: b.Revision, Reason: "Bigger"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	f.dropIns = map[int]AccountLimits{59999: DefaultLimits}
	if err := s.syncLimitsAtStart(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.dropIns) != 2 || f.dropIns[a.UID] != DefaultLimits || f.dropIns[b.UID] != bigger {
		t.Fatalf("drop-ins: %+v", f.dropIns)
	}
	if r := recordFor(t, s, a.ID); limitsOf(r.Account) != DefaultLimits || limitsOf(Account{}) != DefaultLimits {
		t.Fatal("an account without recorded limits must run with the defaults")
	}
}

// The plan route admits limits only as one object with exactly its three
// keys, each once, as whole numbers in bounds.
func TestPlanLimitsHTTPContract(t *testing.T) {
	s, f, _ := setupStore(t)
	a := createFixture(t, s)
	h := handler(s)
	post := func(payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+a.ID+"/plan", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	input := func(limits string) string {
		return `{"actor":"a","input":{"plan":"gold","limits":` + limits + `,"expected_revision":1,"reason":"r"}}`
	}
	writes := len(f.limitsLog)
	for name, payload := range map[string]string{
		"null limits":    input(`null`),
		"limits a list":  input(`[200,2048,200]`),
		"missing key":    input(`{"processes":200,"memory_mib":2048}`),
		"unknown key":    input(`{"processes":200,"memory_mib":2048,"cpu_percent":200,"io_weight":10}`),
		"duplicate key":  input(`{"processes":200,"processes":20,"memory_mib":2048,"cpu_percent":200}`),
		"case alias":     input(`{"Processes":200,"memory_mib":2048,"cpu_percent":200}`),
		"text number":    input(`{"processes":"200","memory_mib":2048,"cpu_percent":200}`),
		"below bounds":   input(`{"processes":1,"memory_mib":2048,"cpu_percent":200}`),
		"fraction":       input(`{"processes":200.5,"memory_mib":2048,"cpu_percent":200}`),
		"null processes": input(`{"processes":null,"memory_mib":2048,"cpu_percent":200}`),
		"all zeros":      input(`{"processes":0,"memory_mib":0,"cpu_percent":0}`),
		"trailing data":  input(`{"processes":200,"memory_mib":2048,"cpu_percent":200} `) + "{}",
	} {
		if rec := post(payload); rec.Code != 400 {
			t.Fatalf("%s: status %d %s", name, rec.Code, rec.Body)
		}
	}
	if len(f.limitsLog) != writes {
		t.Fatal("a refused request reached the native system")
	}
	rec := post(input(`{"processes":200,"memory_mib":2048,"cpu_percent":200}`))
	var got Account
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Limits != bigger || got.Revision != 2 {
		t.Fatalf("plan over HTTP: %d %s", rec.Code, rec.Body)
	}
	// Without limits the route still takes a plan name alone.
	rec = post(`{"actor":"a","input":{"plan":"silver","expected_revision":2,"reason":"r"}}`)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Plan != "silver" || got.Limits != bigger {
		t.Fatalf("plan name alone: %d %s", rec.Code, rec.Body)
	}
}
