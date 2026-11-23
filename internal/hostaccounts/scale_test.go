package hostaccounts

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func createMany(t testing.TB, s *store, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		in := CreateInput{Username: fmt.Sprintf("acct%05d", i), Domain: fmt.Sprintf("site%05d.test", i), Reason: "Scale fixture"}
		if _, e := s.create(context.Background(), in, "test operator"); e != nil {
			t.Fatalf("account %d: %v", i, e)
		}
	}
}

// Every request checks every account's files, and a rotating batch of
// auditBatch accounts also gets the costly full check. No account may be
// skipped by the file check, and every account must come up for the full
// check within a bounded number of requests.
func TestRollingAuditCoversEveryAccount(t *testing.T) {
	s, f, _ := setupStore(t)
	const accounts = 2*auditBatch + 8
	createMany(t, s, 0, accounts)
	ctx := context.Background()
	rounds := (accounts + auditBatch - 1) / auditBatch
	for round := 1; round <= rounds; round++ {
		f.full, f.cheap = map[string]int{}, map[string]int{}
		if _, e := s.list(ctx); e != nil {
			t.Fatal(e)
		}
		if len(f.full) != auditBatch {
			t.Fatalf("round %d ran %d full checks, want %d", round, len(f.full), auditBatch)
		}
		for i := 0; i < accounts; i++ {
			name := fmt.Sprintf("acct%05d", i)
			// The full check includes the file check, so one of the two must
			// have run for this account in this request.
			if f.full[name]+f.cheap[name] != 1 {
				t.Fatalf("round %d: %s checked %d full, %d file-only", round, name, f.full[name], f.cheap[name])
			}
		}
	}
	// Count again across one whole rotation.
	f.full, f.cheap = map[string]int{}, map[string]int{}
	for round := 0; round < rounds; round++ {
		if _, e := s.list(ctx); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < accounts; i++ {
		if name := fmt.Sprintf("acct%05d", i); f.full[name] == 0 {
			t.Fatalf("%s never reached the full check in %d requests", name, rounds)
		}
	}
}

// The rotation follows account IDs, so creating and deleting accounts between
// requests cannot make it skip one: every account that exists for a whole
// rotation is fully checked within it.
func TestRollingAuditStaysFairWhileAccountsChange(t *testing.T) {
	s, f, _ := setupStore(t)
	ctx := context.Background()
	createMany(t, s, 0, 3*auditBatch)
	stable := map[string]bool{}
	items, e := s.records()
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range items {
		stable[r.Account.Username] = true
	}
	f.full = map[string]int{}
	next := 3 * auditBatch
	// Each request is followed by one create and, every other time, a delete
	// of the newest extra account, so the list shifts under the cursor.
	var extra []Account
	for round := 0; round < 6; round++ {
		f.cheap = map[string]int{}
		if _, e := s.list(ctx); e != nil {
			t.Fatal(e)
		}
		in := CreateInput{Username: fmt.Sprintf("acct%05d", next), Domain: fmt.Sprintf("site%05d.test", next), Reason: "Churn"}
		next++
		a, e := s.create(ctx, in, "test operator")
		if e != nil {
			t.Fatal(e)
		}
		extra = append(extra, a)
		if round%2 == 1 {
			gone := extra[0]
			extra = extra[1:]
			if _, e := s.delete(ctx, gone.ID, DeleteInput{ExpectedRevision: gone.Revision, Reason: "Churn"}, "test operator"); e != nil {
				t.Fatal(e)
			}
		}
	}
	for name := range stable {
		if f.full[name] == 0 {
			t.Fatalf("%s was never fully checked while accounts changed", name)
		}
	}
}

// With auditBatch accounts or fewer the broker behaves as it did before the
// bound was raised: every account is fully checked on every request.
func TestSmallInventoryIsFullyCheckedEveryRequest(t *testing.T) {
	s, f, _ := setupStore(t)
	createMany(t, s, 0, auditBatch)
	f.full, f.cheap = map[string]int{}, map[string]int{}
	if _, e := s.list(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(f.full) != auditBatch || len(f.cheap) != 0 {
		t.Fatalf("full=%d file-only=%d", len(f.full), len(f.cheap))
	}
}

// A change the file check can see is caught on the next request for any
// account, whether or not that account is in the full-check batch.
func TestFileVisibleDriftIsCaughtOutsideTheAuditBatch(t *testing.T) {
	s, f, _ := setupStore(t)
	const accounts = 3 * auditBatch
	createMany(t, s, 0, accounts)
	ctx := context.Background()
	f.full, f.cheap = map[string]int{}, map[string]int{}
	if _, e := s.list(ctx); e != nil {
		t.Fatal(e)
	}
	// Pick an account the next request will only file-check, then change it.
	// nextAudit only reads the cursor; refresh is what moves it.
	target := ""
	items, e := s.records()
	if e != nil {
		t.Fatal(e)
	}
	next, _ := s.nextAudit(items)
	for i, r := range items {
		if !next(i) {
			target = r.Account.Username
			break
		}
	}
	changed := f.users[target]
	changed.Account.UID++
	f.users[target] = changed
	listed, e := s.list(ctx)
	if e != nil {
		t.Fatal(e)
	}
	flagged := 0
	for _, a := range listed {
		if a.State == "recovery_required" {
			flagged++
			if a.Username != target {
				t.Fatalf("wrong account flagged: %s", a.Username)
			}
		}
	}
	if flagged != 1 {
		t.Fatalf("%d accounts flagged, want exactly the changed one", flagged)
	}
}

// The inventory is no longer limited to 100 accounts, and the bound that
// replaced it is enforced.
func TestInventoryBeyondTheOldBound(t *testing.T) {
	if MaxAccounts <= 100 {
		t.Fatalf("MaxAccounts is %d", MaxAccounts)
	}
	s, _, _ := setupStore(t)
	const accounts = 130
	createMany(t, s, 0, accounts)
	listed, e := s.list(context.Background())
	if e != nil || len(listed) != accounts {
		t.Fatalf("listed %d accounts: %v", len(listed), e)
	}
	seen := map[int]bool{}
	for _, a := range listed {
		if a.State != "active" || a.UID < 20000 || a.UID > 60000 || seen[a.UID] {
			t.Fatalf("bad account %+v", a)
		}
		seen[a.UID] = true
	}
}

// BenchmarkStoreScale fills the journal store to MaxAccounts with the fake
// native system and reports what one list and one create then cost. It
// measures the store and journal only; native process and file costs are
// measured on the dev VM. Run: go test -run '^$' -bench StoreScale -benchtime 1x ./internal/hostaccounts
func BenchmarkStoreScale(b *testing.B) {
	root := b.TempDir()
	opts := BrokerOptions{StateDir: root + "/broker", HomesDir: root + "/homes", SocketPath: root + "/socket/control.sock", ControllerUID: 2000}
	f := &fakeNative{users: map[string]record{}}
	s, e := openStore(context.Background(), opts, f)
	if e != nil {
		b.Fatal(e)
	}
	defer s.close()
	fill := time.Now()
	createMany(b, s, 0, MaxAccounts-1)
	b.ReportMetric(time.Since(fill).Seconds(), "fill-seconds")
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if items, e := s.list(ctx); e != nil || len(items) != MaxAccounts-1 {
			b.Fatal(len(items), e)
		}
		b.ReportMetric(float64(time.Since(start).Milliseconds()), "list-ms")
	}
	b.StopTimer()
	start := time.Now()
	createMany(b, s, MaxAccounts-1, MaxAccounts)
	b.ReportMetric(float64(time.Since(start).Milliseconds()), "create-at-bound-ms")
	if _, e := s.create(ctx, CreateInput{Username: "onetoomany", Domain: "onetoomany.test", Reason: "Over the bound"}, "test operator"); e != ErrConflict {
		b.Fatalf("create beyond MaxAccounts: %v", e)
	}
}
