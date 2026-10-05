package budget

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOversizedLedgerRejectedBeforeCommit(t *testing.T) {
	s, _ := testStore(t)
	path := filepath.Join(s.dir, "ledger.json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	e = s.locked(func(l *ledger) error {
		for i := 0; i < maxRecords; i++ {
			aid := fmt.Sprintf("%032d", i)
			id := fmt.Sprintf("%080d", i)
			l.Approvals[aid] = Approval{ID: aid, OperationSHA256: opSHA, Revision: strings.Repeat("r", 128), Actor: strings.Repeat("a", 100), MaxCost: DefaultCap, Expires: s.now(), Used: true}
			l.Reservations[id] = Reservation{ID: id, ApprovalID: aid, OperationSHA256: opSHA, Revision: strings.Repeat("r", 128), Month: "2026-09", Reserved: DefaultCap, Actual: 1, State: "settled", Created: s.now()}
		}
		return nil
	}, true)
	if e == nil || !strings.Contains(e.Error(), "size limit") {
		t.Fatal("oversized valid records committed", e)
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected write changed prior ledger", e)
	}
	if _, e = s.Status(); e != nil {
		t.Fatal("prior ledger unreadable", e)
	}
}

func testStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 30, 23, 59, 0, 0, time.UTC)
	s, e := openClock(filepath.Join(realTempDir(t), "budget"), DefaultCap, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	return s, &now
}

const opSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func grant(t *testing.T, s *Store, max int64) Approval {
	t.Helper()
	a, e := s.Approve(opSHA, "rev1", "operator", max, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestConcurrentReservationsCannotExceedCap(t *testing.T) {
	s, _ := testStore(t)
	other, e := openClock(s.dir, DefaultCap, s.now)
	if e != nil {
		t.Fatal(e)
	}
	grants := []Approval{}
	for i := 0; i < 24; i++ {
		grants = append(grants, grant(t, s, 1_000_000))
	}
	var success atomic.Int64
	var wg sync.WaitGroup
	for i, a := range grants {
		wg.Add(1)
		go func(i int, a Approval) {
			defer wg.Done()
			target := s
			if i%2 == 1 {
				target = other
			}
			if _, e := target.Reserve(fmt.Sprintf("call_%d", i), a.ID, opSHA, "rev1", 1_000_000); e == nil {
				success.Add(1)
			}
		}(i, a)
	}
	wg.Wait()
	if success.Load() != 10 {
		t.Fatalf("expected10, got%d", success.Load())
	}
	st, e := s.Status()
	if e != nil || st.Reserved != DefaultCap || st.Remaining != 0 {
		t.Fatalf("status%+v error%v", st, e)
	}
}
func TestApprovalBindingExpirationReplayAndCost(t *testing.T) {
	s, now := testStore(t)
	a := grant(t, s, 1_000_000)
	for _, test := range []struct {
		operation, revision string
		amount              int64
	}{{strings.Repeat("b", 64), "rev1", 1}, {opSHA, "rev2", 1}, {opSHA, "rev1", 1_000_001}} {
		if _, e := s.Reserve("bad", a.ID, test.operation, test.revision, test.amount); e == nil {
			t.Fatal("unbound approval accepted")
		}
	}
	if _, e := s.Reserve("ok", a.ID, opSHA, "rev1", 1_000_000); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Reserve("replay", a.ID, opSHA, "rev1", 1); e == nil {
		t.Fatal("approval replay accepted")
	}
	a = grant(t, s, 1_000_000)
	*now = now.Add(11 * time.Minute)
	if _, e := s.Reserve("expired", a.ID, opSHA, "rev1", 1); e == nil {
		t.Fatal("expired approval accepted")
	}
}
func TestMonthBoundaryPendingAndReconciledCost(t *testing.T) {
	s, now := testStore(t)
	a := grant(t, s, 2_000_000)
	if _, e := s.Reserve("pending", a.ID, opSHA, "rev1", 2_000_000); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(2 * time.Minute)
	st, e := s.Status()
	if e != nil || st.Month != "2026-10" || st.Reserved != 2_000_000 || st.Remaining != 8_000_000 {
		t.Fatalf("pending boundary%+v,%v", st, e)
	}
	if _, e = s.Settle("pending", 1_500_000); e != nil {
		t.Fatal(e)
	}
	st, e = s.Status()
	if e != nil || st.Reserved != 0 || st.Spent != 1_500_000 || st.Remaining != 8_500_000 {
		t.Fatalf("settlement%+v,%v", st, e)
	}
	if _, e = s.Settle("pending", 0); e == nil {
		t.Fatal("settlement replay accepted")
	}
}
func TestUnderestimatedUsagePersistsAndBlocks(t *testing.T) {
	s, _ := testStore(t)
	a := grant(t, s, 1_000_000)
	if _, e := s.Reserve("badestimate", a.ID, opSHA, "rev1", 1_000_000); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Settle("badestimate", 2_000_000); e == nil {
		t.Fatal("missing reconciliation error")
	}
	st, e := s.Status()
	if e != nil || st.Spent != 2_000_000 || st.Remaining != 0 || !st.ReconciliationRequired {
		t.Fatalf("unsafe underestimate%+v %v", st, e)
	}
}
func TestCorruptOrMissingLedgerCannotResetBudget(t *testing.T) {
	s, _ := testStore(t)
	p := filepath.Join(s.dir, "ledger.json")
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	raw[len(raw)/2] ^= 1
	if e = os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Status(); e == nil {
		t.Fatal("tamper accepted")
	}
	if _, e = Open(s.dir, DefaultCap); e == nil {
		t.Fatal("corrupt ledger reset")
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(s.dir, DefaultCap); e == nil {
		t.Fatal("missing ledger reset")
	}
}
func TestPrivateDirectoryGuard(t *testing.T) {
	p := realTempDir(t)
	if e := os.WriteFile(filepath.Join(p, "unrelated.txt"), []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(p, DefaultCap); e == nil {
		t.Fatal("changed permissions of unrelated directory")
	}
}

func TestLiveStoreRejectsDeletedOrChangedKey(t *testing.T) {
	for _, mode := range []string{"deleted", "changed", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := testStore(t)
			path := filepath.Join(s.dir, "key")
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "deleted":
				e = os.Remove(path)
			case "changed":
				raw[0] ^= 1
				e = os.WriteFile(path, raw, 0600)
			case "symlink":
				outside := filepath.Join(realTempDir(t), "foreign.key")
				if e = os.WriteFile(outside, raw, 0600); e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(path); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink(outside, path); e != nil {
					t.Skip("symlink unavailable:", e)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Status(); e == nil {
				t.Fatal("live store accepted missing/changed/linked key")
			}
			if _, e = s.Approve(opSHA, "rev1", "operator", 1, 10*time.Minute); e == nil {
				t.Fatal("live store mutated with invalid key")
			}
		})
	}
}

func realTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		return dir
	}
	dir, e := filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	return dir
}
