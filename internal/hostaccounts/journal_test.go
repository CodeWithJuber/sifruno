package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/olsweb"
)

// webChanges makes n web changes of the account, each moving its quota, and
// answers the account afterwards.
func webChanges(t *testing.T, s *store, a Account, n int) Account {
	t.Helper()
	for i := 0; i < n; i++ {
		got, err := s.setWeb(context.Background(), a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200 + int(a.Revision%2), ExpectedRevision: a.Revision, Reason: "Resize"}, "test operator")
		if err != nil {
			t.Fatalf("web change %d: %v", i, err)
		}
		a = got.Account
	}
	return a
}

// compactedStore has an account whose history was compacted once.
func compactedStore(t *testing.T) (*store, *fakeNative, BrokerOptions, Account) {
	t.Helper()
	s, f, opts := setupStore(t)
	s.db.NoSync = true // no fsync per write: what a commit survives is not under test
	s.web = &WebOptions{ServerUser: "nobody"}
	a := createFixture(t, s)
	for recordFor(t, s, a.ID).HistoryStart == 0 {
		a = webChanges(t, s, a, 1)
	}
	return s, f, opts, a
}

// TestHistoryCompactionKeepsAnAccountInUse: an account changed far more
// often than its history has rows for keeps working, its history stays
// bounded and starts at a checkpoint, and a restarted broker accepts it.
func TestHistoryCompactionKeepsAnAccountInUse(t *testing.T) {
	s, f, opts := setupStore(t)
	s.db.NoSync = true // no fsync per write: what a commit survives is not under test
	s.web = &WebOptions{ServerUser: "nobody"}
	ctx := context.Background()
	a := createFixture(t, s)
	const operations = 320
	compactions, start := 0, uint64(0)
	for i := 0; i < operations; i++ {
		var err error
		switch i % 8 {
		case 3:
			a, err = s.setState(ctx, a.ID, StateInput{"suspended", a.Revision, "Unpaid invoice"}, "test operator")
		case 4:
			a, err = s.setState(ctx, a.ID, StateInput{"active", a.Revision, "Paid"}, "test operator")
		case 6:
			jobs := []CronJob{}
			if i%16 == 6 {
				jobs = []CronJob{{Schedule: "*/5 * * * *", Command: "php wp-cron.php"}}
			}
			var res CronResult
			res, err = s.setCron(ctx, a.ID, CronInput{Jobs: jobs, ExpectedRevision: a.Revision, Reason: "Scheduled jobs changed"}, "test operator")
			a = res.Account
		default:
			var res WebResult
			res, err = s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200 + i%2, ExpectedRevision: a.Revision, Reason: "Resize"}, "test operator")
			a = res.Account
		}
		if err != nil {
			t.Fatalf("operation %d refused: %v", i, err)
		}
		r := recordFor(t, s, a.ID)
		if r.HistoryStart != start {
			compactions, start = compactions+1, r.HistoryStart
		}
		if rows := historyLength(r); rows >= historyCompactAt+operationRows {
			t.Fatalf("operation %d: the history holds %d rows", i, rows)
		}
	}
	r := recordFor(t, s, a.ID)
	rows := historyRows(t, s, a.ID)
	if compactions < 2 || r.HistorySequence < 2*operations || r.HistoryStart == 0 || uint64(len(rows)) != historyLength(r) {
		t.Fatalf("%d compactions, sequence %d, start %d, %d rows", compactions, r.HistorySequence, r.HistoryStart, len(rows))
	}
	first := rows[0]
	if first.Status != checkpointStatus || first.Sequence != r.HistoryStart || first.Before != nil || first.Actor != checkpointActor || rows[1].Status != "intended" || *rows[1].Before != first.After {
		t.Fatalf("the history does not start at its checkpoint: %+v", first)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(ctx, opts, f)
	if err != nil {
		t.Fatalf("a restarted broker refused the compacted history: %v", err)
	}
	defer reopened.close()
	reopened.web = &WebOptions{ServerUser: "nobody"}
	reopened.db.NoSync = true
	if got := recordFor(t, reopened, a.ID); got != r {
		t.Fatalf("the record changed across the restart: %+v", got)
	}
	if _, err := reopened.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Closed"}, "test operator"); err != nil {
		t.Fatalf("delete after compaction: %v", err)
	}
}

// TestCheckpointIsVerified: verifyHistory accepts a compacted history and
// refuses every way of forging or misplacing its checkpoint.
func TestCheckpointIsVerified(t *testing.T) {
	s, _, _, a := compactedStore(t)
	r := recordFor(t, s, a.ID)
	rows := historyRows(t, s, a.ID)
	if len(rows) < 4 || rows[0].Status != checkpointStatus {
		t.Fatalf("no checkpoint: %+v", rows[0])
	}
	start := r.HistoryStart
	put := func(tx *bolt.Tx, e operationEvent, sequence uint64) error {
		raw, _ := json.Marshal(e)
		return tx.Bucket(historyBucket).Put(eventKey(a.ID, sequence), raw)
	}
	errRollback := errors.New("roll back")
	check := func(name string, tamper func(tx *bolt.Tx, r *record) error) {
		t.Helper()
		err := s.db.Update(func(tx *bolt.Tx) error {
			forged := r
			if err := tamper(tx, &forged); err != nil {
				return err
			}
			if verifyHistory(tx, forged) == nil {
				t.Errorf("%s: accepted", name)
			}
			return errRollback
		})
		if !errors.Is(err, errRollback) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := s.db.View(func(tx *bolt.Tx) error { return verifyHistory(tx, r) }); err != nil {
		t.Fatalf("the compacted history is refused: %v", err)
	}
	checkpoint := func(change func(*operationEvent)) func(*bolt.Tx, *record) error {
		return func(tx *bolt.Tx, _ *record) error {
			e := rows[0]
			change(&e)
			return put(tx, e, start)
		}
	}
	check("another account state", checkpoint(func(e *operationEvent) { e.After.Plan = "gold" }))
	check("another identity", checkpoint(func(e *operationEvent) { e.After.UID++ }))
	check("another actor", checkpoint(func(e *operationEvent) { e.Actor = "test operator" }))
	check("another reason", checkpoint(func(e *operationEvent) { e.Reason = "Trust me" }))
	check("another action", checkpoint(func(e *operationEvent) { e.Action = "web" }))
	check("a before", checkpoint(func(e *operationEvent) { before := e.After; e.Before = &before }))
	check("a sequence other than its key", checkpoint(func(e *operationEvent) { e.Sequence++ }))
	check("a bad operation ID", checkpoint(func(e *operationEvent) { e.OperationID = "x" }))
	check("no time", checkpoint(func(e *operationEvent) { e.RecordedAt = time.Time{} }))
	check("an unsettled account", func(tx *bolt.Tx, _ *record) error {
		// The next operation's rows agree, so only the checkpoint's own
		// check refuses.
		e, intent, result := rows[0], rows[1], rows[2]
		e.After.State = "recovery_required"
		intent.Before, result.Before = &e.After, &e.After
		for i, row := range []operationEvent{e, intent, result} {
			if err := put(tx, row, start+uint64(i)); err != nil {
				return err
			}
		}
		return nil
	})
	check("the record names another start", func(_ *bolt.Tx, f *record) error { f.HistoryStart++; return nil })
	check("the record names no start", func(_ *bolt.Tx, f *record) error { f.HistoryStart = 0; return nil })
	check("the record names another sequence", func(_ *bolt.Tx, f *record) error { f.HistorySequence++; return nil })
	check("a row left before the checkpoint", func(tx *bolt.Tx, _ *record) error {
		e := rows[1]
		e.Sequence = start - 1
		return put(tx, e, start-1)
	})
	check("a second checkpoint later on", func(tx *bolt.Tx, _ *record) error {
		last := rows[len(rows)-1]
		e := rows[0]
		e.Sequence, e.After = last.Sequence, last.After
		return put(tx, e, last.Sequence)
	})
	check("a missing row after the checkpoint", func(tx *bolt.Tx, _ *record) error {
		return tx.Bucket(historyBucket).Delete(eventKey(a.ID, start+1))
	})
	check("no checkpoint row", func(tx *bolt.Tx, _ *record) error {
		return tx.Bucket(historyBucket).Delete(eventKey(a.ID, start))
	})

	// A history whose record names no start takes no checkpoint, and no
	// checkpoint replaces less than the create's two rows.
	b := createSecond(t, s)
	plain := recordFor(t, s, b.ID)
	plainRows := historyRows(t, s, b.ID)
	for _, c := range []struct {
		name               string
		sequence, startAt  uint64
		keepEarlierCreates bool
	}{
		{"a checkpoint at the create's result, the record naming no start", 2, 0, false},
		{"a checkpoint at the create's result after the create's intent", 2, 2, true},
		{"a checkpoint at the create, the record naming no start", 1, 0, false},
		{"a checkpoint at the create", 1, 1, false},
	} {
		err := s.db.Update(func(tx *bolt.Tx) error {
			e := plainRows[c.sequence-1]
			e.Status, e.Action, e.Actor, e.Reason, e.Before = checkpointStatus, checkpointStatus, checkpointActor, checkpointReason, nil
			e.After = plain.Account
			raw, _ := json.Marshal(e)
			bucket := tx.Bucket(historyBucket)
			for k := uint64(1); k < c.sequence && !c.keepEarlierCreates; k++ {
				if err := bucket.Delete(eventKey(b.ID, k)); err != nil {
					return err
				}
			}
			if err := bucket.Put(eventKey(b.ID, c.sequence), raw); err != nil {
				return err
			}
			forged := plain
			forged.HistoryStart = c.startAt
			if verifyHistory(tx, forged) == nil {
				t.Errorf("%s: accepted", c.name)
			}
			return errRollback
		})
		if !errors.Is(err, errRollback) {
			t.Fatal(err)
		}
	}
	if _, err := s.records(); err != nil {
		t.Fatalf("a rolled-back forgery changed the store: %v", err)
	}
}

// createSecond makes a second account beside the fixture.
func createSecond(t *testing.T, s *store) Account {
	t.Helper()
	b, err := s.create(context.Background(), CreateInput{Username: "secondacct", Domain: "second.test", Reason: "Second account"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCompactionCrashLeavesTheOldHistory: a compaction whose transaction
// does not commit, as in a crash before the commit, leaves the history as it
// was and a store that loads; the next operation compacts it.
func TestCompactionCrashLeavesTheOldHistory(t *testing.T) {
	s, f, opts := setupStore(t)
	s.db.NoSync = true // no fsync per write: what a commit survives is not under test
	s.web = &WebOptions{ServerUser: "nobody"}
	s.compactAt = 0
	ctx := context.Background()
	a := webChanges(t, s, createFixture(t, s), 100)
	before := recordFor(t, s, a.ID)
	rowsBefore := historyRows(t, s, a.ID)
	if before.HistoryStart != 0 || historyLength(before) < historyCompactAt {
		t.Fatalf("fixture: start %d, %d rows", before.HistoryStart, historyLength(before))
	}
	crash := errors.New("power lost before the commit")
	err := s.db.Update(func(tx *bolt.Tx) error {
		next, err := compactHistory(tx, before, strings.Repeat("c", 32), time.Now().UTC())
		if err != nil || next.HistoryStart == 0 {
			t.Errorf("compaction inside the transaction: %v, start %d", err, next.HistoryStart)
		}
		return crash
	})
	if !errors.Is(err, crash) {
		t.Fatal(err)
	}
	// A compaction that stops part way, refused by its own checks, writes
	// nothing either.
	stale := before
	stale.Account.Plan = "gold"
	err = s.db.Update(func(tx *bolt.Tx) error {
		_, err := compactHistory(tx, stale, strings.Repeat("d", 32), time.Now().UTC())
		return err
	})
	if !errors.Is(err, ErrRecovery) {
		t.Fatalf("a stale record was compacted: %v", err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(ctx, opts, f)
	if err != nil {
		t.Fatalf("the store does not load after the crash: %v", err)
	}
	defer reopened.close()
	reopened.web = &WebOptions{ServerUser: "nobody"}
	reopened.db.NoSync = true
	if got := recordFor(t, reopened, a.ID); got != before {
		t.Fatalf("the record changed: %+v", got)
	}
	rowsAfter := historyRows(t, reopened, a.ID)
	if len(rowsAfter) != len(rowsBefore) || rowsAfter[0].Status != "intended" || rowsAfter[0].Action != "create" {
		t.Fatalf("the history changed: %d rows, first %+v", len(rowsAfter), rowsAfter[0])
	}
	a = webChanges(t, reopened, a, 1)
	if got := recordFor(t, reopened, a.ID); got.HistoryStart == 0 || historyLength(got) > historyKeep+1+2 {
		t.Fatalf("the next operation did not compact: start %d, %d rows", got.HistoryStart, historyLength(got))
	}
}

// TestJournalWithoutCheckpointLoads: a history written before compaction
// existed, with no history_start in its record, loads as it did.
func TestJournalWithoutCheckpointLoads(t *testing.T) {
	s, f, opts := setupStore(t)
	s.db.NoSync = true // no fsync per write: what a commit survives is not under test
	s.web = &WebOptions{ServerUser: "nobody"}
	a := webChanges(t, s, createFixture(t, s), 10)
	var raw []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		raw = bytes.Clone(tx.Bucket(accountBucket).Get([]byte(a.ID)))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("history_start")) {
		t.Fatalf("a record never compacted names a start: %s", raw)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(context.Background(), opts, f)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	r := recordFor(t, reopened, a.ID)
	rows := historyRows(t, reopened, a.ID)
	if r.HistoryStart != 0 || r.HistorySequence != 22 || len(rows) != 22 || rows[0].Sequence != 1 || rows[0].Action != "create" {
		t.Fatalf("start %d, sequence %d, %d rows", r.HistoryStart, r.HistorySequence, len(rows))
	}
}

// TestOperatorKeepsRoomWhenCompactionCannotRun: with compaction off, the
// operations a tenant can reach stop short of the history's end, before
// anything is journaled, and the operator can still suspend, resume and
// delete the account.
func TestOperatorKeepsRoomWhenCompactionCannotRun(t *testing.T) {
	s, _ := webStore(t)
	s.db.NoSync = true
	s.compactAt = 0
	ctx := context.Background()
	a := createFixture(t, s)
	var err error
	for {
		var got WebResult
		got, err = s.setWeb(ctx, a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200 + int(a.Revision%2), ExpectedRevision: a.Revision, Reason: "Resize"}, "test operator")
		if err != nil {
			break
		}
		a = got.Account
	}
	full := recordFor(t, s, a.ID)
	if !errors.Is(err, ErrConflict) || historyRoom(full, operationRows, false) || !historyRoom(full, operatorRows, true) {
		t.Fatalf("web stopped with %v at %d rows", err, historyLength(full))
	}
	if _, err := s.setSSHKeys(ctx, a.ID, SSHKeysInput{Keys: []string{testEd25519Line(t, "dev@laptop")}, ExpectedRevision: a.Revision, Reason: "Add key"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("ssh keys at the tenant limit: %v", err)
	}
	if _, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "gold", ExpectedRevision: a.Revision, Reason: "Upgrade"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("plan at the tenant limit: %v", err)
	}
	if _, err := s.setCron(ctx, a.ID, CronInput{Jobs: []CronJob{{Schedule: "* * * * *", Command: "true"}}, ExpectedRevision: a.Revision, Reason: "Jobs"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("cron at the tenant limit: %v", err)
	}
	if got := recordFor(t, s, a.ID); got != full {
		t.Fatalf("a refused operation journaled: %+v", got)
	}
	a, err = s.setState(ctx, a.ID, StateInput{"suspended", a.Revision, "Unpaid invoice"}, "test operator")
	if err != nil {
		t.Fatalf("suspend at the tenant limit: %v", err)
	}
	a, err = s.setState(ctx, a.ID, StateInput{"active", a.Revision, "Paid"}, "test operator")
	if err != nil {
		t.Fatalf("resume at the tenant limit: %v", err)
	}
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Closed"}, "test operator"); err != nil {
		t.Fatalf("delete at the tenant limit: %v", err)
	}
}

// TestLargestRecordFits: the largest record the broker's inputs can make
// stays inside maxRecordBytes, which records() holds every record to. Only
// one operation is pending at a time, so one of the next fields is filled:
// the largest, a domains set being installed, with a recorded folders set
// at its bound too. Every other field is at its
// bound, texts made of the character JSON escapes most, and the homes
// directory as long as the broker admits it.
func TestLargestRecordFits(t *testing.T) {
	domains := strings.Repeat("a", maxSiteDomainsBytes-2)
	if !siteDomainsSized(domains) || siteDomainsSized(domains+"a") {
		t.Fatal("the domains fixture is not at its bound")
	}
	keys := make([]string, MaxSSHKeys)
	for i := range keys {
		keys[i] = strings.Repeat("k", maxSSHKeyLine)
	}
	names := make([]string, olsweb.MaxDomainsPerSite)
	for i := range names {
		names[i] = strings.Repeat("n", 253)
	}
	escaped := func(n int) string { return strings.Repeat("<", n) }
	cert := CertificateState{NotAfter: math.MaxInt64, Fingerprint: strings.Repeat("f", 64), Names: strings.Join(names, ",")}
	limits := AccountLimits{Processes: math.MaxInt, MemoryMiB: math.MaxInt, CPUPercent: math.MaxInt}
	id := strings.Repeat("a", 32)
	home := "/" + strings.Repeat("h", 2047) + "/" + strings.Repeat("u", 32)
	when := time.Date(2026, 11, 24, 23, 59, 59, 999999999, time.FixedZone("", -12*3600))
	big := ^uint64(0)
	r := record{
		Version:   1,
		Account:   Account{ID: id, Username: strings.Repeat("u", 32), Domain: strings.Repeat("d", 253), Plan: escaped(64), Home: home, PublicHTML: home + "/public_html", State: "recovery_required", UID: lastAccountID, GID: lastAccountID, Revision: big, CreatedAt: when, UpdatedAt: when, Certificate: cert, Limits: limits},
		Tag:       "sifruno-managed-" + id,
		Ownership: ownership{Home: fileIdentity{big, big}, Public: fileIdentity{big, big}, Marker: fileIdentity{big, big}},
		Pending:   &pending{Action: "domains", Target: "sha256=" + strings.Repeat("0", 64), Actor: escaped(120), Reason: escaped(500), OperationID: id},
		Actor:     escaped(120), Reason: escaped(500), HistorySequence: big, HistoryStart: big,
		SSHKeys: strings.Join(keys, "\n"),
		Web:     WebState{PHPVersion: "8.3", QuotaMiB: math.MaxInt},
		TLS:     cert, LimitsNext: limits,
		Cron:    strings.Repeat("c", 64),
		Domains: domains, DomainsNext: domains,
		Folders: largestFolders(t, id),
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxRecordBytes {
		t.Fatalf("the largest record takes %d bytes, more than the %d records() admits", len(raw), maxRecordBytes)
	}
	t.Logf("the largest record takes %d of %d bytes", len(raw), maxRecordBytes)
}

// largestFolders is a folders set as close to maxFoldersBytes as a valid
// one gets: 32 folders, each with its longest path and 64 networks.
func largestFolders(t *testing.T, id string) string {
	t.Helper()
	f := siteFolders{Users: map[string]string{}}
	for i := 0; len(f.Folders) < olsweb.MaxFoldersPerSite; i++ {
		folder := olsweb.Folder{Path: fmt.Sprintf("/%02d%s/%s/", i, strings.Repeat("p", 95), strings.Repeat("q", 95)), Hosts: olsweb.HostsOnly}
		for n := 0; n < olsweb.MaxFolderNetworks; n++ {
			folder.Networks = append(folder.Networks, fmt.Sprintf("2001:db8:%x::/48", 0x1000+n))
		}
		f.Folders = append(f.Folders, folder)
		if !foldersSized(encodeFolders(f)) {
			f.Folders = f.Folders[:len(f.Folders)-1]
			break
		}
	}
	encoded := encodeFolders(f)
	if !validStoredFolders(id, encoded) {
		t.Fatal("the folders fixture is not valid")
	}
	return encoded
}

// TestOversizedRecordIsNotStored: a record past the bound is refused before
// anything is written, so the store stays readable for every account.
func TestOversizedRecordIsNotStored(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	r := recordFor(t, s, a.ID)
	rows := len(historyRows(t, s, a.ID))
	huge := r
	huge.Reason = strings.Repeat("x", maxRecordBytes)
	huge.Pending = &pending{Action: "state", Target: "suspended", Actor: "test operator", Reason: "Too big"}
	before := a
	if _, err := s.beginOperation(huge, &before); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an oversized record was journaled: %v", err)
	}
	if err := s.save(huge); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an oversized record was saved: %v", err)
	}
	if got := recordFor(t, s, a.ID); got != r || len(historyRows(t, s, a.ID)) != rows {
		t.Fatalf("the store changed: %+v", got)
	}
}

// TestDomainsIntentKeepsTheState: a domains intent whose after moves the
// account's state is refused, as a cron intent's is, even when its result
// says it was rejected and so does not repeat that after.
func TestDomainsIntentKeepsTheState(t *testing.T) {
	s, _, _ := setupStore(t)
	s.web = &WebOptions{ServerUser: "nobody"}
	a := webChanges(t, s, createFixture(t, s), 1)
	r := recordFor(t, s, a.ID)
	rows := historyRows(t, s, a.ID)
	intent, result := rows[len(rows)-2], rows[len(rows)-1]
	errRollback := errors.New("roll back")
	for _, c := range []struct {
		action, state string
		accepted      bool
	}{{"domains", "active", true}, {"domains", "suspended", false}, {"cron", "suspended", false}} {
		err := s.db.Update(func(tx *bolt.Tx) error {
			i, res := intent, result
			i.Action, res.Action = c.action, c.action
			i.After.State = c.state
			res.Status, res.After = "rejected", *res.Before
			for _, row := range []operationEvent{i, res} {
				raw, _ := json.Marshal(row)
				if err := tx.Bucket(historyBucket).Put(eventKey(a.ID, row.Sequence), raw); err != nil {
					return err
				}
			}
			forged := r
			forged.Account = *res.Before
			if accepted := verifyHistory(tx, forged) == nil; accepted != c.accepted {
				t.Errorf("a %s intent to %s: accepted %v", c.action, c.state, accepted)
			}
			return errRollback
		})
		if !errors.Is(err, errRollback) {
			t.Fatal(err)
		}
	}
}

// TestHTTPSIntentTurnsOnlyTheSwitch: an https intent's after is its before
// with the next revision and "Always use HTTPS" turned over; one that
// changes anything else, or leaves the switch as it was, is refused.
func TestHTTPSIntentTurnsOnlyTheSwitch(t *testing.T) {
	s, _, _ := setupStore(t)
	s.web = &WebOptions{ServerUser: "nobody"}
	a := webChanges(t, s, createFixture(t, s), 1)
	r := recordFor(t, s, a.ID)
	rows := historyRows(t, s, a.ID)
	intent, result := rows[len(rows)-2], rows[len(rows)-1]
	errRollback := errors.New("roll back")
	for name, c := range map[string]struct {
		edit     func(*Account)
		accepted bool
	}{
		"the switch turned off":  {func(a *Account) { a.PlainHTTP = true }, true},
		"the switch left as is":  {func(*Account) {}, false},
		"the plan changed too":   {func(a *Account) { a.PlainHTTP, a.Plan = true, "other" }, false},
		"the limits changed too": {func(a *Account) { a.PlainHTTP, a.Limits = true, AccountLimits{Processes: 1} }, false},
	} {
		err := s.db.Update(func(tx *bolt.Tx) error {
			i, res := intent, result
			i.Action, res.Action = "https", "https"
			i.After = *i.Before
			i.After.Revision++
			c.edit(&i.After)
			res.Status, res.After = "rejected", *res.Before
			for _, row := range []operationEvent{i, res} {
				raw, _ := json.Marshal(row)
				if err := tx.Bucket(historyBucket).Put(eventKey(a.ID, row.Sequence), raw); err != nil {
					return err
				}
			}
			forged := r
			forged.Account = *res.Before
			if accepted := verifyHistory(tx, forged) == nil; accepted != c.accepted {
				t.Errorf("%s: accepted %v", name, accepted)
			}
			return errRollback
		})
		if !errors.Is(err, errRollback) {
			t.Fatal(err)
		}
	}
}
