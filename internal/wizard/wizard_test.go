package wizard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
)

// These fakes record the typed calls a job makes; they provision nothing.

const testAdminPassword = "Correct-Horse-Battery-9"

// journal is the order of every call across both fakes.
type journal struct {
	mu  sync.Mutex
	all []string
}

func (j *journal) add(call string) {
	j.mu.Lock()
	j.all = append(j.all, call)
	j.mu.Unlock()
}

type fakeAccounts struct {
	mu       sync.Mutex
	order    *journal
	calls    []string
	accounts []hostaccounts.Account
	conflict map[string]bool // usernames Create refuses
	createFn func(context.Context) error
	webErr   error
	install  hostaccounts.WordPressInput
	installF func(context.Context) error
	listErr  error
	delErr   error
	delCtx   error
	next     int
}

func (f *fakeAccounts) record(call string) {
	f.order.add(call)
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

func (f *fakeAccounts) List(context.Context) ([]hostaccounts.Account, error) {
	f.record("list")
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.accounts), f.listErr
}

func (f *fakeAccounts) Create(ctx context.Context, in hostaccounts.CreateInput, actor string) (hostaccounts.Account, error) {
	f.record("create " + in.Username)
	if f.createFn != nil {
		if err := f.createFn(ctx); err != nil {
			return hostaccounts.Account{}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conflict[in.Username] || in.Reason == "" || actor == "" {
		return hostaccounts.Account{}, hostaccounts.ErrConflict
	}
	f.next++
	a := hostaccounts.Account{ID: fmt.Sprintf("%032x", f.next), Username: in.Username, Domain: in.Domain, State: "active", Revision: 1}
	f.accounts = append(f.accounts, a)
	return a, nil
}

func (f *fakeAccounts) Delete(ctx context.Context, id string, in hostaccounts.DeleteInput, _ string) (hostaccounts.Account, error) {
	f.record(fmt.Sprintf("delete %s rev=%d", id[28:], in.ExpectedRevision))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delCtx = ctx.Err()
	if f.delErr != nil {
		return hostaccounts.Account{}, f.delErr
	}
	f.accounts = slices.DeleteFunc(f.accounts, func(a hostaccounts.Account) bool { return a.ID == id })
	return hostaccounts.Account{ID: id}, nil
}

func (f *fakeAccounts) SetWeb(_ context.Context, id string, in hostaccounts.WebInput, _ string) (hostaccounts.WebResult, error) {
	f.record(fmt.Sprintf("web %s php=%s quota=%d rev=%d reason=%s", id[28:], in.PHPVersion, in.QuotaMiB, in.ExpectedRevision, in.Reason))
	if f.webErr != nil {
		return hostaccounts.WebResult{}, f.webErr
	}
	return hostaccounts.WebResult{Account: hostaccounts.Account{ID: id, Revision: in.ExpectedRevision + 1}, Web: hostaccounts.WebState{PHPVersion: in.PHPVersion, QuotaMiB: in.QuotaMiB}}, nil
}

func (f *fakeAccounts) InstallWordPress(ctx context.Context, id string, in hostaccounts.WordPressInput, _ string) (hostaccounts.WordPressResult, error) {
	f.record(fmt.Sprintf("install %s rev=%d", id[28:], in.ExpectedRevision))
	f.mu.Lock()
	f.install = in
	f.mu.Unlock()
	if f.installF != nil {
		if err := f.installF(ctx); err != nil {
			return hostaccounts.WordPressResult{}, err
		}
	}
	return hostaccounts.WordPressResult{Version: "7.1.5"}, nil
}

type fakeDatabases struct {
	mu        sync.Mutex
	order     *journal
	calls     []string
	password  string
	probeErr  error
	existing  []dbhost.Database
	dbErr     error
	userErr   error
	privErr   error
	dropErr   error
	privsSeen []string
}

func (f *fakeDatabases) record(call string) {
	f.order.add(call)
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

func (f *fakeDatabases) Probe(context.Context) (string, error) { return "10.11", f.probeErr }
func (f *fakeDatabases) AllDatabases(context.Context) ([]dbhost.Database, error) {
	return slices.Clone(f.existing), nil
}
func (f *fakeDatabases) AllUsers(context.Context) ([]dbhost.User, error) { return nil, nil }
func (f *fakeDatabases) CreateDatabase(_ context.Context, owner, name string) error {
	f.record("create-db " + owner + " " + name)
	return f.dbErr
}
func (f *fakeDatabases) CreateUser(_ context.Context, owner, name, password string) error {
	f.record("create-user " + owner + " " + name)
	f.mu.Lock()
	f.password = password
	f.mu.Unlock()
	if f.userErr != nil {
		// What MariaDB prints for a syntax error: the statement, password
		// included, after "near".
		return fmt.Errorf("%w near 'IDENTIFIED BY '%s'' at line 1", f.userErr, password)
	}
	return nil
}
func (f *fakeDatabases) SetPrivileges(_ context.Context, owner, user, db string, privs []string) error {
	f.record("grant " + owner + " " + user + " " + db)
	f.mu.Lock()
	f.privsSeen = privs
	f.mu.Unlock()
	return f.privErr
}
func (f *fakeDatabases) DropDatabase(_ context.Context, owner, name string) error {
	f.record("drop-db " + owner + " " + name)
	return f.dropErr
}
func (f *fakeDatabases) DropUser(_ context.Context, owner, name string) error {
	f.record("drop-user " + owner + " " + name)
	return f.dropErr
}

type fixture struct {
	runner *Runner
	acc    *fakeAccounts
	dbs    *fakeDatabases
	order  *journal
	dir    string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "wizard")
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	order := &journal{}
	acc := &fakeAccounts{order: order, conflict: map[string]bool{}}
	dbs := &fakeDatabases{order: order}
	r := New(acc, dbs, store)
	digits := []string{"07", "42", "13", "99", "55"}
	n := 0
	r.digits = func() string { d := digits[n%len(digits)]; n++; return d }
	return fixture{r, acc, dbs, order, dir}
}

func input(domain string) Input {
	return Input{Domain: domain, Title: "My site", AdminUser: "siteadmin", AdminEmail: "me@example.com", AdminPassword: testAdminPassword, PHPVersion: "8.3"}
}

func (f fixture) runJob(t *testing.T, in Input) Job {
	t.Helper()
	job, err := f.runner.Start(context.Background(), in, "local-operator")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	f.runner.Wait()
	done, ok := f.runner.Get(job.ID)
	if !ok {
		t.Fatal("job missing after run")
	}
	return done
}

func stepStates(j Job) string {
	parts := []string{}
	for _, s := range j.Steps {
		parts = append(parts, s.Name+"="+s.State)
	}
	return strings.Join(parts, " ")
}

func TestWordPressJobSucceeds(t *testing.T) {
	f := newFixture(t)
	job, err := f.runner.Start(context.Background(), input("example.com"), "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	if job.State != StateRunning || job.Kind != KindWordPress || !ValidID(job.ID) || job.Error != nil || job.Result != nil {
		t.Fatalf("started job: %+v", job)
	}
	f.runner.Wait()
	done, _ := f.runner.Get(job.ID)
	if done.State != StateSucceeded || done.Error != nil || done.Username != "example" || done.Actor != "local-operator" {
		t.Fatalf("finished job: %+v", done)
	}
	if got := stepStates(done); got != "account=done web=done database=done wordpress=done" {
		t.Fatal(got)
	}
	for _, s := range done.Steps {
		if s.StartedAt == "" || s.FinishedAt == "" || s.Message == "" {
			t.Fatalf("step without times or message: %+v", s)
		}
	}
	want := Result{URL: "http://example.com/", AdminURL: "http://example.com/wp-admin/", WordPressVersion: "7.1.5", AccountID: fmt.Sprintf("%032x", 1)}
	if done.Result == nil || *done.Result != want {
		t.Fatalf("result %+v", done.Result)
	}
	wantAcc := []string{"list", "create example", "web 0001 php=8.3 quota=1024 rev=1 reason=WordPress wizard", "install 0001 rev=2"}
	if !slices.Equal(f.acc.calls, wantAcc) {
		t.Fatalf("broker calls %q", f.acc.calls)
	}
	wantDB := []string{"create-db example example_wp", "create-user example example_wp", "grant example example_wp example_wp"}
	if !slices.Equal(f.dbs.calls, wantDB) || !slices.Equal(f.dbs.privsSeen, []string{"ALL PRIVILEGES"}) {
		t.Fatalf("database calls %q %q", f.dbs.calls, f.dbs.privsSeen)
	}
	in := f.acc.install
	if in.HTTPS || in.Title != "My site" || in.AdminUser != "siteadmin" || in.AdminEmail != "me@example.com" || in.AdminPassword != testAdminPassword || in.DBName != "example_wp" || in.DBUser != "example_wp" {
		t.Fatalf("install input %+v", in)
	}
	if in.DBPassword != f.dbs.password || !regexp.MustCompile(`^[A-Za-z0-9_-]{24}$`).MatchString(in.DBPassword) {
		t.Fatal("database password is not 24 URL-safe characters shared with the install")
	}
}

func TestUsernameFromDomain(t *testing.T) {
	for domain, want := range map[string]string{
		"example.com":                     "example",
		"my-site.example.com":             "mysite",
		"1password.com":                   "s1password",
		"a.com":                           "asite",
		"1.com":                           "s1site",
		"averyveryverylongname.com":       "averyveryver",
		"xn--bcher-kva.example":           "xnbcherkva",
		"123456789012345.example":         "s12345678901",
		"ab.example":                      "absite",
		"mail.example.com":                "mail", // denied: the first try adds digits
		"wordpress-for-everyone.example":  "wordpressfor",
		"shop.example.co.uk":              "shop",
		"x-y.example":                     "xysite",
		"9-9.example":                     "s99",
		"z.example":                       "zsite",
		"sifruno.example":                 "sifruno",
		"0.example":                       "s0site",
		"a1.example":                      "a1site",
		"abc.example":                     "abc",
		"a-b-c-d-e-f-g-h-i-j-k-l.example": "abcdefghijkl",
	} {
		if got := usernameBase(domain); got != want {
			t.Errorf("%s: got %q want %q", domain, got, want)
		}
	}
	if got := usernameCandidate("mail", 0, func() string { return "07" }); got != "mail07" {
		t.Fatalf("denied name not changed: %s", got)
	}
	if got := usernameCandidate("example", 0, func() string { return "07" }); got != "example" {
		t.Fatalf("first try changed: %s", got)
	}
}

// TestDerivedNamesPassTheBroker checks the wizard's names against the broker
// client's own validation: it answers ErrInvalid for a name it refuses and,
// with no socket configured, ErrUnavailable for one it would send.
func TestDerivedNamesPassTheBroker(t *testing.T) {
	client := hostaccounts.NewClient("")
	try := func(name string) error {
		_, err := client.Create(context.Background(), hostaccounts.CreateInput{Username: name, Domain: "example.com", Reason: "check"}, "local-operator")
		return err
	}
	for name := range deniedNames {
		if !errors.Is(try(name), hostaccounts.ErrInvalid) {
			t.Errorf("broker accepts %q, which the wizard treats as denied", name)
		}
	}
	for _, domain := range []string{"example.com", "1.com", "mail.example.com", "sifruno.example", "operator.example", "averyveryverylongname.com", "a.com"} {
		base := usernameBase(domain)
		for try_ := 0; try_ < usernameTries; try_++ {
			name := usernameCandidate(base, try_, randomDigits)
			if !validUsername(name) || errors.Is(try(name), hostaccounts.ErrInvalid) {
				t.Errorf("%s: derived name %q is refused", domain, name)
			}
		}
	}
}

func TestUsernameConflictRetry(t *testing.T) {
	f := newFixture(t)
	f.acc.conflict["example"] = true
	f.acc.conflict["example07"] = true
	done := f.runJob(t, input("example.com"))
	if done.State != StateSucceeded || done.Username != "example42" {
		t.Fatalf("job %s %q %+v", done.State, done.Username, done.Error)
	}
	want := []string{"list", "create example", "list", "create example07", "list", "create example42"}
	if !slices.Equal(f.acc.calls[:len(want)], want) {
		t.Fatalf("calls %q", f.acc.calls)
	}
	if f.dbs.calls[0] != "create-db example42 example42_wp" {
		t.Fatalf("database named after the old name: %q", f.dbs.calls)
	}

	// Five conflicts: the job fails at the account step and undoes nothing.
	f = newFixture(t)
	for _, name := range []string{"example", "example07", "example42", "example13", "example99"} {
		f.acc.conflict[name] = true
	}
	done = f.runJob(t, input("example.com"))
	if done.State != StateFailed || done.Error == nil || done.Error.Step != StepAccount || !strings.Contains(done.Error.Why, "5 account names") {
		t.Fatalf("job %+v %+v", done, done.Error)
	}
	if got := stepStates(done); got != "account=failed web=skipped database=skipped wordpress=skipped" {
		t.Fatal(got)
	}
	if slices.ContainsFunc(f.acc.calls, func(c string) bool { return strings.HasPrefix(c, "delete") }) || len(f.dbs.calls) != 0 {
		t.Fatal("undo touched something the job did not create")
	}

	// A conflict because the domain was just taken stops the retries.
	f = newFixture(t)
	f.acc.conflict["example"] = true
	f.acc.createFn = func(context.Context) error {
		f.acc.mu.Lock()
		defer f.acc.mu.Unlock()
		f.acc.accounts = append(f.acc.accounts, hostaccounts.Account{ID: strings.Repeat("e", 32), Username: "other", Domain: "example.com"})
		return hostaccounts.ErrConflict
	}
	done = f.runJob(t, input("example.com"))
	if done.State != StateFailed || !strings.Contains(done.Error.Why, "hosting account other") || strings.Count(strings.Join(f.acc.calls, ","), "create ") != 1 {
		t.Fatalf("domain conflict: %+v %q", done.Error, f.acc.calls)
	}
}

func TestFailureAtEachStepUndoesInReverse(t *testing.T) {
	installErr := &hostaccounts.InstallError{Step: "install", Detail: "Error: The site you have requested is not installed. password=" + testAdminPassword}
	for _, tc := range []struct {
		name    string
		setup   func(f fixture)
		states  string
		step    string
		what    string
		undoAcc []string
		undoDB  []string
		tech    string
	}{
		{
			name:   "account",
			setup:  func(f fixture) { f.acc.createFn = func(context.Context) error { return hostaccounts.ErrUnavailable } },
			states: "account=failed web=skipped database=skipped wordpress=skipped",
			step:   StepAccount, what: "The hosting account could not be created.",
		},
		{
			name:   "web",
			setup:  func(f fixture) { f.acc.webErr = hostaccounts.ErrWebRejected },
			states: "account=undone web=failed database=skipped wordpress=skipped",
			step:   StepWeb, what: "The site could not be put live.",
			undoAcc: []string{"delete 0001 rev=1"},
		},
		{
			name: "database user",
			setup: func(f fixture) {
				f.dbs.userErr = errors.New("ERROR 1064 (42000) at line 1: You have an error in your SQL syntax")
			},
			states: "account=undone web=undone database=failed wordpress=skipped",
			step:   StepDatabase, what: "The database could not be created.",
			undoAcc: []string{"delete 0001 rev=2"},
			undoDB:  []string{"drop-db example example_wp"},
			tech:    "ERROR 1064 (42000) at line 1: You have an error in your SQL syntax near [statement removed]",
		},
		{
			name:   "database grant",
			setup:  func(f fixture) { f.dbs.privErr = errors.New("ERROR 1044 (42000): Access denied") },
			states: "account=undone web=undone database=failed wordpress=skipped",
			step:   StepDatabase, what: "The database could not be created.",
			undoAcc: []string{"delete 0001 rev=2"},
			undoDB:  []string{"drop-user example example_wp", "drop-db example example_wp"},
		},
		{
			name:   "wordpress",
			setup:  func(f fixture) { f.acc.installF = func(context.Context) error { return installErr } },
			states: "account=undone web=undone database=undone wordpress=failed",
			step:   StepWordPress, what: "WordPress could not be installed.",
			undoAcc: []string{"delete 0001 rev=2"},
			undoDB:  []string{"drop-user example example_wp", "drop-db example example_wp"},
			tech:    "install: Error: The site you have requested is not installed. password=[secret]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			done := f.runJob(t, input("example.com"))
			if done.State != StateFailed || done.Result != nil || done.Error == nil {
				t.Fatalf("job %+v", done)
			}
			if got := stepStates(done); got != tc.states {
				t.Fatal(got)
			}
			e := done.Error
			if e.Step != tc.step || e.What != tc.what || e.Why == "" || e.Next == "" || e.Technical == "" {
				t.Fatalf("error %+v", e)
			}
			if tc.tech != "" && e.Technical != tc.tech {
				t.Fatalf("technical %q", e.Technical)
			}
			var undoAcc, undoDB []string
			for _, c := range f.acc.calls {
				if strings.HasPrefix(c, "delete") {
					undoAcc = append(undoAcc, c)
				}
			}
			for _, c := range f.dbs.calls {
				if strings.HasPrefix(c, "drop") {
					undoDB = append(undoDB, c)
				}
			}
			if !slices.Equal(undoAcc, tc.undoAcc) || !slices.Equal(undoDB, tc.undoDB) {
				t.Fatalf("undo %q %q", undoAcc, undoDB)
			}
			// Newest first: the database user, the database, then the
			// account that owns them.
			var undo []string
			for _, c := range f.order.all {
				if strings.HasPrefix(c, "drop") || strings.HasPrefix(c, "delete") {
					undo = append(undo, c)
				}
			}
			if !slices.Equal(undo, append(slices.Clone(tc.undoDB), tc.undoAcc...)) {
				t.Fatalf("undo order %q", undo)
			}
			if f.acc.delCtx != nil {
				t.Fatal("undo ran on a cancelled context")
			}
			for _, s := range done.Steps {
				if s.State == StepUndone && s.Message != "Removed after a later step failed." {
					t.Fatalf("undone step message %q", s.Message)
				}
			}
			if strings.Contains(e.Technical, testAdminPassword) || (f.dbs.password != "" && strings.Contains(e.Technical, f.dbs.password)) {
				t.Fatal("password in the technical details")
			}
		})
	}
}

func TestUndoFailureIsRecorded(t *testing.T) {
	f := newFixture(t)
	f.acc.webErr = hostaccounts.ErrRecovery
	f.acc.delErr = hostaccounts.ErrConflict
	done := f.runJob(t, input("example.com"))
	if got := stepStates(done); got != "account=done web=failed database=skipped wordpress=skipped" {
		t.Fatal(got)
	}
	if done.Steps[0].Message != "Could not be removed after a later step failed." {
		t.Fatalf("account message %q", done.Steps[0].Message)
	}
	if !strings.Contains(done.Error.Next, "the hosting account example") || !strings.Contains(done.Error.Technical, "undo account: native account identity or revision conflict") {
		t.Fatalf("undo failure not in the job log: %+v", done.Error)
	}
}

func TestTimeLimitStopsTheJobAndStillUndoes(t *testing.T) {
	f := newFixture(t)
	f.runner.limit = 50 * time.Millisecond
	f.acc.installF = func(ctx context.Context) error { <-ctx.Done(); return hostaccounts.ErrUnavailable }
	done := f.runJob(t, input("example.com"))
	if done.State != StateFailed || done.Error.Step != StepWordPress || !strings.Contains(done.Error.Why, "15 minutes") {
		t.Fatalf("job %+v", done.Error)
	}
	if got := stepStates(done); got != "account=undone web=undone database=undone wordpress=failed" {
		t.Fatal(got)
	}
	if f.acc.delCtx != nil {
		t.Fatal("undo ran on the expired job context")
	}
}

func TestExistingDatabaseIsNeitherReusedNorRemoved(t *testing.T) {
	// Registered before the job: the account step takes the next name.
	f := newFixture(t)
	f.dbs.existing = []dbhost.Database{{Name: "example_wp", Owner: "example"}}
	done := f.runJob(t, input("example.com"))
	if done.State != StateSucceeded || done.Username != "example07" || slices.Contains(f.acc.calls, "create example") {
		t.Fatalf("job %s %q %q", done.State, done.Username, f.acc.calls)
	}
	if slices.ContainsFunc(f.dbs.calls, func(c string) bool { return strings.Contains(c, " example_wp") }) {
		t.Fatalf("existing database touched: %q", f.dbs.calls)
	}

	// Registered while the job ran: the database step refuses it and the
	// job removes only its own account.
	f = newFixture(t)
	f.acc.createFn = func(context.Context) error {
		f.dbs.existing = []dbhost.Database{{Name: "example_wp", Owner: "someone"}}
		return nil
	}
	done = f.runJob(t, input("example.com"))
	if got := stepStates(done); got != "account=undone web=undone database=failed wordpress=skipped" {
		t.Fatal(got)
	}
	if !strings.Contains(done.Error.Why, "example_wp was added") {
		t.Fatalf("why %q", done.Error.Why)
	}
	if len(f.dbs.calls) != 0 {
		t.Fatalf("existing database touched: %q", f.dbs.calls)
	}

	// Every candidate's database exists: the account step gives up.
	f = newFixture(t)
	for _, name := range []string{"example", "example07", "example42", "example13", "example99"} {
		f.dbs.existing = append(f.dbs.existing, dbhost.Database{Name: name + "_wp"})
	}
	done = f.runJob(t, input("example.com"))
	if done.Error == nil || done.Error.Step != StepAccount || slices.ContainsFunc(f.acc.calls, func(c string) bool { return strings.HasPrefix(c, "create") }) {
		t.Fatalf("job %+v %q", done.Error, f.acc.calls)
	}
}

func TestRestartTurnsRunningJobsIntoFailed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wizard")
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	running := newJob(strings.Repeat("a", 32), "example.com", "local-operator", time.Now())
	running.Username = "example"
	running.Steps[0].State, running.Steps[1].State = StepDone, StepRunning
	between := newJob(strings.Repeat("b", 32), "other.example", "local-operator", time.Now())
	between.Steps[0].State = StepDone
	finished := newJob(strings.Repeat("c", 32), "done.example", "local-operator", time.Now())
	finished.State = StateSucceeded
	for _, j := range []Job{running, between, finished} {
		if err = store.put(j); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 { // the second open reads what the first one saved
		store, err = OpenStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := store.Get(running.ID)
		if a.State != StateFailed || a.Error == nil || a.Error.Step != StepWeb || a.Error.What != "The panel restarted while this website was being created." || a.Error.Next != "Check Websites and Accounts, remove what was left, then create it again." {
			t.Fatalf("running job after restart: %+v %+v", a, a.Error)
		}
		if got := stepStates(a); got != "account=done web=failed database=skipped wordpress=skipped" {
			t.Fatal(got)
		}
		b, _ := store.Get(between.ID)
		if b.State != StateFailed || b.Error.Step != StepWeb || stepStates(b) != "account=done web=failed database=skipped wordpress=skipped" {
			t.Fatalf("job between steps: %+v %s", b.Error, stepStates(b))
		}
		c, _ := store.Get(finished.ID)
		if c.State != StateSucceeded || c.Error != nil {
			t.Fatal("finished job changed")
		}
	}
}

func TestOneRunningJobPerDomainAndTwoAtMost(t *testing.T) {
	f := newFixture(t)
	release := make(chan struct{})
	f.acc.installF = func(context.Context) error { <-release; return nil }
	first, err := f.runner.Start(context.Background(), input("example.com"), "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	var refusal *Refusal
	_, err = f.runner.Start(context.Background(), input("example.com"), "local-operator")
	if !errors.As(err, &refusal) || !errors.Is(err, ErrConflict) || !strings.Contains(refusal.Detail, "example.com is being created") {
		t.Fatalf("same domain: %v", err)
	}
	if _, err = f.runner.Start(context.Background(), input("other.example"), "local-operator"); err != nil {
		t.Fatalf("second domain: %v", err)
	}
	_, err = f.runner.Start(context.Background(), input("third.example"), "local-operator")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "2 websites are being created") {
		t.Fatalf("third job: %v", err)
	}
	close(release)
	f.runner.Wait()
	if j, _ := f.runner.Get(first.ID); j.State != StateSucceeded {
		t.Fatalf("first job %s", j.State)
	}
	// The domain is free to try again, and now belongs to an account.
	_, err = f.runner.Start(context.Background(), input("example.com"), "local-operator")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "already belongs to the hosting account example") {
		t.Fatalf("taken domain: %v", err)
	}
	if got := len(f.runner.List()); got != 2 {
		t.Fatalf("refused starts were recorded: %d jobs", got)
	}
}

func TestStartRefusals(t *testing.T) {
	f := newFixture(t)
	for field, change := range map[string]func(*Input){
		"domain":         func(in *Input) { in.Domain = "Example.com" },
		"title":          func(in *Input) { in.Title = "   " },
		"admin_user":     func(in *Input) { in.AdminUser = "-admin" },
		"admin_email":    func(in *Input) { in.AdminEmail = "Me <me@example.com>" },
		"admin_password": func(in *Input) { in.AdminPassword = " short" },
		"php_version":    func(in *Input) { in.PHPVersion = "7.4" },
	} {
		in := input("example.com")
		change(&in)
		_, err := f.runner.Start(context.Background(), in, "local-operator")
		if !errors.Is(err, ErrInvalid) || !strings.HasPrefix(err.Error(), field+" ") {
			t.Errorf("%s: %v", field, err)
		}
	}
	f.acc.listErr = hostaccounts.ErrUnavailable
	if _, err := f.runner.Start(context.Background(), input("example.com"), "local-operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("broker down: %v", err)
	}
	f.acc.listErr = nil
	f.dbs.probeErr = dbhost.ErrUnavailable
	if _, err := f.runner.Start(context.Background(), input("example.com"), "local-operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("database down: %v", err)
	}
	if len(f.acc.calls) != 2 || len(f.runner.List()) != 0 {
		t.Fatalf("refused starts reached the broker or the store: %q", f.acc.calls)
	}
	// A refused start frees its slot.
	f.dbs.probeErr = nil
	if _, err := f.runner.Start(context.Background(), input("example.com"), "local-operator"); err != nil {
		t.Fatal(err)
	}
	f.runner.Wait()
	// The title's outer spaces are dropped, as the broker refuses them.
	if f.acc.install.Title != "My site" {
		t.Fatalf("title %q", f.acc.install.Title)
	}
}

func TestStoredJobsHoldNoSecrets(t *testing.T) {
	f := newFixture(t)
	f.runJob(t, input("example.com"))
	dbPassword := f.dbs.password
	// A failure whose error text quotes both passwords.
	f.acc.installF = func(context.Context) error {
		return &hostaccounts.InstallError{Step: "config", Detail: "dbpass=" + f.dbs.password + " admin=" + testAdminPassword}
	}
	f.runJob(t, input("other.example"))
	f.dbs.userErr = errors.New("ERROR 1064")
	f.runJob(t, input("third.example"))
	path := filepath.Join(f.dir, storeFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testAdminPassword, dbPassword, f.dbs.password} {
		if secret == "" || strings.Contains(string(raw), secret) {
			t.Fatal("a password reached the job store")
		}
	}
	for _, key := range []string{"password", "IDENTIFIED"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("job store mentions %q", key)
		}
	}
	var data storeData
	if err = json.Unmarshal(raw, &data); err != nil || len(data.Jobs) != 3 {
		t.Fatalf("store content: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("store file mode %v", info.Mode())
	}
	dirInfo, err := os.Stat(f.dir)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("store directory mode %v", dirInfo.Mode())
	}
	leftovers, _ := filepath.Glob(filepath.Join(f.dir, ".*tmp*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left: %q", leftovers)
	}
}

func TestStoreKeepsTheNewest50(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wizard")
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 55 {
		j := newJob(fmt.Sprintf("%032x", i+1), "example.com", "local-operator", time.Now())
		j.State = StateFailed
		if i == 0 {
			j.State = StateRunning // a running job is never dropped
		}
		if err = store.put(j); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.jobs) != 50 {
		t.Fatalf("kept %d", len(store.jobs))
	}
	if _, ok := store.Get(fmt.Sprintf("%032x", 1)); !ok {
		t.Fatal("running job dropped")
	}
	if _, ok := store.Get(fmt.Sprintf("%032x", 2)); ok {
		t.Fatal("oldest finished job kept")
	}
	list := store.List(maxListed)
	if len(list) != 20 || list[0].ID != fmt.Sprintf("%032x", 55) {
		t.Fatal("list is not the newest 20, newest first")
	}
}
