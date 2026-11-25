package wizard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
)

const testDBPassword = "chosen db pass 0123"

func (f *fakeAccounts) InstallPlaceholder(ctx context.Context, id string, in hostaccounts.PlaceholderInput, actor string) (hostaccounts.PlaceholderResult, error) {
	f.record(fmt.Sprintf("page %s rev=%d", id[28:], in.ExpectedRevision))
	if actor == "" {
		return hostaccounts.PlaceholderResult{}, hostaccounts.ErrInvalid
	}
	if f.pageF != nil {
		written, err := f.pageF(ctx)
		return hostaccounts.PlaceholderResult{Written: written}, err
	}
	return hostaccounts.PlaceholderResult{Written: true}, nil
}

func phpInput(domain string, database bool) Input {
	in := Input{Kind: KindPHP, Domain: domain, PHPVersion: "8.2"}
	if database {
		in.Database, in.DBPassword = true, testDBPassword
	}
	return in
}

func TestPHPSiteJobSucceeds(t *testing.T) {
	f := newFixture(t)
	// A PHP site without a database does not need the database server.
	f.dbs.probeErr = errors.New("database server down")
	done := f.runJob(t, phpInput("example.com", false))
	if done.State != StateSucceeded || done.Kind != KindPHP || done.Username != "example" || done.PHPVersion != "8.2" || done.Error != nil {
		t.Fatalf("finished job: %+v", done)
	}
	if got := stepStates(done); got != "account=done web=done ssl=skipped database=skipped placeholder=done" {
		t.Fatal(got)
	}
	titles := []string{}
	for _, s := range done.Steps {
		titles = append(titles, s.Title)
		if s.StartedAt == "" || s.FinishedAt == "" || s.Message == "" {
			t.Fatalf("step without times or message: %+v", s)
		}
	}
	if !slices.Equal(titles, []string{"Create the hosting account", "Put the site live with PHP", "Turn on https", "Create the database", "Add a placeholder page"}) {
		t.Fatalf("titles %q", titles)
	}
	if msg := done.Steps[3].Message; msg != "No database was asked for." {
		t.Fatalf("database step: %q", msg)
	}
	if msg := done.Steps[4].Message; !strings.Contains(msg, "public_html/index.php") {
		t.Fatalf("placeholder step: %q", msg)
	}
	want := Result{URL: "http://example.com/", AccountID: fmt.Sprintf("%032x", 1)}
	if done.Result == nil || *done.Result != want {
		t.Fatalf("result %+v", done.Result)
	}
	wantAcc := []string{"list", "create example", "web 0001 php=8.2 quota=1024 rev=1 reason=PHP site wizard", "page 0001 rev=2"}
	if !slices.Equal(f.acc.calls, wantAcc) {
		t.Fatalf("broker calls %q", f.acc.calls)
	}
	if len(f.dbs.calls) != 0 {
		t.Fatalf("database calls %q", f.dbs.calls)
	}
}

func TestPHPSiteWithDatabase(t *testing.T) {
	f := newFixture(t)
	done := f.runJob(t, phpInput("example.com", true))
	if got := stepStates(done); got != "account=done web=done ssl=skipped database=done placeholder=done" {
		t.Fatal(got)
	}
	wantDB := []string{"create-db example example_wp", "create-user example example_wp", "grant example example_wp example_wp"}
	if !slices.Equal(f.dbs.calls, wantDB) || f.dbs.password != testDBPassword {
		t.Fatalf("database calls %q, the user's password is not the one chosen", f.dbs.calls)
	}
	if done.Result == nil || done.Result.Database != "example_wp" || done.Result.AdminURL != "" || done.Result.WordPressVersion != "" {
		t.Fatalf("result %+v", done.Result)
	}
	if msg := done.Steps[3].Message; msg != "Created the database example_wp and its user example_wp." {
		t.Fatalf("database step: %q", msg)
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, storeFile))
	if err != nil || strings.Contains(string(raw), testDBPassword) || strings.Contains(string(raw), "password") {
		t.Fatalf("job store: %v, or it holds the password", err)
	}
	// A PHP job is kept by a reopened store, as it was saved.
	store, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if again, ok := store.Get(done.ID); !ok || again.Kind != KindPHP || len(again.Steps) != 5 || again.Result.Database != "example_wp" {
		t.Fatalf("reopened: %+v", again)
	}
}

func TestPHPSitePlaceholderLeavesFilesAlone(t *testing.T) {
	f := newFixture(t)
	f.acc.pageF = func(context.Context) (bool, error) { return false, nil }
	done := f.runJob(t, phpInput("example.com", false))
	if done.State != StateSucceeded || done.Steps[4].State != StepDone || !strings.Contains(done.Steps[4].Message, "already had files") {
		t.Fatalf("job %+v", done.Steps[4])
	}
}

func TestPHPSiteFailureUndoes(t *testing.T) {
	pageErr := &hostaccounts.InstallError{Step: "placeholder", Detail: "index.php could not be created " + testDBPassword}
	for _, tc := range []struct {
		name     string
		database bool
		setup    func(f fixture)
		states   string
		step     string
		what     string
		undoAcc  []string
		undoDB   []string
		tech     string
	}{
		{
			name:     "placeholder fails",
			database: true,
			setup:    func(f fixture) { f.acc.pageF = func(context.Context) (bool, error) { return false, pageErr } },
			states:   "account=undone web=undone ssl=skipped database=undone placeholder=failed",
			step:     StepPlaceholder, what: "The placeholder page could not be added.",
			undoAcc: []string{"delete 0001 rev=2"},
			undoDB:  []string{"drop-user example example_wp", "drop-db example example_wp"},
			tech:    "placeholder: index.php could not be created [secret]",
		},
		{
			name:     "placeholder fails without a database",
			database: false,
			setup: func(f fixture) {
				f.acc.pageF = func(context.Context) (bool, error) { return false, hostaccounts.ErrConflict }
			},
			states: "account=undone web=undone ssl=skipped database=skipped placeholder=failed",
			step:   StepPlaceholder, what: "The placeholder page could not be added.",
			undoAcc: []string{"delete 0001 rev=2"},
		},
		{
			name:     "database user",
			database: true,
			setup: func(f fixture) {
				f.dbs.userErr = errors.New("ERROR 1064 (42000) at line 1: You have an error in your SQL syntax")
			},
			states: "account=undone web=undone ssl=skipped database=failed placeholder=skipped",
			step:   StepDatabase, what: "The database could not be created.",
			undoAcc: []string{"delete 0001 rev=2"},
			undoDB:  []string{"drop-db example example_wp"},
			tech:    "ERROR 1064 (42000) at line 1: You have an error in your SQL syntax near [statement removed]",
		},
		{
			name:     "web",
			database: true,
			setup:    func(f fixture) { f.acc.webErr = hostaccounts.ErrWebRejected },
			states:   "account=undone web=failed ssl=skipped database=skipped placeholder=skipped",
			step:     StepWeb, what: "The site could not be put live.",
			undoAcc: []string{"delete 0001 rev=1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			done := f.runJob(t, phpInput("example.com", tc.database))
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
			var undo []string
			for _, c := range f.order.all {
				if strings.HasPrefix(c, "drop") || strings.HasPrefix(c, "delete") {
					undo = append(undo, c)
				}
			}
			if !slices.Equal(undo, append(slices.Clone(tc.undoDB), tc.undoAcc...)) {
				t.Fatalf("undo %q", undo)
			}
			raw, err := os.ReadFile(filepath.Join(f.dir, storeFile))
			if err != nil || strings.Contains(string(raw), testDBPassword) {
				t.Fatal("the chosen password reached the job store")
			}
		})
	}
}

func TestPHPSiteUndoReason(t *testing.T) {
	f := newFixture(t)
	var reason string
	f.acc.pageF = func(context.Context) (bool, error) { return false, hostaccounts.ErrUnavailable }
	acc := &reasonAccounts{fakeAccounts: f.acc, reason: &reason}
	f.runner.accounts = acc
	f.runJob(t, phpInput("example.com", false))
	if reason != "PHP site wizard: removed after a later step failed" {
		t.Fatalf("undo reason %q", reason)
	}
}

// reasonAccounts records the reason undo gives the broker.
type reasonAccounts struct {
	*fakeAccounts
	reason *string
}

func (r *reasonAccounts) Delete(ctx context.Context, id string, in hostaccounts.DeleteInput, actor string) (hostaccounts.Account, error) {
	*r.reason = in.Reason
	return r.fakeAccounts.Delete(ctx, id, in, actor)
}

func TestPHPSiteInputRules(t *testing.T) {
	good := phpInput("example.com", true)
	if _, err := Validate(good); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(phpInput("example.com", false)); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		change func(*Input)
		prefix string
	}{
		"bad domain":                   {func(in *Input) { in.Domain = "Example.com" }, "domain "},
		"bad PHP version":              {func(in *Input) { in.PHPVersion = "7.4" }, "php_version "},
		"short database password":      {func(in *Input) { in.DBPassword = "short" }, "database_password "},
		"database password edge space": {func(in *Input) { in.DBPassword = " " + testDBPassword }, "database_password "},
		"database password line break": {func(in *Input) { in.DBPassword = "chosen\npassword0123" }, "database_password "},
		"no database password":         {func(in *Input) { in.DBPassword = "" }, "database_password "},
		"password without database":    {func(in *Input) { in.Database = false }, "database_password "},
		"a WordPress title":            {func(in *Input) { in.Title = "My site" }, "A PHP site has no WordPress"},
		"a WordPress admin":            {func(in *Input) { in.AdminUser = "siteadmin" }, "A PHP site has no WordPress"},
		"a WordPress admin password":   {func(in *Input) { in.AdminPassword = testAdminPassword }, "A PHP site has no WordPress"},
		"an unknown kind":              {func(in *Input) { in.Kind = "static" }, "The website type"},
	} {
		in := good
		tc.change(&in)
		_, err := Validate(in)
		var refusal *Refusal
		if !errors.As(err, &refusal) || !errors.Is(err, ErrInvalid) || !strings.HasPrefix(refusal.Detail, tc.prefix) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A WordPress site's database password is the panel's to make.
	wp := input("example.com")
	wp.Database, wp.DBPassword = true, testDBPassword
	if _, err := Validate(wp); !errors.Is(err, ErrInvalid) {
		t.Fatalf("WordPress with a chosen database password: %v", err)
	}
	if in, err := Validate(input("example.com")); err != nil || in.Kind != KindWordPress {
		t.Fatalf("a request without a kind is WordPress: %+v %v", in, err)
	}
	// A refused PHP site reaches neither the broker nor the store.
	f := newFixture(t)
	bad := good
	bad.DBPassword = "short"
	if _, err := f.runner.Start(context.Background(), bad, "local-operator"); !errors.Is(err, ErrInvalid) || len(f.acc.calls) != 0 || len(f.runner.List()) != 0 {
		t.Fatalf("refused start: %v %q", err, f.acc.calls)
	}
}

// A stored job of a kind this panel does not know makes the store unusable,
// so it is set aside like any other damaged job file.
func TestStoreRefusesAnUnknownKind(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wizard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	steps := []string{}
	for _, s := range phpStepTitles {
		steps = append(steps, `{"name":"`+s.name+`","title":"`+s.title+`","state":"done","message":"","started_at":"","finished_at":""}`)
	}
	job := func(kind string) string {
		return `{"version":1,"jobs":[{"id":"` + strings.Repeat("a", 32) + `","kind":"` + kind + `","domain":"example.com","username":"example","php_version":"8.3","state":"succeeded","steps":[` + strings.Join(steps, ",") + `],"error":null,"result":{"url":"http://example.com/","admin_url":"","wordpress_version":"","account_id":"` + strings.Repeat("b", 32) + `"},"actor":"local-operator","created_at":"2026-11-24T00:00:00Z","updated_at":"2026-11-24T00:00:00Z"}]}`
	}
	logOutput = &strings.Builder{}
	t.Cleanup(func() { logOutput = os.Stderr })
	for kind, kept := range map[string]bool{KindPHP: true, "static": false} {
		if err := os.WriteFile(filepath.Join(dir, storeFile), []byte(job(kind)), 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := OpenStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := store.Get(strings.Repeat("a", 32)); ok != kept {
			t.Errorf("kind %s: kept %v", kind, ok)
		}
	}
}
