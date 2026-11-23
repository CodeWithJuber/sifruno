package wizard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPHPVersionIsKeptWithTheJob(t *testing.T) {
	f := newFixture(t)
	in := input("example.com")
	in.PHPVersion = "8.2"
	done := f.runJob(t, in)
	if done.PHPVersion != "8.2" {
		t.Fatalf("job PHP version %q", done.PHPVersion)
	}
	store, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if again, ok := store.Get(done.ID); !ok || again.PHPVersion != "8.2" {
		t.Fatalf("reopened job PHP version %q", again.PHPVersion)
	}
}

// A job file written before php_version existed still opens, as it was.
func TestJobFileWithoutPHPVersionLoads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wizard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	steps := []string{}
	for _, s := range stepTitles {
		steps = append(steps, fmt.Sprintf(`{"name":%q,"title":%q,"state":"done","message":"","started_at":"2026-11-20T10:00:00Z","finished_at":"2026-11-20T10:01:00Z"}`, s.name, s.title))
	}
	id := strings.Repeat("a", 32)
	old := `{"version":1,"jobs":[{"id":"` + id + `","kind":"wordpress","domain":"example.com","username":"example","state":"succeeded","steps":[` + strings.Join(steps, ",") +
		`],"error":null,"result":{"url":"https://example.com/","admin_url":"https://example.com/wp-admin/","wordpress_version":"7.1.5","account_id":"` + strings.Repeat("b", 32) + `"},"actor":"local-operator","created_at":"2026-11-20T10:00:00Z","updated_at":"2026-11-20T10:05:00Z"}]}`
	if err := os.WriteFile(filepath.Join(dir, storeFile), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if aside, _ := filepath.Glob(filepath.Join(dir, storeFile+".corrupt-*")); len(aside) != 0 {
		t.Fatalf("old file set aside: %q", aside)
	}
	j, ok := store.Get(id)
	if !ok || j.PHPVersion != "" || j.State != StateSucceeded || j.Result == nil || j.Result.WordPressVersion != "7.1.5" {
		t.Fatalf("old job %+v", j)
	}
	r := New(&fakeAccounts{}, &fakeDatabases{}, store, nil)
	if got := r.Succeeded(); len(got) != 1 || got[0].ID != id {
		t.Fatalf("succeeded %+v", got)
	}
}

func TestSucceededListsEveryKeptSiteNewestFirst(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "wizard"))
	if err != nil {
		t.Fatal(err)
	}
	// 40 jobs, more than List's 20: every third failed, one succeeded without
	// an account (not a site), and the newest still running.
	for i := range 40 {
		j := newJob(fmt.Sprintf("%032x", i+1), fmt.Sprintf("site%d.example", i+1), "local-operator", time.Now())
		switch {
		case i == 39:
			// left running
		case i%3 == 0:
			j.State = StateFailed
		case i == 10:
			j.State = StateSucceeded
			j.Result = &Result{URL: "http://x.example/"}
		default:
			j.State = StateSucceeded
			j.Result = &Result{URL: "https://" + j.Domain + "/", AccountID: fmt.Sprintf("%032x", 1000+i)}
		}
		if err = store.put(j); err != nil {
			t.Fatal(err)
		}
	}
	got := New(&fakeAccounts{}, &fakeDatabases{}, store, nil).Succeeded()
	want := []string{}
	for i := 38; i >= 0; i-- {
		if i%3 != 0 && i != 10 {
			want = append(want, fmt.Sprintf("%032x", i+1))
		}
	}
	ids := []string{}
	for _, j := range got {
		ids = append(ids, j.ID)
	}
	if strings.Join(ids, " ") != strings.Join(want, " ") {
		t.Fatalf("succeeded %q\nwant %q", ids, want)
	}
	if len(got) <= maxListed {
		t.Fatalf("only %d sites: the list is limited like List's %d", len(got), maxListed)
	}
	// Copies: changing one does not change the store.
	got[0].Result.URL = "changed"
	if again, _ := store.Get(got[0].ID); again.Result.URL == "changed" {
		t.Fatal("Succeeded shares the store's result")
	}
}
