package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// InstallPlaceholder of the fake: failure "placeholder-fail" is a failed PHP
// run, "placeholder-kept" a public_html that already held files.
func (f *fakeNative) InstallPlaceholder(_ context.Context, r record) (bool, error) {
	f.placeholders++
	switch f.failure {
	case "placeholder-fail":
		return false, &InstallError{Step: "placeholder", Detail: "index.php could not be written"}
	case "placeholder-kept":
		return false, nil
	}
	return true, nil
}

func TestPlaceholderNeedsALiveSite(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	if _, err := s.installPlaceholder(ctx, a.ID, PlaceholderInput{ExpectedRevision: a.Revision}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("placeholder before the site is live: %v", err)
	}
	a = liveSite(t, s, a)
	for name, tc := range map[string]struct {
		id       string
		revision uint64
		actor    string
		want     error
	}{
		"stale revision":  {a.ID, a.Revision + 1, "test operator", ErrConflict},
		"no revision":     {a.ID, 0, "test operator", ErrInvalid},
		"bad account id":  {"../" + a.ID, a.Revision, "test operator", ErrInvalid},
		"unknown account": {strings.Repeat("e", 32), a.Revision, "test operator", ErrNotFound},
		"no actor":        {a.ID, a.Revision, "", ErrInvalid},
	} {
		if _, err := s.installPlaceholder(ctx, tc.id, PlaceholderInput{ExpectedRevision: tc.revision}, tc.actor); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if f.placeholders != 0 {
		t.Fatal("a refused placeholder reached the native system")
	}
	s.web = nil
	if _, err := s.installPlaceholder(ctx, a.ID, PlaceholderInput{ExpectedRevision: a.Revision}, "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("placeholder with the web operation off: %v", err)
	}
}

func TestPlaceholderJournalsNothing(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := liveSite(t, s, createFixture(t, s))
	before := recordFor(t, s, a.ID)
	in := PlaceholderInput{ExpectedRevision: a.Revision}
	if got, err := s.installPlaceholder(ctx, a.ID, in, "test operator"); err != nil || !got.Written {
		t.Fatalf("placeholder: %+v %v", got, err)
	}
	f.failure = "placeholder-kept"
	if got, err := s.installPlaceholder(ctx, a.ID, in, "test operator"); err != nil || got.Written {
		t.Fatalf("placeholder into a folder with files: %+v %v", got, err)
	}
	f.failure = "placeholder-fail"
	_, err := s.installPlaceholder(ctx, a.ID, in, "test operator")
	var failed *InstallError
	if !errors.As(err, &failed) || failed.Step != "placeholder" {
		t.Fatalf("failed placeholder: %v", err)
	}
	if after := recordFor(t, s, a.ID); after != before || len(s.installing) != 0 || f.placeholders != 3 {
		t.Fatal("a placeholder changed the account record or left it busy")
	}
}

func TestPlaceholderHTTPContract(t *testing.T) {
	s, f := webStore(t)
	a := liveSite(t, s, createFixture(t, s))
	h := handler(s)
	post := func(payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+a.ID+"/placeholder", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	body, _ := json.Marshal(map[string]any{"actor": "test operator", "input": PlaceholderInput{ExpectedRevision: a.Revision}})
	// The page and its path are fixed: a caller cannot send either.
	for _, extra := range []string{`"page":"<?php system($_GET[1]);",`, `"path":"/etc/passwd",`} {
		if rec := post(strings.Replace(string(body), `"expected_revision"`, extra+`"expected_revision"`, 1)); rec.Code != 400 {
			t.Fatalf("a caller-chosen %s must be refused: %d", extra, rec.Code)
		}
	}
	rec := post(string(body))
	var result map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil || len(result) != 1 || result["written"] != true {
		t.Fatalf("placeholder over HTTP: %d %s", rec.Code, rec.Body)
	}
	f.failure = "placeholder-fail"
	rec = post(string(body))
	var failure struct{ Error, Step, Detail string }
	if rec.Code != 422 || json.Unmarshal(rec.Body.Bytes(), &failure) != nil || failure.Error != "install_failed" || failure.Step != "placeholder" {
		t.Fatalf("failed placeholder over HTTP: %d %s", rec.Code, rec.Body)
	}
	if f.placeholders != 2 {
		t.Fatalf("native calls %d", f.placeholders)
	}
}

// The client refuses what the broker would, before it connects; with no
// socket configured, a valid request is unavailable.
func TestPlaceholderClientChecks(t *testing.T) {
	c, ok := NewClient("").(PlaceholderService)
	if !ok {
		t.Fatal("the client has no placeholder operation")
	}
	id := strings.Repeat("a", 32)
	for name, tc := range map[string]struct {
		id       string
		revision uint64
		actor    string
		want     error
	}{
		"bad id":      {"../x", 1, "operator", ErrInvalid},
		"no revision": {id, 0, "operator", ErrInvalid},
		"no actor":    {id, 1, "", ErrInvalid},
		"valid":       {id, 1, "operator", ErrUnavailable},
	} {
		if _, err := c.InstallPlaceholder(context.Background(), tc.id, PlaceholderInput{ExpectedRevision: tc.revision}, tc.actor); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestPlaceholderOutcome(t *testing.T) {
	for _, tc := range []struct {
		out     string
		code    int
		written bool
		failed  bool
	}{
		{"written\n", 0, true, false},
		{"kept\n", 0, false, false},
		{"PHP Deprecated:  something in Command line code\nwritten\n", 0, true, false},
		{"written\n", 5, false, true},
		{"index.php could not be written\n", 5, false, true},
		{"", 0, false, true},
		{"written please\n", 0, false, true},
	} {
		written, err := placeholderOutcome([]byte(tc.out), tc.code)
		var failed *InstallError
		if written != tc.written || (err != nil) != tc.failed || (tc.failed && (!errors.As(err, &failed) || failed.Step != "placeholder")) {
			t.Errorf("%q exit %d: %v %v", tc.out, tc.code, written, err)
		}
	}
}

// The script and page run here with this machine's PHP CLI, as the broker
// runs them with the site's: php -n -r SCRIPT in public_html, the page on
// stdin. Skipped where PHP is not installed.
func TestPlaceholderScriptWithPHP(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php is not installed")
	}
	run := func(dir string) (bool, error) {
		t.Helper()
		cmd := exec.Command(php, "-n", "-r", placeholderScript)
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(placeholderPage)
		out, err := cmd.CombinedOutput()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return placeholderOutcome(out, code)
	}

	empty := t.TempDir()
	if written, err := run(empty); err != nil || !written {
		t.Fatalf("empty folder: %v %v", written, err)
	}
	index := filepath.Join(empty, "index.php")
	got, err := os.ReadFile(index)
	info, serr := os.Stat(index)
	if err != nil || serr != nil || string(got) != placeholderPage || info.Mode().Perm() != 0o644 {
		t.Fatalf("index.php: %v %v %v", err, serr, info)
	}
	// Run again: the folder now holds index.php, which stays as it is.
	if err := os.WriteFile(index, []byte("<?php echo 'mine';"), 0o600); err != nil {
		t.Fatal(err)
	}
	if written, err := run(empty); err != nil || written {
		t.Fatalf("second run: %v %v", written, err)
	}
	if got, _ := os.ReadFile(index); string(got) != "<?php echo 'mine';" {
		t.Fatal("the tenant's index.php was replaced")
	}

	// One hidden file is enough to leave the folder alone.
	hidden := t.TempDir()
	if err := os.WriteFile(filepath.Join(hidden, ".htaccess"), []byte("# mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if written, err := run(hidden); err != nil || written {
		t.Fatalf("folder with a hidden file: %v %v", written, err)
	}
	if _, err := os.Lstat(filepath.Join(hidden, "index.php")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("index.php written next to the tenant's file")
	}

	// A folder the user cannot write is a failure, not a quiet "kept".
	if os.Geteuid() != 0 {
		locked := t.TempDir()
		if err := os.Chmod(locked, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(locked, 0o755) })
		var failed *InstallError
		if written, err := run(locked); written || !errors.As(err, &failed) || !strings.Contains(failed.Detail, "could not be created") {
			t.Fatalf("read-only folder: %v %v", written, err)
		}
	}

	// The page says "It runs PHP." only when PHP runs it.
	if strings.Contains(placeholderPage, "It runs PHP.") {
		t.Fatal("the page's source already holds the text the proof looks for")
	}
	page := filepath.Join(t.TempDir(), "index.php")
	if err := os.WriteFile(page, []byte(placeholderPage), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(php, "-n", page).Output()
	if err != nil || !bytes.Contains(out, []byte("<h1>This website is ready</h1>")) || !bytes.Contains(out, []byte("It runs PHP.")) || bytes.Contains(out, []byte("<?php")) {
		t.Fatalf("rendered page: %v\n%s", err, out)
	}
}
