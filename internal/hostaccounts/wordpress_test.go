package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func wordpressInput(username string, revision uint64) WordPressInput {
	return WordPressInput{
		ExpectedRevision: revision,
		Title:            "Proof site",
		AdminUser:        "siteadmin",
		AdminEmail:       "owner@example.test",
		AdminPassword:    "correct horse battery",
		DBName:           username + "_wp",
		DBUser:           username + "_wp",
		DBPassword:       "db-password-0123",
	}
}

func TestWordPressInputValidation(t *testing.T) {
	good := wordpressInput("fixtureacct", 2)
	if !validWordPress(good, "fixtureacct") {
		t.Fatal("a valid request was refused")
	}
	for name, change := range map[string]func(*WordPressInput){
		"no revision":                 func(in *WordPressInput) { in.ExpectedRevision = 0 },
		"blank title":                 func(in *WordPressInput) { in.Title = "   " },
		"title with a newline":        func(in *WordPressInput) { in.Title = "a\nb" },
		"admin name starting with -":  func(in *WordPressInput) { in.AdminUser = "-path=/etc" },
		"admin name with a space":     func(in *WordPressInput) { in.AdminUser = "site admin" },
		"email with a display name":   func(in *WordPressInput) { in.AdminEmail = "Owner <owner@example.test>" },
		"email without a domain":      func(in *WordPressInput) { in.AdminEmail = "owner" },
		"short admin password":        func(in *WordPressInput) { in.AdminPassword = "short" },
		"password with a newline":     func(in *WordPressInput) { in.AdminPassword = "first line\nsecond" },
		"database of another account": func(in *WordPressInput) { in.DBName = "otheracct_wp" },
		"database user of another":    func(in *WordPressInput) { in.DBUser = "otheracct_wp" },
		"bare prefix":                 func(in *WordPressInput) { in.DBName = "fixtureacct_" },
		"database name with a dot":    func(in *WordPressInput) { in.DBName = "fixtureacct_wp.x" },
		"database user too long":      func(in *WordPressInput) { in.DBUser = "fixtureacct_" + strings.Repeat("u", 40) },
	} {
		in := good
		change(&in)
		if validWordPress(in, "fixtureacct") {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInstallDetailHidesSecretsAndControlBytes(t *testing.T) {
	out := []byte("Warning: x\x1b[31m\nError: Access denied for 'u'@'localhost' using password db-password-0123\r\n" + strings.Repeat("y", 700))
	got := installDetail(out, "db-password-0123")
	if strings.Contains(got, "db-password-0123") || strings.ContainsAny(got, "\x1b\r\n") || len(got) > 512 {
		t.Fatalf("detail %q", got)
	}
	if !strings.HasSuffix(got, "yyyy") {
		t.Fatal("the end of the output must be kept")
	}
}

func liveSite(t *testing.T, s *store, a Account) Account {
	t.Helper()
	got, err := s.setWeb(context.Background(), a.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: a.Revision, Reason: "Go live"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	return got.Account
}

func TestWordPressInstallNeedsALiveSite(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	if _, err := s.installWordPress(ctx, a.ID, wordpressInput(a.Username, a.Revision), "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("install before the site is live: %v", err)
	}
	a = liveSite(t, s, a)
	if _, err := s.installWordPress(ctx, a.ID, wordpressInput(a.Username, a.Revision+1), "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("install with a stale revision: %v", err)
	}
	if _, err := s.installWordPress(ctx, a.ID, wordpressInput("otheracct", a.Revision), "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("install into another account's database: %v", err)
	}
	if f.wpInstalls != 0 {
		t.Fatal("a refused install reached the native system")
	}
	s.web = nil
	if _, err := s.installWordPress(ctx, a.ID, wordpressInput(a.Username, a.Revision), "test operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("install with the web operation off: %v", err)
	}
}

func TestWordPressInstallJournalsNothing(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := liveSite(t, s, createFixture(t, s))
	before := recordFor(t, s, a.ID)
	got, err := s.installWordPress(ctx, a.ID, wordpressInput(a.Username, a.Revision), "test operator")
	if err != nil || got.Version != "6.8.3" {
		t.Fatalf("install: %+v %v", got, err)
	}
	if after := recordFor(t, s, a.ID); after != before {
		t.Fatal("an install changed the account record")
	}
	f.failure = "wp-fail"
	_, err = s.installWordPress(ctx, a.ID, wordpressInput(a.Username, a.Revision), "test operator")
	var failed *InstallError
	if !errors.As(err, &failed) || !errors.Is(err, ErrInstallFailed) || failed.Step != "download" || strings.Contains(failed.Detail, "db-password-0123") {
		t.Fatalf("failed install: %v %+v", err, failed)
	}
	if after := recordFor(t, s, a.ID); after != before || len(s.installing) != 0 {
		t.Fatal("a failed install left the account changed or busy")
	}
}

// The install runs outside the broker lock: other requests are served
// meanwhile, but this account cannot be deleted or installed twice.
func TestWordPressInstallHoldsNoLock(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := liveSite(t, s, createFixture(t, s))
	gate := make(chan struct{})
	f.wpStarted, f.wpGate = make(chan struct{}, 1), gate
	done := make(chan error, 1)
	go func() {
		_, err := s.installWordPress(ctx, a.ID, wordpressInput(a.Username, a.Revision), "test operator")
		done <- err
	}()
	<-f.wpStarted
	if _, err := s.list(ctx); err != nil {
		t.Fatalf("list during an install: %v", err)
	}
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete during an install: %v", err)
	}
	// Refused before the native system, so it does not wait at the gate.
	if _, err := s.installWordPress(ctx, a.ID, wordpressInput(a.Username, a.Revision), "test operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second install during the first: %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := s.delete(ctx, a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Remove"}, "test operator"); err != nil {
		t.Fatalf("delete after the install: %v", err)
	}
}

func TestWordPressHTTPContract(t *testing.T) {
	s, f := webStore(t)
	a := liveSite(t, s, createFixture(t, s))
	h := handler(s)
	post := func(payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+a.ID+"/wordpress", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	in := wordpressInput(a.Username, a.Revision)
	body, _ := json.Marshal(map[string]any{"actor": "test operator", "input": in})
	if rec := post(strings.Replace(string(body), `"title"`, `"url":"http://evil.test","title"`, 1)); rec.Code != 400 {
		t.Fatalf("a caller-chosen URL must be refused: %d", rec.Code)
	}
	rec := post(string(body))
	var result WordPressResult
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Version != "6.8.3" {
		t.Fatalf("install over HTTP: %d %s", rec.Code, rec.Body)
	}
	f.failure = "wp-fail"
	rec = post(string(body))
	var failure struct{ Error, Step, Detail string }
	if rec.Code != 422 || json.Unmarshal(rec.Body.Bytes(), &failure) != nil || failure.Error != "install_failed" || failure.Step != "download" || strings.Contains(rec.Body.String(), in.DBPassword) {
		t.Fatalf("failed install over HTTP: %d %s", rec.Code, rec.Body)
	}
}
