package phpmyadmin

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sifruno/internal/dbhost"
)

// fakeDatabase stands in for dbhost.LocalService: the server's temporary
// users, each with its owner, databases and password.
type fakeDatabase struct {
	mu        sync.Mutex
	users     map[string]fakeUser
	calls     []string
	createErr func(name, password string) error
	dropErr   error
	listErr   error
}

type fakeUser struct {
	owner, password string
	databases       []string
}

func newFakeDatabase() *fakeDatabase { return &fakeDatabase{users: map[string]fakeUser{}} }

func (f *fakeDatabase) CreateSignonUser(_ context.Context, owner, name, password string, databases []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "create "+owner+" "+name+" "+strings.Join(databases, ","))
	if !dbhost.ValidSignonUser(name) {
		return errors.New("bad name " + name)
	}
	if f.createErr != nil {
		if err := f.createErr(name, password); err != nil {
			return err
		}
	}
	if _, ok := f.users[name]; ok {
		return dbhost.ErrExists
	}
	f.users[name] = fakeUser{owner: owner, password: password, databases: slices.Clone(databases)}
	return nil
}

func (f *fakeDatabase) DropSignonUser(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "drop "+name)
	if f.dropErr != nil {
		return f.dropErr
	}
	delete(f.users, name)
	return nil
}

func (f *fakeDatabase) SignonUsers(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []string{}
	for name := range f.users {
		out = append(out, name)
	}
	slices.Sort(out)
	return out, nil
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestService(t *testing.T, db Database, c *clock) (*Service, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "phpmyadmin")
	s, err := New(Config{StateDir: dir, Database: db, PublicPort: 8444, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func codeOf(t *testing.T, h Handoff) string {
	t.Helper()
	u, err := url.Parse(h.Path)
	if err != nil || u.Path != SignonPath || u.Host != "" || len(u.Query()) != 1 {
		t.Fatalf("handoff path %q", h.Path)
	}
	code := u.Query().Get("code")
	if !codePattern.MatchString(code) {
		t.Fatalf("code %q", code)
	}
	return code
}

func TestOpenMakesATemporaryUserForTheDatabasesGiven(t *testing.T) {
	db := newFakeDatabase()
	c := &clock{now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	s, dir := newTestService(t, db, c)
	h, err := s.Open(context.Background(), "alpha", []string{"alpha_wp", "alpha_shop"})
	if err != nil {
		t.Fatal(err)
	}
	if len(db.users) != 1 {
		t.Fatalf("users %v", db.users)
	}
	var user string
	for name, u := range db.users {
		user = name
		if u.owner != "alpha" || !slices.Equal(u.databases, []string{"alpha_wp", "alpha_shop"}) || len(u.password) != 43 {
			t.Fatalf("user %s: owner %s, databases %v, password of %d characters", name, u.owner, u.databases, len(u.password))
		}
	}
	if !h.LoginExpires.Equal(c.Now().Add(time.Hour)) || !h.CodeExpires.Equal(c.Now().Add(time.Minute)) {
		t.Fatalf("expiry: login %v code %v", h.LoginExpires, h.CodeExpires)
	}
	// The password is in neither the address nor the record.
	if strings.Contains(h.Path, db.users[user].password) {
		t.Fatal("the password is in the handoff path")
	}
	if got := s.SignonURL("panel.example.test", h); got != "https://panel.example.test:8444"+h.Path {
		t.Fatalf("signon URL %q", got)
	}
	if got := s.SignonURL("2001:db8::1", h); got != "https://[2001:db8::1]:8444"+h.Path {
		t.Fatalf("signon URL for an IPv6 address %q", got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil || !strings.Contains(string(raw), user) || !strings.Contains(string(raw), `"owner":"alpha"`) || strings.Contains(string(raw), db.users[user].password) {
		t.Fatalf("record %s %v", raw, err)
	}
	for _, path := range []string{dir, filepath.Join(dir, stateFile)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is not private: %v", path, info.Mode())
		}
	}

	// Two clicks, two users and two codes.
	h2, err := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	if err != nil || codeOf(t, h2) == codeOf(t, h) || len(db.users) != 2 {
		t.Fatalf("second open: %v, %d users", err, len(db.users))
	}
	if _, err := s.Open(context.Background(), "", []string{"alpha_wp"}); err == nil {
		t.Fatal("an empty owner was accepted")
	}
	if _, err := s.Open(context.Background(), "alpha", nil); err == nil {
		t.Fatal("no databases was accepted")
	}
}

func TestACodeWorksOnceAndForAMinute(t *testing.T) {
	db := newFakeDatabase()
	c := &clock{now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	s, _ := newTestService(t, db, c)
	h, err := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	if err != nil {
		t.Fatal(err)
	}
	code := codeOf(t, h)
	login, err := s.Redeem(code)
	if err != nil || db.users[login.User].password != login.Password || !login.Expires.Equal(h.LoginExpires) {
		t.Fatalf("redeem: %+v %v", login.User, err)
	}
	if _, err := s.Redeem(code); !errors.Is(err, ErrCodeRefused) {
		t.Fatalf("a used code: %v", err)
	}

	// Expired: refused at 60 s, and gone after the attempt.
	h, _ = s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	code = codeOf(t, h)
	c.Add(60 * time.Second)
	if _, err := s.Redeem(code); !errors.Is(err, ErrCodeRefused) {
		t.Fatalf("an expired code: %v", err)
	}
	c.Add(-30 * time.Second)
	if _, err := s.Redeem(code); !errors.Is(err, ErrCodeRefused) {
		t.Fatalf("a code refused once works later: %v", err)
	}

	// Unknown and malformed codes.
	for _, bad := range []string{"", strings.Repeat("A", 43), strings.Repeat("A", 42), code + "A", strings.Repeat("A", 42) + "/"} {
		if _, err := s.Redeem(bad); !errors.Is(err, ErrCodeRefused) {
			t.Fatalf("code %q: %v", bad, err)
		}
	}

	// A code whose user was swept is refused even inside its minute.
	short, err := New(Config{StateDir: t.TempDir(), Database: db, PublicPort: 8444, Now: c.Now, LoginTTL: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	h, _ = short.Open(context.Background(), "alpha", []string{"alpha_wp"})
	c.Add(31 * time.Second)
	if _, err := short.Redeem(codeOf(t, h)); !errors.Is(err, ErrCodeRefused) {
		t.Fatalf("the code of an expired login: %v", err)
	}
}

func TestSweepDropsExpiredAndUnrecordedUsers(t *testing.T) {
	db := newFakeDatabase()
	c := &clock{now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	s, dir := newTestService(t, db, c)
	ctx := context.Background()
	first, _ := s.Open(ctx, "alpha", []string{"alpha_wp"})
	c.Add(30 * time.Minute)
	second, _ := s.Open(ctx, "beta", []string{"beta_wp"})
	firstUser, secondUser := "", ""
	for name, u := range db.users {
		if u.owner == "alpha" {
			firstUser = name
		} else {
			secondUser = name
		}
	}
	// Left by a crash: on the server, in no record.
	orphan := dbhost.SignonUserPrefix + "00000000000000000000"
	db.users[orphan] = fakeUser{owner: "gamma"}

	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.users[orphan]; ok {
		t.Fatal("the unrecorded user is still on the server")
	}
	if len(db.users) != 2 {
		t.Fatalf("a live user was dropped: %v", db.calls)
	}

	// The first expires at 60 minutes: gone, and its redeemed session ends.
	c.Add(30 * time.Minute)
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.users[firstUser]; ok {
		t.Fatal("the expired user is still on the server")
	}
	if _, ok := db.users[secondUser]; !ok {
		t.Fatal("the user with 30 minutes left was dropped")
	}
	if _, err := s.Redeem(codeOf(t, first)); !errors.Is(err, ErrCodeRefused) {
		t.Fatalf("the expired user's code: %v", err)
	}

	// A failed drop keeps the record, and the next sweep tries again; a
	// restarted panel reads the record and still drops the user.
	c.Add(31 * time.Minute)
	db.dropErr = dbhost.ErrUnavailable
	if err := s.Sweep(ctx); !errors.Is(err, dbhost.ErrUnavailable) {
		t.Fatalf("failed drop: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if !strings.Contains(string(raw), secondUser) {
		t.Fatal("a user that could not be dropped left the record")
	}
	db.dropErr = nil
	restarted, err := New(Config{StateDir: dir, Database: db, PublicPort: 8444, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(db.users) != 0 {
		t.Fatalf("users left after the sweep: %v", db.users)
	}
	if _, err := restarted.Redeem(codeOf(t, second)); !errors.Is(err, ErrCodeRefused) {
		t.Fatal("a code survived the restart")
	}
	raw, _ = os.ReadFile(filepath.Join(dir, stateFile))
	if string(raw) != `{"logins":[]}` {
		t.Fatalf("record after the sweep: %s", raw)
	}

	// A name in the record that is not a temporary user's is never dropped.
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"logins":[{"user":"alpha_wp","owner":"alpha","expires_at":"2020-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	db.calls = nil
	again, err := New(Config{StateDir: dir, Database: db, PublicPort: 8444, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Sweep(ctx); err != nil || len(db.calls) != 0 {
		t.Fatalf("sweep with a foreign name: %v %q", err, db.calls)
	}
}

func TestOpenFailuresLeaveNothingBehind(t *testing.T) {
	db := newFakeDatabase()
	c := &clock{now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	s, dir := newTestService(t, db, c)
	ctx := context.Background()

	// The database server quotes the password: it never reaches the error.
	db.createErr = func(_, password string) error {
		return errors.New("ERROR 1064 (42000) at line 1: near 'IDENTIFIED BY '" + password + "''")
	}
	_, err := s.Open(ctx, "alpha", []string{"alpha_wp"})
	if err == nil || !strings.Contains(err.Error(), "[secret]") {
		t.Fatalf("error %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if string(raw) != `{"logins":[]}` {
		t.Fatalf("a failed create stayed recorded: %s", raw)
	}
	db.createErr = func(string, string) error { return dbhost.ErrUnavailable }
	if _, err := s.Open(ctx, "alpha", []string{"alpha_wp"}); !errors.Is(err, dbhost.ErrUnavailable) {
		t.Fatalf("server down: %v", err)
	}

	// A random name the server has already: another name, once.
	tries := 0
	db.createErr = func(string, string) error {
		tries++
		if tries == 1 {
			return dbhost.ErrExists
		}
		return nil
	}
	if _, err := s.Open(ctx, "alpha", []string{"alpha_wp"}); err != nil || tries != 2 {
		t.Fatalf("retry: %v after %d tries", err, tries)
	}
	db.createErr = func(string, string) error { return dbhost.ErrExists }
	if _, err := s.Open(ctx, "alpha", []string{"alpha_wp"}); !errors.Is(err, dbhost.ErrExists) {
		t.Fatalf("two taken names: %v", err)
	}
	db.createErr = nil

	// At most MaxLogins at once.
	for len(s.logins) < MaxLogins {
		if _, err := s.Open(ctx, "alpha", []string{"alpha_wp"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Open(ctx, "alpha", []string{"alpha_wp"}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("over the limit: %v", err)
	}

	// The record cannot be written: no user is made.
	fresh, _ := newTestService(t, db, c)
	if err := os.Chmod(fresh.cfg.StateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fresh.cfg.StateDir, 0o700) })
	if os.Geteuid() != 0 {
		before := len(db.users)
		if _, err := fresh.Open(ctx, "alpha", []string{"alpha_wp"}); !errors.Is(err, ErrNotRecorded) || len(db.users) != before {
			t.Fatalf("unwritable record: %v", err)
		}
	}
}

func TestTheAdmissionCookieEndsWithItsLogin(t *testing.T) {
	db := newFakeDatabase()
	c := &clock{now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	s, _ := newTestService(t, db, c)
	h, err := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	if err != nil {
		t.Fatal(err)
	}
	code := codeOf(t, h)
	user, ok := s.Peek(code)
	if !ok || db.users[user].owner != "alpha" {
		t.Fatalf("peek %q %v", user, ok)
	}
	// Peeking does not use the code up.
	if _, err := s.Redeem(code); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Peek(code); ok {
		t.Fatal("a redeemed code still peeks")
	}
	token, expires, err := s.Admit(user)
	if err != nil || !expires.Equal(h.LoginExpires) || !codePattern.MatchString(token) {
		t.Fatalf("admit %v %v", expires, err)
	}
	if !s.Admitted(token) {
		t.Fatal("a fresh admission is refused")
	}
	for _, bad := range []string{"", strings.Repeat("A", 43), token + "A", code} {
		if s.Admitted(bad) {
			t.Fatalf("%q admitted", bad)
		}
	}
	other, _, err := s.Admit(user)
	if err != nil || other == token {
		t.Fatal("two admissions share a value")
	}
	s.Revoke(other)
	if s.Admitted(other) || !s.Admitted(token) {
		t.Fatal("revoke ended the wrong admission")
	}
	if _, _, err := s.Admit("SifrunoPMA_ffffffffffffffffffff"); err == nil {
		t.Fatal("an admission for a user with no login")
	}

	// The login expires: the admission ends with it, before the sweep too.
	c.Add(time.Hour)
	if s.Admitted(token) {
		t.Fatal("the admission outlived its login")
	}
	if _, _, err := s.Admit(user); err == nil {
		t.Fatal("an admission for an expired login")
	}
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.admissions) != 0 {
		t.Fatalf("admissions left after the sweep: %d", len(s.admissions))
	}

	// A swept login's code no longer peeks.
	h, _ = s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	code = codeOf(t, h)
	c.Add(61 * time.Second)
	if _, ok := s.Peek(code); ok {
		t.Fatal("an expired code peeks")
	}
	if _, err := New(Config{StateDir: t.TempDir(), Database: db}); err == nil {
		t.Fatal("a service without the origin's port")
	}
}
