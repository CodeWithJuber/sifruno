package operator

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Sessions opened with a password and a code are saved, sealed, in the
// panel's private folder, so a restart does not sign people out. Sessions
// opened with the access key are not: a restart still ends them.

// restart saves the sessions as a graceful stop does, then opens the private
// folder again as a starting panel does, on the same clock.
func restart(t *testing.T, m *Manager) (*Manager, http.Handler) {
	t.Helper()
	if err := m.Close(); err != nil {
		t.Fatalf("saving sessions on close: %v", err)
	}
	m2, err := Open(filepath.Dir(m.AccessKeyPath()))
	if err != nil {
		t.Fatal(err)
	}
	m2.now = m.now
	mux := http.NewServeMux()
	m2.Register(mux)
	return m2, mux
}

func savedSessionsPath(m *Manager) string { return filepath.Join(m.dir, savedSessionsFile) }

func TestPasswordSessionsSurviveARestart(t *testing.T) {
	m, h, key := fixture(t)
	base := time.Unix(1_800_000_000, 0)
	clock := base
	m.now = func() time.Time { return clock }
	secret, _ := setUpAdmin(t, m, h, key, clock)
	clock = clock.Add(30 * time.Second)
	normal, normalCSRF := signInAs(t, h, "admin", setupWords, codeAt(t, secret, clock))
	clock = clock.Add(30 * time.Second)
	w := opRequest(h, "POST", "/api/v1/session/login", keepSignedInBody("admin", setupWords, codeAt(t, secret, clock)), nil, "")
	if w.Code != 200 {
		t.Fatalf("kept sign-in: %d", w.Code)
	}
	kept := w.Result().Cookies()[0]
	keyCookie, _ := signIn(t, h, key, nil)
	before := inventoryFor(t, h, normal)

	clock = clock.Add(10 * time.Minute)
	if w := opRequest(h, "GET", inventoryPath, "", normal, ""); w.Code != 200 {
		t.Fatalf("activity before the restart: %d", w.Code)
	}
	lastActivity := clock

	m2, h2 := restart(t, m)
	if sessionStatus(h2, normal) != 200 || sessionStatus(h2, kept) != 200 {
		t.Fatal("a password session did not survive the restart")
	}
	if sessionStatus(h2, keyCookie) != 401 {
		t.Fatal("an access-key session survived the restart")
	}
	if s := decodeBody[Session](t, opRequest(h2, "GET", "/api/v1/session", "", kept, "").Body.Bytes()); !s.KeptSignedIn || s.Username != "admin" || s.Role != "admin" {
		t.Fatalf("kept session after the restart: %+v", s)
	}
	after := inventoryFor(t, h2, normal)
	if len(after.Items) != len(before.Items)-1 {
		t.Fatalf("inventory had %d sessions, has %d after the restart", len(before.Items), len(after.Items))
	}
	for _, item := range after.Items {
		found := false
		for _, old := range before.Items {
			found = found || (old.ID == item.ID && old.CreatedAt.Equal(item.CreatedAt) && old.ExpiresAt.Equal(item.ExpiresAt) && old.KeptSignedIn == item.KeptSignedIn)
		}
		if !found {
			t.Fatalf("session %s changed in the restart", item.ID)
		}
	}

	// The idle time counts from the last activity before the restart.
	clock = lastActivity.Add(sessionIdle - time.Minute)
	if sessionStatus(h2, normal) != 200 {
		t.Fatal("the session ended before its idle limit")
	}
	clock = lastActivity.Add(sessionIdle + time.Second)
	if sessionStatus(h2, normal) != 401 || sessionStatus(h2, kept) != 200 {
		t.Fatal("the saved last activity was not kept")
	}
	// The CSRF token still guards and admits a change.
	if w := opRequest(h2, "POST", "/api/v1/session/logout", "{}", kept, normalCSRF); w.Code != 403 {
		t.Fatalf("another session's CSRF token: %d", w.Code)
	}
	if m2.Close() != nil {
		t.Fatal("second close")
	}
}

func TestSavedSessionsArePrivateSealedAndWrittenOnlyOnChange(t *testing.T) {
	m, h, key := fixture(t)
	clock := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return clock }
	secret, _ := setUpAdmin(t, m, h, key, clock)
	clock = clock.Add(30 * time.Second)
	cookie, csrf := signInAs(t, h, "admin", setupWords, codeAt(t, secret, clock))
	id := currentID(t, h, cookie)
	if err := m.saveSessions(); err != nil {
		t.Fatal(err)
	}
	path := savedSessionsPath(m)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0600 {
			t.Fatalf("saved sessions mode %o", st.Mode().Perm())
		}
	}
	_, rawID, _, _ := m.session(withCookie(cookie))
	for _, secret := range []string{"admin", id, csrf, rawID, cookie.Value} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("the saved sessions file holds a session value in the clear")
		}
	}

	// Nothing changed: no new write.
	first, _ := os.Stat(path)
	if err := m.saveSessions(); err != nil {
		t.Fatal(err)
	}
	if second, _ := os.Stat(path); !os.SameFile(first, second) {
		t.Fatal("an unchanged snapshot was written again")
	}
	clock = clock.Add(time.Minute)
	if w := opRequest(h, "GET", inventoryPath, "", cookie, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if err := m.saveSessions(); err != nil {
		t.Fatal(err)
	}
	if third, _ := os.Stat(path); os.SameFile(first, third) {
		t.Fatal("new activity was not saved")
	}
}

func TestDamagedSavedSessionsDoNotStopThePanel(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, path string){
		"garbage": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"wrong mode": func(t *testing.T, path string) {
			if runtime.GOOS == "windows" {
				t.Skip("modes are Unix")
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		},
		"sealed with other keys": func(t *testing.T, path string) {
			dir := filepath.Dir(path)
			if err := os.Remove(filepath.Join(dir, "session.keys")); err != nil {
				t.Fatal(err)
			}
		},
		"flipped byte": func(t *testing.T, path string) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			i := bytes.Index(raw, []byte(`"sealed": "`)) + len(`"sealed": "`) + 10
			if raw[i] == 'A' {
				raw[i] = 'B'
			} else {
				raw[i] = 'A'
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, h, key := fixture(t)
			clock := time.Unix(1_800_000_000, 0)
			m.now = func() time.Time { return clock }
			secret, _ := setUpAdmin(t, m, h, key, clock)
			clock = clock.Add(30 * time.Second)
			cookie, _ := signInAs(t, h, "admin", setupWords, codeAt(t, secret, clock))
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			damage(t, savedSessionsPath(m))

			m2, err := Open(filepath.Dir(m.AccessKeyPath()))
			if err != nil {
				t.Fatalf("a damaged sessions file stopped the panel: %v", err)
			}
			m2.now = m.now
			h2 := http.NewServeMux()
			m2.Register(h2)
			if sessionStatus(h2, cookie) != 401 || len(m2.active) != 0 {
				t.Fatal("sessions came back from a damaged file")
			}
			var lines []string
			m2.StartSaving(func(line string) { lines = append(lines, line) })
			if err := m2.Close(); err != nil {
				t.Fatalf("the next save did not replace the damaged file: %v", err)
			}
			if len(lines) != 1 || !strings.Contains(lines[0], savedSessionsFile) || !strings.Contains(lines[0], "sign in again") {
				t.Fatalf("log lines: %q", lines)
			}
			m3, err := Open(filepath.Dir(m.AccessKeyPath()))
			if err != nil || m3.loadProblem != "" {
				t.Fatalf("the replaced file is still damaged: %v", err)
			}
		})
	}
}

func TestExpiredSavedSessionsAreDropped(t *testing.T) {
	m, h, key := fixture(t)
	// Signed in 13 hours ago, so only the kept session can still be live.
	clock := time.Now().Add(-13 * time.Hour)
	m.now = func() time.Time { return clock }
	secret, _ := setUpAdmin(t, m, h, key, clock)
	clock = clock.Add(30 * time.Second)
	signInAs(t, h, "admin", setupWords, codeAt(t, secret, clock))
	clock = clock.Add(30 * time.Second)
	if w := opRequest(h, "POST", "/api/v1/session/login", keepSignedInBody("admin", setupWords, codeAt(t, secret, clock)), nil, ""); w.Code != 200 {
		t.Fatalf("kept sign-in: %d", w.Code)
	}
	if err := m.saveSessions(); err != nil {
		t.Fatal(err)
	}
	m2, err := Open(filepath.Dir(m.AccessKeyPath()))
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.active) != 1 || len(m2.seen) != 1 {
		t.Fatalf("%d sessions loaded, want the kept one only", len(m2.active))
	}
	for _, a := range m2.active {
		if !a.kept {
			t.Fatal("an expired session was loaded")
		}
	}
}

// A session for a login that is gone is not loaded: an admin's username that
// admins.json no longer has, or a customer that customers.json no longer has.
func TestSavedSessionsOfRemovedLoginsAreDropped(t *testing.T) {
	m, h, clock, adminCookie, csrf := customerFixture(t)
	secret, _ := setUpAdmin(t, m, h, mustKey(t, m), clock.now)
	clock.now = clock.now.Add(30 * time.Second)
	signInAs(t, h, "admin", setupWords, codeAt(t, secret, clock.now))
	created := createLogin(t, h, adminCookie, csrf, "alice", siteA)
	setUpCustomer(t, h, linkToken(t, created.SetupLink), clock.now)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{adminsFile, customersFile} {
		if err := os.Remove(filepath.Join(m.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	m2, err := Open(filepath.Dir(m.AccessKeyPath()))
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.active) != 0 {
		t.Fatalf("%d sessions of removed logins were loaded", len(m2.active))
	}
}

func mustKey(t *testing.T, m *Manager) string {
	t.Helper()
	b, err := os.ReadFile(m.AccessKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func withCookie(c *http.Cookie) *http.Request {
	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/session", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.AddCookie(c)
	return r
}

// Every way a session ends, or an admin's view changes, is in the next save,
// so a restart cannot bring an ended session back.
func TestEndedSessionsStayEndedAfterARestart(t *testing.T) {
	type admins struct {
		m            *Manager
		h            http.Handler
		clock        *customerClock
		keyCookie    *http.Cookie
		keyCSRF      string
		secret       string
		one, two     *http.Cookie
		oneCSRF      string
		twoCSRF      string
		customer     *http.Cookie
		customerCode string
	}
	setUp := func(t *testing.T) admins {
		m, h, clock, keyCookie, keyCSRF := customerFixture(t)
		secret, _ := setUpAdmin(t, m, h, mustKey(t, m), clock.now)
		clock.now = clock.now.Add(30 * time.Second)
		one, oneCSRF := signInAs(t, h, "admin", setupWords, codeAt(t, secret, clock.now))
		clock.now = clock.now.Add(30 * time.Second)
		two, twoCSRF := signInAs(t, h, "admin", setupWords, codeAt(t, secret, clock.now))
		created := createLogin(t, h, one, oneCSRF, "alice", siteA)
		customerSecret, customer, _ := setUpCustomer(t, h, linkToken(t, created.SetupLink), clock.now)
		// The first save has every session in it.
		if err := m.saveSessions(); err != nil {
			t.Fatal(err)
		}
		return admins{m, h, clock, keyCookie, keyCSRF, secret, one, two, oneCSRF, twoCSRF, customer, customerSecret}
	}

	t.Run("sign-out", func(t *testing.T) {
		f := setUp(t)
		if w := opRequest(f.h, "POST", "/api/v1/session/logout", "{}", f.one, f.oneCSRF); w.Code != 200 {
			t.Fatal(w.Code)
		}
		_, h2 := restart(t, f.m)
		if sessionStatus(h2, f.one) != 401 || sessionStatus(h2, f.two) != 200 {
			t.Fatal("a signed-out session came back")
		}
	})
	t.Run("revoke", func(t *testing.T) {
		f := setUp(t)
		if w := opRequest(f.h, "POST", revokePath(currentID(t, f.h, f.two)), "{}", f.one, f.oneCSRF); w.Code != 200 {
			t.Fatal(w.Code)
		}
		_, h2 := restart(t, f.m)
		if sessionStatus(h2, f.two) != 401 || sessionStatus(h2, f.one) != 200 {
			t.Fatal("a revoked session came back")
		}
	})
	t.Run("revoke others", func(t *testing.T) {
		f := setUp(t)
		if w := opRequest(f.h, "POST", "/api/v1/session/revoke-others", "{}", f.one, f.oneCSRF); w.Code != 200 {
			t.Fatal(w.Code)
		}
		_, h2 := restart(t, f.m)
		if sessionStatus(h2, f.two) != 401 || sessionStatus(h2, f.one) != 200 || sessionStatus(h2, f.customer) != 200 {
			t.Fatal("sign out everywhere else did not last")
		}
	})
	t.Run("password change", func(t *testing.T) {
		f := setUp(t)
		f.clock.now = f.clock.now.Add(30 * time.Second)
		if w := opRequest(f.h, "POST", passwordPath, changeBody(setupWords, codeAt(t, f.secret, f.clock.now), "a brand new long password"), f.one, f.oneCSRF); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		_, h2 := restart(t, f.m)
		if sessionStatus(h2, f.two) != 401 || sessionStatus(h2, f.one) != 200 {
			t.Fatal("a session the password change ended came back")
		}
	})
	t.Run("customer turned off", func(t *testing.T) {
		f := setUp(t)
		for _, disabled := range []string{`{"disabled":true}`, `{"disabled":false}`} {
			if w := opRequest(f.h, "POST", "/api/v1/session/customers/alice/state", disabled, f.one, f.oneCSRF); w.Code != 200 {
				t.Fatal(w.Code)
			}
		}
		_, h2 := restart(t, f.m)
		if sessionStatus(h2, f.customer) != 401 {
			t.Fatal("turning the login off did not end its session for good")
		}
	})
	t.Run("new setup link", func(t *testing.T) {
		f := setUp(t)
		w := opRequest(f.h, "POST", "/api/v1/session/customers/alice/setup-link", "{}", f.one, f.oneCSRF)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		f.clock.now = f.clock.now.Add(30 * time.Second)
		setUpCustomer(t, f.h, linkToken(t, decodeBody[CustomerSetupLink](t, w.Body.Bytes()).SetupLink), f.clock.now)
		_, h2 := restart(t, f.m)
		if sessionStatus(h2, f.customer) != 401 {
			t.Fatal("a session the new setup link ended came back once the login was set up again")
		}
	})
	t.Run("view as", func(t *testing.T) {
		f := setUp(t)
		if w := opRequest(f.h, "POST", "/api/v1/session/view-as", `{"username":"alice"}`, f.one, f.oneCSRF); w.Code != 200 {
			t.Fatal(w.Code)
		}
		m2, h2 := restart(t, f.m)
		if s := decodeBody[Session](t, opRequest(h2, "GET", "/api/v1/session", "", f.one, "").Body.Bytes()); s.ViewAs != "alice" {
			t.Fatalf("viewing as a customer was lost in the restart: %+v", s)
		}
		if w := opRequest(h2, "POST", "/api/v1/session/view-as/end", "{}", f.one, f.oneCSRF); w.Code != 200 {
			t.Fatal(w.Code)
		}
		_, h3 := restart(t, m2)
		if s := decodeBody[Session](t, opRequest(h3, "GET", "/api/v1/session", "", f.one, "").Body.Bytes()); s.ViewAs != "" {
			t.Fatalf("going back to the admin view was lost in the restart: %+v", s)
		}
	})
}

// The background saver does not wait its 30 seconds when a session ends.
func TestEndingASessionIsSavedSoon(t *testing.T) {
	m, h, key := fixture(t)
	clock := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return clock }
	secret, _ := setUpAdmin(t, m, h, key, clock)
	clock = clock.Add(30 * time.Second)
	one, oneCSRF := signInAs(t, h, "admin", setupWords, codeAt(t, secret, clock))
	if err := m.saveSessions(); err != nil {
		t.Fatal(err)
	}
	m.StartSaving(func(line string) { t.Errorf("saver logged %q", line) })
	defer m.Close()
	if w := opRequest(h, "POST", "/api/v1/session/logout", "{}", one, oneCSRF); w.Code != 200 {
		t.Fatal(w.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m2, err := Open(filepath.Dir(m.AccessKeyPath()))
		if err != nil {
			t.Fatal(err)
		}
		m2.now = m.now
		h2 := http.NewServeMux()
		m2.Register(h2)
		if sessionStatus(h2, one) == 401 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the sign-out was not saved within 5 seconds")
}
