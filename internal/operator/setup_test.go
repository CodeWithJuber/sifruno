package operator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const setupPath = "/api/v1/session/setup"

func decodeBody[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	return v
}

func problemCode(t *testing.T, raw []byte) string {
	t.Helper()
	return decodeBody[struct {
		Error string `json:"error"`
	}](t, raw).Error
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, ok := decodeTOTPSecret(secret)
	if !ok {
		t.Fatal("secret does not decode")
	}
	return hotp(key, uint64(at.Unix()/totpPeriod))
}

func adminLoginBody(username, password, code string) string {
	b, _ := json.Marshal(map[string]string{"username": username, "password": password, "totp_code": code})
	return string(b)
}

// setUpAdmin runs first-run setup through the HTTP handlers and returns the
// admin's TOTP secret.
func setUpAdmin(t *testing.T, m *Manager, h http.Handler, key string, now time.Time) (string, *http.Cookie) {
	t.Helper()
	cookie, s := signIn(t, h, key, nil)
	w := opRequest(h, "POST", setupPath+"/totp", `{"username":"admin"}`, cookie, s.CSRFToken)
	if w.Code != 200 {
		t.Fatalf("begin setup status %d %s", w.Code, w.Body.String())
	}
	secret := decodeBody[setupSecret](t, w.Body.Bytes()).Secret
	w = opRequest(h, "POST", setupPath+"/admin", adminLoginBody("admin", "a long enough password", codeAt(t, secret, now)), cookie, s.CSRFToken)
	if w.Code != 200 {
		t.Fatalf("finish setup status %d %s", w.Code, w.Body.String())
	}
	if got := decodeBody[Session](t, w.Body.Bytes()); got.Username != "admin" || got.CSRFToken != s.CSRFToken {
		t.Fatal("setup must turn the current session into the admin's")
	}
	return secret, cookie
}

func TestFirstRunSetupCreatesAdminOnce(t *testing.T) {
	m, h, key := fixture(t)
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }

	w := opRequest(h, "GET", setupPath, "", nil, "")
	if w.Code != 200 || !decodeBody[setupStatus](t, w.Body.Bytes()).AdminRequired {
		t.Fatal("a fresh panel must ask for setup")
	}
	if w := opRequest(h, "POST", setupPath+"/totp", `{"username":"admin"}`, nil, ""); w.Code != 401 {
		t.Fatalf("setup without a session: %d", w.Code)
	}
	cookie, s := signIn(t, h, key, nil)
	if w := opRequest(h, "POST", setupPath+"/totp", `{"username":"admin"}`, cookie, ""); w.Code != 403 {
		t.Fatalf("setup without CSRF: %d", w.Code)
	}
	if w := opRequest(h, "POST", setupPath+"/totp", `{"username":"Bad Name"}`, cookie, s.CSRFToken); w.Code != 422 || problemCode(t, w.Body.Bytes()) != "invalid_username" {
		t.Fatalf("bad username: %d", w.Code)
	}
	w = opRequest(h, "POST", setupPath+"/totp", `{"username":"admin"}`, cookie, s.CSRFToken)
	if w.Code != 200 {
		t.Fatalf("begin setup: %d", w.Code)
	}
	secret := decodeBody[setupSecret](t, w.Body.Bytes()).Secret
	good := codeAt(t, secret, now)
	for _, tc := range []struct {
		body, code string
		status     int
	}{
		{adminLoginBody("admin", "short", good), "invalid_password", 422},
		{adminLoginBody("admin", "a long enough password", "000000"), "invalid_code", 422},
		{adminLoginBody("other", "a long enough password", good), "setup_expired", 409},
	} {
		w := opRequest(h, "POST", setupPath+"/admin", tc.body, cookie, s.CSRFToken)
		if w.Code != tc.status || problemCode(t, w.Body.Bytes()) != tc.code {
			t.Fatalf("want %d %s, got %d %s", tc.status, tc.code, w.Code, w.Body.String())
		}
	}
	if len(m.admins.Admins) != 0 {
		t.Fatal("a refused setup created an admin")
	}
	w = opRequest(h, "POST", setupPath+"/admin", adminLoginBody("admin", "a long enough password", good), cookie, s.CSRFToken)
	if w.Code != 200 {
		t.Fatalf("finish setup: %d %s", w.Code, w.Body.String())
	}
	w = opRequest(h, "GET", "/api/v1/session", "", cookie, "")
	if decodeBody[Session](t, w.Body.Bytes()).Username != "admin" {
		t.Fatal("session should now belong to the admin")
	}
	w = opRequest(h, "GET", setupPath, "", nil, "")
	if decodeBody[setupStatus](t, w.Body.Bytes()).AdminRequired {
		t.Fatal("setup still reported as required")
	}
	other, otherSession := signIn(t, h, key, nil)
	if w := opRequest(h, "POST", setupPath+"/totp", `{"username":"second"}`, other, otherSession.CSRFToken); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "setup_complete" {
		t.Fatalf("second setup: %d", w.Code)
	}
}

func TestSetupSecretExpires(t *testing.T) {
	m, h, key := fixture(t)
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	cookie, s := signIn(t, h, key, nil)
	w := opRequest(h, "POST", setupPath+"/totp", `{"username":"admin"}`, cookie, s.CSRFToken)
	secret := decodeBody[setupSecret](t, w.Body.Bytes()).Secret
	now = now.Add(setupLifetime + time.Second) // the session itself lasts 15 minutes
	w = opRequest(h, "POST", setupPath+"/admin", adminLoginBody("admin", "a long enough password", codeAt(t, secret, now)), cookie, s.CSRFToken)
	if w.Code != 409 || problemCode(t, w.Body.Bytes()) != "setup_expired" {
		t.Fatalf("expired setup accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestAdminLoginPasswordCodeReplayAndRestart(t *testing.T) {
	m, h, key := fixture(t)
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	secret, _ := setUpAdmin(t, m, h, key, now)

	// The code used to finish setup cannot sign in again.
	if w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody("admin", "a long enough password", codeAt(t, secret, now)), nil, ""); w.Code != 401 {
		t.Fatalf("setup code replayed: %d", w.Code)
	}
	now = now.Add(totpPeriod * time.Second)
	for _, body := range []string{
		adminLoginBody("admin", "wrong password here", codeAt(t, secret, now)),
		adminLoginBody("nobody", "a long enough password", codeAt(t, secret, now)),
		adminLoginBody("admin", "a long enough password", "123456"),
	} {
		w := opRequest(h, "POST", "/api/v1/session/login", body, nil, "")
		if w.Code != 401 || problemCode(t, w.Body.Bytes()) != "invalid_credentials" {
			t.Fatalf("bad credentials: %d %s", w.Code, w.Body.String())
		}
	}
	w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody("admin", "a long enough password", codeAt(t, secret, now)), nil, "")
	if w.Code != 200 || decodeBody[Session](t, w.Body.Bytes()).Username != "admin" || len(w.Result().Cookies()) != 1 {
		t.Fatalf("admin login: %d %s", w.Code, w.Body.String())
	}
	if w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody("admin", "a long enough password", codeAt(t, secret, now)), nil, ""); w.Code != 401 {
		t.Fatal("same code accepted twice")
	}
	mixed := `{"access_key":"` + key + `","username":"admin","password":"a long enough password","totp_code":"123456"}`
	if w := opRequest(h, "POST", "/api/v1/session/login", mixed, nil, ""); w.Code != 400 {
		t.Fatalf("mixed credentials: %d", w.Code)
	}
	if c, s := signIn(t, h, key, nil); c == nil || s.Username != "" {
		t.Fatal("the local access key must still open a key session")
	}

	// The last used step survives a restart, so a code cannot be replayed then.
	m2, err := Open(filepath.Dir(m.AccessKeyPath()))
	if err != nil {
		t.Fatal(err)
	}
	m2.now = func() time.Time { return now }
	h2 := http.NewServeMux()
	m2.Register(h2)
	if w := opRequest(h2, "POST", "/api/v1/session/login", adminLoginBody("admin", "a long enough password", codeAt(t, secret, now)), nil, ""); w.Code != 401 {
		t.Fatal("code replayed after restart")
	}
	now = now.Add(totpPeriod * time.Second)
	if w := opRequest(h2, "POST", "/api/v1/session/login", adminLoginBody("admin", "a long enough password", codeAt(t, secret, now)), nil, ""); w.Code != 200 {
		t.Fatalf("login after restart: %d", w.Code)
	}
}

func TestAdminLoginRateLimitPerAccount(t *testing.T) {
	m, h, key := fixture(t)
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	secret, _ := setUpAdmin(t, m, h, key, now)
	for i := 0; i < 5; i++ {
		if w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody("admin", "wrong password here", "123456"), nil, ""); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	now = now.Add(totpPeriod * time.Second)
	w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody("admin", "a long enough password", codeAt(t, secret, now)), nil, "")
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("sixth attempt within a minute: %d", w.Code)
	}
	// A name in another bucket is unaffected, and so is the key login.
	if w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody(nameInBucket(t, m, "admin", false), "wrong password here", "123456"), nil, ""); w.Code != 401 {
		t.Fatalf("a name in another bucket hit the admin's limit: %d", w.Code)
	}
	signIn(t, h, key, nil)
}

// nameInBucket finds a made-up username that shares (or does not share) the
// rate-limit bucket of name.
func nameInBucket(t *testing.T, m *Manager, name string, same bool) string {
	t.Helper()
	local := httptest.NewRequest("POST", "http://127.0.0.1:8080/", nil)
	target := m.loginBucket(name, local)
	for i := 0; i < 100000; i++ {
		candidate := "guess" + strconv.Itoa(i)
		if (m.loginBucket(candidate, local) == target) == same {
			return candidate
		}
	}
	t.Fatal("no candidate name found")
	return ""
}

// Once a bucket is spent, an existing and a made-up username in it get the
// same answer, so a 429 cannot be used to find out which names exist.
func TestExhaustedBucketDoesNotRevealUsernames(t *testing.T) {
	m, h, key := fixture(t)
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	setUpAdmin(t, m, h, key, now)
	twin := nameInBucket(t, m, "admin", true)
	for i := 0; i < 5; i++ {
		if w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody(twin, "wrong password here", "123456"), nil, ""); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	existing := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody("admin", "wrong password here", "123456"), nil, "")
	fake := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody(twin, "wrong password here", "123456"), nil, "")
	if existing.Code != 429 || fake.Code != 429 || problemCode(t, existing.Body.Bytes()) != problemCode(t, fake.Body.Bytes()) {
		t.Fatalf("existing and made-up names answered differently: %d and %d", existing.Code, fake.Code)
	}
}

func TestKeyOnlyLoginKeepsItsAnswers(t *testing.T) {
	_, h, _ := fixture(t)
	for _, body := range []string{`{"access_key":""}`, `{"access_key":"` + strings.Repeat("A", 43) + `"}`} {
		if w := opRequest(h, "POST", "/api/v1/session/login", body, nil, ""); w.Code != 401 {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
	if w := opRequest(h, "POST", "/api/v1/session/login", `{"username":"admin"}`, nil, ""); w.Code != 400 {
		t.Fatalf("partial admin credentials: %d", w.Code)
	}
}
