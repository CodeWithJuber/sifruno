package operator

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// The admin's sign-in words, as setUpAdmin sets them.
	setupWords    = "a long enough password"
	passwordPath  = "/api/v1/session/password"
	authBeginPath = "/api/v1/session/authenticator/begin"
	authDonePath  = "/api/v1/session/authenticator/finish"
)

func changeBody(current, code, next string) string {
	return jsonBody(map[string]string{"current_password": current, "totp_code": code, "new_password": next})
}

func confirmBody(current, code string) string {
	return jsonBody(map[string]string{"current_password": current, "totp_code": code})
}

// signInAs signs a username in with a password and a code, and returns the
// session's cookie and CSRF token.
func signInAs(t *testing.T, h http.Handler, username, password, code string) (*http.Cookie, string) {
	t.Helper()
	w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody(username, password, code), nil, "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("sign in %s: %d %s", username, w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0], decodeBody[Session](t, w.Body.Bytes()).CSRFToken
}

func sessionStatus(h http.Handler, cookie *http.Cookie) int {
	return opRequest(h, "GET", "/api/v1/session", "", cookie, "").Code
}

// An admin changes its password with the current one and a current code.
// Its other sessions end; this one, and the access key's, stay. The old
// password stops working, the code cannot be used again, and the change
// survives a restart.
func TestAdminChangesItsPassword(t *testing.T) {
	m, h, key := fixture(t)
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	// The setup session became the admin's: with other, two to end.
	secret, setupCookie := setUpAdmin(t, m, h, key, now)
	now = now.Add(30 * time.Second)
	cookie, csrf := signInAs(t, h, "admin", setupWords, codeAt(t, secret, now))
	now = now.Add(30 * time.Second)
	other, _ := signInAs(t, h, "admin", setupWords, codeAt(t, secret, now))
	keyCookie, keySession := signIn(t, h, key, nil)
	now = now.Add(30 * time.Second)
	code := codeAt(t, secret, now)
	const next = "a brand new long password"

	// Refused before any password is checked: no CSRF token, an API token,
	// the access key's session, and a new password that breaks the rules.
	if w := opRequest(h, "POST", passwordPath, changeBody(setupWords, code, next), cookie, ""); w.Code != 403 {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	if w := bearer(h, "POST", passwordPath, "sfr_"+strings.Repeat("A", 43)); w.Code != 403 || problemCode(t, w.Body.Bytes()) != "token_not_allowed" {
		t.Fatalf("API token: %d %s", w.Code, w.Body.String())
	}
	if w := opRequest(h, "POST", passwordPath, changeBody(setupWords, code, next), keyCookie, keySession.CSRFToken); w.Code != 403 || problemCode(t, w.Body.Bytes()) != "admin_sign_in_required" {
		t.Fatalf("access-key session: %d %s", w.Code, w.Body.String())
	}
	for _, short := range []string{"too short", "admin", setupWords} {
		if w := opRequest(h, "POST", passwordPath, changeBody(setupWords, code, short), cookie, csrf); w.Code != 422 || problemCode(t, w.Body.Bytes()) != "invalid_password" {
			t.Fatalf("new password %q: %d %s", short, w.Code, w.Body.String())
		}
	}
	// A wrong password and a wrong code get the same answer.
	wrongPassword := opRequest(h, "POST", passwordPath, changeBody("not the password at all", code, next), cookie, csrf)
	wrongCode := opRequest(h, "POST", passwordPath, changeBody(setupWords, "000000", next), cookie, csrf)
	if wrongPassword.Code != 422 || wrongCode.Code != 422 || wrongPassword.Body.String() != wrongCode.Body.String() || problemCode(t, wrongCode.Body.Bytes()) != "invalid_credentials" {
		t.Fatalf("wrong password %d %s, wrong code %d %s", wrongPassword.Code, wrongPassword.Body.String(), wrongCode.Code, wrongCode.Body.String())
	}

	w := opRequest(h, "POST", passwordPath, changeBody(setupWords, code, next), cookie, csrf)
	if w.Code != 200 || decodeBody[passwordChanged](t, w.Body.Bytes()).OtherSessionsEnded != 2 {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	if sessionStatus(h, other) != 401 || sessionStatus(h, setupCookie) != 401 || sessionStatus(h, cookie) != 200 || sessionStatus(h, keyCookie) != 200 {
		t.Fatal("only the admin's other sessions may end")
	}
	refillLoginBuckets(m)
	if w := customerSignIn(h, "admin", next, code); w.Code != 401 {
		t.Fatalf("the code used for the change signed in: %d", w.Code)
	}
	now = now.Add(30 * time.Second)
	if w := customerSignIn(h, "admin", setupWords, codeAt(t, secret, now)); w.Code != 401 {
		t.Fatalf("old password: %d", w.Code)
	}
	m2, err := Open(filepath.Dir(m.AccessKeyPath()))
	if err != nil {
		t.Fatal(err)
	}
	m2.now = func() time.Time { return now }
	h2 := http.NewServeMux()
	m2.Register(h2)
	signInAs(t, h2, "admin", next, codeAt(t, secret, now))
}

// A customer changes its own password the same way; its other sessions end,
// and an admin viewing as the customer cannot change it.
func TestCustomerChangesItsPassword(t *testing.T) {
	m, h, clock, adminCookie, adminCSRF := customerFixture(t)
	secret, cookie, session := setUpCustomer(t, h, linkToken(t, createLogin(t, h, adminCookie, adminCSRF, "alice", siteA).SetupLink), clock.now)
	clock.now = clock.now.Add(30 * time.Second)
	other, _ := signInAs(t, h, "alice", customerPassword, codeAt(t, secret, clock.now))
	if w := opRequest(h, "POST", "/api/v1/session/view-as", `{"username":"alice"}`, adminCookie, adminCSRF); w.Code != 200 {
		t.Fatalf("view as: %d", w.Code)
	}
	clock.now = clock.now.Add(30 * time.Second)
	code := codeAt(t, secret, clock.now)
	const next = "the customer's new password"
	if w := opRequest(h, "POST", passwordPath, changeBody(customerPassword, code, next), adminCookie, adminCSRF); w.Code != 403 || problemCode(t, w.Body.Bytes()) != "viewing_as_customer" {
		t.Fatalf("admin viewing as alice: %d %s", w.Code, w.Body.String())
	}
	w := opRequest(h, "POST", passwordPath, changeBody(customerPassword, code, next), cookie, session.CSRFToken)
	if w.Code != 200 || decodeBody[passwordChanged](t, w.Body.Bytes()).OtherSessionsEnded != 1 {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	// The admin's session, viewing as alice, is not alice's and stays.
	if sessionStatus(h, other) != 401 || sessionStatus(h, cookie) != 200 || sessionStatus(h, adminCookie) != 200 {
		t.Fatal("only the customer's other session may end")
	}
	refillLoginBuckets(m)
	clock.now = clock.now.Add(30 * time.Second)
	if w := customerSignIn(h, "alice", customerPassword, codeAt(t, secret, clock.now)); w.Code != 401 {
		t.Fatalf("old password: %d", w.Code)
	}
	signInAs(t, h, "alice", next, codeAt(t, secret, clock.now))
	// A turned-off login cannot change anything: its session has ended.
	if w := opRequest(h, "POST", "/api/v1/session/view-as/end", `{}`, adminCookie, adminCSRF); w.Code != 200 {
		t.Fatalf("end view as: %d", w.Code)
	}
	if w := opRequest(h, "POST", "/api/v1/session/customers/alice/state", `{"disabled":true}`, adminCookie, adminCSRF); w.Code != 200 {
		t.Fatalf("disable: %d", w.Code)
	}
	if w := opRequest(h, "POST", passwordPath, changeBody(next, codeAt(t, secret, clock.now.Add(30*time.Second)), "yet another long password"), cookie, session.CSRFToken); w.Code != 401 {
		t.Fatalf("turned-off login: %d", w.Code)
	}
}

// Every try uses the username's sign-in bucket, so a session cookie gets no
// more password guesses than the sign-in form, and the two share the limit.
func TestCredentialChangesUseTheSignInLimit(t *testing.T) {
	m, h, clock, adminCookie, adminCSRF := customerFixture(t)
	secret, cookie, session := setUpCustomer(t, h, linkToken(t, createLogin(t, h, adminCookie, adminCSRF, "alice", siteA).SetupLink), clock.now)
	refillLoginBuckets(m)
	clock.now = clock.now.Add(30 * time.Second)
	code := codeAt(t, secret, clock.now)
	for i := 0; i < 5; i++ {
		path, body := passwordPath, changeBody("not the password at all", code, "a brand new long password")
		if i%2 == 1 {
			path, body = authBeginPath, confirmBody("not the password at all", code)
		}
		if w := opRequest(h, "POST", path, body, cookie, session.CSRFToken); w.Code != 422 {
			t.Fatalf("try %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	w := opRequest(h, "POST", authBeginPath, confirmBody(customerPassword, code), cookie, session.CSRFToken)
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("sixth try: %d", w.Code)
	}
	if w := customerSignIn(h, "alice", customerPassword, code); w.Code != 429 {
		t.Fatalf("sign-in after the limit was used up: %d", w.Code)
	}
}

// Moving to a new authenticator app: the current password and code first,
// then a code from the new key. The old app works until then and not after;
// other sessions stay. The new key belongs to the session that asked for it
// and lasts 10 minutes.
func TestAuthenticatorChange(t *testing.T) {
	m, h, key := fixture(t)
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	secret, _ := setUpAdmin(t, m, h, key, now)
	now = now.Add(30 * time.Second)
	cookie, csrf := signInAs(t, h, "admin", setupWords, codeAt(t, secret, now))
	now = now.Add(30 * time.Second)
	other, otherCSRF := signInAs(t, h, "admin", setupWords, codeAt(t, secret, now))
	now = now.Add(30 * time.Second)
	code := codeAt(t, secret, now)

	if w := opRequest(h, "POST", authDonePath, `{"totp_code":"123456"}`, cookie, csrf); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "authenticator_change_expired" {
		t.Fatalf("finish before begin: %d %s", w.Code, w.Body.String())
	}
	if w := opRequest(h, "POST", authBeginPath, confirmBody(setupWords, "000000"), cookie, csrf); w.Code != 422 || problemCode(t, w.Body.Bytes()) != "invalid_credentials" {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body.String())
	}
	w := opRequest(h, "POST", authBeginPath, confirmBody(setupWords, code), cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	issued := decodeBody[setupSecret](t, w.Body.Bytes())
	if _, ok := decodeTOTPSecret(issued.Secret); !ok || issued.Secret == secret || issued.URI != totpURI("admin", issued.Secret) {
		t.Fatalf("new key: %+v", issued)
	}
	// The code that started it is used up.
	if w := opRequest(h, "POST", authBeginPath, confirmBody(setupWords, code), cookie, csrf); w.Code != 422 {
		t.Fatalf("begin code replayed: %d", w.Code)
	}
	// Only the session that asked has the new key.
	if w := opRequest(h, "POST", authDonePath, jsonBody(map[string]string{"totp_code": codeAt(t, issued.Secret, now)}), other, otherCSRF); w.Code != 409 {
		t.Fatalf("finish from another session: %d", w.Code)
	}
	if w := opRequest(h, "POST", authDonePath, jsonBody(map[string]string{"totp_code": codeAt(t, secret, now.Add(30*time.Second))}), cookie, csrf); w.Code != 422 || problemCode(t, w.Body.Bytes()) != "invalid_code" {
		t.Fatalf("old app's code for the new key: %d %s", w.Code, w.Body.String())
	}
	if w := opRequest(h, "POST", authDonePath, jsonBody(map[string]string{"totp_code": codeAt(t, issued.Secret, now)}), cookie, csrf); w.Code != 200 || !decodeBody[authenticatorChanged](t, w.Body.Bytes()).Changed {
		t.Fatalf("finish: %d %s", w.Code, w.Body.String())
	}
	if sessionStatus(h, other) != 200 || sessionStatus(h, cookie) != 200 {
		t.Fatal("other sessions stay after an authenticator change")
	}
	refillLoginBuckets(m)
	now = now.Add(30 * time.Second)
	if w := customerSignIn(h, "admin", setupWords, codeAt(t, secret, now)); w.Code != 401 {
		t.Fatalf("old app after the change: %d", w.Code)
	}
	signInAs(t, h, "admin", setupWords, codeAt(t, issued.Secret, now))

	// A new key not confirmed within 10 minutes is dropped.
	now = now.Add(30 * time.Second)
	if w := opRequest(h, "POST", authBeginPath, confirmBody(setupWords, codeAt(t, issued.Secret, now)), cookie, csrf); w.Code != 200 {
		t.Fatalf("second begin: %d %s", w.Code, w.Body.String())
	}
	late := decodeBody[setupSecret](t, w.Body.Bytes())
	now = now.Add(setupLifetime + time.Second)
	if w := opRequest(h, "POST", authDonePath, jsonBody(map[string]string{"totp_code": codeAt(t, late.Secret, now)}), cookie, csrf); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "authenticator_change_expired" {
		t.Fatalf("finish after 10 minutes: %d %s", w.Code, w.Body.String())
	}
}
