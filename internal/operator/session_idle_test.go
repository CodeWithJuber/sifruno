package operator

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// A session ends after 30 minutes without a request and after 12 hours in any
// case. "Keep me signed in on this device" makes those 24 hours and 7 days and
// keeps the cookie when the browser closes. The panel's once-a-minute check of
// GET /api/v1/session is not activity, or an open tab would never go idle.

func TestSessionEndsWhenIdleAndActivityKeepsItOpen(t *testing.T) {
	m, h, key := fixture(t)
	base := time.Now().UTC()
	clock := base
	m.now = func() time.Time { return clock }
	c, _ := signIn(t, h, key, nil)

	clock = base.Add(20 * time.Minute)
	if w := opRequest(h, "GET", inventoryPath, "", c, ""); w.Code != 200 {
		t.Fatalf("a request 20 minutes in: %d", w.Code)
	}
	clock = base.Add(45 * time.Minute)
	if sessionStatus(h, c) != 200 {
		t.Fatal("a request 25 minutes ago must keep the session open")
	}
	clock = base.Add(20*time.Minute + sessionIdle + time.Second)
	if sessionStatus(h, c) != 401 {
		t.Fatal("30 minutes without a request must end the session")
	}
}

func TestSessionCheckIsNotActivity(t *testing.T) {
	m, h, key := fixture(t)
	base := time.Now().UTC()
	clock := base
	m.now = func() time.Time { return clock }
	c, _ := signIn(t, h, key, nil)
	for _, at := range []time.Duration{10 * time.Minute, 20 * time.Minute, 29 * time.Minute} {
		clock = base.Add(at)
		if sessionStatus(h, c) != 200 {
			t.Fatalf("session check at %s", at)
		}
	}
	clock = base.Add(sessionIdle + time.Second)
	if sessionStatus(h, c) != 401 {
		t.Fatal("the panel's session check kept an idle session open")
	}
}

func TestSessionEndsAtItsHardLimitDespiteActivity(t *testing.T) {
	m, h, key := fixture(t)
	base := time.Now().UTC()
	clock := base
	m.now = func() time.Time { return clock }
	c, s := signIn(t, h, key, nil)
	if !s.ExpiresAt.Equal(base.Truncate(time.Second).Add(sessionMax)) {
		t.Fatalf("expires_at %s is not the 12-hour limit", s.ExpiresAt)
	}
	for at := 20 * time.Minute; at < sessionMax; at += 20 * time.Minute {
		clock = base.Add(at)
		if w := opRequest(h, "GET", inventoryPath, "", c, ""); w.Code != 200 {
			t.Fatalf("activity at %s: %d", at, w.Code)
		}
	}
	clock = base.Add(sessionMax + time.Second)
	if sessionStatus(h, c) != 401 {
		t.Fatal("activity must not carry a session past 12 hours")
	}
}

func keepSignedInBody(username, password, code string) string {
	b, _ := json.Marshal(map[string]any{"username": username, "password": password, "totp_code": code, "remember": true})
	return string(b)
}

func TestKeepMeSignedInLastsLongerAndKeepsTheCookie(t *testing.T) {
	m, h, key := fixture(t)
	base := time.Now().UTC()
	clock := base
	m.now = func() time.Time { return clock }
	secret, _ := setUpAdmin(t, m, h, key, base)

	clock = base.Add(time.Minute)
	w := opRequest(h, "POST", "/api/v1/session/login", adminLoginBody("admin", "a long enough password", codeAt(t, secret, clock)), nil, "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("normal sign-in: %d %s", w.Code, w.Body.String())
	}
	normal := w.Result().Cookies()[0]
	if normal.MaxAge != 0 || !normal.Expires.IsZero() {
		t.Fatal("a normal sign-in must set a cookie that ends with the browser")
	}

	clock = base.Add(2 * time.Minute)
	w = opRequest(h, "POST", "/api/v1/session/login", keepSignedInBody("admin", "a long enough password", codeAt(t, secret, clock)), nil, "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("kept sign-in: %d %s", w.Code, w.Body.String())
	}
	kept := w.Result().Cookies()[0]
	if kept.MaxAge != int(keptMax.Seconds()) {
		t.Fatalf("kept cookie Max-Age %d", kept.MaxAge)
	}
	s := decodeBody[Session](t, w.Body.Bytes())
	if !s.KeptSignedIn || !s.ExpiresAt.Equal(clock.Truncate(time.Second).Add(keptMax)) {
		t.Fatalf("kept session reports %+v", s)
	}

	start := clock
	clock = start.Add(23 * time.Hour)
	if sessionStatus(h, kept) != 200 || sessionStatus(h, normal) != 401 {
		t.Fatal("after 23 idle hours only the kept session may stay")
	}
	clock = start.Add(keptIdle + time.Second)
	if sessionStatus(h, kept) != 401 {
		t.Fatal("24 hours without a request must end a kept session")
	}

	clock = base.Add(10 * time.Minute)
	w = opRequest(h, "POST", "/api/v1/session/login", keepSignedInBody("admin", "a long enough password", codeAt(t, secret, clock)), nil, "")
	if w.Code != 200 {
		t.Fatalf("second kept sign-in: %d", w.Code)
	}
	again := w.Result().Cookies()[0]
	start = clock
	for at := 20 * time.Hour; at < keptMax; at += 20 * time.Hour {
		clock = start.Add(at)
		if w := opRequest(h, "GET", inventoryPath, "", again, ""); w.Code != 200 {
			t.Fatalf("kept activity at %s: %d", at, w.Code)
		}
	}
	clock = start.Add(keptMax + time.Second)
	if sessionStatus(h, again) != 401 {
		t.Fatal("activity must not carry a kept session past 7 days")
	}
}

func TestKeepMeSignedInNeedsAPasswordSignIn(t *testing.T) {
	_, h, key := fixture(t)
	b, _ := json.Marshal(map[string]any{"access_key": key, "remember": true})
	w := opRequest(h, "POST", "/api/v1/session/login", string(b), nil, "")
	if w.Code != http.StatusBadRequest || problemCode(t, w.Body.Bytes()) != "invalid_request" {
		t.Fatalf("access key with remember: %d %s", w.Code, w.Body.String())
	}
}
