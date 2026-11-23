package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// The setup routes must pass the outer API write guard and reach the
// operator, which then applies its own session, Origin and CSRF checks.
func TestSessionSetupRoutesReachTheOperator(t *testing.T) {
	f := websiteFixture(t)
	w := websiteRequest(f.handler, "GET", "/api/v1/session/setup", nil, nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"admin_required":true`) {
		t.Fatalf("setup status: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/v1/session/setup/totp", "/api/v1/session/setup/admin"} {
		if w := websiteRequest(f.handler, "POST", path, map[string]string{"username": "admin"}, nil, ""); w.Code != 401 {
			t.Fatalf("%s without a session: %d", path, w.Code)
		}
	}
	cookie, csrf := websiteSignIn(t, f)
	w = websiteRequest(f.handler, "POST", "/api/v1/session/setup/totp", map[string]string{"username": "admin"}, cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("begin setup through the API: %d %s", w.Code, w.Body.String())
	}
	var secret struct {
		Secret string `json:"secret"`
		URI    string `json:"otpauth_uri"`
	}
	if json.Unmarshal(w.Body.Bytes(), &secret) != nil || len(secret.Secret) != 32 || !strings.HasPrefix(secret.URI, "otpauth://totp/Sifruno:admin?") {
		t.Fatal("setup secret response malformed")
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/setup/nope", map[string]string{}, cookie, csrf); w.Code != 405 {
		t.Fatalf("unknown session route not refused by the write guard: %d", w.Code)
	}
}
