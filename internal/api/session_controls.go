package api

import (
	"net/http"
	"slices"
	"strings"
)

// Manager owns authentication and strict body/ID validation. This allowlist
// admits only the named local session operations through the outer API guard.
func allowedSessionMutation(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch r.URL.Path {
	case "/api/v1/session/login", "/api/v1/session/logout", "/api/v1/session/revoke-others",
		"/api/v1/session/setup/totp", "/api/v1/session/setup/admin", "/api/v1/session/tokens",
		"/api/v1/session/customers", "/api/v1/session/customer-setup/begin", "/api/v1/session/customer-setup/finish",
		"/api/v1/session/view-as", "/api/v1/session/view-as/end",
		"/api/v1/session/password", "/api/v1/session/authenticator/begin", "/api/v1/session/authenticator/finish":
		return true
	}
	for _, prefix := range []string{"/api/v1/session/sessions/", "/api/v1/session/tokens/"} {
		if strings.HasPrefix(r.URL.Path, prefix) {
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
			return len(parts) == 2 && parts[0] != "" && parts[1] == "revoke"
		}
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/session/customers/"); ok {
		parts := strings.Split(rest, "/")
		return len(parts) == 2 && parts[0] != "" && slices.Contains([]string{"websites", "state", "setup-link", "delete"}, parts[1])
	}
	return false
}
