package api

import (
	"net/http"
	"strings"
)

// Manager owns authentication and strict body/ID validation. This allowlist
// admits only the named local session operations through the outer API guard.
func allowedSessionMutation(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch r.URL.Path {
	case "/api/v1/session/login", "/api/v1/session/logout", "/api/v1/session/revoke-others":
		return true
	}
	const prefix = "/api/v1/session/sessions/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] == "revoke"
}
