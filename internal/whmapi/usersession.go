package whmapi

import (
	"net/http"
	"net/url"
	"strings"
)

// WithSessionStore attaches the one-time login session store used by
// create_user_session. BaseURL is the panel's external HTTPS base used in
// the login URL (e.g. https://panel.example.com); the observed per-service
// port is appended. Empty BaseURL fails the call closed.
func (s *Server) WithSessionStore(st *SessionStore, baseURL string) *Server {
	s.sessions = st
	s.baseURL = strings.TrimRight(baseURL, "/")
	return s
}

// handleUserSession implements create_user_session from the observed 138
// captures (batch 3 and batch 6):
//   - missing user:      The “user” parameter is required.
//   - missing service:   The “service” parameter is required.
//   - invalid service:   The “service” parameter is invalid. The only
//     supported services for this API call are “cpaneld”, “webmaild”, and
//     “whostmgrd”.
//   - unknown user:      You cannot create a session for the user “x”
//     because they do not exist.
//   - success:           data{url, session, cp_security_token, expires,
//     service[, locale]}; reason "Created session"; expires = +300s.
func (s *Server) handleUserSession(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	user := q.Get("user")
	if user == "" {
		writeError(w, "create_user_session", "The “user” parameter is required.")
		return
	}
	service := q.Get("service")
	if service == "" {
		writeError(w, "create_user_session", "The “service” parameter is required.")
		return
	}
	port, ok := validSessionServices[service]
	if !ok {
		writeError(w, "create_user_session", "The “service” parameter is invalid. The only supported services for this API call are “cpaneld”, “webmaild”, and “whostmgrd”.")
		return
	}
	// The account must exist and be visible to the backend.
	found := false
	for _, a := range s.backend.ListAccounts() {
		if a.User == user {
			found = true
			break
		}
	}
	if !found {
		writeError(w, "create_user_session", "You cannot create a session for the user “"+user+"” because they do not exist.")
		return
	}
	if s.sessions == nil || s.baseURL == "" {
		writeError(w, "create_user_session", "API failure: (XID "+xid()+") Session storage is not configured; no session was created.")
		return
	}
	locale := q.Get("locale")
	issued, err := s.sessions.Create(user, service, locale)
	if err != nil {
		writeError(w, "create_user_session", "API failure: (XID "+xid()+") Session creation failed; nothing was stored.")
		return
	}
	loginURL := s.baseURL + ":" + port + "/" + issued.Record.ID + "/login/?session=" + url.QueryEscape(issued.SessionToken)
	if locale != "" {
		loginURL += "&locale=" + url.QueryEscape(locale)
	}
	data := map[string]any{
		"url":               loginURL,
		"session":           issued.SessionToken,
		"cp_security_token": issued.SecToken,
		"expires":           issued.Record.ExpiresAt,
		"service":           service,
	}
	if locale != "" {
		data["locale"] = locale
	}
	writeSuccessReason(w, "create_user_session", "Created session", data, "")
}
