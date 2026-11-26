package operator

import (
	"net/http"
)

// View as customer: an admin opens the panel as one customer, to see what
// it sees and help it. The admin's own session carries the customer's name
// (Jev chose this over a second session or a request header, 0.67): while
// it does, the session has exactly that customer's access, so the panel's
// customer table and website checks apply to it, and the broker records
// its changes as "admin:<name> as customer:<customer>". Going back clears
// the name; the session keeps its cookie, CSRF token and expiry.

func (m *Manager) beginViewAs(w http.ResponseWriter, r *http.Request) {
	s, id, a, ok := m.adminSession(w, r, true)
	if !ok {
		return
	}
	var input struct {
		Username string `json:"username"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	if _, found := m.customers.Load().find(input.Username); !validUsername(input.Username) || !found {
		WriteError(w, 404, "customer_not_found", "That customer is not on the list. It may have been removed. Reload the page.")
		return
	}
	m.mu.Lock()
	if !m.authorizingSessionLocked(id, a) {
		m.mu.Unlock()
		WriteError(w, 401, "unauthorized", "Your session ended. Sign in again.")
		return
	}
	a.viewAs = input.Username
	m.active[id] = a
	m.mu.Unlock()
	m.saveSoon()
	writeJSON(w, m.publicSession(a, s.Values["csrf"].(string)))
}

// endViewAs takes the session back to the admin's own view. It works even
// when the customer was removed meanwhile.
func (m *Manager) endViewAs(w http.ResponseWriter, r *http.Request) {
	s, id, a, ok := m.checkSession(w, r, true)
	if !ok {
		return
	}
	if a.customer {
		WriteError(w, 403, "admin_only", "Only an admin can do this. Your login manages your own websites.")
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, true) {
		return
	}
	m.mu.Lock()
	if !m.authorizingSessionLocked(id, a) {
		m.mu.Unlock()
		WriteError(w, 401, "unauthorized", "Your session ended. Sign in again.")
		return
	}
	a.viewAs = ""
	m.active[id] = a
	m.mu.Unlock()
	m.saveSoon()
	writeJSON(w, m.publicSession(a, s.Values["csrf"].(string)))
}
