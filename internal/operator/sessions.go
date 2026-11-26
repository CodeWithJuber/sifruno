package operator

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/sessions"
)

// ManagedSession exposes a revocation handle, not an authentication credential.
// Its ID is independent of the private cookie session ID and CSRF token.
type ManagedSession struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Current   bool      `json:"current"`
	// KeptSignedIn marks a "Keep me signed in on this device" session.
	KeptSignedIn bool `json:"kept_signed_in"`
}
type Inventory struct {
	Items    []ManagedSession `json:"items"`
	Capacity int              `json:"capacity"`
	// IdleSeconds is how long a session lasts without a request; a kept
	// session lasts KeptIdleSeconds.
	IdleSeconds     int `json:"idle_seconds"`
	KeptIdleSeconds int `json:"kept_idle_seconds"`
}

func validManagementID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Caller holds mu. Refuse the bounded unlikely collision rather than selecting
// an existing management handle or overwriting a different session.
func (m *Manager) newManagementIDLocked() (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		var b [16]byte
		if _, e := rand.Read(b[:]); e != nil {
			return "", e
		}
		id := hex.EncodeToString(b[:])
		collision := false
		for _, a := range m.active {
			if a.managementID == id {
				collision = true
				break
			}
		}
		if !collision {
			return id, nil
		}
	}
	return "", errors.New("operator management handle unavailable")
}
func (m *Manager) authorizingSessionLocked(id string, expected activeSession) bool {
	m.pruneLocked()
	actual, ok := m.active[id]
	return ok && actual == expected
}

// managementAuthorization admits the panel's own management (sessions,
// tokens, setup, customer logins, viewing as a customer) to an admin's
// session only: never a customer's, and never an admin's while it views the
// panel as a customer.
func (m *Manager) managementAuthorization(w http.ResponseWriter, r *http.Request, mutation bool) (string, activeSession, bool) {
	_, id, a, ok := m.adminSession(w, r, mutation)
	return id, a, ok
}

// adminSession is managementAuthorization, also returning the cookie session.
func (m *Manager) adminSession(w http.ResponseWriter, r *http.Request, mutation bool) (*sessions.Session, string, activeSession, bool) {
	s, id, a, ok := m.checkSession(w, r, mutation)
	if !ok {
		return nil, "", activeSession{}, false
	}
	switch {
	case a.customer:
		WriteError(w, 403, "admin_only", "Only an admin can do this. Your login manages your own websites.")
		return nil, "", activeSession{}, false
	case a.viewAs != "":
		WriteError(w, 403, "admin_only", "You are viewing the panel as a customer. Go back to your admin view first, then try again.")
		return nil, "", activeSession{}, false
	}
	return s, id, a, true
}
func (m *Manager) getSessions(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, false)
	if !ok {
		return
	}
	m.mu.Lock()
	if !m.authorizingSessionLocked(id, a) {
		m.mu.Unlock()
		WriteError(w, 401, "unauthorized", "Operator session required")
		return
	}
	inventory := Inventory{Items: make([]ManagedSession, 0, len(m.active)), Capacity: maxSessions, IdleSeconds: int(sessionIdle.Seconds()), KeptIdleSeconds: int(keptIdle.Seconds())}
	// Customers' sessions are theirs: the admin's list and its "sign out
	// everywhere else" leave them alone.
	for rawID, entry := range m.active {
		if !entry.customer {
			inventory.Items = append(inventory.Items, ManagedSession{entry.managementID, entry.created, entry.expires, rawID == id, entry.kept})
		}
	}
	m.mu.Unlock()
	sort.Slice(inventory.Items, func(i, j int) bool {
		if inventory.Items[i].CreatedAt.Equal(inventory.Items[j].CreatedAt) {
			return inventory.Items[i].ID < inventory.Items[j].ID
		}
		return inventory.Items[i].CreatedAt.After(inventory.Items[j].CreatedAt)
	})
	writeJSON(w, inventory)
}
func (m *Manager) revokeSession(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	target := r.PathValue("id")
	if !validManagementID(target) {
		WriteError(w, 400, "invalid_request", "Valid session management ID required")
		return
	}
	m.mu.Lock()
	if !m.authorizingSessionLocked(id, a) {
		m.mu.Unlock()
		WriteError(w, 401, "unauthorized", "Operator session required")
		return
	}
	if target == a.managementID {
		m.mu.Unlock()
		WriteError(w, 409, "current_session", "Use logout for the current session")
		return
	}
	found := ""
	for rawID, entry := range m.active {
		if entry.managementID == target && !entry.customer {
			found = rawID
			break
		}
	}
	if found == "" {
		m.mu.Unlock()
		WriteError(w, 404, "session_not_found", "Managed session not found")
		return
	}
	delete(m.active, found)
	m.mu.Unlock()
	m.saveSoon()
	writeJSON(w, struct {
		RevokedCount int `json:"revoked_count"`
	}{1})
}
func (m *Manager) revokeOthers(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	m.mu.Lock()
	if !m.authorizingSessionLocked(id, a) {
		m.mu.Unlock()
		WriteError(w, 401, "unauthorized", "Operator session required")
		return
	}
	count := 0
	for other, entry := range m.active {
		if other != id && !entry.customer {
			delete(m.active, other)
			count++
		}
	}
	m.mu.Unlock()
	m.saveSoon()
	writeJSON(w, struct {
		RevokedCount int `json:"revoked_count"`
	}{count})
}
