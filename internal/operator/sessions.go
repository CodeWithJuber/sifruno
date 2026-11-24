package operator

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"time"
)

// ManagedSession exposes a revocation handle, not an authentication credential.
// Its ID is independent of the private cookie session ID and CSRF token.
type ManagedSession struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Current   bool      `json:"current"`
}
type Inventory struct {
	Items           []ManagedSession `json:"items"`
	Capacity        int              `json:"capacity"`
	LifetimeSeconds int              `json:"lifetime_seconds"`
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
func (m *Manager) managementAuthorization(w http.ResponseWriter, r *http.Request, mutation bool) (string, activeSession, bool) {
	if _, ok := m.authorizeSession(w, r, mutation); !ok {
		return "", activeSession{}, false
	}
	_, id, a, ok := m.session(r)
	if !ok {
		WriteError(w, 401, "unauthorized", "Operator session required")
	}
	return id, a, ok
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
	inventory := Inventory{Items: make([]ManagedSession, 0, len(m.active)), Capacity: maxSessions, LifetimeSeconds: int(sessionLifetime.Seconds())}
	for rawID, entry := range m.active {
		inventory.Items = append(inventory.Items, ManagedSession{entry.managementID, entry.created, entry.expires, rawID == id})
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
		if entry.managementID == target {
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
	for other := range m.active {
		if other != id {
			delete(m.active, other)
			count++
		}
	}
	m.mu.Unlock()
	writeJSON(w, struct {
		RevokedCount int `json:"revoked_count"`
	}{count})
}
