package operator

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// Sessions opened with a password and a code, or with a passkey (an admin's
// or a customer's), are saved in the private folder, so restarting the panel does not sign
// people out (Jev, 0.81). Sessions opened with the access key are not saved:
// a restart still ends them.
//
// sessions.json is sealed with AES-256-GCM under a key derived from
// session.keys, which already decides whether a cookie opens anything:
// moving session.keys aside ends every session, saved ones too. The file
// holds each session's cookie ID, the SHA-256 of its CSRF token (never the
// token), its management handle, times, username and kind.
//
// A background saver (StartSaving) takes a snapshot under mu every 30
// seconds, and soon after a session ends, and writes only when the snapshot
// changed; Close saves once more when the panel stops. A file that cannot
// be read does not stop the panel: it starts with no saved sessions, says
// so in one line, and the next save replaces it.

const (
	savedSessionsFile     = "sessions.json"
	maxSavedSessionsBytes = 256 << 10
	sessionSaveEvery      = 30 * time.Second
	savedSessionsLabel    = "sifruno operator saved sessions v1"
)

type sealedSessions struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	Sealed  string `json:"sealed"`
}

type savedSessions struct {
	Version  int            `json:"version"`
	Sessions []savedSession `json:"sessions"`
}

type savedSession struct {
	ID           string    `json:"id"`
	CSRFHash     string    `json:"csrf_sha256"`
	ManagementID string    `json:"management_id"`
	Created      time.Time `json:"created"`
	Expires      time.Time `json:"expires"`
	Seen         time.Time `json:"seen"`
	Username     string    `json:"username"`
	Customer     bool      `json:"customer,omitempty"`
	Kept         bool      `json:"kept,omitempty"`
	ViewAs       string    `json:"view_as,omitempty"`
}

// savedSessionsKey derives the sealing key from session.keys.
func savedSessionsKey(sessionKeys []byte) [32]byte {
	mac := hmac.New(sha256.New, sessionKeys)
	mac.Write([]byte(savedSessionsLabel))
	var key [32]byte
	copy(key[:], mac.Sum(nil))
	return key
}

func savedSessionsAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// valid checks one saved session as strictly as the panel made it.
func (s savedSession) valid() bool {
	csrf, err := base64.RawStdEncoding.Strict().DecodeString(s.CSRFHash)
	limit := sessionMax
	if s.Kept {
		limit = keptMax
	}
	return validToken(s.ID) && err == nil && len(csrf) == sha256.Size && validManagementID(s.ManagementID) &&
		!s.Created.IsZero() && s.Expires.Equal(s.Created.Add(limit)) && !s.Seen.Before(s.Created) && !s.Seen.After(s.Expires) &&
		validUsername(s.Username) && (s.ViewAs == "" || (validUsername(s.ViewAs) && !s.Customer))
}

// loadSavedSessions reads sessions.json into the session table: every entry
// must be valid, or none is loaded; then sessions that ended while the panel
// was stopped, and sessions of logins that are gone, are left out. It
// returns the plain snapshot it loaded, or a sentence for the log when the
// file could not be used. Called from Open, before the manager is shared.
func (m *Manager) loadSavedSessions(key [32]byte) (string, []byte) {
	damaged := "Saved sign-ins could not be read: " + savedSessionsFile + " in the panel's private folder is damaged, has the wrong mode (it must be 0600) or was sealed with other session keys, so everyone who was signed in has to sign in again. The panel replaces the file on its next save."
	var sealed sealedSessions
	found, err := readPrivateJSON(m.dir, savedSessionsFile, maxSavedSessionsBytes, &sealed)
	if err != nil {
		return damaged, nil
	}
	if !found {
		return "", nil
	}
	nonce, nonceErr := base64.RawStdEncoding.Strict().DecodeString(sealed.Nonce)
	ciphertext, dataErr := base64.RawStdEncoding.Strict().DecodeString(sealed.Sealed)
	aead, err := savedSessionsAEAD(key)
	if sealed.Version != 1 || nonceErr != nil || dataErr != nil || err != nil || len(nonce) != aead.NonceSize() {
		return damaged, nil
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(savedSessionsFile))
	if err != nil {
		return damaged, nil
	}
	var saved savedSessions
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if dec.Decode(&saved) != nil || dec.More() || saved.Version != 1 || len(saved.Sessions) > maxSessions {
		return damaged, nil
	}
	ids, handles, perCustomer, customers := map[string]bool{}, map[string]bool{}, map[string]int{}, 0
	for _, s := range saved.Sessions {
		if !s.valid() || ids[s.ID] || handles[s.ManagementID] {
			return damaged, nil
		}
		ids[s.ID], handles[s.ManagementID] = true, true
		if s.Customer {
			customers++
			perCustomer[s.Username]++
			if customers > maxCustomerSessions || perCustomer[s.Username] > maxSessionsPerCustomer {
				return damaged, nil
			}
		}
	}
	now := m.now()
	logins := m.customers.Load()
	for _, s := range saved.Sessions {
		a := activeSession{expires: s.Expires, managementID: s.ManagementID, created: s.Created, username: s.Username, kept: s.Kept, customer: s.Customer, viewAs: s.ViewAs}
		csrf, _ := base64.RawStdEncoding.DecodeString(s.CSRFHash) // checked by valid
		copy(a.csrf[:], csrf)
		_, admin := m.admins.find(s.Username)
		_, customer := logins.find(s.Username)
		if (s.Customer && !customer) || (!s.Customer && !admin) {
			continue
		}
		m.seen[s.ID] = s.Seen
		if !now.Before(m.deadlineLocked(s.ID, a)) {
			delete(m.seen, s.ID)
			continue
		}
		m.active[s.ID] = a
	}
	return "", m.sessionSnapshotLocked()
}

// sessionSnapshotLocked is the plain form of the sessions to save, sorted
// by ID so an unchanged table gives the same bytes. Called with mu held.
func (m *Manager) sessionSnapshotLocked() []byte {
	out := savedSessions{Version: 1, Sessions: []savedSession{}}
	for id, a := range m.active {
		if a.username == "" {
			continue
		}
		seen, ok := m.seen[id]
		if !ok {
			seen = a.created
		}
		out.Sessions = append(out.Sessions, savedSession{ID: id, CSRFHash: base64.RawStdEncoding.EncodeToString(a.csrf[:]), ManagementID: a.managementID,
			Created: a.created, Expires: a.expires, Seen: seen.UTC(), Username: a.username, Customer: a.customer, Kept: a.kept, ViewAs: a.viewAs})
	}
	slices.SortFunc(out.Sessions, func(a, b savedSession) int { return strings.Compare(a.ID, b.ID) })
	raw, _ := json.Marshal(out)
	return raw
}

// saveSessions writes sessions.json when the sessions changed since the last
// write. The snapshot is taken under mu; sealing and writing happen after
// it is released (lock order: saveMu, then mu).
func (m *Manager) saveSessions() error {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	m.mu.Lock()
	m.pruneLocked()
	plain := m.sessionSnapshotLocked()
	m.mu.Unlock()
	if m.lastSaved != nil && bytes.Equal(plain, m.lastSaved) {
		return nil
	}
	aead, err := savedSessionsAEAD(m.savedKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := sealedSessions{Version: 1, Nonce: base64.RawStdEncoding.EncodeToString(nonce),
		Sealed: base64.RawStdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, []byte(savedSessionsFile)))}
	if err := writePrivateJSON(m.dir, savedSessionsFile, maxSavedSessionsBytes, sealed); err != nil {
		return err
	}
	m.lastSaved = plain
	return nil
}

// saveSoon asks the background saver to save now rather than at its next
// tick. Ending a session calls it, so a crash soon after a sign-out or a
// revocation cannot bring the session back. It never blocks, so it may be
// called with any lock held.
func (m *Manager) saveSoon() {
	select {
	case m.saveWake <- struct{}{}:
	default:
	}
}

// StartSaving starts the background saver. logf gets one plain line when
// the saved sessions could not be read at start, when a save fails, and when
// saving works again. Call Close when the panel stops.
func (m *Manager) StartSaving(logf func(string)) {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	if m.saveDone != nil {
		return
	}
	if m.loadProblem != "" {
		logf(m.loadProblem)
	}
	m.saveDone = make(chan struct{})
	go m.saveLoop(logf, m.saveStop, m.saveDone)
}

func (m *Manager) saveLoop(logf func(string), stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	tick := time.NewTicker(sessionSaveEvery)
	defer tick.Stop()
	failing := false
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		case <-m.saveWake:
		}
		err := m.saveSessions()
		switch {
		case err != nil && !failing:
			logf("Sign-ins could not be saved to " + savedSessionsFile + " in the panel's private folder, so restarting the panel now would sign people out. The panel tries again every 30 seconds; check that its disk has space and the folder is writable.")
		case err == nil && failing:
			logf("Sign-ins are saved again.")
		}
		failing = err != nil
	}
}

// Close stops the background saver and saves the sessions once more. The
// panel calls it after its listeners have stopped, so no request changes a
// session after the last save. Sessions keep working in memory.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() { close(m.saveStop) })
	m.saveMu.Lock()
	done := m.saveDone
	m.saveMu.Unlock()
	if done != nil {
		<-done
	}
	if err := m.saveSessions(); err != nil {
		return errors.New("sign-ins could not be saved to " + savedSessionsFile + " in the panel's private folder, so the people signed in now have to sign in again after the restart; check that its disk has space and the folder is writable")
	}
	return nil
}
