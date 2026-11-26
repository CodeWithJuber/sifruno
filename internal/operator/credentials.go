package operator

import (
	"net/http"
	"time"
)

// A signed-in admin or customer changes its own password, or moves its codes
// to a new authenticator app. Both start like a sign-in: the current password
// and a current code from the app in use. That holds a stolen session cookie
// to what the sign-in form allows: every attempt takes one try from the
// username's sign-in bucket first (the same keyed limiter as sign-in, Jev
// 0.86), the Argon2id work is bounded, a wrong password and a wrong code get
// one answer, and the code's step is saved with the change, so a code works
// once.
//
//   - POST /api/v1/session/password {current_password, totp_code,
//     new_password}: saves the new Argon2id hash and ends the person's other
//     sessions.
//   - POST /api/v1/session/authenticator/begin {current_password, totp_code}:
//     issues a new key to this session for 10 minutes. The old app keeps
//     working until the change is finished.
//   - POST /api/v1/session/authenticator/finish {totp_code}: a code from the
//     new app proves it is set up; the new key then replaces the old one.
//     Other sessions stay (Jev, 0.62).
//
// They need a session with Origin and CSRF, signed in with a username: not
// an API token (sessionOnly), not the access key, which has no password, and
// not an admin viewing as a customer, whose login is not the customer's.

const wrongCurrentCredentials = "The current password or code is wrong. Check them and try again."

type passwordChanged struct {
	OtherSessionsEnded int `json:"other_sessions_ended"`
}

type authenticatorChanged struct {
	Changed bool `json:"changed"`
}

// ownLogin admits a change to the signed-in person's own login.
func (m *Manager) ownLogin(w http.ResponseWriter, r *http.Request) (string, activeSession, bool) {
	_, id, a, ok := m.checkSession(w, r, true)
	if !ok {
		return "", activeSession{}, false
	}
	switch {
	case a.viewAs != "":
		WriteError(w, 403, "viewing_as_customer", "You are viewing the panel as a customer, whose password and authenticator app are its own. Go back to your admin view to change yours.")
		return "", activeSession{}, false
	case a.username == "":
		WriteError(w, 403, "admin_sign_in_required", "You signed in with the server's access key, which has no password or authenticator app. Sign in with your admin username to change them.")
		return "", activeSession{}, false
	}
	if _, ok := m.sessionPrincipal(w, id, a); !ok {
		return "", activeSession{}, false
	}
	return id, a, true
}

// ownLoginLocked finds the signed-in person's login and returns a copy of
// the file it is kept in, ready to change: password and totp point into the
// copy, and save writes it and makes it current. found is false when the
// login is gone, or a customer's is turned off or waiting for a new setup.
// Called with adminMu held.
func (m *Manager) ownLoginLocked(a activeSession) (password *passwordHash, totp *adminTOTP, save func() error, found bool) {
	if a.customer {
		current := m.customers.Load()
		i, ok := current.find(a.username)
		if !ok || !current.Customers[i].ready() {
			return nil, nil, nil, false
		}
		next := current.clone()
		c := &next.Customers[i]
		return c.Password, c.TOTP, func() error {
			if err := saveCustomers(m.dir, next, m.admins); err != nil {
				return err
			}
			m.customers.Store(&next)
			return nil
		}, true
	}
	i, ok := m.admins.find(a.username)
	if !ok {
		return nil, nil, nil, false
	}
	next := m.admins
	next.Admins = append([]adminRecord(nil), m.admins.Admins...)
	record := &next.Admins[i]
	return &record.Password, &record.TOTP, func() error {
		if err := saveAdmins(m.dir, next); err != nil {
			return err
		}
		m.admins = next
		return nil
	}, true
}

// checkOwnPassword checks the signed-in person's current password as a
// sign-in does, and answers the request when it fails. It returns the hash
// it checked, so the change can make sure it is still the current one.
func (m *Manager) checkOwnPassword(w http.ResponseWriter, r *http.Request, a activeSession, password string) (passwordHash, bool) {
	m.adminMu.Lock()
	allowed := m.loginBucket(a.username, r).Allow()
	current, _, _, found := m.ownLoginLocked(a)
	var hash passwordHash
	if found {
		hash = *current
	}
	m.adminMu.Unlock()
	if !allowed {
		w.Header().Set("Retry-After", "60")
		WriteError(w, 429, "rate_limited", "Too many tries for this login. Wait a minute and try again.")
		return passwordHash{}, false
	}
	if !found {
		writeLoginChanged(w)
		return passwordHash{}, false
	}
	if !m.acquireHash(r) {
		WriteError(w, 503, "operator_unavailable", "The check was interrupted. Try again.")
		return passwordHash{}, false
	}
	ok := hash.matches(password)
	m.releaseHash()
	if !ok {
		WriteError(w, 422, "invalid_credentials", wrongCurrentCredentials)
		return passwordHash{}, false
	}
	return hash, true
}

func writeLoginChanged(w http.ResponseWriter) {
	WriteError(w, 409, "login_changed", "Your login changed while this was being checked, so nothing was saved. Reload the page and try again.")
}

// confirmCodeLocked finishes the check against the login as it is now: the
// password must still be the one checked, and the code must be right and
// newer than the last one used. It records the code's step in the copy, so
// the save that makes the change also uses up the code, and makes sure the
// session is still live. Called with adminMu held.
func (m *Manager) confirmCodeLocked(w http.ResponseWriter, id string, a activeSession, checked passwordHash, code string) (password *passwordHash, totp *adminTOTP, save func() error, ok bool) {
	password, totp, save, found := m.ownLoginLocked(a)
	if !found || *password != checked {
		writeLoginChanged(w)
		return nil, nil, nil, false
	}
	step, valid := verifyTOTP(totp.Secret, code, m.now(), totp.LastStep)
	if !valid {
		WriteError(w, 422, "invalid_credentials", wrongCurrentCredentials)
		return nil, nil, nil, false
	}
	// Lock order: adminMu, then mu.
	m.mu.Lock()
	live := m.authorizingSessionLocked(id, a)
	m.mu.Unlock()
	if !live {
		WriteError(w, 401, "unauthorized", "Your session ended before anything was saved. Sign in again.")
		return nil, nil, nil, false
	}
	totp.LastStep = step
	return password, totp, save, true
}

func (m *Manager) changePassword(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.ownLogin(w, r)
	if !ok {
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		TOTPCode        string `json:"totp_code"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	if problem := passwordProblem(a.username, input.NewPassword); problem != "" {
		WriteError(w, 422, "invalid_password", problem)
		return
	}
	if input.NewPassword == input.CurrentPassword {
		WriteError(w, 422, "invalid_password", "The new password is the same as the current one. Choose a different one.")
		return
	}
	checked, ok := m.checkOwnPassword(w, r, a, input.CurrentPassword)
	if !ok {
		return
	}
	if !m.acquireHash(r) {
		WriteError(w, 503, "operator_unavailable", "The change was interrupted. Try again.")
		return
	}
	hash, err := hashPassword(input.NewPassword)
	m.releaseHash()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "The password could not be changed right now. Try again in a minute.")
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	password, _, save, ok := m.confirmCodeLocked(w, id, a, checked, input.TOTPCode)
	if !ok {
		return
	}
	*password = hash
	if err := save(); err != nil {
		WriteError(w, 503, "operator_unavailable", "The new password could not be saved on the server, so the current one still works. Try again; if it keeps failing, the panel's disk needs a check.")
		return
	}
	// Everyone else signed in as this person is signed out: a new password is
	// often chosen because the old one leaked.
	m.mu.Lock()
	var ended []string
	for other, s := range m.active {
		if other != id && s.username == a.username && s.customer == a.customer {
			delete(m.active, other)
			ended = append(ended, other)
		}
	}
	m.mu.Unlock()
	m.saveSoon()
	for _, other := range ended {
		delete(m.authenticatorPending, other)
	}
	writeJSON(w, passwordChanged{OtherSessionsEnded: len(ended)})
}

func (m *Manager) beginAuthenticatorChange(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.ownLogin(w, r)
	if !ok {
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		TOTPCode        string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	checked, ok := m.checkOwnPassword(w, r, a, input.CurrentPassword)
	if !ok {
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "A new key could not be made right now. Try again in a minute.")
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	_, _, save, ok := m.confirmCodeLocked(w, id, a, checked, input.TOTPCode)
	if !ok {
		return
	}
	// Only the code's step changes here, so it cannot be used again.
	if err := save(); err != nil {
		WriteError(w, 503, "operator_unavailable", "The check could not be recorded on the server, so nothing changed. Try again; if it keeps failing, the panel's disk needs a check.")
		return
	}
	now := m.now()
	for key, p := range m.authenticatorPending {
		if !now.Before(p.expires) {
			delete(m.authenticatorPending, key)
		}
	}
	expires := now.UTC().Add(setupLifetime).Truncate(time.Second)
	m.authenticatorPending[id] = pendingSetup{username: a.username, secret: secret, expires: expires}
	writeJSON(w, setupSecret{Secret: secret, URI: totpURI(a.username, secret), ExpiresAt: expires})
}

func (m *Manager) finishAuthenticatorChange(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.ownLogin(w, r)
	if !ok {
		return
	}
	var input struct {
		TOTPCode string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	pending, found := m.authenticatorPending[id]
	if !found || !m.now().Before(pending.expires) || pending.username != a.username {
		WriteError(w, 409, "authenticator_change_expired", "This step took more than 10 minutes, or it was started again in another tab. Start again with your password and a code from the app you use now.")
		return
	}
	step, ok := verifyTOTP(pending.secret, input.TOTPCode, m.now(), -1)
	if !ok {
		WriteError(w, 422, "invalid_code", "That code did not match the new key. Check that the new entry in your app is the one for this panel and that your phone's clock is right, then enter its newest code.")
		return
	}
	_, totp, save, found := m.ownLoginLocked(a)
	if !found {
		writeLoginChanged(w)
		return
	}
	m.mu.Lock()
	live := m.authorizingSessionLocked(id, a)
	m.mu.Unlock()
	if !live {
		WriteError(w, 401, "unauthorized", "Your session ended before anything was saved. Sign in again.")
		return
	}
	*totp = adminTOTP{Secret: pending.secret, LastStep: step}
	if err := save(); err != nil {
		WriteError(w, 503, "operator_unavailable", "The new app could not be saved on the server, so your codes still come from the app you used before. Try again; if it keeps failing, the panel's disk needs a check.")
		return
	}
	delete(m.authenticatorPending, id)
	writeJSON(w, authenticatorChanged{Changed: true})
}
