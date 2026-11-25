package operator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// Admin sign-in and first-run setup. The local access key stays what it was:
// a loopback-only credential for whoever can read the panel's private state
// (that person can already forge sessions from session.keys). Password plus
// code is the login for people, and the one that will face the network.

const setupLifetime = 10 * time.Minute

type pendingSetup struct {
	username string
	secret   string
	expires  time.Time
}

// Five tries at once, then one more each minute. Every name, existing or not,
// lands in one of loginBuckets buckets chosen by a keyed hash, so an existing
// and a made-up username are throttled the same way and a 429 reveals nothing
// about which names exist. Memory stays fixed whatever names are tried.
//
// Over the network the bucket is chosen by username and caller IP together,
// from a separate, larger set: one outside address cannot lock the admin out
// of other addresses or out of the server itself. The separate remote global
// limiter still caps all network attempts together.
const (
	loginBuckets       = 256
	remoteLoginBuckets = 4096
)

func newAccountLimiter() *rate.Limiter { return rate.NewLimiter(rate.Every(time.Minute), 5) }

// loginBucket is called with adminMu held.
func (m *Manager) loginBucket(username string, r *http.Request) *rate.Limiter {
	mac := hmac.New(sha256.New, m.bucketKey[:])
	mac.Write([]byte(username))
	if !IsRemote(r) {
		return m.buckets[mac.Sum(nil)[0]]
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	mac.Write([]byte{0})
	mac.Write([]byte(peer))
	return m.remoteBuckets[binary.BigEndian.Uint16(mac.Sum(nil))%remoteLoginBuckets]
}

// acquireHash bounds concurrent Argon2id work (19 MiB each) so a burst of
// sign-ins cannot exhaust memory.
func (m *Manager) acquireHash(r *http.Request) bool {
	select {
	case m.hashSlots <- struct{}{}:
		return true
	case <-r.Context().Done():
		return false
	}
}
func (m *Manager) releaseHash() { <-m.hashSlots }

// passwordLogin checks a password and a one-time code for an admin or a
// customer; customer reports which signed in. Admins and customers never
// share a username. Every failure gets the same answer, so the response does
// not reveal which part was wrong, whether the login exists, or whether a
// customer's login is turned off or not set up yet. A used code is recorded
// before the session starts and cannot be replayed.
func (m *Manager) passwordLogin(w http.ResponseWriter, r *http.Request, username, password, code string) (customer, ok bool) {
	m.adminMu.Lock()
	allowed := m.loginBucket(username, r).Allow()
	hash, found := m.dummy, false
	if i, admin := m.admins.find(username); admin {
		hash, found = m.admins.Admins[i].Password, true
	} else if c, ok := m.loginCustomerLocked(username); ok {
		hash, found, customer = *c.Password, true, true
	}
	m.adminMu.Unlock()
	if !allowed {
		w.Header().Set("Retry-After", "60")
		WriteError(w, 429, "rate_limited", "Too many sign-in attempts for this username. Wait a minute and try again.")
		return false, false
	}
	if !m.acquireHash(r) {
		WriteError(w, 503, "operator_unavailable", "Sign-in was interrupted. Try again.")
		return false, false
	}
	passwordOK := hash.matches(password) && found
	m.releaseHash()
	if !passwordOK {
		WriteError(w, 401, "invalid_credentials", "The username, password or code is wrong. Check them and try again.")
		return false, false
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	// Re-read under the lock: another sign-in may have used a code
	// meanwhile, an admin may have changed the customer's login, and the
	// person may have changed the password (credentials.go).
	if customer {
		return true, m.recordCustomerCodeLocked(w, username, hash, code)
	}
	i, found := m.admins.find(username)
	if !found || m.admins.Admins[i].Password != hash {
		WriteError(w, 401, "invalid_credentials", "The username, password or code is wrong. Check them and try again.")
		return false, false
	}
	step, ok := verifyTOTP(m.admins.Admins[i].TOTP.Secret, code, m.now(), m.admins.Admins[i].TOTP.LastStep)
	if !ok {
		WriteError(w, 401, "invalid_credentials", "The username, password or code is wrong. Check them and try again.")
		return false, false
	}
	next := m.admins
	next.Admins = append([]adminRecord(nil), m.admins.Admins...)
	next.Admins[i].TOTP.LastStep = step
	if err := saveAdmins(m.dir, next); err != nil {
		WriteError(w, 503, "operator_unavailable", "Sign-in could not be recorded on the server. Try again; if it keeps failing, check the panel's disk.")
		return false, false
	}
	m.admins = next
	return false, true
}

// loginCustomerLocked is the customer record a sign-in may check: one that
// is set up and turned on. Called with adminMu held.
func (m *Manager) loginCustomerLocked(username string) (customerRecord, bool) {
	customers := m.customers.Load()
	i, found := customers.find(username)
	if !found || !customers.Customers[i].ready() {
		return customerRecord{}, false
	}
	return customers.Customers[i], true
}

// recordCustomerCodeLocked finishes a customer's sign-in once the password
// matched: the login must still be ready with the same password, and the
// code must be new. The code's step is saved before the session starts.
// Called with adminMu held.
func (m *Manager) recordCustomerCodeLocked(w http.ResponseWriter, username string, checked passwordHash, code string) bool {
	c, ok := m.loginCustomerLocked(username)
	if !ok || *c.Password != checked {
		WriteError(w, 401, "invalid_credentials", "The username, password or code is wrong. Check them and try again.")
		return false
	}
	step, ok := verifyTOTP(c.TOTP.Secret, code, m.now(), c.TOTP.LastStep)
	if !ok {
		WriteError(w, 401, "invalid_credentials", "The username, password or code is wrong. Check them and try again.")
		return false
	}
	next := m.customers.Load().clone()
	i, _ := next.find(username)
	next.Customers[i].TOTP.LastStep = step
	if err := saveCustomers(m.dir, next, m.admins); err != nil {
		WriteError(w, 503, "operator_unavailable", "Sign-in could not be recorded on the server. Try again; if it keeps failing, ask whoever runs this server to check the panel's disk.")
		return false
	}
	m.customers.Store(&next)
	return true
}

type setupStatus struct {
	AdminRequired bool `json:"admin_required"`
}

// getSetup tells the panel whether to show first-run setup or sign-in. It
// reveals only whether an admin exists.
func (m *Manager) getSetup(w http.ResponseWriter, r *http.Request) {
	if !admitted(r) {
		WriteError(w, 403, "local_access_required", "Local operator access required")
		return
	}
	m.adminMu.Lock()
	required := len(m.admins.Admins) == 0
	m.adminMu.Unlock()
	writeJSON(w, setupStatus{AdminRequired: required})
}

// setupSession admits setup steps only from a session opened with the access
// key, and only while no admin exists yet.
func (m *Manager) setupSession(w http.ResponseWriter, r *http.Request) (string, activeSession, bool) {
	if !localRequest(r) {
		WriteError(w, 403, "local_access_required", "First-run setup works only on the server itself.")
		return "", activeSession{}, false
	}
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return "", activeSession{}, false
	}
	m.adminMu.Lock()
	done := len(m.admins.Admins) > 0
	m.adminMu.Unlock()
	if done || a.username != "" {
		WriteError(w, 409, "setup_complete", "An admin account already exists. Sign in with it instead.")
		return "", activeSession{}, false
	}
	return id, a, true
}

type setupSecret struct {
	Secret    string    `json:"secret"`
	URI       string    `json:"otpauth_uri"`
	ExpiresAt time.Time `json:"expires_at"`
}

// beginSetup issues the authenticator secret for the chosen username. The
// secret is shown once, to this session only, and expires after 10 minutes.
func (m *Manager) beginSetup(w http.ResponseWriter, r *http.Request) {
	id, _, ok := m.setupSession(w, r)
	if !ok {
		return
	}
	var input struct {
		Username string `json:"username"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	if !validUsername(input.Username) {
		WriteError(w, 422, "invalid_username", "Choose a username of 3 to 32 lowercase letters, digits, dots, dashes or underscores, starting with a letter.")
		return
	}
	if _, taken := m.customers.Load().find(input.Username); taken {
		WriteError(w, 409, "username_taken", "A customer already signs in with this username. Choose another one for the admin.")
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Setup is unavailable right now. Try again.")
		return
	}
	expires := m.now().UTC().Add(setupLifetime).Truncate(time.Second)
	m.adminMu.Lock()
	now := m.now()
	for key, p := range m.pending {
		if !now.Before(p.expires) {
			delete(m.pending, key)
		}
	}
	m.pending[id] = pendingSetup{username: input.Username, secret: secret, expires: expires}
	m.adminMu.Unlock()
	writeJSON(w, setupSecret{Secret: secret, URI: totpURI(input.Username, secret), ExpiresAt: expires})
}

// finishSetup creates the first admin once the person proves their
// authenticator works, then turns the current session into that admin's.
func (m *Manager) finishSetup(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.setupSession(w, r)
	if !ok {
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	m.adminMu.Lock()
	pending, found := m.pending[id]
	m.adminMu.Unlock()
	if !found || !m.now().Before(pending.expires) || pending.username != input.Username {
		WriteError(w, 409, "setup_expired", "This setup step expired or changed. Start again from the username step.")
		return
	}
	if problem := passwordProblem(input.Username, input.Password); problem != "" {
		WriteError(w, 422, "invalid_password", problem)
		return
	}
	step, ok := verifyTOTP(pending.secret, input.TOTPCode, m.now(), -1)
	if !ok {
		WriteError(w, 422, "invalid_code", "That code did not match. Check that your phone's clock is right and enter the newest code.")
		return
	}
	if !m.acquireHash(r) {
		WriteError(w, 503, "operator_unavailable", "Setup was interrupted. Try again.")
		return
	}
	hash, err := hashPassword(input.Password)
	m.releaseHash()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Setup is unavailable right now. Try again.")
		return
	}
	m.adminMu.Lock()
	if len(m.admins.Admins) > 0 {
		m.adminMu.Unlock()
		WriteError(w, 409, "setup_complete", "An admin account already exists. Sign in with it instead.")
		return
	}
	if _, taken := m.customers.Load().find(input.Username); taken {
		m.adminMu.Unlock()
		WriteError(w, 409, "username_taken", "A customer already signs in with this username. Start again and choose another one for the admin.")
		return
	}
	// The session may have been revoked while the password was hashed; decide
	// with it still active (lock order adminMu, then mu).
	m.mu.Lock()
	stillActive := m.authorizingSessionLocked(id, a)
	m.mu.Unlock()
	if !stillActive {
		m.adminMu.Unlock()
		WriteError(w, 401, "unauthorized", "This session ended before the admin was created. Start setup again.")
		return
	}
	next := adminFile{Version: 1, Admins: []adminRecord{{Username: input.Username, Password: hash,
		TOTP: adminTOTP{Secret: pending.secret, LastStep: step}, CreatedAt: m.now().UTC().Truncate(time.Second)}}}
	if err := saveAdmins(m.dir, next); err != nil {
		m.adminMu.Unlock()
		WriteError(w, 503, "operator_unavailable", "The admin account could not be saved on the server. Check the panel's disk, then try again.")
		return
	}
	m.admins = next
	delete(m.pending, id)
	m.adminMu.Unlock()

	m.mu.Lock()
	current, ok := m.active[id]
	if ok && current == a {
		current.username = input.Username
		m.active[id] = current
	}
	m.mu.Unlock()
	if !ok || current.username != input.Username {
		WriteError(w, 401, "unauthorized", "The admin account was created, but this session ended. Sign in with it.")
		return
	}
	s, _, _, valid := m.session(r)
	if !valid {
		WriteError(w, 401, "unauthorized", "The admin account was created, but this session ended. Sign in with it.")
		return
	}
	writeJSON(w, Session{Authenticated: true, CSRFToken: s.Values["csrf"].(string), ExpiresAt: current.expires, Username: input.Username})
}
