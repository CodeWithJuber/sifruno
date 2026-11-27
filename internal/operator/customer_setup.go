package operator

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// A customer sets up its own login from the link an admin sent: the link's
// secret proves who it is, then it connects an authenticator app and
// chooses a password, as the first admin does (setup.go). The two routes,
// /api/v1/session/customer-setup/begin and /finish, need no session; they
// work on the server and over the HTTPS listener, with the exact Origin.
//
// Wrong links are limited like wrong API tokens: only a failure uses an
// attempt, only a failure is refused while a limit is used up, and a valid
// link always works. On the server a 20-attempt burst refills one every 3
// seconds; over the network a separate burst of 20, plus 5 per caller IP
// refilling one a minute. A link carries 256 random bits, so the limits
// only keep guessing traffic down.

const setupLinkWrong = "This setup link does not work. It may be cut short, already used, turned off, or more than a day old. Ask whoever sent it for a new link."

type customerSetupSecret struct {
	Username  string    `json:"username"`
	Secret    string    `json:"secret"`
	URI       string    `json:"otpauth_uri"`
	ExpiresAt time.Time `json:"expires_at"`
}

// setupLinkLimiters are the limiters a wrong link uses, as bearerLimiters.
func (m *Manager) setupLinkLimiters(r *http.Request) (global, peer *rate.Limiter) {
	if !IsRemote(r) {
		return m.setupLimiter, nil
	}
	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		addr = r.RemoteAddr
	}
	mac := hmac.New(sha256.New, m.bucketKey[:])
	mac.Write([]byte("setup-link\x00"))
	mac.Write([]byte(addr))
	return m.remoteSetupLimiter, m.remoteSetupBuckets[binary.BigEndian.Uint16(mac.Sum(nil))%remoteLoginBuckets]
}

// refuseSetupLink answers a wrong link and counts it.
func (m *Manager) refuseSetupLink(w http.ResponseWriter, r *http.Request) {
	global, peer := m.setupLinkLimiters(r)
	if (peer != nil && peer.Tokens() < 1) || global.Tokens() < 1 {
		retry := "3"
		if peer != nil && peer.Tokens() < 1 {
			retry = "60"
		}
		w.Header().Set("Retry-After", retry)
		WriteError(w, 429, "rate_limited", "Too many tries with a setup link that does not work. Wait a minute, check that the whole link was copied, and try again.")
		return
	}
	global.Allow()
	if peer != nil {
		peer.Allow()
	}
	WriteError(w, 404, "setup_link_invalid", setupLinkWrong)
}

// lookupSetupLink finds the customer a link's secret belongs to. The link
// must be the customer's current one, unexpired, and the login turned on.
// Every stored hash is compared, without stopping at a match. It reads the
// published snapshot and takes no lock.
func (m *Manager) lookupSetupLink(token string) (username, hash string, ok bool) {
	if !validToken(token) {
		return "", "", false
	}
	sum := sha256.Sum256([]byte(token))
	customers := m.customers.Load()
	index := -1
	for i, c := range customers.Customers {
		if c.Setup == nil {
			continue
		}
		stored, err := base64.RawStdEncoding.Strict().DecodeString(c.Setup.Hash)
		if err == nil && subtle.ConstantTimeCompare(sum[:], stored) == 1 {
			index = i
		}
	}
	if index < 0 {
		return "", "", false
	}
	c := customers.Customers[index]
	if c.Disabled || !m.now().Before(c.Setup.ExpiresAt) {
		return "", "", false
	}
	return c.Username, c.Setup.Hash, true
}

func setupLinkAdmitted(w http.ResponseWriter, r *http.Request) bool {
	if !admitted(r) {
		WriteError(w, 403, "local_access_required", "Local operator access required")
		return false
	}
	if !sameOrigin(r) {
		WriteError(w, 403, "origin_not_allowed", "Open the setup link in the browser at the panel's own address.")
		return false
	}
	return true
}

// beginCustomerSetup issues the authenticator secret for the link's
// customer. Opening the link again replaces it; it lasts 10 minutes.
func (m *Manager) beginCustomerSetup(w http.ResponseWriter, r *http.Request) {
	if !setupLinkAdmitted(w, r) {
		return
	}
	var input struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	username, hash, ok := m.lookupSetupLink(input.Token)
	if !ok {
		m.refuseSetupLink(w, r)
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Setup is unavailable right now. Try again in a minute.")
		return
	}
	expires := m.now().UTC().Add(setupLifetime).Truncate(time.Second)
	m.adminMu.Lock()
	now := m.now()
	for key, p := range m.customerPending {
		if !now.Before(p.expires) {
			delete(m.customerPending, key)
		}
	}
	m.customerPending[hash] = pendingSetup{username: username, secret: secret, expires: expires}
	m.adminMu.Unlock()
	writeJSON(w, customerSetupSecret{Username: username, Secret: secret, URI: totpURI(username, secret), ExpiresAt: expires})
}

// finishCustomerSetup saves the password and authenticator once a code from
// the app proves it is set up, retires the link, and signs the customer in.
func (m *Manager) finishCustomerSetup(w http.ResponseWriter, r *http.Request) {
	if !setupLinkAdmitted(w, r) {
		return
	}
	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	username, hash, ok := m.lookupSetupLink(input.Token)
	if !ok {
		m.refuseSetupLink(w, r)
		return
	}
	m.adminMu.Lock()
	pending, found := m.customerPending[hash]
	m.adminMu.Unlock()
	if !found || !m.now().Before(pending.expires) || pending.username != username {
		WriteError(w, 409, "setup_expired", "This step took more than 10 minutes, or the link was opened again elsewhere. Start again: the panel shows a new key for your app.")
		return
	}
	if problem := passwordProblem(username, input.Password); problem != "" {
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
	password, err := hashPassword(input.Password)
	m.releaseHash()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Setup is unavailable right now. Try again in a minute.")
		return
	}
	m.adminMu.Lock()
	// The admin may have replaced the link, turned the login off or removed
	// it while the password was hashed: decide on the login as it is now.
	next := m.customers.Load().clone()
	i, found := next.find(username)
	if !found || next.Customers[i].Setup == nil || next.Customers[i].Setup.Hash != hash || next.Customers[i].Disabled || !m.now().Before(next.Customers[i].Setup.ExpiresAt) {
		m.adminMu.Unlock()
		WriteError(w, 404, "setup_link_invalid", setupLinkWrong)
		return
	}
	c := &next.Customers[i]
	c.Password, c.TOTP, c.Setup = &password, &adminTOTP{Secret: pending.secret, LastStep: step}, nil
	if err := saveCustomers(m.dir, next, m.admins); err != nil {
		m.adminMu.Unlock()
		WriteError(w, 503, "operator_unavailable", "Your login could not be saved on the server, so nothing changed. Try again; if it keeps failing, tell whoever sent the link.")
		return
	}
	m.customers.Store(&next)
	delete(m.customerPending, hash)
	m.adminMu.Unlock()
	m.startSession(w, r, username, true, false)
}
