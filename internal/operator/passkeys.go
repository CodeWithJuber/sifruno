package operator

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkeys sign an admin or a customer in on their own, with user
// verification (a fingerprint, face or device PIN) required every time. A
// password and an authenticator code stay the way in when a passkey is not
// at hand (Jev, 0.96). Code here; the WebAuthn checks are go-webauthn's.
//
//   - Where: a passkey belongs to one relying party ID, a domain name, so
//     passkeys work only when the panel is opened at one of its --panel-host
//     names over HTTPS with a certificate browsers trust (SetPasskeySites).
//     An IP address cannot be a relying party ID, and the server's own
//     loopback address is not where people sign in, so there the panel says
//     passkeys need the panel's name.
//   - Adding: on Account, a person signed in with its own session adds a
//     passkey with the current password and a current code, the rule a
//     password change follows. Credentials are discoverable (resident key
//     required), at most 10 per login, kept with the login in admins.json or
//     customers.json with a name the person gives.
//   - Signing in: "Sign in with a passkey", or the username field's
//     autofill, asks the browser for any passkey of this panel; the passkey's
//     user handle names the login. Wrong answers count against the sign-in
//     limits like a wrong password.
//   - Ceremonies (the random challenges) live in memory only, for 5 minutes,
//     and work once: a sign-in's is bound to the request that began it by a
//     random token, an addition's to the session that began it.
//   - A customer's new setup link removes its passkeys; turning its login off
//     blocks them; a password change keeps them.

const (
	maxPasskeys      = 10
	passkeyLifetime  = 5 * time.Minute
	maxPasskeyLogins = 256
	// passkeyBodyBytes bounds a request that carries a browser's passkey
	// answer: with no attestation it is well under 4 KiB.
	passkeyBodyBytes = 16 << 10
	maxPasskeyName   = 64
	passkeyRPName    = "Sifruno panel"
)

// passkeyRecord is one passkey as admins.json or customers.json keeps it.
type passkeyRecord struct {
	// ID is the credential ID and PublicKey its COSE public key, both
	// base64url without padding.
	ID             string    `json:"id"`
	PublicKey      string    `json:"public_key"`
	SignCount      uint32    `json:"sign_count"`
	BackupEligible bool      `json:"backup_eligible"`
	BackupState    bool      `json:"backup_state"`
	CloneWarning   bool      `json:"clone_warning,omitempty"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"created_at"`
	LastUsedAt     time.Time `json:"last_used_at,omitzero"`
}

// loginPasskeys is the part of an admin's or customer's record that holds its
// passkeys. PasskeyUser is the WebAuthn user handle, 32 random bytes in
// base64url, made with the first passkey; it names the login without
// revealing it.
type loginPasskeys struct {
	PasskeyUser string          `json:"passkey_user,omitempty"`
	Passkeys    []passkeyRecord `json:"passkeys,omitempty"`
}

func validPasskeyName(s string) bool {
	if !utf8.ValidString(s) || s != strings.TrimSpace(s) || s == "" || utf8.RuneCountInString(s) > maxPasskeyName {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func (p passkeyRecord) valid() bool {
	id, idErr := base64.RawURLEncoding.Strict().DecodeString(p.ID)
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(p.PublicKey)
	return idErr == nil && keyErr == nil && len(id) > 0 && len(id) <= 1023 && len(key) > 0 && len(key) <= 2048 &&
		validPasskeyName(p.Name) && !p.CreatedAt.IsZero() && (p.BackupEligible || !p.BackupState)
}

// validate checks one login's passkeys, and adds their IDs and the user
// handle to seen, so a file (and admins and customers together) never has
// one twice.
func (l loginPasskeys) validate(seen map[string]bool) error {
	if len(l.Passkeys) > maxPasskeys || (len(l.Passkeys) > 0 && !validToken(l.PasskeyUser)) || (l.PasskeyUser != "" && !validToken(l.PasskeyUser)) {
		return errors.New("invalid passkeys")
	}
	if l.PasskeyUser != "" {
		if seen["user:"+l.PasskeyUser] {
			return errors.New("invalid passkeys")
		}
		seen["user:"+l.PasskeyUser] = true
	}
	for _, p := range l.Passkeys {
		if !p.valid() || seen["id:"+p.ID] {
			return errors.New("invalid passkeys")
		}
		seen["id:"+p.ID] = true
	}
	return nil
}

func (l loginPasskeys) clone() loginPasskeys {
	return loginPasskeys{PasskeyUser: l.PasskeyUser, Passkeys: slices.Clone(l.Passkeys)}
}

// passkeyPublicID is the handle Account uses for a passkey: not its
// credential ID, which can be 1023 bytes long.
func passkeyPublicID(credentialID string) string {
	sum := sha256.Sum256([]byte(credentialID))
	return hex.EncodeToString(sum[:16])
}

// passkeyUser is a login as go-webauthn sees it.
type passkeyUser struct {
	handle   []byte
	username string
	records  []passkeyRecord
}

func (u passkeyUser) WebAuthnID() []byte          { return u.handle }
func (u passkeyUser) WebAuthnName() string        { return u.username }
func (u passkeyUser) WebAuthnDisplayName() string { return u.username }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.records))
	for _, p := range u.records {
		id, _ := base64.RawURLEncoding.DecodeString(p.ID)
		key, _ := base64.RawURLEncoding.DecodeString(p.PublicKey)
		out = append(out, webauthn.Credential{ID: id, PublicKey: key,
			Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: p.BackupEligible, BackupState: p.BackupState},
			Authenticator: webauthn.Authenticator{SignCount: p.SignCount, CloneWarning: p.CloneWarning}})
	}
	return out
}

// passkeySites is where passkeys work: the https origins of the panel's
// names, by the Host a browser sends for them, and whether the certificate
// for them is one browsers trust now.
type passkeySites struct {
	origins map[string]string
	first   string
	trusted func() bool
}

// SetPasskeySites sets the https origins passkeys work at, such as
// https://panel.example.com:8443: the panel's --panel-host names that are
// domain names, on the HTTPS listener's port. trusted reports whether the
// listener's certificate for them is one browsers trust now (the operator's
// own, or Let's Encrypt's once it is in place). Without a call, or with no
// origins, passkeys are off. An origin whose host is an IP address is left
// out: it cannot be a relying party ID.
func (m *Manager) SetPasskeySites(origins []string, trusted func() bool) {
	sites := passkeySites{origins: map[string]string{}, trusted: trusted}
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil || u.Path != "" || u.User != nil || protocol.ValidateRPID(u.Hostname()) != nil {
			continue
		}
		origin := "https://" + strings.ToLower(u.Host)
		sites.origins[strings.ToLower(u.Host)] = origin
		if sites.first == "" {
			sites.first = origin
		}
	}
	m.passkeySites.Store(&sites)
}

// passkeyPlace is the relying party for one request.
type passkeyPlace struct {
	rpID, origin string
}

// PasskeyStatus says whether passkeys work where the request came from, and
// if not, why and what to do. Address is the panel's https address at its
// name, when it has one.
type PasskeyStatus struct {
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
	Address   string `json:"address,omitempty"`
}

// passkeyPlaceFor answers where passkeys work for this request, or why they
// do not.
func (m *Manager) passkeyPlaceFor(r *http.Request) (passkeyPlace, PasskeyStatus) {
	sites := m.passkeySites.Load()
	if sites == nil || len(sites.origins) == 0 {
		return passkeyPlace{}, PasskeyStatus{Detail: "Passkeys need the panel's name and a trusted certificate, and this panel has neither yet. Sign in with your password and code. To turn passkeys on, whoever runs the server installs the panel again with --panel-host and --acme-email."}
	}
	host := strings.ToLower(r.Host)
	origin, named := sites.origins[host]
	switch {
	case !IsRemote(r) || !named:
		return passkeyPlace{}, PasskeyStatus{Detail: "Passkeys need the panel's name. You opened it at an IP address or another name, so sign in with your password and code here, or open the panel at " + sites.first + " to use a passkey.", Address: sites.first}
	case sites.trusted == nil || !sites.trusted():
		return passkeyPlace{}, PasskeyStatus{Detail: "Passkeys need a certificate browsers trust for the panel's name, and the panel does not have one yet. Sign in with your password and code. The panel gets one from Let's Encrypt when it is installed with --acme-email; once it is in place, reload the page.", Address: sites.first}
	}
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	return passkeyPlace{rpID: hostname, origin: origin}, PasskeyStatus{Available: true, Address: sites.first}
}

func (p passkeyPlace) relyingParty() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{RPID: p.rpID, RPDisplayName: passkeyRPName, RPOrigins: []string{p.origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(), UserVerification: protocol.VerificationRequired},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyLifetime, TimeoutUVD: passkeyLifetime},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyLifetime, TimeoutUVD: passkeyLifetime},
		}})
}

func writePasskeysUnavailable(w http.ResponseWriter, status PasskeyStatus) {
	WriteError(w, 409, "passkeys_unavailable", status.Detail)
}

// pendingPasskeyLogin is a sign-in ceremony in progress, by the SHA-256 of
// the token its begin answer carried. Under adminMu.
type pendingPasskeyLogin struct {
	session webauthn.SessionData
	origin  string
	expires time.Time
}

// pendingPasskeyAdd is a passkey being added, by session ID. Under adminMu.
type pendingPasskeyAdd struct {
	session  webauthn.SessionData
	origin   string
	username string
	customer bool
	handle   string
	expires  time.Time
}

// passkeyLogin is a login found by its passkey user handle: a copy, taken
// under adminMu.
type passkeyLogin struct {
	username string
	customer bool
	passkeys loginPasskeys
}

func (l passkeyLogin) user() passkeyUser {
	handle, _ := base64.RawURLEncoding.DecodeString(l.passkeys.PasskeyUser)
	return passkeyUser{handle: handle, username: l.username, records: l.passkeys.Passkeys}
}

// passkeyLoginLocked finds the login a user handle names: an admin, or a
// customer whose login is set up and turned on. Called with adminMu held.
func (m *Manager) passkeyLoginLocked(handle []byte) (passkeyLogin, bool) {
	if len(handle) != 32 {
		return passkeyLogin{}, false
	}
	encoded := base64.RawURLEncoding.EncodeToString(handle)
	for _, a := range m.admins.Admins {
		if a.PasskeyUser == encoded {
			return passkeyLogin{username: a.Username, passkeys: a.loginPasskeys.clone()}, true
		}
	}
	customers := m.customers.Load()
	for _, c := range customers.Customers {
		if c.PasskeyUser == encoded && c.ready() {
			return passkeyLogin{username: c.Username, customer: true, passkeys: c.loginPasskeys.clone()}, true
		}
	}
	return passkeyLogin{}, false
}

// passkeyTakenLocked reports whether any login has this credential ID or
// user handle already. Called with adminMu held.
func (m *Manager) passkeyTakenLocked(credentialID, handle, username string, customer bool) bool {
	check := func(name string, isCustomer bool, l loginPasskeys) bool {
		if handle != "" && l.PasskeyUser == handle && (name != username || isCustomer != customer) {
			return true
		}
		return slices.ContainsFunc(l.Passkeys, func(p passkeyRecord) bool { return p.ID == credentialID })
	}
	for _, a := range m.admins.Admins {
		if check(a.Username, false, a.loginPasskeys) {
			return true
		}
	}
	for _, c := range m.customers.Load().Customers {
		if check(c.Username, true, c.loginPasskeys) {
			return true
		}
	}
	return false
}

// ownPasskeysLocked returns a copy of the passkeys of the login a session
// belongs to, ready to change, and save, which writes the copy and makes it
// current. found is false when the login is gone, or a customer's is turned
// off or waiting for a new setup. Called with adminMu held.
func (m *Manager) ownPasskeysLocked(username string, customer bool) (keys *loginPasskeys, save func() error, found bool) {
	if customer {
		current := m.customers.Load()
		i, ok := current.find(username)
		if !ok || !current.Customers[i].ready() {
			return nil, nil, false
		}
		next := current.clone()
		return &next.Customers[i].loginPasskeys, func() error {
			if err := saveCustomers(m.dir, next, m.admins); err != nil {
				return err
			}
			m.customers.Store(&next)
			return nil
		}, true
	}
	i, ok := m.admins.find(username)
	if !ok {
		return nil, nil, false
	}
	next := m.admins
	next.Admins = append([]adminRecord(nil), m.admins.Admins...)
	next.Admins[i].loginPasskeys = next.Admins[i].loginPasskeys.clone()
	return &next.Admins[i].loginPasskeys, func() error {
		if err := saveAdmins(m.dir, next); err != nil {
			return err
		}
		m.admins = next
		return nil
	}, true
}

// Passkey is one passkey as Account shows it.
type Passkey struct {
	ID string `json:"id"`
	// CredentialID is the credential ID in base64url, which the browser's
	// passkey manager knows it by.
	CredentialID string     `json:"credential_id"`
	Name         string     `json:"name"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	// Synced reports that the passkey is backed up, as passkeys in a
	// password manager or a phone's account are.
	Synced bool `json:"synced"`
	// Blocked is set when the passkey reported a use count lower than
	// before, which can mean it was copied; it no longer signs in.
	Blocked bool `json:"blocked"`
}

// PasskeyList is the signed-in person's passkeys and whether passkeys work
// where the panel is open. RPID and UserID let the browser's passkey
// manager drop passkeys the panel no longer has.
type PasskeyList struct {
	Items    []Passkey `json:"items"`
	Capacity int       `json:"capacity"`
	PasskeyStatus
	RPID   string `json:"rp_id,omitempty"`
	UserID string `json:"user_id,omitempty"`
}

func (p passkeyRecord) public() Passkey {
	out := Passkey{ID: passkeyPublicID(p.ID), CredentialID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt, Synced: p.BackupState, Blocked: p.CloneWarning}
	if !p.LastUsedAt.IsZero() {
		used := p.LastUsedAt
		out.LastUsedAt = &used
	}
	return out
}

func (m *Manager) passkeyList(r *http.Request, l loginPasskeys) PasskeyList {
	place, status := m.passkeyPlaceFor(r)
	out := PasskeyList{Items: make([]Passkey, 0, len(l.Passkeys)), Capacity: maxPasskeys, PasskeyStatus: status}
	for _, p := range l.Passkeys {
		out.Items = append(out.Items, p.public())
	}
	if status.Available {
		out.RPID, out.UserID = place.rpID, l.PasskeyUser
	}
	return out
}

// listPasskeys answers the signed-in person's own passkeys; it needs what a
// change to its login needs, except Origin and CSRF.
func (m *Manager) listPasskeys(w http.ResponseWriter, r *http.Request) {
	_, a, ok := m.ownLoginFor(w, r, false)
	if !ok {
		return
	}
	m.adminMu.Lock()
	keys, _, found := m.ownPasskeysLocked(a.username, a.customer)
	var l loginPasskeys
	if found {
		l = *keys
	}
	m.adminMu.Unlock()
	if !found {
		writeLoginChanged(w)
		return
	}
	writeJSON(w, m.passkeyList(r, l))
}

type passkeyCreation struct {
	Options   protocol.PublicKeyCredentialCreationOptions `json:"options"`
	ExpiresAt time.Time                                   `json:"expires_at"`
}

// beginPasskey checks the current password and a current code, as a password
// change does, and answers the options for the browser to make a passkey.
func (m *Manager) beginPasskey(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.ownLogin(w, r)
	if !ok {
		return
	}
	place, status := m.passkeyPlaceFor(r)
	if !status.Available {
		writePasskeysUnavailable(w, status)
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		TOTPCode        string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	m.adminMu.Lock()
	keys, _, found := m.ownPasskeysLocked(a.username, a.customer)
	full := found && len(keys.Passkeys) >= maxPasskeys
	m.adminMu.Unlock()
	if full {
		WriteError(w, 409, "passkey_limit", "This login already has 10 passkeys, the most it can have. Remove one you no longer use, then add the new one.")
		return
	}
	checked, ok := m.checkOwnPassword(w, r, a, input.CurrentPassword)
	if !ok {
		return
	}
	rp, err := place.relyingParty()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Passkeys could not be set up right now. Try again in a minute.")
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
	keys, _, found = m.ownPasskeysLocked(a.username, a.customer)
	if !found {
		writeLoginChanged(w)
		return
	}
	handle := keys.PasskeyUser
	if handle == "" {
		if handle, err = randomToken(); err != nil {
			WriteError(w, 503, "operator_unavailable", "Passkeys could not be set up right now. Try again in a minute.")
			return
		}
	}
	user := passkeyLogin{username: a.username, customer: a.customer, passkeys: loginPasskeys{PasskeyUser: handle, Passkeys: keys.Passkeys}}.user()
	exclude := make([]protocol.CredentialDescriptor, 0, len(keys.Passkeys))
	for _, c := range user.WebAuthnCredentials() {
		exclude = append(exclude, c.Descriptor())
	}
	creation, session, err := rp.BeginRegistration(user, webauthn.WithExclusions(exclude), webauthn.WithRegistrationOrigin(place.origin))
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Passkeys could not be set up right now. Try again in a minute.")
		return
	}
	now := m.now()
	for key, p := range m.passkeyAdds {
		if !now.Before(p.expires) {
			delete(m.passkeyAdds, key)
		}
	}
	expires := now.UTC().Add(passkeyLifetime).Truncate(time.Second)
	m.passkeyAdds[id] = pendingPasskeyAdd{session: *session, origin: place.origin, username: a.username, customer: a.customer, handle: handle, expires: expires}
	writeJSON(w, passkeyCreation{Options: creation.Response, ExpiresAt: expires})
}

// finishPasskey checks the browser's new passkey against the ceremony this
// session began and keeps it with the login.
func (m *Manager) finishPasskey(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.ownLogin(w, r)
	if !ok {
		return
	}
	place, status := m.passkeyPlaceFor(r)
	if !status.Available {
		writePasskeysUnavailable(w, status)
		return
	}
	var input struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decodeJSONWithin(w, r, &input, false, passkeyBodyBytes) {
		return
	}
	name := strings.TrimSpace(input.Name)
	if !validPasskeyName(name) {
		WriteError(w, 422, "invalid_name", "Give the passkey a name of 1 to 64 characters, such as the phone, computer or password manager it is saved in.")
		return
	}
	m.adminMu.Lock()
	pending, found := m.passkeyAdds[id]
	delete(m.passkeyAdds, id)
	m.adminMu.Unlock()
	if !found || !m.now().Before(pending.expires) || pending.username != a.username || pending.customer != a.customer || pending.origin != place.origin {
		WriteError(w, 409, "passkey_expired", "This step took more than 5 minutes, or it was started again in another tab. Start again with your password and a code.")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(input.Credential)
	if err != nil {
		WriteError(w, 400, "invalid_request", "The browser's answer could not be read, so no passkey was added. Start again.")
		return
	}
	rp, err := place.relyingParty()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Passkeys could not be set up right now. Try again in a minute.")
		return
	}
	handle, _ := base64.RawURLEncoding.DecodeString(pending.handle)
	credential, err := rp.CreateCredential(passkeyUser{handle: handle, username: a.username}, pending.session, parsed)
	if err != nil {
		WriteError(w, 422, "passkey_not_added", "The new passkey did not pass the panel's checks, so it was not added. It must confirm it is you with a fingerprint, face or PIN. Start again, or try another device or password manager.")
		return
	}
	record := passkeyRecord{ID: base64.RawURLEncoding.EncodeToString(credential.ID), PublicKey: base64.RawURLEncoding.EncodeToString(credential.PublicKey),
		SignCount: credential.Authenticator.SignCount, BackupEligible: credential.Flags.BackupEligible, BackupState: credential.Flags.BackupState,
		Name: name, CreatedAt: m.now().UTC().Truncate(time.Second)}
	if !record.valid() {
		WriteError(w, 422, "passkey_not_added", "The new passkey did not pass the panel's checks, so it was not added. Start again, or try another device or password manager.")
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	keys, save, found := m.ownPasskeysLocked(a.username, a.customer)
	if !found || (keys.PasskeyUser != "" && keys.PasskeyUser != pending.handle) {
		writeLoginChanged(w)
		return
	}
	if !m.stillActiveLocked(id, a) {
		WriteError(w, 401, "unauthorized", "Your session ended before the passkey was saved. Sign in again.")
		return
	}
	switch {
	case len(keys.Passkeys) >= maxPasskeys:
		WriteError(w, 409, "passkey_limit", "This login already has 10 passkeys, the most it can have. Remove one you no longer use, then add the new one.")
		return
	case m.passkeyTakenLocked(record.ID, pending.handle, a.username, a.customer):
		WriteError(w, 409, "passkey_exists", "This passkey is already added to a login on this panel. Choose another device or password manager.")
		return
	}
	keys.PasskeyUser = pending.handle
	keys.Passkeys = append(keys.Passkeys, record)
	if err := save(); err != nil {
		WriteError(w, 503, "operator_unavailable", "The passkey could not be saved on the server, so it was not added. Try again; if it keeps failing, the panel's disk needs a check.")
		return
	}
	writeJSON(w, record.public())
}

// removePasskey removes one of the signed-in person's passkeys and answers
// the passkeys left.
func (m *Manager) removePasskey(w http.ResponseWriter, r *http.Request) {
	_, a, ok := m.ownLogin(w, r)
	if !ok {
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	target := r.PathValue("id")
	if !validManagementID(target) {
		WriteError(w, 400, "invalid_request", "Valid passkey ID required")
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	keys, save, found := m.ownPasskeysLocked(a.username, a.customer)
	if !found {
		writeLoginChanged(w)
		return
	}
	i := slices.IndexFunc(keys.Passkeys, func(p passkeyRecord) bool { return passkeyPublicID(p.ID) == target })
	if i < 0 {
		WriteError(w, 404, "passkey_not_found", "That passkey is not on this login any more. Reload the page.")
		return
	}
	keys.Passkeys = slices.Delete(keys.Passkeys, i, i+1)
	if err := save(); err != nil {
		WriteError(w, 503, "operator_unavailable", "The change could not be saved on the server, so the passkey still works. Try again; if it keeps failing, the panel's disk needs a check.")
		return
	}
	writeJSON(w, m.passkeyList(r, *keys))
}

// getPasskeyLogin tells the sign-in page whether to offer passkeys here. It
// needs no session and reveals only how the panel is set up.
func (m *Manager) getPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !admitted(r) {
		WriteError(w, 403, "local_access_required", "Local operator access required")
		return
	}
	_, status := m.passkeyPlaceFor(r)
	writeJSON(w, status)
}

type passkeyCeremony struct {
	Ceremony  string                                     `json:"ceremony"`
	Options   protocol.PublicKeyCredentialRequestOptions `json:"options"`
	ExpiresAt time.Time                                  `json:"expires_at"`
}

// beginPasskeyLogin answers a challenge for any passkey of this panel, and a
// token that binds it to this request: finish needs both.
func (m *Manager) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !admitted(r) {
		WriteError(w, 403, "local_access_required", "Local operator access required")
		return
	}
	if !sameOrigin(r) {
		WriteError(w, 403, "origin_not_allowed", "Exact local Origin required")
		return
	}
	place, status := m.passkeyPlaceFor(r)
	if !status.Available {
		writePasskeysUnavailable(w, status)
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, true) {
		return
	}
	rp, err := place.relyingParty()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Passkey sign-in is unavailable right now. Sign in with your password and code.")
		return
	}
	assertion, session, err := rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired), webauthn.WithLoginOrigin(place.origin))
	token, tokenErr := randomToken()
	if err != nil || tokenErr != nil {
		WriteError(w, 503, "operator_unavailable", "Passkey sign-in is unavailable right now. Sign in with your password and code.")
		return
	}
	now := m.now()
	expires := now.UTC().Add(passkeyLifetime).Truncate(time.Second)
	key := sha256.Sum256([]byte(token))
	m.adminMu.Lock()
	for k, p := range m.passkeyLogins {
		if !now.Before(p.expires) {
			delete(m.passkeyLogins, k)
		}
	}
	// Bounded: the oldest ceremony makes room. Someone opening many sign-in
	// pages can make another person start again, not use memory.
	for len(m.passkeyLogins) >= maxPasskeyLogins {
		oldest := ""
		for k, p := range m.passkeyLogins {
			if oldest == "" || p.expires.Before(m.passkeyLogins[oldest].expires) {
				oldest = k
			}
		}
		delete(m.passkeyLogins, oldest)
	}
	m.passkeyLogins[string(key[:])] = pendingPasskeyLogin{session: *session, origin: place.origin, expires: expires}
	m.adminMu.Unlock()
	writeJSON(w, passkeyCeremony{Ceremony: token, Options: assertion.Response, ExpiresAt: expires})
}

const wrongPasskey = "The passkey could not be checked, so you are not signed in. Try again, or sign in with your password and code."

// finishPasskeyLogin checks the browser's passkey answer against the
// ceremony the token names and starts the login's session: an admin's or a
// customer's, kept signed in when asked. Every try takes one from the
// sign-in limits, as a password does.
func (m *Manager) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !admitted(r) {
		WriteError(w, 403, "local_access_required", "Local operator access required")
		return
	}
	if !sameOrigin(r) {
		WriteError(w, 403, "origin_not_allowed", "Exact local Origin required")
		return
	}
	// Where passkeys are off, nothing is tried, so the server's own sign-in
	// limit (the access key's way back in) is never touched from here.
	place, status := m.passkeyPlaceFor(r)
	if !status.Available {
		writePasskeysUnavailable(w, status)
		return
	}
	if !m.remoteLimiter.Allow() {
		w.Header().Set("Retry-After", "3")
		WriteError(w, 429, "rate_limited", "Login attempt limit reached")
		return
	}
	var input struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
		Remember   bool            `json:"remember"`
	}
	if !decodeJSONWithin(w, r, &input, false, passkeyBodyBytes) {
		return
	}
	if !validToken(input.Ceremony) || len(input.Credential) == 0 {
		WriteError(w, 400, "invalid_request", "Send the ceremony token and the browser's passkey answer.")
		return
	}
	key := sha256.Sum256([]byte(input.Ceremony))
	m.adminMu.Lock()
	pending, found := m.passkeyLogins[string(key[:])]
	delete(m.passkeyLogins, string(key[:]))
	m.adminMu.Unlock()
	if !found || !m.now().Before(pending.expires) || pending.origin != place.origin {
		WriteError(w, 409, "passkey_expired", "The passkey request expired or was already used. Choose your passkey again.")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(input.Credential)
	if err != nil {
		WriteError(w, 401, "invalid_credentials", wrongPasskey)
		return
	}
	m.adminMu.Lock()
	login, found := m.passkeyLoginLocked(parsed.Response.UserHandle)
	bucketName := "passkey:" + base64.RawURLEncoding.EncodeToString(parsed.Response.UserHandle)
	if found {
		bucketName = login.username
	}
	allowed := m.loginBucket(bucketName, r).Allow()
	m.adminMu.Unlock()
	if !allowed {
		w.Header().Set("Retry-After", "60")
		WriteError(w, 429, "rate_limited", "Too many sign-in attempts for this login. Wait a minute and try again.")
		return
	}
	credentialID := base64.RawURLEncoding.EncodeToString(parsed.RawID)
	if !found || !slices.ContainsFunc(login.passkeys.Passkeys, func(p passkeyRecord) bool { return p.ID == credentialID }) {
		// 404 lets the browser's passkey manager drop a passkey the panel
		// no longer has (signalUnknownCredential).
		WriteError(w, 404, "passkey_unknown", "This passkey is not on any login of this panel; it may have been removed. Sign in with your password and code.")
		return
	}
	rp, err := place.relyingParty()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Passkey sign-in is unavailable right now. Sign in with your password and code.")
		return
	}
	user := login.user()
	if _, _, err := rp.ValidatePasskeyLogin(func(_, _ []byte) (webauthn.User, error) { return user, nil }, pending.session, parsed); err != nil {
		WriteError(w, 401, "invalid_credentials", wrongPasskey)
		return
	}
	if !m.recordPasskeyUse(w, login, credentialID, parsed) {
		return
	}
	m.startSession(w, r, login.username, login.customer, input.Remember)
}

// recordPasskeyUse saves the passkey's new use count and last use
// against the login as it is now, and refuses the sign-in when the login or
// passkey went meanwhile, or the count went back. go-webauthn leaves a
// count that does not grow to the relying party (CloneWarning): the panel
// refuses it and marks the passkey, which then signs in no more, because a
// count going back can mean the passkey was copied. A passkey that always
// reports 0, as synced ones do, is fine. It takes adminMu.
func (m *Manager) recordPasskeyUse(w http.ResponseWriter, login passkeyLogin, credentialID string, parsed *protocol.ParsedCredentialAssertionData) bool {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	keys, save, found := m.ownPasskeysLocked(login.username, login.customer)
	i := -1
	if found && keys.PasskeyUser == login.passkeys.PasskeyUser {
		i = slices.IndexFunc(keys.Passkeys, func(p passkeyRecord) bool { return p.ID == credentialID })
	}
	if i < 0 {
		WriteError(w, 401, "invalid_credentials", wrongPasskey)
		return false
	}
	p := &keys.Passkeys[i]
	counter := webauthn.Authenticator{SignCount: p.SignCount, CloneWarning: p.CloneWarning}
	counter.UpdateCounter(parsed.Response.AuthenticatorData.Counter)
	if counter.CloneWarning {
		if !p.CloneWarning {
			p.CloneWarning = true
			_ = save() // A failed save only leaves the passkey unmarked; this sign-in is refused either way.
		}
		WriteError(w, 401, "passkey_blocked", "This passkey reported fewer uses than before, which can mean it was copied, so the panel no longer accepts it. Sign in with your password and code, then remove it on Account and add it again.")
		return false
	}
	p.SignCount = counter.SignCount
	p.BackupState = parsed.Response.AuthenticatorData.Flags.HasBackupState()
	p.LastUsedAt = m.now().UTC().Truncate(time.Second)
	if err := save(); err != nil {
		WriteError(w, 503, "operator_unavailable", "Sign-in could not be recorded on the server. Try again; if it keeps failing, check the panel's disk.")
		return false
	}
	return true
}
