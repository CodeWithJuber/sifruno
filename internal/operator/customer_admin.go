package operator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"slices"
	"sort"
	"time"
)

// An admin's routes for customer logins, under /api/v1/session/customers:
// list, create (with a setup link), change websites, turn off and on, make a
// new setup link (which also resets the password and authenticator), and
// remove. Each needs an admin's own session (managementAuthorization), not
// a token, a customer, or an admin viewing as a customer.

// customerBodyBytes bounds a request that lists websites: 64 IDs of 32
// characters, quoted, fit with room to spare.
const customerBodyBytes = 4096

// WebsiteCheck answers which of the given hosting account IDs do not exist.
// The API sets it (CheckWebsitesWith) so an admin gives a customer real
// websites only; without it an ID is checked for its form only. An ID that
// does not exist gives nothing: hosting account IDs are 128 random bits and
// never reused.
type WebsiteCheck func(ctx context.Context, ids []string) (missing []string, err error)

// CheckWebsitesWith sets the check for the websites an admin gives a
// customer.
func (m *Manager) CheckWebsitesWith(check WebsiteCheck) { m.websiteCheck.Store(&check) }

// SetPublicAddress sets the address customers reach the panel at, such as
// https://panel.example.com:2083; setup links start with it. Without it a
// link is a path, and the panel puts the admin's own address in front.
func (m *Manager) SetPublicAddress(address string) { m.publicAddress.Store(&address) }

// CustomerLogin is what the panel shows about a customer's login: never its
// password hash, authenticator secret or setup link.
type CustomerLogin struct {
	Username string   `json:"username"`
	Websites []string `json:"websites"`
	Disabled bool     `json:"disabled"`
	// Setup is "done", "pending" (the link works) or "expired".
	Setup          string     `json:"setup"`
	SetupExpiresAt *time.Time `json:"setup_expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

type CustomerLoginList struct {
	Items    []CustomerLogin `json:"items"`
	Capacity int             `json:"capacity"`
}

// CustomerSetupLink answers a new login or a new setup link. It is the only
// place the link appears; the server keeps only its hash.
type CustomerSetupLink struct {
	CustomerLogin
	SetupLink string `json:"setup_link"`
}

func (c customerRecord) public(now time.Time) CustomerLogin {
	out := CustomerLogin{Username: c.Username, Websites: slices.Clone(c.Websites), Disabled: c.Disabled, Setup: "done", CreatedAt: c.CreatedAt}
	if c.Setup != nil {
		expires := c.Setup.ExpiresAt
		out.SetupExpiresAt, out.Setup = &expires, "pending"
		if !now.Before(expires) {
			out.Setup = "expired"
		}
	}
	return out
}

// newSetupLink makes a link's secret and the half the server keeps.
func (m *Manager) newSetupLink() (string, setupLink, error) {
	token, err := randomToken()
	if err != nil {
		return "", setupLink{}, err
	}
	sum := sha256.Sum256([]byte(token))
	expires := m.now().UTC().Truncate(time.Second).Add(setupLinkLifetime)
	return token, setupLink{Hash: base64.RawStdEncoding.EncodeToString(sum[:]), ExpiresAt: expires}, nil
}

// setupLinkURL puts the secret in the fragment, which browsers do not send
// to the server or in a Referer.
func (m *Manager) setupLinkURL(token string) string {
	base := ""
	if p := m.publicAddress.Load(); p != nil {
		base = *p
	}
	return base + "/setup#" + token
}

// checkWebsites answers the request and returns false when the websites are
// malformed, too many, none, or not on this server.
func (m *Manager) checkWebsites(w http.ResponseWriter, r *http.Request, ids []string) ([]string, bool) {
	websites, ok := normalWebsites(ids)
	switch {
	case !ok:
		WriteError(w, 422, "invalid_websites", "Choose at most 64 websites from the panel's list.")
		return nil, false
	case len(websites) == 0:
		WriteError(w, 422, "invalid_websites", "Choose at least one website for this login.")
		return nil, false
	}
	check := m.websiteCheck.Load()
	if check == nil || *check == nil {
		return websites, true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	missing, err := (*check)(ctx, websites)
	switch {
	case err != nil:
		WriteError(w, 503, "operator_unavailable", "The account service did not answer, so the panel could not check the websites. Nothing changed. Try again in a minute.")
		return nil, false
	case len(missing) > 0:
		WriteError(w, 422, "unknown_website", "One of the chosen websites is not on this server any more. Reload the page and choose again.")
		return nil, false
	}
	return websites, true
}

// customerTarget is the customer a route's {username} names. Called with
// adminMu held; an unknown or malformed name answers 404.
func (m *Manager) customerTargetLocked(w http.ResponseWriter, r *http.Request) (customerFile, int, bool) {
	username := r.PathValue("username")
	next := m.customers.Load().clone()
	i, found := next.find(username)
	if !validUsername(username) || !found {
		WriteError(w, 404, "customer_not_found", "That customer is not on the list. It may have been removed. Reload the page.")
		return customerFile{}, -1, false
	}
	return next, i, true
}

// commitCustomersLocked saves a changed customer file and publishes it,
// after rechecking the admin session that asked (lock order adminMu, then
// mu). Called with adminMu held.
func (m *Manager) commitCustomersLocked(w http.ResponseWriter, id string, a activeSession, next customerFile) bool {
	if !m.stillActiveLocked(id, a) {
		WriteError(w, 401, "unauthorized", "Your session ended before the change was saved, so nothing changed. Sign in again and try again.")
		return false
	}
	if err := saveCustomers(m.dir, next, m.admins); err != nil {
		WriteError(w, 503, "operator_unavailable", "The change could not be saved on the server, so nothing changed. Check the panel's disk, then try again.")
		return false
	}
	m.customers.Store(&next)
	return true
}

// dropPendingLocked forgets a customer's half-finished setup, so an old
// link's secret cannot finish it. Called with adminMu held.
func (m *Manager) dropPendingLocked(username string) {
	for key, p := range m.customerPending {
		if p.username == username {
			delete(m.customerPending, key)
		}
	}
}

func (m *Manager) listCustomers(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := m.managementAuthorization(w, r, false); !ok {
		return
	}
	now := m.now()
	customers := m.customers.Load()
	out := CustomerLoginList{Items: make([]CustomerLogin, 0, len(customers.Customers)), Capacity: maxCustomers}
	for _, c := range customers.Customers {
		out.Items = append(out.Items, c.public(now))
	}
	sort.Slice(out.Items, func(i, j int) bool { return out.Items[i].Username < out.Items[j].Username })
	writeJSON(w, out)
}

func (m *Manager) createCustomer(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct {
		Username string   `json:"username"`
		Websites []string `json:"websites"`
	}
	if !decodeJSONWithin(w, r, &input, false, customerBodyBytes) {
		return
	}
	if !validUsername(input.Username) {
		WriteError(w, 422, "invalid_username", "Choose a username of 3 to 32 lowercase letters, digits, dots, dashes or underscores, starting with a letter.")
		return
	}
	websites, ok := m.checkWebsites(w, r, input.Websites)
	if !ok {
		return
	}
	token, link, err := m.newSetupLink()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "The login could not be made right now. Nothing changed. Try again.")
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	next := m.customers.Load().clone()
	_, isAdmin := m.admins.find(input.Username)
	_, isCustomer := next.find(input.Username)
	switch {
	case isAdmin || isCustomer:
		WriteError(w, 409, "username_taken", "Someone already signs in with this username. Choose another one.")
		return
	case len(next.Customers) >= maxCustomers:
		WriteError(w, 409, "customer_limit", "This panel already has 500 customer logins, the most it keeps. Remove one that is no longer used, then try again.")
		return
	}
	record := customerRecord{Username: input.Username, Websites: websites, Setup: &link, CreatedAt: m.now().UTC().Truncate(time.Second)}
	next.Customers = append(next.Customers, record)
	if !m.commitCustomersLocked(w, id, a, next) {
		return
	}
	writeJSON(w, CustomerSetupLink{CustomerLogin: record.public(m.now()), SetupLink: m.setupLinkURL(token)})
}

func (m *Manager) setCustomerWebsites(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct {
		Websites []string `json:"websites"`
	}
	if !decodeJSONWithin(w, r, &input, false, customerBodyBytes) {
		return
	}
	websites, ok := m.checkWebsites(w, r, input.Websites)
	if !ok {
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	next, i, ok := m.customerTargetLocked(w, r)
	if !ok {
		return
	}
	next.Customers[i].Websites = websites
	if !m.commitCustomersLocked(w, id, a, next) {
		return
	}
	writeJSON(w, next.Customers[i].public(m.now()))
}

// setCustomerState turns a login off or on. Turning it off ends the
// customer's sessions at once; an admin can still view the panel as it.
func (m *Manager) setCustomerState(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct {
		Disabled *bool `json:"disabled"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	if input.Disabled == nil {
		WriteError(w, 422, "invalid_request", "Send disabled: true to turn the login off, or false to turn it on.")
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	next, i, ok := m.customerTargetLocked(w, r)
	if !ok {
		return
	}
	next.Customers[i].Disabled = *input.Disabled
	if !m.commitCustomersLocked(w, id, a, next) {
		return
	}
	if *input.Disabled {
		m.dropPendingLocked(next.Customers[i].Username)
		m.mu.Lock()
		m.endCustomerSessionsLocked(next.Customers[i].Username, false)
		m.mu.Unlock()
	}
	writeJSON(w, next.Customers[i].public(m.now()))
}

// newCustomerSetupLink resets a login: the password, authenticator and
// passkeys are cleared, the customer's sessions end, and a new link replaces
// any old one.
// It is how a customer who lost the authenticator app gets back in.
func (m *Manager) newCustomerSetupLink(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	token, link, err := m.newSetupLink()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "The link could not be made right now. Nothing changed. Try again.")
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	next, i, ok := m.customerTargetLocked(w, r)
	if !ok {
		return
	}
	c := &next.Customers[i]
	// The passkeys go with the password and authenticator: the new setup
	// may be for someone other than whoever held them.
	c.Password, c.TOTP, c.Setup, c.loginPasskeys = nil, nil, &link, loginPasskeys{}
	if !m.commitCustomersLocked(w, id, a, next) {
		return
	}
	m.dropPendingLocked(c.Username)
	m.mu.Lock()
	m.endCustomerSessionsLocked(c.Username, false)
	m.mu.Unlock()
	writeJSON(w, CustomerSetupLink{CustomerLogin: c.public(m.now()), SetupLink: m.setupLinkURL(token)})
}

// deleteCustomer removes a login. The customer's sessions end, and admins
// viewing the panel as it go back to their own view. Its websites stay.
func (m *Manager) deleteCustomer(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	next, i, ok := m.customerTargetLocked(w, r)
	if !ok {
		return
	}
	removed := next.Customers[i]
	next.Customers = slices.Delete(next.Customers, i, i+1)
	if !m.commitCustomersLocked(w, id, a, next) {
		return
	}
	m.dropPendingLocked(removed.Username)
	m.mu.Lock()
	m.endCustomerSessionsLocked(removed.Username, true)
	m.mu.Unlock()
	writeJSON(w, removed.public(m.now()))
}

// ForgetWebsite takes a removed website off every customer's list. The API
// calls it after a delete succeeds. A failure to save leaves the ID on the
// list, which then gives nothing: IDs are never reused.
func (m *Manager) ForgetWebsite(accountID string) error {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	next := m.customers.Load().clone()
	changed := false
	for i := range next.Customers {
		if j, found := slices.BinarySearch(next.Customers[i].Websites, accountID); found {
			next.Customers[i].Websites = slices.Delete(next.Customers[i].Websites, j, j+1)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := saveCustomers(m.dir, next, m.admins); err != nil {
		return err
	}
	m.customers.Store(&next)
	return nil
}
