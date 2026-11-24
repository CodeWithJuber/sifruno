package operator

import (
	"net/http"
	"slices"
)

// Principal is who a request acts for. An admin's session, the access key
// and an API token have the whole panel. A customer's session, and an admin
// session viewing the panel as a customer, are restricted: they may reach
// only that customer's websites, and only the routes the API's customer
// table allows (internal/api/customer_routes.go).
type Principal struct {
	// Actor is what the root broker records as the actor of a change, and so
	// what the account history shows. "local-operator" for an admin (per-admin
	// names come with the audit log), "customer:<name>" for a customer, and
	// "admin:<name> as customer:<customer>" for an admin viewing as a
	// customer, so a change made while viewing is the admin's.
	Actor string
	// Customer is set for a restricted principal: the customer whose
	// websites it may reach.
	Customer string
	// Websites are the hosting account IDs Customer may reach, sorted.
	Websites []string
}

// Restricted reports whether the principal is limited to one customer's
// websites.
func (p Principal) Restricted() bool { return p.Customer != "" }

// Owns reports whether a restricted principal may reach the website with
// this hosting account ID.
func (p Principal) Owns(accountID string) bool {
	_, found := slices.BinarySearch(p.Websites, accountID)
	return p.Restricted() && found
}

// principalFor resolves a session against the current customer snapshot.
// ok is false when a customer's session has no usable login any more
// (removed, disabled or reset), or an admin views a customer that was
// removed; such a session must not act. It takes no lock: the snapshot is
// read-only.
func (m *Manager) principalFor(a activeSession) (Principal, bool) {
	customers := m.customers.Load()
	switch {
	case a.customer:
		i, found := customers.find(a.username)
		if !found || !customers.Customers[i].ready() {
			return Principal{}, false
		}
		return Principal{Actor: "customer:" + a.username, Customer: a.username, Websites: slices.Clone(customers.Customers[i].Websites)}, true
	case a.viewAs != "":
		i, found := customers.find(a.viewAs)
		if !found {
			return Principal{}, false
		}
		admin := a.username
		if admin == "" {
			admin = "local-operator"
		}
		return Principal{Actor: "admin:" + admin + " as customer:" + a.viewAs, Customer: a.viewAs, Websites: slices.Clone(customers.Customers[i].Websites)}, true
	default:
		return Principal{Actor: "local-operator"}, true
	}
}

// sessionPrincipal is principalFor for a request, answering the request
// when the session cannot act. A customer session without a login is
// ended; an admin viewing a removed customer goes back to its own view.
func (m *Manager) sessionPrincipal(w http.ResponseWriter, id string, a activeSession) (Principal, bool) {
	p, ok := m.principalFor(a)
	if ok {
		return p, true
	}
	m.mu.Lock()
	current, live := m.active[id]
	if live && current == a {
		if a.customer {
			delete(m.active, id)
		} else {
			current.viewAs = ""
			m.active[id] = current
		}
	}
	m.mu.Unlock()
	if a.customer {
		WriteError(w, 401, "login_disabled", "Your panel login was turned off or removed, so you were signed out. Ask whoever gave you the login to turn it on again or send you a new setup link.")
	} else {
		WriteError(w, 409, "view_as_ended", "The customer you were viewing was removed, so the panel went back to your admin view and did nothing. Reload the page.")
	}
	return Principal{}, false
}

// Scope reads the session cookie a request carries, without answering the
// request or checking Origin and CSRF (Authorize does that). restricted is
// true for a customer's session and an admin viewing as a customer; then
// ok is false when that session can no longer act and the request must be
// refused. A request without a live session is not restricted.
//
// The API calls this for every request, so a customer session meets the
// customer table also on routes that loopback serves without a session.
func (m *Manager) Scope(r *http.Request) (p Principal, restricted, ok bool) {
	_, _, a, found := m.session(r)
	if !found || (!a.customer && a.viewAs == "") {
		return Principal{}, false, true
	}
	p, ok = m.principalFor(a)
	return p, true, ok
}

// customerSessionRoomLocked makes room for one more session of this
// customer: it ends the customer's oldest session when it has four, and
// reports false when customers already hold their share of the table.
// Called with mu held.
func (m *Manager) customerSessionRoomLocked(username string) bool {
	total, oldestID := 0, ""
	var mine []string
	for id, a := range m.active {
		if !a.customer {
			continue
		}
		total++
		if a.username == username {
			mine = append(mine, id)
			if oldestID == "" || a.created.Before(m.active[oldestID].created) || (a.created.Equal(m.active[oldestID].created) && a.managementID < m.active[oldestID].managementID) {
				oldestID = id
			}
		}
	}
	if len(mine) >= maxSessionsPerCustomer {
		delete(m.active, oldestID)
		total--
	}
	return total < maxCustomerSessions
}

// endCustomerSessionsLocked ends every session of a customer and takes every
// admin session viewing it back to the admin's own view. Called with mu held
// (after adminMu, when a customer's login changes).
func (m *Manager) endCustomerSessionsLocked(username string, viewers bool) {
	for id, a := range m.active {
		switch {
		case a.customer && a.username == username:
			delete(m.active, id)
		case viewers && !a.customer && a.viewAs == username:
			a.viewAs = ""
			m.active[id] = a
		}
	}
}
