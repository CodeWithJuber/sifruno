package api

import (
	"net/http"
	"path"
	"slices"
	"strings"

	"sifruno/internal/operator"
)

// What a customer may do, in one place. A customer's session, and an admin's
// while it views the panel as a customer, are restricted (operator.Principal):
// they reach a route only when this table allows it, and a route whose
// address names a website only for that customer's own websites. Every
// route the panel registers has an entry, adminOnly included;
// TestCustomerRouteTableCoversEveryRoute fails when a route is added
// without a decision, or an entry names a route that does not exist.
//
// A customer may list and open its websites, change their domains and
// redirects, databases (phpMyAdmin included), files and scheduled jobs, read
// their logs and usage, and see their backups. It may not create, suspend,
// resume or delete a website, change its PHP version, folder, plan or
// limits, take or restore a backup, set up backup storage, see the server,
// use API tokens, see other customers, run the New website wizard, move a
// website here from another server, or use the older static sites.
// (PHP version and the folder repair stay admin-only: Jev, 0.82.)

type customerAccess int

const (
	// adminOnly: a restricted session is refused (403).
	adminOnly customerAccess = iota
	// customerOpen: no website in the address and nothing about anyone
	// else: the panel page itself, and the session's own sign-in routes.
	customerOpen
	// ownWebsite: the {account_id} in the address must be one of the
	// customer's websites; any other ID, real or not, gets one answer (404).
	ownWebsite
	// ownWebsites: the handler answers with the customer's websites only.
	ownWebsites
)

const websiteID = "account_id"

var customerRoutes = map[string]customerAccess{
	// The panel page and its assets hold no data. The catch-all also answers
	// 404 for any /api/ or /openapi path no other route serves.
	"/": customerOpen,

	// Sign-in, the session itself, and a customer's own setup link.
	"POST /api/v1/session/login":                 customerOpen,
	"GET /api/v1/session":                        customerOpen,
	"POST /api/v1/session/logout":                customerOpen,
	"GET /api/v1/session/setup":                  customerOpen,
	"POST /api/v1/session/customer-setup/begin":  customerOpen,
	"POST /api/v1/session/customer-setup/finish": customerOpen,
	// An admin viewing as a customer must be able to go back.
	"POST /api/v1/session/view-as/end": customerOpen,
	// The signed-in person's own password and authenticator app. The
	// operator refuses an admin viewing as a customer: the login is the
	// customer's.
	"POST /api/v1/session/password":             customerOpen,
	"POST /api/v1/session/authenticator/begin":  customerOpen,
	"POST /api/v1/session/authenticator/finish": customerOpen,
	// The panel's own management: admins only.
	"GET /api/v1/session/sessions":                         adminOnly,
	"POST /api/v1/session/sessions/{id}/revoke":            adminOnly,
	"POST /api/v1/session/revoke-others":                   adminOnly,
	"POST /api/v1/session/setup/totp":                      adminOnly,
	"POST /api/v1/session/setup/admin":                     adminOnly,
	"GET /api/v1/session/tokens":                           adminOnly,
	"POST /api/v1/session/tokens":                          adminOnly,
	"POST /api/v1/session/tokens/{id}/revoke":              adminOnly,
	"GET /api/v1/session/customers":                        adminOnly,
	"POST /api/v1/session/customers":                       adminOnly,
	"POST /api/v1/session/customers/{username}/websites":   adminOnly,
	"POST /api/v1/session/customers/{username}/state":      adminOnly,
	"POST /api/v1/session/customers/{username}/setup-link": adminOnly,
	"POST /api/v1/session/customers/{username}/delete":     adminOnly,
	"POST /api/v1/session/view-as":                         adminOnly,

	// Websites: the list and one website's page.
	"GET /api/v1/websites/sites":                                               ownWebsites,
	"GET /api/v1/websites/sites/{account_id}":                                  ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/domain-add":                      ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/domain-remove":                   ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/redirect-add":                    ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/redirect-remove":                 ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/php":                             adminOnly,
	"POST /api/v1/websites/sites/{account_id}/state":                           adminOnly,
	"POST /api/v1/websites/sites/{account_id}/folder":                          adminOnly,
	"POST /api/v1/websites/sites/{account_id}/delete":                          adminOnly,
	"GET /api/v1/websites/sites/{account_id}/databases":                        ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/databases":                       ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/databases/users":                 ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/databases/{name}/delete":         ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/databases/users/{user}/password": ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/databases/users/{user}/delete":   ownWebsite,
	// phpMyAdmin opens on its own origin, signed in as a temporary user
	// limited to this website's databases (internal/phpmyadmin).
	"POST /api/v1/websites/sites/{account_id}/databases/phpmyadmin": ownWebsite,
	"GET /api/v1/websites/sites/{account_id}/files":                 ownWebsite,
	"GET /api/v1/websites/sites/{account_id}/files/content":         ownWebsite,
	"GET /api/v1/websites/sites/{account_id}/files/download":        ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/files/save":           ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/files/folder":         ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/files/rename":         ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/files/delete":         ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/files/mode":           ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/files/upload":         ownWebsite,
	"GET /api/v1/websites/sites/{account_id}/cron":                  ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/cron":                 ownWebsite,
	"GET /api/v1/websites/sites/{account_id}/logs/{kind}":           ownWebsite,
	"GET /api/v1/websites/sites/{account_id}/usage":                 ownWebsite,
	"GET /api/v1/websites/sites/{account_id}/backups":               ownWebsite,
	"POST /api/v1/websites/sites/{account_id}/backups":              adminOnly,
	"POST /api/v1/websites/sites/{account_id}/backups/restore":      adminOnly,
	"POST /api/v1/websites/sites/{account_id}/backups/drill":        adminOnly,
	"GET /api/v1/websites/backup-storage":                           adminOnly,
	"POST /api/v1/websites/backup-storage":                          adminOnly,
	"POST /api/v1/websites/backup-storage/password":                 adminOnly,
	"POST /api/v1/websites/backup-storage/password-saved":           adminOnly,

	// The New website wizard and its jobs, which list every website.
	"POST /api/v1/websites/wordpress": adminOnly,
	"POST /api/v1/websites/php":       adminOnly,
	"GET /api/v1/websites/jobs":       adminOnly,
	"GET /api/v1/websites/jobs/{id}":  adminOnly,

	// Hosting accounts: create, suspend, plans, delete, previews.
	"GET /api/v1/accounts":              adminOnly,
	"POST /api/v1/accounts":             adminOnly,
	"GET /api/v1/accounts/capability":   adminOnly,
	"POST /api/v1/accounts/{id}/state":  adminOnly,
	"POST /api/v1/accounts/{id}/plan":   adminOnly,
	"POST /api/v1/accounts/{id}/delete": adminOnly,
	"/api/v1/accounts/web-preview":      adminOnly,

	// The older static sites, which are the server's, not a customer's.
	"GET /api/v1/sites":                                  adminOnly,
	"POST /api/v1/sites":                                 adminOnly,
	"POST /api/v1/sites/import":                          adminOnly,
	"GET /api/v1/sites/{id}":                             adminOnly,
	"DELETE /api/v1/sites/{id}":                          adminOnly,
	"PUT /api/v1/sites/{id}/name":                        adminOnly,
	"POST /api/v1/sites/{id}/rename":                     adminOnly,
	"PUT /api/v1/sites/{id}/domain":                      adminOnly,
	"POST /api/v1/sites/{id}/state":                      adminOnly,
	"GET /api/v1/sites/{id}/files":                       adminOnly,
	"GET /api/v1/sites/{id}/file":                        adminOnly,
	"PUT /api/v1/sites/{id}/file":                        adminOnly,
	"DELETE /api/v1/sites/{id}/file":                     adminOnly,
	"PUT /api/v1/sites/{id}/upload":                      adminOnly,
	"POST /api/v1/sites/{id}/upload":                     adminOnly,
	"GET /api/v1/sites/{id}/files/download":              adminOnly,
	"GET /api/v1/sites/{id}/backups":                     adminOnly,
	"POST /api/v1/sites/{id}/backups":                    adminOnly,
	"GET /api/v1/sites/{id}/backups/{backupID}/download": adminOnly,
	"POST /api/v1/sites/{id}/remove-backup":              adminOnly,
	"POST /api/v1/sites/{id}/restore":                    adminOnly,
	"POST /api/v1/sites/{id}/restore-preview":            adminOnly,
	"POST /api/v1/sites/{id}/restore-file":               adminOnly,
	"POST /api/v1/sites/{id}/restore-file-preview":       adminOnly,
	"POST /api/v1/sites/{id}/archive-restore":            adminOnly,
	"POST /api/v1/sites/{id}/archive-restore-preview":    adminOnly,
	"GET /api/v1/sites/{id}/backup-schedule":             adminOnly,
	"PUT /api/v1/sites/{id}/backup-schedule":             adminOnly,

	// The server, the panel's settings, and the API description.
	"GET /api/v1/server":    adminOnly,
	"GET /api/v1/services":  adminOnly,
	"GET /api/v1/status":    adminOnly,
	"GET /api/v1/platform":  adminOnly,
	"GET /api/v1/trail":     adminOnly,
	"GET /api/v1/budget":    adminOnly,
	"GET /openapi.json":     adminOnly,
	"GET /openapi.yaml":     adminOnly,
	"GET /openapi-3.0.json": adminOnly,
	"GET /openapi-3.0.yaml": adminOnly,

	// Moving a website here from another server: it needs root on the old
	// server and makes a hosting account, so it is the operator's.
	"POST /api/v1/websites/migrations/sources":               adminOnly,
	"GET /api/v1/websites/migrations/sources/{id}":           adminOnly,
	"POST /api/v1/websites/migrations/sources/{id}/host-key": adminOnly,
	"GET /api/v1/websites/migrations/sources/{id}/accounts":  adminOnly,
	"POST /api/v1/websites/migrations/sources/{id}/cancel":   adminOnly,
	"POST /api/v1/websites/migrations":                       adminOnly,
	"POST /api/v1/websites/migrations/{id}/verify":           adminOnly,
	"POST /api/v1/websites/migrations/{id}/accept":           adminOnly,
	"POST /api/v1/websites/migrations/{id}/ready":            adminOnly,
	// Key lines a migration could not prove removed from an old server.
	"GET /api/v1/websites/migrations/stale-keys":               adminOnly,
	"POST /api/v1/websites/migrations/stale-keys/{id}/cleared": adminOnly,

	// The WHM compatibility transport and cPanel paths.
	"/json-api/":         adminOnly,
	"/execute/":          adminOnly,
	"/cpsess":            adminOnly,
	"/scripts/":          adminOnly,
	"/usr/local/cpanel/": adminOnly,
}

// customerAllowedRoutes lists the routes the table lets a restricted session
// use, sorted. The session routes hand it to the panel
// (operator.Manager.SetCustomerRoutes), which shows a restricted viewer only
// the controls these allow, so the panel and this table cannot disagree. An
// ownWebsite route is listed too: its website must still be the customer's.
func customerAllowedRoutes() []string {
	var allowed []string
	for pattern, access := range customerRoutes {
		if access != adminOnly {
			allowed = append(allowed, pattern)
		}
	}
	slices.Sort(allowed)
	return allowed
}

// customerAdmitted applies the table to a restricted principal and answers
// the request when it is refused. The route is the one the mux will serve:
// a path the mux would clean or redirect, or one with escaped characters,
// is refused first, so the address the table reads is the one the handler
// gets.
func customerAdmitted(w http.ResponseWriter, r *http.Request, mux *routeMux, p operator.Principal) bool {
	if r.URL.RawPath != "" || path.Clean(r.URL.Path) != r.URL.Path {
		refuseCustomerRoute(w)
		return false
	}
	_, pattern := mux.Handler(r)
	switch customerRoutes[pattern] {
	case customerOpen, ownWebsites:
		return true
	case ownWebsite:
		id, ok := patternValue(pattern, r.URL.Path, websiteID)
		if ok && p.Owns(id) {
			return true
		}
		// Not this customer's, or no such website: one answer for both.
		operator.WriteError(w, 404, "website_not_found", websiteNotFound)
		return false
	default:
		refuseCustomerRoute(w)
		return false
	}
}

func refuseCustomerRoute(w http.ResponseWriter) {
	operator.WriteError(w, 403, "customer_not_allowed", "Your login cannot use this part of the panel. It manages your own websites; ask whoever runs this server for anything else.")
}

// patternValue reads the path segment a pattern's {name} matched. Patterns
// in the table have one segment per wildcard and no {name...} wildcards.
func patternValue(pattern, urlPath, name string) (string, bool) {
	if _, p, found := strings.Cut(pattern, " "); found {
		pattern = p
	}
	want, got := strings.Split(pattern, "/"), strings.Split(urlPath, "/")
	if len(want) != len(got) {
		return "", false
	}
	for i, segment := range want {
		if segment == "{"+name+"}" {
			return got[i], true
		}
	}
	return "", false
}

// customerScope is the gate every request meets first: a request carrying a
// restricted session is held to the table even on routes loopback serves
// without a session. Authorize checks the table again (admit), because an
// admin's session can start or stop viewing as a customer between the two.
func customerScope(w http.ResponseWriter, r *http.Request, mux *routeMux, op *operator.Manager) bool {
	if op == nil {
		return true
	}
	p, restricted, ok := op.Scope(r)
	switch {
	case !restricted:
		return true
	case !ok:
		operator.WriteError(w, 401, "login_disabled", "Your panel session ended: the login was turned off or removed, or the customer you were viewing was removed. Reload the page.")
		return false
	}
	return customerAdmitted(w, r, mux, p)
}
