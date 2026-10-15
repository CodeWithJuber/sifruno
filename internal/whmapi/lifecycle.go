package whmapi

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"regexp"
)

// LifecycleBackend extends Backend with the observed account lifecycle
// mutations. Implementations map to sifruno's real account service; errors
// use the sentinel values below so handlers can emit the exact observed
// WHM reason strings.
type LifecycleBackend interface {
	Backend
	CreateAccount(ctx context.Context, username, domain string) (Account, error)
	// SuspendAccount reports whether the account was already suspended
	// (the reference answers repeat suspends with success-with-notice).
	SuspendAccount(ctx context.Context, username, reason string) (already bool, err error)
	UnsuspendAccount(ctx context.Context, username string) error
}

var (
	// ErrDuplicateUser maps to the observed "already has an account named"
	// reason.
	ErrDuplicateUser = errors.New("whmapi: account already exists")
	// ErrInvalidUsername maps to the observed "not a valid username" reason.
	ErrInvalidUsername = errors.New("whmapi: invalid username")
	// ErrNoSuchUser maps to the observed "do not have a user named" reason.
	ErrNoSuchUser = errors.New("whmapi: no such user")
	// ErrUnsupported marks operations this backend honestly cannot perform
	// yet (e.g. account removal has no hostaccounts counterpart).
	ErrUnsupported = errors.New("whmapi: operation not supported by backend")
)

// xid returns a 6-character random token matching the observed volatile
// `(XID xxxxxx)` segment of reference error strings.
func xid() string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b [6]byte
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "000000"
	}
	for i, v := range raw {
		b[i] = alpha[int(v)%len(alpha)]
	}
	return string(b[:])
}

var whmUsername = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

// Compat reason strings: the "(XID …) … at …/Create.pm line 659." shape is
// an interface contract — unchanged clients pattern-match it. The volatile
// XID is freshly generated per call like the reference. See
// docs/reference/whm-cpanel-138-lifecycle-capture.md §3.
func reasonDuplicateUser(username string) string {
	return fmt.Sprintf("(XID %s) This system already has an account named “%s”. at /usr/local/cpanel/Whostmgr/Accounts/Create.pm line 659.\n", xid(), username)
}
func reasonInvalidUsername(username string) string {
	return fmt.Sprintf("(XID %s) “%s” is not a valid username on this system. at /usr/local/cpanel/Whostmgr/Accounts/Create.pm line 659.\n", xid(), username)
}
func reasonNoSuchUser(username string) string {
	return fmt.Sprintf("API failure: (XID %s) You do not have a user named “%s”.", xid(), username)
}

func (s *Server) handleCreateAcct(w http.ResponseWriter, r *http.Request) {
	lb, ok := s.backend.(LifecycleBackend)
	if !ok {
		writeError(w, "createacct", "API failure: account creation is not available on this backend.")
		return
	}
	q := r.URL.Query()
	username, domain := q.Get("username"), q.Get("domain")
	if username == "" {
		// Observed verbatim on the reference.
		writeError(w, "createacct", `No user name supplied: "username" is a required argument.`)
		return
	}
	if !whmUsername.MatchString(username) {
		writeError(w, "createacct", reasonInvalidUsername(username))
		return
	}
	if domain == "" {
		writeError(w, "createacct", `No domain supplied: "domain" is a required argument.`)
		return
	}
	acct, err := lb.CreateAccount(r.Context(), username, domain)
	if errors.Is(err, ErrDuplicateUser) {
		writeError(w, "createacct", reasonDuplicateUser(username))
		return
	}
	if errors.Is(err, ErrInvalidUsername) {
		writeError(w, "createacct", reasonInvalidUsername(username))
		return
	}
	if err != nil {
		writeError(w, "createacct", "API failure: (XID "+xid()+") Account creation failed; the operation journal retains the pending state.")
		return
	}
	// Truthful step log: only steps actually performed by this backend.
	raw := "Checking input data......Done\n" +
		"Setting up System User...Done\n" +
		"Setting up Userdata......Done\n" +
		"Setting up Home Directory......Done\n" +
		"Account Creation Complete!!!...Account Creation Ok...Done\n"
	writeSuccess(w, "createacct", map[string]any{
		"ip": acct.IP, "package": acct.Plan,
		"nameserver": nil, "nameserver2": nil, "nameserver3": "", "nameserver4": "",
		"nameservera": nil, "nameservera2": nil, "nameservera3": nil, "nameservera4": nil,
		"nameserverentry": nil, "nameserverentry2": nil, "nameserverentry3": nil, "nameserverentry4": nil,
	}, raw)
}

func (s *Server) handleSuspendAcct(w http.ResponseWriter, r *http.Request) {
	lb, ok := s.backend.(LifecycleBackend)
	if !ok {
		writeError(w, "suspendacct", "API failure: account suspension is not available on this backend.")
		return
	}
	q := r.URL.Query()
	username := q.Get("user")
	if username == "" {
		writeError(w, "suspendacct", `No user name supplied: "user" is a required argument.`)
		return
	}
	reason := q.Get("reason")
	if reason == "" {
		reason = "Suspended via WHM API"
	}
	already, err := lb.SuspendAccount(r.Context(), username, reason)
	if errors.Is(err, ErrNoSuchUser) {
		writeError(w, "suspendacct", reasonNoSuchUser(username))
		return
	}
	if err != nil {
		writeError(w, "suspendacct", "API failure: (XID "+xid()+") Suspension failed; the account keeps its previous state.")
		return
	}
	if already {
		// Observed: repeat suspend is success-with-notice, not an error.
		writeSuccess(w, "suspendacct", nil, fmt.Sprintf("User '%s' is already suspended. Provide '--force' argument if you wish to do this.\n", username))
		return
	}
	writeSuccess(w, "suspendacct", nil, fmt.Sprintf("Changing Shell to /bin/false...Done\nLocking Password...Done\nSuspending websites...\n%s's account has been suspended\n", username))
}

func (s *Server) handleUnsuspendAcct(w http.ResponseWriter, r *http.Request) {
	lb, ok := s.backend.(LifecycleBackend)
	if !ok {
		writeError(w, "unsuspendacct", "API failure: account unsuspension is not available on this backend.")
		return
	}
	username := r.URL.Query().Get("user")
	if username == "" {
		writeError(w, "unsuspendacct", `No user name supplied: "user" is a required argument.`)
		return
	}
	err := lb.UnsuspendAccount(r.Context(), username)
	if errors.Is(err, ErrNoSuchUser) {
		writeError(w, "unsuspendacct", reasonNoSuchUser(username))
		return
	}
	if err != nil {
		writeError(w, "unsuspendacct", "API failure: (XID "+xid()+") Unsuspension failed; the account keeps its previous state.")
		return
	}
	writeSuccess(w, "unsuspendacct", nil, fmt.Sprintf("Unsuspending websites...\n%s's account is now active\n%s's account has been unsuspended\n", username, username))
}

func (s *Server) handleRemoveAcct(w http.ResponseWriter, r *http.Request) {
	// hostaccounts has no delete operation; fail closed and honest rather
	// than fabricate the ~40-step observed removal pipeline.
	username := r.URL.Query().Get("user")
	if username == "" {
		writeError(w, "removeacct", `No user name supplied: "user" is a required argument.`)
		return
	}
	writeError(w, "removeacct", "API failure: (XID "+xid()+") Account removal is not implemented on this backend; no state was changed.")
}
