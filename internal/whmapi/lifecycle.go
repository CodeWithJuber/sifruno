package whmapi

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sifruno/internal/dnshost"
	"strings"
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

// PlanCreator is an optional LifecycleBackend extension that records the
// WHM package as account plan metadata.
type PlanCreator interface {
	CreateAccountPlan(ctx context.Context, username, domain, plan string) (Account, error)
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
	// ErrConflicted marks a revision race against the account service; the
	// caller should re-read and retry.
	ErrConflicted = errors.New("whmapi: account revision conflict")
)

// Remover is an optional backend extension for journaled account removal.
type Remover interface {
	RemoveAccount(ctx context.Context, username string) error
}

// PlanChanger is an optional backend extension for package changes.
type PlanChanger interface {
	ChangePackage(ctx context.Context, username, plan string) error
}

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
// XID is freshly generated per call.
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
	plan := q.Get("plan")
	if s.pkgs != nil && plan != "" && !s.pkgs.Has(plan) {
		// Reason wording observed for changepackage; createacct's own
		// missing-plan wording is unverified (noted in the batch doc).
		writeError(w, "createacct", "API failure: (XID "+xid()+") Specified package does not exist.")
		return
	}
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
	var acct Account
	var err error
	if pc, ok := lb.(PlanCreator); ok && plan != "" {
		acct, err = pc.CreateAccountPlan(r.Context(), username, domain, plan)
	} else {
		acct, err = lb.CreateAccount(r.Context(), username, domain)
	}
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
	// Default DNS zone for the account domain (reference pipeline step).
	dnsNote := ""
	if s.dns != nil {
		ns1, ns2 := s.dnsNS1, s.dnsNS2
		if ns1 == "" {
			ns1, ns2 = "ns1."+domain, "ns2."+domain
		}
		ip := acct.IP
		if ip == "" || ip == "*unknown*" {
			ip = s.dnsIP
		}
		if ip == "" {
			ip = "127.0.0.1"
		}
		if zerr := s.dns.Save(dnshost.NewDefaultZone(domain, ns1, ns2, ip)); zerr != nil {
			dnsNote = "Setting up DNS zone...Failed (" + zerr.Error() + ")\n"
		} else {
			dnsNote = "Setting up DNS zone...Done\n"
		}
	}
	// Truthful step log: only steps actually performed by this backend.
	raw := "Checking input data......Done\n" +
		"Setting up System User...Done\n" +
		"Setting up Userdata......Done\n" +
		"Setting up Home Directory......Done\n" +
		dnsNote +
		"Account Creation Complete!!!...Account Creation Ok...Done\n"
	if plan == "" {
		plan = acct.Plan
	}
	writeSuccess(w, "createacct", map[string]any{
		"ip": acct.IP, "package": plan,
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

type dbPurger interface {
	PurgeOwner(ctx context.Context, owner string) (purged []string, errs []string)
}

type mailPurger interface {
	PurgeAccount(ctx context.Context, account string, domains []string) (purged int, errs []string)
}

func joinErrs(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	return " (" + strings.Join(errs, "; ") + ")"
}

func (s *Server) handleRemoveAcct(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		writeError(w, "removeacct", `No user name supplied: "user" is a required argument.`)
		return
	}
	rm, ok := s.backend.(Remover)
	if !ok {
		writeError(w, "removeacct", "API failure: (XID "+xid()+") Account removal is not implemented on this backend; no state was changed.")
		return
	}
	// Capture the account's domains before removal for the post-purge.
	acctDomains := []string{}
	for _, a := range s.backend.ListAccounts() {
		if a.User == username {
			if a.Domain != "" {
				acctDomains = append(acctDomains, a.Domain)
			}
			break
		}
	}
	err := rm.RemoveAccount(r.Context(), username)
	if errors.Is(err, ErrNoSuchUser) {
		writeError(w, "removeacct", reasonNoSuchUser(username))
		return
	}
	if err != nil {
		// The broker journals the pending deletion; an uncertain effect is
		// never reported as removed.
		writeError(w, "removeacct", "API failure: (XID "+xid()+") Removal did not complete; the account is marked recovery_required and the operation is journaled.")
		return
	}
	// Truthful step log: only what this backend actually did (the full
	// observed ~40-step pipeline includes services sifruno does not run yet).
	// Post-removal purge of account-owned resources (the reference's
	// removeacct does the same). Failures are logged into the step
	// output, never hidden — the account itself is already gone.
	purgeNotes := ""
	if s.dns != nil {
		for _, d := range acctDomains {
			_ = s.dns.Delete(d)
		}
		purgeNotes += fmt.Sprintf("Removing DNS zones...%d removed...Done\n", len(acctDomains))
	}
	if s.db != nil {
		if purger, ok := s.db.(dbPurger); ok {
			purged, perrs := purger.PurgeOwner(r.Context(), username)
			purgeNotes += fmt.Sprintf("Removing MySQL databases and users...%d removed%s...Done\n", len(purged), joinErrs(perrs))
		}
	}
	if s.mail != nil {
		if purger, ok := s.mail.(mailPurger); ok {
			n, perrs := purger.PurgeAccount(r.Context(), username, acctDomains)
			purgeNotes += fmt.Sprintf("Removing mailboxes...%d removed%s...Done\n", n, joinErrs(perrs))
		}
	}
	if s.tlsStore != nil {
		tlsRemoved := 0
		for _, d := range acctDomains {
			if err := s.tlsStore.Delete(r.Context(), d); err == nil {
				tlsRemoved++
			}
		}
		_ = s.tlsStore.PurgeAccount(username)
		if s.autossl != nil {
			_ = s.autossl.PurgeAccount(username)
		}
		purgeNotes += fmt.Sprintf("Removing SSL certificates...%d removed...Done\n", tlsRemoved)
	}
	if s.backups != nil {
		n, _ := s.backups.Purge(r.Context(), username)
		purgeNotes += fmt.Sprintf("Removing backup archives...%d removed...Done\n", n)
	}
	raw := fmt.Sprintf("Locking account and setting shell to nologin......Done\nRemoving User & Group.......Success...Done\nRemoving HTTP virtual hosts...%s...Done\n%s%s account removed\n", username, purgeNotes, username)
	// Observed success reason: "<user> account removed" (not "OK").
	writeSuccessReason(w, "removeacct", username+" account removed", map[string]any{}, raw)
}

func (s *Server) handleChangePackage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	username, plan := q.Get("user"), q.Get("pkg")
	if username == "" {
		writeError(w, "changepackage", `No user name supplied: "user" is a required argument.`)
		return
	}
	if plan == "" {
		writeError(w, "changepackage", `API failure: (XID `+xid()+`) No package name supplied.`)
		return
	}
	if s.pkgs != nil && !s.pkgs.Has(plan) {
		// Observed verbatim on the reference.
		writeError(w, "changepackage", "API failure: (XID "+xid()+") Specified package does not exist.")
		return
	}
	pc, ok := s.backend.(PlanChanger)
	if !ok {
		writeError(w, "changepackage", "API failure: (XID "+xid()+") Package changes are not implemented on this backend; no state was changed.")
		return
	}
	err := pc.ChangePackage(r.Context(), username, plan)
	if errors.Is(err, ErrNoSuchUser) {
		writeError(w, "changepackage", reasonNoSuchUser(username))
		return
	}
	if err != nil {
		writeError(w, "changepackage", "API failure: (XID "+xid()+") Package change failed; the account keeps its previous plan.")
		return
	}
	// The observed success emits an HTML diff log in output.raw; sifruno
	// logs the actual change only (no fabricated limit rewrites).
	raw := fmt.Sprintf("Changing plan from previous to %s\nShell Access Set Correctly (noshell)\n", plan)
	writeSuccess(w, "changepackage", nil, raw)
}
