// Package hostaccounts exposes a narrow native Linux account foundation. Domain
// is reserved metadata only; no web, DNS, mail, database or cPanel parity exists.
package hostaccounts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrUnavailable = errors.New("native account service unavailable")
	ErrInvalid     = errors.New("invalid native account input")
	ErrConflict    = errors.New("native account identity or revision conflict")
	ErrNotFound    = errors.New("native account not found")
	ErrRecovery    = errors.New("native account recovery required")
)

// DeleteAttempts is how many times a delete ends the account's processes
// and runs userdel before it gives up on a user that stays busy.
const DeleteAttempts = 3

// ErrDeleteBusy is a delete refused because the account's processes were
// still running after the broker tried to end them: nothing was removed and
// the account is unchanged. It is a conflict too: errors.Is(err,
// ErrConflict) holds.
var ErrDeleteBusy = fmt.Errorf("%w: account processes still running", ErrConflict)

// ErrDeleteStopped is a delete the broker stopped before anything was
// removed for another reason than a busy user: ending the account's
// processes failed or ran out of time. The account is as it was. It is an
// unavailable answer too: errors.Is(err, ErrUnavailable) holds.
var ErrDeleteStopped = fmt.Errorf("%w: delete stopped before anything was removed", ErrUnavailable)

// MaxAccounts bounds one broker's inventory. Every request reads all records
// and checks each account's files, so the bound is a cost limit, not a
// product limit: BenchmarkStoreScale records what a list and a create cost at
// this size. The earlier bound of 100 came from running two utilities per
// account on every request, which the rotating audit batch replaced.
const MaxAccounts = 2000
const MaxRequestBytes = 16 << 10

type Capability struct {
	Available    bool     `json:"available"`
	Reason       string   `json:"reason"`
	Backend      string   `json:"backend"`
	Restrictions []string `json:"restrictions"`
}
type Account struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Domain     string    `json:"domain"`
	Plan       string    `json:"plan"`
	Home       string    `json:"home"`
	PublicHTML string    `json:"public_html"`
	State      string    `json:"state"`
	UID        int       `json:"uid"`
	GID        int       `json:"gid"`
	Revision   uint64    `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	// Certificate is the site's installed certificate, left out when there
	// is none. It always equals the record's TLS, so the account list shows
	// it and the journal's before and after rows record it.
	Certificate CertificateState `json:"certificate,omitzero"`
	// Limits are the account's process, memory and CPU limits; the stored
	// account and the journal's rows carry them, so every plan change that
	// sets them is recorded. An account made before limits were recorded has
	// none stored and runs with DefaultLimits; the account list shows the
	// limits in force either way.
	Limits AccountLimits `json:"limits,omitzero"`
	// Web is the live site's PHP version and quota, left out when there is no
	// site. Only the account list and a state change's answer fill it in,
	// from the record's Web: the stored account and the journal's rows never
	// carry it, so the accounts and journals written before this field need
	// no change.
	Web WebState `json:"web,omitzero"`
	// SiteFolderChanged says the account's own user changed what the broker
	// recorded in its home: public_html renamed, replaced or removed, or the
	// mode of the home or public_html changed. It concerns this account
	// alone: the broker refuses its web, certificate and WordPress changes
	// until the folder is back, and holds up nothing else. Like Web, only
	// the account list fills it in; the stored account and the journal's
	// rows never carry it.
	SiteFolderChanged bool `json:"site_folder_changed,omitempty"`
	// SiteDomains is the live site's aliases and how many redirects it has,
	// left out when it has neither. Like Web, only the account list and a
	// change's answer fill it in: the stored account and the journal's rows
	// never carry it, so a pointer keeps Account comparable while they
	// compare it.
	SiteDomains *SiteDomainsSummary `json:"site_domains,omitempty"`
}
type CreateInput struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	// Plan is reserved package metadata (WHM package name); empty = "default".
	Plan   string `json:"plan"`
	Reason string `json:"reason"`
}
type StateInput struct {
	State            string `json:"state"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}
type PlanInput struct {
	Plan string `json:"plan"`
	// Limits, when given, replace the account's limits; left out, they stay.
	Limits           AccountLimits `json:"limits,omitzero"`
	ExpectedRevision uint64        `json:"expected_revision"`
	Reason           string        `json:"reason"`
}
type DeleteInput struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}
type Service interface {
	Capability(context.Context) (Capability, error)
	List(context.Context) ([]Account, error)
	Create(context.Context, CreateInput, string) (Account, error)
	SetState(context.Context, string, StateInput, string) (Account, error)
	// SetPlan updates the plan name and, when given, the account's process,
	// memory and CPU limits, which the broker applies to the account's user
	// slice and its site's PHP (README, Resource limits).
	SetPlan(context.Context, string, PlanInput, string) (Account, error)
	// Delete permanently removes the managed identity after ownership
	// verification. There is no undo; the operation is journaled.
	Delete(context.Context, string, DeleteInput, string) (Account, error)
}
type BrokerOptions struct {
	StateDir      string
	SocketPath    string
	HomesDir      string
	ControllerUID uint32
}

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)
var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var deniedNames = map[string]bool{"root": true, "daemon": true, "bin": true, "sys": true, "sync": true, "games": true, "man": true, "lp": true, "mail": true, "news": true, "uucp": true, "proxy": true, "www_data": true, "backup": true, "list": true, "irc": true, "gnats": true, "nobody": true, "systemd_network": true, "systemd_resolve": true, "dbus": true, "polkitd": true, "sshd": true, "apache": true, "nginx": true, "mysql": true, "postgres": true, "ftp": true, "operator": true, "sifruno": true}

func validText(s string, max int) bool {
	return s != "" && strings.TrimSpace(s) == s && len(s) <= max && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}
func validUsername(s string) bool { return usernamePattern.MatchString(s) && !deniedNames[s] }
func validDomain(s string) bool {
	if s == "" || len(s) > 253 || s != strings.ToLower(s) || net.ParseIP(s) != nil {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func validCreate(in CreateInput, actor string) bool {
	validPlan := in.Plan == "" || validText(in.Plan, 64)
	return validUsername(in.Username) && validDomain(in.Domain) && validPlan && validText(in.Reason, 500) && validText(actor, 120)
}
func validState(in StateInput, actor string) bool {
	return (in.State == "active" || in.State == "suspended") && in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}
func validPlan(in PlanInput, actor string) bool {
	return validText(in.Plan, 64) && (!in.Limits.given() || validLimits(in.Limits)) && in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}
func validDelete(in DeleteInput, actor string) bool {
	return in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}
func unavailable(reason string) Capability {
	return Capability{Reason: reason, Backend: "unavailable", Restrictions: restrictions()}
}
func restrictions() []string {
	return []string{"domain_is_metadata_only", "managed_regular_identities_with_subordinate_ids", "files_only_nss_and_bounded_yes_or_no_useradd_defaults_required", "private_primary_group_only", "password_locked_and_nologin_in_all_states", "ssh_keys_are_sftp_only_and_broker_managed", "suspension_is_pam_account_expiry_only", "existing_processes_mail_web_and_databases_unaffected", "no_delete_or_original_backup_restore", "no_cpanel_compatibility_certification"}
}
