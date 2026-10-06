// Package hostaccounts exposes a narrow native Linux account foundation. Domain
// is reserved metadata only; no web, DNS, mail, database or cPanel parity exists.
package hostaccounts

import (
	"context"
	"errors"
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

const MaxAccounts = 100
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
	Home       string    `json:"home"`
	PublicHTML string    `json:"public_html"`
	State      string    `json:"state"`
	UID        int       `json:"uid"`
	GID        int       `json:"gid"`
	Revision   uint64    `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
type CreateInput struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Reason   string `json:"reason"`
}
type StateInput struct {
	State            string `json:"state"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}
type Service interface {
	Capability(context.Context) (Capability, error)
	List(context.Context) ([]Account, error)
	Create(context.Context, CreateInput, string) (Account, error)
	SetState(context.Context, string, StateInput, string) (Account, error)
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
	return validUsername(in.Username) && validDomain(in.Domain) && validText(in.Reason, 500) && validText(actor, 120)
}
func validState(in StateInput, actor string) bool {
	return (in.State == "active" || in.State == "suspended") && in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}
func unavailable(reason string) Capability {
	return Capability{Reason: reason, Backend: "unavailable", Restrictions: restrictions()}
}
func restrictions() []string {
	return []string{"domain_is_metadata_only", "managed_service_identities_with_system_flag", "files_only_nss_and_bounded_yes_or_no_useradd_defaults_required", "private_primary_group_only", "password_locked_and_nologin_in_all_states", "suspension_is_pam_account_expiry_only", "existing_processes_mail_web_and_databases_unaffected", "no_delete_or_original_backup_restore", "no_cpanel_compatibility_certification"}
}
