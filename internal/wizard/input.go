package wizard

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Input is what the person typed. Kind is KindWordPress ("" means it too) or
// KindPHP. A WordPress site has a title and an admin account; a PHP site has
// neither, and a database only if Database is set, with the password the
// person chose for its user. The passwords are held in memory only and never
// stored; the run drops its references when it ends, after the step that
// last uses them or after undoing a failed job.
type Input struct {
	Kind          string
	Domain        string
	Title         string
	AdminUser     string
	AdminEmail    string
	AdminPassword string
	PHPVersion    string
	Database      bool
	DBPassword    string
}

// wantsDatabase reports whether the site gets a database: a WordPress site
// always, a PHP site when the person asked for one.
func (in Input) wantsDatabase() bool { return in.Kind != KindPHP || in.Database }

var (
	// ErrInvalid, ErrConflict and ErrUnavailable classify a refused start.
	ErrInvalid     = errors.New("invalid website request")
	ErrConflict    = errors.New("website request conflicts with the server's state")
	ErrUnavailable = errors.New("website creation unavailable")
)

// Refusal is why a job was not started. Detail is plain English for the
// person; Reason is ErrInvalid, ErrConflict or ErrUnavailable.
type Refusal struct {
	Reason error
	Detail string
}

func (e *Refusal) Error() string { return e.Detail }
func (e *Refusal) Unwrap() error { return e.Reason }

func refuse(reason error, format string, args ...any) error {
	return &Refusal{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

var (
	adminUserPattern = regexp.MustCompile(`^[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,59}$`)
	usernamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)
	phpVersions      = map[string]bool{"8.1": true, "8.2": true, "8.3": true, "8.4": true}
)

// deniedNames mirrors hostaccounts.deniedNames: the broker refuses these
// usernames. TestDerivedNamesPassTheBroker keeps the two in step.
var deniedNames = map[string]bool{"root": true, "daemon": true, "bin": true, "sys": true, "sync": true, "games": true, "man": true, "lp": true, "mail": true, "news": true, "uucp": true, "proxy": true, "www_data": true, "backup": true, "list": true, "irc": true, "gnats": true, "nobody": true, "systemd_network": true, "systemd_resolve": true, "dbus": true, "polkitd": true, "sshd": true, "apache": true, "nginx": true, "mysql": true, "postgres": true, "ftp": true, "operator": true, "sifruno": true}

// Validate checks every field the way the broker will, so a request it
// would refuse is refused here, before anything is created. It returns the
// input with the title's outer spaces removed (the broker refuses them) and
// Kind set.
func Validate(in Input) (Input, error) {
	if in.Kind == "" {
		in.Kind = KindWordPress
	}
	switch in.Kind {
	case KindWordPress:
		if in.Database || in.DBPassword != "" {
			return in, refuse(ErrInvalid, "A WordPress site always gets its own database; the panel makes its password.")
		}
	case KindPHP:
		return validatePHP(in)
	default:
		return in, refuse(ErrInvalid, "The website type must be WordPress or PHP site.")
	}
	in.Title = strings.TrimSpace(in.Title)
	switch {
	case !validDomain(in.Domain):
		return in, refuse(ErrInvalid, "domain must be a lowercase domain name with at least one dot, such as example.com.")
	case !validTitle(in.Title):
		return in, refuse(ErrInvalid, "title must be 1 to 200 characters, not only spaces, with no control characters. Letters outside English count as 2 to 4.")
	case !adminUserPattern.MatchString(in.AdminUser):
		return in, refuse(ErrInvalid, "admin_user must be 1 to 60 characters: letters, numbers and . _ @ -, not starting with -.")
	case !validAdminEmail(in.AdminEmail):
		return in, refuse(ErrInvalid, "admin_email must be a plain email address such as me@example.com, at most 100 characters.")
	case !validPassword(in.AdminPassword):
		return in, refuse(ErrInvalid, "admin_password must be 12 to 128 characters, with no control characters and no space at the start or end.")
	case !phpVersions[in.PHPVersion]:
		return in, refuse(ErrInvalid, "php_version must be 8.1, 8.2, 8.3 or 8.4.")
	}
	return in, nil
}

// validatePHP checks a PHP site: its domain and PHP version, and the
// database user's password when it asks for a database. It has no WordPress
// fields.
func validatePHP(in Input) (Input, error) {
	switch {
	case !validDomain(in.Domain):
		return in, refuse(ErrInvalid, "domain must be a lowercase domain name with at least one dot, such as example.com.")
	case !phpVersions[in.PHPVersion]:
		return in, refuse(ErrInvalid, "php_version must be 8.1, 8.2, 8.3 or 8.4.")
	case in.Title != "" || in.AdminUser != "" || in.AdminEmail != "" || in.AdminPassword != "":
		return in, refuse(ErrInvalid, "A PHP site has no WordPress title or admin account.")
	case in.Database && !validPassword(in.DBPassword):
		return in, refuse(ErrInvalid, "database_password must be 12 to 128 characters, with no control characters and no space at the start or end.")
	case !in.Database && in.DBPassword != "":
		return in, refuse(ErrInvalid, "database_password is only for a site that gets a database. Leave it empty, or ask for a database.")
	}
	return in, nil
}

// validDomain is hostaccounts.validDomain: a lowercase host name with at
// least two labels, not an IP address.
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

// validText is the broker's rule for free text: no outer spaces, valid
// UTF-8, no control characters, at most max bytes.
func validText(s string, max int) bool {
	return s != "" && strings.TrimSpace(s) == s && len(s) <= max && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// validTitle counts bytes, as the broker does, so a title it would refuse
// after the account exists is refused before.
func validTitle(s string) bool { return validText(s, 200) }

func validAdminEmail(s string) bool {
	if !validText(s, 100) || strings.ContainsAny(s, " <>\"") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == "" && strings.Count(s, "@") == 1
}

// validPassword is the broker's rule (12 to 128 bytes, one stdin line, no
// outer space because WP-CLI trims what it reads) plus no control
// characters at all.
func validPassword(s string) bool {
	if len(s) < 12 || len(s) > 128 || strings.Trim(s, " ") != s || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// usernameBase derives the hosting account's name from the domain: the
// first label, lowercased, [a-z0-9] only, starting with a letter ("s" is
// put in front if not), cut to 12 characters, and "site" added when shorter
// than 3.
func usernameBase(domain string) string {
	label, _, _ := strings.Cut(domain, ".")
	b := make([]byte, 0, len(label)+1)
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b = append(b, c)
		}
	}
	name := string(b)
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "s" + name
	}
	if len(name) > 12 {
		name = name[:12]
	}
	if len(name) < 3 {
		name += "site"
	}
	return name
}

// usernameCandidate is the name for one try: the base first (unless the
// broker refuses it outright), then the base with two random digits.
func usernameCandidate(base string, try int, digits func() string) string {
	if try == 0 && !deniedNames[base] {
		return base
	}
	return base + digits()
}

func randomDigits() string { return fmt.Sprintf("%02d", rand.IntN(100)) }

func validUsername(s string) bool { return usernamePattern.MatchString(s) && !deniedNames[s] }
