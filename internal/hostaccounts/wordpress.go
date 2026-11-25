package hostaccounts

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

// ErrInstallFailed means a WP-CLI step ended with an error. The broker
// records nothing for an install, so the account is as it was; the files the
// step left in public_html are the tenant's own.
var ErrInstallFailed = errors.New("WordPress install failed")

// InstallError says which step the broker ran as the site's user failed (a
// WP-CLI step of the WordPress install, or the placeholder page), with the
// end of what it printed (printable ASCII only, secrets removed, at most 512
// bytes). Installed says WordPress itself was installed before the step
// failed (a LiteSpeed Cache step, or reading the version): the site works,
// and running the install again stops at its download step, which finds
// WordPress's files.
type InstallError struct {
	Step      string `json:"step"`
	Detail    string `json:"detail"`
	Installed bool   `json:"wordpress_installed,omitempty"`
}

func (e *InstallError) Error() string {
	if e.Installed {
		return "WordPress is installed; only its " + e.Step + " step failed"
	}
	return "site " + e.Step + " step failed"
}
func (e *InstallError) Is(target error) bool { return target == ErrInstallFailed }

// WordPressInput installs WordPress into a live site. The passwords reach
// WP-CLI on stdin, never in a process argument. The site address is the
// account's own domain.
type WordPressInput struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	HTTPS            bool   `json:"https"`
	Title            string `json:"title"`
	AdminUser        string `json:"admin_user"`
	AdminEmail       string `json:"admin_email"`
	AdminPassword    string `json:"admin_password"`
	DBName           string `json:"db_name"`
	DBUser           string `json:"db_user"`
	DBPassword       string `json:"db_password"`
}

// WordPressResult reports the installed WordPress version.
type WordPressResult struct {
	Version string `json:"version"`
}

// WordPressService is implemented by the store and the client.
type WordPressService interface {
	InstallWordPress(ctx context.Context, id string, in WordPressInput, actor string) (WordPressResult, error)
}

// wordpressTimeout bounds a whole install, download included. It does not
// follow the caller, so a client that gives up does not cut a step in half.
const wordpressTimeout = 10 * time.Minute

// The install adds the LiteSpeed Cache plugin, which is how WordPress asks
// OpenLiteSpeed's cache module to keep a page. WP-CLI fetches this exact
// version from wordpress.org as the site's user, then checks every file
// against wordpress.org's published checksums for it
// (downloads.wordpress.org/plugin-checksums/litespeed-cache/7.9.3.json)
// before it activates the plugin. 7.9.3 is the version the wordpress.org
// plugin API named on 2026-11-24 (released 2026-11-03).
const (
	LSCachePlugin        = "litespeed-cache"
	LSCachePluginVersion = "7.9.3"
)

var (
	wpAdminPattern   = regexp.MustCompile(`^[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,59}$`)
	wpDBNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	wpVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?([-.][A-Za-z0-9]+)?$`)
)

// validSecret accepts a password that fits on one stdin line. WP-CLI trims
// what its prompt reads (php-cli-tools Streams::input), so an edge space
// would be dropped there but not by the database: it is refused.
func validSecret(s string) bool {
	if len(s) < 12 || len(s) > 128 || strings.Trim(s, " ") != s {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validAdminEmail(s string) bool {
	if len(s) > 100 || !validText(s, 100) || strings.ContainsAny(s, " <>\"") {
		return false
	}
	a, e := mail.ParseAddress(s)
	return e == nil && a.Address == s && a.Name == "" && strings.Count(s, "@") == 1
}

// validWordPress checks what the caller sent; the database names must carry
// the account's prefix, as the panel's database tools name them.
func validWordPress(in WordPressInput, username string) bool {
	prefix := username + "_"
	return in.ExpectedRevision != 0 &&
		validText(in.Title, 200) && strings.TrimSpace(in.Title) != "" &&
		wpAdminPattern.MatchString(in.AdminUser) &&
		validAdminEmail(in.AdminEmail) &&
		validSecret(in.AdminPassword) && validSecret(in.DBPassword) &&
		wpDBNamePattern.MatchString(in.DBName) && len(in.DBName) <= 64 && strings.HasPrefix(in.DBName, prefix) && len(in.DBName) > len(prefix) &&
		wpDBNamePattern.MatchString(in.DBUser) && len(in.DBUser) <= 47 && strings.HasPrefix(in.DBUser, prefix) && len(in.DBUser) > len(prefix)
}

// installDetail keeps the end of a step's output: printable ASCII only, the
// secrets removed, at most 512 bytes.
func installDetail(out []byte, secrets ...string) string {
	text := string(out)
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "[secret]")
		}
	}
	b := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\n' || c == '\t':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		}
	}
	text = strings.Join(strings.Fields(string(b)), " ")
	if len(text) > 512 {
		text = text[len(text)-512:]
	}
	return text
}
