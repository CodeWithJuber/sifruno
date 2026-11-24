//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sifruno/internal/olsweb"
)

// The WordPress install runs WP-CLI with the site's own LSPHP as the
// account's user. Its privileges are the tenant's: it can write only what
// the tenant can already write, so a tenant's files can change what it does
// but not what it may touch. The passwords reach it on stdin (WP-CLI's
// --prompt), never in an argument another local user could read.
const (
	// The installer puts WP-CLI here and checks it against the release's
	// published sha512; the broker checks it again before every install.
	wpcliPath = "/usr/local/lib/sifruno/wp-cli.phar"
	// WP-CLI 2.12.0 (wp-cli-2.12.0.phar.sha512 from the GitHub release).
	wpcliSHA512 = "be928f6b8ca1e8dfb9d2f4b75a13aa4aee0896f8a9a0a1c45cd5d2c98605e6172e6d014dda2e27f88c98befc16c040cbb2bd1bfa121510ea5cdf5f6a30fe8832"
	maxWPCLI    = 32 << 20
	chmodPath   = "/usr/bin/chmod"
	// Sites run in an OpenLiteSpeed namespace container, which does not see
	// the MariaDB socket, so WordPress connects over loopback TCP.
	wpDBHost = "127.0.0.1"
	wpLocale = "en_US"
)

// wpPHP is the CLI binary of the LSPHP the site runs.
func wpPHP(version string) string {
	return olsweb.ServerRoot + "/lsphp" + strings.ReplaceAll(version, ".", "") + "/bin/php"
}

// checkWPCLI accepts the phar only as a regular root-owned file, readable by
// the site user, whose bytes match the pinned release.
func checkWPCLI() error {
	info, e := trustedFile(wpcliPath, false)
	if e != nil || info.Mode().Perm()&0004 == 0 || info.Size() > maxWPCLI {
		return ErrUnavailable
	}
	fd, e := unix.Open(wpcliPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), wpcliPath)
	defer f.Close()
	held, e := f.Stat()
	if e != nil || !os.SameFile(info, held) {
		return ErrUnavailable
	}
	h := sha512.New()
	if _, e := io.Copy(h, io.LimitReader(f, maxWPCLI+1)); e != nil || hex.EncodeToString(h.Sum(nil)) != wpcliSHA512 {
		return ErrUnavailable
	}
	return nil
}

// tailBuffer keeps the last 64 KiB a step printed and never fails a write,
// so a chatty step is not cut short by its own output.
type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if over := len(t.b) - 64<<10; over > 0 {
		t.b = append(t.b[:0], t.b[over:]...)
	}
	return len(p), nil
}

// runAsSite runs a fixed program as the account's user: its UID and GID, no
// supplementary groups, a clean environment, in its public_html. Go's exec
// drops to that user before it changes directory and sets the parent-death
// signal after, so the child never acts as root.
func (n *linuxSystem) runAsSite(ctx context.Context, r record, path, stdin string, args ...string) ([]byte, int, error) {
	if ctx.Err() != nil || r.Account.UID <= 0 || r.Account.GID <= 0 {
		return nil, -1, ErrUnavailable
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = r.Account.PublicHTML
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + r.Account.Home, "USER=" + r.Account.Username, "LOGNAME=" + r.Account.Username, "WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(r.Account.UID), Gid: uint32(r.Account.GID), Groups: []uint32{}},
		Setpgid:    true,
		Pdeathsig:  syscall.SIGKILL,
	}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	cmd.Stdin = strings.NewReader(stdin)
	out := &tailBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return out.b, -1, ErrUnavailable
	}
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return out.b, -1, ErrUnavailable
	}
	return out.b, cmd.ProcessState.ExitCode(), nil
}

func (n *linuxSystem) InstallWordPress(ctx context.Context, r record, in WordPressInput) (WordPressResult, error) {
	if n.webUID <= 0 || !r.Web.enabled() {
		return WordPressResult{}, ErrUnavailable
	}
	php := wpPHP(r.Web.PHPVersion)
	for _, p := range []string{php, chmodPath} {
		if info, e := trustedFile(p, false); e != nil || info.Mode().Perm()&0001 == 0 {
			return WordPressResult{}, ErrUnavailable
		}
	}
	if checkWPCLI() != nil {
		return WordPressResult{}, ErrUnavailable
	}
	wp := func(args ...string) []string {
		return append([]string{"-d", "memory_limit=256M", wpcliPath, "--path=" + r.Account.PublicHTML, "--no-color"}, args...)
	}
	scheme := "http"
	if in.HTTPS {
		scheme = "https"
	}
	secrets := []string{in.AdminPassword, in.DBPassword}
	failed := func(step string, out []byte) error {
		return &InstallError{Step: step, Detail: installDetail(out, secrets...)}
	}
	// WP-CLI answers a skipped check (checksums it could not fetch) with
	// success too, so the cache plugin's check must say it verified it.
	verified := []byte("Success: Verified 1 of 1 plugins.")
	steps := []struct {
		name, path, stdin string
		args              []string
		want              []byte // output the step must print, if any
	}{
		{"download", php, "", wp("core", "download", "--locale="+wpLocale), nil},
		{"config", php, in.DBPassword + "\n", wp("config", "create", "--dbname="+in.DBName, "--dbuser="+in.DBUser, "--dbhost="+wpDBHost, "--prompt=dbpass"), nil},
		// wp-config.php holds the database password and PHP runs as the site
		// user, so no one else needs to read it.
		{"config", chmodPath, "", []string{"0600", r.Account.PublicHTML + "/wp-config.php"}, nil},
		{"install", php, in.AdminPassword + "\n", wp("core", "install", "--url="+scheme+"://"+r.Account.Domain, "--title="+in.Title, "--admin_user="+in.AdminUser, "--admin_email="+in.AdminEmail, "--skip-email", "--prompt=admin_password"), nil},
		// LiteSpeed Cache, pinned, checked against wordpress.org's checksums
		// before it is activated. "Cache Logged-in Users" is on by default;
		// off, a signed-in visitor's pages are never cached.
		{"cache plugin", php, "", wp("plugin", "install", LSCachePlugin, "--version="+LSCachePluginVersion), nil},
		{"cache plugin", php, "", wp("plugin", "verify-checksums", LSCachePlugin, "--version="+LSCachePluginVersion), verified},
		{"cache plugin", php, "", wp("plugin", "activate", LSCachePlugin), nil},
		{"cache plugin", php, "", wp("litespeed-option", "set", "cache-priv", "0"), nil},
	}
	for _, st := range steps {
		out, code, e := n.runAsSite(ctx, r, st.path, st.stdin, st.args...)
		if e != nil || code != 0 || (st.want != nil && !bytes.Contains(out, st.want)) {
			return WordPressResult{}, failed(st.name, out)
		}
	}
	out, code, e := n.runAsSite(ctx, r, php, "", wp("core", "version")...)
	version := string(bytes.TrimSpace(out))
	if e != nil || code != 0 || !wpVersionPattern.MatchString(version) {
		return WordPressResult{}, failed("version", out)
	}
	return WordPressResult{Version: version}, nil
}
