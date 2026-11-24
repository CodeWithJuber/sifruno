//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sifruno/internal/olsweb"
)

// The WordPress install runs WP-CLI with the site's own LSPHP as the
// account's user. Its privileges are the tenant's: it can write only what
// the tenant can already write, so a tenant's files can change what it does
// but not what it may touch. The tenant controls code WP-CLI loads
// (wp-cli.yml in public_html, wp-config.php, mu-plugins), so every step
// runs inside the account's own user slice with its plan's task limit (see
// runAsSite), never in the broker's cgroup. The passwords reach it on stdin
// (WP-CLI's --prompt), never in an argument another local user could read.
const (
	// systemdRun starts each step as a transient service; it is one of the
	// fixed utilities pinned at start.
	systemdRun = "/usr/bin/systemd-run"
	// siteHome is the HOME of every step: an empty directory, root's, which
	// no tenant can write (made with the web operation, ensureEmptyRootDir).
	// WP-CLI 2.12.0 uses HOME only for its global config
	// (~/.wp-cli/config.yml), its packages (~/.wp-cli/packages, whose
	// autoloader it loads) and its cache (~/.wp-cli/cache), and the install
	// needs none of them, so with this HOME it reads no file of the tenant's
	// from there. The cache is off: WP_CLI_CACHE_DIR=/dev/null, which
	// WP-CLI's FileCache treats as "no cache" without a warning.
	siteHome = "/var/lib/sifruno-site-home"
	// siteStopTimeout bounds the systemctl kill that ends a step's unit when
	// the step runs out of time.
	siteStopTimeout = 15 * time.Second
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

// siteUnitPattern is the only unit name a step runs in, and the only one
// the broker kills: the account's UID and 64 random bits.
var siteUnitPattern = regexp.MustCompile(`^sifruno-site-[0-9]{5}-[0-9a-f]{16}\.service$`)

// siteUnit names a new step's unit, so two steps never share one.
func siteUnit(uid int) (string, error) {
	if !validLimitUID(uid) {
		return "", ErrInvalid
	}
	var b [8]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrUnavailable
	}
	return "sifruno-site-" + strconv.Itoa(uid) + "-" + hex.EncodeToString(b[:]) + ".service", nil
}

// siteRunArgs is systemd-run's whole argument list for one step: a
// transient service, unit, in the account's user slice, run by systemd as
// the account's UID and GID (no other group: the broker admits only an
// account that is in no group, managedIdentity), in its public_html, which
// systemd enters after it drops to that user. The service has the plan's
// task limit and stops by itself when the time left runs out, even if the
// broker is gone. When the program ends, systemd kills every process still
// in the unit (KillMode=control-group, KillSignal=SIGKILL), those that left
// its session with setsid too. --wait and --pipe keep the program's input,
// output and exit status the broker's; --collect unloads the unit even when
// it failed. systemd expands $NAME and ${NAME} in a service's arguments when
// it runs them, so every "$" is doubled, which it turns back into one.
func siteRunArgs(r record, unit string, left time.Duration, path string, args []string) ([]string, error) {
	uid := r.Account.UID
	limits := recordLimits(r)
	if !validLimitUID(uid) || r.Account.GID != uid || !siteUnitPattern.MatchString(unit) || !strings.HasPrefix(unit, "sifruno-site-"+strconv.Itoa(uid)+"-") ||
		!validLimits(limits) || left <= 0 || !filepath.IsAbs(path) || !filepath.IsAbs(r.Account.PublicHTML) || !validUsername(r.Account.Username) {
		return nil, ErrInvalid
	}
	id := strconv.Itoa(uid)
	out := []string{
		"--quiet", "--wait", "--pipe", "--collect",
		"--unit=" + unit,
		// A fixed description: by default systemd-run describes the unit
		// with its whole command line, which carries the site's title, admin
		// email and database names, and any local user can read a unit's
		// description.
		"--description=sifruno site step",
		"--slice=user-" + id + ".slice",
		"--uid=" + id, "--gid=" + id,
		"--working-directory=" + r.Account.PublicHTML,
		"--property=TasksMax=" + strconv.Itoa(limits.Processes),
		"--property=RuntimeMaxSec=" + strconv.FormatInt(int64((left+time.Second-1)/time.Second), 10),
		"--property=KillMode=control-group",
		"--property=KillSignal=SIGKILL",
		// The steps need no setuid program.
		"--property=NoNewPrivileges=yes",
		"--setenv=PATH=/usr/bin:/bin",
		"--setenv=LANG=C.UTF-8",
		"--setenv=HOME=" + siteHome,
		"--setenv=USER=" + r.Account.Username,
		"--setenv=LOGNAME=" + r.Account.Username,
		"--setenv=WP_CLI_CACHE_DIR=/dev/null",
		"--setenv=WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
		"--",
	}
	for _, a := range append([]string{path}, args...) {
		out = append(out, strings.ReplaceAll(a, "$", "$$"))
	}
	return out, nil
}

// stopSiteUnit kills every process of a step's unit. Ending systemd-run
// alone would leave the unit running.
func (n *linuxSystem) stopSiteUnit(ctx context.Context, unit string) error {
	if !siteUnitPattern.MatchString(unit) {
		return ErrInvalid
	}
	_, e := n.commandWithin(ctx, siteStopTimeout, systemctl, "kill", "--signal=SIGKILL", unit)
	return e
}

// runAsSite runs a fixed program as the account's user, through the pinned
// systemd-run, as one transient service in the account's user slice (see
// siteRunArgs). Root changes nothing in the tenant's home: systemd only
// switches to the user and enters public_html as that user. The step must
// have a deadline. When it passes, the unit is killed by name; systemd-run
// then returns, or WaitDelay kills it, and systemd's own RuntimeMaxSec stops
// the unit if that kill failed.
func (n *linuxSystem) runAsSite(ctx context.Context, r record, path, stdin string, args ...string) ([]byte, int, error) {
	deadline, ok := ctx.Deadline()
	if ctx.Err() != nil || !ok || n.limitsUID(r.Account.UID) != nil {
		return nil, -1, ErrUnavailable
	}
	before, ok := n.tools[systemdRun]
	actual, e := trustedFile(systemdRun, false)
	if !ok || e != nil || !os.SameFile(before, actual) || before.Size() != actual.Size() || !before.ModTime().Equal(actual.ModTime()) {
		return nil, -1, ErrUnavailable
	}
	unit, e := siteUnit(r.Account.UID)
	if e != nil {
		return nil, -1, ErrUnavailable
	}
	runArgs, e := siteRunArgs(r, unit, time.Until(deadline), path, args)
	if e != nil {
		return nil, -1, ErrUnavailable
	}
	cmd := exec.CommandContext(ctx, systemdRun, runArgs...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// systemd holds a copy of the output pipe until it releases the inactive
	// unit, just after systemd-run returns; on a busy host that can take a
	// moment, and Wait fails if the pipe is still open after WaitDelay.
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error { return n.stopSiteUnit(context.WithoutCancel(ctx), unit) }
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
	return runWordPressSteps(wordPressSteps(r, in, php), []string{in.AdminPassword, in.DBPassword}, func(st wpStep) ([]byte, int, error) {
		return n.runAsSite(ctx, r, st.path, st.stdin, st.args...)
	})
}

// wpStep is one program the install runs as the site's user, and the text
// it must print, if any.
type wpStep struct {
	name, path, stdin string
	args              []string
	want              []byte
}

// wordPressSteps is the whole install, in order; the last step reads the
// installed version.
func wordPressSteps(r record, in WordPressInput, php string) []wpStep {
	wp := func(args ...string) []string {
		return append([]string{"-d", "memory_limit=256M", wpcliPath, "--path=" + r.Account.PublicHTML, "--no-color"}, args...)
	}
	scheme := "http"
	if in.HTTPS {
		scheme = "https"
	}
	// WP-CLI answers a skipped check (checksums it could not fetch) with
	// success too, so the cache plugin's check must say it verified it.
	verified := []byte("Success: Verified 1 of 1 plugins.")
	// LiteSpeed Cache 7.9.3's own example sets the option with "false"
	// (cli/option.cls.php, Option::set); the command then prints the key and
	// the stored value, which is 0 for an option that is off (Option::get).
	privateOff := []byte("cache-priv:\n0\n")
	return []wpStep{
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
		{"cache setting", php, "", wp("litespeed-option", "set", "cache-priv", "false"), privateOff},
		{"version", php, "", wp("core", "version"), nil},
	}
}

// runWordPressSteps runs the steps in order and stops at the first that
// fails, ends badly or does not print what it must; the last step prints
// the WordPress version. A failure after core install says WordPress is
// installed (InstallError.Installed): the site works, and running the
// install again would stop at its download step, which finds WordPress's
// files.
func runWordPressSteps(steps []wpStep, secrets []string, run func(wpStep) ([]byte, int, error)) (WordPressResult, error) {
	installed := false
	for i, st := range steps {
		out, code, e := run(st)
		ok := e == nil && code == 0 && (st.want == nil || bytes.Contains(out, st.want))
		version := string(bytes.TrimSpace(out))
		if ok && i == len(steps)-1 && wpVersionPattern.MatchString(version) {
			return WordPressResult{Version: version}, nil
		}
		if !ok || i == len(steps)-1 {
			return WordPressResult{}, &InstallError{Step: st.name, Detail: installDetail(out, secrets...), Installed: installed}
		}
		if st.name == "install" {
			installed = true
		}
	}
	return WordPressResult{}, ErrUnavailable
}
