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
	// systemdRun starts each step in a transient scope, setprivPath drops
	// it to the account's user and envPath gives it a clean environment and
	// its start folder; all three are fixed utilities pinned at start.
	systemdRun  = "/usr/bin/systemd-run"
	setprivPath = "/usr/bin/setpriv"
	envPath     = "/usr/bin/env"
	// siteHome is the HOME of every step: an empty directory, root's, which
	// no tenant can write (made with the web operation, ensureEmptyRootDir).
	// WP-CLI 2.12.0 uses HOME only for its global config
	// (~/.wp-cli/config.yml), its packages (~/.wp-cli/packages, whose
	// autoloader it loads) and its cache (~/.wp-cli/cache), and the install
	// needs none of them, so with this HOME it reads no file of the tenant's
	// from there. The cache is off: WP_CLI_CACHE_DIR=/dev/null, which
	// WP-CLI's FileCache treats as "no cache" without a warning.
	siteHome = "/var/lib/sifruno-site-home"
	// siteStopTimeout bounds the systemctl kill that ends what is left of a
	// step's scope after the step, and the step itself when it runs out of
	// time.
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
var siteUnitPattern = regexp.MustCompile(`^sifruno-site-[0-9]{5}-[0-9a-f]{16}\.scope$`)

// siteUnit names a new step's scope, so two steps never share one.
func siteUnit(uid int) (string, error) {
	if !validLimitUID(uid) {
		return "", ErrInvalid
	}
	var b [8]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrUnavailable
	}
	return "sifruno-site-" + strconv.Itoa(uid) + "-" + hex.EncodeToString(b[:]) + ".scope", nil
}

// siteRunArgs is systemd-run's whole argument list for one step, started
// in the account's public_html (see siteRunArgsIn).
func siteRunArgs(r record, unit string, left time.Duration, path string, args []string) ([]string, error) {
	return siteRunArgsIn(r, unit, left, r.Account.PublicHTML, path, args)
}

// siteRunArgsIn is systemd-run's whole argument list for one step, started
// in dir: the account's public_html, or its home (the file manager's
// helper, which must work while public_html is missing). Only those two are
// accepted. All references are to the versions AlmaLinux 9 ships: systemd
// v252, util-linux v2.37.4 and coreutils v8.32.
//
// systemd-run --scope puts itself in a new transient scope, unit, in the
// account's user slice, with the plan's task limit and the time left, and
// then executes the rest of the line itself (start_transient_scope in
// src/run/run.c): the broker's own pipes are the program's input and
// output, and the program's exit status is systemd-run's. A scope is
// started through PID 1's private socket (run.c:1757-1760), not the bus
// that --wait and --pipe need. RuntimeMaxSec is a scope property
// (bus_append_scope_property in src/shared/bus-unit-util.c, RuntimeMaxUSec
// in src/core/dbus-scope.c): when it passes, systemd sends KillSignal to
// every process in the scope (scope_dispatch_timer in src/core/scope.c),
// even if the broker is gone. --collect unloads the scope even when it
// failed, as one that reached RuntimeMaxSec does. A scope is not stopped
// when its first process ends, so runSiteProgram kills it by name after
// every step.
//
// systemd-run's own --uid and --gid would set the IDs without setgroups
// (run.c:1490-1528), so the broker passes neither. setpriv drops to the
// account's UID and GID with no supplementary group (the broker admits only
// an account that is in no group, managedIdentity), sets no_new_privs, and
// empties the inheritable and bounding capability sets, which empties the
// ambient set too. It keeps the capabilities it needs across its setresuid
// (PR_SET_KEEPCAPS, sys-utils/setpriv.c:1002-1048), so the bounding set can
// be dropped for a non-root target, and execve leaves a non-root program no
// capability. Changing credentials clears the parent-death signal the
// broker set; --pdeathsig keep sets it again just before the exec
// (setpriv.c:1056), so the program is killed if the broker dies. env then
// clears the environment, sets the fixed one and enters dir, as the
// account's user, so root never follows a path in the home
// (src/env.c:874-933).
//
// No program on the way expands anything: systemd-run (run.c:1542), setpriv
// and env each execute the arguments as given, so a "$" or "%" in a site's
// title reaches WP-CLI unchanged. env takes every NAME=VALUE before the
// program as an assignment, so the program's path must not hold "=".
func siteRunArgsIn(r record, unit string, left time.Duration, dir, path string, args []string) ([]string, error) {
	uid := r.Account.UID
	limits := recordLimits(r)
	if !validLimitUID(uid) || r.Account.GID != uid || !siteUnitPattern.MatchString(unit) || !strings.HasPrefix(unit, "sifruno-site-"+strconv.Itoa(uid)+"-") ||
		!validLimits(limits) || left <= 0 || !filepath.IsAbs(path) || strings.Contains(path, "=") || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		(dir != r.Account.PublicHTML && dir != r.Account.Home) || !validUsername(r.Account.Username) {
		return nil, ErrInvalid
	}
	id := strconv.Itoa(uid)
	out := []string{
		"--quiet", "--scope", "--collect",
		"--unit=" + unit,
		// A fixed description: by default systemd-run describes the unit
		// with its whole command line, which carries the site's title, admin
		// email and database names, and any local user can read a unit's
		// description.
		"--description=sifruno site step",
		"--slice=user-" + id + ".slice",
		"--property=TasksMax=" + strconv.Itoa(limits.Processes),
		"--property=RuntimeMaxSec=" + strconv.FormatInt(int64((left+time.Second-1)/time.Second), 10),
		"--property=KillMode=control-group",
		"--property=KillSignal=SIGKILL",
		"--", setprivPath,
		"--reuid=" + id, "--regid=" + id, "--clear-groups",
		// The steps need no setuid program and no capability.
		"--no-new-privs", "--inh-caps=-all", "--bounding-set=-all",
		"--pdeathsig=keep",
		"--", envPath, "-i", "--chdir=" + dir, "--",
		"PATH=/usr/bin:/bin",
		"LANG=C.UTF-8",
		"HOME=" + siteHome,
		"USER=" + r.Account.Username,
		"LOGNAME=" + r.Account.Username,
		"WP_CLI_CACHE_DIR=/dev/null",
		"WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
		path,
	}
	return append(out, args...), nil
}

// siteUnitGone reports whether systemctl kill's exit status and output
// mean that nothing of the step is left in unit: either the kill reached
// it, or systemd has already unloaded the scope. systemd unloads a scope
// moments after its last process ends and then answers "Unit <name> not
// loaded." (bus_get_unit_by_name in src/core/dbus-manager.c at v252), which
// systemctl prints with exit status 1; it never unloads a unit whose cgroup
// still holds a process (unit_may_gc in src/core/unit.c), and a tenant
// cannot move a process out of its root-owned slice.
func siteUnitGone(unit string, code int, out []byte) bool {
	return code == 0 || code == 1 && bytes.Contains(out, []byte("Unit "+unit+" not loaded."))
}

// stopSiteUnit kills every process left in a step's scope.
func (n *linuxSystem) stopSiteUnit(ctx context.Context, unit string) error {
	if !siteUnitPattern.MatchString(unit) {
		return ErrInvalid
	}
	out, code, e := n.commandStatus(ctx, siteStopTimeout, systemctl, "kill", "--signal=SIGKILL", unit)
	if e != nil || !siteUnitGone(unit, code, out) {
		return ErrUnavailable
	}
	return nil
}

// runAsSite runs a fixed program as the account's user, through the pinned
// systemd-run, setpriv and env, in one transient scope in the account's
// user slice (see siteRunArgs). Root changes nothing in the tenant's home:
// it only switches to the user, who enters public_html. The step must have
// a deadline. When it passes, the scope is killed by name, and
// systemd's own RuntimeMaxSec stops it if that kill failed.
func (n *linuxSystem) runAsSite(ctx context.Context, r record, path, stdin string, args ...string) ([]byte, int, error) {
	out := &tailBuffer{}
	code, e := n.runSiteProgram(ctx, r, r.Account.PublicHTML, path, strings.NewReader(stdin), out, out, args...)
	return out.b, code, e
}

// runSiteProgram is runAsSite with the folder the step starts in (see
// siteRunArgsIn) and streams: stdin is copied to the program as it reads,
// and its output reaches stdout and stderr as it writes, so a caller can
// pass a large file through without holding it.
func (n *linuxSystem) runSiteProgram(ctx context.Context, r record, dir, path string, stdin io.Reader, stdout, stderr io.Writer, args ...string) (int, error) {
	deadline, ok := ctx.Deadline()
	if ctx.Err() != nil || !ok || n.limitsUID(r.Account.UID) != nil {
		return -1, ErrUnavailable
	}
	for _, p := range []string{systemdRun, setprivPath, envPath} {
		before, ok := n.tools[p]
		actual, e := trustedFile(p, false)
		if !ok || e != nil || !os.SameFile(before, actual) || before.Size() != actual.Size() || !before.ModTime().Equal(actual.ModTime()) {
			return -1, ErrUnavailable
		}
	}
	unit, e := siteUnit(r.Account.UID)
	if e != nil {
		return -1, ErrUnavailable
	}
	runArgs, e := siteRunArgsIn(r, unit, time.Until(deadline), dir, path, args)
	if e != nil {
		return -1, ErrUnavailable
	}
	cmd := exec.CommandContext(ctx, systemdRun, runArgs...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	// The step gets a session of its own, as a service did, so the tenant's
	// program is not in the broker's session or process group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	// A process the step left may hold the output pipes open; Wait gives up
	// on them after WaitDelay, and the scope is killed just after.
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error { return n.stopSiteUnit(context.WithoutCancel(ctx), unit) }
	cmd.Stdin = stdin
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	// The scope outlives its first process: whatever the step left, a
	// process that called setsid too, is killed now, after a success, a
	// failure or a timeout alike. A step whose leftovers may still run has
	// failed.
	stopErr := n.stopSiteUnit(context.WithoutCancel(ctx), unit)
	if ctx.Err() != nil || stopErr != nil {
		return -1, ErrUnavailable
	}
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return -1, ErrUnavailable
	}
	code := cmd.ProcessState.ExitCode()
	// env exits 125 when it cannot enter dir or set the environment, setpriv
	// 127 when a privilege change fails, and either 126 or 127 when it cannot
	// execute the next program (errexec in util-linux's include/c.h,
	// src/env.c:945): the program did not run, which the broker reports as
	// its own failure, not the program's. A program's own 125 to 127 counts
	// the same; every caller fails a step on any non-zero status. systemd-run
	// failing before the scope starts, and setpriv's few earlier errors
	// (no_new_privs, PR_SET_KEEPCAPS), exit 1 like a failed program.
	if code >= 125 && code <= 127 {
		return -1, ErrUnavailable
	}
	return code, nil
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
