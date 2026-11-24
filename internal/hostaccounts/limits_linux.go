//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The limits operation's root effects, each fixed:
//   - the account's slice drop-in, /etc/systemd/system/user-<uid>.slice.d/
//     50-sifruno-limits.conf. Its path is built only from a UID in the
//     account range (never 0, a system user or the controller), and it is
//     reached through directory handles opened without following links
//     from the root-owned unit directory, which no tenant can write. The
//     file is root's, 0644, written beside its target with O_EXCL|O_NOFOLLOW,
//     synced and renamed; new files and directories take the unit
//     directory's SELinux label;
//   - `systemctl daemon-reload`, by a direct exec of /usr/bin/systemctl,
//     so systemd loads the drop-in. systemd reads unit files and drop-ins
//     when it loads a unit or reloads; a reload reruns the generators and
//     rereads every unit file, which takes a moment on a host with many
//     units, so it runs once per account change and once at start.

const (
	systemdUnitDir = "/etc/systemd/system"
	// systemdReloadTimeout bounds daemon-reload, which rereads every unit.
	systemdReloadTimeout = 60 * time.Second
	limitsFileMode       = 0644
)

// limitsUID refuses a UID outside the account range or the controller's.
func (n *linuxSystem) limitsUID(uid int) error {
	if !validLimitUID(uid) || uid == int(n.opts.ControllerUID) {
		return ErrInvalid
	}
	return nil
}

// openUnitDir opens the systemd unit directory, which must be root's and
// writable by nobody else along its whole path.
func (n *linuxSystem) openUnitDir() (*os.File, error) {
	if authority(n.unitDir) != nil {
		return nil, ErrUnavailable
	}
	return openRootDir(n.unitDir)
}

// openSliceDir opens (with create, making it root's 0755) the account's
// slice drop-in directory below units, without following a link. An
// existing one must be root's and writable by nobody else.
func openSliceDir(units *os.File, uid int, create bool) (*os.File, error) {
	name, e := sliceDropInDir(uid)
	if e != nil {
		return nil, e
	}
	created := false
	if create {
		if e := unix.Mkdirat(int(units.Fd()), name, 0755); e == nil {
			created = true
		} else if !errors.Is(e, unix.EEXIST) {
			return nil, ErrUnavailable
		}
	}
	fd, e := unix.Openat(int(units.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	dir := os.NewFile(uintptr(fd), name)
	if created && (unix.Fchown(fd, 0, 0) != nil || unix.Fchmod(fd, 0755) != nil) {
		dir.Close()
		return nil, ErrUnavailable
	}
	owner, _, mode, e := ownerOfHandle(dir)
	if e != nil || owner != 0 || mode&0022 != 0 {
		dir.Close()
		return nil, ErrUnavailable
	}
	return dir, nil
}

// writeLimits makes the account's drop-in hold exactly these limits and
// reports whether it changed anything.
func (n *linuxSystem) writeLimits(units *os.File, uid int, l AccountLimits) (bool, error) {
	if e := n.limitsUID(uid); e != nil {
		return false, e
	}
	want, e := renderSliceLimits(l)
	if e != nil {
		return false, e
	}
	dir, e := openSliceDir(units, uid, true)
	if e != nil {
		return false, ErrUnavailable
	}
	defer dir.Close()
	got, meta, found, e := readAt(dir, limitsDropIn)
	if e != nil {
		return false, e
	}
	if found && bytes.Equal(got, want) && meta == (fileMeta{0, 0, limitsFileMode}) {
		return false, nil
	}
	if e := writeAt(dir, limitsDropIn, want, fileMeta{0, 0, limitsFileMode}); e != nil {
		return false, e
	}
	return true, nil
}

// removeLimitsFile removes the broker's drop-in of the UID and its
// directory when nothing else is in it (an administrator's own drop-ins
// stay). It reports whether it removed the file.
func removeLimitsFile(units *os.File, uid int) (bool, error) {
	dir, e := openSliceDir(units, uid, false)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	defer dir.Close()
	removed := true
	if e := unix.Unlinkat(int(dir.Fd()), limitsDropIn, 0); errors.Is(e, unix.ENOENT) {
		removed = false
	} else if e != nil {
		return false, ErrUnavailable
	}
	name, _ := sliceDropInDir(uid)
	if e := unix.Unlinkat(int(units.Fd()), name, unix.AT_REMOVEDIR); e != nil && !errors.Is(e, unix.ENOTEMPTY) && !errors.Is(e, unix.EEXIST) {
		return removed, ErrUnavailable
	}
	return removed, nil
}

func (n *linuxSystem) reloadSystemd(ctx context.Context) error {
	_, e := n.commandWithin(ctx, systemdReloadTimeout, systemctl, "daemon-reload")
	return e
}

// sliceLoaded reports whether systemd has the account's user slice in
// memory. systemd reads a unit's configuration, drop-ins included, when the
// unit is first referenced, and a reload is needed only to change a unit
// that is already loaded (systemd.unit(5), "Unit Garbage Collection", at
// v252). `systemctl list-units --all` shows the units systemd has in memory
// and loads none (systemctl(1), list-units). A brand-new account's slice is
// usually not loaded, so its create skips the slow reload; an active slice,
// or a deleted account's slice that a reused UID finds still loaded, gets
// it.
func (n *linuxSystem) sliceLoaded(ctx context.Context, uid int) (bool, error) {
	if e := n.limitsUID(uid); e != nil {
		return false, e
	}
	name := "user-" + strconv.Itoa(uid) + ".slice"
	out, e := n.command(ctx, systemctl, "list-units", "--all", "--plain", "--no-legend", "--full", "--", name)
	if e != nil {
		return false, e
	}
	return sliceListed(out, name), nil
}

// sliceListed reads list-units' output: one unit per line, its name first
// (after a status bullet, if one is printed despite --plain).
func sliceListed(out []byte, name string) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) > 0 && (f[0] == name || len(f) > 1 && f[1] == name) {
			return true
		}
	}
	return false
}

// reloadIfLoaded reloads systemd unless the account's slice is certainly
// not loaded; when list-units fails, it reloads.
func (n *linuxSystem) reloadIfLoaded(ctx context.Context, uid int) error {
	if loaded, e := n.sliceLoaded(ctx, uid); e == nil && !loaded {
		return nil
	}
	return n.reloadSystemd(ctx)
}

func (n *linuxSystem) ApplyLimits(ctx context.Context, uid int, l AccountLimits) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if e := n.limitsUID(uid); e != nil {
		return e
	}
	units, e := n.openUnitDir()
	if e != nil {
		return e
	}
	defer units.Close()
	if _, e := n.writeLimits(units, uid, l); e != nil {
		return e
	}
	// A loaded slice is reloaded even when the file was already right: an
	// earlier write whose reload failed left it unloaded. A slice systemd
	// has not loaded reads the file when it is first referenced.
	return n.reloadIfLoaded(ctx, uid)
}

func (n *linuxSystem) VerifyLimits(uid int, l AccountLimits) error {
	if e := n.limitsUID(uid); e != nil {
		return e
	}
	want, e := renderSliceLimits(l)
	if e != nil {
		return e
	}
	units, e := n.openUnitDir()
	if e != nil {
		return e
	}
	defer units.Close()
	dir, e := openSliceDir(units, uid, false)
	if e != nil {
		return ErrRecovery
	}
	defer dir.Close()
	got, meta, found, e := readAt(dir, limitsDropIn)
	if e != nil || !found || !bytes.Equal(got, want) || meta != (fileMeta{0, 0, limitsFileMode}) {
		return ErrRecovery
	}
	return nil
}

func (n *linuxSystem) RemoveLimits(ctx context.Context, uid int) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if e := n.limitsUID(uid); e != nil {
		return e
	}
	units, e := n.openUnitDir()
	if e != nil {
		return e
	}
	defer units.Close()
	removed, e := removeLimitsFile(units, uid)
	if e != nil {
		return e
	}
	if !removed {
		return nil
	}
	return n.reloadSystemd(ctx)
}

func (n *linuxSystem) SyncLimits(ctx context.Context, want map[int]AccountLimits) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	units, e := n.openUnitDir()
	if e != nil {
		return e
	}
	defer units.Close()
	changed := false
	var first error
	note := func(c bool, e error) {
		changed = changed || c
		if first == nil {
			first = e
		}
	}
	for uid, l := range want {
		note(n.writeLimits(units, uid, l))
	}
	// A drop-in of an account-range UID that no account holds is a delete's
	// leftover: only the broker writes 50-sifruno-limits.conf there.
	names, e := units.Readdirnames(-1)
	if e != nil && !errors.Is(e, io.EOF) {
		note(false, ErrUnavailable)
	}
	for _, name := range names {
		rest, ok := strings.CutPrefix(name, "user-")
		if !ok {
			continue
		}
		digits, ok := strings.CutSuffix(rest, ".slice.d")
		if !ok {
			continue
		}
		uid, e := strconv.Atoi(digits)
		if e != nil || strconv.Itoa(uid) != digits || !validLimitUID(uid) {
			continue
		}
		if _, held := want[uid]; held {
			continue
		}
		note(removeLimitsFile(units, uid))
	}
	if changed {
		note(false, n.reloadSystemd(ctx))
	}
	return first
}
