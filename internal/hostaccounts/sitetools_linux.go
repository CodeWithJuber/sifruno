//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"

	"golang.org/x/sys/unix"
)

// The native side of scheduled jobs, logs and usage. Every path is fixed
// and outside every home: the crontab directory and the log directories are
// root's, so no tenant can put a link where root writes or reads.
//   - crontab: /var/spool/cron/<username>, root-owned 0600, written beside
//     its target with O_EXCL|O_NOFOLLOW and renamed, as cronie's own crontab
//     leaves it when root runs it (crontab.c: the owner is root when the
//     real and effective IDs are root's; mkstemp makes it 0600). crond
//     accepts a regular, single-link file of mode 0600 owned by root or the
//     user (database.c, check_open) and runs its jobs as that user. root
//     never runs a job's command.
//   - logs: olsweb.LogRoot/<site name>/access.log and error.log, which
//     OpenLiteSpeed writes and hands to its own user; read only, through
//     directory handles opened without following links.
//   - disk: `xfs_quota -x -c "report -u -b -n -N -L <uid> -U <uid>"`, a
//     read-only report by numeric UID on the homes filesystem.
//   - traffic counters: <state>/usage/<account id>.json, root 0600, in a
//     0700 directory of the broker's private state.

// cronSpoolDir is cronie's SPOOL_DIR on AlmaLinux 9: ${localstatedir}/spool/cron
// (configure.ac), which the cronie package makes root 0700.
const cronSpoolDir = "/var/spool/cron"

// cronTempName is where SetCron writes before its rename. crond skips a
// name that starts with a dot (database.c, not_a_crontab).
func cronTempName(id string) string { return ".sifruno-new-" + id }

// cronDirectory opens the crontab directory: root's along its whole path,
// and private to root as the package makes it.
func (n *linuxSystem) cronDirectory() (*os.File, error) {
	if authority(n.cronDir) != nil {
		return nil, ErrUnavailable
	}
	d, e := openRootDir(n.cronDir)
	if e != nil {
		return nil, ErrUnavailable
	}
	if uid, _, mode, e := ownerOfHandle(d); e != nil || uid != 0 || mode&0077 != 0 {
		d.Close()
		return nil, ErrUnavailable
	}
	return d, nil
}

// crontabObject checks what is at name before it is replaced or removed:
// nothing, or a regular single-link file owned by root or the account, the
// only kinds crond reads. Anything else is left alone: the broker does not
// guess.
func crontabObject(dir *os.File, name string, uid int) error {
	var st unix.Stat_t
	switch e := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(e, unix.ENOENT):
		return nil
	case e != nil:
		return ErrUnavailable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || (st.Uid != 0 && int(st.Uid) != uid) {
		return ErrRecovery
	}
	return nil
}

func (n *linuxSystem) SetCron(ctx context.Context, r record, content []byte) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if !validUsername(r.Account.Username) || !idPattern.MatchString(r.Account.ID) || r.Account.UID < firstAccountID || r.Account.UID > lastAccountID || len(content) > len(cronFileHeader)+maxCronLines {
		return ErrInvalid
	}
	dir, e := n.cronDirectory()
	if e != nil {
		return e
	}
	defer dir.Close()
	name, temp := r.Account.Username, cronTempName(r.Account.ID)
	if e := crontabObject(dir, name, r.Account.UID); e != nil {
		return e
	}
	if e := crontabObject(dir, temp, r.Account.UID); e != nil {
		return e
	}
	if e := unix.Unlinkat(int(dir.Fd()), temp, 0); e != nil && !errors.Is(e, unix.ENOENT) {
		return ErrUnavailable
	}
	if content == nil {
		if e := unix.Unlinkat(int(dir.Fd()), name, 0); e != nil && !errors.Is(e, unix.ENOENT) {
			return ErrUnavailable
		}
	} else {
		fd, e := unix.Openat(int(dir.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e != nil {
			return ErrUnavailable
		}
		f := os.NewFile(uintptr(fd), temp)
		_, e = f.Write(content)
		if e == nil {
			e = f.Chown(0, 0)
		}
		if e == nil {
			// Chmod after Chown: the mode must not depend on the umask.
			e = f.Chmod(0600)
		}
		if e == nil {
			e = f.Sync()
		}
		if closed := f.Close(); e == nil {
			e = closed
		}
		if e == nil {
			// crond sees the rename through inotify (IN_MOVED_TO, cron.c)
			// and, without it, by the directory's modification time.
			e = unix.Renameat(int(dir.Fd()), temp, int(dir.Fd()), name)
		}
		if e != nil {
			_ = unix.Unlinkat(int(dir.Fd()), temp, 0)
			return ErrUnavailable
		}
	}
	// The rename or unlink is done. It is not read back: the account's own
	// user may rewrite its crontab at any moment with cronie's setuid
	// crontab, and that must not turn a finished write into an unfinished
	// operation. VerifyCron finds such an edit later.
	_ = dir.Sync()
	return nil
}

// VerifyCron also answers ErrConflict when what is at the crontab's name is
// something SetCron would refuse to replace, so a change is refused before
// anything is journaled.
func (n *linuxSystem) VerifyCron(r record, content []byte) error {
	if !validUsername(r.Account.Username) || !idPattern.MatchString(r.Account.ID) {
		return ErrInvalid
	}
	dir, e := n.cronDirectory()
	if e != nil {
		return e
	}
	defer dir.Close()
	for _, name := range []string{r.Account.Username, cronTempName(r.Account.ID)} {
		switch e := crontabObject(dir, name, r.Account.UID); {
		case errors.Is(e, ErrRecovery):
			return ErrConflict
		case e != nil:
			return e
		}
	}
	return verifyCrontab(dir, r.Account.Username, content)
}

// verifyCrontab requires exactly what SetCron writes: no file for no jobs,
// otherwise these bytes, root-owned 0600 with one link.
func verifyCrontab(dir *os.File, name string, content []byte) error {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		if content == nil {
			return nil
		}
		return ErrRecovery
	}
	if e != nil || content == nil {
		if e == nil {
			unix.Close(fd)
		}
		return ErrRecovery
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 {
		return ErrRecovery
	}
	got, e := io.ReadAll(io.LimitReader(f, int64(len(content))+1))
	if e != nil || !bytes.Equal(got, content) {
		return ErrRecovery
	}
	return nil
}

// ---- Logs -------------------------------------------------------------------

var siteNamePattern = regexp.MustCompile(`^u[a-f0-9]{31}$`)

// openSiteLogDir opens logRoot/<site>: root's along the whole path and
// writable by no one else, so the files in it are the web server's. A site
// that never went live has no directory yet: errNoLogs.
func (n *linuxSystem) openSiteLogDir(site string) (*os.File, error) {
	if n.webUID <= 0 {
		return nil, ErrUnavailable
	}
	if !siteNamePattern.MatchString(site) {
		return nil, ErrInvalid
	}
	if authority(n.logRoot) != nil {
		if _, e := os.Lstat(n.logRoot); errors.Is(e, os.ErrNotExist) {
			return nil, errNoLogs
		}
		return nil, ErrUnavailable
	}
	root, e := openRootDir(n.logRoot)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer root.Close()
	fd, e := unix.Openat(int(root.Fd()), site, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, errNoLogs
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	d := os.NewFile(uintptr(fd), site)
	if uid, _, mode, e := ownerOfHandle(d); e != nil || uid != 0 || mode&0022 != 0 {
		d.Close()
		return nil, ErrUnavailable
	}
	return d, nil
}

// logStat admits a log file: regular, one link, owned by root or the web
// server's user, which OpenLiteSpeed hands its logs to (testRolling and
// postRotate in src/log4cxx/logrotate.cpp).
func (n *linuxSystem) logStat(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && (st.Uid == 0 || int(st.Uid) == n.webUID)
}

// openLogAt opens dir/name for reading without following a link or
// blocking on a FIFO; ENOENT comes back as itself.
func (n *linuxSystem) openLogAt(dir *os.File, name string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, st, e
	}
	if e != nil {
		return nil, st, ErrUnavailable
	}
	if unix.Fstat(fd, &st) != nil || !n.logStat(&st) {
		unix.Close(fd)
		return nil, st, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), name), st, nil
}

func (n *linuxSystem) TailLog(ctx context.Context, site, kind string) (LogTail, error) {
	name := logFileNames[kind]
	if ctx == nil || ctx.Err() != nil || name == "" {
		return LogTail{}, ErrInvalid
	}
	missing := LogTail{Kind: kind, Lines: []string{}, Missing: true}
	dir, e := n.openSiteLogDir(site)
	if errors.Is(e, errNoLogs) {
		return missing, nil
	}
	if e != nil {
		return LogTail{}, e
	}
	defer dir.Close()
	f, st, e := n.openLogAt(dir, name)
	if errors.Is(e, unix.ENOENT) {
		return missing, nil
	}
	if e != nil {
		return LogTail{}, e
	}
	defer f.Close()
	lines, truncated, e := readTail(f, st.Size)
	if e != nil {
		return LogTail{}, e
	}
	return LogTail{Kind: kind, Lines: lines, Truncated: truncated, Size: st.Size}, nil
}

// linuxLogDir is a site's log directory for the traffic counter.
type linuxLogDir struct {
	n   *linuxSystem
	dir *os.File
}

func (n *linuxSystem) SiteLogDir(site string) (siteLogDir, error) {
	d, e := n.openSiteLogDir(site)
	if e != nil {
		return nil, e
	}
	return linuxLogDir{n: n, dir: d}, nil
}

func (d linuxLogDir) Close() error { return d.dir.Close() }

// maxLogDirEntries bounds the names read from one log directory.
const maxLogDirEntries = 4 * maxAccessLogs

func (d linuxLogDir) AccessLogs() ([]logFile, error) {
	if _, e := d.dir.Seek(0, io.SeekStart); e != nil {
		return nil, ErrUnavailable
	}
	var files []logFile
	seen := 0
	for {
		names, e := d.dir.Readdirnames(256)
		seen += len(names)
		if seen > maxLogDirEntries {
			return nil, ErrUnavailable
		}
		for _, name := range names {
			if !accessLogName.MatchString(name) {
				continue
			}
			var st unix.Stat_t
			if unix.Fstatat(int(d.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !d.n.logStat(&st) {
				continue
			}
			files = append(files, logFile{Name: name, Dev: uint64(st.Dev), Ino: st.Ino, MTime: st.Mtim.Nano(), Size: st.Size})
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	if len(files) > maxAccessLogs {
		// The newest ones: older copies hold nothing of this month.
		sort.Slice(files, func(i, j int) bool { return files[i].MTime > files[j].MTime })
		files = files[:maxAccessLogs]
	}
	return files, nil
}

func (d linuxLogDir) Open(f logFile) (io.ReadCloser, error) {
	file, st, e := d.n.openLogAt(d.dir, f.Name)
	if e != nil {
		return nil, ErrUnavailable
	}
	if uint64(st.Dev) != f.Dev || st.Ino != f.Ino {
		file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}

// ---- Disk -------------------------------------------------------------------

// quotaReportUIDs is how many account UIDs one report covers, so its output
// stays well within the 64 KiB a command may print (one line is about 62
// bytes).
const quotaReportUIDs = 500

// quotaReportArgs is xfs_quota's argument list for the user quota report
// of UIDs lo to hi on the homes filesystem: expert mode (-x), which report
// needs, blocks only (-b), numeric IDs (-n), no header (-N).
func quotaReportArgs(lo, hi int, homes string) []string {
	return []string{"-x", "-c", fmt.Sprintf("report -u -b -n -N -L %d -U %d", lo, hi), homes}
}

// quotaRanges groups the accounts' UIDs, in order, into reports of at most
// quotaReportUIDs accounts each. Only account UIDs lie in the range the
// broker allocates, so a report holds about one line per account; one that
// prints more than a command may fails, and the usage read with it.
func quotaRanges(uids []int) [][2]int {
	sorted := slices.Clone(uids)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	var ranges [][2]int
	for i := 0; i < len(sorted); i += quotaReportUIDs {
		ranges = append(ranges, [2]int{sorted[i], sorted[min(i+quotaReportUIDs, len(sorted))-1]})
	}
	return ranges
}

func (n *linuxSystem) QuotaUsage(ctx context.Context, uids []int) (map[int]quotaUsage, error) {
	if n.webUID <= 0 {
		return nil, ErrUnavailable
	}
	for _, uid := range uids {
		if uid < firstAccountID || uid > lastAccountID {
			return nil, ErrInvalid
		}
	}
	out := map[int]quotaUsage{}
	for _, r := range quotaRanges(uids) {
		report, e := n.command(ctx, xfsQuota, quotaReportArgs(r[0], r[1], n.opts.HomesDir)...)
		if e != nil {
			return nil, ErrUnavailable
		}
		for id, q := range parseQuotaReport(report) {
			if id >= r[0] && id <= r[1] {
				out[id] = q
			}
		}
	}
	return out, nil
}

// ---- Traffic counters ---------------------------------------------------------

const usageDirName = "usage"

// usageDir opens <state>/usage, making it root 0700 the first time. The
// state directory is the broker's own (GuardState checks it is root 0700).
func (n *linuxSystem) usageDir(create bool) (*os.File, error) {
	state, e := openRootDir(n.opts.StateDir)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer state.Close()
	if create {
		if e := unix.Mkdirat(int(state.Fd()), usageDirName, 0700); e != nil && !errors.Is(e, unix.EEXIST) {
			return nil, ErrUnavailable
		}
	}
	fd, e := unix.Openat(int(state.Fd()), usageDirName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	d := os.NewFile(uintptr(fd), usageDirName)
	if uid, _, mode, e := ownerOfHandle(d); e != nil || uid != os.Geteuid() || mode != 0700 {
		d.Close()
		return nil, ErrUnavailable
	}
	return d, nil
}

func usageFileName(id string) (string, bool) {
	return id + ".json", idPattern.MatchString(id)
}

func (n *linuxSystem) LoadUsageState(id string) ([]byte, error) {
	name, ok := usageFileName(id)
	if !ok {
		return nil, ErrInvalid
	}
	d, e := n.usageDir(false)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer d.Close()
	b, _, ok, e := readAt(d, name)
	if e != nil || !ok {
		return nil, e
	}
	return b, nil
}

func (n *linuxSystem) SaveUsageState(id string, b []byte) error {
	name, ok := usageFileName(id)
	if !ok || len(b) > 4096 {
		return ErrInvalid
	}
	d, e := n.usageDir(true)
	if e != nil {
		return ErrUnavailable
	}
	defer d.Close()
	return writeAt(d, name, b, fileMeta{uid: os.Geteuid(), gid: os.Getegid(), mode: 0600})
}

func (n *linuxSystem) RemoveUsageState(id string) error {
	name, ok := usageFileName(id)
	if !ok {
		return ErrInvalid
	}
	d, e := n.usageDir(false)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	defer d.Close()
	for _, n := range []string{name, name + ".sifruno-new"} {
		if e := unix.Unlinkat(int(d.Fd()), n, 0); e != nil && !errors.Is(e, unix.ENOENT) {
			return ErrUnavailable
		}
	}
	return nil
}
