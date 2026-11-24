//go:build linux

package hostaccounts

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// backupCommand is one fixed program a backup operation runs, directly,
// with an absolute path and no shell.
type backupCommand struct {
	path  string
	args  []string
	env   []string
	dir   string
	stdin io.Reader
	// stdout, when set, takes the program's output; otherwise stdout and
	// stderr together are kept as a 64 KiB tail.
	stdout io.Writer
	// uid and gid 0 run the program as root (the broker); otherwise it runs
	// as that site user, with no supplementary groups.
	uid, gid int
	limit    time.Duration
}

// resticEngine is the Linux backupEngine.
type resticEngine struct {
	// dir is <state>/backup, root 0700: the SSH key, the password, the
	// known_hosts file, restic's cache and the database dumps.
	dir string
	// stage holds each restore's and drill's staging folder.
	stage string
	run   func(context.Context, backupCommand) ([]byte, int, error)
	tools func() error
	// prepare makes dir, its subfolders and stage; owner is who their
	// files must belong to (root). chown sets an owner. They are fields so
	// a test that is not root can run the engine on scratch folders.
	prepare func() error
	owner   int
	chown   func(f *os.File, uid, gid int) error
	// space reads the free and total bytes and the block size of the
	// filesystem holding a folder.
	space func(dir string) (avail, total, block uint64, err error)
}

func newResticEngine(stateDir string) *resticEngine {
	e := &resticEngine{dir: stateDir + "/backup", stage: restoreRoot, run: runBackupCommand, tools: checkBackupTools, owner: 0,
		chown: func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }, space: diskSpace}
	e.prepare = e.prepareDirs
	return e
}

// diskSpace is statfs: the bytes an unprivileged writer may still use, so
// root's reserve on ext4 is not counted as free.
func diskSpace(dir string) (avail, total, block uint64, err error) {
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) != nil || st.Bsize <= 0 {
		return 0, 0, 0, ErrUnavailable
	}
	unit := uint64(st.Bsize)
	if st.Frsize > 0 {
		unit = uint64(st.Frsize)
	}
	return st.Bavail * unit, st.Blocks * unit, unit, nil
}

// room is how much may still be written to dir's filesystem before its
// margin is reached.
func (e *resticEngine) room(dir string) (uint64, uint64, error) {
	avail, total, _, err := e.space(dir)
	if err != nil {
		return 0, 0, ErrUnavailable
	}
	return roomLeft(avail, total), freeMargin(total), nil
}

// fitsStage refuses a restore or drill of the snapshot that would not leave
// the margin free where it is staged. restic's restore size counts each
// file at its full length, so a tenant's sparse file counts whole although
// --sparse writes only its data: such a site may be refused a restore it
// would have fitted, but the server's disk never fills.
func (e *resticEngine) fitsStage(ctx context.Context, t BackupTarget, snapshot string) error {
	stdout := &boundedBuffer{max: 64 << 10}
	out, code, err := e.restic(ctx, t, "known_hosts", backupTimeout, stdout, restoreSizeArgs(snapshot)...)
	if err != nil || code != 0 {
		return backupFailed("restore", append(stdout.b, out...))
	}
	size, entries, ok := parseRestoreSize(stdout.b)
	if !ok {
		return &BackupError{Step: "restore", Detail: "restic's size of the backup could not be read"}
	}
	avail, total, block, err := e.space(e.stage)
	if err != nil {
		return ErrUnavailable
	}
	return spaceForRestore(restoreNeed(size, entries, block), avail, total)
}

// cappedWriter passes at most max bytes on and fails the write that would
// go past them. The program writing into it then gets a broken pipe and
// stops, so a dump never grows past its cap.
type cappedWriter struct {
	w      io.Writer
	n, max uint64
	over   bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.n+uint64(len(p)) > c.max {
		c.over = true
		return 0, ErrUnavailable
	}
	n, err := c.w.Write(p)
	c.n += uint64(n)
	return n, err
}

// runBackupCommand runs one fixed program, as root or as a site user. Go's
// exec drops to the site user before it changes directory, and the whole
// process group is killed when the time limit ends.
func runBackupCommand(ctx context.Context, c backupCommand) ([]byte, int, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(c.path) || c.uid < 0 || c.gid < 0 || (c.uid == 0) != (c.gid == 0) || c.limit <= 0 {
		return nil, -1, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, c.limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.path, c.args...)
	cmd.Dir = c.dir
	cmd.Env = c.env
	attr := &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if c.uid != 0 {
		attr.Credential = &syscall.Credential{Uid: uint32(c.uid), Gid: uint32(c.gid), Groups: []uint32{}}
	}
	cmd.SysProcAttr = attr
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	cmd.Stdin = c.stdin
	out := &tailBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if c.stdout != nil {
		cmd.Stdout = c.stdout
	}
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

// checkRestic accepts restic only as a regular root-owned executable whose
// bytes match the pinned release.
func checkRestic() error {
	info, e := trustedFile(resticPath, false)
	if e != nil || info.Mode().Perm()&0100 == 0 || info.Size() > maxRestic {
		return ErrUnavailable
	}
	fd, e := unix.Open(resticPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), resticPath)
	defer f.Close()
	held, e := f.Stat()
	if e != nil || !os.SameFile(info, held) {
		return ErrUnavailable
	}
	return pinnedSHA256(f, maxRestic, resticSHA256)
}

// pinnedSHA256 reads at most max bytes and compares their sha256.
func pinnedSHA256(r io.Reader, max int64, want string) error {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r, max+1))
	if e != nil || n > max || hex.EncodeToString(h.Sum(nil)) != want {
		return ErrUnavailable
	}
	return nil
}

// checkBackupTools checks restic's pin and that ssh, the MariaDB client and
// dump tool and cp are root-owned regular executables.
func checkBackupTools() error {
	if checkRestic() != nil {
		return ErrUnavailable
	}
	for _, p := range []string{sshPath, mariadbPath, mariadbDumpPath, cpPath} {
		if info, e := trustedFile(p, false); e != nil || info.Mode().Perm()&0001 == 0 {
			return ErrUnavailable
		}
	}
	return nil
}

// prepareDirs makes the broker's backup folder (0700) and its cache, tmp
// and dump folders in the broker's state, and the restore root (0711) in
// /var/lib, with mkdirat under root-owned parents. Existing ones must be
// root's with exactly that mode.
func (e *resticEngine) prepareDirs() error {
	if authority(filepath.Dir(e.dir)) != nil || authority(filepath.Dir(e.stage)) != nil {
		return ErrUnavailable
	}
	if ensureOwnDir(filepath.Dir(e.dir), filepath.Base(e.dir), 0700) != nil {
		return ErrUnavailable
	}
	for _, sub := range []string{"cache", "tmp", "dump"} {
		if ensureOwnDir(e.dir, sub, 0700) != nil {
			return ErrUnavailable
		}
	}
	return ensureOwnDir(filepath.Dir(e.stage), filepath.Base(e.stage), 0711)
}

func ensureOwnDir(parentPath, name string, mode os.FileMode) error {
	parent, e := openRootDir(parentPath)
	if e != nil {
		return ErrUnavailable
	}
	defer parent.Close()
	created := false
	if e := unix.Mkdirat(int(parent.Fd()), name, uint32(mode)); e == nil {
		created = true
	} else if !errors.Is(e, unix.EEXIST) {
		return ErrUnavailable
	}
	d, e := openDirectoryAt(int(parent.Fd()), name)
	if e != nil {
		return ErrUnavailable
	}
	defer d.Close()
	if created && (unix.Fchown(int(d.Fd()), 0, 0) != nil || unix.Fchmod(int(d.Fd()), uint32(mode)) != nil) {
		return ErrUnavailable
	}
	owner, group, perm, e := ownerOfHandle(d)
	if e != nil || owner != 0 || group != 0 || perm != mode {
		return ErrUnavailable
	}
	return nil
}

// writePrivate creates dir/name, never through a link, with this owner and
// mode, or replaces it by rename.
func (e *resticEngine) writePrivate(dir *os.File, name string, data []byte, uid, gid int, mode os.FileMode) error {
	tmp := name + ".sifruno-new"
	_ = unix.Unlinkat(int(dir.Fd()), tmp, 0)
	fd, err := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = e.chown(f, uid, gid)
	}
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name)
	}
	if err != nil {
		_ = unix.Unlinkat(int(dir.Fd()), tmp, 0)
		return ErrUnavailable
	}
	return nil
}

// readPrivate reads dir/name only as a regular file of the engine's owner
// with mode 0600; found is false when it does not exist.
func (e *resticEngine) readPrivate(dir *os.File, name string) ([]byte, bool, error) {
	b, meta, found, err := readAt(dir, name)
	if err != nil || found && (meta.uid != e.owner || meta.mode != 0600) {
		return nil, false, ErrUnavailable
	}
	return b, found, nil
}

const backupKeyComment = "sifruno-backup"

// publicKey makes the broker's ed25519 key pair the first time and returns
// the public half as an authorized_keys line.
func (e *resticEngine) publicKey(dir *os.File) (string, error) {
	raw, found, err := e.readPrivate(dir, "ssh_key")
	if err != nil {
		return "", err
	}
	if !found {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", ErrUnavailable
		}
		block, err := ssh.MarshalPrivateKey(private, backupKeyComment)
		if err != nil {
			return "", ErrUnavailable
		}
		if e.writePrivate(dir, "ssh_key", pem.EncodeToMemory(block), e.owner, e.owner, 0600) != nil {
			return "", ErrUnavailable
		}
		if raw, found, err = e.readPrivate(dir, "ssh_key"); err != nil || !found {
			return "", ErrUnavailable
		}
	}
	key, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return "", ErrUnavailable
	}
	var public ssh.PublicKey
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		public, err = ssh.NewPublicKey(k.Public())
	case ed25519.PrivateKey:
		public, err = ssh.NewPublicKey(k.Public())
	default:
		return "", ErrUnavailable
	}
	if err != nil {
		return "", ErrUnavailable
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " " + backupKeyComment, nil
}

var repositoryPasswordPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// password reads the repository password, making it the first time when
// create is set: 32 random bytes, base64url.
func (e *resticEngine) password(dir *os.File, create bool) (string, error) {
	raw, found, err := e.readPrivate(dir, "password")
	if err != nil {
		return "", err
	}
	if !found {
		if !create {
			return "", ErrUnavailable
		}
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", ErrUnavailable
		}
		if e.writePrivate(dir, "password", []byte(base64.RawURLEncoding.EncodeToString(b[:])), e.owner, e.owner, 0600) != nil {
			return "", ErrUnavailable
		}
		if raw, found, err = e.readPrivate(dir, "password"); err != nil || !found {
			return "", ErrUnavailable
		}
	}
	if !repositoryPasswordPattern.Match(raw) {
		return "", ErrUnavailable
	}
	return string(raw), nil
}

func (e *resticEngine) openDir() (*os.File, error) {
	if e.prepare() != nil {
		return nil, ErrUnavailable
	}
	return openRootDir(e.dir)
}

func (e *resticEngine) Status(ctx context.Context) (string, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", false, ErrUnavailable
	}
	dir, err := e.openDir()
	if err != nil {
		return "", false, err
	}
	defer dir.Close()
	key, err := e.publicKey(dir)
	if err != nil {
		return "", false, err
	}
	if _, err = e.password(dir, true); err != nil {
		return "", false, err
	}
	return key, e.tools() == nil, nil
}

func (e *resticEngine) Password() (string, error) {
	dir, err := e.openDir()
	if err != nil {
		return "", err
	}
	defer dir.Close()
	return e.password(dir, false)
}

// restic runs restic as root against the target. The password reaches it
// as a root-only file named in its environment, never as an argument.
func (e *resticEngine) restic(ctx context.Context, t BackupTarget, knownHosts string, limit time.Duration, stdout io.Writer, args ...string) ([]byte, int, error) {
	if !resticSafeArgumentSet.MatchString(e.dir) {
		return nil, -1, ErrUnavailable
	}
	global, ok := resticGlobal(e.dir, knownHosts, t)
	if !ok || e.tools() != nil {
		return nil, -1, ErrUnavailable
	}
	return e.run(ctx, backupCommand{path: resticPath, args: append(global, args...), env: resticEnv(e.dir), dir: e.dir, stdout: stdout, limit: limit})
}

// rootSQL runs SQL from stdin as root over the MariaDB socket.
func (e *resticEngine) rootSQL(ctx context.Context, sql string) ([]byte, int, error) {
	return e.run(ctx, backupCommand{path: mariadbPath, args: rootSQLArgs(), env: []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + e.dir}, dir: e.dir, stdin: strings.NewReader(sql), limit: time.Minute})
}

func siteEnv(r record) []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + r.Account.Home, "USER=" + r.Account.Username, "LOGNAME=" + r.Account.Username}
}

func (e *resticEngine) SetTarget(ctx context.Context, t BackupTarget) (bool, error) {
	dir, err := e.openDir()
	if err != nil {
		return false, err
	}
	defer dir.Close()
	const next = "known_hosts.next"
	if e.writePrivate(dir, next, knownHostsFile(t), e.owner, e.owner, 0600) != nil {
		return false, ErrUnavailable
	}
	defer unix.Unlinkat(int(dir.Fd()), next, 0)
	initialized := false
	out, code, err := e.restic(ctx, t, next, backupTargetTimeout, nil, "cat", "config")
	switch {
	case err == nil && code == 0:
	case err == nil && code == 12:
		return false, &BackupError{Step: "password", Detail: "The storage path already holds a backup repository that this server's password does not open."}
	default:
		// Most often there is no repository yet (restic says 10); any other
		// failure, such as a refused key, fails the init the same way.
		initOut, initCode, initErr := e.restic(ctx, t, next, backupTargetTimeout, nil, "init")
		if initErr != nil || initCode != 0 {
			if code == 10 {
				out = initOut
			}
			return false, backupFailed("connect", out)
		}
		initialized = true
	}
	if unix.Renameat(int(dir.Fd()), next, int(dir.Fd()), "known_hosts") != nil {
		return false, ErrUnavailable
	}
	_ = dir.Sync()
	return initialized, nil
}

// boundedBuffer keeps a whole output up to max bytes and fails the write
// past it, which stops the program's output copy.
type boundedBuffer struct {
	b   []byte
	max int
}

func (w *boundedBuffer) Write(p []byte) (int, error) {
	if len(w.b)+len(p) > w.max {
		return 0, ErrUnavailable
	}
	w.b = append(w.b, p...)
	return len(p), nil
}

// freshDumps empties the account's dump folder and opens it.
func (e *resticEngine) freshDumps(dir *os.File, id string) (*os.File, error) {
	dumps, err := openDirectoryAt(int(dir.Fd()), "dump")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer dumps.Close()
	if os.RemoveAll(dumpDir(e.dir, id)) != nil {
		return nil, ErrUnavailable
	}
	if unix.Mkdirat(int(dumps.Fd()), id, 0700) != nil {
		return nil, ErrUnavailable
	}
	d, err := openDirectoryAt(int(dumps.Fd()), id)
	if err != nil || e.chown(d, e.owner, e.owner) != nil || d.Chmod(0700) != nil {
		if d != nil {
			d.Close()
		}
		return nil, ErrUnavailable
	}
	return d, nil
}

func (e *resticEngine) Backup(ctx context.Context, t BackupTarget, r record, dbs []string) (Snapshot, error) {
	dir, err := e.openDir()
	if err != nil {
		return Snapshot{}, err
	}
	defer dir.Close()
	if e.tools() != nil {
		return Snapshot{}, ErrUnavailable
	}
	for _, db := range dbs {
		out, code, err := e.rootSQL(ctx, dbObjectsSQL(db))
		if err != nil || code != 0 {
			return Snapshot{}, backupFailed("database", out)
		}
		if kinds := strings.Fields(string(out)); len(kinds) > 0 {
			if kinds[0] == "missing" {
				return Snapshot{}, &BackupError{Step: "database", Detail: "The database " + db + " does not exist."}
			}
			return Snapshot{}, &BackupError{Step: "database", Detail: "The database " + db + " has views, triggers, stored routines or events (" + strings.Join(uniqueWords(kinds), ", ") + "). Backups cover tables and their rows only, so this database cannot be backed up yet."}
		}
	}
	dumps, err := e.freshDumps(dir, r.Account.ID)
	if err != nil {
		return Snapshot{}, err
	}
	defer dumps.Close()
	// The dumps are plain copies of the databases: they are removed once
	// restic has them.
	defer os.RemoveAll(dumpDir(e.dir, r.Account.ID))
	for _, db := range dbs {
		// Each dump may use what is free beyond the margin, measured after
		// the dumps before it, and at most maxDumpBytes.
		room, margin, err := e.room(dumpDir(e.dir, r.Account.ID))
		if err != nil {
			return Snapshot{}, err
		}
		if room == 0 {
			return Snapshot{}, &BackupError{Step: "space", Detail: "The server has less than " + byteSize(margin) + " of disk free, which must stay free for the server itself, so the database " + db + " was not dumped. Free up disk space on the server, then try again."}
		}
		limit := min(room, maxDumpBytes)
		fd, err := unix.Openat(int(dumps.Fd()), db+".sql", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return Snapshot{}, ErrUnavailable
		}
		f := os.NewFile(uintptr(fd), db+".sql")
		capped := &cappedWriter{w: f, max: limit}
		out, code, err := e.run(ctx, backupCommand{path: mariadbDumpPath, args: dumpArgs(db), env: []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + e.dir}, dir: e.dir, stdout: capped, limit: backupTimeout})
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		switch {
		case capped.over && limit == maxDumpBytes:
			return Snapshot{}, &BackupError{Step: "dump", Detail: "The dump of the database " + db + " grew past " + byteSize(maxDumpBytes) + ", the most a backup takes of one database, so it was stopped and nothing was backed up."}
		case capped.over:
			return Snapshot{}, &BackupError{Step: "space", Detail: "The dump of the database " + db + " would have left less than " + byteSize(margin) + " of disk free on the server, so it was stopped and nothing was backed up. Free up disk space on the server, then try again."}
		case err != nil || code != 0:
			return Snapshot{}, backupFailed("dump", out)
		}
	}
	// restic keeps its cache and the packs it is about to upload in the
	// broker's folder too: it starts only with room beyond the margin.
	if room, margin, err := e.room(e.dir); err != nil {
		return Snapshot{}, err
	} else if room == 0 {
		return Snapshot{}, &BackupError{Step: "space", Detail: "The server has less than " + byteSize(margin) + " of disk free, which must stay free for the server itself, so nothing was backed up. Free up disk space on the server, then try again."}
	}
	out, code, err := e.restic(ctx, t, "known_hosts", backupTimeout, nil, backupArgs(r.Account.Home, dumpDir(e.dir, r.Account.ID), r.Account.ID, dbs)...)
	if err != nil || code != 0 {
		return Snapshot{}, backupFailed("backup", out)
	}
	summary, ok := parseBackupSummary(out)
	if !ok {
		return Snapshot{}, backupFailed("backup", out)
	}
	return Snapshot{ID: summary.SnapshotID, Time: summary.BackupStart.UTC(), Bytes: summary.TotalBytes, Files: summary.TotalFiles, Databases: dbs}, nil
}

func uniqueWords(words []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, w := range words {
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	sort.Strings(out)
	return out
}

func (e *resticEngine) Snapshots(ctx context.Context, t BackupTarget, r record) ([]Snapshot, error) {
	if e.prepare() != nil {
		return nil, ErrUnavailable
	}
	stdout := &boundedBuffer{max: 4 << 20}
	out, code, err := e.restic(ctx, t, "known_hosts", backupListTimeout, stdout, snapshotsArgs(r.Account.ID)...)
	if err != nil || code != 0 {
		return nil, backupFailed("snapshot", out)
	}
	return parseSnapshots(stdout.b, r.Account.ID, r.Account.Home, dumpDir(e.dir, r.Account.ID))
}

// newStage makes the operation's staging folder, root-only 0700.
func (e *resticEngine) newStage(op string) (*os.File, error) {
	root, err := openRootDir(e.stage)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer root.Close()
	if unix.Mkdirat(int(root.Fd()), op, 0700) != nil {
		return nil, ErrUnavailable
	}
	d, err := openDirectoryAt(int(root.Fd()), op)
	if err != nil {
		return nil, ErrUnavailable
	}
	if e.chown(d, e.owner, e.owner) != nil || d.Chmod(0700) != nil {
		d.Close()
		return nil, ErrUnavailable
	}
	return d, nil
}

// snapshotFor finds the account's own snapshot by its full ID.
func (e *resticEngine) snapshotFor(ctx context.Context, t BackupTarget, r record, id string) (Snapshot, error) {
	items, err := e.Snapshots(ctx, t, r)
	if err != nil {
		return Snapshot{}, err
	}
	for _, s := range items {
		if s.ID == id {
			return s, nil
		}
	}
	return Snapshot{}, &BackupError{Step: "snapshot", Detail: "That backup is not one of this site's backups."}
}

// Restore restores into a fresh root-owned staging folder outside every
// home. Root writes nothing the tenant controls: the folder is then opened
// to the site's group only, and the copy into the home and each database
// import run as the site user, so a tenant's own files can harm only that
// tenant. Each database is loaded by a temporary MariaDB user granted only
// on it, dropped afterwards even when the load fails.
func (e *resticEngine) Restore(ctx context.Context, t BackupTarget, r record, in RestoreInput, l backupLeftover) error {
	if e.prepare() != nil || e.tools() != nil || r.Account.UID <= 0 || r.Account.GID <= 0 {
		return ErrUnavailable
	}
	snap, err := e.snapshotFor(ctx, t, r, in.Snapshot)
	if err != nil {
		return err
	}
	for _, db := range in.Databases {
		if l.Users[db] == "" {
			return ErrUnavailable
		}
		if !contains(snap.Databases, db) {
			return &BackupError{Step: "snapshot", Detail: "That backup has no copy of the database " + db + "."}
		}
		// The database must still exist: the broker never makes one.
		out, code, err := e.rootSQL(ctx, databaseExistsSQL(db))
		if err != nil || code != 0 {
			return backupFailed("database", out)
		}
		if strings.TrimSpace(string(out)) != "1" {
			return &BackupError{Step: "database", Detail: "The database " + db + " does not exist on this server, so it cannot be restored into. Create it again for this site with the same name, then restore it."}
		}
	}
	if err := e.fitsStage(ctx, t, in.Snapshot); err != nil {
		return err
	}
	stage, err := e.newStage(l.Op)
	if err != nil {
		return err
	}
	defer stage.Close()
	stagePath := filepath.Join(e.stage, l.Op)
	if in.Files {
		out, code, err := e.restic(ctx, t, "known_hosts", backupTimeout, nil, restoreArgs(in.Snapshot+":"+r.Account.Home, stagePath+"/files", false)...)
		if err != nil || code != 0 {
			return backupFailed("restore", out)
		}
	}
	if len(in.Databases) > 0 {
		out, code, err := e.restic(ctx, t, "known_hosts", backupTimeout, nil, restoreArgs(in.Snapshot+":"+dumpDir(e.dir, r.Account.ID), stagePath+"/db", false)...)
		if err != nil || code != 0 {
			return backupFailed("restore", out)
		}
	}
	if in.Files {
		files, err := openDirectoryAt(int(stage.Fd()), "files")
		if err != nil {
			return ErrUnavailable
		}
		// The copy gives the home the staged folder's mode, so it gets the
		// owner and mode the broker requires of a home.
		err = e.chown(files, r.Account.UID, r.Account.GID)
		if err == nil {
			err = files.Chmod(0750)
		}
		files.Close()
		if err != nil {
			return ErrUnavailable
		}
	}
	// Only the site's private group may enter the staging folder now.
	if e.chown(stage, e.owner, r.Account.GID) != nil || stage.Chmod(0750) != nil {
		return ErrUnavailable
	}
	if in.Files {
		out, code, err := e.run(ctx, backupCommand{path: cpPath, args: copyArgs(stagePath+"/files", r.Account.Home), env: siteEnv(r), dir: r.Account.Home, uid: r.Account.UID, gid: r.Account.GID, limit: backupTimeout})
		if err != nil || code != 0 {
			return backupFailed("copy", out)
		}
	}
	for _, db := range in.Databases {
		if err := e.importDatabase(ctx, r, stage, stagePath, db, l.Users[db]); err != nil {
			return err
		}
	}
	return nil
}

func contains(items []string, item string) bool {
	for _, x := range items {
		if x == item {
			return true
		}
	}
	return false
}

// importDatabase loads one database's dump as the site user, through a
// temporary MariaDB user that exists only while it runs.
func (e *resticEngine) importDatabase(ctx context.Context, r record, stage *os.File, stagePath, db, user string) error {
	dumps, err := openDirectoryAt(int(stage.Fd()), "db")
	if err != nil {
		return &BackupError{Step: "snapshot", Detail: "That backup has no copy of the database " + db + "."}
	}
	defer dumps.Close()
	fd, err := unix.Openat(int(dumps.Fd()), db+".sql", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &BackupError{Step: "snapshot", Detail: "That backup has no copy of the database " + db + "."}
	}
	dump := os.NewFile(uintptr(fd), db+".sql")
	defer dump.Close()
	if info, err := dump.Stat(); err != nil || !info.Mode().IsRegular() {
		return ErrUnavailable
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ErrUnavailable
	}
	password := hex.EncodeToString(b[:])
	if !restoreUserPattern.MatchString(user) || !restoreSecretPattern.MatchString(password) {
		return ErrUnavailable
	}
	// The option file is the site group's to read (0440) inside the
	// staging folder only that group may enter; it is gone after the load.
	cnf := "client-" + db + ".cnf"
	if e.writePrivate(stage, cnf, restoreClientConfig(user, password), e.owner, r.Account.GID, 0440) != nil {
		return ErrUnavailable
	}
	defer unix.Unlinkat(int(stage.Fd()), cnf, 0)
	// The drop is deferred before the create runs, so a create that made
	// the user and then failed to grant still drops it.
	defer e.dropRestoreUser(user)
	out, code, err := e.rootSQL(ctx, createRestoreUserSQL(db, user, password))
	if err != nil || code != 0 {
		return backupFailed("import", out, password)
	}
	out, code, err = e.run(ctx, backupCommand{path: mariadbPath, args: importArgs(stagePath+"/"+cnf, db), env: siteEnv(r), dir: r.Account.Home, stdin: dump, uid: r.Account.UID, gid: r.Account.GID, limit: backupTimeout})
	if err != nil || code != 0 {
		return backupFailed("import", out, password)
	}
	return nil
}

// dropRestoreUser runs on its own short limit, so a restore that ran out of
// time still drops its user. If this fails too, the store's leftover list
// drops it before the next backup operation.
func (e *resticEngine) dropRestoreUser(user string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, code, err := e.rootSQL(ctx, dropRestoreUserSQL(user))
	if err != nil || code != 0 {
		return ErrUnavailable
	}
	return nil
}

// SweepDumps removes every account's dump folder under the broker's own
// state (root 0700, which no tenant can reach). Each backup makes its folder
// and removes it when it ends, so at start, before any backup runs, whatever
// is there was left by a broker stopped mid-dump. RemoveAll does not follow
// links.
func (e *resticEngine) SweepDumps() error {
	root := filepath.Join(e.dir, "dump")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrUnavailable
	}
	failed := false
	for _, entry := range entries {
		if os.RemoveAll(filepath.Join(root, entry.Name())) != nil {
			failed = true
		}
	}
	if failed {
		return ErrUnavailable
	}
	return nil
}

func (e *resticEngine) Cleanup(ctx context.Context, l backupLeftover) error {
	if !l.valid() {
		return ErrUnavailable
	}
	failed := false
	users := make([]string, 0, len(l.Users))
	for _, user := range l.Users {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		if _, code, err := e.rootSQL(ctx, dropRestoreUserSQL(user)); err != nil || code != 0 {
			failed = true
		}
	}
	// RemoveAll removes relative to each opened folder and never follows a
	// link, so what the site user changed under its staged home cannot send
	// it elsewhere.
	if err := os.RemoveAll(filepath.Join(e.stage, l.Op)); err != nil {
		failed = true
	}
	if failed {
		return ErrUnavailable
	}
	return nil
}

func (e *resticEngine) Drill(ctx context.Context, t BackupTarget, r record, l backupLeftover, now time.Time) (DrillResult, error) {
	if e.prepare() != nil || e.tools() != nil {
		return DrillResult{}, ErrUnavailable
	}
	items, err := e.Snapshots(ctx, t, r)
	if err != nil {
		return DrillResult{}, err
	}
	if len(items) == 0 {
		return DrillResult{}, &BackupError{Step: "snapshot", Detail: "This site has no backup yet."}
	}
	latest := items[0]
	if err := e.fitsStage(ctx, t, latest.ID); err != nil {
		return DrillResult{}, err
	}
	stage, err := e.newStage(l.Op)
	if err != nil {
		return DrillResult{}, err
	}
	defer stage.Close()
	stagePath := filepath.Join(e.stage, l.Op)
	// The drill's folder stays root-only: nothing runs as the site user.
	out, code, err := e.restic(ctx, t, "known_hosts", backupTimeout, nil, restoreArgs(latest.ID, stagePath+"/all", true)...)
	if err != nil || code != 0 {
		return DrillResult{}, backupFailed("restore", out)
	}
	fd, err := unix.Openat(int(stage.Fd()), "ls.json", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return DrillResult{}, ErrUnavailable
	}
	list := os.NewFile(uintptr(fd), "ls.json")
	defer list.Close()
	out, code, err = e.restic(ctx, t, "known_hosts", backupTimeout, list, "ls", "--json", latest.ID)
	if err != nil || code != 0 {
		return DrillResult{}, backupFailed("compare", out)
	}
	if _, err := list.Seek(0, io.SeekStart); err != nil {
		return DrillResult{}, ErrUnavailable
	}
	files, problem := compareRestored(stagePath+"/all", list)
	if problem != "" {
		return DrillResult{}, &BackupError{Step: "compare", Detail: backupDetail([]byte(problem))}
	}
	subset := drillSubset(now)
	out, code, err = e.restic(ctx, t, "known_hosts", backupTimeout, nil, "check", "--read-data-subset="+subset)
	if err != nil || code != 0 {
		return DrillResult{}, backupFailed("check", out)
	}
	return DrillResult{AccountID: r.Account.ID, Snapshot: latest.ID, SnapshotTime: latest.Time, CheckedAt: now, Passed: true, Files: files, Subset: subset}, nil
}

// compareRestored checks every file, folder and link restic lists for the
// snapshot against what the restore wrote under root: the same kind, the
// same size for a file, the same target for a link. It returns how many it
// compared, or the first difference.
func compareRestored(root string, list io.Reader) (uint64, string) {
	scan := bufio.NewScanner(list)
	scan.Buffer(make([]byte, 64<<10), 1<<20)
	var n uint64
	for scan.Scan() {
		var node lsNode
		if json.Unmarshal(scan.Bytes(), &node) != nil {
			return n, "restic's file list could not be read"
		}
		if node.MessageType != "node" {
			continue
		}
		if !strings.HasPrefix(node.Path, "/") || path.Clean(node.Path) != node.Path {
			return n, "restic listed an unexpected path"
		}
		if node.Type != "file" && node.Type != "dir" && node.Type != "symlink" {
			continue
		}
		info, err := os.Lstat(root + node.Path)
		if err != nil {
			return n, node.Path + " was not restored"
		}
		switch node.Type {
		case "file":
			if !info.Mode().IsRegular() || uint64(info.Size()) != node.Size {
				return n, node.Path + " was restored with a different size"
			}
		case "dir":
			if !info.IsDir() {
				return n, node.Path + " was not restored as a folder"
			}
		case "symlink":
			target, err := os.Readlink(root + node.Path)
			if info.Mode()&os.ModeSymlink == 0 || err != nil || node.LinkTarget != "" && target != node.LinkTarget {
				return n, node.Path + " was not restored as the same link"
			}
		}
		n++
	}
	if scan.Err() != nil {
		return n, "restic's file list could not be read"
	}
	if n == 0 {
		return n, "restic listed nothing to compare"
	}
	return n, ""
}

func (e *resticEngine) Prune(ctx context.Context, t BackupTarget) (PruneResult, error) {
	if e.prepare() != nil || e.tools() != nil {
		return PruneResult{}, ErrUnavailable
	}
	// unlock removes only locks whose process is gone, such as one left by
	// a broker that stopped mid-run.
	_, _, _ = e.restic(ctx, t, "known_hosts", backupListTimeout, nil, "unlock")
	stdout := &boundedBuffer{max: 16 << 20}
	out, code, err := e.restic(ctx, t, "known_hosts", backupTimeout, stdout, forgetArgs()...)
	if err != nil || code != 0 {
		return PruneResult{}, backupFailed("prune", append(stdout.b, out...))
	}
	return PruneResult{Removed: parsePruneRemoved(stdout.b)}, nil
}
