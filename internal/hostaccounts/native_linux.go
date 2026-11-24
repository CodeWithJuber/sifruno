//go:build linux

package hostaccounts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/olsweb"
)

const nologin = "/usr/sbin/nologin"

// killPath ends an account's processes. It only ever runs as the account's
// own user (see signalAs), never as root.
const killPath = "/usr/bin/kill"

// systemctl reloads systemd after an account's slice limits change
// (limits_linux.go), with or without the web operation. systemd-run starts
// what the broker runs as a site's user in that user's slice
// (wordpress_linux.go); AlmaLinux 9's systemd package ships it as a regular
// root-owned 0755 file.
var fixedUtilities = []string{"/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/sbin/userdel", "/usr/bin/passwd", "/usr/bin/chage", killPath, nologin, systemctl, systemdRun}

type nativeUser struct {
	Username         string
	UID, GID         int
	Home, Shell, Tag string
}
type nativeGroup struct {
	Name    string
	GID     int
	Members string
}

// sshKeysDir is where sshd reads managed accounts' keys. It sits outside
// every home so a tenant cannot add keys or plant a link there, and it is a
// fixed path like the utilities: the installer creates it (root, 0711) and
// points sshd's AuthorizedKeysFile at it. A host without it has no SFTP keys.
const sshKeysDir = "/etc/sifruno/ssh/authorized_keys"

// mailSpoolDir is where useradd leaves a spool for a regular user when the
// host's CREATE_MAIL_SPOOL default is yes. Delete removes that one file.
const mailSpoolDir = "/var/spool/mail"

type linuxSystem struct {
	opts    BrokerOptions
	webUID  int // OpenLiteSpeed's user; 0 while the web operation is off
	tools   map[string]os.FileInfo
	db      os.FileInfo
	sshDir  string
	mailDir string
	// tlsDir is olsweb.TLSRoot, the only path the rendered config names; it
	// is a field so a root-only test can use a scratch directory.
	tlsDir string
	// unitDir is systemdUnitDir, where the accounts' slice drop-ins go; a
	// field so a root-only test can use a scratch directory.
	unitDir string
	// cronDir is cronSpoolDir and logRoot olsweb.LogRoot (sitetools_linux.go),
	// fields for the same reason.
	cronDir string
	logRoot string
	cacheMu sync.Mutex
	cache   *accountDatabase
}

// accountDatabase is one parse of /etc/passwd and /etc/group with the
// lookups identity needs. It is reused only while both files are provably
// the same objects with the same change times, so verifying every account
// costs two stats instead of two full parses per account.
type accountDatabase struct {
	passwd, group fileStamp
	usersByName   map[string][]nativeUser
	usersByUID    map[int][]nativeUser
	groupsByName  map[string][]nativeGroup
	groupsByGID   map[int][]nativeGroup
	memberOfAny   map[string]bool
}
type fileStamp struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
}

func newLinuxSystem(opts BrokerOptions, web *WebOptions) (*linuxSystem, error) {
	tools, e := trustedUtilities()
	if e != nil || supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return nil, ErrUnavailable
	}
	n := &linuxSystem{opts: opts, tools: tools, sshDir: sshKeysDir, mailDir: mailSpoolDir, tlsDir: olsweb.TLSRoot, unitDir: systemdUnitDir, cronDir: cronSpoolDir, logRoot: olsweb.LogRoot}
	if web != nil && n.enableWeb(web) != nil {
		return nil, ErrUnavailable
	}
	return n, nil
}

func trustedUtilities() (map[string]os.FileInfo, error) {
	tools := map[string]os.FileInfo{}
	for _, p := range fixedUtilities {
		info, e := trustedFile(p, false)
		if e != nil || info.Mode().Perm()&0111 == 0 {
			return nil, ErrUnavailable
		}
		tools[p] = info
	}
	return tools, nil
}

func supportedUseraddDefaults() error {
	b, e := readBoundedSystemFile("/etc/default/useradd", maxUseraddDefaultsBytes)
	if e != nil {
		return ErrUnavailable
	}
	return serviceAccountDefaults(b)
}

func supportedNSS() error {
	b, e := readSystemFile("/etc/nsswitch.conf")
	if e != nil {
		return e
	}
	return filesOnlyNSS(b)
}
func authority(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	for current := path; ; current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrUnavailable
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}
func trustedFile(path string, private bool) (os.FileInfo, error) {
	if authority(filepath.Dir(path)) != nil {
		return nil, ErrUnavailable
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm() != 0600) {
		return nil, ErrUnavailable
	}
	return info, nil
}
func (n *linuxSystem) GuardState(dir string) error {
	if supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return ErrUnavailable
	}
	if authority(dir) != nil {
		return ErrUnavailable
	}
	info, e := os.Lstat(dir)
	if e != nil || info.Mode().Perm() != 0700 {
		return ErrUnavailable
	}
	for _, name := range []string{".sifruno-state", ".sifruno-hostbroker"} {
		if _, e = trustedFile(filepath.Join(dir, name), true); e != nil {
			return ErrUnavailable
		}
	}
	p := filepath.Join(dir, "hostaccounts.db")
	info, e = trustedFile(p, true)
	if errors.Is(e, ErrUnavailable) {
		if _, stErr := os.Lstat(p); errors.Is(stErr, os.ErrNotExist) && n.db == nil {
			return nil
		}
		return ErrUnavailable
	}
	if e != nil {
		return ErrUnavailable
	}
	if n.db != nil && !os.SameFile(n.db, info) {
		return ErrUnavailable
	}
	n.db = info
	return nil
}

func (n *linuxSystem) GuardHomes(records []record) error {
	if authority(n.opts.HomesDir) != nil {
		return ErrRecovery
	}
	f, e := openDirectoryAt(unix.AT_FDCWD, n.opts.HomesDir)
	if e != nil {
		return ErrRecovery
	}
	defer f.Close()
	entries, e := f.ReadDir(MaxAccounts + 1)
	if e != nil && !errors.Is(e, io.EOF) || len(entries) > MaxAccounts {
		return ErrRecovery
	}
	known := map[string]bool{}
	for _, r := range records {
		known[r.Account.Username] = true
	}
	for _, entry := range entries {
		if !known[entry.Name()] || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrRecovery
		}
	}
	return nil
}

type commandBuffer struct{ bytes.Buffer }

func (b *commandBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 64<<10 {
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}

// commandTimeout bounds one fixed command; a slower one gets its own limit
// through commandWithin.
const commandTimeout = 15 * time.Second

func (n *linuxSystem) command(ctx context.Context, path string, args ...string) ([]byte, error) {
	return n.commandWithin(ctx, commandTimeout, path, args...)
}

// commandWithin is command with its own time limit, for a program that is
// known to be slow on a busy host (OpenLiteSpeed's graceful restart).
func (n *linuxSystem) commandWithin(ctx context.Context, limit time.Duration, path string, args ...string) ([]byte, error) {
	out, code, e := n.run(ctx, limit, path, false, args...)
	if e != nil || code != 0 {
		return nil, ErrUnavailable
	}
	return out, nil
}

// commandStatus is command for a program whose non-zero exit is an answer,
// not a failure (openlitespeed -t); its output is stdout and stderr together.
func (n *linuxSystem) commandStatus(ctx context.Context, limit time.Duration, path string, args ...string) ([]byte, int, error) {
	return n.run(ctx, limit, path, true, args...)
}

func (n *linuxSystem) run(ctx context.Context, limit time.Duration, path string, combined bool, args ...string) ([]byte, int, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, -1, ErrUnavailable
	}
	if supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return nil, -1, ErrUnavailable
	}
	before, ok := n.tools[path]
	actual, e := trustedFile(path, false)
	if !ok || e != nil || !os.SameFile(before, actual) || before.Size() != actual.Size() || !before.ModTime().Equal(actual.ModTime()) {
		return nil, -1, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = n.opts.StateDir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + n.opts.StateDir}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	out, stderr := &commandBuffer{}, &commandBuffer{}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if combined {
		cmd.Stderr = out
	}
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, -1, ErrUnavailable
	}
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return nil, -1, ErrUnavailable
	}
	return out.Bytes(), cmd.ProcessState.ExitCode(), nil
}
func readSystemFile(path string) ([]byte, error) {
	return readBoundedSystemFile(path, 4<<20)
}
func readBoundedSystemFile(path string, max int64) ([]byte, error) {
	if _, e := trustedFile(path, false); e != nil {
		return nil, ErrUnavailable
	}
	f, e := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, ErrUnavailable
	}
	return b, nil
}
func systemUsers() ([]nativeUser, error) {
	b, e := readSystemFile("/etc/passwd")
	if e != nil {
		return nil, e
	}
	out := []nativeUser{}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) != 7 {
			return nil, ErrUnavailable
		}
		uid, e := strconv.Atoi(parts[2])
		if e != nil || uid < 0 {
			return nil, ErrUnavailable
		}
		gid, e := strconv.Atoi(parts[3])
		if e != nil || gid < 0 {
			return nil, ErrUnavailable
		}
		out = append(out, nativeUser{parts[0], uid, gid, parts[5], parts[6], parts[4]})
		if len(out) > 100000 {
			return nil, ErrUnavailable
		}
	}
	if scanner.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
func systemGroups() ([]nativeGroup, error) {
	b, e := readSystemFile("/etc/group")
	if e != nil {
		return nil, e
	}
	out := []nativeGroup{}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) != 4 {
			return nil, ErrUnavailable
		}
		gid, e := strconv.Atoi(parts[2])
		if e != nil || gid < 0 {
			return nil, ErrUnavailable
		}
		out = append(out, nativeGroup{parts[0], gid, parts[3]})
		if len(out) > 100000 {
			return nil, ErrUnavailable
		}
	}
	if scanner.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
func (n *linuxSystem) Plan(ctx context.Context, name string) (int, int, error) {
	if ctx == nil || ctx.Err() != nil || !validUsername(name) {
		return 0, 0, ErrInvalid
	}
	if supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return 0, 0, ErrUnavailable
	}
	if authority(n.opts.HomesDir) != nil {
		return 0, 0, ErrUnavailable
	}
	users, e := systemUsers()
	if e != nil {
		return 0, 0, e
	}
	groups, e := systemGroups()
	if e != nil {
		return 0, 0, e
	}
	used := map[int]bool{int(n.opts.ControllerUID): true}
	for _, u := range users {
		if u.Username == name {
			return 0, 0, ErrConflict
		}
		used[u.UID] = true
	}
	for _, g := range groups {
		if g.Name == name {
			return 0, 0, ErrConflict
		}
		used[g.GID] = true
	}
	if _, e = os.Lstat(filepath.Join(n.opts.HomesDir, name)); e == nil {
		return 0, 0, ErrConflict
	} else if !errors.Is(e, os.ErrNotExist) {
		return 0, 0, ErrUnavailable
	}
	for id := firstAccountID; id <= lastAccountID; id++ {
		if !used[id] {
			return id, id, nil
		}
	}
	return 0, 0, ErrConflict
}
func stampOf(path string) (fileStamp, error) {
	info, e := trustedFile(path, false)
	if e != nil {
		return fileStamp{}, ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStamp{}, ErrUnavailable
	}
	return fileStamp{uint64(st.Dev), st.Ino, st.Size, st.Mtim.Nano(), st.Ctim.Nano()}, nil
}

// database returns the current passwd and group view. The stamps are taken
// before and after the parse, so a file replaced mid-read is never cached.
func (n *linuxSystem) database() (*accountDatabase, error) {
	n.cacheMu.Lock()
	defer n.cacheMu.Unlock()
	passwd, e := stampOf("/etc/passwd")
	if e != nil {
		return nil, e
	}
	group, e := stampOf("/etc/group")
	if e != nil {
		return nil, e
	}
	if n.cache != nil && n.cache.passwd == passwd && n.cache.group == group {
		return n.cache, nil
	}
	n.cache = nil
	users, e := systemUsers()
	if e != nil {
		return nil, e
	}
	groups, e := systemGroups()
	if e != nil {
		return nil, e
	}
	after, e := stampOf("/etc/passwd")
	if e != nil || after != passwd {
		return nil, ErrUnavailable
	}
	if after, e = stampOf("/etc/group"); e != nil || after != group {
		return nil, ErrUnavailable
	}
	db := indexAccounts(users, groups)
	db.passwd, db.group = passwd, group
	n.cache = db
	return db, nil
}

func indexAccounts(users []nativeUser, groups []nativeGroup) *accountDatabase {
	db := &accountDatabase{usersByName: map[string][]nativeUser{}, usersByUID: map[int][]nativeUser{}, groupsByName: map[string][]nativeGroup{}, groupsByGID: map[int][]nativeGroup{}, memberOfAny: map[string]bool{}}
	for _, u := range users {
		db.usersByName[u.Username] = append(db.usersByName[u.Username], u)
		db.usersByUID[u.UID] = append(db.usersByUID[u.UID], u)
	}
	for _, g := range groups {
		db.groupsByName[g.Name] = append(db.groupsByName[g.Name], g)
		db.groupsByGID[g.GID] = append(db.groupsByGID[g.GID], g)
		for _, member := range strings.Split(g.Members, ",") {
			db.memberOfAny[member] = true
		}
	}
	return db
}

// managedIdentity is the indexed form of the identity rules: exactly one
// passwd entry with this name, no other name on its UID, the recorded
// UID/GID/home/tag, the nologin shell, and a private primary group that has
// this GID alone, no members, and no membership of the account anywhere.
// privateGroupOnly states the same group rule over the raw list.
func (db *accountDatabase) managedIdentity(r record) (nativeUser, bool) {
	named := db.usersByName[r.Account.Username]
	if len(named) != 1 || len(db.usersByUID[r.Account.UID]) != 1 {
		return nativeUser{}, false
	}
	user := named[0]
	if user.UID != r.Account.UID || user.GID != r.Account.GID || user.Home != r.Account.Home || user.Shell != nologin || user.Tag != r.Tag {
		return nativeUser{}, false
	}
	group := db.groupsByName[r.Account.Username]
	if len(group) != 1 || group[0].GID != r.Account.GID || group[0].Members != "" || len(db.groupsByGID[r.Account.GID]) != 1 || db.memberOfAny[r.Account.Username] {
		return nativeUser{}, false
	}
	return user, true
}

func (n *linuxSystem) identity(r record) (nativeUser, error) {
	if supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return nativeUser{}, ErrUnavailable
	}
	db, e := n.database()
	if e != nil {
		return nativeUser{}, e
	}
	user, ok := db.managedIdentity(r)
	if !ok {
		return nativeUser{}, ErrRecovery
	}
	return user, nil
}

func privateGroupOnly(groups []nativeGroup, name string, gid int) bool {
	found := false
	for _, g := range groups {
		if g.Name == name {
			if found || g.GID != gid || g.Members != "" {
				return false
			}
			found = true
		} else if g.GID == gid {
			return false
		}
		for _, member := range strings.Split(g.Members, ",") {
			if member == name {
				return false
			}
		}
	}
	return found
}
func (n *linuxSystem) admission(ctx context.Context, r record) error {
	raw, e := n.command(ctx, "/usr/bin/passwd", "--status", r.Account.Username)
	if e != nil {
		return e
	}
	parts := strings.Fields(string(raw))
	if len(parts) < 2 || parts[0] != r.Account.Username || !lockedStatus(parts[1]) {
		return ErrRecovery
	}
	raw, e = n.command(ctx, "/usr/bin/chage", "--list", r.Account.Username)
	if e != nil {
		return e
	}
	found := false
	expiry := ""
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "Account expires" {
			if found {
				return ErrRecovery
			}
			found = true
			expiry = strings.TrimSpace(value)
		}
	}
	if !found {
		return ErrRecovery
	}
	if r.Account.State == "active" && expiry != "never" {
		return ErrRecovery
	}
	if r.Account.State == "suspended" && expiry != "Jan 02, 1970" {
		return ErrRecovery
	}
	return nil
}
func (n *linuxSystem) Create(ctx context.Context, r record, persist func(ownership) error) (ownership, error) {
	uid, gid, e := n.Plan(ctx, r.Account.Username)
	if e != nil || uid != r.Account.UID || gid != r.Account.GID {
		return ownership{}, ErrRecovery
	}
	owners := filepath.Join(n.opts.StateDir, "owners")
	if e = os.Mkdir(owners, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return ownership{}, ErrUnavailable
	}
	if authority(owners) != nil {
		return ownership{}, ErrUnavailable
	}
	if info, err := os.Lstat(owners); err != nil || info.Mode().Perm() != 0700 {
		return ownership{}, ErrUnavailable
	}
	marker := n.markerPath(r)
	f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return ownership{}, ErrRecovery
	}
	_, e = f.Write([]byte(r.Tag + "\n"))
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil || closed != nil {
		return ownership{}, ErrRecovery
	}
	r.Ownership.Marker, e = markerIdentity(marker, r.Tag)
	if e != nil || persist(r.Ownership) != nil {
		return ownership{}, ErrRecovery
	}
	skel := filepath.Join(n.opts.StateDir, "empty-skel")
	if e = os.Mkdir(skel, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return ownership{}, ErrUnavailable
	}
	entries, e := os.ReadDir(skel)
	if e != nil || len(entries) != 0 || authority(skel) != nil {
		return ownership{}, ErrUnavailable
	}
	if _, e = n.command(ctx, "/usr/sbin/groupadd", "--gid", strconv.Itoa(r.Account.GID), "--", r.Account.Username); e != nil {
		return ownership{}, e
	}
	if _, e = n.command(ctx, "/usr/sbin/useradd", useraddArgs(r, skel)...); e != nil {
		return ownership{}, e
	}
	return n.RecoverCreate(ctx, r, persist)
}

// useraddArgs creates a regular (non-system) user. Shadow then allocates the
// subordinate UID and GID ranges from login.defs, which rootless containers
// need later; system-account mode skipped them. The explicit IDs, private
// group, empty supplementary groups, empty skeleton, nologin shell and locked
// password are unchanged. On a host whose CREATE_MAIL_SPOOL default is yes a
// regular user also gets a mail spool file; Delete removes it.
func useraddArgs(r record, skel string) []string {
	return []string{"--uid", strconv.Itoa(r.Account.UID), "--gid", strconv.Itoa(r.Account.GID), "--no-user-group", "--groups", "", "--create-home", "--home-dir", r.Account.Home, "--skel", skel, "--shell", nologin, "--comment", r.Tag, "--password", "!", "--expiredate", "", "--", r.Account.Username}
}

func lockedStatus(token string) bool { return token == "L" || token == "LK" }
func (n *linuxSystem) markerPath(r record) string {
	return filepath.Join(n.opts.StateDir, "owners", r.Account.ID)
}
func openDirectoryAt(parent int, name string) (*os.File, error) {
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrRecovery
	}
	return os.NewFile(uintptr(fd), name), nil
}
func heldIdentity(f *os.File, uid, gid int, mode os.FileMode) (fileIdentity, error) {
	info, e := f.Stat()
	if e != nil || !info.IsDir() {
		return fileIdentity{}, ErrRecovery
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid || int(st.Gid) != gid || mode != 0 && info.Mode().Perm() != mode {
		return fileIdentity{}, ErrRecovery
	}
	return fileIdentity{uint64(st.Dev), st.Ino}, nil
}
func dirIdentity(path string, uid, gid int, mode os.FileMode) (fileIdentity, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fileIdentity{}, ErrRecovery
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid || int(st.Gid) != gid || (mode != 0 && info.Mode().Perm() != mode) {
		return fileIdentity{}, ErrRecovery
	}
	return fileIdentity{uint64(st.Dev), st.Ino}, nil
}
func markerIdentity(path, tag string) (fileIdentity, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fileIdentity{}, ErrRecovery
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 || info.Size() > 128 {
		return fileIdentity{}, ErrRecovery
	}
	f, e := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return fileIdentity{}, ErrRecovery
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return fileIdentity{}, ErrRecovery
	}
	b, e := io.ReadAll(io.LimitReader(f, 129))
	if e != nil || string(b) != tag+"\n" {
		return fileIdentity{}, ErrRecovery
	}
	return fileIdentity{uint64(st.Dev), st.Ino}, nil
}
func (n *linuxSystem) RecoverCreate(ctx context.Context, r record, persist func(ownership) error) (ownership, error) {
	if _, e := n.identity(r); e != nil {
		return ownership{}, e
	}
	check := targetRecord(r, "active")
	if e := n.admission(ctx, check); e != nil {
		return ownership{}, e
	}
	mark, e := markerIdentity(n.markerPath(r), r.Tag)
	if e != nil || mark != r.Ownership.Marker {
		return ownership{}, ErrRecovery
	}
	if authority(n.opts.HomesDir) != nil {
		return ownership{}, ErrRecovery
	}
	parent, e := openDirectoryAt(unix.AT_FDCWD, n.opts.HomesDir)
	if e != nil {
		return ownership{}, e
	}
	defer parent.Close()
	home, e := openDirectoryAt(int(parent.Fd()), r.Account.Username)
	if e != nil {
		return ownership{}, e
	}
	defer home.Close()
	id, e := heldIdentity(home, r.Account.UID, r.Account.GID, 0)
	if e != nil {
		return ownership{}, e
	}
	if r.Ownership.Home.Ino != 0 && r.Ownership.Home != id {
		return ownership{}, ErrRecovery
	}
	r.Ownership.Home = id
	if persist(r.Ownership) != nil {
		return ownership{}, ErrRecovery
	}
	if home.Chmod(0750) != nil {
		return ownership{}, ErrRecovery
	}
	if r.Ownership.Public.Ino == 0 {
		if unix.Mkdirat(int(home.Fd()), "public_html", 0750) != nil {
			return ownership{}, ErrRecovery
		}
	}
	pub, e := openDirectoryAt(int(home.Fd()), "public_html")
	if e != nil {
		return ownership{}, e
	}
	defer pub.Close()
	info, e := pub.Stat()
	if e != nil {
		return ownership{}, ErrRecovery
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || !((st.Uid == 0 && st.Gid == 0) || (int(st.Uid) == r.Account.UID && int(st.Gid) == r.Account.GID)) {
		return ownership{}, ErrRecovery
	}
	publicID := fileIdentity{uint64(st.Dev), st.Ino}
	if r.Ownership.Public.Ino != 0 && r.Ownership.Public != publicID {
		return ownership{}, ErrRecovery
	}
	if r.Ownership.Public.Ino == 0 && (st.Uid != 0 || st.Gid != 0) {
		return ownership{}, ErrRecovery
	}
	r.Ownership.Public = publicID
	if persist(r.Ownership) != nil {
		return ownership{}, ErrRecovery
	}
	if pub.Chmod(0750) != nil || pub.Chown(r.Account.UID, r.Account.GID) != nil {
		return ownership{}, ErrRecovery
	}
	final := targetRecord(r, "active")
	if e = n.Verify(ctx, final); e != nil {
		return ownership{}, e
	}
	return r.Ownership, nil
}

// VerifyAccountIdentity checks what files alone show about a managed account
// and only root can change: the passwd and group identity, the recorded home
// directory object and its owner, and the ownership marker. The home sits in
// the root-owned homes directory, so its account cannot replace it or give
// it away; its mode is the account's own to change and is checked by
// VerifySiteFiles. It starts no process, so the store can run it for every
// account on every request.
func (n *linuxSystem) VerifyAccountIdentity(r record) error {
	if authority(n.opts.HomesDir) != nil {
		return ErrRecovery
	}
	if _, e := n.identity(r); e != nil {
		return e
	}
	home, e := dirIdentity(r.Account.Home, r.Account.UID, r.Account.GID, 0)
	if e != nil || home != r.Ownership.Home {
		return ErrRecovery
	}
	marker, e := markerIdentity(n.markerPath(r), r.Tag)
	if e != nil || marker != r.Ownership.Marker {
		return ErrRecovery
	}
	return nil
}

// VerifySiteFiles checks what the account's own user can change in its home:
// the home's mode 0750, and public_html as the directory recorded at create,
// not a link, owned by the account, mode 0750. It only reads.
func (n *linuxSystem) VerifySiteFiles(r record) error {
	if _, e := dirIdentity(r.Account.Home, r.Account.UID, r.Account.GID, 0750); e != nil {
		return ErrRecovery
	}
	pub, e := dirIdentity(r.Account.PublicHTML, r.Account.UID, r.Account.GID, 0750)
	if e != nil || pub != r.Ownership.Public {
		return ErrRecovery
	}
	return nil
}

// VerifyIdentity is everything files alone show: VerifyAccountIdentity and
// VerifySiteFiles.
func (n *linuxSystem) VerifyIdentity(r record) error {
	if e := n.VerifyAccountIdentity(r); e != nil {
		return e
	}
	return n.VerifySiteFiles(r)
}

// VerifyAccount adds the password-lock and expiry observation, which needs
// the passwd and chage utilities, to VerifyAccountIdentity. The store runs it
// for the account an operation touches and for a rotating batch, not for
// every account on every request.
func (n *linuxSystem) VerifyAccount(ctx context.Context, r record) error {
	if e := n.VerifyAccountIdentity(r); e != nil {
		return e
	}
	return n.admission(ctx, r)
}

// Verify is VerifyAccount with VerifySiteFiles, for an operation that writes
// into the account's folders.
func (n *linuxSystem) Verify(ctx context.Context, r record) error {
	if e := n.VerifyIdentity(r); e != nil {
		return e
	}
	return n.admission(ctx, r)
}

// Delete removes the managed identity. Every destructive step is gated on
// the recorded ownership evidence: the marker must match first (proof we
// manage this account), the system user must match the recorded UID/GID/home
// exactly (a foreign or recycled UID is refused), and the home directory is
// removed only when it is the exact recorded path with the recorded
// identity. The marker is removed last so a crash mid-delete stays visible
// and the operation can be safely retried by the store's reconciliation.
// The account's processes end before userdel (removeUser); the store takes
// a live site out of the config before it calls Delete.
func (n *linuxSystem) Delete(ctx context.Context, r record) error {
	marker, e := markerIdentity(n.markerPath(r), r.Tag)
	if e == nil && marker != r.Ownership.Marker {
		return ErrRecovery
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	// A missing marker with a still-present user is not owned deletable
	// state; a missing marker with everything already gone is a completed
	// delete (safe retry).
	users, e := systemUsers()
	if e != nil {
		return e
	}
	present := false
	for _, u := range users {
		if u.Username == r.Account.Username {
			if u.UID != r.Account.UID || u.GID != r.Account.GID || u.Home != r.Account.Home {
				return ErrRecovery
			}
			present = true
		} else if u.UID == r.Account.UID {
			return ErrRecovery
		}
	}
	if present && marker != r.Ownership.Marker {
		return ErrRecovery
	}
	if present {
		if e = n.removeUser(ctx, r); e != nil {
			return e
		}
	}
	if info, e := os.Lstat(r.Account.Home); e == nil {
		if !info.IsDir() || r.Account.Home != filepath.Join(n.opts.HomesDir, r.Account.Username) {
			return ErrRecovery
		}
		// The recorded object and its owner, which only root can change; not
		// its mode, which the account may have changed. RemoveAll does not
		// follow links inside it.
		home, e := dirIdentity(r.Account.Home, r.Account.UID, r.Account.GID, 0)
		if e != nil || home != r.Ownership.Home {
			return ErrRecovery
		}
		if e = os.RemoveAll(r.Account.Home); e != nil {
			return ErrUnavailable
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	if e = n.removeAccountFiles(r); e != nil {
		return e
	}
	if e = os.Remove(n.markerPath(r)); e != nil && !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	return nil
}

// userdelBusy is userdel's exit status for a user with a running process
// (shadow-utils E_USER_BUSY). userdel checks for one before it opens the
// account files, so with this status it changed nothing.
const userdelBusy = 8

// Ending an account's processes takes at most processPasses passes. A pass
// signals every process of the account, then waits up to processWait for
// them to be gone, looking every processPoll. The next pass catches what
// started meanwhile: a fork that raced the signal, or a process root
// started for the account. userdelTries bounds the same race between the
// last pass and userdel.
//
// processBudget bounds all the process ending of one delete, every pass of
// every try, on its own clock and well inside the delete's own limit: a
// tenant with very many processes makes each /proc scan slow, and when the
// budget runs out the user counts as busy, so the delete is put back and
// ends rejected instead of running into that limit. putBackTimeout bounds
// the put-back (usermod, then passwd and chage to check the account), on a
// context of its own.
const (
	processPasses  = 4
	processWait    = 250 * time.Millisecond
	processPoll    = 25 * time.Millisecond
	killTimeout    = 5 * time.Second
	userdelTries   = DeleteAttempts
	processBudget  = 20 * time.Second
	putBackTimeout = time.Minute
)

// removeUser removes the account's user once its processes have ended. An
// active account is first expired and locked, as a suspend does, so no new
// login or cron job starts for it while they end. userdel is tried a few
// times, each after the processes were ended again (userRemoval.run).
func (n *linuxSystem) removeUser(ctx context.Context, r record) error {
	active := r.Account.State == "active"
	return userRemoval{
		lock: func(ctx context.Context) error {
			if !active {
				return nil
			}
			_, e := n.command(ctx, "/usr/sbin/usermod", "--expiredate", "1970-01-02", "--lock", "--", r.Account.Username)
			return e
		},
		end: func(ctx context.Context) error { return n.EndProcesses(ctx, r) },
		userdel: func(ctx context.Context) (int, error) {
			_, code, e := n.commandStatus(ctx, commandTimeout, "/usr/sbin/userdel", "--", r.Account.Username)
			return code, e
		},
		putBack: func(ctx context.Context) error {
			// When the lock step itself failed (the shadow file busy, say),
			// the account is often unchanged, and a usermod now could fail the
			// same way and leave the delete pending for everyone. Check first,
			// and undo only what the lock changed.
			if n.VerifyAccount(ctx, r) == nil {
				return nil
			}
			if active {
				if _, e := n.command(ctx, "/usr/sbin/usermod", "--expiredate", "", "--lock", "--", r.Account.Username); e != nil {
					return e
				}
			}
			return n.VerifyAccount(ctx, r)
		},
	}.run(ctx, processBudget)
}

// userRemoval is the steps of removeUser, kept apart so their order, the
// budget and the put-back can be tested without root. lock expires and
// locks an active account; end ends its processes; userdel answers
// userdel's exit status; putBack undoes lock and checks the account is as
// its record says.
type userRemoval struct {
	lock, end, putBack func(context.Context) error
	userdel            func(context.Context) (int, error)
}

// run removes the user. Whatever stops it before userdel changed anything
// takes one path: the user still busy after the last try, the budget for
// ending processes spent, a /proc read or kill or the lock failing, the
// caller's limit. putBack runs on a fresh, bounded context, since the
// caller's may be what ran out, and the answer is errAccountBusy for a busy
// user (the budget spent counts as busy) and errNothingRemoved otherwise:
// the account is as it was. If the put-back fails, its error is the answer
// and the delete stays pending. A userdel that exits other than 0 or 8, or
// does not finish, leaves the user in a state nobody knows: its error is
// the answer, and the delete stays pending too.
func (u userRemoval) run(ctx context.Context, budget time.Duration) error {
	stopped, e := u.remove(ctx, budget)
	if stopped == nil {
		return e
	}
	backCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), putBackTimeout)
	defer cancel()
	if e := u.putBack(backCtx); e != nil {
		return e
	}
	if errors.Is(stopped, errAccountBusy) {
		return errAccountBusy
	}
	return errNothingRemoved
}

// remove runs lock, then end and userdel up to userdelTries times. stopped
// is why it stopped before userdel changed anything; otherwise err is
// userdel's answer: nil when the user is gone.
func (u userRemoval) remove(ctx context.Context, budget time.Duration) (stopped, err error) {
	if e := u.lock(ctx); e != nil {
		return e, nil
	}
	endCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for try := 0; try < userdelTries; try++ {
		// Processes still there after the passes go on to userdel, which
		// judges for itself.
		if e := u.end(endCtx); e != nil && !errors.Is(e, errAccountBusy) {
			if endCtx.Err() != nil && ctx.Err() == nil {
				return errAccountBusy, nil
			}
			return e, nil
		}
		if ctx.Err() != nil {
			return ErrUnavailable, nil
		}
		code, e := u.userdel(ctx)
		switch {
		case e != nil:
			return nil, e
		case code == 0:
			return nil, nil
		case code != userdelBusy:
			return nil, ErrUnavailable
		}
	}
	return errAccountBusy, nil
}

// EndProcesses ends every process that runs as the account's user: an SFTP
// session, a PHP worker, a cron job, anything the tenant started. Each pass
// checks the credential again (processCredential), runs kill as that user
// (signalAs) and waits for the processes to be gone (accountRunning).
// errAccountBusy: some were still there after the last pass.
func (n *linuxSystem) EndProcesses(ctx context.Context, r record) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	for pass := 0; pass < processPasses; pass++ {
		cred, e := n.processCredential(r)
		if e != nil {
			return e
		}
		if e = n.signalAs(ctx, cred); e != nil {
			return e
		}
		gone, e := waitGone(ctx, cred.Uid)
		if e != nil {
			return e
		}
		if gone {
			return nil
		}
	}
	return errAccountBusy
}

// processCredential is the credential that ends an account's processes,
// read from passwd and group now: see accountCredential.
func (n *linuxSystem) processCredential(r record) (*syscall.Credential, error) {
	if supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return nil, ErrUnavailable
	}
	db, e := n.database()
	if e != nil {
		return nil, e
	}
	return accountCredential(db, r, n.opts.ControllerUID)
}

// accountCredential is the account's own UID and GID with no supplementary
// groups, given only for an ID in the range the broker allocates (never 0,
// a system user or the controller) that passwd and group show as exactly
// this account: one user with this name and none other on its UID, the
// recorded IDs, home, tag and nologin shell, and its private group.
// Otherwise ErrRecovery: the kill must not run as anyone else.
func accountCredential(db *accountDatabase, r record, controllerUID uint32) (*syscall.Credential, error) {
	uid, gid := r.Account.UID, r.Account.GID
	if uid < firstAccountID || uid > lastAccountID || gid != uid || uid == int(controllerUID) {
		return nil, ErrRecovery
	}
	user, ok := db.managedIdentity(r)
	if !ok || user.UID != uid || user.GID != gid {
		return nil, ErrRecovery
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, nil
}

// killArgs is kill's whole argument list: SIGKILL to PID -1. "--" ends the
// options, so -1 is a PID.
func killArgs() []string { return []string{"-s", "KILL", "--", "-1"} }

// killCommand is kill as cred: the fixed binary, in "/", with a clean
// environment, no input (the null device) and no supplementary groups. Go's
// exec sets the groups, GID and UID in the child before it runs the binary,
// and runs nothing when that fails. Its context ends only this process.
func killCommand(ctx context.Context, cred *syscall.Credential) *exec.Cmd {
	cmd := exec.CommandContext(ctx, killPath, killArgs()...)
	cmd.Dir = "/"
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	return cmd
}

// signalAs runs `kill -s KILL -- -1` as the account. kill(2) with PID -1
// from a process that is not root signals every process that user may
// signal, other than itself: those whose real or saved user ID is the
// account's, and those in user namespaces the account made. That is only
// the account's own; no other user's process can be hit. It refuses any
// credential outside the broker's range, so it never runs as root. Its exit
// status says only whether anything was signalled; the caller looks at
// /proc.
func (n *linuxSystem) signalAs(ctx context.Context, cred *syscall.Credential) error {
	if cred == nil || cred.Uid < firstAccountID || cred.Uid > lastAccountID || cred.Gid != cred.Uid || len(cred.Groups) != 0 || cred.NoSetGroups {
		return ErrRecovery
	}
	before, ok := n.tools[killPath]
	actual, e := trustedFile(killPath, false)
	if !ok || e != nil || !os.SameFile(before, actual) || before.Size() != actual.Size() || !before.ModTime().Equal(actual.ModTime()) {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, killTimeout)
	defer cancel()
	cmd := killCommand(ctx, cred)
	out := &commandBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	// An exit status means kill ran as the account; any other error means
	// it did not run at all.
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return ErrUnavailable
	}
	return nil
}

// waitGone looks until no process of uid is left, for up to processWait.
func waitGone(ctx context.Context, uid uint32) (bool, error) {
	deadline := time.Now().Add(processWait)
	for {
		running, e := accountRunning(ctx, uid)
		if e != nil {
			return false, e
		}
		if !running {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ErrUnavailable
		case <-time.After(processPoll):
		}
	}
}

// accountRunning reports whether a process has uid as its real, effective
// or saved user ID, a zombie not yet reaped included. That is what userdel
// looks for (shadow-utils user_busy), less the subordinate IDs and the
// per-thread IDs it also reads; userdel stays the judge of those. A
// process that ends while it is read is skipped. A scan of very many
// processes is slow, so it stops with ErrUnavailable as soon as ctx is
// done, between entries.
func accountRunning(ctx context.Context, uid uint32) (bool, error) {
	proc, e := os.Open("/proc")
	if e != nil {
		return false, ErrUnavailable
	}
	defer proc.Close()
	for {
		names, readErr := proc.Readdirnames(1024)
		for _, name := range names {
			if ctx.Err() != nil {
				return false, ErrUnavailable
			}
			if !pidName(name) {
				continue
			}
			status, e := readProcStatus("/proc/" + name + "/status")
			if errors.Is(e, os.ErrNotExist) || errors.Is(e, syscall.ESRCH) {
				continue
			}
			if e != nil {
				return false, ErrUnavailable
			}
			ids, ok := statusUIDs(status)
			if !ok {
				return false, ErrUnavailable
			}
			if ids[0] == uid || ids[1] == uid || ids[2] == uid {
				return true, nil
			}
		}
		if errors.Is(readErr, io.EOF) {
			return false, nil
		}
		if readErr != nil {
			return false, ErrUnavailable
		}
	}
}

func pidName(name string) bool {
	if name == "" || len(name) > 10 {
		return false
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func readProcStatus(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

// statusUIDs reads the real, effective, saved and file-system user IDs
// from the "Uid:" line of /proc/<pid>/status.
func statusUIDs(status []byte) ([4]uint32, bool) {
	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 4 {
			return [4]uint32{}, false
		}
		var ids [4]uint32
		for i, f := range fields {
			v, e := strconv.ParseUint(f, 10, 32)
			if e != nil {
				return [4]uint32{}, false
			}
			ids[i] = uint32(v)
		}
		return ids, true
	}
	return [4]uint32{}, false
}

// removeAccountFiles removes what an account has outside the home: its
// site's TLS directory, the managed SFTP key file and the mail spool useradd
// may have made. Each is removed only when it is the expected kind of
// object, so a name reused later never inherits any of them. The store runs
// a delete only after the site has left the OpenLiteSpeed config.
func (n *linuxSystem) removeAccountFiles(r record) error {
	if !validUsername(r.Account.Username) {
		return ErrRecovery
	}
	if !idPattern.MatchString(r.Account.ID) {
		return ErrRecovery
	}
	if e := n.removeSiteTLS(r); e != nil {
		return e
	}
	// The temporary name SetSSHKeys writes before its rename survives a crash
	// between the two; it holds only public keys but goes with the account.
	for _, path := range []string{filepath.Join(n.sshDir, r.Account.Username), filepath.Join(n.sshDir, ".new-"+r.Account.ID)} {
		if e := removeRegular(path, 0, false); e != nil {
			return e
		}
	}
	// The crontab, whoever wrote it (cronie's crontab run by root leaves it
	// root's, by the user the user's), and SetCron's temporary name. crond
	// keeps a crontab whose user is gone as an orphan and loads it again
	// when a user of that name appears (cronie database.c, check_orphans),
	// so it must not outlive the account.
	if !filepath.IsAbs(n.cronDir) {
		return ErrUnavailable
	}
	for _, name := range []string{r.Account.Username, cronTempName(r.Account.ID)} {
		if e := removeRegular(filepath.Join(n.cronDir, name), r.Account.UID, true); e != nil {
			return e
		}
	}
	return removeRegular(filepath.Join(n.mailDir, r.Account.Username), r.Account.UID, true)
}

// removeRegular unlinks path when it is a regular file owned by uid. A
// missing file or a missing parent directory is a completed removal. Any
// other object is left alone and reported: the broker does not guess.
func removeRegular(path string, uid int, ownerMayBeRoot bool) error {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) || errors.Is(e, syscall.ENOTDIR) {
		return nil
	}
	if e != nil {
		return ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || !(int(st.Uid) == uid || ownerMayBeRoot && st.Uid == 0) {
		return ErrRecovery
	}
	if e = os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	return nil
}

// SetSSHKeys makes the account's managed key file hold exactly the given
// canonical keys, each behind the fixed SFTP-only options. The file is
// root-owned and readable by the account's private group only, which is what
// sshd needs to read it as the user and all StrictModes accepts. It is
// written beside the target and renamed, so sshd never sees a partial file.
// An empty set removes the file. The key directory must already exist as a
// root-owned 0711 directory under root-owned parents; the broker does not
// create host policy.
func (n *linuxSystem) SetSSHKeys(ctx context.Context, r record, canonical []string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if !validUsername(r.Account.Username) || len(canonical) > MaxSSHKeys {
		return ErrInvalid
	}
	for _, line := range canonical {
		if c, _, ok := normalizeSSHKey(line); !ok || c != line {
			return ErrInvalid
		}
	}
	info, e := os.Lstat(n.sshDir)
	if e != nil || authority(n.sshDir) != nil || info.Mode() != os.ModeDir|0711 {
		return ErrUnavailable
	}
	target := filepath.Join(n.sshDir, r.Account.Username)
	if len(canonical) == 0 {
		if e = removeRegular(target, 0, false); e != nil {
			return e
		}
		return syncDirectory(n.sshDir)
	}
	if existing, e := os.Lstat(target); e == nil {
		st, ok := existing.Sys().(*syscall.Stat_t)
		if !ok || !existing.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 {
			return ErrRecovery
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	content := renderAuthorizedKeys(canonical)
	temp := filepath.Join(n.sshDir, ".new-"+r.Account.ID)
	if e = os.Remove(temp); e != nil && !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	f, e := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrUnavailable
	}
	_, e = f.Write(content)
	if e == nil {
		e = f.Chown(0, r.Account.GID)
	}
	if e == nil {
		// Chmod after Chown: the mode must not depend on the process umask.
		e = f.Chmod(0640)
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil || closed != nil {
		_ = os.Remove(temp)
		return ErrUnavailable
	}
	if e = os.Rename(temp, target); e != nil {
		_ = os.Remove(temp)
		return ErrUnavailable
	}
	if e = syncDirectory(n.sshDir); e != nil {
		return e
	}
	return n.verifySSHKeys(r, canonical)
}

// VerifySSHKeys is verifySSHKeys for the store, extended to the empty set,
// whose installed form is the absence of the file.
func (n *linuxSystem) VerifySSHKeys(r record, canonical []string) error {
	if !validUsername(r.Account.Username) {
		return ErrInvalid
	}
	if len(canonical) == 0 {
		if _, e := os.Lstat(filepath.Join(n.sshDir, r.Account.Username)); errors.Is(e, os.ErrNotExist) || errors.Is(e, syscall.ENOTDIR) {
			return nil
		}
		return ErrRecovery
	}
	return n.verifySSHKeys(r, canonical)
}

// verifySSHKeys re-reads the installed file and requires the exact bytes,
// owner, group and mode that SetSSHKeys writes.
func (n *linuxSystem) verifySSHKeys(r record, canonical []string) error {
	target := filepath.Join(n.sshDir, r.Account.Username)
	f, e := os.OpenFile(target, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return ErrRecovery
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return ErrRecovery
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0640 || st.Uid != 0 || int(st.Gid) != r.Account.GID || st.Nlink != 1 {
		return ErrRecovery
	}
	want := renderAuthorizedKeys(canonical)
	got, e := io.ReadAll(io.LimitReader(f, int64(len(want))+1))
	if e != nil || !bytes.Equal(got, want) {
		return ErrRecovery
	}
	return nil
}

func syncDirectory(path string) error {
	d, e := openDirectoryAt(unix.AT_FDCWD, path)
	if e != nil {
		return ErrUnavailable
	}
	defer d.Close()
	if d.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

// SetState checks only what root controls, before and after: a suspend must
// not depend on anything the account's own user can change.
func (n *linuxSystem) SetState(ctx context.Context, r record, state string) error {
	current := r
	current.Pending = nil
	if e := n.VerifyAccount(ctx, current); e != nil {
		return e
	}
	expiry := ""
	if state == "suspended" {
		expiry = "1970-01-02"
	}
	if _, e := n.command(ctx, "/usr/sbin/usermod", "--expiredate", expiry, "--lock", "--", r.Account.Username); e != nil {
		return e
	}
	return n.VerifyAccount(ctx, targetRecord(r, state))
}
