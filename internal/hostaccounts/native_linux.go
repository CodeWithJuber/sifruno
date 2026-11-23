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
)

const nologin = "/usr/sbin/nologin"

var fixedUtilities = []string{"/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/sbin/userdel", "/usr/bin/passwd", "/usr/bin/chage", nologin}

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
	n := &linuxSystem{opts: opts, tools: tools, sshDir: sshKeysDir, mailDir: mailSpoolDir}
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
	for id := 20000; id <= 60000; id++ {
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

// VerifyIdentity checks everything about a managed account that files alone
// show: the passwd and group identity, the recorded home and public_html
// objects, and the ownership marker. It starts no process, so the store can
// run it for every account on every request.
func (n *linuxSystem) VerifyIdentity(r record) error {
	if authority(n.opts.HomesDir) != nil {
		return ErrRecovery
	}
	if _, e := n.identity(r); e != nil {
		return e
	}
	home, e := dirIdentity(r.Account.Home, r.Account.UID, r.Account.GID, 0750)
	if e != nil || home != r.Ownership.Home {
		return ErrRecovery
	}
	pub, e := dirIdentity(r.Account.PublicHTML, r.Account.UID, r.Account.GID, 0750)
	if e != nil || pub != r.Ownership.Public {
		return ErrRecovery
	}
	marker, e := markerIdentity(n.markerPath(r), r.Tag)
	if e != nil || marker != r.Ownership.Marker {
		return ErrRecovery
	}
	return nil
}

// Verify adds the password-lock and expiry observation, which needs the
// passwd and chage utilities. The store runs it for the account an operation
// touches and for a rotating batch, not for every account on every request.
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
// Known delta vs the reference's removeacct pipeline: managed identities
// are nologin system users with no processes, mail, databases or web vhosts,
// so there is nothing further to tear down yet; as those services land,
// their teardown joins this operation before user removal.
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
		if _, e = n.command(ctx, "/usr/sbin/userdel", "--", r.Account.Username); e != nil {
			return e
		}
	}
	if info, e := os.Lstat(r.Account.Home); e == nil {
		if !info.IsDir() || r.Account.Home != filepath.Join(n.opts.HomesDir, r.Account.Username) {
			return ErrRecovery
		}
		home, e := dirIdentity(r.Account.Home, r.Account.UID, r.Account.GID, 0750)
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

// removeAccountFiles removes the two per-account files that live outside the
// home: the managed SFTP key file and the mail spool useradd may have made.
// Each is removed only when it is the expected kind of object, so a name
// reused later never inherits either one.
func (n *linuxSystem) removeAccountFiles(r record) error {
	if !validUsername(r.Account.Username) {
		return ErrRecovery
	}
	if !idPattern.MatchString(r.Account.ID) {
		return ErrRecovery
	}
	// The temporary name SetSSHKeys writes before its rename survives a crash
	// between the two; it holds only public keys but goes with the account.
	for _, path := range []string{filepath.Join(n.sshDir, r.Account.Username), filepath.Join(n.sshDir, ".new-"+r.Account.ID)} {
		if e := removeRegular(path, 0, false); e != nil {
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

func (n *linuxSystem) SetState(ctx context.Context, r record, state string) error {
	current := r
	current.Pending = nil
	if e := n.Verify(ctx, current); e != nil {
		return e
	}
	expiry := ""
	if state == "suspended" {
		expiry = "1970-01-02"
	}
	if _, e := n.command(ctx, "/usr/sbin/usermod", "--expiredate", expiry, "--lock", "--", r.Account.Username); e != nil {
		return e
	}
	return n.Verify(ctx, targetRecord(r, state))
}
