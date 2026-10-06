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
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const nologin = "/usr/sbin/nologin"

var fixedUtilities = []string{"/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/bin/passwd", "/usr/bin/chage", nologin}

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
type linuxSystem struct {
	opts  BrokerOptions
	tools map[string]os.FileInfo
	db    os.FileInfo
}

func newLinuxSystem(opts BrokerOptions) (*linuxSystem, error) {
	tools, e := trustedUtilities()
	if e != nil || supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return nil, ErrUnavailable
	}
	return &linuxSystem{opts: opts, tools: tools}, nil
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
	return mailDisabledDefaults(b)
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
func (n *linuxSystem) command(ctx context.Context, path string, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return nil, ErrUnavailable
	}
	before, ok := n.tools[path]
	actual, e := trustedFile(path, false)
	if !ok || e != nil || !os.SameFile(before, actual) || before.Size() != actual.Size() || !before.ModTime().Equal(actual.ModTime()) {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
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
	if cmd.Run() != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return out.Bytes(), nil
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
func (n *linuxSystem) identity(r record) (nativeUser, error) {
	if supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return nativeUser{}, ErrUnavailable
	}
	users, e := systemUsers()
	if e != nil {
		return nativeUser{}, e
	}
	var user nativeUser
	found := false
	for _, u := range users {
		if u.Username != r.Account.Username && u.UID == r.Account.UID {
			return nativeUser{}, ErrRecovery
		}
		if u.Username == r.Account.Username {
			if found {
				return nativeUser{}, ErrRecovery
			}
			user = u
			found = true
		}
	}
	if !found || user.UID != r.Account.UID || user.GID != r.Account.GID || user.Home != r.Account.Home || user.Shell != nologin || user.Tag != r.Tag {
		return nativeUser{}, ErrRecovery
	}
	groups, e := systemGroups()
	if e != nil {
		return nativeUser{}, e
	}
	if !privateGroupOnly(groups, r.Account.Username, r.Account.GID) {
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

func useraddArgs(r record, skel string) []string {
	return []string{"-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", "--uid", strconv.Itoa(r.Account.UID), "--gid", strconv.Itoa(r.Account.GID), "--no-user-group", "--groups", "", "--create-home", "--home-dir", r.Account.Home, "--skel", skel, "--shell", nologin, "--comment", r.Tag, "--password", "!", "--expiredate", "", "--", r.Account.Username}
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
func (n *linuxSystem) Verify(ctx context.Context, r record) error {
	if authority(n.opts.HomesDir) != nil {
		return ErrRecovery
	}
	if _, e := n.identity(r); e != nil {
		return e
	}
	if e := n.admission(ctx, r); e != nil {
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
