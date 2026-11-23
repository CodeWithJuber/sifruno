//go:build linux

package hostaccounts

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/olsweb"
)

// The web operation's root effects, each a fixed program or a direct call:
//   - web server access: a POSIX ACL written with fsetxattr on directory
//     handles opened without following links and matched to the identities
//     recorded at create (setfacl follows a symlink given as its argument);
//   - disk quota: xfs_quota on the homes filesystem, by numeric UID;
//   - config: every path below the OpenLiteSpeed root is reached through
//     directory handles opened with O_NOFOLLOW, one component at a time, and
//     files are created with O_EXCL|O_NOFOLLOW and renamed into place, so an
//     account that owns one of those directories cannot redirect a root
//     write with a symlink. The config is tested with `openlitespeed -t`,
//     restored on failure, and applied with `systemctl reload lsws`, whose
//     reload is OpenLiteSpeed's graceful restart (`lswsctrl restart`; the
//     broker does not run lswsctrl itself, which packages install as a
//     symlink). New files take their SELinux label from the directory they
//     are created in, so no relabelling is needed.

const (
	olsBinary  = olsweb.ServerRoot + "/bin/openlitespeed"
	systemctl  = "/usr/bin/systemctl"
	olsService = "lsws.service"
	// OpenLiteSpeed's config test and graceful restart are slow on a busy
	// host: one restart took 18 s on the dev VM, past the 15 s every other
	// command gets. Both fit inside webApplyTimeout with the quota commands.
	olsTestTimeout   = 60 * time.Second
	olsReloadTimeout = 120 * time.Second
	xfsQuota         = "/usr/sbin/xfs_quota"
	// The installer adds this line to httpd_config.conf; the broker only
	// checks for it and never edits the server-wide file.
	olsInclude = "include " + olsweb.ServerRoot + "/" + olsweb.ServerConfigPath
	maxOLSFile = 1 << 20
)

var webUtilities = []string{xfsQuota, olsBinary, systemctl}

// POSIX ACL extended attribute format (include/uapi/linux/posix_acl_xattr.h).
const (
	aclVersion   = 2
	aclUserObj   = 0x01
	aclUser      = 0x02
	aclGroupObj  = 0x04
	aclMask      = 0x10
	aclOther     = 0x20
	aclUndefined = 0xffffffff
	aclXattr     = "system.posix_acl_access"
)

// enableWeb admits the web tools and resolves the OpenLiteSpeed user.
func (n *linuxSystem) enableWeb(web *WebOptions) error {
	for _, p := range webUtilities {
		info, e := trustedFile(p, false)
		if e != nil || info.Mode().Perm()&0111 == 0 {
			return ErrUnavailable
		}
		n.tools[p] = info
	}
	users, e := systemUsers()
	if e != nil {
		return ErrUnavailable
	}
	n.webUID = -1
	for _, u := range users {
		if u.Username == web.ServerUser {
			if n.webUID != -1 {
				return ErrUnavailable
			}
			n.webUID = u.UID
		}
	}
	if n.webUID <= 0 {
		return ErrUnavailable
	}
	return nil
}

// webACL is the access ACL for a 0750 directory with one named entry for
// the web server: perm 1 (traverse) on the home, 5 (read and traverse) on
// public_html. The mask equals the group bits, so the mode stays 0750.
func webACL(webUID int, perm uint16) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(aclVersion))
	entry := func(tag, p uint16, id uint32) {
		_ = binary.Write(&b, binary.LittleEndian, tag)
		_ = binary.Write(&b, binary.LittleEndian, p)
		_ = binary.Write(&b, binary.LittleEndian, id)
	}
	entry(aclUserObj, 7, aclUndefined)
	entry(aclUser, perm, uint32(webUID))
	entry(aclGroupObj, 5, aclUndefined)
	entry(aclMask, 5, aclUndefined)
	entry(aclOther, 0, aclUndefined)
	return b.Bytes()
}

// GrantWebAccess sets the ACLs on the home and public_html handles that
// match the identities recorded when the account was created.
func (n *linuxSystem) GrantWebAccess(_ context.Context, r record) error {
	if n.webUID <= 0 {
		return ErrUnavailable
	}
	homes, e := openRootDir(n.opts.HomesDir)
	if e != nil {
		return ErrRecovery
	}
	defer homes.Close()
	home, e := openDirectoryAt(int(homes.Fd()), r.Account.Username)
	if e != nil {
		return ErrRecovery
	}
	defer home.Close()
	if id, e := heldIdentity(home, r.Account.UID, r.Account.GID, 0750); e != nil || id != r.Ownership.Home {
		return ErrRecovery
	}
	public, e := openDirectoryAt(int(home.Fd()), "public_html")
	if e != nil {
		return ErrRecovery
	}
	defer public.Close()
	if id, e := heldIdentity(public, r.Account.UID, r.Account.GID, 0750); e != nil || id != r.Ownership.Public {
		return ErrRecovery
	}
	for _, d := range []struct {
		f    *os.File
		perm uint16
	}{{home, 1}, {public, 5}} {
		want := webACL(n.webUID, d.perm)
		if unix.Fsetxattr(int(d.f.Fd()), aclXattr, want, 0) != nil {
			return ErrUnavailable
		}
		got := make([]byte, 256)
		size, e := unix.Fgetxattr(int(d.f.Fd()), aclXattr, got)
		if e != nil || !bytes.Equal(got[:size], want) {
			return ErrUnavailable
		}
		if _, e := heldIdentity(d.f, r.Account.UID, r.Account.GID, 0750); e != nil {
			return ErrRecovery
		}
	}
	return nil
}

// setQuota sets the hard limit and a soft limit 10% lower; 0 removes both.
func (n *linuxSystem) setQuota(ctx context.Context, uid, hardMiB int) error {
	limit := fmt.Sprintf("limit -u bsoft=%dm bhard=%dm %d", softQuotaMiB(hardMiB), hardMiB, uid)
	_, e := n.command(ctx, xfsQuota, "-x", "-c", limit, n.opts.HomesDir)
	return e
}

func (n *linuxSystem) quotaEnforced(ctx context.Context) bool {
	out, e := n.command(ctx, xfsQuota, "-x", "-c", "state -u", n.opts.HomesDir)
	return e == nil && userQuotaOn(out)
}

// userQuotaOn reads xfs_quota's "state -u" report.
func userQuotaOn(out []byte) bool {
	accounting, enforcement := false, false
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		switch strings.Join(strings.Fields(sc.Text()), " ") {
		case "Accounting: ON":
			accounting = true
		case "Enforcement: ON":
			enforcement = true
		}
	}
	return accounting && enforcement
}

func includesSifruno(main []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(main))
	for sc.Scan() {
		if strings.Join(strings.Fields(sc.Text()), " ") == olsInclude {
			return true
		}
	}
	return false
}

// openRootDir opens a fixed absolute directory without following a final
// link. Its parents are system directories only root can change.
func openRootDir(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), path), nil
}

func ownerOfHandle(f *os.File) (uid, gid int, mode os.FileMode, err error) {
	info, e := f.Stat()
	if e != nil {
		return 0, 0, 0, ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, ErrUnavailable
	}
	return int(st.Uid), int(st.Gid), info.Mode().Perm(), nil
}

// fileMeta is a config file's owner and permission bits, put back with its
// bytes when a change is undone.
type fileMeta struct {
	uid, gid int
	mode     os.FileMode
}

func readAt(dir *os.File, name string) ([]byte, fileMeta, bool, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, fileMeta{}, false, nil
	}
	if e != nil {
		return nil, fileMeta{}, false, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	uid, gid, mode, e := ownerOfHandle(f)
	if e != nil {
		return nil, fileMeta{}, false, ErrUnavailable
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > maxOLSFile {
		return nil, fileMeta{}, false, ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, maxOLSFile+1))
	if e != nil || len(b) > maxOLSFile {
		return nil, fileMeta{}, false, ErrUnavailable
	}
	return b, fileMeta{uid, gid, mode}, true, nil
}

// writeAt replaces dir/name atomically: a new private file created beside it
// (never through a link), given the owner and mode, synced, then renamed
// over it.
func writeAt(dir *os.File, name string, data []byte, meta fileMeta) error {
	tmp := name + ".sifruno-new"
	_ = unix.Unlinkat(int(dir.Fd()), tmp, 0)
	fd, e := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, e = f.Write(data)
	if e == nil {
		e = f.Chown(meta.uid, meta.gid)
	}
	if e == nil {
		e = f.Chmod(meta.mode)
	}
	if e == nil {
		e = f.Sync()
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e == nil {
		e = unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name)
	}
	if e != nil {
		_ = unix.Unlinkat(int(dir.Fd()), tmp, 0)
		return ErrUnavailable
	}
	_ = dir.Sync()
	return nil
}

// configTxn is one config install: the handles it holds and what it changed,
// so a failed test can put everything back.
type configTxn struct {
	handles []*os.File
	files   []fileChange
	dirs    []dirChange
}
type fileChange struct {
	dir     *os.File
	name    string
	old     []byte
	oldMeta fileMeta
	existed bool
}
type dirChange struct {
	parent *os.File
	name   string
}

func (t *configTxn) close() {
	for i := len(t.handles) - 1; i >= 0; i-- {
		_ = t.handles[i].Close()
	}
}

// subdir opens parent/name without following a link, creating it (0750,
// owned as given) if needed; restore removes a directory it created. An
// existing directory keeps its owner and mode and must pass safe, when given.
func (t *configTxn) subdir(parent *os.File, name string, uid, gid int, safe func(uid, gid int, mode os.FileMode) bool) (*os.File, error) {
	created := false
	if e := unix.Mkdirat(int(parent.Fd()), name, 0750); e == nil {
		created = true
	} else if !errors.Is(e, unix.EEXIST) {
		return nil, ErrUnavailable
	}
	d, e := openDirectoryAt(int(parent.Fd()), name)
	if e != nil {
		return nil, ErrUnavailable
	}
	t.handles = append(t.handles, d)
	if created {
		t.dirs = append(t.dirs, dirChange{parent, name})
		if unix.Fchown(int(d.Fd()), uid, gid) != nil || unix.Fchmod(int(d.Fd()), 0750) != nil {
			return nil, ErrUnavailable
		}
		return d, nil
	}
	if safe != nil {
		if u, g, mode, e := ownerOfHandle(d); e != nil || !safe(u, g, mode) {
			return nil, ErrUnavailable
		}
	}
	return d, nil
}

// write replaces dir/name with data (owner and mode from meta) and returns
// whether the bytes changed.
func (t *configTxn) write(dir *os.File, name string, data []byte, meta fileMeta) (bool, error) {
	old, oldMeta, existed, e := readAt(dir, name)
	if e != nil {
		return false, e
	}
	if existed && bytes.Equal(old, data) {
		return false, nil
	}
	t.files = append(t.files, fileChange{dir, name, old, oldMeta, existed})
	return true, writeAt(dir, name, data, meta)
}

func (t *configTxn) remove(dir *os.File, name string) error {
	old, oldMeta, existed, e := readAt(dir, name)
	if e != nil || !existed {
		return e
	}
	t.files = append(t.files, fileChange{dir, name, old, oldMeta, true})
	if unix.Unlinkat(int(dir.Fd()), name, 0) != nil {
		return ErrUnavailable
	}
	return nil
}

// restore undoes the changes in reverse order and reports any it could not.
func (t *configTxn) restore() error {
	var failed error
	for i := len(t.files) - 1; i >= 0; i-- {
		c := t.files[i]
		var e error
		if c.existed {
			e = writeAt(c.dir, c.name, c.old, c.oldMeta)
		} else if e = unix.Unlinkat(int(c.dir.Fd()), c.name, 0); errors.Is(e, unix.ENOENT) {
			e = nil
		}
		if e != nil {
			failed = ErrRecovery
		}
	}
	for i := len(t.dirs) - 1; i >= 0; i-- {
		if e := unix.Unlinkat(int(t.dirs[i].parent.Fd()), t.dirs[i].name, unix.AT_REMOVEDIR); e != nil && !errors.Is(e, unix.ENOENT) {
			failed = ErrRecovery
		}
	}
	return failed
}

// configDirSafe reports whether the web server's user cannot change a config
// directory: it does not own it, others cannot write it, and its group may
// write only if that group is root's.
func (n *linuxSystem) configDirSafe(uid, gid int, mode os.FileMode) bool {
	return uid != n.webUID && mode&0002 == 0 && (mode&0020 == 0 || gid == 0)
}

// writeSites renders the site list and installs it below the OpenLiteSpeed
// root as part of t: changed files are replaced atomically and broker vhosts
// no longer listed lose their config file. When a site has a certificate it
// first makes sure the HTTPS listener's own certificate exists. It returns
// the vhosts whose config bytes changed, so the test can tell this change's
// problems from a tenant's. On an error the caller restores t.
func (n *linuxSystem) writeSites(t *configTxn, sites []olsweb.Site) (map[string]bool, error) {
	files, e := olsweb.Render(webServer(sites))
	if e != nil {
		return nil, ErrWebRejected
	}
	changed := map[string]bool{}
	fail := func(err error) (map[string]bool, error) { return nil, err }
	if anyCertificate(sites) {
		if e := n.ensureListenerCertificate(t); e != nil {
			return fail(e)
		}
	}
	root, e := openRootDir(olsweb.ServerRoot)
	if e != nil {
		return fail(ErrUnavailable)
	}
	t.handles = append(t.handles, root)
	if uid, _, mode, e := ownerOfHandle(root); e != nil || uid != 0 || mode&0022 != 0 {
		return fail(ErrUnavailable)
	}
	conf, e := openDirectoryAt(int(root.Fd()), "conf")
	if e != nil {
		return fail(ErrUnavailable)
	}
	t.handles = append(t.handles, conf)
	confUID, confGID, confMode, e := ownerOfHandle(conf)
	// The web server's user must not be able to change the server config.
	if e != nil || !n.configDirSafe(confUID, confGID, confMode) {
		return fail(ErrUnavailable)
	}
	private := fileMeta{confUID, confGID, 0600}
	main, _, ok, e := readAt(conf, "httpd_config.conf")
	if e != nil || !ok || !includesSifruno(main) {
		return fail(ErrWebRejected)
	}
	logs, e := openDirectoryAt(int(root.Fd()), "logs")
	if e != nil {
		return fail(ErrUnavailable)
	}
	t.handles = append(t.handles, logs)
	logUID, logGID, _, e := ownerOfHandle(logs)
	if e != nil {
		return fail(ErrUnavailable)
	}
	vhosts, e := t.subdir(conf, "vhosts", confUID, confGID, n.configDirSafe)
	if e != nil {
		return fail(e)
	}
	// Log directories are not checked: OpenLiteSpeed may own its own, and
	// the broker writes no file in them, only makes the directories.
	logRoot, e := t.subdir(logs, strings.TrimPrefix(olsweb.LogRoot, olsweb.ServerRoot+"/logs/"), logUID, logGID, nil)
	if e != nil {
		return fail(e)
	}
	want := map[string]bool{}
	for _, s := range sites {
		dir := olsweb.NamePrefix + s.Name
		want[dir] = true
		vhost, e := t.subdir(vhosts, dir, confUID, confGID, n.configDirSafe)
		if e != nil {
			return fail(e)
		}
		if _, e := t.subdir(logRoot, s.Name, logUID, logGID, nil); e != nil {
			return fail(e)
		}
		wrote, e := t.write(vhost, "vhconf.conf", files[olsweb.VhostConfigPath(s.Name)], private)
		if e != nil {
			return fail(e)
		}
		changed[dir] = wrote
	}
	entries, e := vhosts.ReadDir(-1)
	if e != nil {
		return fail(ErrUnavailable)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), olsweb.NamePrefix) && !want[entry.Name()] && entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		stale, e := openDirectoryAt(int(vhosts.Fd()), name)
		if e != nil {
			return fail(ErrUnavailable)
		}
		t.handles = append(t.handles, stale)
		if e := t.remove(stale, "vhconf.conf"); e != nil {
			return fail(e)
		}
	}
	// The server fragment that names the vhosts goes last.
	if _, e := t.write(conf, strings.TrimPrefix(olsweb.ServerConfigPath, "conf/"), files[olsweb.ServerConfigPath], private); e != nil {
		return fail(e)
	}
	return changed, nil
}

// configTest runs `openlitespeed -t` and judges it with olsTestPasses.
func (n *linuxSystem) configTest(ctx context.Context, changed map[string]bool) error {
	out, code, e := n.commandStatus(ctx, olsTestTimeout, olsBinary, "-t")
	if e != nil || !olsTestPasses(out, code, changed) {
		return ErrWebRejected
	}
	return nil
}

// olsTestPasses reads `openlitespeed -t`, which exits 2 after an [ERROR] and
// 1 after any other message (the stock Example vhost always warns). Lines
// look like "DATE TIME [WARN] [PID] [config:server:vhosts:vhost:NAME] text";
// the bracketed context comes from the server, not from a tenant's files.
//
// A broker vhost whose config this change did not rewrite is skipped: what
// it reports comes from its tenant's own files (a public_html removed or
// swapped), and one tenant must not block another account's change. A
// rewritten broker vhost fails on an error or a warning, anything else on
// an error, and an exit status the lines do not explain fails too.
func olsTestPasses(out []byte, code int, changed map[string]bool) bool {
	if code < 0 || code > 2 {
		return false
	}
	errorLines := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		level := -1
		for i, f := range fields {
			if f == "[ERROR]" || f == "[WARN]" {
				level = i
				break
			}
		}
		if level < 0 {
			continue
		}
		isError := fields[level] == "[ERROR]"
		if isError {
			errorLines++
		}
		vhost := ""
		if level+2 < len(fields) {
			vhost = olsContextVhost(fields[level+2])
		}
		switch {
		case strings.HasPrefix(vhost, olsweb.NamePrefix):
			if changed[vhost] {
				return false
			}
		case isError:
			return false
		}
	}
	return code != 2 || errorLines > 0
}

// olsContextVhost returns NAME from a "[...:vhost:NAME...]" context, or "".
func olsContextVhost(context string) string {
	if !strings.HasPrefix(context, "[") || !strings.HasSuffix(context, "]") {
		return ""
	}
	i := strings.LastIndex(context, ":vhost:")
	if i < 0 {
		return ""
	}
	name := context[i+len(":vhost:") : len(context)-1]
	if j := strings.IndexAny(name, ":]"); j >= 0 {
		name = name[:j]
	}
	return name
}

// installSites writes and tests the config, then reloads; a failed test puts
// the old files back and returns ErrWebRejected (ErrRecovery if that fails).
func (n *linuxSystem) installSites(ctx context.Context, sites []olsweb.Site) error {
	return n.installWith(ctx, &configTxn{}, sites, "")
}

// installWith completes t, which may already hold a site's certificate
// files, with the rendered config, tests it and reloads. A failed write or
// test puts back everything t changed and returns the error (ErrRecovery if
// that fails). touched names a vhost whose certificate t rewrote, so the
// test judges it as changed even when its vhconf.conf bytes are the same.
func (n *linuxSystem) installWith(ctx context.Context, t *configTxn, sites []olsweb.Site, touched string) error {
	defer t.close()
	changed, e := n.writeSites(t, sites)
	if e == nil {
		if touched != "" {
			changed[touched] = true
		}
		e = n.configTest(ctx, changed)
	}
	if e != nil {
		if r := t.restore(); r != nil {
			return r
		}
		return e
	}
	if _, e = n.commandWithin(ctx, olsReloadTimeout, systemctl, "reload", olsService); e != nil {
		return ErrUnavailable
	}
	return nil
}

func (n *linuxSystem) ApplyWeb(ctx context.Context, r record, previous, next WebState, sites []olsweb.Site) error {
	if n.webUID <= 0 || !validWebState(next) {
		return ErrUnavailable
	}
	// Nothing has changed yet, so this refusal leaves the account as it was.
	if !n.quotaEnforced(ctx) {
		return ErrWebRejected
	}
	if e := n.setQuota(ctx, r.Account.UID, next.QuotaMiB); e != nil {
		return e
	}
	e := n.installSites(ctx, sites)
	if errors.Is(e, ErrWebRejected) {
		// The broker owns its accounts' quotas: a rejected change goes back
		// to the recorded one, and a first enable to none. A quota read back
		// here could already be the new one when this is a recovery.
		if n.setQuota(ctx, r.Account.UID, previous.QuotaMiB) != nil {
			return ErrRecovery
		}
	}
	return e
}

func (n *linuxSystem) ApplySites(ctx context.Context, sites []olsweb.Site) error {
	if n.webUID <= 0 {
		return ErrUnavailable
	}
	return n.installSites(ctx, sites)
}
