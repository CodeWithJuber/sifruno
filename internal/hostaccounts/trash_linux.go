//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// trashName is the folder in the homes directory a delete moves a home into,
// as <homes>/.sifruno-trash/<account ID>, so the delete answers at once
// however many files the home holds; the trash remover empties it in the
// background, outside the store lock. It is not a username (validUsername
// refuses a leading dot), so no account's home can have its name.
const trashName = ".sifruno-trash"

// trashRetry is how often the remover tries again while entries remain: a
// folder on another device, or a removal that failed.
const trashRetry = 10 * time.Minute

var (
	// errNoTrash: the homes directory has no trash folder, and none was to
	// be made.
	errNoTrash = errors.New("no trash folder")
	// errOtherDevice: a folder in a trash entry is on another device or
	// mount, which the remover never enters.
	errOtherDevice = errors.New("a folder on another device or mount")
	// errTrashChanged: a folder the remover walked is no longer where it
	// was (its ".." or its name now names another folder).
	errTrashChanged = errors.New("a folder in the trash moved")
)

// fileOwner is the owner the trash must have: root in the broker, a test's
// own user in tests.
type fileOwner struct{ uid, gid uint32 }

var rootOwner = fileOwner{0, 0}

// trashIn opens the trash folder in the homes directory homes holds: a
// directory named trashName, not a link, of owner's with mode 0700, on the
// homes directory's filesystem. With create it makes a missing one through
// the handle and gives it that owner and mode, whatever the umask or the
// homes directory's group. Anything else there is refused (ErrRecovery):
// the broker never moves a home into, or removes from, a folder that is
// not its own. errNoTrash: none there and create is false.
func trashIn(homes *os.File, create bool, owner fileOwner) (*os.File, error) {
	hfd := int(homes.Fd())
	var h, st unix.Stat_t
	if unix.Fstat(hfd, &h) != nil {
		return nil, ErrUnavailable
	}
	made := false
	switch e := unix.Fstatat(hfd, trashName, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(e, unix.ENOENT):
		if !create {
			return nil, errNoTrash
		}
		switch e := unix.Mkdirat(hfd, trashName, 0700); {
		case e == nil:
			made = true
		case !errors.Is(e, unix.EEXIST):
			return nil, ErrUnavailable
		}
	case e != nil:
		return nil, ErrUnavailable
	}
	trash, e := openDirectoryAt(hfd, trashName)
	if e != nil {
		return nil, ErrRecovery
	}
	tfd := int(trash.Fd())
	if made && (unix.Fchown(tfd, int(owner.uid), int(owner.gid)) != nil || unix.Fchmod(tfd, 0700) != nil) {
		trash.Close()
		return nil, ErrUnavailable
	}
	var t unix.Stat_t
	if unix.Fstat(tfd, &t) != nil || t.Mode&unix.S_IFMT != unix.S_IFDIR || t.Uid != owner.uid || t.Gid != owner.gid || t.Mode&07777 != 0700 || t.Dev != h.Dev {
		trash.Close()
		return nil, ErrRecovery
	}
	return trash, nil
}

// homeIs reports whether st is r's recorded home: a directory with the
// recorded device and inode, of the account's UID and GID. Its mode is the
// account's own to change and is not judged.
func homeIs(st unix.Stat_t, r record) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && uint64(st.Dev) == r.Ownership.Home.Dev && st.Ino == r.Ownership.Home.Ino && int(st.Uid) == r.Account.UID && int(st.Gid) == r.Account.GID
}

// detachHome moves r's home, by its name in the homes directory homes
// holds, into the trash as the account's ID: renameat2 between the two
// held handles with RENAME_NOREPLACE, so no link is followed and nothing in
// the trash is replaced. The home must be the recorded one before the move
// and the entry in the trash the same after it (homeIs); both folders are
// synced. A home that is not there counts as moved: a delete stopped after
// its move finds it in the trash already. ErrRecovery: the home is not the
// recorded one, or the trash holds an entry with the account's ID; nothing
// was moved.
func detachHome(homes, trash *os.File, r record) error {
	hfd, tfd := int(homes.Fd()), int(trash.Fd())
	if !validUsername(r.Account.Username) || !idPattern.MatchString(r.Account.ID) {
		return ErrRecovery
	}
	var st unix.Stat_t
	switch e := unix.Fstatat(hfd, r.Account.Username, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(e, unix.ENOENT):
		return nil
	case e != nil:
		return ErrUnavailable
	}
	if !homeIs(st, r) {
		return ErrRecovery
	}
	switch e := unix.Renameat2(hfd, r.Account.Username, tfd, r.Account.ID, unix.RENAME_NOREPLACE); {
	case errors.Is(e, unix.EEXIST):
		return ErrRecovery
	case e != nil:
		return ErrUnavailable
	}
	var moved unix.Stat_t
	if unix.Fstatat(tfd, r.Account.ID, &moved, unix.AT_SYMLINK_NOFOLLOW) != nil || !homeIs(moved, r) {
		return ErrRecovery
	}
	if unix.Fsync(tfd) != nil || unix.Fsync(hfd) != nil {
		return ErrUnavailable
	}
	return nil
}

// trashOwners answers every UID and GID that owns an entry of the trash in
// the homes directory homes holds. Plan never hands one of them out, so the
// files a deleted account left in the trash never count against a new
// account's quota. No trash: none.
func trashOwners(homes *os.File, owner fileOwner) (map[int]bool, error) {
	trash, e := trashIn(homes, false, owner)
	if errors.Is(e, errNoTrash) {
		return map[int]bool{}, nil
	}
	if e != nil {
		return nil, e
	}
	defer trash.Close()
	names, e := entryNames(trash, -1)
	if e != nil {
		return nil, e
	}
	ids := map[int]bool{}
	for _, name := range names {
		var st unix.Stat_t
		switch e := unix.Fstatat(int(trash.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); {
		case errors.Is(e, unix.ENOENT):
			// Removed meanwhile by the remover.
			continue
		case e != nil:
			return nil, ErrUnavailable
		}
		ids[int(st.Uid)], ids[int(st.Gid)] = true, true
	}
	return ids, nil
}

// entryStat is what the remover reads of an entry, without following a
// link: its type, device, inode and mount.
type entryStat struct {
	mode     uint16
	dev, ino uint64
	mnt      uint64
	mntKnown bool
}

func (e entryStat) dir() bool { return e.mode&unix.S_IFMT == unix.S_IFDIR }

// statEntry reads name in the folder fd holds (name "": that folder) with
// statx, never following a link. The mount ID is known on Linux 5.8 and
// later (AlmaLinux 9 runs 5.14); a mount of the same device shows only in it.
func statEntry(fd int, name string) (entryStat, error) {
	flags := unix.AT_SYMLINK_NOFOLLOW | unix.AT_STATX_SYNC_AS_STAT
	if name == "" {
		flags |= unix.AT_EMPTY_PATH
	}
	var x unix.Statx_t
	if e := unix.Statx(fd, name, flags, unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID, &x); e != nil {
		return entryStat{}, e
	}
	if x.Mask&(unix.STATX_TYPE|unix.STATX_INO) != unix.STATX_TYPE|unix.STATX_INO {
		return entryStat{}, ErrUnavailable
	}
	return entryStat{mode: x.Mode, dev: unix.Mkdev(x.Dev_major, x.Dev_minor), ino: x.Ino, mnt: x.Mnt_id, mntKnown: x.Mask&unix.STATX_MNT_ID != 0}, nil
}

// trashRemover empties the trash in the background, outside the store
// lock, so a delete answers at once and no other account waits for it. It
// runs when the broker starts, after each delete (wake), and every
// trashRetry while entries remain. It starts only from entries named as
// account IDs, and logs by account ID only: never a name from a tenant's
// files.
type trashRemover struct {
	homes  string
	owner  fileOwner
	guard  func(string) error
	retry  time.Duration
	wakeup chan struct{}
	// stat reads every entry before the remover acts on it: statEntry in
	// the broker; a test wraps it to count descriptors, stop or hold the
	// remover, or show a mount.
	stat func(fd int, name string) (entryStat, error)
}

// newTrashRemover is the broker's remover of the trash in homes, which
// authority must accept (root's, and writable by root alone, up to /).
func newTrashRemover(homes string) *trashRemover {
	return &trashRemover{homes: homes, owner: rootOwner, guard: authority, retry: trashRetry, wakeup: make(chan struct{}, 1), stat: statEntry}
}

// wake asks the remover to run again soon; it never waits.
func (t *trashRemover) wake() {
	select {
	case t.wakeup <- struct{}{}:
	default:
	}
}

// run removes the trash's entries until ctx ends: now, on every wake, and
// every retry while entries remain.
func (t *trashRemover) run(ctx context.Context) {
	for {
		left := t.drain(ctx)
		var retry <-chan time.Time
		var timer *time.Timer
		if left {
			timer = time.NewTimer(t.retry)
			retry = timer.C
		}
		select {
		case <-ctx.Done():
		case <-t.wakeup:
		case <-retry:
		}
		if timer != nil {
			timer.Stop()
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// drain removes every trash entry named as an account ID, and reports
// whether entries remain: one it could not remove, or the time ran out.
func (t *trashRemover) drain(ctx context.Context) (left bool) {
	if ctx.Err() != nil {
		return true
	}
	if t.guard(t.homes) != nil {
		logCleanup("-", "empty the trash: the homes folder", ErrRecovery)
		return true
	}
	homes, e := openDirectoryAt(unix.AT_FDCWD, t.homes)
	if e != nil {
		logCleanup("-", "empty the trash: the homes folder", e)
		return true
	}
	defer homes.Close()
	trash, e := trashIn(homes, false, t.owner)
	if errors.Is(e, errNoTrash) {
		return false
	}
	if e != nil {
		logCleanup("-", "empty the trash: "+trashName+" is not the broker's own folder", e)
		return true
	}
	defer trash.Close()
	names, e := entryNames(trash, -1)
	if e != nil {
		logCleanup("-", "empty the trash: list it", e)
		return true
	}
	other := false
	for _, name := range names {
		if ctx.Err() != nil {
			return true
		}
		if !idPattern.MatchString(name) {
			other = true
			continue
		}
		switch e := t.removeEntry(ctx, int(trash.Fd()), name); {
		case e == nil:
		case ctx.Err() != nil:
			return true
		case errors.Is(e, errOtherDevice):
			logCleanup(name, "empty the trash: a folder on another device or mount is left in it", e)
			left = true
		default:
			logCleanup(name, "empty the trash", e)
			left = true
		}
	}
	if other {
		logCleanup("-", "empty the trash: an entry not named as an account ID is left", ErrRecovery)
	}
	return left
}

// removeEntry removes the trash entry name, which the trash fd holds, and
// everything in it, without following a link. A folder on another device
// or mount is never entered: the entry is left (errOtherDevice).
func (t *trashRemover) removeEntry(ctx context.Context, trash int, name string) error {
	top, e := t.stat(trash, name)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return ErrUnavailable
	}
	if !top.dir() {
		// Only homes are moved in; anything else goes as it is.
		if e := unix.Unlinkat(trash, name, 0); e != nil && !errors.Is(e, unix.ENOENT) {
			return ErrUnavailable
		}
		return nil
	}
	root, e := statEntry(trash, "")
	if e != nil {
		return ErrUnavailable
	}
	if top.dev != root.dev || top.mntKnown && root.mntKnown && top.mnt != root.mnt {
		return errOtherDevice
	}
	// A folder a read missed an entry of (one added or listed while it was
	// being emptied) is not empty at its removal: walk it again, a few
	// times, then leave it for the next run.
	for try := 0; ; try++ {
		e = t.removeTree(ctx, trash, name, top)
		if !errors.Is(e, unix.ENOTEMPTY) || try == 2 {
			return e
		}
	}
}

// trashFrame is a folder the walk entered: its name in its parent, its
// identity, and whether it keeps a folder on another device or mount (kept)
// and so stays. The walk keeps one per level (memory grows with depth, open
// descriptors do not).
type trashFrame struct {
	name     string
	dev, ino uint64
	kept     bool
}

// removeTree empties and removes the folder name in the folder trash holds,
// whose stat is top, walking it by directory handles: it holds one handle
// at a time (two while it changes level), opens each folder with O_NOFOLLOW
// and O_DIRECTORY and checks it is the entry it read, unlinks every other
// entry by name, never follows a link, and steps up through "..", checked
// against the identity of the folder it came from. A folder that moved
// meanwhile stops it (errTrashChanged); the entry stays for the next run.
// A folder on another device or mount is never entered: it and the folders
// above it stay, everything else goes, and the entry is left
// (errOtherDevice). ctx is checked before every entry, and a removal
// stopped by it is resumed by the next run from what is left.
func (t *trashRemover) removeTree(ctx context.Context, trash int, name string, top entryStat) error {
	cur, e := t.enter(trash, name, top)
	if e != nil {
		return e
	}
	defer func() {
		if cur >= 0 {
			unix.Close(cur)
		}
	}()
	path := []trashFrame{{name, top.dev, top.ino, false}}
	// kept holds the identities of the folders that stay: those on another
	// device or mount and the folders above them, so a read again skips them.
	kept := map[[2]uint64]bool{}
	buf := make([]byte, 8192)
	for {
		n, e := unix.Getdents(cur, buf)
		if e != nil {
			return ErrUnavailable
		}
		if n > 0 {
			// A folder entered is read from its start; otherwise the read
			// goes on where it was.
			_, _, names := unix.ParseDirent(buf[:n], -1, nil)
			for _, child := range names {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				st, e := t.stat(cur, child)
				if errors.Is(e, unix.ENOENT) {
					continue
				}
				if e != nil {
					return ErrUnavailable
				}
				if !st.dir() {
					if e := unix.Unlinkat(cur, child, 0); e != nil && !errors.Is(e, unix.ENOENT) {
						return ErrUnavailable
					}
					continue
				}
				if kept[[2]uint64{st.dev, st.ino}] {
					continue
				}
				if st.dev != top.dev || st.mntKnown && top.mntKnown && st.mnt != top.mnt {
					kept[[2]uint64{st.dev, st.ino}] = true
					path[len(path)-1].kept = true
					continue
				}
				next, e := t.enter(cur, child, st)
				if e != nil {
					return e
				}
				unix.Close(cur)
				cur = next
				path = append(path, trashFrame{child, st.dev, st.ino, false})
				break
			}
			continue
		}
		// cur is empty: step up and remove it by name.
		done := path[len(path)-1]
		if len(path) == 1 {
			unix.Close(cur)
			cur = -1
			if done.kept {
				return errOtherDevice
			}
			return removeEmptied(trash, done)
		}
		up, e := unix.Openat(cur, "..", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if e != nil {
			return ErrUnavailable
		}
		parent := path[len(path)-2]
		if st, e := statEntry(up, ""); e != nil || st.dev != parent.dev || st.ino != parent.ino {
			unix.Close(up)
			return errTrashChanged
		}
		unix.Close(cur)
		cur = up
		path = path[:len(path)-1]
		if done.kept {
			kept[[2]uint64{done.dev, done.ino}] = true
			path[len(path)-1].kept = true
			continue
		}
		if e := removeEmptied(cur, done); e != nil && !errors.Is(e, unix.ENOTEMPTY) {
			return e
		}
		// cur is a new handle: it is read again from its start, where only
		// what is left of it remains.
	}
}

// enter opens the folder name in the folder parent holds, without
// following a link, and checks it is the entry st read.
func (t *trashRemover) enter(parent int, name string, st entryStat) (int, error) {
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, ErrUnavailable
	}
	opened, e := statEntry(fd, "")
	if e != nil || opened.dev != st.dev || opened.ino != st.ino || st.mntKnown && opened.mntKnown && opened.mnt != st.mnt {
		unix.Close(fd)
		return -1, errTrashChanged
	}
	return fd, nil
}

// removeEmptied removes the folder f names in the folder parent holds, once
// it is still that folder. A folder gone already is removed; one not empty
// (something was added through a handle a process kept) answers ENOTEMPTY,
// and the walk reads it again.
func removeEmptied(parent int, f trashFrame) error {
	st, e := statEntry(parent, f.name)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return ErrUnavailable
	}
	if !st.dir() || st.dev != f.dev || st.ino != f.ino {
		return errTrashChanged
	}
	switch e := unix.Unlinkat(parent, f.name, unix.AT_REMOVEDIR); {
	case e == nil, errors.Is(e, unix.ENOENT):
		return nil
	case errors.Is(e, unix.ENOTEMPTY):
		return unix.ENOTEMPTY
	default:
		return ErrUnavailable
	}
}
