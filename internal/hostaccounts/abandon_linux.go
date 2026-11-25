//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// groupdelPath removes the private group a create made when userdel left
// it, or when useradd never ran (AbandonCreate). It is shadow-utils' own,
// from the same package as groupadd.
const groupdelPath = "/usr/sbin/groupdel"

// AbandonCreate removes what an unfinished create of r made, and nothing
// else, so the store can end the create. It checks everything first, and
// answers an *AbandonRefusedError, having changed nothing, when what it
// finds is not provably the create's own:
//
//   - the ownership marker, which the create writes and records before
//     groupadd, is the recorded one whenever a user, group, home or mail
//     spool is there;
//   - a user with the account's name or UID is the only one, with the
//     journaled UID, GID, tag, home and nologin shell (createdUser);
//   - a group with the account's name or GID is its private group alone
//     (createdGroup), and is there whenever the user is;
//   - the home, directly in the homes directory and not a link, is the one
//     recorded, or (the user there to prove it) one useradd made for it
//     (createdHome), and holds nothing but the empty public_html the broker
//     made (abandonedHome);
//   - the mail spool is a regular file of the account's, or root's as
//     useradd makes it before its chown.
//
// It then records the home's identity (persist), so a run stopped half way
// still knows it, and removes as a delete does: the user (its processes
// ended first; a user still busy is refused, nothing removed), the group if
// userdel left it, the home, the spool, and the marker last. What is
// already gone counts as removed, so it can run again. A failure half way
// is an error, not a refusal: the create stays unfinished.
func (n *linuxSystem) AbandonCreate(ctx context.Context, r record, persist func(ownership) error) error {
	name, uid, gid := r.Account.Username, r.Account.UID, r.Account.GID
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if !validUsername(name) || !idPattern.MatchString(r.Account.ID) || uid < firstAccountID || uid > lastAccountID || gid != uid || uid == int(n.opts.ControllerUID) || r.Account.Home != filepath.Join(n.opts.HomesDir, name) {
		return atStep("record", ErrRecovery)
	}
	if supportedNSS() != nil || supportedUseraddDefaults() != nil {
		return atStep("host policy", ErrUnavailable)
	}
	if authority(n.opts.HomesDir) != nil {
		return atStep("homes folder", ErrRecovery)
	}
	markerPath := n.markerPath(r)
	marked := false
	if _, e := os.Lstat(markerPath); e == nil {
		mark, e := markerIdentity(markerPath, r.Tag)
		if e != nil || r.Ownership.Marker.Ino != 0 && mark != r.Ownership.Marker {
			return abandonRefused(AbandonMarker)
		}
		marked = r.Ownership.Marker.Ino != 0
	} else if !errors.Is(e, os.ErrNotExist) {
		return atStep("marker", ErrUnavailable)
	}
	db, e := n.database()
	if e != nil {
		return atStep("passwd and group", e)
	}
	userThere, e := createdUser(db, r)
	if e != nil {
		return e
	}
	groupThere, e := createdGroup(db, r)
	if e != nil {
		return e
	}
	if userThere && !groupThere {
		return abandonRefused(AbandonGroup)
	}
	spool := filepath.Join(n.mailDir, name)
	spoolThere := false
	if info, e := os.Lstat(spool); e == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || !(int(st.Uid) == uid || st.Uid == 0) {
			return abandonRefused(AbandonMailSpool)
		}
		spoolThere = true
	} else if !errors.Is(e, os.ErrNotExist) && !errors.Is(e, syscall.ENOTDIR) {
		return atStep("mail spool", ErrUnavailable)
	}
	parent, e := openDirectoryAt(unix.AT_FDCWD, n.opts.HomesDir)
	if e != nil {
		return atStep("homes folder", e)
	}
	defer parent.Close()
	var home, public *os.File
	owned := r.Ownership
	var st unix.Stat_t
	switch e := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(e, unix.ENOENT):
	case e != nil:
		return atStep("home", ErrUnavailable)
	default:
		home, public, owned, e = abandonedHome(parent, r, userThere)
		if e != nil {
			return e
		}
		defer home.Close()
		if public != nil {
			defer public.Close()
		}
	}
	if !marked && (userThere || groupThere || home != nil || spoolThere) {
		return abandonRefused(AbandonMarker)
	}
	if owned != r.Ownership {
		if persist(owned) != nil {
			return atStep("record", ErrRecovery)
		}
		r.Ownership = owned
	}

	if userThere {
		// The user never was active: its password is locked and its shell
		// nologin, so there is nothing to lock first or put back.
		e := userRemoval{
			lock:    func(context.Context) error { return nil },
			end:     func(ctx context.Context) error { return n.EndProcesses(ctx, r) },
			userdel: func(ctx context.Context) (int, error) { return n.userdel(ctx, r) },
			putBack: func(context.Context) error { return nil },
		}.run(ctx, processBudget)
		switch {
		case errors.Is(e, errAccountBusy):
			return abandonRefused(AbandonProcesses)
		case e != nil:
			return atStep("remove user", e)
		}
	}
	if groupThere {
		db, e := n.database()
		if e != nil {
			return atStep("groupdel", e)
		}
		left, e := createdGroup(db, r)
		if e != nil {
			return atStep("groupdel", ErrRecovery)
		}
		if left {
			if _, e := n.command(ctx, groupdelPath, "--", name); e != nil {
				return atStep("groupdel", e)
			}
		}
	}
	if home != nil {
		if public != nil {
			if e := removeHeldDirectory(home, "public_html", r.Ownership.Public); e != nil {
				return atStep("public_html", e)
			}
		}
		if e := removeHeldDirectory(parent, name, r.Ownership.Home); e != nil {
			return atStep("home", e)
		}
	}
	if e := removeRegular(spool, uid, true); e != nil {
		return atStep("mail spool", e)
	}
	if e := os.Remove(markerPath); e != nil && !errors.Is(e, os.ErrNotExist) {
		return atStep("marker", ErrUnavailable)
	}
	return nil
}

// createdUser reports whether passwd shows the user a create of r made:
// the only user with the account's name and the only one on its UID, with
// the journaled UID, GID, tag, home and the nologin shell. Any other user
// with that name or UID is refused.
func createdUser(db *accountDatabase, r record) (bool, error) {
	named, onUID := db.usersByName[r.Account.Username], db.usersByUID[r.Account.UID]
	if len(named) == 0 && len(onUID) == 0 {
		return false, nil
	}
	if len(named) == 1 && len(onUID) == 1 {
		u := named[0]
		if u.UID == r.Account.UID && u.GID == r.Account.GID && u.Tag == r.Tag && u.Home == r.Account.Home && u.Shell == nologin {
			return true, nil
		}
	}
	return false, abandonRefused(AbandonUser)
}

// createdGroup reports whether group shows the private group a create of r
// made: the only group with the account's name and the only one on its GID,
// with the journaled GID, no members, the account a member of no group,
// and no other user's primary group. Any other group with that name or GID
// is refused.
func createdGroup(db *accountDatabase, r record) (bool, error) {
	named, onGID := db.groupsByName[r.Account.Username], db.groupsByGID[r.Account.GID]
	if len(named) == 0 && len(onGID) == 0 {
		return false, nil
	}
	if len(named) != 1 || len(onGID) != 1 || named[0].GID != r.Account.GID || named[0].Members != "" || db.memberOfAny[r.Account.Username] {
		return false, abandonRefused(AbandonGroup)
	}
	for _, users := range db.usersByName {
		for _, u := range users {
			if u.GID == r.Account.GID && u.Username != r.Account.Username {
				return false, abandonRefused(AbandonGroup)
			}
		}
	}
	return true, nil
}

// abandonedHome opens r's home in the homes directory parent, and its
// public_html if there is one, and answers both held open with the
// ownership that records them. It is refused unless the home, on the homes
// filesystem and not a link, is the one recorded, or (the create's user
// there to prove it) one useradd made for that user (createdHome), and
// holds nothing but an empty public_html that is the one recorded or, not
// recorded yet, root's as the broker makes it before its chown.
func abandonedHome(parent *os.File, r record, userThere bool) (home, public *os.File, owned ownership, err error) {
	owned = r.Ownership
	home, e := openDirectoryAt(int(parent.Fd()), r.Account.Username)
	if e != nil {
		return nil, nil, owned, abandonRefused(AbandonHome)
	}
	defer func() {
		if err != nil {
			home.Close()
			if public != nil {
				public.Close()
			}
			home, public = nil, nil
		}
	}()
	var p, h unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &p) != nil || unix.Fstat(int(home.Fd()), &h) != nil {
		return home, nil, owned, atStep("home", ErrUnavailable)
	}
	id := fileIdentity{uint64(h.Dev), h.Ino}
	switch {
	case h.Dev != p.Dev:
		return home, nil, owned, abandonRefused(AbandonHome)
	case owned.Home.Ino != 0:
		if owned.Home != id {
			return home, nil, owned, abandonRefused(AbandonHome)
		}
	case userThere:
		made, _, e := createdHome(parent, home, r)
		if e != nil || made != id {
			return home, nil, owned, abandonRefused(AbandonHome)
		}
		owned.Home = id
	default:
		return home, nil, owned, abandonRefused(AbandonHome)
	}
	names, e := entryNames(home, 2)
	if e != nil {
		return home, nil, owned, atStep("home", e)
	}
	if len(names) == 0 {
		return home, nil, owned, nil
	}
	if len(names) > 1 || names[0] != "public_html" {
		return home, nil, owned, abandonRefused(AbandonHomeNotEmpty)
	}
	public, e = openDirectoryAt(int(home.Fd()), "public_html")
	if e != nil {
		return home, nil, owned, abandonRefused(AbandonHomeNotEmpty)
	}
	var s unix.Stat_t
	if unix.Fstat(int(public.Fd()), &s) != nil {
		return home, public, owned, atStep("public_html", ErrUnavailable)
	}
	publicID := fileIdentity{uint64(s.Dev), s.Ino}
	if s.Dev != h.Dev || owned.Public.Ino != 0 && owned.Public != publicID || owned.Public.Ino == 0 && (s.Uid != 0 || s.Gid != 0) {
		return home, public, owned, abandonRefused(AbandonHomeNotEmpty)
	}
	if names, e = entryNames(public, 1); e != nil || len(names) != 0 {
		return home, public, owned, abandonRefused(AbandonHomeNotEmpty)
	}
	owned.Public = publicID
	return home, public, owned, nil
}

// entryNames lists up to max names in the directory dir holds open, through
// a handle of its own, so dir's offset does not move.
func entryNames(dir *os.File, max int) ([]string, error) {
	list, e := openDirectoryAt(int(dir.Fd()), ".")
	if e != nil {
		return nil, ErrUnavailable
	}
	defer list.Close()
	names, e := list.Readdirnames(max)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, ErrUnavailable
	}
	return names, nil
}

// removeHeldDirectory removes the directory name in parent when it is
// still the one with identity id. rmdir removes only an empty one.
func removeHeldDirectory(parent *os.File, name string, id fileIdentity) error {
	var st unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (fileIdentity{uint64(st.Dev), st.Ino}) != id {
		return ErrRecovery
	}
	if unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR) != nil {
		return ErrUnavailable
	}
	return nil
}
