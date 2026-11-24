//go:build linux

package hostaccounts

import (
	"context"

	"golang.org/x/sys/unix"
)

// AdoptPublicHTML opens the homes directory, the account's home and its
// current public_html one component at a time with O_NOFOLLOW|O_DIRECTORY,
// so a link or a file named public_html is refused, not followed. The home
// must be the recorded object, owned by the account; public_html must be a
// directory owned by the account and its private group, on the home's
// filesystem (where the account's quota counts). Only then are both set to
// mode 0750 with fchmod on those handles, which also clears any set-ID or
// sticky bit, and public_html's identity is returned for the store to
// record. Nothing is created, removed or followed, and no path is reopened
// between the check and the change.
func (n *linuxSystem) AdoptPublicHTML(_ context.Context, r record) (fileIdentity, error) {
	if !validUsername(r.Account.Username) {
		return fileIdentity{}, ErrInvalid
	}
	if authority(n.opts.HomesDir) != nil {
		return fileIdentity{}, ErrUnavailable
	}
	homes, e := openRootDir(n.opts.HomesDir)
	if e != nil {
		return fileIdentity{}, ErrUnavailable
	}
	defer homes.Close()
	home, e := openDirectoryAt(int(homes.Fd()), r.Account.Username)
	if e != nil {
		return fileIdentity{}, ErrConflict
	}
	defer home.Close()
	homeID, e := heldIdentity(home, r.Account.UID, r.Account.GID, 0)
	if e != nil || homeID != r.Ownership.Home {
		return fileIdentity{}, ErrConflict
	}
	public, e := openDirectoryAt(int(home.Fd()), "public_html")
	if e != nil {
		return fileIdentity{}, ErrConflict
	}
	defer public.Close()
	publicID, e := heldIdentity(public, r.Account.UID, r.Account.GID, 0)
	if e != nil || publicID.Dev != homeID.Dev {
		return fileIdentity{}, ErrConflict
	}
	for _, d := range []int{int(home.Fd()), int(public.Fd())} {
		if unix.Fchmod(d, 0750) != nil {
			return fileIdentity{}, ErrUnavailable
		}
	}
	if _, e := heldIdentity(home, r.Account.UID, r.Account.GID, 0750); e != nil {
		return fileIdentity{}, ErrUnavailable
	}
	if _, e := heldIdentity(public, r.Account.UID, r.Account.GID, 0750); e != nil {
		return fileIdentity{}, ErrUnavailable
	}
	return publicID, nil
}
