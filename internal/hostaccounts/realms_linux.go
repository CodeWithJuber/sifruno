//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"sifruno/internal/olsweb"
)

// Realm user files of protected folders (folders.go). OpenLiteSpeed reads a
// realm's userDB when a request needs it, as the web server user, and its
// config test checks, as root, that the file exists. So the files live in
// olsweb.RealmRoot, outside every home, which root makes in /var/lib like the
// challenge and suspended directories (root, 0755): one directory per site,
// root:root 0750 with one ACL entry giving the web server user read and
// traverse, and in it the site's realm files, root:root 0640 with one ACL
// entry giving the web server user read and the group nothing. Every path is
// reached through directory handles opened with O_NOFOLLOW, files are made
// with O_EXCL|O_NOFOLLOW under a temporary name and renamed into place, and
// nothing a tenant controls is read or written: the bytes come from the
// migration's root-only staging copy.

// realmFileACL is the access ACL of a 0640 realm file: the web server user
// may read it, root's group may not.
func realmFileACL(webUID int) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(aclVersion))
	entry := func(tag, p uint16, id uint32) {
		_ = binary.Write(&b, binary.LittleEndian, tag)
		_ = binary.Write(&b, binary.LittleEndian, p)
		_ = binary.Write(&b, binary.LittleEndian, id)
	}
	entry(aclUserObj, 6, aclUndefined)
	entry(aclUser, 4, uint32(webUID))
	entry(aclGroupObj, 0, aclUndefined)
	entry(aclMask, 4, aclUndefined)
	entry(aclOther, 0, aclUndefined)
	return b.Bytes()
}

// realmFileName is the name of a realm file in its site directory, from the
// path olsweb.RealmFile gives.
func realmFileName(site, path string) (string, bool) {
	name, ok := strings.CutPrefix(path, olsweb.RealmRoot+"/"+site+"/")
	if !ok || name == "" || strings.ContainsRune(name, '/') || !strings.HasPrefix(name, "realm") || !strings.HasSuffix(name, ".htpasswd") {
		return "", false
	}
	return name, true
}

// openRealmRoot opens olsweb.RealmRoot, making it when missing. It must be
// root's and writable by no one else, along its whole path.
func openRealmRoot(create bool) (*os.File, error) {
	if authority(filepath.Dir(olsweb.RealmRoot)) != nil {
		return nil, ErrUnavailable
	}
	parent, e := openRootDir(filepath.Dir(olsweb.RealmRoot))
	if e != nil {
		return nil, ErrUnavailable
	}
	defer parent.Close()
	name := filepath.Base(olsweb.RealmRoot)
	if create {
		if e := unix.Mkdirat(int(parent.Fd()), name, 0755); e == nil {
			d, e := openDirectoryAt(int(parent.Fd()), name)
			if e != nil {
				return nil, ErrUnavailable
			}
			if unix.Fchown(int(d.Fd()), 0, 0) != nil || unix.Fchmod(int(d.Fd()), 0755) != nil {
				d.Close()
				return nil, ErrUnavailable
			}
			return d, nil
		} else if !errors.Is(e, unix.EEXIST) {
			return nil, ErrUnavailable
		}
	}
	d, e := openDirectoryAt(int(parent.Fd()), name)
	if e != nil {
		return nil, e
	}
	owner, group, mode, e := ownerOfHandle(d)
	if e != nil || owner != 0 || mode&0002 != 0 || (mode&0020 != 0 && group != 0) {
		d.Close()
		return nil, ErrUnavailable
	}
	return d, nil
}

func (n *linuxSystem) WriteSiteRealms(ctx context.Context, site string, files map[string][]byte) error {
	if ctx == nil || ctx.Err() != nil || n.webUID <= 0 {
		return ErrUnavailable
	}
	if !siteDirPattern.MatchString(site) || len(files) == 0 || len(files) > olsweb.MaxFoldersPerSite {
		return ErrInvalid
	}
	want := map[string][]byte{}
	for path, data := range files {
		name, ok := realmFileName(site, path)
		if !ok || len(data) == 0 || len(data) > maxOLSFile {
			return ErrInvalid
		}
		want[name] = data
	}
	root, e := openRealmRoot(true)
	if e != nil {
		return e
	}
	defer root.Close()
	if e := unix.Mkdirat(int(root.Fd()), site, 0750); e != nil && !errors.Is(e, unix.EEXIST) {
		return ErrUnavailable
	}
	dir, e := openDirectoryAt(int(root.Fd()), site)
	if e != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	if unix.Fchown(int(dir.Fd()), 0, 0) != nil || unix.Fchmod(int(dir.Fd()), 0750) != nil {
		return ErrUnavailable
	}
	if unix.Fsetxattr(int(dir.Fd()), aclXattr, webACL(n.webUID, 5), 0) != nil {
		return ErrUnavailable
	}
	// Only root writes here; anything else in the directory is an old file
	// of this site or a temporary name a stopped write left.
	names, e := dir.Readdirnames(-1)
	if e != nil {
		return ErrUnavailable
	}
	for _, name := range names {
		if _, keep := want[name]; !keep {
			if e := removeTreeAt(ctx, int(dir.Fd()), name, 0); e != nil {
				return e
			}
		}
	}
	for name, data := range want {
		if e := writeRealmFile(dir, name, data, n.webUID); e != nil {
			return e
		}
	}
	return nil
}

func writeRealmFile(dir *os.File, name string, data []byte, webUID int) error {
	if old, meta, ok, e := readAt(dir, name); e == nil && ok && bytes.Equal(old, data) && meta.uid == 0 && meta.gid == 0 && meta.mode == 0640 {
		return nil
	}
	suffix, e := randomID()
	if e != nil {
		return e
	}
	temp := name + ".tmp-" + suffix
	fd, e := unix.Openat(int(dir.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), temp)
	_, werr := io.Copy(f, bytes.NewReader(data))
	ok := werr == nil && f.Sync() == nil && unix.Fchown(fd, 0, 0) == nil && unix.Fchmod(fd, 0640) == nil &&
		unix.Fsetxattr(fd, aclXattr, realmFileACL(webUID), 0) == nil
	if f.Close() != nil {
		ok = false
	}
	if !ok || unix.Renameat(int(dir.Fd()), temp, int(dir.Fd()), name) != nil {
		_ = unix.Unlinkat(int(dir.Fd()), temp, 0)
		return ErrUnavailable
	}
	if unix.Fsync(int(dir.Fd())) != nil {
		return ErrUnavailable
	}
	return nil
}

func (n *linuxSystem) RemoveSiteRealms(ctx context.Context, site string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if !siteDirPattern.MatchString(site) {
		return ErrInvalid
	}
	root, e := openRealmRoot(false)
	if e != nil {
		if errors.Is(e, ErrRecovery) {
			// openDirectoryAt reports a missing RealmRoot this way: nothing
			// was ever written.
			return nil
		}
		return e
	}
	defer root.Close()
	return removeTreeAt(ctx, int(root.Fd()), site, 0)
}
