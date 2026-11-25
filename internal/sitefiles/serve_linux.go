//go:build linux

package sitefiles

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// maxDeleteDepth bounds how deep a folder delete goes. Each level holds one
// open folder, so the bound also bounds the open files.
const maxDeleteDepth = 256

var errHome = errors.New("the working directory is not a folder of the running user")

// Serve answers one request. home is the user's home, opened by the
// caller; in holds the request line and the bytes after it; out gets the
// answer. Every path is opened one name at a time from home, never
// following a link, so an answer is about the home's own tree: a link is
// listed as a link, and an operation on a link, or on a path through one,
// is refused, except delete and rename, which act on the link itself.
//
// An operation that fails answers with its code and Serve returns nil.
// Serve returns an error only when the request could not be read whole, the
// answer could not be written whole, or the file changed size while it was
// sent; the caller then exits non-zero and the broker discards the answer.
func Serve(home *os.File, in io.Reader, out io.Writer) error {
	// Only home's descriptor is used below; without this the *os.File could
	// be collected meanwhile and its finalizer close that descriptor, which
	// a later open would then reuse for another folder.
	defer runtime.KeepAlive(home)
	var st unix.Stat_t
	if err := unix.Fstat(int(home.Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Getuid() {
		return errHome
	}
	br := bufio.NewReaderSize(in, 64<<10)
	line, err := ReadLine(br, MaxRequestLine)
	if err != nil {
		return err
	}
	req, err := ParseRequest(line)
	if err != nil {
		return answer(out, Answer{Error: ErrInvalid})
	}
	names, _ := SplitPath(req.Path)
	s := &server{home: int(home.Fd()), in: br, out: out}
	switch req.Op {
	case OpList:
		return s.list(names)
	case OpRead:
		return s.read(names, true)
	case OpDownload:
		return s.read(names, false)
	case OpWrite, OpUpload:
		return s.put(req, names)
	case OpMkdir:
		return s.mkdir(names)
	case OpRename:
		to, _ := SplitPath(req.To)
		return s.rename(names, to)
	case OpDelete:
		return s.remove(names)
	case OpMode:
		mode, _ := ParseMode(req.Mode)
		return s.mode(names, mode)
	}
	return answer(out, Answer{Error: ErrInvalid})
}

type server struct {
	home int
	in   *bufio.Reader
	out  io.Writer
}

func answer(out io.Writer, a Answer) error {
	line, err := EncodeLine(a)
	if err != nil {
		return err
	}
	_, err = out.Write(line)
	return err
}

func (s *server) fail(code string) error { return answer(s.out, Answer{Error: code}) }

func (s *server) done(e Entry) error { return answer(s.out, Answer{File: &e}) }

// errorCode turns a system call's error into an answer's code.
func errorCode(err error) string {
	switch {
	case errors.Is(err, unix.ENOENT):
		return ErrNotFound
	case errors.Is(err, unix.EEXIST), errors.Is(err, unix.ENOTEMPTY):
		return ErrExists
	case errors.Is(err, unix.ENOTDIR):
		return ErrNotAFolder
	case errors.Is(err, unix.EISDIR):
		return ErrIsAFolder
	case errors.Is(err, unix.ELOOP):
		return ErrIsLink
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM), errors.Is(err, unix.EROFS), errors.Is(err, unix.ETXTBSY):
		return ErrPermission
	case errors.Is(err, unix.EDQUOT):
		return ErrQuota
	case errors.Is(err, unix.ENOSPC):
		return ErrNoSpace
	case errors.Is(err, unix.EFBIG):
		return ErrTooLarge
	case errors.Is(err, unix.EXDEV):
		return ErrUnsupported
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENAMETOOLONG):
		return ErrInvalid
	}
	return ErrFailed
}

// classify names why opening name in dir failed: a link and a file in the
// way are told apart by lstat, since O_NOFOLLOW reports both as errors.
func classify(dir int, name string, err error) string {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		var st unix.Stat_t
		if unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFLNK:
				return ErrIsLink
			case unix.S_IFDIR:
				return ErrFailed
			}
			return ErrNotAFolder
		}
	}
	return errorCode(err)
}

// folder opens the folder at names, one name at a time from the home, each
// with O_NOFOLLOW. O_PATH needs only search permission, as the kernel's own
// lookup does; final opens the last folder for reading its names.
func (s *server) folder(names []string, final bool) (int, string) {
	flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(s.home, ".", flags, 0)
	if err != nil {
		return -1, errorCode(err)
	}
	for i, name := range names {
		f := flags
		if final && i == len(names)-1 {
			f = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		}
		next, err := unix.Openat(fd, name, f, 0)
		if err != nil {
			code := classify(fd, name, err)
			unix.Close(fd)
			return -1, code
		}
		unix.Close(fd)
		fd = next
	}
	if final && len(names) == 0 {
		unix.Close(fd)
		if fd, err = unix.Openat(s.home, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
			return -1, errorCode(err)
		}
	}
	return fd, ""
}

// parent opens the folder that holds the path's last name.
func (s *server) parent(names []string) (int, string, string) {
	dir, code := s.folder(names[:len(names)-1], false)
	if code != "" {
		return -1, "", code
	}
	return dir, names[len(names)-1], ""
}

func entry(name string, st *unix.Stat_t) Entry {
	sec, nsec := st.Mtim.Unix()
	e := Entry{Name: name, Mode: formatMode(st.Mode & 0o7777), Modified: FormatModified(time.Unix(sec, nsec))}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		e.Type, e.Size, e.Version = "file", st.Size, version(st)
	case unix.S_IFDIR:
		e.Type = "folder"
	case unix.S_IFLNK:
		e.Type = "link"
	default:
		e.Type = "other"
	}
	return e
}

// version is a file's Entry.Version. A write by the file manager renames a
// new inode into place, so even two writes within one clock tick differ.
func version(st *unix.Stat_t) string {
	var b [56]byte
	ms, mn := st.Mtim.Unix()
	cs, cn := st.Ctim.Unix()
	for i, v := range []uint64{st.Dev, st.Ino, uint64(st.Size), uint64(ms), uint64(mn), uint64(cs), uint64(cn)} {
		binary.BigEndian.PutUint64(b[i*8:], v)
	}
	sum := sha256.Sum256(b[:])
	return hex.EncodeToString(sum[:8])
}

func (s *server) list(names []string) error {
	fd, code := s.folder(names, true)
	if code != "" {
		return s.fail(code)
	}
	f := os.NewFile(uintptr(fd), "folder")
	defer f.Close()
	a := Answer{Entries: []Entry{}}
	for !a.Truncated {
		batch, err := f.Readdirnames(512)
		for _, name := range batch {
			if !ValidName(name) {
				a.Skipped++
				continue
			}
			var st unix.Stat_t
			if e := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				if errors.Is(e, unix.ENOENT) {
					continue
				}
				return s.fail(errorCode(e))
			}
			if len(a.Entries) == MaxEntries {
				a.Truncated = true
				break
			}
			a.Entries = append(a.Entries, entry(name, &st))
		}
		if errors.Is(err, io.EOF) || (err == nil && len(batch) == 0) {
			break
		}
		if err != nil {
			return s.fail(errorCode(err))
		}
	}
	sort.Slice(a.Entries, func(i, j int) bool { return a.Entries[i].Name < a.Entries[j].Name })
	if len(a.Entries) == 0 {
		a.Entries = nil
	}
	return answer(s.out, a)
}

// read sends a file: for the editor (text) at most MaxTextBytes of UTF-8
// with no NUL, read whole first; for a download at most MaxDownloadBytes,
// streamed. O_NONBLOCK keeps a named pipe from holding the open.
func (s *server) read(names []string, text bool) error {
	dir, name, code := s.parent(names)
	if code != "" {
		return s.fail(code)
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return s.fail(classify(dir, name, err))
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return s.fail(errorCode(err))
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFDIR:
		return s.fail(ErrIsAFolder)
	default:
		return s.fail(ErrNotAFile)
	}
	limit := int64(MaxDownloadBytes)
	if text {
		limit = MaxTextBytes
	}
	if st.Size > limit {
		return s.fail(ErrTooLarge)
	}
	e := entry(name, &st)
	if !text {
		if err := s.done(e); err != nil {
			return err
		}
		// The answer promised Size bytes: a file that shrank meanwhile ends
		// the stream short, which the broker reports as a failure.
		_, err := io.CopyN(s.out, f, st.Size)
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return s.fail(errorCode(err))
	}
	if int64(len(data)) > limit {
		return s.fail(ErrTooLarge)
	}
	if !Text(data) {
		return s.fail(ErrBinary)
	}
	e.Size = int64(len(data))
	if err := s.done(e); err != nil {
		return err
	}
	_, err = s.out.Write(data)
	return err
}

// errInput is the request's bytes ending early or running on: the broker
// sends exactly Size bytes.
var errInput = errors.New("the request's bytes did not match its size")

// put writes a file whole or not at all: the bytes go to a new temporary
// file beside the target, which is synced and given its mode, then renamed
// over the target (write, or an upload that may overwrite) or linked to a
// name that must be free (an upload that may not). A link, a folder or
// anything but a regular file at the target is refused and left alone.
func (s *server) put(r Request, names []string) error {
	dir, name, code := s.parent(names)
	if code != "" {
		return s.fail(code)
	}
	defer unix.Close(dir)
	mode := uint32(0o644)
	var st unix.Stat_t
	err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err == nil:
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
		case unix.S_IFLNK:
			return s.fail(ErrIsLink)
		case unix.S_IFDIR:
			return s.fail(ErrIsAFolder)
		default:
			return s.fail(ErrNotAFile)
		}
		// An upload replaces a file only when asked; a write without the
		// version it opened is a new file, so it never replaces one either.
		if (r.Op == OpUpload && !r.Overwrite) || (r.Op == OpWrite && r.ExpectedVersion == "") {
			return s.fail(ErrExists)
		}
		if r.ExpectedVersion != "" && version(&st) != r.ExpectedVersion {
			return s.fail(ErrChanged)
		}
		mode = st.Mode & 0o777
	case errors.Is(err, unix.ENOENT):
		if r.ExpectedVersion != "" {
			return s.fail(ErrChanged)
		}
	default:
		return s.fail(errorCode(err))
	}
	var data []byte
	if r.Op == OpWrite {
		data = make([]byte, r.Size)
		if _, err := io.ReadFull(s.in, data); err != nil {
			return errInput
		}
		if !Text(data) {
			return s.fail(ErrBinary)
		}
	}
	tmp, fd, code := temporary(dir)
	if code != "" {
		return s.fail(code)
	}
	f := os.NewFile(uintptr(fd), tmp)
	discard := func() { f.Close(); unix.Unlinkat(dir, tmp, 0) }
	if r.Op == OpWrite {
		_, err = f.Write(data)
	} else {
		in := &countingReader{r: s.in}
		var n int64
		n, err = io.CopyN(f, in, r.Size)
		if n < r.Size && in.err != nil {
			discard()
			return errInput
		}
	}
	if err == nil {
		if _, e := s.in.ReadByte(); !errors.Is(e, io.EOF) {
			discard()
			return errInput
		}
		err = f.Sync()
	}
	if err == nil {
		err = unix.Fchmod(fd, mode)
	}
	if err != nil {
		discard()
		return s.fail(errorCode(err))
	}
	if r.Op == OpWrite || r.Overwrite {
		err = unix.Renameat(dir, tmp, dir, name)
	} else if err = unix.Linkat(dir, tmp, dir, name, 0); err == nil {
		unix.Unlinkat(dir, tmp, 0)
	}
	if err != nil {
		discard()
		return s.fail(errorCode(err))
	}
	// The rename or unlink changed the inode's change time, so the version
	// the answer gives is read after them, from the file still held open.
	var made unix.Stat_t
	err = unix.Fstat(fd, &made)
	f.Close()
	if err != nil {
		return s.fail(errorCode(err))
	}
	return s.done(entry(name, &made))
}

// countingReader remembers a read error, so a short request is told apart
// from a write that failed (a full quota).
type countingReader struct {
	r   io.Reader
	err error
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil {
		c.err = err
	}
	return n, err
}

// temporary makes a new, empty file beside the target, only the user's,
// under a name no one else chose (O_EXCL), never through a link.
func temporary(dir int) (string, int, string) {
	for range 4 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", -1, ErrFailed
		}
		name := ".sifruno-" + hex.EncodeToString(b[:]) + ".tmp"
		fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			return name, fd, ""
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, errorCode(err)
		}
	}
	return "", -1, ErrFailed
}

func (s *server) mkdir(names []string) error {
	dir, name, code := s.parent(names)
	if code != "" {
		return s.fail(code)
	}
	defer unix.Close(dir)
	if err := unix.Mkdirat(dir, name, 0o755); err != nil {
		return s.fail(errorCode(err))
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return s.fail(errorCode(err))
	}
	return s.done(entry(name, &st))
}

// rename moves a name, a link as itself, to a new path inside the home,
// never over an existing name (RENAME_NOREPLACE; where the filesystem
// lacks it, the new name is checked first).
func (s *server) rename(from, to []string) error {
	fdir, fname, code := s.parent(from)
	if code != "" {
		return s.fail(code)
	}
	defer unix.Close(fdir)
	tdir, tname, code := s.parent(to)
	if code != "" {
		return s.fail(code)
	}
	defer unix.Close(tdir)
	err := unix.Renameat2(fdir, fname, tdir, tname, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		var st unix.Stat_t
		switch e := unix.Fstatat(tdir, tname, &st, unix.AT_SYMLINK_NOFOLLOW); {
		case e == nil:
			err = unix.EEXIST
		case errors.Is(e, unix.ENOENT):
			err = unix.Renameat(fdir, fname, tdir, tname)
		default:
			err = e
		}
	}
	if err != nil {
		return s.fail(errorCode(err))
	}
	var st unix.Stat_t
	if err := unix.Fstatat(tdir, tname, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return s.fail(errorCode(err))
	}
	return s.done(entry(tname, &st))
}

// remove deletes a file or a link (the link itself, never its target), or
// a folder with everything in it, without following any link inside: each
// folder is opened with O_NOFOLLOW from its parent's handle and every name
// is removed relative to that handle. The answer shows what was removed.
func (s *server) remove(names []string) error {
	dir, name, code := s.parent(names)
	if code != "" {
		return s.fail(code)
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return s.fail(errorCode(err))
	}
	e := entry(name, &st)
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		code = removeTree(dir, name, 0)
	} else if err := unix.Unlinkat(dir, name, 0); err != nil {
		code = errorCode(err)
	}
	if code != "" {
		return s.fail(code)
	}
	return s.done(e)
}

func removeTree(parent int, name string, depth int) string {
	if depth >= maxDeleteDepth {
		return ErrTooDeep
	}
	// A process of the user may add names while the folder empties; a few
	// passes catch those, then the delete gives up.
	for range 3 {
		if code := emptyFolder(parent, name, depth); code != "" {
			return code
		}
		err := unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		if err == nil || errors.Is(err, unix.ENOENT) {
			return ""
		}
		if !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.EEXIST) {
			return errorCode(err)
		}
	}
	return ErrFailed
}

func emptyFolder(parent int, name string, depth int) string {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return classify(parent, name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	for {
		batch, err := f.Readdirnames(256)
		for _, child := range batch {
			var st unix.Stat_t
			if e := unix.Fstatat(fd, child, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				if errors.Is(e, unix.ENOENT) {
					continue
				}
				return errorCode(e)
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				if code := removeTree(fd, child, depth+1); code != "" {
					return code
				}
				continue
			}
			if e := unix.Unlinkat(fd, child, 0); e != nil && !errors.Is(e, unix.ENOENT) {
				return errorCode(e)
			}
		}
		if errors.Is(err, io.EOF) || (err == nil && len(batch) == 0) {
			return ""
		}
		if err != nil {
			return errorCode(err)
		}
	}
}

// mode sets a file's or folder's permission bits. fchmodat cannot refuse a
// link on Linux 5.14 (AlmaLinux 9), so the name is opened as O_PATH without
// following, checked, and changed through /proc/self/fd, which acts on that
// very inode: a link swapped in meanwhile cannot redirect it.
func (s *server) mode(names []string, mode uint32) error {
	dir, name, code := s.parent(names)
	if code != "" {
		return s.fail(code)
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return s.fail(classify(dir, name, err))
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return s.fail(errorCode(err))
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return s.fail(ErrIsLink)
	}
	if err := unix.Chmod("/proc/self/fd/"+strconv.Itoa(fd), mode); err != nil {
		return s.fail(errorCode(err))
	}
	if err := unix.Fstat(fd, &st); err != nil {
		return s.fail(errorCode(err))
	}
	return s.done(entry(name, &st))
}
