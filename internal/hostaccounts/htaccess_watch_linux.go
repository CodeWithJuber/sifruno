//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

// The .htaccess watcher is one fanotify group with one mark on the homes
// filesystem. It learns only that a name exactly ".htaccess" was created,
// written, moved or deleted somewhere on that filesystem, and the reloader
// (htaccess_watch.go) restarts the web server for it.
//
// What it relies on, read on 2026-11-25:
//
//   - fanotify_init(2) and fanotify_mark(2), man-pages 6.19
//     (https://man7.org/linux/man-pages/man2/fanotify_init.2.html,
//     .../fanotify_mark.2.html): FAN_REPORT_DFID_NAME is
//     FAN_REPORT_DIR_FID|FAN_REPORT_NAME (Linux 5.9). For FAN_CREATE,
//     FAN_DELETE and FAN_MOVE the name is that of the created, deleted or
//     moved entry; for other events on a non-directory it is the entry the
//     object had when the event happened. FAN_CREATE, FAN_DELETE and
//     FAN_MOVED_FROM/TO (Linux 5.1) need a group that reports file handles,
//     which FAN_CLASS_CONTENT and FAN_CLASS_PRE_CONTENT refuse (EINVAL), so
//     the group is FAN_CLASS_NOTIF. FAN_MARK_FILESYSTEM (Linux 4.20) needs
//     CAP_SYS_ADMIN and covers every mount of the filesystem; with it,
//     FAN_EVENT_ON_CHILD "has no effect". A filesystem with a zero fsid (the
//     page names fuse) answers ENODEV, a btrfs subvolume EXDEV, one that
//     cannot encode file handles EOPNOTSUPP. XFS, which the homes
//     filesystem must be for its quotas, has both; so has tmpfs in 5.14
//     (mm/shmem.c shmem_statfs sets f_fsid from the superblock's UUID).
//   - fanotify(7), man-pages 6.19: with file handles fd is FAN_NOFD for
//     every event; a DFID_NAME record is the info header, the fsid, a
//     struct file_handle and the NUL-terminated name; read(2) fails with
//     EINVAL when the buffer cannot hold the next event; a queue past
//     /proc/sys/fs/fanotify/max_queued_events drops events and reports
//     FAN_Q_OVERFLOW instead; consecutive events of one object from one
//     process may be merged into one.
//   - Linux v5.14, the kernel AlmaLinux 9 is built from
//     (https://github.com/torvalds/linux/tree/v5.14):
//     fs/notify/fanotify/fanotify_user.c do_fanotify_mark (lines 1395-1406)
//     sets FAN_EVENT_ON_CHILD on a filesystem mark when the group reports
//     directory file handles, so an event on a file reaches the group with
//     its parent's handle and its own name; that is how FAN_CLOSE_WRITE
//     carries the name ".htaccess". The mask is checked only against
//     FANOTIFY_EVENTS, which holds FAN_MODIFY and FAN_CLOSE_WRITE as well
//     as the directory entry events (lines 1262 and 1310;
//     include/linux/fanotify.h 75-90), and lines 1355-1357 refuse those
//     entry events only to a group without file handles or on a mount
//     mark, so the mark is a filesystem mark.
//     fanotify_test_fid (1196-1235) gives the ENODEV, EXDEV and EOPNOTSUPP
//     above. copy_info_to_user (311-403) writes the record as fanotify(7)
//     says. fs/notify/fanotify/fanotify.c fanotify_alloc_event (566-658)
//     charges each queued event to the memory cgroup of the group's
//     creator, the broker. The default queue is 16384 events
//     (FANOTIFY_DEFAULT_MAX_EVENTS) and the broker never asks for an
//     unlimited one.
//
// The events, and why:
//
//   - FAN_CREATE, FAN_DELETE, FAN_MOVED_FROM, FAN_MOVED_TO: a .htaccess
//     appears, goes, or is renamed into or out of place (an editor or WP-CLI
//     writing a temporary file and renaming it over the old one).
//   - FAN_CLOSE_WRITE, not FAN_MODIFY: FAN_MODIFY fires on every write(2), so
//     a tenant could queue an event per byte; FAN_CLOSE_WRITE fires once when
//     a file opened for writing is closed, after its content is final, which
//     is when a restart can read it. A writer that keeps the file open is
//     seen when it closes it. Both are accepted with FAN_REPORT_DFID_NAME on
//     5.14 (the mask check above). The kernel test in
//     htaccess_watch_linux_test.go reads these events and their names from
//     the kernel it runs on: Linux 6.8 when this was written. On 5.14 it is
//     read from the source, until the dev VM runs the root-only test.
//   - Not FAN_ONDIR: a directory named .htaccess means nothing to the web
//     server. A folder moved into place with a .htaccess already inside it
//     is not seen, since no event names that file; nor is truncate(2) on a
//     path, which is a FAN_MODIFY alone. The next seen change, web change or
//     restart picks those up.
//
// Hostile tenants:
//
//   - Nothing a tenant names is opened, read or followed. The handle in an
//     event is skipped without open_by_handle_at, so no event is mapped to
//     a site: a graceful restart reloads every vhost anyway, so knowing
//     which site changed would not make a restart cheaper, only add a root
//     open of a tenant's directory.
//   - Memory is bounded: the kernel's queue is limited and its overflow is
//     one event; the broker reads into one buffer made once and parses it
//     in place, and a change adds to a counter (htaccessReloader). A flood
//     costs a restart per window, whether it is of .htaccess changes or of
//     other events that fill the queue.
//   - Names are compared byte for byte with ".htaccess" and never printed.
//
// When fanotify cannot be set up (EPERM, ENOSYS, a homes filesystem that
// refuses the mark, a group or mark limit) the broker logs it once and runs
// without the watcher, as before: .htaccess changes then take effect at the
// next web change or OpenLiteSpeed restart. It does not poll instead: it
// cannot tell whether a .htaccess changed without reading tenants'
// folders, so a poll would be a blind restart on a timer, which every
// account would pay for on a server where the change is rare (Jev,
// 2026-11-25: run without 0.72, retry later 0.24, blind periodic restart
// 0.04).

// htaccessMask is the events the watcher takes.
const htaccessMask = unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO | unix.FAN_CLOSE_WRITE

// htaccessReadSize is the one read buffer. An event is at most its 24-byte
// metadata and one record: 20 bytes, a handle of at most 255 bytes (its
// length is a u8, struct fanotify_fh in fs/notify/fanotify/fanotify.h) and
// a name of at most 255 bytes and its NUL, so every read fits at least one.
const htaccessReadSize = 64 << 10

// htaccessName is the one name the watcher acts on.
var htaccessName = []byte(".htaccess")

// Offsets in struct fanotify_event_metadata and in a DFID_NAME record.
const (
	fanMetadataLen = 24 // event_len u32, vers u8, reserved u8, metadata_len u16, mask u64, fd s32, pid s32
	fanRecordHead  = 4  // info_type u8, pad u8, len u16
	fanNameRecord  = 20 // the head, fsid [8]byte, handle_bytes u32, handle_type s32
)

// startHtaccessWatch starts the watcher of the homes filesystem, whose
// changes restart the web server through restart, until ctx ends. Without
// fanotify it logs that once and returns. Its first restart comes one quiet
// period after it starts, for changes made while no watcher ran.
func startHtaccessWatch(ctx context.Context, homes string, restart func(context.Context) error) {
	events, e := openHtaccessEvents(homes)
	if e != nil {
		logHtaccessOff("could not start", e)
		return
	}
	h := newHtaccessReloader(restart)
	go h.run(ctx)
	h.lost(1)
	go func() {
		if e := h.read(ctx, events); e != nil {
			// Whatever came before the stop gets its restart.
			h.lost(1)
			logHtaccessOff("stopped", e)
		}
	}()
}

// openHtaccessEvents marks the filesystem of homes, which authority must
// accept (root's, and writable by root alone, up to /). The mark is made
// through a handle to homes opened without following a link.
func openHtaccessEvents(homes string) (*os.File, error) {
	if e := authority(homes); e != nil {
		return nil, e
	}
	dir, e := openDirectoryAt(unix.AT_FDCWD, homes)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	return htaccessGroup(dir, unix.FAN_MARK_FILESYSTEM, htaccessMask)
}

// htaccessGroup makes a fanotify group that reports directory handles and
// names, and marks dir with markFlags and mask: FAN_MARK_FILESYSTEM in the
// broker; a test marks one directory. The group is non-blocking, so reads
// wait in Go's poller and Close ends one.
func htaccessGroup(dir *os.File, markFlags uint, mask uint64) (*os.File, error) {
	fd, e := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY|unix.O_CLOEXEC)
	if e != nil {
		return nil, e
	}
	if e := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|markFlags, mask, int(dir.Fd()), ""); e != nil {
		unix.Close(fd)
		return nil, e
	}
	return os.NewFile(uintptr(fd), "fanotify"), nil
}

// read gives h the changes events reports until ctx ends, then closes
// events. It answers nil when ctx ended, and why it stopped otherwise.
func (h *htaccessReloader) read(ctx context.Context, events *os.File) error {
	stop := context.AfterFunc(ctx, func() { events.Close() })
	defer stop()
	defer events.Close()
	buf := make([]byte, htaccessReadSize)
	for {
		n, e := events.Read(buf)
		if ctx.Err() != nil {
			return nil
		}
		if e != nil {
			return e
		}
		seen, missed, e := htaccessEvents(buf[:n])
		if seen > 0 {
			h.changed(seen)
		}
		if missed > 0 {
			h.lost(missed)
		}
		if e != nil {
			return e
		}
	}
}

// htaccessEvents counts, in what one read returned, the events that name
// .htaccess (seen) and the queue overflows (missed). It parses in place
// and allocates nothing. An event it cannot read is an error, with the
// counts of the events before it; a descriptor in one is closed.
func htaccessEvents(buf []byte) (seen, missed uint64, err error) {
	for len(buf) > 0 {
		if len(buf) < fanMetadataLen {
			return seen, missed, errFanotifyEvent
		}
		eventLen := binary.NativeEndian.Uint32(buf[0:4])
		metadataLen := binary.NativeEndian.Uint16(buf[6:8])
		mask := binary.NativeEndian.Uint64(buf[8:16])
		fd := int32(binary.NativeEndian.Uint32(buf[16:20]))
		if fd != unix.FAN_NOFD {
			if fd >= 0 {
				unix.Close(int(fd))
			}
			return seen, missed, errFanotifyEvent
		}
		if buf[4] != unix.FANOTIFY_METADATA_VERSION || eventLen < fanMetadataLen || uint64(eventLen) > uint64(len(buf)) || metadataLen < fanMetadataLen || uint32(metadataLen) > eventLen {
			return seen, missed, errFanotifyEvent
		}
		event := buf[:eventLen]
		buf = buf[eventLen:]
		if mask&unix.FAN_Q_OVERFLOW != 0 {
			missed++
			continue
		}
		named, e := namesHtaccess(event[metadataLen:])
		if e != nil {
			return seen, missed, e
		}
		if named {
			seen++
		}
	}
	return seen, missed, nil
}

// namesHtaccess reports whether one of an event's information records is a
// directory handle with the name .htaccess.
func namesHtaccess(records []byte) (bool, error) {
	named := false
	for len(records) > 0 {
		if len(records) < fanRecordHead {
			return false, errFanotifyEvent
		}
		size := int(binary.NativeEndian.Uint16(records[2:4]))
		if size < fanRecordHead || size > len(records) {
			return false, errFanotifyEvent
		}
		record := records[:size]
		records = records[size:]
		if record[0] != unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
			continue
		}
		if size < fanNameRecord {
			return false, errFanotifyEvent
		}
		handle := uint64(binary.NativeEndian.Uint32(record[12:16]))
		if handle > uint64(size-fanNameRecord) {
			return false, errFanotifyEvent
		}
		name := record[fanNameRecord+int(handle):]
		end := bytes.IndexByte(name, 0)
		if end >= 0 && bytes.Equal(name[:end], htaccessName) {
			named = true
		}
	}
	return named, nil
}
