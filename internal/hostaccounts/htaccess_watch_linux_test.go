//go:build linux

package hostaccounts

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fanotifyEvent builds one event as fanotify(7) lays it out for a group
// with FAN_REPORT_DFID_NAME: the metadata, then one information record
// holding the directory's file handle and the entry's name, padded to 4.
func fanotifyEvent(mask uint64, name string) []byte {
	handle := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	record := make([]byte, 0, 64)
	record = append(record, unix.FAN_EVENT_INFO_TYPE_DFID_NAME, 0, 0, 0) // type, pad, len (below)
	record = append(record, 9, 9, 9, 9, 9, 9, 9, 9)                      // fsid
	record = binary.NativeEndian.AppendUint32(record, uint32(len(handle)))
	record = binary.NativeEndian.AppendUint32(record, 1) // handle_type
	record = append(record, handle...)
	record = append(record, name...)
	record = append(record, 0)
	for len(record)%4 != 0 {
		record = append(record, 0)
	}
	binary.NativeEndian.PutUint16(record[2:4], uint16(len(record)))
	if mask&unix.FAN_Q_OVERFLOW != 0 {
		record = nil
	}
	return append(fanotifyMetadata(mask, 24+len(record), 24, unix.FAN_NOFD), record...)
}

func fanotifyMetadata(mask uint64, eventLen, metadataLen int, fd int32) []byte {
	m := make([]byte, 24)
	binary.NativeEndian.PutUint32(m[0:4], uint32(eventLen))
	m[4] = unix.FANOTIFY_METADATA_VERSION
	binary.NativeEndian.PutUint16(m[6:8], uint16(metadataLen))
	binary.NativeEndian.PutUint64(m[8:16], mask)
	binary.NativeEndian.PutUint32(m[16:20], uint32(fd))
	binary.NativeEndian.PutUint32(m[20:24], 4242)
	return m
}

func join(events ...[]byte) []byte {
	var out []byte
	for _, e := range events {
		out = append(out, e...)
	}
	return out
}

func TestHtaccessEventsCountOnlyTheExactName(t *testing.T) {
	buf := join(
		fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess"),
		fanotifyEvent(unix.FAN_CREATE|unix.FAN_CLOSE_WRITE, ".htaccess"),
		fanotifyEvent(unix.FAN_MOVED_TO, ".htaccess"),
		fanotifyEvent(unix.FAN_DELETE, ".htaccess"),
		fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess.bak"),
		fanotifyEvent(unix.FAN_CLOSE_WRITE, "x.htaccess"),
		fanotifyEvent(unix.FAN_CLOSE_WRITE, ".HTACCESS"),
		fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess "),
		fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess\n"),
		fanotifyEvent(unix.FAN_CLOSE_WRITE, "index.php"),
		fanotifyEvent(unix.FAN_Q_OVERFLOW, ""),
	)
	seen, missed, err := htaccessEvents(buf)
	if err != nil || seen != 4 || missed != 1 {
		t.Fatalf("seen %d, missed %d, %v", seen, missed, err)
	}
}

// A record that is not a name (a file handle alone) names nothing.
func TestHtaccessEventsSkipRecordsWithoutAName(t *testing.T) {
	e := fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess")
	e[24] = unix.FAN_EVENT_INFO_TYPE_DFID
	if seen, missed, err := htaccessEvents(e); err != nil || seen != 0 || missed != 0 {
		t.Fatalf("seen %d, missed %d, %v", seen, missed, err)
	}
	// A name without its terminating NUL inside the record is no name.
	e = fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess")
	for i := 24 + 28; i < len(e); i++ {
		e[i] = 'x'
	}
	copy(e[24+28:], ".htaccess")
	if seen, _, err := htaccessEvents(e); err != nil || seen != 0 {
		t.Fatalf("unterminated name: seen %d, %v", seen, err)
	}
}

// The kernel writes these bytes, but a malformed event stops the watcher
// instead of being guessed at; it never loops or reads past the buffer.
func TestHtaccessEventsRefuseMalformedEvents(t *testing.T) {
	good := fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess")
	cases := map[string][]byte{
		"short metadata":      good[:20],
		"event past the read": good[:len(good)-4],
		"event shorter than its metadata": func() []byte {
			e := append([]byte(nil), good...)
			binary.NativeEndian.PutUint32(e[0:4], 16)
			return e
		}(),
		"another metadata version": func() []byte {
			e := append([]byte(nil), good...)
			e[4] = unix.FANOTIFY_METADATA_VERSION + 1
			return e
		}(),
		"metadata past the event": func() []byte {
			e := append([]byte(nil), good...)
			binary.NativeEndian.PutUint16(e[6:8], uint16(len(e)+4))
			return e
		}(),
		"record of length 0": func() []byte {
			e := append([]byte(nil), good...)
			binary.NativeEndian.PutUint16(e[26:28], 0)
			return e
		}(),
		"record past the event": func() []byte {
			e := append([]byte(nil), good...)
			binary.NativeEndian.PutUint16(e[26:28], uint16(len(e)))
			return e
		}(),
		"handle past the record": func() []byte {
			e := append([]byte(nil), good...)
			binary.NativeEndian.PutUint32(e[24+12:24+16], 1<<20)
			return e
		}(),
	}
	for name, buf := range cases {
		if _, _, err := htaccessEvents(buf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A group that reports file handles never opens the object: an event with
// a descriptor is malformed, and the descriptor is closed, not leaked.
func TestHtaccessEventsCloseAnUnexpectedDescriptor(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p[1])
	e := fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess")
	binary.NativeEndian.PutUint32(e[16:20], uint32(p[0]))
	if _, _, err := htaccessEvents(e); err == nil {
		t.Fatal("an event with a descriptor was accepted")
	}
	if _, err := unix.FcntlInt(uintptr(p[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		unix.Close(p[0])
		t.Fatalf("the event's descriptor is still open: %v", err)
	}
}

func TestHtaccessEventsAllocateNothing(t *testing.T) {
	buf := join(fanotifyEvent(unix.FAN_CLOSE_WRITE, ".htaccess"), fanotifyEvent(unix.FAN_CREATE, "wp-config.php"))
	if n := testing.AllocsPerRun(1000, func() { _, _, _ = htaccessEvents(buf) }); n != 0 {
		t.Fatalf("%v allocations per read", n)
	}
}

// readFor reads the group's events for d and counts them as the watcher
// does; bytes says whether anything was reported at all.
func readFor(t *testing.T, events *os.File, d time.Duration) (seen, missed uint64, bytes int) {
	t.Helper()
	buf := make([]byte, htaccessReadSize)
	if err := events.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatal(err)
	}
	for {
		n, err := events.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return seen, missed, bytes
		}
		if err != nil {
			t.Fatal(err)
		}
		bytes += n
		s, m, err := htaccessEvents(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		seen, missed = seen+s, missed+m
	}
}

// The kernel's own events, read the watcher's way. Marking a filesystem
// needs root; marking one directory does not (Linux 5.13 and later), and
// it reports the same records for the same events of its entries, so this
// runs as any user where the kernel allows it.
func TestHtaccessEventsFromTheKernel(t *testing.T) {
	dir := t.TempDir()
	d, err := openDirectoryAt(unix.AT_FDCWD, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	events, err := htaccessGroup(d, 0, htaccessMask|unix.FAN_EVENT_ON_CHILD)
	if err != nil {
		t.Skipf("fanotify is not open to this user here: %v", err)
	}
	defer events.Close()
	write := func(name string, flags int) {
		t.Helper()
		f, err := os.OpenFile(filepath.Join(dir, name), flags, 0644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("RewriteEngine On\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"index.php", ".htaccess.bak", "x.htaccess", ".HTACCESS"} {
		write(name, os.O_WRONLY|os.O_CREATE)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if seen, missed, n := readFor(t, events, 300*time.Millisecond); seen != 0 || missed != 0 || n == 0 {
		t.Fatalf("other names: seen %d, missed %d, %d bytes read", seen, missed, n)
	}
	steps := []struct {
		what string
		do   func()
	}{
		{"a new .htaccess", func() { write(".htaccess", os.O_WRONLY|os.O_CREATE|os.O_EXCL) }},
		{"a .htaccess changed in place", func() { write(".htaccess", os.O_WRONLY|os.O_APPEND) }},
		{"a .htaccess renamed into place", func() {
			write("tmp", os.O_WRONLY|os.O_CREATE)
			if err := os.Rename(filepath.Join(dir, "tmp"), filepath.Join(dir, ".htaccess")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a .htaccess renamed away", func() {
			if err := os.Rename(filepath.Join(dir, ".htaccess"), filepath.Join(dir, "old")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a .htaccess deleted", func() {
			write(".htaccess", os.O_WRONLY|os.O_CREATE)
			_, _, _ = readFor(t, events, 200*time.Millisecond)
			if err := os.Remove(filepath.Join(dir, ".htaccess")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, step := range steps {
		step.do()
		if seen, missed, _ := readFor(t, events, 300*time.Millisecond); seen == 0 || missed != 0 {
			t.Fatalf("%s: seen %d, missed %d", step.what, seen, missed)
		}
	}
}

// TestRootOnlyHtaccessWatchRestartsOnceForAWrite marks the filesystem of
// the test's temporary folder as the broker marks the homes filesystem,
// and sees a .htaccess write make exactly one restart, and other names
// none. The mark sees the whole filesystem, so another process writing a
// .htaccess on it meanwhile would add a restart.
func TestRootOnlyHtaccessWatchRestartsOnceForAWrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: a filesystem mark needs CAP_SYS_ADMIN")
	}
	dir := t.TempDir()
	d, err := openDirectoryAt(unix.AT_FDCWD, dir)
	if err != nil {
		t.Fatal(err)
	}
	events, err := htaccessGroup(d, unix.FAN_MARK_FILESYSTEM, htaccessMask)
	d.Close()
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EXDEV) {
		t.Skipf("the temporary folder's filesystem cannot take a filesystem mark (no fsid or no file handles, or a subvolume): %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	restarts := make(chan struct{}, 16)
	h := newHtaccessReloader(func(context.Context) error { restarts <- struct{}{}; return nil })
	h.quiet, h.maxWait, h.window = 200*time.Millisecond, time.Second, 2*time.Second
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go h.run(ctx)
	read := make(chan error, 1)
	go func() { read <- h.read(ctx, events) }()
	for _, name := range []string{"index.php", ".htaccess.bak", "x.htaccess"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-restarts:
		t.Fatal("restarted for another name")
	case <-time.After(2 * time.Second):
	}
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("RewriteEngine On\n"), 0644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-restarts:
	case <-time.After(10 * time.Second):
		t.Fatal("a .htaccess write made no restart")
	}
	select {
	case <-restarts:
		t.Fatal("one .htaccess write made a second restart")
	case <-time.After(4 * time.Second):
	}
	cancel()
	select {
	case err := <-read:
		if err != nil {
			t.Fatalf("the reader stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader did not stop with its context")
	}
}
