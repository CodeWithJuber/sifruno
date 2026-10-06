//go:build linux

package hostaccounts

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// admitBrokerPaths checks every startup destination before the first write.
// This is a cooperative metadata check, not atomic admission against another
// privileged actor. declaredDir and the later socket check still guard drift.
// Nonempty state remains subject to openStore's existing recovery rules; this
// check neither reads the database nor certifies persisted broker state.
func admitBrokerPaths(opts BrokerOptions) error {
	if !validBrokerPaths(opts) {
		return ErrInvalid
	}
	var directories [3]os.FileInfo
	for i, d := range []struct {
		path string
		mode os.FileMode
	}{{opts.StateDir, 0700}, {opts.HomesDir, 0755}, {filepath.Dir(opts.SocketPath), 0755}} {
		if authority(filepath.Dir(d.path)) != nil {
			return ErrUnavailable
		}
		info, e := os.Lstat(d.path)
		if errors.Is(e, os.ErrNotExist) {
			// Linux mkdir inherits setgid from its direct parent. Refuse it
			// before any startup write rather than adopting a special mode.
			parent, e := os.Lstat(filepath.Dir(d.path))
			if e != nil || parent.Mode()&os.ModeSetgid != 0 {
				return ErrUnavailable
			}
			continue
		}
		if e != nil || authority(d.path) != nil || info.Mode() != os.ModeDir|d.mode {
			return ErrUnavailable
		}
		directories[i] = info
	}
	if _, e := os.Lstat(opts.SocketPath); e == nil {
		return ErrConflict
	} else if !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	fresh, e := brokerDirectoryEmpty(opts.StateDir, directories[0])
	if e != nil {
		return e
	}
	if fresh {
		empty, e := brokerDirectoryEmpty(opts.HomesDir, directories[1])
		if e != nil || !empty {
			return ErrUnavailable
		}
	}
	return nil
}

// A single directory entry is sufficient to distinguish fresh startup from
// reopen, including interrupted bootstrap with only the private-state marker.
// Existing directories are opened without following a final symlink, and no
// entry contents are opened or inspected.
func brokerDirectoryEmpty(path string, before os.FileInfo) (bool, error) {
	if before == nil {
		return true, nil
	}
	f, e := openDirectoryAt(unix.AT_FDCWD, path)
	if e != nil {
		return false, ErrUnavailable
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !os.SameFile(before, info) {
		return false, ErrUnavailable
	}
	entries, e := f.ReadDir(1)
	if e != nil && !errors.Is(e, io.EOF) {
		return false, ErrUnavailable
	}
	return len(entries) == 0, nil
}
