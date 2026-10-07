//go:build linux

package hostwebruntime

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
)

func inspectInstallation(ctx context.Context, opts Options, record func(string, bool)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	root := os.Geteuid() == 0
	record("native_linux_root", root)
	if !root {
		return ErrUnavailable
	}
	p := opts.Profile
	dirs := []struct {
		name, path string
		private    bool
	}{
		{"root", opts.Root, true}, {"managed", p.ManagedRoot, true},
		{"homes", p.ManagedHomeRoot, false}, {"front_jail", p.FrontChroot, false},
		{"backend_jails", p.BackendChrootRoot, false}, {"runtime_directory", p.RuntimeRoot, false}, {"tls_directory", p.TLSRoot, false},
	}
	for _, dir := range dirs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := inspectDirectory(dir.path, dir.private)
		record(dir.name, err == nil)
		if err != nil {
			return err
		}
	}
	_, _, err := installationInputDigest(ctx, p)
	record("trusted_inputs", err == nil)
	return err
}

// Reuses the executor's trusted-root traversal. This does not promise immunity
// to privileged ancestor replacement. Recheck the opened leaf before admitting it.
func inspectDirectory(path string, private bool) error {
	fd, err := checkedDir(path, private)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 || (private && st.Mode&0777 != 0700) {
		return ErrUnavailable
	}
	return nil
}
