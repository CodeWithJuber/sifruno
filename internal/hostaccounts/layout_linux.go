//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Dependencies belong to one invocation; no mutable process-wide test hooks.
type layoutNativeDependencies struct {
	admission func(context.Context, BrokerOptions) BrokerAdmissionReport
	egid      func() int
	lstat     func(string) (os.FileInfo, error)
	authority func(string) error
	empty     func(string, os.FileInfo) (bool, error)
	open      func(int, string) (*os.File, error)
	mkdir     func(int, string, uint32) error
	chmod     func(*os.File, os.FileMode) error
	chown     func(*os.File, int, int) error
}

func nativeLayoutDependencies() layoutNativeDependencies {
	return layoutNativeDependencies{admission: CheckBrokerAdmission, egid: os.Getegid, lstat: os.Lstat, authority: authority, empty: brokerDirectoryEmpty, open: openDirectoryAt, mkdir: unix.Mkdirat,
		chmod: func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) },
		chown: func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }}
}

type layoutDirectory struct {
	path   string
	mode   os.FileMode
	uid    uint32
	before os.FileInfo
	parent os.FileInfo
}

func controllerLayout(ctx context.Context, opts LayoutOptions, prepare bool) LayoutReport {
	return nativeControllerLayout(ctx, opts, prepare, nativeLayoutDependencies())
}

func validLayoutOptions(opts LayoutOptions) bool {
	if !validBrokerPaths(opts.BrokerOptions) || opts.BrokerOptions.ControllerUID == ^uint32(0) {
		return false
	}
	p := opts.ControllerStateDir
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || len(p) > 2048 || strings.ContainsAny(p, "\x00\r\n") {
		return false
	}
	for _, other := range []string{opts.BrokerOptions.StateDir, opts.BrokerOptions.HomesDir, filepath.Dir(opts.BrokerOptions.SocketPath)} {
		if p == other || strings.HasPrefix(p, other+"/") || strings.HasPrefix(other, p+"/") {
			return false
		}
	}
	return true
}

func nativeControllerLayout(ctx context.Context, opts LayoutOptions, prepare bool, d layoutNativeDependencies) LayoutReport {
	dirs := [4]layoutDirectory{
		{path: opts.BrokerOptions.StateDir, mode: 0700},
		{path: opts.BrokerOptions.HomesDir, mode: 0755},
		{path: filepath.Dir(opts.BrokerOptions.SocketPath), mode: 0755},
		{path: opts.ControllerStateDir, mode: 0700, uid: opts.BrokerOptions.ControllerUID},
	}
	p := layoutProbes{
		valid:     func() bool { return validLayoutOptions(opts) },
		admission: func(ctx context.Context) BrokerAdmissionReport { return d.admission(ctx, opts.BrokerOptions) },
		group: func() error {
			if d.egid() != 0 {
				return ErrUnavailable
			}
			return nil
		},
		access: func(ctx context.Context) error { return layoutControllerAccess(ctx, opts, d) },
		inspect: func(ctx context.Context) ([4]string, error) {
			var actions [4]string
			for i := range dirs {
				info, parent, e := inspectLayoutDirectory(ctx, dirs[i], d)
				if e != nil {
					actions[i] = "refused"
					return actions, layoutFailure{directory: i}
				}
				dirs[i].before, dirs[i].parent = info, parent
				actions[i] = "admitted_existing"
				if info == nil {
					actions[i] = "planned_create"
				}
			}
			return actions, nil
		},
		prepare: func(ctx context.Context, r *LayoutReport) error {
			for i := range dirs {
				// All four targets and host prerequisites are rechecked before
				// every addition, including targets admitted as existing.
				if e := recheckLayout(ctx, opts, dirs, d); e != nil {
					return e
				}
				if dirs[i].before != nil {
					continue
				}
				created, info, e := createLayoutDirectory(ctx, dirs[i], opts, dirs, d)
				if e != nil {
					return layoutFailure{directory: i, created: created}
				}
				dirs[i].before = info
				r.Directories[i].Action = "created"
			}
			return recheckLayout(ctx, opts, dirs, d)
		},
	}
	return probeControllerLayout(ctx, "linux", prepare, p)
}

func layoutMetadata(info os.FileInfo, mode os.FileMode, uid uint32) bool {
	if info == nil || info.Mode() != os.ModeDir|mode {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && st.Gid == 0
}

func layoutInitialMetadata(info os.FileInfo, mode os.FileMode) bool {
	if info == nil || info.Mode() & ^os.ModePerm != os.ModeDir || info.Mode().Perm() & ^mode != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && st.Gid == 0
}

func inspectLayoutDirectory(ctx context.Context, dir layoutDirectory, d layoutNativeDependencies) (os.FileInfo, os.FileInfo, error) {
	if ctx.Err() != nil || d.authority(filepath.Dir(dir.path)) != nil {
		return nil, nil, ErrUnavailable
	}
	parent, e := d.lstat(filepath.Dir(dir.path))
	if e != nil || parent == nil {
		return nil, nil, ErrUnavailable
	}
	info, e := d.lstat(dir.path)
	if errors.Is(e, os.ErrNotExist) {
		if parent.Mode()&os.ModeSetgid != 0 || ctx.Err() != nil {
			return nil, nil, ErrUnavailable
		}
		return nil, parent, nil
	}
	if e != nil || !layoutMetadata(info, dir.mode, dir.uid) {
		return nil, nil, ErrUnavailable
	}
	empty, e := d.empty(dir.path, info)
	if e != nil || !empty || ctx.Err() != nil {
		return nil, nil, ErrUnavailable
	}
	return info, parent, nil
}

func recheckLayout(ctx context.Context, opts LayoutOptions, dirs [4]layoutDirectory, d layoutNativeDependencies) error {
	return recheckLayoutAuthorities(ctx, opts, dirs, d, false)
}

func recheckLayoutAuthorities(ctx context.Context, opts LayoutOptions, dirs [4]layoutDirectory, d layoutNativeDependencies, modePending bool) error {
	if ctx.Err() != nil || d.egid() != 0 {
		return ErrUnavailable
	}
	a := d.admission(ctx, opts.BrokerOptions)
	admitted := a.Supported
	if modePending {
		// The exclusive new root leaf may still have umask-restricted mode.
		// Reuse every host prerequisite, but inspect all directory metadata
		// ourselves until its descriptor-only mode assignment is complete.
		admitted = len(a.Checks) == 9
		for i := 0; i < 7 && i < len(a.Checks); i++ {
			admitted = admitted && a.Checks[i].Status == "pass"
		}
	}
	if !admitted || ctx.Err() != nil || layoutControllerAccessPending(ctx, opts, d, modePending && dirs[2].mode != 0755) != nil {
		return ErrUnavailable
	}
	if _, e := d.lstat(opts.BrokerOptions.SocketPath); !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	for i, dir := range dirs {
		info, parent, e := inspectLayoutDirectory(ctx, dir, d)
		if e != nil || !os.SameFile(dir.parent, parent) || (dir.before == nil) != (info == nil) || dir.before != nil && !os.SameFile(dir.before, info) {
			return layoutFailure{directory: i}
		}
	}
	return nil
}

// Root metadata authority alone permits private ancestors that the controller
// cannot traverse. Require other-execute without inferring any supplementary
// groups; only the private controller-owned leaf is exempt from this gate.
func layoutControllerAccess(ctx context.Context, opts LayoutOptions, d layoutNativeDependencies) error {
	return layoutControllerAccessPending(ctx, opts, d, false)
}

func layoutControllerAccessPending(ctx context.Context, opts LayoutOptions, d layoutNativeDependencies, socketModePending bool) error {
	for _, start := range []string{filepath.Dir(opts.ControllerStateDir), filepath.Dir(opts.BrokerOptions.SocketPath)} {
		if socketModePending && start == filepath.Dir(opts.BrokerOptions.SocketPath) {
			start = filepath.Dir(start) // Only our pinned new socket leaf awaits chmod.
		}
		for current := start; ; current = filepath.Dir(current) {
			if ctx.Err() != nil {
				return ErrUnavailable
			}
			info, e := d.lstat(current)
			if errors.Is(e, os.ErrNotExist) && current == start && current == filepath.Dir(opts.BrokerOptions.SocketPath) {
				continue // The declared socket parent may be created as 0755.
			}
			if e != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0001 == 0 || info.Mode().Perm()&0022 != 0 {
				return ErrUnavailable
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 {
				return ErrUnavailable
			}
			if current == "/" {
				break
			}
		}
	}
	return nil
}

// Exclusive mkdirat prevents adoption if a missing target becomes occupied.
// The parent and leaf handles pin our writes, but the path observations remain
// cooperative checks rather than atomic defense against privileged replacement.
func createLayoutDirectory(ctx context.Context, dir layoutDirectory, opts LayoutOptions, dirs [4]layoutDirectory, d layoutNativeDependencies) (bool, os.FileInfo, error) {
	parentPath := filepath.Dir(dir.path)
	parent, e := d.open(unix.AT_FDCWD, parentPath)
	if e != nil {
		return false, nil, ErrUnavailable
	}
	defer parent.Close()
	parentInfo, e := parent.Stat()
	if e != nil || !os.SameFile(dir.parent, parentInfo) || parentInfo.Mode()&os.ModeSetgid != 0 || d.authority(parentPath) != nil {
		return false, nil, ErrUnavailable
	}
	if e = recheckLayout(ctx, opts, dirs, d); e != nil || ctx.Err() != nil {
		return false, nil, ErrUnavailable
	}
	if e = d.mkdir(int(parent.Fd()), filepath.Base(dir.path), uint32(dir.mode)); e != nil {
		return false, nil, ErrUnavailable
	}
	created := true
	// Record the just-created no-follow inode relative to the held parent,
	// then require the opened leaf to be that exact root-owned inode.
	var leafBefore unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), filepath.Base(dir.path), &leafBefore, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return created, nil, ErrUnavailable
	}
	leaf, e := d.open(int(parent.Fd()), filepath.Base(dir.path))
	if e != nil {
		return created, nil, ErrUnavailable
	}
	defer leaf.Close()
	var opened unix.Stat_t
	info, e := leaf.Stat()
	if e != nil || unix.Fstat(int(leaf.Fd()), &opened) != nil || leafBefore.Dev != opened.Dev || leafBefore.Ino != opened.Ino || !layoutInitialMetadata(info, dir.mode) || leafBefore.Uid != 0 || leafBefore.Gid != 0 || leafBefore.Mode != opened.Mode {
		return created, nil, ErrUnavailable
	}
	initialDir := dir
	initialDir.mode = info.Mode().Perm()
	if e = verifyLayoutLeaf(ctx, initialDir, parentInfo, info, 0, d); e != nil {
		return created, nil, e
	}
	if info.Mode().Perm() != dir.mode {
		pending := layoutPendingLeaf(dirs, dir.path, info, initialDir.mode)
		if recheckLayoutAuthorities(ctx, opts, pending, d, true) != nil || ctx.Err() != nil {
			return created, nil, ErrUnavailable
		}
		current, e := leaf.Stat()
		if e != nil || !os.SameFile(info, current) || !layoutInitialMetadata(current, dir.mode) || current.Mode() != info.Mode() || verifyLayoutLeaf(ctx, initialDir, parentInfo, current, 0, d) != nil {
			return created, nil, ErrUnavailable
		}
		// This inode was created exclusively above and is still root-owned,
		// empty, no-follow and pinned. Never chmod an existing declaration.
		if d.chmod(leaf, dir.mode) != nil {
			return created, nil, ErrUnavailable
		}
		current, e = leaf.Stat()
		if e != nil || !os.SameFile(info, current) || verifyLayoutLeaf(ctx, dir, parentInfo, current, 0, d) != nil {
			return created, nil, ErrUnavailable
		}
		info = current
	}
	if dir.uid != 0 {
		// Host/controller prerequisites and every other target must still
		// pass before the only ownership-changing operation. The new leaf
		// has not been assigned to the controller yet, so use root metadata.
		pending := layoutPendingLeaf(dirs, dir.path, info, dir.mode)
		if recheckLayout(ctx, opts, pending, d) != nil || ctx.Err() != nil {
			return created, nil, ErrUnavailable
		}
		current, e := leaf.Stat()
		if e != nil || !os.SameFile(info, current) || !layoutMetadata(current, dir.mode, 0) || verifyLayoutLeaf(ctx, dir, parentInfo, current, 0, d) != nil {
			return created, nil, ErrUnavailable
		}
		if e = d.chown(leaf, int(dir.uid), -1); e != nil {
			return created, nil, ErrUnavailable
		}
	}
	current, e := leaf.Stat()
	if e != nil || !os.SameFile(info, current) || verifyLayoutLeaf(ctx, dir, parentInfo, current, dir.uid, d) != nil {
		return created, nil, ErrUnavailable
	}
	return created, current, nil
}

func layoutPendingLeaf(dirs [4]layoutDirectory, path string, info os.FileInfo, mode os.FileMode) [4]layoutDirectory {
	for i := range dirs {
		if dirs[i].path == path {
			dirs[i].before, dirs[i].uid, dirs[i].mode = info, 0, mode
		}
	}
	return dirs
}

func verifyLayoutLeaf(ctx context.Context, dir layoutDirectory, parentInfo, leafInfo os.FileInfo, uid uint32, d layoutNativeDependencies) error {
	if ctx.Err() != nil || d.authority(filepath.Dir(dir.path)) != nil || !layoutMetadata(leafInfo, dir.mode, uid) {
		return ErrUnavailable
	}
	currentParent, e := d.lstat(filepath.Dir(dir.path))
	if e != nil || !os.SameFile(parentInfo, currentParent) {
		return ErrUnavailable
	}
	current, e := d.lstat(dir.path)
	if e != nil || !os.SameFile(leafInfo, current) || !layoutMetadata(current, dir.mode, uid) {
		return ErrUnavailable
	}
	empty, e := d.empty(dir.path, current)
	if e != nil || !empty || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
