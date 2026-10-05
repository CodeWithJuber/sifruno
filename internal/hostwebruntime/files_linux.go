//go:build linux

package hostwebruntime

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

// openat2 confines every executor write to the held managed-directory inode.
// No fallback to path-string writes is provided on older kernels.
func openBelow(fd int, name string, flags int, mode uint32) (int, error) {
	return unix.Openat2(fd, name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
}
func checkedDir(p string, private bool) (int, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return -1, ErrInvalid
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		current = filepath.Join(current, part)
		var st unix.Stat_t
		if unix.Lstat(current, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 && !(st.Mode&unix.S_ISVTX != 0 && current != p) {
			return -1, ErrUnavailable
		}
		if current == p && private && st.Mode&0777 != 0700 {
			return -1, ErrUnavailable
		}
	}
	fd, err := unix.Open(p, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_RDONLY, 0)
	if err != nil {
		return -1, ErrUnavailable
	}
	return fd, nil
}
func regular(fd int, mode uint32, max int64) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0777 != mode || st.Size < 0 || st.Size > max {
		return ErrRecovery
	}
	return nil
}
func readBelow(root int, name string, mode uint32, limit int) ([]byte, error) {
	fd, err := openBelow(root, name, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	if regular(fd, mode, int64(limit)) != nil {
		unix.Close(fd)
		return nil, ErrRecovery
	}
	f := os.NewFile(uintptr(fd), "managed-input")
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, ErrRecovery
	}
	return b, nil
}
func mkdirBelow(root int, name string) error {
	parent, err := unix.Dup(root)
	if err != nil {
		return ErrRecovery
	}
	defer func() { unix.Close(parent) }()
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return ErrInvalid
		}
		if err := unix.Mkdirat(parent, part, 0700); err != nil && err != unix.EEXIST {
			return ErrRecovery
		}
		fd, err := openBelow(parent, part, unix.O_DIRECTORY|unix.O_RDONLY, 0)
		if err != nil {
			return ErrRecovery
		}
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		if err != nil || st.Uid != 0 || st.Mode&0777 != 0700 {
			unix.Close(fd)
			return ErrRecovery
		}
		if unix.Fsync(parent) != nil {
			unix.Close(fd)
			return ErrRecovery
		}
		unix.Close(parent)
		parent = fd
	}
	return unix.Fsync(parent)
}
func writeExclusive(root int, name string, data []byte) error {
	fd, err := openBelow(root, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return ErrRecovery
	}
	f := os.NewFile(uintptr(fd), "managed-output")
	err = f.Chmod(0600)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	parent, err := openBelow(root, filepath.Dir(name), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return ErrRecovery
	}
	defer unix.Close(parent)
	return unix.Fsync(parent)
}
func (r *Runtime) stage(g hostwebgeneration.Generation) error {
	if validateGeneration(r.opts.Profile, g, g.ID == "") != nil {
		return ErrInvalid
	}
	dir := generationPath(g)
	if fd, err := openBelow(r.fd, dir, unix.O_DIRECTORY|unix.O_RDONLY, 0); err == nil {
		unix.Close(fd)
		return r.disk(g)
	} else if err != unix.ENOENT {
		return ErrRecovery
	}
	fd, err := openBelow(r.fd, "generations", unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return ErrRecovery
	}
	f := os.NewFile(uintptr(fd), "generations")
	names, err := f.Readdirnames(MaxGenerations + 1)
	f.Close()
	if err != nil && err != io.EOF {
		return ErrRecovery
	}
	if len(names) >= MaxGenerations {
		return ErrLimit
	}
	if !g.Denied && len(names) >= MaxGenerations-2 {
		return ErrLimit
	}
	if mkdirBelow(r.fd, dir) != nil {
		return ErrRecovery
	}
	for _, v := range g.Bundle.Files {
		if mkdirBelow(r.fd, filepath.Join(dir, filepath.Dir(v.Path))) != nil || writeExclusive(r.fd, filepath.Join(dir, v.Path), v.Data) != nil {
			return ErrRecovery
		}
	}
	return r.disk(g)
}
func (r *Runtime) disk(g hostwebgeneration.Generation) error {
	if validateGeneration(r.opts.Profile, g, g.ID == "") != nil {
		return ErrRecovery
	}
	expected := map[string]bool{}
	for _, v := range g.Bundle.Files {
		name := filepath.Join(generationPath(g), v.Path)
		expected[v.Path] = true
		data, err := readBelow(r.fd, name, uint32(v.Mode), hostweb.MaxBundleFileBytes)
		if err != nil || hash(data) != v.SHA256 || !bytes.Equal(data, v.Data) {
			return ErrRecovery
		}
	}
	// Reject unknown configs/dirs instead of accepting merely the requested set.
	var walk func(string, string) error
	walk = func(dir, rel string) error {
		fd, err := openBelow(r.fd, dir, unix.O_DIRECTORY|unix.O_RDONLY, 0)
		if err != nil {
			return ErrRecovery
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0777 != 0700 {
			unix.Close(fd)
			return ErrRecovery
		}
		f := os.NewFile(uintptr(fd), "generation-directory")
		entries, err := f.ReadDir(hostweb.MaxBundleFiles + 8)
		f.Close()
		if err != nil && err != io.EOF {
			return ErrRecovery
		}
		if len(entries) > hostweb.MaxBundleFiles+7 {
			return ErrLimit
		}
		for _, e := range entries {
			p := filepath.Join(rel, e.Name())
			if e.IsDir() {
				if p != "apache" && p != "apache/backends" && p != "fpm" {
					return ErrRecovery
				}
				if err := walk(filepath.Join(dir, e.Name()), p); err != nil {
					return err
				}
			} else if !expected[p] {
				return ErrRecovery
			}
		}
		return nil
	}
	return walk(generationPath(g), "")
}
func metadataCopy(v record) record {
	strip := func(g hostwebgeneration.Generation) hostwebgeneration.Generation {
		g = copyGeneration(g)
		for i := range g.Bundle.Files {
			g.Bundle.Files[i].Data = nil
		}
		return g
	}
	v.Current = strip(v.Current)
	v.Processes = append([]processPin(nil), v.Processes...)
	if v.Pending != nil {
		t := *v.Pending
		t.Before = strip(t.Before)
		t.After = strip(t.After)
		t.Target = strip(t.Target)
		v.Pending = &t
	}
	if v.Repair != nil {
		n := *v.Repair
		n.Request = copyRepairRequest(n.Request)
		n.Request.Original.Before = strip(n.Request.Original.Before)
		n.Request.Original.After = strip(n.Request.Original.After)
		n.Request.Target = strip(n.Request.Target)
		n.Retained = append([]hostwebgeneration.Generation(nil), n.Retained...)
		for i := range n.Retained {
			n.Retained[i] = strip(n.Retained[i])
		}
		v.Repair = &n
	}
	if v.CompletedRepair != nil {
		n := *v.CompletedRepair
		n.Request = copyRepairRequest(n.Request)
		n.Request.Original.Before = strip(n.Request.Original.Before)
		n.Request.Original.After = strip(n.Request.Original.After)
		n.Request.Target = strip(n.Request.Target)
		n.Retained = append([]hostwebgeneration.Generation(nil), n.Retained...)
		for i := range n.Retained {
			n.Retained[i] = strip(n.Retained[i])
		}
		v.CompletedRepair = &n
	}
	return v
}
func (r *Runtime) persist(v record) error {
	if err := validateRecord(r.opts.Profile, v); err != nil {
		return err
	}
	data, err := json.Marshal(metadataCopy(v))
	if err != nil || len(data) > MaxMetadataBytes {
		return ErrLimit
	}
	old, readErr := readBelow(r.fd, "state.json", 0600, MaxMetadataBytes)
	if r.stateSHA == "" {
		if readErr != unix.ENOENT {
			return ErrRecovery
		}
	} else if readErr != nil || hash(old) != r.stateSHA {
		return ErrRecovery
	}
	// A stale interrupted temporary file is quarantine, never overwritten.
	if err = writeExclusive(r.fd, "state.next", data); err != nil {
		return ErrRecovery
	}
	if err = unix.Renameat(r.fd, "state.next", r.fd, "state.json"); err != nil {
		return ErrRecovery
	}
	if err = unix.Fsync(r.fd); err != nil {
		return err
	}
	r.stateSHA = hash(data)
	return nil
}
func (r *Runtime) load() (record, error) {
	data, err := readBelow(r.fd, "state.json", 0600, MaxMetadataBytes)
	if err != nil {
		return record{}, err
	}
	if r.stateSHA != "" && hash(data) != r.stateSHA {
		return record{}, ErrRecovery
	}
	var v record
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return record{}, ErrRecovery
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return record{}, ErrRecovery
	}
	hydrate := func(g *hostwebgeneration.Generation, owned bool) error {
		if !hex64.MatchString(g.SnapshotSHA256) || !hex64.MatchString(g.ProfileSHA256) || g.ID != "" && !idPattern.MatchString(g.ID) || len(g.Accounts) > hostweb.MaxManagedAccounts {
			return ErrRecovery
		}
		render := append([]hostaccounts.Account{}, g.Accounts...)
		if g.Denied {
			for i := range render {
				render[i].State = "suspended"
			}
		}
		want, e := hostweb.Compile(r.opts.Profile, render)
		if e != nil || len(want.Files) != len(g.Bundle.Files) || g.Bundle.Profile != want.Profile || g.Bundle.SHA256 != want.SHA256 {
			return ErrRecovery
		}
		for i, f := range want.Files {
			old := g.Bundle.Files[i]
			if old.Path != f.Path || old.Mode != f.Mode || old.SHA256 != f.SHA256 || len(old.Data) != 0 {
				return ErrRecovery
			}
			g.Bundle.Files[i].Data = f.Data
		}
		if owned {
			return r.disk(*g)
		}
		return nil
	}
	if hydrate(&v.Current, true) != nil {
		return record{}, ErrRecovery
	}
	if v.Pending != nil {
		if hydrate(&v.Pending.Before, true) != nil || hydrate(&v.Pending.After, true) != nil || hydrate(&v.Pending.Target, true) != nil {
			return record{}, ErrRecovery
		}
	}
	if v.Repair != nil {
		if hydrate(&v.Repair.Request.Original.Before, false) != nil || hydrate(&v.Repair.Request.Original.After, false) != nil || hydrate(&v.Repair.Request.Target, true) != nil {
			return record{}, ErrRecovery
		}
		for i := range v.Repair.Retained {
			if hydrate(&v.Repair.Retained[i], true) != nil {
				return record{}, ErrRecovery
			}
		}
	}
	if v.CompletedRepair != nil {
		if hydrate(&v.CompletedRepair.Request.Original.Before, false) != nil || hydrate(&v.CompletedRepair.Request.Original.After, false) != nil || hydrate(&v.CompletedRepair.Request.Target, true) != nil {
			return record{}, ErrRecovery
		}
		for i := range v.CompletedRepair.Retained {
			if hydrate(&v.CompletedRepair.Retained[i], true) != nil {
				return record{}, ErrRecovery
			}
		}
	}
	if validateRecord(r.opts.Profile, v) != nil || v.InputsSHA256 != r.inputsSHA {
		return record{}, ErrRecovery
	}
	// Native metadata is written in one canonical encoding. This also rejects
	// duplicate known keys, aliases and extra whitespace on a reopened record,
	// rather than letting Decoder silently pick the last duplicate value.
	canonical, err := json.Marshal(metadataCopy(v))
	if err != nil || !bytes.Equal(canonical, data) {
		return record{}, ErrRecovery
	}
	if err = r.checkPins(v); err != nil {
		return record{}, err
	}
	r.stateSHA = hash(data)
	return v, nil
}
