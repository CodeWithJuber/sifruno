//go:build linux

package hostwebruntime

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/hostwebgeneration"
)

type Runtime struct {
	opts       Options
	fd, lockFD int
	inputsSHA  string
	stateSHA   string
	gate       chan struct{}
	closed     bool
	children   map[int]*os.Process
	binaries   map[string]string
}

var _ hostwebgeneration.Executor = (*Runtime)(nil)

func Open(o Options) (*Runtime, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnavailable
	}
	if validateOptions(o) != nil {
		return nil, ErrInvalid
	}
	base, err := checkedDir(o.Root, true)
	if err != nil {
		return nil, err
	}
	unix.Close(base)
	for _, p := range []string{o.Profile.ManagedHomeRoot, o.Profile.FrontChroot, o.Profile.BackendChrootRoot, o.Profile.RuntimeRoot, o.Profile.TLSRoot} {
		fd, e := checkedDir(p, false)
		if e != nil {
			return nil, e
		}
		unix.Close(fd)
	}
	fd, err := checkedDir(o.Profile.ManagedRoot, true)
	if err != nil {
		return nil, err
	}
	r := &Runtime{opts: o, fd: fd, lockFD: -1, gate: make(chan struct{}, 1), children: map[int]*os.Process{}}
	ok := false
	defer func() {
		if !ok {
			if r.lockFD >= 0 {
				unix.Close(r.lockFD)
			}
			unix.Close(fd)
		}
	}()
	lock, err := openBelow(fd, "executor.lock", unix.O_CREAT|unix.O_RDWR, 0600)
	if err != nil || regular(lock, 0600, 0) != nil {
		if lock >= 0 {
			unix.Close(lock)
		}
		return nil, ErrUnavailable
	}
	r.lockFD = lock
	if unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, ErrConflict
	}
	if mkdirBelow(fd, "generations") != nil {
		return nil, ErrRecovery
	}
	if next, e := openBelow(fd, "state.next", unix.O_RDONLY, 0); e != unix.ENOENT {
		if e == nil {
			unix.Close(next)
		}
		return nil, ErrRecovery
	}
	r.inputsSHA, err = r.inputDigest()
	if err != nil {
		return nil, err
	}
	if _, err = r.load(); err != nil && err != unix.ENOENT {
		return nil, ErrRecovery
	}
	ok = true
	return r, nil
}
func (r *Runtime) acquire(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	select {
	case r.gate <- struct{}{}:
		if r.closed {
			<-r.gate
			return ErrUnavailable
		}
		if err := ctx.Err(); err != nil {
			<-r.gate
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *Runtime) release() { <-r.gate }
func (r *Runtime) guard() error {
	base, e := checkedDir(r.opts.Root, true)
	if e != nil {
		return ErrRecovery
	}
	unix.Close(base)
	var st unix.Stat_t
	if unix.Fstat(r.fd, &st) != nil || st.Uid != 0 || st.Mode&0777 != 0700 {
		return ErrRecovery
	}
	// Detect pathname replacement of the held leaf; ancestor checks repeat too.
	fd, err := checkedDir(r.opts.Profile.ManagedRoot, true)
	if err != nil {
		return ErrRecovery
	}
	defer unix.Close(fd)
	var current unix.Stat_t
	if unix.Fstat(fd, &current) != nil || current.Dev != st.Dev || current.Ino != st.Ino {
		return ErrRecovery
	}
	value, err := r.inputDigest()
	if err != nil || value != r.inputsSHA {
		return ErrRecovery
	}
	return nil
}

// Bootstrap is an explicit trusted setup action. It admits only the exact
// empty-ID denied generation for the snapshot; Observe subsequently proves
// an owned front listener and HTTP denial rather than echoing this input.
func (r *Runtime) Bootstrap(ctx context.Context, g hostwebgeneration.Generation) error {
	ctx, cancel, err := bounded(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err = r.acquire(ctx); err != nil {
		return err
	}
	defer r.release()
	g = copyGeneration(g)
	if validateGeneration(r.opts.Profile, g, true) != nil {
		return ErrInvalid
	}
	if r.guard() != nil {
		return ErrRecovery
	}
	v, loadErr := r.load()
	if loadErr == nil {
		if v.Current.Identity() != g.Identity() || v.Pending != nil || v.Repair != nil || v.Revision != 0 {
			return ErrConflict
		}
		if _, e := r.observe(ctx, v); e == nil {
			return ErrConflict
		}
		// Explicit retry is permitted only for this exact denied bootstrap.
		if e := r.stop(&v); e != nil {
			return e
		}
		if e := r.persist(v); e != nil {
			return e
		}
	} else if loadErr != unix.ENOENT {
		return ErrRecovery
	}
	if err = r.absent(g); err != nil {
		return err
	}
	if err = r.stage(g); err != nil {
		return err
	}
	if err = r.prepareOutputs(g); err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	v = record{Version: 1, Current: g, InputsSHA256: r.inputsSHA, BootID: boot}
	if err = r.persist(v); err != nil {
		return err
	}
	if err = r.syntax(ctx, g); err != nil {
		return err
	}
	if err = r.launch(ctx, &v, g); err != nil {
		_ = r.stop(&v)
		_ = r.persist(v)
		return ErrRecovery
	}
	_, err = r.observe(ctx, v)
	return err
}

func (r *Runtime) Observe(ctx context.Context) (hostwebgeneration.Identity, error) {
	ctx, cancel, err := bounded(ctx)
	if err != nil {
		return hostwebgeneration.Identity{}, err
	}
	defer cancel()
	if err = r.acquire(ctx); err != nil {
		return hostwebgeneration.Identity{}, err
	}
	defer r.release()
	if r.guard() != nil {
		return hostwebgeneration.Identity{}, ErrRecovery
	}
	v, err := r.load()
	if err != nil {
		return hostwebgeneration.Identity{}, ErrRecovery
	}
	return r.observe(ctx, v)
}
func (r *Runtime) observe(ctx context.Context, v record) (hostwebgeneration.Identity, error) {
	candidates := []hostwebgeneration.Generation{v.Current}
	if v.Pending != nil && v.Pending.Target.Identity() != v.Current.Identity() {
		candidates = append(candidates, v.Pending.Target)
	}
	if v.Repair != nil && v.Repair.Request.Target.Identity() != v.Current.Identity() {
		candidates = append(candidates, v.Repair.Request.Target)
	}
	for _, g := range candidates {
		if ctx.Err() != nil {
			return hostwebgeneration.Identity{}, ctx.Err()
		}
		if r.disk(g) == nil && r.live(ctx, v.Processes, g) == nil {
			return g.Identity(), nil
		}
	}
	return hostwebgeneration.Identity{}, ErrRecovery
}
func validTransition(p Options, t hostwebgeneration.Transition) bool {
	return t.Revision != ^uint64(0) && t.Before.ID != t.After.ID && idPattern.MatchString(t.OperationID) && validateGeneration(p.Profile, t.Before, t.Before.ID == "") == nil && validateGeneration(p.Profile, t.After, false) == nil
}
func (r *Runtime) Apply(ctx context.Context, t hostwebgeneration.Transition) error {
	ctx, cancel, err := bounded(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err = r.acquire(ctx); err != nil {
		return err
	}
	defer r.release()
	t.Before = copyGeneration(t.Before)
	t.After = copyGeneration(t.After)
	if !validTransition(r.opts, t) {
		return ErrInvalid
	}
	if r.guard() != nil {
		return ErrRecovery
	}
	v, err := r.load()
	if err != nil {
		return ErrRecovery
	}
	if v.Pending != nil || v.Repair != nil {
		return ErrRecovery
	}
	if v.Revision != t.Revision || v.LastOperation == t.OperationID {
		return ErrConflict
	}
	got, err := r.observe(ctx, v)
	if err != nil {
		return err
	}
	if got != t.Before.Identity() {
		return ErrConflict
	}
	return r.replace(ctx, &v, transaction{t.OperationID, t.Revision, t.Before, t.After, t.After})
}

// Rollback also serves as the explicit trusted repair primitive for an
// unhealthy pending executor. It does not require a fabricated healthy
// observation, but refuses any foreign/stale recorded process. Coordinator
// Recover currently requires healthy Observe first, so composition needs an
// independently reviewed pending-repair step for this failure case.
func (r *Runtime) Rollback(ctx context.Context, t hostwebgeneration.Transition, target hostwebgeneration.Generation) error {
	ctx, cancel, err := bounded(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err = r.acquire(ctx); err != nil {
		return err
	}
	defer r.release()
	t.Before = copyGeneration(t.Before)
	t.After = copyGeneration(t.After)
	target = copyGeneration(target)
	if !validTransition(r.opts, t) || validateGeneration(r.opts.Profile, target, target.ID == "") != nil {
		return ErrInvalid
	}
	// A serving rollback must be the exact known prior snapshot. A fresh denial
	// may differ because the coordinator reserved newer/suspended accounts.
	if !target.Denied && (target.Identity() != t.Before.Identity() || target.SnapshotSHA256 != t.After.SnapshotSHA256) {
		return ErrConflict
	}
	if r.guard() != nil {
		return ErrRecovery
	}
	v, err := r.load()
	if err != nil {
		return ErrRecovery
	}
	if v.Repair != nil {
		return ErrRecovery
	}
	if t.Revision != v.Revision && !(t.Revision+1 == v.Revision && v.LastOperation == t.OperationID) {
		return ErrConflict
	}
	if v.Pending != nil {
		p := v.Pending
		if p.OperationID != t.OperationID || p.Revision != t.Revision || p.Before.Identity() != t.Before.Identity() || p.After.Identity() != t.After.Identity() {
			return ErrConflict
		}
		if err = r.verifyRecorded(v.Processes, true); err != nil {
			return err
		}
	} else {
		// Explicit repair also covers controller-thread death after a clean
		// commit. Metadata is validated, every still-present pin is verified,
		// and all unknown listeners are refused before replacement.
		got := v.Current.Identity()
		if got != t.Before.Identity() && got != t.After.Identity() {
			return ErrConflict
		}
		if err = r.verifyRecorded(v.Processes, true); err != nil {
			return err
		}
	}
	return r.replace(ctx, &v, transaction{t.OperationID, t.Revision, t.Before, t.After, target})
}
func (r *Runtime) replace(ctx context.Context, v *record, t transaction) error {
	for _, a := range t.Target.Accounts {
		if a.State == "active" && !t.Target.Denied {
			if r.prepared(a) != nil {
				return ErrRecovery
			}
		}
	}
	if err := r.stage(t.Target); err != nil {
		return err
	}
	if err := r.prepareOutputs(t.Target); err != nil {
		return err
	}
	if err := r.syntax(ctx, t.Target); err != nil {
		return err
	}
	v.Pending = &t
	if err := r.persist(*v); err != nil {
		return err
	}
	if err := r.stop(v); err != nil {
		return err
	}
	if err := r.persist(*v); err != nil {
		return err
	}
	if err := r.absent(t.Target); err != nil {
		return err
	}
	if err := r.launch(ctx, v, t.Target); err != nil {
		_ = r.stop(v)
		_ = r.persist(*v)
		return ErrRecovery
	}
	if _, err := r.observe(ctx, *v); err != nil {
		_ = r.stop(v)
		_ = r.persist(*v)
		return ErrRecovery
	}
	if ctx.Err() != nil {
		_ = r.stop(v)
		_ = r.persist(*v)
		return ErrRecovery
	}
	v.Current = t.Target
	v.Pending = nil
	v.Revision = t.Revision + 1
	v.LastOperation = t.OperationID
	v.CompletedRepair = nil
	return r.persist(*v)
}
func (r *Runtime) Shutdown(ctx context.Context) error {
	ctx, cancel, err := bounded(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err = r.acquire(ctx); err != nil {
		return err
	}
	defer r.release()
	if r.guard() != nil {
		return ErrRecovery
	}
	v, err := r.load()
	if err != nil {
		return ErrRecovery
	}
	if err = r.stop(&v); err != nil {
		return err
	}
	return r.persist(v)
}

// Close releases controller handles. It is not a serving-state transition.
func (r *Runtime) Close() error {
	if err := r.acquire(context.Background()); err != nil {
		return err
	}
	defer r.release()
	r.closed = true
	unix.Flock(r.lockFD, unix.LOCK_UN)
	unix.Close(r.lockFD)
	return unix.Close(r.fd)
}
func (r *Runtime) prepareOutputs(g hostwebgeneration.Generation) error {
	for _, dir := range []string{"logs", "backend", "front-mutex"} {
		if mkdirBelow(r.fd, dir) != nil {
			return ErrRecovery
		}
	}
	for _, a := range g.Accounts {
		if a.State == "active" && !g.Denied {
			if mkdirBelow(r.fd, "backend/"+a.ID+"-mutex") != nil {
				return ErrRecovery
			}
		}
	}
	// Precreate log files so root daemons cannot follow substituted links.
	logs := []string{"front-error.log"}
	for _, a := range g.Accounts {
		if a.State == "active" && !g.Denied {
			for _, suffix := range []string{"-apache.log", "-fpm.log", "-fpm-slow.log"} {
				logs = append(logs, "logs/"+a.ID+suffix)
			}
		}
	}
	for _, name := range logs {
		if _, err := readBelow(r.fd, name, 0600, 8<<20); err == unix.ENOENT {
			if writeExclusive(r.fd, name, nil) != nil {
				return ErrRecovery
			}
		} else if err != nil {
			return ErrRecovery
		}
	}
	return nil
}

func (r *Runtime) checkPins(v record) error {
	allowed := map[string]string{}
	add := func(g hostwebgeneration.Generation) {
		base := filepath.Join(r.opts.Profile.ManagedRoot, generationPath(g))
		allowed[filepath.Join(base, "apache/front.conf")] = "front:"
		for _, a := range g.Accounts {
			if a.State == "active" && !g.Denied {
				allowed[filepath.Join(base, "apache/backends/"+a.ID+".conf")] = "backend:" + a.ID
				allowed[filepath.Join(base, "fpm/"+a.ID+".conf")] = "fpm:" + a.ID
			}
		}
	}
	add(v.Current)
	if v.Pending != nil {
		add(v.Pending.Before)
		add(v.Pending.After)
		add(v.Pending.Target)
	}
	if v.Repair != nil {
		add(v.Repair.Request.Target)
		for _, g := range v.Repair.Retained {
			add(g)
		}
	}
	for _, pin := range v.Processes {
		if allowed[pin.Config] != pin.Role+":"+pin.AccountID || !hex64.MatchString(pin.ExecutableSHA256) || !decimal.MatchString(pin.Start) || !bootPattern.MatchString(pin.Boot) || pin.Namespace == 0 || pin.ExecutableIno == 0 {
			return ErrRecovery
		}
	}
	return nil
}

func (r *Runtime) inputDigest() (string, error) {
	var parts []string
	if r.binaries == nil {
		r.binaries = map[string]string{}
	}
	for _, p := range []string{r.opts.Profile.ApacheBinary, r.opts.Profile.FPMBinary} {
		h, err := executableHash(p)
		if err != nil {
			return "", err
		}
		parts = append(parts, p+":"+h)
		// Only installation/repeated guard refresh uses this cache; the
		// aggregate digest is checked against persisted installation identity.
		r.binaries[p] = h
	}
	fd, err := checkedDir(r.opts.Profile.ApacheModuleRoot, false)
	if err != nil {
		return "", err
	}
	unix.Close(fd)
	for _, name := range []string{"mpm_event", "unixd", "authz_core", "authz_host", "dir", "log_config", "proxy", "proxy_http", "proxy_fcgi", "ssl", "mime"} {
		p := filepath.Join(r.opts.Profile.ApacheModuleRoot, "mod_"+name+".so")
		h, err := trustedHash(p, 64<<20, false)
		if err != nil {
			return "", err
		}
		parts = append(parts, name+":"+h)
	}
	ca, err := trustedHash(r.opts.Profile.CAFile, 256<<10, false)
	if err != nil {
		return "", err
	}
	parts = append(parts, "ca:"+ca)
	return hash([]byte(strings.Join(parts, "\n"))), nil
}
func trustedRead(p string, limit int64, executable bool) ([]byte, error) {
	fd, err := checkedDir(filepath.Dir(p), false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	child, err := openBelow(fd, filepath.Base(p), unix.O_RDONLY, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(child), "trusted-input")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(child, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0022 != 0 || st.Size > limit || st.Size < 1 {
		return nil, ErrUnavailable
	}
	if executable && st.Mode&0111 == 0 {
		return nil, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrUnavailable
	}
	return b, nil
}
func trustedHash(p string, limit int64, executable bool) (string, error) {
	b, e := trustedRead(p, limit, executable)
	if e != nil {
		return "", e
	}
	return hash(b), nil
}
func executableHash(p string) (string, error) {
	b, e := trustedRead(p, 64<<20, true)
	if e != nil || len(b) < 4 || string(b[:4]) != "\x7fELF" {
		return "", ErrUnavailable
	}
	return hash(b), nil
}

func retry(ctx context.Context, fn func() error) error {
	var last error
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if last = fn(); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
