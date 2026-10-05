//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostwebgeneration"
	"sifruno/internal/hostwebruntime"
)

func writeOwned(fd int, name string, b []byte) error {
	n, e := below(fd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0600)
	if e != nil {
		return errContract
	}
	f := os.NewFile(uintptr(n), "crash-fixture-owned")
	defer f.Close()
	if f.Chmod(0600) != nil {
		return errContract
	}
	if _, e = f.Write(b); e != nil {
		return errContract
	}
	if f.Sync() != nil || unix.Fsync(fd) != nil {
		return errContract
	}
	return nil
}
func provider(fd int, in fixtureInput) fixtureProvider {
	return fixtureProvider{read: func() ([]byte, error) {
		b, e := readOwned(fd, "fixture-inventory.json", 0600, inputLimit)
		if e != nil {
			return nil, e
		}
		var rows []hostaccounts.Account
		if json.Unmarshal(b, &rows) != nil || (digest(rows) != digest(in.Accounts) && digest(rows) != digest(suspendedInventory(in))) {
			return nil, errContract
		}
		return b, nil
	}}
}

type crashingExecutor struct {
	*hostwebruntime.Runtime
	nonce string
	pipe  *os.File
}

func (x *crashingExecutor) Apply(ctx context.Context, t hostwebgeneration.Transition) error {
	if e := x.Runtime.Apply(ctx, t); e != nil {
		return e
	}
	n, e := x.InspectRecovery(ctx)
	if e != nil {
		return e
	}
	stat, e := readKernel("/proc/self/stat", 8192)
	if e != nil {
		return e
	}
	start, e := processStart(stat)
	if e != nil {
		return e
	}
	b := boundary{x.nonce, os.Getpid(), start, t.OperationID, t.Before.Identity(), t.After.Identity(), n}
	if !validBoundary(b) {
		return errContract
	}
	if json.NewEncoder(x.pipe).Encode(b) != nil {
		return errContract
	}
	// The callback NEVER returns to Coordinator.Apply/Finish, even at deadline.
	<-ctx.Done()
	os.Exit(3)
	return errContract
}
func child() error {
	fd, e := openRoot(fixtureRoot)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	pipe := os.NewFile(3, "parent-owned-boundary")
	defer pipe.Close()
	var st unix.Stat_t
	if unix.Fstat(3, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errContract
	}
	raw, e := readOwned(fd, "qualification-input.json", 0600, inputLimit)
	if e != nil {
		return e
	}
	in, e := parseInput(raw)
	if e != nil {
		return e
	}
	nonce := os.Args[2]
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	rt, e := hostwebruntime.Open(hostwebruntime.Options{Root: in.Root, Profile: in.Profile})
	if e != nil {
		return e
	}
	defer rt.Close()
	boot, e := generation(in, "", true)
	if e != nil {
		return e
	}
	if e = rt.Bootstrap(ctx, boot); e != nil {
		return e
	}
	c, e := hostwebgeneration.Open(fixtureRoot+"/coordinator", in.Profile, provider(fd, in), &crashingExecutor{rt, nonce, pipe})
	if e != nil {
		return e
	}
	defer c.Close()
	p, e := c.Plan(ctx)
	if e != nil {
		return e
	}
	return c.Apply(ctx, hostwebgeneration.ApplyInput{Plan: p, Actor: "fixture-root", Reason: "owned controller death boundary"})
}

type gatedRepair struct {
	*hostwebruntime.Runtime
	allow bool
}

func (x *gatedRepair) RepairDenied(ctx context.Context, q hostwebgeneration.DeniedRepairRequest) (hostwebgeneration.DeniedRepairReceipt, error) {
	if !x.allow {
		return hostwebgeneration.DeniedRepairReceipt{}, hostwebgeneration.ErrRecovery
	}
	return x.Runtime.RepairDenied(ctx, q)
}
func processStart(b []byte) (string, error) {
	i := strings.LastIndex(string(b), ")")
	if i < 0 {
		return "", errContract
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return "", errContract
	}
	n, e := strconv.ParseUint(f[19], 10, 64)
	if e != nil || n == 0 {
		return "", errContract
	}
	return f[19], nil
}
func checkpointNow(ctx context.Context, c *hostwebgeneration.Coordinator, rt *hostwebruntime.Runtime, stage string, r *report) (checkpoint, error) {
	s, e := c.Status()
	if e != nil {
		return checkpoint{}, e
	}
	n, e := rt.InspectRecovery(ctx)
	if e != nil {
		return checkpoint{}, e
	}
	h, e := c.History()
	if e != nil {
		return checkpoint{}, e
	}
	x := checkpoint{stage, s, n, digest(h)}
	r.Checkpoints = append(r.Checkpoints, x)
	if n.Observed != nil {
		r.Observations = append(r.Observations, observation{stage, *n.Observed})
	}
	return x, nil
}
func probes(ctx context.Context, fd int, in fixtureInput, stage string, allDenied bool, r *report) error {
	client := servingClient()
	defer client.CloseIdleConnections()
	for i, a := range in.Accounts {
		for _, route := range []string{"/index.html", "/probe.php"} {
			status, b, e := request(ctx, client, a.Domain, route)
			ok := e == nil
			pid := 0
			if allDenied || i == 1 {
				ok = ok && status == 403 && !bytes.Contains(b, []byte("SIFRUNO_"))
			} else if route == "/index.html" {
				ok = ok && status == 200 && bytes.Equal(b, []byte("SIFRUNO_STATIC_"+a.Username+"\n"))
			} else {
				p, pe := phpBody(b, a)
				pid = p.PID
				ok = ok && status == 200 && pe == nil
				if ok {
					w, we := actualWorker(fd, a, p, in.Profile.BackendChrootRoot+"/"+a.ID)
					if we != nil {
						return we
					}
					r.Workers = append(r.Workers, w)
				}
			}
			r.Probes = append(r.Probes, probeEvidence{a.ID, stage + route, status, len(b), hash(b), ok, pid})
			if !ok {
				return errContract
			}
		}
	}
	status, b, e := request(ctx, client, "foreign.test", "/index.html")
	ok := e == nil && status == 403 && !bytes.Contains(b, []byte("SIFRUNO_"))
	r.Probes = append(r.Probes, probeEvidence{"", stage + "/foreign.test", status, len(b), hash(b), ok, 0})
	if !ok {
		return errContract
	}
	return nil
}

func openRoot(p string) (int, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || os.Geteuid() != 0 {
		return -1, errContract
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		current = filepath.Join(current, part)
		var s unix.Stat_t
		if unix.Lstat(current, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Uid != 0 || s.Gid != 0 || s.Mode&0022 != 0 && !(s.Mode&unix.S_ISVTX != 0 && current != p) || current == p && s.Mode&0777 != 0700 {
			return -1, errContract
		}
	}
	return unix.Open(p, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}
func below(fd int, name string, flags int, mode uint32) (int, error) {
	return unix.Openat2(fd, name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
}
func readOwned(fd int, name string, mode uint32, limit int) ([]byte, error) {
	n, e := below(fd, name, unix.O_RDONLY, 0)
	if e != nil {
		return nil, errContract
	}
	f := os.NewFile(uintptr(n), "qualification-owned-input")
	defer f.Close()
	var s unix.Stat_t
	if unix.Fstat(n, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFREG || s.Uid != 0 || s.Gid != 0 || s.Nlink != 1 || s.Mode&0777 != mode || s.Size < 0 || s.Size > int64(limit) {
		return nil, errContract
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(b) > limit {
		return nil, errContract
	}
	return b, nil
}
func writeReport(fd int, r report) error {
	b, e := json.Marshal(r)
	if e != nil || len(b) > reportLimit {
		return errContract
	}
	n, e := below(fd, "qualification-report.json", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0600)
	if e != nil {
		return errContract
	}
	f := os.NewFile(uintptr(n), "qualification-report")
	defer f.Close()
	if f.Chmod(0600) != nil {
		return errContract
	}
	if _, e = f.Write(b); e != nil {
		return errContract
	}
	if f.Sync() != nil || unix.Fsync(fd) != nil {
		return errContract
	}
	return nil
}
func readKernel(p string, limit int) ([]byte, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, errContract
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(b) > limit {
		return nil, errContract
	}
	return b, nil
}
func fields(b []byte) (map[string][]string, error) {
	if len(b) > 32<<10 {
		return nil, errContract
	}
	m := map[string][]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, ok = m[k]; ok {
			return nil, errContract
		}
		m[k] = strings.Fields(v)
	}
	return m, nil
}
func prerequisites() (map[string]string, error) {
	v := map[string]string{}
	b, e := readKernel("/sys/fs/selinux/enforce", 8)
	if e != nil || strings.TrimSpace(string(b)) != "1" {
		return v, errContract
	}
	v["selinux_enforce"] = "1"
	b, e = readKernel("/proc/self/status", 32<<10)
	if e != nil {
		return v, e
	}
	f, e := fields(b)
	if e != nil {
		return v, e
	}
	for _, k := range []string{"NoNewPrivs", "CapEff", "CapPrm", "CapBnd", "CapAmb", "CapInh"} {
		if len(f[k]) != 1 {
			return v, errContract
		}
		v[k] = f[k][0]
	}
	for _, k := range []string{"CapEff", "CapPrm", "CapBnd"} {
		n, e := strconv.ParseUint(v[k], 16, 64)
		if e != nil || n&(1<<12|1<<13) != 0 {
			return v, errContract
		}
	}
	v["network_admin_raw_absent"] = "true"
	b, e = readKernel("/proc/sys/kernel/osrelease", 256)
	if e != nil {
		return v, e
	}
	k := strings.TrimSpace(string(b))
	if len(k) > 128 || strings.IndexFunc(k, func(r rune) bool { return r < 32 || r > 126 }) >= 0 {
		return v, errContract
	}
	v["kernel_release"] = k
	return v, nil
}
func driverHash(fd int) (string, error) {
	exe, e := os.Executable()
	if e != nil || exe != fixtureRoot+"/qualification-driver" {
		return "", errContract
	}
	b, e := readOwned(fd, "qualification-driver", 0700, 32<<20)
	if e != nil {
		return "", e
	}
	var a, c unix.Stat_t
	if unix.Stat("/proc/self/exe", &a) != nil || unix.Lstat(exe, &c) != nil || a.Dev != c.Dev || a.Ino != c.Ino {
		return "", errContract
	}
	return hash(b), nil
}
func observe(ctx context.Context, rt *hostwebruntime.Runtime, g hostwebgeneration.Generation, stage string, r *report) error {
	x, e := rt.Observe(ctx)
	if e != nil {
		return e
	}
	r.Observations = append(r.Observations, observation{Stage: stage, Identity: x})
	if x != g.Identity() {
		return errContract
	}
	return nil
}
func classify(e error) string {
	switch {
	case errors.Is(e, context.Canceled):
		return "cancelled"
	case errors.Is(e, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(e, hostwebruntime.ErrUnavailable):
		return "runtime_unavailable"
	case errors.Is(e, hostwebruntime.ErrRecovery):
		return "runtime_recovery_required"
	case errors.Is(e, hostwebruntime.ErrConflict):
		return "runtime_conflict"
	case errors.Is(e, hostwebruntime.ErrLimit):
		return "runtime_limit"
	default:
		return "contract_or_runtime_rejected"
	}
}
func extinct(ctx context.Context, in fixtureInput) bool {
	addresses := []string{"127.0.0.1:18082"}
	for _, a := range in.Accounts {
		addresses = append(addresses, fmt.Sprintf("127.73.%d.%d:18443", a.UID>>8, a.UID&255))
	}
	for _, address := range addresses {
		c, e := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if e == nil {
			c.Close()
			return false
		}
		if !errors.Is(e, unix.ECONNREFUSED) {
			return false
		}
	}
	return true
}

func run() (result error) {
	fd, e := openRoot(fixtureRoot)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	for _, name := range []string{"qualification-report.json", "fixture-inventory.json", "coordinator"} {
		n, e := below(fd, name, unix.O_RDONLY, 0)
		if e != unix.ENOENT {
			if e == nil {
				unix.Close(n)
			}
			return errContract
		}
	}
	raw, e := readOwned(fd, "qualification-input.json", 0600, inputLimit)
	if e != nil {
		return e
	}
	in, e := parseInput(raw)
	if e != nil {
		return e
	}
	nonce, e := newID()
	if e != nil {
		return e
	}
	r := report{SchemaVersion: 2, FixtureOnly: true, ExecutionKind: "native-linux-controller-crash-driver", RunID: in.RunID, Nonce: nonce, InputSHA256: hash(raw), ProfileSHA256: digest(in.Profile), Stage: "admission"}
	var rt *hostwebruntime.Runtime
	var c *hostwebgeneration.Coordinator
	defer func() {
		if c != nil {
			if c.Close() != nil && result == nil {
				result = errContract
			}
		}
		if rt != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			e := rt.Shutdown(ctx)
			r.ShutdownPassed = e == nil
			r.ListenersExtinct = e == nil && extinct(ctx, in)
			r.NamespacesExtinct = e == nil && namespacesExtinct(r.ObservedNamespaces)
			cancel()
			r.ClosePassed = rt.Close() == nil
		}
		b, e := readOwned(fd, "qualification-input.json", 0600, inputLimit)
		r.InputStable = e == nil && bytes.Equal(b, raw)
		b, e = readKernel("/sys/fs/selinux/enforce", 8)
		r.SELinuxStable = e == nil && strings.TrimSpace(string(b)) == "1"
		if result == nil && (!r.ShutdownPassed || !r.ClosePassed || !r.ListenersExtinct || !r.NamespacesExtinct || !r.InputStable || !r.SELinuxStable) {
			result = errContract
			r.Stage = "cleanup_or_stability"
		}
		r.Passed = result == nil
		if r.Passed {
			r.Stage = "complete"
		} else {
			r.Stage += ":" + classify(result)
		}
		if writeReport(fd, r) != nil {
			result = errContract
			fmt.Fprintln(os.Stderr, "qualification_report_write_failed")
		}
	}()
	r.DriverSHA256, e = driverHash(fd)
	if e != nil {
		return e
	}
	catalog, e := readOwned(fd, "source_catalog.json", 0600, 2<<20)
	if e != nil || !json.Valid(catalog) {
		return errContract
	}
	r.SourceCatalogSHA256 = hash(catalog)
	r.Prerequisites, e = prerequisites()
	if e != nil {
		return e
	}
	sigctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(sigctx, 180*time.Second)
	defer cancel()
	if e = unix.Mkdirat(fd, "coordinator", 0700); e != nil {
		return errContract
	}
	if unix.Fsync(fd) != nil {
		return errContract
	}
	rows, _ := json.Marshal(in.Accounts)
	if e = writeOwned(fd, "fixture-inventory.json", rows); e != nil {
		return e
	}
	r.Stage = "child_native_apply"
	reader, writer, e := os.Pipe()
	if e != nil {
		return errContract
	}
	defer reader.Close()
	cmd := exec.Command(fixtureRoot+"/qualification-driver", "--child-apply", nonce)
	cmd.ExtraFiles = []*os.File{writer}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if e = cmd.Start(); e != nil {
		writer.Close()
		return errContract
	}
	writer.Close()
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	r.Crash.ParentPID = os.Getpid()
	r.Crash.ChildPID = cmd.Process.Pid
	stat, e := readKernel(fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid), 8192)
	if e != nil {
		return e
	}
	r.Crash.ChildStart, e = processStart(stat)
	if e != nil {
		return e
	}
	type answer struct {
		b boundary
		e error
	}
	ch := make(chan answer, 1)
	go func() {
		var b boundary
		d := json.NewDecoder(io.LimitReader(reader, reportLimit))
		d.DisallowUnknownFields()
		e := d.Decode(&b)
		ch <- answer{b, e}
	}()
	select {
	case a := <-ch:
		if a.e != nil || !validBoundary(a.b) {
			return errContract
		}
		r.Crash.Boundary = a.b
	case <-ctx.Done():
		return ctx.Err()
	}
	b := r.Crash.Boundary
	r.Generations = append(r.Generations, b.Before, b.After)
	r.Observations = append(r.Observations, observation{"before_kill", *b.Native.Observed})
	stat, e = readKernel(fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid), 8192)
	if e != nil {
		return e
	}
	start, e := processStart(stat)
	if e != nil {
		return e
	}
	r.Crash.OwnedChild = b.PID == cmd.Process.Pid && b.Start == r.Crash.ChildStart && start == b.Start && b.Nonce == nonce
	if !r.Crash.OwnedChild {
		return errContract
	}
	nativeBefore, e := readOwned(fd, "managed/state.json", 0600, hostwebruntime.MaxMetadataBytes)
	if e != nil || hash(nativeBefore) != b.Native.StateSHA256 {
		return errContract
	}
	if e = collectNamespaces(nativeBefore, &r); e != nil {
		return e
	}
	journalBefore, e := readOwned(fd, "coordinator/generations.db", 0600, 8<<20)
	if e != nil {
		return e
	}
	r.Crash.JournalBeforeSHA256 = hash(journalBefore)
	if e = cmd.Process.Kill(); e != nil {
		return errContract
	}
	we := cmd.Wait()
	waited = true
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	r.Crash.Signal = int(ws.Signal())
	r.Crash.WaitSignaled = we != nil && ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
	if !r.Crash.WaitSignaled {
		return errContract
	}
	journalAfter, e := readOwned(fd, "coordinator/generations.db", 0600, 8<<20)
	if e != nil {
		return e
	}
	r.Crash.JournalAfterSHA256 = hash(journalAfter)
	if !bytes.Equal(journalBefore, journalAfter) {
		return errContract
	}
	nativeAfter, e := readOwned(fd, "managed/state.json", 0600, hostwebruntime.MaxMetadataBytes)
	if e != nil {
		return e
	}
	r.Crash.NativeMetadataStable = bytes.Equal(nativeBefore, nativeAfter)
	if !r.Crash.NativeMetadataStable {
		return errContract
	}
	deadline := time.Now().Add(8 * time.Second)
	for !extinct(ctx, in) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	r.Crash.ListenersExtinct = extinct(ctx, in)
	r.Crash.NamespacesExtinct = namespacesExtinct(r.ObservedNamespaces)
	if !r.Crash.ListenersExtinct || !r.Crash.NamespacesExtinct {
		return errContract
	}
	r.Stage = "reopen_after_kill"
	rt, e = hostwebruntime.Open(hostwebruntime.Options{Root: in.Root, Profile: in.Profile})
	if e != nil {
		return e
	}
	_, e = rt.Observe(ctx)
	r.Crash.StrictObserveRejected = errors.Is(e, hostwebruntime.ErrRecovery)
	if !r.Crash.StrictObserveRejected {
		return errContract
	}
	gate := &gatedRepair{Runtime: rt}
	p := provider(fd, in)
	open := func() error {
		var e error
		c, e = hostwebgeneration.Open(fixtureRoot+"/coordinator", in.Profile, p, gate)
		return e
	}
	if e = open(); e != nil {
		return e
	}
	cp, e := checkpointNow(ctx, c, rt, "after_kill", &r)
	if e != nil {
		return e
	}
	if cp.Coordinator.Revision != 0 || cp.Coordinator.Current != nil || cp.Coordinator.Phase != "applying" || cp.Coordinator.PendingOperation != b.OperationID || cp.Native.Observed != nil || cp.Native.CompletedApply == nil || *cp.Native.CompletedApply != *b.Native.CompletedApply {
		return errContract
	}
	h, e := c.History()
	if e != nil || len(h) != 1 || h[0].Phase != "intended" {
		return errContract
	}
	r.Stage = "change_current_inventory"
	rows, _ = json.Marshal(suspendedInventory(in))
	if e = writeOwned(fd, "fixture-inventory.next", rows); e != nil {
		return e
	}
	if e = unix.Renameat(fd, "fixture-inventory.next", fd, "fixture-inventory.json"); e != nil || unix.Fsync(fd) != nil {
		return errContract
	}
	r.InventorySHA256 = hash(rows)
	repair := func() hostwebgeneration.RepairInput {
		s, _ := c.Status()
		return hostwebgeneration.RepairInput{ExpectedRevision: s.Revision, PendingOperation: s.PendingOperation, Actor: "fixture-root", Reason: "current inventory denial after owned death"}
	}
	// Checkpoint the consumed Apply counter, then deliberately refuse the native
	// repair call. These cooperative refusals test reopen/CAS; they are not crashes.
	r.Stage = "checkpoint_consumed_apply"
	if e = c.RepairDenied(ctx, repair()); !errors.Is(e, hostwebgeneration.ErrRecovery) {
		return errContract
	}
	cp, e = checkpointNow(ctx, c, rt, "apply_checkpoint", &r)
	if e != nil {
		return e
	}
	if cp.Coordinator.Revision != 1 || cp.Coordinator.Current != nil || cp.Coordinator.PendingOperation != b.OperationID || cp.Native.Revision != 1 {
		return errContract
	}
	for _, stage := range []string{"repeated_checkpoint", "reopened_checkpoint"} {
		if stage == "reopened_checkpoint" {
			if c.Close() != nil {
				return errContract
			}
			c = nil
			if e = open(); e != nil {
				return e
			}
		}
		if e = c.RepairDenied(ctx, repair()); !errors.Is(e, hostwebgeneration.ErrRecovery) {
			return errContract
		}
		next, e := checkpointNow(ctx, c, rt, stage, &r)
		if e != nil {
			return e
		}
		if next.Coordinator.Revision != 1 || next.Coordinator.Current != nil || next.Coordinator.PendingOperation != b.OperationID || next.Native.StateSHA256 != cp.Native.StateSHA256 {
			return errContract
		}
	}
	r.Stage = "stale_repair_refused"
	beforeDB, e := readOwned(fd, "coordinator/generations.db", 0600, 8<<20)
	if e != nil {
		return e
	}
	stale := repair()
	stale.ExpectedRevision = 0
	if e = c.RepairDenied(ctx, stale); !errors.Is(e, hostwebgeneration.ErrConflict) {
		return errContract
	}
	stale = repair()
	stale.PendingOperation = strings.Repeat("f", 32)
	if e = c.RepairDenied(ctx, stale); !errors.Is(e, hostwebgeneration.ErrConflict) {
		return errContract
	}
	afterDB, e := readOwned(fd, "coordinator/generations.db", 0600, 8<<20)
	if e != nil || !bytes.Equal(beforeDB, afterDB) {
		return errContract
	}
	if _, e = checkpointNow(ctx, c, rt, "stale_refused", &r); e != nil {
		return e
	}
	r.Stage = "fresh_denied_repair"
	gate.allow = true
	if e = c.RepairDenied(ctx, repair()); e != nil {
		return e
	}
	cp, e = checkpointNow(ctx, c, rt, "denied_repaired", &r)
	if e != nil {
		return e
	}
	if cp.Coordinator.Revision != 2 || cp.Coordinator.PendingOperation != "" || cp.Coordinator.Current == nil || !cp.Coordinator.Current.Denied || cp.Coordinator.Current.SnapshotSHA256 != digest(suspendedInventory(in)) || cp.Coordinator.Current.GenerationID == b.After.GenerationID || cp.Native.Revision != 2 || cp.Native.Completed == nil || cp.Native.CompletedApply != nil || cp.Native.Observed == nil || *cp.Native.Observed != *cp.Coordinator.Current {
		return errContract
	}
	r.Generations = append(r.Generations, *cp.Coordinator.Current)
	if e = collectCurrentNamespaces(fd, cp.Native.StateSHA256, &r); e != nil {
		return e
	}
	if e = probes(ctx, fd, in, "repair_denied", true, &r); e != nil {
		return e
	}
	// Healthy denial must refuse a new repair; neither reopen nor repetition can
	// consume another counter. Reopen native handles too, retaining fresh daemons.
	for _, stage := range []string{"healthy_repair_refused", "reopened_denied"} {
		if stage == "reopened_denied" {
			if c.Close() != nil {
				return errContract
			}
			c = nil
			if rt.Close() != nil {
				return errContract
			}
			rt = nil
			rt, e = hostwebruntime.Open(hostwebruntime.Options{Root: in.Root, Profile: in.Profile})
			if e != nil {
				return e
			}
			gate.Runtime = rt
			if e = open(); e != nil {
				return e
			}
		}
		if e = c.RepairDenied(ctx, repair()); !errors.Is(e, hostwebgeneration.ErrConflict) {
			return errContract
		}
		next, e := checkpointNow(ctx, c, rt, stage, &r)
		if e != nil {
			return e
		}
		if next.Coordinator != cp.Coordinator {
			if next.Coordinator.Revision != 2 || next.Coordinator.PendingOperation != "" || next.Coordinator.Current == nil || *next.Coordinator.Current != *cp.Coordinator.Current {
				return errContract
			}
		}
		if next.Native.StateSHA256 != cp.Native.StateSHA256 {
			return errContract
		}
	}
	r.Stage = "separate_current_inventory_apply"
	plan, e := c.Plan(ctx)
	if e != nil {
		return e
	}
	if e = c.Apply(ctx, hostwebgeneration.ApplyInput{Plan: plan, Actor: "fixture-root", Reason: "separate selective apply of admitted current inventory"}); e != nil {
		return e
	}
	cp, e = checkpointNow(ctx, c, rt, "selective_apply", &r)
	if e != nil {
		return e
	}
	if cp.Coordinator.Revision != 3 || cp.Coordinator.PendingOperation != "" || cp.Coordinator.Current == nil || cp.Coordinator.Current.Denied || cp.Coordinator.Current.SnapshotSHA256 != digest(suspendedInventory(in)) || cp.Native.Revision != 3 || cp.Native.Observed == nil || *cp.Native.Observed != *cp.Coordinator.Current {
		return errContract
	}
	r.Generations = append(r.Generations, *cp.Coordinator.Current)
	if e = collectCurrentNamespaces(fd, cp.Native.StateSHA256, &r); e != nil {
		return e
	}
	if e = probes(ctx, fd, in, "selective", false, &r); e != nil {
		return e
	}
	r.History, e = c.History()
	if e != nil {
		return e
	}
	checkpoints := 0
	for _, ev := range r.History {
		if ev.Phase == "committed" && ev.OperationID == b.OperationID {
			return errContract
		}
		if ev.Phase == "apply_checkpoint" {
			checkpoints++
		}
	}
	if checkpoints != 1 {
		return errContract
	}
	return nil
}
func actualWorker(fd int, a hostaccounts.Account, p phpIdentity, root string) (workerEvidence, error) {
	var out workerEvidence
	b, e := readOwned(fd, "managed/state.json", 0600, hostwebruntime.MaxMetadataBytes)
	if e != nil {
		return out, e
	}
	var st struct {
		Pending   json.RawMessage
		Processes []struct {
			Role, AccountID string
			PID             int
			Namespace       uint64
		}
	}
	if json.Unmarshal(b, &st) != nil || len(st.Processes) != 3 || string(st.Pending) != "null" {
		return out, errContract
	}
	master := 0
	var ns uint64
	for _, pin := range st.Processes {
		if pin.Role == "fpm" && pin.AccountID == a.ID {
			if master != 0 {
				return out, errContract
			}
			master = pin.PID
			ns = pin.Namespace
		}
	}
	if master <= 1 || ns == 0 {
		return out, errContract
	}
	children, e := readKernel(fmt.Sprintf("/proc/%d/task/%d/children", master, master), 4096)
	if e != nil {
		return out, e
	}
	ids := strings.Fields(string(children))
	if len(ids) == 0 || len(ids) > 64 {
		return out, errContract
	}
	found := false
	for _, s := range ids {
		pid, e := strconv.Atoi(s)
		if e != nil || pid <= 1 {
			return out, errContract
		}
		initialStat, e := readKernel(fmt.Sprintf("/proc/%d/stat", pid), 8192)
		if e != nil {
			continue
		}
		initialStart, e := processStart(initialStat)
		if e != nil {
			return out, e
		}
		status, e := readKernel(fmt.Sprintf("/proc/%d/status", pid), 32<<10)
		if e != nil {
			continue
		}
		f, e := fields(status)
		if e != nil {
			return out, e
		}
		nsp := f["NSpid"]
		if len(nsp) < 2 || len(nsp) > 8 || nsp[0] != strconv.Itoa(pid) || nsp[len(nsp)-1] != strconv.Itoa(p.PID) {
			continue
		}
		if found {
			return out, errContract
		}
		found = true
		out = workerEvidence{AccountID: a.ID, HostPID: pid, NamespacePID: p.PID, Capabilities: map[string]string{}}
		for key, target := range map[string]*[]int{"Uid": &out.UID, "Gid": &out.GID} {
			if len(f[key]) != 4 {
				return out, errContract
			}
			want := a.UID
			if key == "Gid" {
				want = a.GID
			}
			for _, s := range f[key] {
				n, e := strconv.Atoi(s)
				if e != nil || n != want {
					return out, errContract
				}
				*target = append(*target, n)
			}
		}
		if len(f["Groups"]) > 32 {
			return out, errContract
		}
		seen := map[int]bool{}
		for _, s := range f["Groups"] {
			n, e := strconv.Atoi(s)
			if e != nil || n != a.GID || seen[n] {
				return out, errContract
			}
			seen[n] = true
			out.Groups = append(out.Groups, n)
		}
		for _, k := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
			if len(f[k]) != 1 {
				return out, errContract
			}
			n, e := strconv.ParseUint(f[k][0], 16, 64)
			if e != nil || n != 0 {
				return out, errContract
			}
			out.Capabilities[k] = f[k][0]
		}
		var n unix.Stat_t
		if unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid), &n) != nil || n.Ino != ns {
			return out, errContract
		}
		out.Namespace = n.Ino
		out.Root, e = os.Readlink(fmt.Sprintf("/proc/%d/root", pid))
		if e != nil || out.Root != root {
			return out, errContract
		}
		stat, e := readKernel(fmt.Sprintf("/proc/%d/stat", pid), 8192)
		if e != nil {
			return out, e
		}
		out.Start, e = processStart(stat)
		if e != nil || out.Start != initialStart {
			return out, errContract
		}
		stat2, e := readKernel(fmt.Sprintf("/proc/%d/stat", pid), 8192)
		if e != nil {
			return out, e
		}
		start, e := processStart(stat2)
		if e != nil || start != out.Start {
			return out, errContract
		}
	}
	b2, e := readOwned(fd, "managed/state.json", 0600, hostwebruntime.MaxMetadataBytes)
	if e != nil || !bytes.Equal(b, b2) || !found {
		return out, errContract
	}
	return out, nil
}

func collectNamespaces(raw []byte, r *report) error {
	var v struct{ Processes []struct{ Namespace uint64 } }
	if json.Unmarshal(raw, &v) != nil || len(v.Processes) < 1 || len(v.Processes) > hostwebruntime.MaxProcesses {
		return errContract
	}
	for _, p := range v.Processes {
		if p.Namespace == 0 {
			return errContract
		}
		found := false
		for _, ns := range r.ObservedNamespaces {
			if ns == p.Namespace {
				found = true
			}
		}
		if !found {
			r.ObservedNamespaces = append(r.ObservedNamespaces, p.Namespace)
		}
	}
	return nil
}
func collectCurrentNamespaces(fd int, wantSHA string, r *report) error {
	b, e := readOwned(fd, "managed/state.json", 0600, hostwebruntime.MaxMetadataBytes)
	if e != nil || hash(b) != wantSHA {
		return errContract
	}
	return collectNamespaces(b, r)
}
func namespacesExtinct(ids []uint64) bool {
	if len(ids) == 0 || len(ids) > 3*hostwebruntime.MaxProcesses {
		return false
	}
	entries, e := os.ReadDir("/proc")
	if e != nil || len(entries) > 65536 {
		return false
	}
	for _, entry := range entries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		var s unix.Stat_t
		e := unix.Stat("/proc/"+entry.Name()+"/ns/pid", &s)
		if e == unix.ENOENT || e == unix.ESRCH {
			continue
		}
		if e != nil {
			return false
		}
		for _, ns := range ids {
			if s.Ino == ns {
				return false
			}
		}
	}
	return true
}
