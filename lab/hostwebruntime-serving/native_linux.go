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
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostwebgeneration"
	"sifruno/internal/hostwebruntime"
)

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
		return errContract
	}
	defer unix.Close(fd)
	if n, e := below(fd, "qualification-report.json", unix.O_RDONLY, 0); e != unix.ENOENT {
		if e == nil {
			unix.Close(n)
		}
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
	nonce, e := newID()
	if e != nil {
		return errContract
	}
	r := report{SchemaVersion: 1, FixtureOnly: true, ExecutionKind: "native-linux-driver", RunID: in.RunID, Nonce: nonce, RuntimeManifestSHA256: runtimeManifestSHA, InputSHA256: hash(raw), ProfileSHA256: digest(in.Profile), Stage: "driver_admission"}
	var rt *hostwebruntime.Runtime
	// A fresh cleanup context is used even after the serving deadline. Success
	// is decided only after cleanup, input recheck and report persistence.
	defer func() {
		if rt != nil {
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			e := rt.Shutdown(c)
			r.ShutdownPassed = e == nil
			r.ListenersExtinct = e == nil && extinct(c, in)
			cancel()
			r.ClosePassed = rt.Close() == nil
		}
		b, e := readOwned(fd, "qualification-input.json", 0600, inputLimit)
		r.InputStable = e == nil && bytes.Equal(b, raw)
		b, e = readKernel("/sys/fs/selinux/enforce", 8)
		r.SELinuxStable = e == nil && strings.TrimSpace(string(b)) == "1"
		if result == nil && (!r.ShutdownPassed || !r.ClosePassed || !r.ListenersExtinct || !r.InputStable || !r.SELinuxStable) {
			result = errContract
			r.Stage = "cleanup_or_stability_failed"
		}
		r.Passed = result == nil
		if r.Passed {
			r.Stage = "complete"
		} else {
			r.Stage += ":" + classify(result)
		}
		if writeReport(fd, r) != nil {
			result = errContract
			fmt.Fprintln(os.Stderr, "qualification_report_write_failed:"+r.Stage)
		}
	}()
	r.DriverSHA256, e = driverHash(fd)
	if e != nil {
		return e
	}
	r.Stage = "prerequisites"
	r.Prerequisites, e = prerequisites()
	if e != nil {
		return e
	}
	sigctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(sigctx, 120*time.Second)
	defer cancel()
	r.Stage = "runtime_open"
	rt, e = hostwebruntime.Open(hostwebruntime.Options{Root: in.Root, Profile: in.Profile})
	if e != nil {
		return e
	}
	bootstrap, e := generation(in, "", true)
	if e != nil {
		return e
	}
	r.Generations = append(r.Generations, bootstrap.Identity())
	r.Stage = "bootstrap"
	if e = rt.Bootstrap(ctx, bootstrap); e != nil {
		return e
	}
	if e = observe(ctx, rt, bootstrap, "bootstrap", &r); e != nil {
		return e
	}
	id, e := newID()
	if e != nil {
		return e
	}
	active, e := generation(in, id, false)
	if e != nil {
		return e
	}
	op, e := newID()
	if e != nil {
		return e
	}
	r.Generations = append(r.Generations, active.Identity())
	r.Stage = "apply_active"
	if e = rt.Apply(ctx, hostwebgeneration.Transition{OperationID: op, Revision: 0, Before: bootstrap, After: active}); e != nil {
		return e
	}
	if e = observe(ctx, rt, active, "active_before_requests", &r); e != nil {
		return e
	}
	client := servingClient()
	defer client.CloseIdleConnections()
	r.Stage = "static_php_worker_probes"
	for _, a := range in.Accounts {
		status, b, e := request(ctx, client, a.Domain, "/index.html")
		ok := e == nil && status == 200 && bytes.Equal(b, []byte("SIFRUNO_STATIC_"+a.Username+"\n"))
		r.Probes = append(r.Probes, probeEvidence{AccountID: a.ID, Kind: "static", Status: status, Bytes: len(b), SHA256: hash(b), ContractPassed: ok})
		if !ok {
			return errContract
		}
		status, b, e = request(ctx, client, a.Domain, "/probe.php")
		p, pe := phpBody(b, a)
		ok = e == nil && status == 200 && pe == nil
		r.Probes = append(r.Probes, probeEvidence{AccountID: a.ID, Kind: "php", Status: status, Bytes: len(b), SHA256: hash(b), ContractPassed: ok})
		if !ok {
			return errContract
		}
		if e = observe(ctx, rt, active, "active_after_php_"+a.Username, &r); e != nil {
			return e
		}
		w, e := actualWorker(fd, a, p, in.Profile.BackendChrootRoot+"/"+a.ID)
		if e != nil {
			return e
		}
		r.Workers = append(r.Workers, w)
		if e = observe(ctx, rt, active, "active_after_worker_"+a.Username, &r); e != nil {
			return e
		}
	}
	if e = observe(ctx, rt, active, "active_after_all_workers", &r); e != nil {
		return e
	}
	suspended := in
	suspended.Accounts = append([]hostaccounts.Account{}, in.Accounts...)
	for i := range suspended.Accounts {
		suspended.Accounts[i].State = "suspended"
		suspended.Accounts[i].Revision++
		suspended.Accounts[i].UpdatedAt = suspended.Accounts[i].UpdatedAt.Add(time.Nanosecond)
	}
	id, e = newID()
	if e != nil {
		return e
	}
	denied, e := generation(suspended, id, true)
	if e != nil {
		return e
	}
	op, e = newID()
	if e != nil {
		return e
	}
	r.Generations = append(r.Generations, denied.Identity())
	r.Stage = "apply_suspended_denied"
	if e = rt.Apply(ctx, hostwebgeneration.Transition{OperationID: op, Revision: 1, Before: active, After: denied}); e != nil {
		return e
	}
	if e = observe(ctx, rt, denied, "suspended_denied", &r); e != nil {
		return e
	}
	for _, host := range []string{in.Accounts[0].Domain, in.Accounts[1].Domain, "foreign.test"} {
		status, b, e := request(ctx, client, host, "/index.html")
		ok := e == nil && status == 403 && !bytes.Contains(b, []byte("SIFRUNO_STATIC_")) && !bytes.Contains(b, []byte("SIFRUNO_PHP_")) && !bytes.Contains(b, []byte("SIFRUNO_PRIVATE_")) && !bytes.Contains(b, []byte("SIFRUNO_CONTROLLER_"))
		r.Probes = append(r.Probes, probeEvidence{Kind: "denied_" + host, Status: status, Bytes: len(b), SHA256: hash(b), ContractPassed: ok})
		if !ok {
			return errContract
		}
	}
	return observe(ctx, rt, denied, "suspended_after_requests", &r)
}

// The journal provides candidates only. Fresh /proc identities, namespace PID,
// root, credentials and capability values are the worker evidence.
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
	if json.Unmarshal(b, &st) != nil || len(st.Processes) != 5 || string(st.Pending) != "null" {
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
