//go:build linux

package hostwebruntime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/hostwebgeneration"
)

func procRead(pid int, name string, limit int) ([]byte, error) {
	if pid <= 1 {
		return nil, ErrRecovery
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, ErrRecovery
	}
	return b, nil
}
func startIdentity(pid int) (string, error) {
	b, err := procRead(pid, "stat", 8192)
	if err != nil {
		return "", err
	}
	end := bytes.LastIndex(b, []byte(") "))
	if end < 0 || !bytes.HasPrefix(b, []byte(strconv.Itoa(pid)+" (")) {
		return "", ErrRecovery
	}
	fields := strings.Fields(string(b[end+2:]))
	if len(fields) < 20 || !decimal.MatchString(fields[19]) {
		return "", ErrRecovery
	}
	return fields[19], nil
}
func bootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	s := strings.TrimSpace(string(b))
	if err != nil || !bootPattern.MatchString(s) {
		return "", ErrUnavailable
	}
	return s, nil
}
func namespaceID(pid int) (uint64, error) {
	var st unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid), &st) != nil {
		return 0, ErrRecovery
	}
	return st.Ino, nil
}
func statusFields(pid int) (map[string][]string, error) {
	b, err := procRead(pid, "status", 8192)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapInh", "CapAmb", "NSpid":
			if _, ok := out[k]; ok {
				return nil, ErrRecovery
			}
			out[k] = strings.Fields(v)
		}
	}
	for _, k := range []string{"Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapInh", "CapAmb", "NSpid"} {
		if _, ok := out[k]; !ok {
			return nil, ErrRecovery
		}
	}
	return out, nil
}
func (r *Runtime) pin(pid int, role, id, exe, config string) (processPin, error) {
	start, e := startIdentity(pid)
	if e != nil {
		return processPin{}, ErrRecovery
	}
	boot, e := bootID()
	if e != nil {
		return processPin{}, e
	}
	ns, e := namespaceID(pid)
	parent, _ := namespaceID(os.Getpid())
	if e != nil || ns == parent {
		return processPin{}, ErrUnavailable
	}
	h, e := executableHash(exe)
	if e != nil {
		return processPin{}, e
	}
	p := processPin{Role: role, AccountID: id, PID: pid, Start: start, Boot: boot, Executable: exe, ExecutableSHA256: h, Config: config, Namespace: ns}
	var st unix.Stat_t
	if unix.Stat(exe, &st) != nil {
		return processPin{}, ErrRecovery
	}
	p.ExecutableDev = uint64(st.Dev)
	p.ExecutableIno = st.Ino
	if r.binaries == nil {
		r.binaries = map[string]string{}
	}
	r.binaries[exe] = h
	if e = r.verifyPin(p); e != nil {
		return processPin{}, e
	}
	return p, nil
}
func (r *Runtime) verifyPin(p processPin) error {
	boot, e := bootID()
	if e != nil || boot != p.Boot {
		return ErrRecovery
	}
	start, e := startIdentity(p.PID)
	if e != nil || start != p.Start {
		return ErrRecovery
	}
	ns, e := namespaceID(p.PID)
	if e != nil || ns != p.Namespace {
		return ErrRecovery
	}
	status, e := statusFields(p.PID)
	if e != nil {
		return ErrRecovery
	}
	if len(status["NSpid"]) < 2 || status["NSpid"][len(status["NSpid"])-1] != "1" {
		return ErrRecovery
	}
	for _, k := range []string{"Uid", "Gid"} {
		if len(status[k]) != 4 {
			return ErrRecovery
		}
		for _, v := range status[k] {
			if v != "0" {
				return ErrRecovery
			}
		}
	}
	group, e := unix.Getpgid(p.PID)
	if e != nil || group != p.PID {
		return ErrRecovery
	}
	sid, e := unix.Getsid(p.PID)
	if e != nil || sid != p.PID {
		return ErrRecovery
	}
	fd, e := unix.Open(fmt.Sprintf("/proc/%d/exe", p.PID), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrRecovery
	}
	var actual, current unix.Stat_t
	e = unix.Fstat(fd, &actual)
	unix.Close(fd)
	if e != nil || unix.Lstat(p.Executable, &current) != nil || uint64(actual.Dev) != p.ExecutableDev || actual.Ino != p.ExecutableIno || actual.Dev != current.Dev || actual.Ino != current.Ino || actual.Mode&unix.S_IFMT != unix.S_IFREG || current.Uid != 0 || current.Nlink != 1 || current.Mode&0022 != 0 || r.binaries[p.Executable] != p.ExecutableSHA256 {
		return ErrRecovery
	}
	argv, e := procRead(p.PID, "cmdline", 8192)
	if e != nil || !commandMatches(r, p, argv) {
		return ErrRecovery
	}
	if again, e := startIdentity(p.PID); e != nil || again != p.Start {
		return ErrRecovery
	}
	return nil
}
func commandMatches(r *Runtime, p processPin, b []byte) bool {
	args := []string{p.Executable, "-DFOREGROUND", "-f", p.Config, "-d", r.opts.Profile.FrontChroot}
	if p.Role == "backend" {
		args[5] = filepath.Join(r.opts.Profile.BackendChrootRoot, p.AccountID)
	}
	if p.Role == "fpm" {
		args = []string{p.Executable, "-y", p.Config, "-F"}
		// FPM overwrites argv after startup; only this exact documented master
		// title/config path is accepted, never an arbitrary prefix match.
		title := bytes.TrimRight(b, "\x00")
		if string(title) == "php-fpm: master process ("+p.Config+")" {
			return true
		}
	}
	return bytes.Equal(b, []byte(strings.Join(args, "\x00")+"\x00"))
}

func (r *Runtime) verifyRecorded(pins []processPin, allowDead bool) error {
	for _, p := range pins {
		boot, e := bootID()
		if e != nil || boot != p.Boot {
			return ErrRecovery
		}
		if _, e := startIdentity(p.PID); os.IsNotExist(e) {
			if allowDead {
				continue
			}
			return ErrRecovery
		}
		if e := r.verifyPin(p); e != nil {
			return e
		}
	}
	return nil
}

// Linux owns descendant teardown: every daemon is namespace init. The exec
// trap prevents any daemon instruction before the parent's durable PID pin.
// Pdeathsig covers the trap/registration window; it is deliberately retained
// after detach, so controller-thread death fails closed rather than orphaning.
func (r *Runtime) gatedLaunch(ctx context.Context, v *record, role, id, exe, config string, args []string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := exec.Command(exe, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/", "TZ=UTC"}
	cmd.Dir = r.opts.Root
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Cloneflags: unix.CLONE_NEWPID, Ptrace: true, Pdeathsig: syscall.SIGKILL}
	if cmd.Start() != nil {
		return ErrUnavailable
	}
	pid := cmd.Process.Pid
	r.children[pid] = cmd.Process
	// pidfd remains tied to the exact child even if a PID is later reused.
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		delete(r.children, pid)
		return ErrUnavailable
	}
	defer unix.Close(fd)
	detached := false
	defer func() {
		if !detached {
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			_, _ = cmd.Process.Wait()
			delete(r.children, pid)
		}
	}()
	var status unix.WaitStatus
	for {
		var got int
		got, err = unix.Wait4(pid, &status, unix.WUNTRACED|unix.WNOHANG, nil)
		if err != nil {
			return ErrUnavailable
		}
		if got == pid {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	if !status.Stopped() || status.StopSignal() != unix.SIGTRAP {
		return ErrUnavailable
	}
	if unix.PtraceSetOptions(pid, unix.PTRACE_O_EXITKILL) != nil {
		return ErrUnavailable
	}
	p, err := r.pin(pid, role, id, exe, config)
	if err != nil {
		return err
	}
	v.Processes = append(v.Processes, p)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = r.persist(*v); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if unix.PtraceDetach(pid) != nil {
		return ErrUnavailable
	}
	detached = true
	return nil
}

func (r *Runtime) stop(v *record) error {
	if err := r.verifyRecorded(v.Processes, true); err != nil {
		return err
	}
	var fds []unix.PollFd
	var pids []int
	defer func() {
		for _, fd := range fds {
			unix.Close(int(fd.Fd))
		}
	}()
	// Obtain all exact handles and verify every identity before any signal.
	for i := len(v.Processes) - 1; i >= 0; i-- {
		p := v.Processes[i]
		if _, e := startIdentity(p.PID); os.IsNotExist(e) {
			continue
		}
		fd, e := unix.PidfdOpen(p.PID, 0)
		if e != nil {
			return ErrRecovery
		}
		if e = r.verifyPin(p); e != nil {
			unix.Close(fd)
			return e
		}
		fds = append(fds, unix.PollFd{Fd: int32(fd), Events: unix.POLLIN})
		pids = append(pids, p.PID)
	}
	for _, fd := range fds {
		if e := unix.PidfdSendSignal(int(fd.Fd), unix.SIGTERM, nil, 0); e != nil && e != unix.ESRCH {
			return ErrRecovery
		}
	}
	wait := func(timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for {
			all := true
			for _, fd := range fds {
				if fd.Revents&unix.POLLIN == 0 {
					all = false
				}
			}
			if all {
				return true
			}
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return false
			}
			if _, e := unix.Poll(fds, int(min(remaining, time.Second)/time.Millisecond)+1); e != nil && e != unix.EINTR {
				return false
			}
		}
	}
	if !wait(CleanupTimeout) {
		for _, fd := range fds {
			if fd.Revents&unix.POLLIN == 0 {
				if e := unix.PidfdSendSignal(int(fd.Fd), unix.SIGKILL, nil, 0); e != nil && e != unix.ESRCH {
					return ErrRecovery
				}
			}
		}
		if !wait(time.Second) {
			return ErrRecovery
		}
	}
	for _, pid := range pids {
		if child := r.children[pid]; child != nil {
			_, _ = child.Wait()
			delete(r.children, pid)
		}
	}
	v.Processes = nil
	return nil
}
func (r *Runtime) launch(ctx context.Context, v *record, g hostwebgeneration.Generation) error {
	p := r.opts.Profile
	base := filepath.Join(p.ManagedRoot, generationPath(g))
	for _, a := range g.Accounts {
		if a.State != "active" || g.Denied {
			continue
		}
		fpm := filepath.Join(base, "fpm/"+a.ID+".conf")
		if err := r.gatedLaunch(ctx, v, "fpm", a.ID, p.FPMBinary, fpm, []string{"-y", fpm, "-F"}); err != nil {
			return err
		}
		conf := filepath.Join(base, "apache/backends/"+a.ID+".conf")
		if err := r.gatedLaunch(ctx, v, "backend", a.ID, p.ApacheBinary, conf, []string{"-DFOREGROUND", "-f", conf, "-d", filepath.Join(p.BackendChrootRoot, a.ID)}); err != nil {
			return err
		}
	}
	conf := filepath.Join(base, "apache/front.conf")
	if err := r.gatedLaunch(ctx, v, "front", "", p.ApacheBinary, conf, []string{"-DFOREGROUND", "-f", conf, "-d", p.FrontChroot}); err != nil {
		return err
	}
	return retry(ctx, func() error { _, err := r.observe(ctx, *v); return err })
}

func (r *Runtime) syntax(ctx context.Context, g hostwebgeneration.Generation) error {
	p := r.opts.Profile
	base := filepath.Join(p.ManagedRoot, generationPath(g))
	if err := r.checkCommand(ctx, p.ApacheBinary, []string{"-t", "-f", filepath.Join(base, "apache/front.conf"), "-d", p.FrontChroot}); err != nil {
		return err
	}
	for _, a := range g.Accounts {
		if a.State == "active" && !g.Denied {
			if err := r.checkCommand(ctx, p.ApacheBinary, []string{"-t", "-f", filepath.Join(base, "apache/backends/"+a.ID+".conf"), "-d", filepath.Join(p.BackendChrootRoot, a.ID)}); err != nil {
				return err
			}
			if err := r.checkCommand(ctx, p.FPMBinary, []string{"-y", filepath.Join(base, "fpm/"+a.ID+".conf"), "-t"}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (r *Runtime) checkCommand(ctx context.Context, exe string, args []string) error {
	cmd := exec.Command(exe, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/", "TZ=UTC"}
	cmd.Dir = r.opts.Root
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Cloneflags: unix.CLONE_NEWPID, Pdeathsig: syscall.SIGKILL}
	if cmd.Start() != nil {
		return ErrUnavailable
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return ErrUnavailable
	}
	defer unix.Close(fd)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			return ErrRecovery
		}
		return ctx.Err()
	case <-ctx.Done():
		_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		select {
		case <-done:
			return ctx.Err()
		case <-time.After(CleanupTimeout):
			return ErrRecovery
		}
	}
}
