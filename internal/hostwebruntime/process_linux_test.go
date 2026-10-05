//go:build linux

package hostwebruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This helper is compiled only into the test binary. It is not Apache/FPM and
// cannot qualify serving, account isolation or distribution compatibility.
func init() {
	if len(os.Args) == 3 && os.Args[1] == "--runtime-mechanics-child" {
		_, _ = syscall.Setsid()
		_ = os.WriteFile(os.Args[2], []byte(strconv.Itoa(os.Getpid())), 0600)
		for {
			time.Sleep(time.Second)
		}
	}
	if len(os.Args) == 6 && os.Args[1] == "-DFOREGROUND" && strings.Contains(os.Args[3], "TestNamespace") {
		managed := filepath.Clean(filepath.Join(filepath.Dir(os.Args[3]), "../../.."))
		exe, _ := os.Executable()
		child := exec.Command(exe, "--runtime-mechanics-child", filepath.Join(managed, "mechanics.descendant"))
		child.Env = []string{"PATH=/usr/bin:/bin"}
		if child.Start() != nil {
			os.Exit(2)
		}
		_ = os.WriteFile(filepath.Join(managed, "mechanics.started"), []byte("resumed"), 0600)
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGTERM)
		<-done
		os.Exit(0)
	}
}
func mechanics(t *testing.T) (*Runtime, record, string) {
	t.Helper()
	if os.Getenv("SIFRUNO_NATIVE_RUNTIME_TEST") != "1" {
		t.Skip("explicit disposable Linux native mechanics opt-in required")
	}
	r := filesystemRuntime(t)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	r.opts.Profile.ApacheBinary = exe
	r.opts.Profile.FPMBinary = exe
	g := testGeneration(t, r.opts, "", true)
	if e = r.stage(g); e != nil {
		t.Fatal(e)
	}
	v := record{Version: 1, Current: g, InputsSHA256: r.inputsSHA}
	if e = r.persist(v); e != nil {
		t.Fatal(e)
	}
	conf := filepath.Join(r.opts.Profile.ManagedRoot, generationPath(g), "apache/front.conf")
	return r, v, conf
}
func TestNamespaceRegistrationAndDescendantCleanup(t *testing.T) {
	r, v, conf := mechanics(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e := r.gatedLaunch(ctx, &v, "front", "", r.opts.Profile.ApacheBinary, conf, []string{"-DFOREGROUND", "-f", conf, "-d", r.opts.Profile.FrontChroot}); e != nil {
		t.Fatal("required pidns/ptrace/pidfd mechanics unavailable:", e)
	}
	t.Cleanup(func() { _ = r.stop(&v) })
	if e := retry(ctx, func() error {
		_, e := os.Stat(filepath.Join(r.opts.Profile.ManagedRoot, "mechanics.descendant"))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	disk, e := r.load()
	if e != nil || len(disk.Processes) != 1 {
		t.Fatal("durable registration missing", e)
	}
	if e = r.verifyPin(disk.Processes[0]); e != nil {
		t.Fatal(e)
	}
	pin := disk.Processes[0]
	bad := pin
	bad.Start = "999999999999999"
	if r.verifyPin(bad) == nil {
		t.Fatal("foreign start identity")
	}
	bad = pin
	bad.Boot = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if r.verifyPin(bad) == nil {
		t.Fatal("foreign boot")
	}
	ids, e := namespaceMembers(pin)
	if e != nil || len(ids) < 2 {
		t.Fatal("descendant not observed", e)
	}
	if e = r.stop(&v); e != nil {
		t.Fatal(e)
	}
	for _, pid := range ids {
		if _, e = startIdentity(pid); !os.IsNotExist(e) {
			t.Fatal("namespace descendant remains", pid, e)
		}
	}
}
func TestNamespaceStoppedChildReapedOnRegistrationFailure(t *testing.T) {
	r, v, conf := mechanics(t)
	if e := writeExclusive(r.fd, "state.next", []byte("interrupted")); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e := r.gatedLaunch(ctx, &v, "front", "", r.opts.Profile.ApacheBinary, conf, []string{"-DFOREGROUND", "-f", conf, "-d", r.opts.Profile.FrontChroot})
	if !errors.Is(e, ErrRecovery) {
		t.Fatal("required stopped registration failure path:", e)
	}
	if len(v.Processes) != 1 {
		t.Fatal("registration trap was not reached")
	}
	if _, e = startIdentity(v.Processes[0].PID); !os.IsNotExist(e) {
		t.Fatal("stopped init not reaped", e)
	}
	if _, e = os.Stat(filepath.Join(r.opts.Profile.ManagedRoot, "mechanics.started")); !os.IsNotExist(e) {
		t.Fatal("daemon executed before durable registration")
	}
	// Actual on-disk prior metadata is unchanged, not a healthy observation.
	b, e := os.ReadFile(filepath.Join(r.opts.Profile.ManagedRoot, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	var old record
	if json.Unmarshal(b, &old) != nil || len(old.Processes) != 0 {
		t.Fatal("failed registration replaced prior metadata")
	}
}
