//go:build linux

package hostwebruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func filesystemRuntime(t *testing.T) *Runtime {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("Linux root filesystem admission")
	}
	root := t.TempDir()
	o := testOptions(root)
	if e := os.Mkdir(o.Profile.ManagedRoot, 0700); e != nil {
		t.Fatal(e)
	}
	fd, e := checkedDir(o.Profile.ManagedRoot, true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { unix.Close(fd) })
	r := &Runtime{opts: o, fd: fd, lockFD: -1, inputsSHA: strings.Repeat("a", 64), gate: make(chan struct{}, 1), children: map[int]*os.Process{}}
	if mkdirBelow(fd, "generations") != nil {
		t.Fatal("generation directory")
	}
	return r
}
func TestDiskAndMetadataAreReal(t *testing.T) {
	r := filesystemRuntime(t)
	g := testGeneration(t, r.opts, "", true)
	if e := r.stage(g); e != nil {
		t.Fatal(e)
	}
	v := record{Version: 1, Current: g, InputsSHA256: r.inputsSHA}
	if e := r.persist(v); e != nil {
		t.Fatal(e)
	}
	got, e := r.load()
	if e != nil || got.Current.Identity() != g.Identity() {
		t.Fatal(e)
	}
	// No process/listener proof exists. Disk metadata must not produce Identity.
	if _, e := r.observe(context.Background(), got); e == nil {
		t.Fatal("metadata echoed as observed serving")
	}
	file := filepath.Join(r.opts.Profile.ManagedRoot, generationPath(g), "apache/front.conf")
	if e := os.WriteFile(file, []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := r.load(); e == nil {
		t.Fatal("disk alteration accepted")
	}
}
func TestConfinementAndLinkAdmission(t *testing.T) {
	r := filesystemRuntime(t)
	outside := t.TempDir()
	if e := os.Symlink(outside, filepath.Join(r.opts.Profile.ManagedRoot, "escape")); e != nil {
		t.Fatal(e)
	}
	if mkdirBelow(r.fd, "escape/written") == nil {
		t.Fatal("symlink mkdir escaped")
	}
	if _, e := os.Stat(filepath.Join(outside, "written")); !os.IsNotExist(e) {
		t.Fatal("outside write")
	}
	if e := writeExclusive(r.fd, "original", []byte("private")); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(filepath.Join(r.opts.Profile.ManagedRoot, "original"), filepath.Join(r.opts.Profile.ManagedRoot, "alias")); e != nil {
		t.Fatal(e)
	}
	if _, e := readBelow(r.fd, "original", 0600, 100); e == nil {
		t.Fatal("hardlink admitted")
	}
	if _, e := readBelow(r.fd, "../outside", 0600, 100); e == nil {
		t.Fatal("traversal admitted")
	}
}
func TestDirectoryModeAndUnknownConfig(t *testing.T) {
	r := filesystemRuntime(t)
	g := testGeneration(t, r.opts, "", true)
	if e := r.stage(g); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(r.opts.Profile.ManagedRoot, generationPath(g), "apache")
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if r.disk(g) == nil {
		t.Fatal("directory mode drift")
	}
	os.Chmod(dir, 0700)
	if e := os.WriteFile(filepath.Join(dir, "extra.conf"), []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	if r.disk(g) == nil {
		t.Fatal("unknown config admitted")
	}
}
func TestMetadataCompareAndExclusiveTemp(t *testing.T) {
	r := filesystemRuntime(t)
	g := testGeneration(t, r.opts, "", true)
	if e := r.stage(g); e != nil {
		t.Fatal(e)
	}
	v := record{Version: 1, Current: g, InputsSHA256: r.inputsSHA}
	if e := r.persist(v); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(r.opts.Profile.ManagedRoot, "state.json")
	data, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, append(data, ' '), 0600); e != nil {
		t.Fatal(e)
	}
	if r.persist(v) == nil {
		t.Fatal("concurrent metadata overwrite")
	}
	if e = os.WriteFile(file, data, 0600); e != nil {
		t.Fatal(e)
	}
	if e = writeExclusive(r.fd, "state.next", []byte("interrupted")); e != nil {
		t.Fatal(e)
	}
	if r.persist(v) == nil {
		t.Fatal("interrupted temporary overwritten")
	}
}
func TestCancellableLockDoesNotPoison(t *testing.T) {
	r := &Runtime{gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 50; i++ {
		if !errors.Is(r.acquire(ctx), context.Canceled) {
			t.Fatal("canceled lock")
		}
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if e := r.acquire(ctx2); e != nil {
		t.Fatal(e)
	}
	r.release()
}
func TestGenerationStorageBound(t *testing.T) {
	r := filesystemRuntime(t)
	for i := 0; i < MaxGenerations; i++ {
		if mkdirBelow(r.fd, "generations/"+strings.Repeat("a", 30)+string([]byte{byte('a' + i/10), byte('0' + i%10)})) != nil {
			t.Fatal("fixture directory")
		}
	}
	g := testGeneration(t, r.opts, "", true)
	if !errors.Is(r.stage(g), ErrLimit) {
		t.Fatal("generation bound")
	}
}
func TestDeniedRecoveryStorageReserve(t *testing.T) {
	r := filesystemRuntime(t)
	for i := 0; i < MaxGenerations-2; i++ {
		if mkdirBelow(r.fd, "generations/reserved-"+strings.Repeat("a", i+1)) != nil {
			t.Fatal("fixture directory")
		}
	}
	active := testGeneration(t, r.opts, strings.Repeat("b", 32), false)
	if !errors.Is(r.stage(active), ErrLimit) {
		t.Fatal("serving consumed denied recovery reserve")
	}
	denied := testGeneration(t, r.opts, strings.Repeat("c", 32), true)
	if e := r.stage(denied); e != nil {
		t.Fatal("denied slot not available", e)
	}
}
