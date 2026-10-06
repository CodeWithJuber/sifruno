//go:build linux

package hostaccounts

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// Positive authority fixtures cannot live below /tmp, whose writable ancestor
// is intentionally refused. These tests own and remove only this new subtree.
func brokerPathsFixture(t *testing.T) (string, BrokerOptions) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned authority fixture under /root")
	}
	if authority("/root") != nil {
		t.Skip("/root ancestors do not satisfy broker authority")
	}
	root, e := os.MkdirTemp("/root", "broker-paths-")
	if e != nil {
		t.Skipf("cannot create owned /root fixture: %v", e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(root); e != nil {
			t.Errorf("remove owned fixture: %v", e)
		}
	})
	return root, BrokerOptions{StateDir: filepath.Join(root, "state"), HomesDir: filepath.Join(root, "homes"), SocketPath: filepath.Join(root, "socket", "broker.sock"), ControllerUID: 2000}
}

func brokerFixtureDir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if e := os.Mkdir(path, mode); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}

func brokerFixtureFile(t *testing.T, path, contents string) {
	t.Helper()
	if e := os.WriteFile(path, []byte(contents), 0600); e != nil {
		t.Fatal(e)
	}
}

func brokerPathsSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	entries := map[string]string{}
	e := filepath.WalkDir(root, func(path string, _ os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		st := info.Sys().(*syscall.Stat_t)
		value := fmt.Sprintf("%v:%d:%d:%d:%d:%d:%d:%d", info.Mode(), st.Uid, st.Gid, st.Dev, st.Ino, st.Nlink, info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			value += ":" + string(raw)
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, e := os.Readlink(path)
			if e != nil {
				return e
			}
			value += ":" + target
		}
		entries[path] = value
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return entries
}

func assertBrokerAdmissionReadOnly(t *testing.T, root string, opts BrokerOptions, want error) {
	t.Helper()
	before := brokerPathsSnapshot(t, root)
	if e := admitBrokerPaths(opts); e != want {
		t.Fatalf("admission = %v, want %v", e, want)
	}
	if after := brokerPathsSnapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatalf("admission changed fixture\nbefore: %v\nafter: %v", before, after)
	}
}

func TestBrokerPathAdmissionLateFailuresReadOnly(t *testing.T) {
	for _, target := range []string{"homes", "socket"} {
		for _, problem := range []string{"file", "symlink", "wrong_mode", "writable", "foreign_owner", "sticky", "setgid", "missing_parent", "linked_parent", "writable_parent", "foreign_parent"} {
			t.Run(target+"/"+problem, func(t *testing.T) {
				root, opts := brokerPathsFixture(t)
				path := opts.HomesDir
				if target == "socket" {
					path = filepath.Dir(opts.SocketPath)
				}
				switch problem {
				case "file":
					brokerFixtureFile(t, path, "owned unrelated file")
				case "symlink":
					if e := os.Symlink(root, path); e != nil {
						t.Fatal(e)
					}
				case "wrong_mode", "writable", "foreign_owner", "sticky", "setgid":
					mode := os.FileMode(0700)
					if problem == "writable" {
						mode = 0775
					} else if problem == "foreign_owner" {
						mode = 0755
					} else if problem == "sticky" {
						mode = 0755 | os.ModeSticky
					} else if problem == "setgid" {
						mode = 0755 | os.ModeSetgid
					}
					brokerFixtureDir(t, path, mode)
					if problem == "foreign_owner" {
						if e := os.Chown(path, 65534, -1); e != nil {
							t.Fatal(e)
						}
					}
				default:
					parent := filepath.Join(root, "late-parent")
					path = filepath.Join(parent, target)
					if problem == "linked_parent" {
						if e := os.Symlink(root, parent); e != nil {
							t.Fatal(e)
						}
					} else if problem != "missing_parent" {
						mode := os.FileMode(0755)
						if problem == "writable_parent" {
							mode = 0775
						}
						brokerFixtureDir(t, parent, mode)
						if problem == "foreign_parent" {
							if e := os.Chown(parent, 65534, -1); e != nil {
								t.Fatal(e)
							}
						}
					}
					if target == "homes" {
						opts.HomesDir = path
					} else {
						opts.SocketPath = filepath.Join(path, "broker.sock")
					}
				}
				assertBrokerAdmissionReadOnly(t, root, opts, ErrUnavailable)
			})
		}
	}
}

func TestBrokerPathAdmissionOccupiedSocketReadOnly(t *testing.T) {
	for _, kind := range []string{"file", "directory", "dangling_symlink", "socket"} {
		t.Run(kind, func(t *testing.T) {
			root, opts := brokerPathsFixture(t)
			brokerFixtureDir(t, filepath.Dir(opts.SocketPath), 0755)
			switch kind {
			case "file":
				brokerFixtureFile(t, opts.SocketPath, "occupied")
			case "directory":
				brokerFixtureDir(t, opts.SocketPath, 0700)
			case "dangling_symlink":
				if e := os.Symlink(filepath.Join(root, "missing"), opts.SocketPath); e != nil {
					t.Fatal(e)
				}
			case "socket":
				listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: opts.SocketPath, Net: "unix"})
				if e != nil {
					t.Fatal(e)
				}
				listener.SetUnlinkOnClose(false)
				defer listener.Close()
			}
			assertBrokerAdmissionReadOnly(t, root, opts, ErrConflict)
		})
	}
}

func TestBrokerPathAdmissionFreshHomesReadOnly(t *testing.T) {
	for _, existingState := range []bool{false, true} {
		t.Run(fmt.Sprint(existingState), func(t *testing.T) {
			root, opts := brokerPathsFixture(t)
			if existingState {
				brokerFixtureDir(t, opts.StateDir, 0700)
			}
			brokerFixtureDir(t, opts.HomesDir, 0755)
			brokerFixtureFile(t, filepath.Join(opts.HomesDir, "unrelated"), "preserve shared homes")
			assertBrokerAdmissionReadOnly(t, root, opts, ErrUnavailable)
		})
	}
}

func TestBrokerPathAdmissionPositiveReadOnly(t *testing.T) {
	root, opts := brokerPathsFixture(t)
	assertBrokerAdmissionReadOnly(t, root, opts, nil)
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{opts.StateDir, 0700}, {opts.HomesDir, 0755}, {filepath.Dir(opts.SocketPath), 0755}} {
		brokerFixtureDir(t, d.path, d.mode)
	}
	assertBrokerAdmissionReadOnly(t, root, opts, nil)
}

func TestBrokerPathAdmissionReopenAndInterruptedBootstrap(t *testing.T) {
	root, opts := brokerPathsFixture(t)
	brokerFixtureDir(t, opts.StateDir, 0700)
	brokerFixtureDir(t, opts.HomesDir, 0755)
	brokerFixtureFile(t, filepath.Join(opts.StateDir, ".sifruno-state"), "private Sifruno application state\n")
	assertBrokerAdmissionReadOnly(t, root, opts, nil)
	native := &fakeNative{users: map[string]record{}}
	s, e := openStore(context.Background(), opts, native)
	if e != nil {
		t.Fatal("interrupted bootstrap", e)
	}
	t.Cleanup(func() { s.close() })
	account := createFixture(t, s)
	brokerFixtureDir(t, account.Home, 0755)
	if e := s.close(); e != nil {
		t.Fatal(e)
	}
	assertBrokerAdmissionReadOnly(t, root, opts, nil)
	reopened, e := openStore(context.Background(), opts, native)
	if e != nil {
		t.Fatal("reopen", e)
	}
	defer reopened.close()
	accounts, e := reopened.list(context.Background())
	if e != nil || len(accounts) != 1 || accounts[0] != account {
		t.Fatal("reopen changed persisted account", accounts, e)
	}
}

func TestBrokerPathAdmissionInvalidAndCancelledReadOnly(t *testing.T) {
	root, opts := brokerPathsFixture(t)
	for _, bad := range []BrokerOptions{
		{StateDir: "relative", HomesDir: opts.HomesDir, SocketPath: opts.SocketPath, ControllerUID: 2000},
		{StateDir: opts.StateDir, HomesDir: opts.HomesDir, SocketPath: "/broker.sock", ControllerUID: 2000},
		{StateDir: opts.StateDir, HomesDir: opts.StateDir, SocketPath: opts.SocketPath, ControllerUID: 2000},
		{StateDir: opts.StateDir, HomesDir: opts.HomesDir, SocketPath: opts.SocketPath},
	} {
		assertBrokerAdmissionReadOnly(t, root, bad, ErrInvalid)
	}
	before := brokerPathsSnapshot(t, root)
	if e := RunBroker(nil, opts); e != ErrInvalid {
		t.Fatal("nil context", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := RunBroker(ctx, opts); e != ErrUnavailable {
		t.Fatal("cancelled context", e)
	}
	if after := brokerPathsSnapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("invalid/cancelled startup changed fixture")
	}
}
