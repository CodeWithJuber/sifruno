//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func layoutGuestFixture(t *testing.T) (string, LayoutOptions, layoutNativeDependencies) {
	t.Helper()
	if os.Getenv("SIFRUNO_CONTROLLER_LAYOUT_GUEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires explicit isolated Linux guest and root")
	}
	if authority("/run") != nil {
		t.Fatal("isolated guest /run authority required")
	}
	root, e := os.MkdirTemp("/run", "l-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if filepath.Dir(root) != "/run" || !strings.HasPrefix(filepath.Base(root), "l-") {
			t.Fatal("invalid owned fixture cleanup path")
		}
		if e := os.RemoveAll(root); e != nil {
			t.Error(e)
		}
	})
	if os.Chmod(root, 0755) != nil {
		t.Fatal("fresh fixture traversal mode")
	}
	opts := LayoutOptions{BrokerOptions: BrokerOptions{StateDir: filepath.Join(root, "broker"), HomesDir: filepath.Join(root, "homes"), SocketPath: filepath.Join(root, "socket", "broker.sock"), ControllerUID: 65534}, ControllerStateDir: filepath.Join(root, "controller")}
	d := nativeLayoutDependencies()
	// Only policy inputs are isolated per-call fixtures. All directory admission,
	// ownership, no-follow handles, exclusive mkdirat and descriptor chown are real.
	d.admission = func(ctx context.Context, broker BrokerOptions) BrokerAdmissionReport {
		p := layoutGuestStartupDependencies()
		return probeBrokerAdmission(ctx, "linux", nativeBrokerAdmissionProbes(broker, p))
	}
	return root, opts, d
}

func layoutGuestStartupDependencies() startupNativeDependencies {
	return startupNativeDependencies{
		euid:      os.Geteuid,
		users:     func() ([]nativeUser, error) { return []nativeUser{{UID: 65534}}, nil },
		utilities: func() (map[string]os.FileInfo, error) { return nil, nil },
		readFile: func(string, int64) ([]byte, error) {
			return []byte("passwd: files\ngroup: files\nshadow: files\n"), nil
		},
		defaults: func() error { return nil }, paths: admitBrokerPaths, lstat: os.Lstat, authority: authority, empty: brokerDirectoryEmpty,
	}
}

func layoutFixturePaths(opts LayoutOptions) [4]string {
	return [4]string{opts.BrokerOptions.StateDir, opts.BrokerOptions.HomesDir, filepath.Dir(opts.BrokerOptions.SocketPath), opts.ControllerStateDir}
}

func layoutFixtureExisting(t *testing.T, opts LayoutOptions, index int) {
	t.Helper()
	path := layoutFixturePaths(opts)[index]
	mode := os.FileMode(0755)
	if index == 0 || index == 3 {
		mode = 0700
	}
	brokerFixtureDir(t, path, mode)
	if index == 3 && os.Chown(path, int(opts.BrokerOptions.ControllerUID), 0) != nil {
		t.Fatal("fixture controller ownership")
	}
}

func assertLayoutNoAdditions(t *testing.T, root string, opts LayoutOptions, d layoutNativeDependencies) LayoutReport {
	t.Helper()
	before := brokerPathsSnapshot(t, root)
	var result LayoutReport
	for _, prepare := range []bool{false, true} {
		result = nativeControllerLayout(context.Background(), opts, prepare, d)
		if result.Ready || result.ReadOnly == prepare {
			t.Fatal("unsafe layout admitted", result)
		}
		if after := brokerPathsSnapshot(t, root); !reflect.DeepEqual(before, after) {
			t.Fatalf("refusal changed owned fixture: before=%v after=%v", before, after)
		}
	}
	return result
}

func TestControllerLayoutNativeFreshPreparation(t *testing.T) {
	root, opts, d := layoutGuestFixture(t)
	before := brokerPathsSnapshot(t, root)
	r := nativeControllerLayout(context.Background(), opts, false, d)
	if !r.Ready || !r.ReadOnly {
		t.Fatal(r)
	}
	for _, dir := range r.Directories {
		if dir.Action != "planned_create" {
			t.Fatal(r)
		}
	}
	if after := brokerPathsSnapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("read-only fresh check created paths")
	}
	chownCalls := 0
	actualChown := d.chown
	d.chown = func(f *os.File, uid, gid int) error {
		chownCalls++
		if uid != 65534 || gid != -1 {
			t.Fatal("wrong ownership declaration")
		}
		return actualChown(f, uid, gid)
	}
	r = nativeControllerLayout(context.Background(), opts, true, d)
	if !r.Ready || r.ReadOnly || chownCalls != 1 {
		t.Fatal(r, chownCalls)
	}
	for i, path := range layoutFixturePaths(opts) {
		info, e := os.Lstat(path)
		mode, uid := os.FileMode(0755), uint32(0)
		if i == 0 || i == 3 {
			mode = 0700
		}
		if i == 3 {
			uid = 65534
		}
		if e != nil || !layoutMetadata(info, mode, uid) || r.Directories[i].Action != "created" {
			t.Fatal("incorrect physical layout", path, info, e, r)
		}
	}
	if _, e := os.Lstat(opts.BrokerOptions.SocketPath); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("setup touched socket", e)
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 4 {
		t.Fatal("unexpected setup additions", entries, e)
	}
	before = brokerPathsSnapshot(t, root)
	r = nativeControllerLayout(context.Background(), opts, true, d)
	if !r.Ready || chownCalls != 1 {
		t.Fatal("idempotent exact existing layout", r)
	}
	for _, dir := range r.Directories {
		if dir.Action != "admitted_existing" {
			t.Fatal(r)
		}
	}
	if after := brokerPathsSnapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("existing layout metadata changed")
	}
}

func TestControllerLayoutNativeExistingNoAdoption(t *testing.T) {
	for index := 0; index < 4; index++ {
		for _, problem := range []string{"nonempty", "mode", "foreign_owner", "group", "special", "symlink", "file"} {
			t.Run(layoutFixtureRole(index)+"/"+problem, func(t *testing.T) {
				root, opts, d := layoutGuestFixture(t)
				path := layoutFixturePaths(opts)[index]
				if problem == "symlink" {
					if os.Symlink(root, path) != nil {
						t.Fatal("symlink fixture")
					}
				} else if problem == "file" {
					brokerFixtureFile(t, path, "unrelated declaration")
				} else {
					layoutFixtureExisting(t, opts, index)
					switch problem {
					case "nonempty":
						brokerFixtureFile(t, filepath.Join(path, "unrelated"), "keep")
					case "mode":
						if os.Chmod(path, 0750) != nil {
							t.Fatal("mode fixture")
						}
					case "foreign_owner":
						if os.Chown(path, 12345, -1) != nil {
							t.Fatal("owner fixture")
						}
					case "group":
						if os.Chown(path, -1, 12345) != nil {
							t.Fatal("group fixture")
						}
					case "special":
						info, _ := os.Lstat(path)
						if os.Chmod(path, info.Mode().Perm()|os.ModeSetgid) != nil {
							t.Fatal("setgid fixture")
						}
					}
				}
				assertLayoutNoAdditions(t, root, opts, d)
			})
		}
	}
}

func layoutFixtureRole(index int) string {
	return []string{"broker_state", "managed_homes", "socket_parent", "controller_state"}[index]
}

func TestControllerLayoutNativeRefusalNoAdditions(t *testing.T) {
	for _, problem := range []string{"overlap", "relative", "unclean", "zero_uid", "sentinel_uid", "bounds", "effective_group", "missing_parent", "setgid_parent", "writable_parent", "symlink_parent", "socket_file", "socket_symlink", "controller_private_ancestor", "socket_private_ancestor", "duplicate_controller", "missing_controller", "nss", "utilities", "defaults"} {
		t.Run(problem, func(t *testing.T) {
			root, opts, d := layoutGuestFixture(t)
			privateAccess := false
			switch problem {
			case "effective_group":
				d.egid = func() int { return 12345 }
			case "overlap":
				opts.ControllerStateDir = filepath.Join(opts.BrokerOptions.HomesDir, "private")
			case "relative":
				opts.ControllerStateDir = "relative"
			case "unclean":
				opts.ControllerStateDir = root + "/./controller"
			case "zero_uid":
				opts.BrokerOptions.ControllerUID = 0
			case "sentinel_uid":
				opts.BrokerOptions.ControllerUID = ^uint32(0)
			case "bounds":
				opts.ControllerStateDir = "/" + strings.Repeat("x", 2049)
			case "missing_parent":
				opts.ControllerStateDir = filepath.Join(root, "missing", "controller")
			case "setgid_parent", "writable_parent", "symlink_parent", "controller_private_ancestor", "socket_private_ancestor":
				parent := filepath.Join(root, "parent")
				mode := os.FileMode(0755)
				if problem == "setgid_parent" {
					mode |= os.ModeSetgid
				}
				if problem == "writable_parent" {
					mode = 0775
				}
				if strings.Contains(problem, "private_ancestor") {
					mode = 0700
					privateAccess = true
				}
				if problem == "symlink_parent" {
					if os.Symlink(root, parent) != nil {
						t.Fatal("linked parent")
					}
				} else {
					brokerFixtureDir(t, parent, mode)
				}
				if problem == "socket_private_ancestor" {
					opts.BrokerOptions.SocketPath = filepath.Join(parent, "socket", "broker.sock")
				} else {
					opts.ControllerStateDir = filepath.Join(parent, "controller")
				}
			case "socket_file", "socket_symlink":
				layoutFixtureExisting(t, opts, 2)
				if problem == "socket_file" {
					brokerFixtureFile(t, opts.BrokerOptions.SocketPath, "occupied")
				} else if os.Symlink(filepath.Join(root, "missing"), opts.BrokerOptions.SocketPath) != nil {
					t.Fatal("occupied dangling socket")
				}
			default:
				p := layoutGuestStartupDependencies()
				switch problem {
				case "duplicate_controller":
					p.users = func() ([]nativeUser, error) { return []nativeUser{{UID: 65534}, {UID: 65534}}, nil }
				case "missing_controller":
					p.users = func() ([]nativeUser, error) { return nil, nil }
				case "nss":
					p.readFile = func(string, int64) ([]byte, error) { return []byte("passwd: sss\ngroup: files\nshadow: files\n"), nil }
				case "utilities":
					p.utilities = func() (map[string]os.FileInfo, error) { return nil, ErrUnavailable }
				case "defaults":
					p.defaults = func() error { return ErrUnavailable }
				}
				d.admission = func(ctx context.Context, opts BrokerOptions) BrokerAdmissionReport {
					return probeBrokerAdmission(ctx, "linux", nativeBrokerAdmissionProbes(opts, p))
				}
			}
			r := assertLayoutNoAdditions(t, root, opts, d)
			if privateAccess && r.Checks[10].Status != "refused" {
				t.Fatal("missing controller access refusal", r)
			}
		})
	}
}

func TestControllerLayoutNativePartialCancellationPreserves(t *testing.T) {
	for _, problem := range []string{"canceled_initially", "canceled_after_broker", "mkdir_failure", "chown_failure", "canceled_after_chown"} {
		t.Run(problem, func(t *testing.T) {
			root, opts, d := layoutGuestFixture(t)
			unrelated := filepath.Join(root, "unrelated")
			brokerFixtureFile(t, unrelated, "keep unrelated bytes")
			before := brokerPathsSnapshot(t, root)[unrelated]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch problem {
			case "canceled_initially":
				cancel()
			case "canceled_after_broker":
				actual := d.admission
				calls := 0
				d.admission = func(ctx context.Context, opts BrokerOptions) BrokerAdmissionReport {
					calls++
					if calls == 4 {
						cancel()
					}
					return actual(ctx, opts)
				}
			case "mkdir_failure":
				actual := d.mkdir
				d.mkdir = func(parent int, leaf string, mode uint32) error {
					if leaf == "homes" {
						return os.ErrPermission
					}
					return actual(parent, leaf, mode)
				}
			case "chown_failure":
				d.chown = func(*os.File, int, int) error { return os.ErrPermission }
			case "canceled_after_chown":
				actual := d.chown
				d.chown = func(f *os.File, uid, gid int) error { e := actual(f, uid, gid); cancel(); return e }
			}
			r := nativeControllerLayout(ctx, opts, true, d)
			if r.Ready || r.Checks[12].Status != "refused" && problem != "canceled_initially" {
				t.Fatal(r)
			}
			if after := brokerPathsSnapshot(t, root)[unrelated]; before != after {
				t.Fatal("partial failure altered unrelated fixture")
			}
			paths := layoutFixturePaths(opts)
			for i, path := range paths {
				_, e := os.Lstat(path)
				wantExisting := problem != "canceled_initially" && (i == 0 || problem == "chown_failure" || problem == "canceled_after_chown")
				if wantExisting && e != nil || !wantExisting && !errors.Is(e, os.ErrNotExist) {
					t.Fatal("partial additions not preserved", problem, i, e)
				}
			}
			if problem == "chown_failure" || problem == "canceled_after_chown" {
				info, _ := os.Lstat(opts.ControllerStateDir)
				uid := uint32(0)
				if problem == "canceled_after_chown" {
					uid = 65534
				}
				if !layoutMetadata(info, 0700, uid) {
					t.Fatal("partial controller metadata changed", info)
				}
			}
		})
	}
}

func TestControllerLayoutNativePinnedOwnership(t *testing.T) {
	for _, problem := range []string{"leaf_replacement", "occupied_at_mkdir", "parent_replacement"} {
		t.Run(problem, func(t *testing.T) {
			root, opts, d := layoutGuestFixture(t)
			chownCalls := 0
			actualChown := d.chown
			d.chown = func(f *os.File, uid, gid int) error { chownCalls++; return actualChown(f, uid, gid) }
			unrelated := filepath.Join(root, "unrelated")
			brokerFixtureDir(t, unrelated, 0700)
			unrelatedBefore, _ := os.Lstat(unrelated)
			switch problem {
			case "leaf_replacement":
				actual := d.open
				d.open = func(parent int, name string) (*os.File, error) {
					f, e := actual(parent, name)
					if e == nil && name == "controller" {
						if os.Rename(opts.ControllerStateDir, filepath.Join(root, "preserved-controller")) != nil || os.Symlink(unrelated, opts.ControllerStateDir) != nil {
							t.Fatal("replacement fixture")
						}
					}
					return f, e
				}
			case "occupied_at_mkdir":
				actual := d.mkdir
				d.mkdir = func(parent int, name string, mode uint32) error {
					if name == "controller" && unix.Mkdirat(parent, name, mode) != nil {
						t.Fatal("race occupant fixture")
					}
					return actual(parent, name, mode)
				}
			case "parent_replacement":
				parent := filepath.Join(root, "parent")
				brokerFixtureDir(t, parent, 0755)
				opts.BrokerOptions.StateDir = filepath.Join(parent, "broker")
				actual := d.open
				d.open = func(fd int, name string) (*os.File, error) {
					f, e := actual(fd, name)
					if e == nil && name == parent {
						if os.Rename(parent, filepath.Join(root, "preserved-parent")) != nil {
							t.Fatal("parent drift")
						}
						brokerFixtureDir(t, parent, 0755)
					}
					return f, e
				}
			}
			r := nativeControllerLayout(context.Background(), opts, true, d)
			if r.Ready || chownCalls != 0 {
				t.Fatal("drift was adopted or chowned", r, chownCalls)
			}
			unrelatedAfter, _ := os.Lstat(unrelated)
			if !os.SameFile(unrelatedBefore, unrelatedAfter) || !layoutMetadata(unrelatedAfter, 0700, 0) {
				t.Fatal("unrelated target changed")
			}
			if problem == "leaf_replacement" {
				preserved, e := os.Lstat(filepath.Join(root, "preserved-controller"))
				if e != nil || !layoutMetadata(preserved, 0700, 0) {
					t.Fatal("created leaf not preserved", preserved, e)
				}
			}
			if problem == "parent_replacement" {
				for _, parent := range []string{"parent", "preserved-parent"} {
					if _, e := os.Lstat(filepath.Join(root, parent, "broker")); !errors.Is(e, os.ErrNotExist) {
						t.Fatal("parent drift wrote through stale directory", e)
					}
				}
			}
		})
	}
}

func TestControllerLayoutNativeRestrictiveUmask(t *testing.T) {
	for _, problem := range []string{"success", "chmod_failure", "canceled_before_chmod", "replacement_before_chmod"} {
		t.Run(problem, func(t *testing.T) {
			root, opts, d := layoutGuestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// A per-call mkdir mask exercises the same initial 0700 leaves as
			// umask 077 without changing process-global umask or another test.
			actualMkdir := d.mkdir
			d.mkdir = func(parent int, name string, mode uint32) error { return actualMkdir(parent, name, mode&0700) }
			chmodCalls := 0
			actualChmod := d.chmod
			d.chmod = func(f *os.File, mode os.FileMode) error {
				chmodCalls++
				if problem == "chmod_failure" {
					return os.ErrPermission
				}
				return actualChmod(f, mode)
			}
			unrelated := filepath.Join(root, "unrelated")
			brokerFixtureDir(t, unrelated, 0700)
			before, _ := os.Lstat(unrelated)
			if problem == "canceled_before_chmod" || problem == "replacement_before_chmod" {
				actualOpen := d.open
				d.open = func(parent int, name string) (*os.File, error) {
					f, e := actualOpen(parent, name)
					if e == nil && name == "homes" {
						if problem == "canceled_before_chmod" {
							cancel()
						} else if os.Rename(opts.BrokerOptions.HomesDir, filepath.Join(root, "preserved-homes")) != nil || os.Symlink(unrelated, opts.BrokerOptions.HomesDir) != nil {
							t.Fatal("pre-chmod drift fixture")
						}
					}
					return f, e
				}
			}
			r := nativeControllerLayout(ctx, opts, true, d)
			if problem == "success" {
				if !r.Ready || chmodCalls != 2 {
					t.Fatal("restrictive mask not prepared", r, chmodCalls)
				}
				for i, path := range layoutFixturePaths(opts) {
					info, e := os.Lstat(path)
					mode, uid := os.FileMode(0755), uint32(0)
					if i == 0 || i == 3 {
						mode = 0700
					}
					if i == 3 {
						uid = 65534
					}
					if e != nil || !layoutMetadata(info, mode, uid) {
						t.Fatal("incorrect prepared masked leaf", i, info, e)
					}
				}
				beforeSecond := brokerPathsSnapshot(t, root)
				if next := nativeControllerLayout(context.Background(), opts, true, d); !next.Ready || chmodCalls != 2 || !reflect.DeepEqual(beforeSecond, brokerPathsSnapshot(t, root)) {
					t.Fatal("existing leaf chmodded", next)
				}
			} else {
				if r.Ready {
					t.Fatal("unsafe chmod admitted", r)
				}
				if problem != "chmod_failure" && chmodCalls != 0 {
					t.Fatal("chmod after drift/cancellation", chmodCalls)
				}
				if _, e := os.Lstat(opts.BrokerOptions.StateDir); e != nil {
					t.Fatal("completed broker not preserved", e)
				}
				if _, e := os.Lstat(filepath.Dir(opts.BrokerOptions.SocketPath)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("continued after chmod failure", e)
				}
			}
			after, _ := os.Lstat(unrelated)
			if !os.SameFile(before, after) || !layoutMetadata(after, 0700, 0) {
				t.Fatal("unrelated descriptor chmod target changed")
			}
		})
	}
}
