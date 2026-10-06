//go:build linux

package hostaccounts

import (
	"context"
	"os"
	"testing"
)

func startupTestDependencies(t *testing.T) startupNativeDependencies {
	t.Helper()
	return startupNativeDependencies{
		euid:      func() int { return 0 },
		users:     func() ([]nativeUser, error) { return []nativeUser{{UID: 7}}, nil },
		utilities: func() (map[string]os.FileInfo, error) { return nil, nil },
		readFile: func(path string, max int64) ([]byte, error) {
			if path != "/etc/nsswitch.conf" || max != maxNSSPolicyBytes {
				t.Fatal("unbounded or unexpected file")
			}
			return []byte("passwd: files\ngroup: files\nshadow: files\n"), nil
		},
		defaults: func() error { return nil }, paths: func(BrokerOptions) error { return nil },
		lstat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		authority: func(string) error { return nil }, empty: func(string, os.FileInfo) (bool, error) { return true, nil },
	}
}

func TestStartupNativeGuardComposition(t *testing.T) {
	opts := BrokerOptions{StateDir: "/dedicated/state", HomesDir: "/dedicated/homes", SocketPath: "/dedicated/run/broker.sock", ControllerUID: 7}
	for _, mode := range []string{"pass", "configuration", "privilege", "controller", "duplicate", "utilities", "nss_file", "nss_policy", "defaults", "paths"} {
		t.Run(mode, func(t *testing.T) {
			d := startupTestDependencies(t)
			o := opts
			want := -1
			switch mode {
			case "configuration":
				o.ControllerUID = 0
				want = 0
			case "privilege":
				d.euid = func() int { return 7 }
				want = 1
			case "controller":
				d.users = func() ([]nativeUser, error) { return nil, nil }
				want = 2
			case "duplicate":
				d.users = func() ([]nativeUser, error) { return []nativeUser{{UID: 7}, {UID: 7}}, nil }
				want = 2
			case "utilities":
				d.utilities = func() (map[string]os.FileInfo, error) { return nil, ErrUnavailable }
				want = 3
			case "nss_file":
				d.readFile = func(string, int64) ([]byte, error) { return nil, ErrUnavailable }
				want = 4
			case "nss_policy":
				d.readFile = func(string, int64) ([]byte, error) { return []byte("passwd: sss\ngroup: files\nshadow: files\n"), nil }
				want = 5
			case "defaults":
				d.defaults = func() error { return ErrUnavailable }
				want = 6
			case "paths":
				d.paths = func(BrokerOptions) error { return ErrUnavailable }
				want = 7
			}
			r := probeBrokerAdmission(context.Background(), "linux", nativeBrokerAdmissionProbes(o, d))
			if want < 0 {
				if !r.Supported {
					t.Fatal(r)
				}
				return
			}
			if r.Supported || r.Checks[want].Status != "refused" {
				t.Fatal(r)
			}
		})
	}
}

func TestStartupNativeFreshStateObservation(t *testing.T) {
	path := t.TempDir()
	if os.Chmod(path, 0700) != nil {
		t.Fatal("chmod")
	}
	info, e := os.Lstat(path)
	if e != nil {
		t.Fatal(e)
	}
	opts := BrokerOptions{StateDir: "/dedicated/state", HomesDir: "/dedicated/homes", SocketPath: "/dedicated/run/broker.sock", ControllerUID: 7}
	for _, mode := range []string{"missing", "empty", "persisted", "drift", "authority"} {
		t.Run(mode, func(t *testing.T) {
			d := startupTestDependencies(t)
			if mode != "missing" {
				d.lstat = func(string) (os.FileInfo, error) { return info, nil }
			}
			if mode == "persisted" {
				d.empty = func(string, os.FileInfo) (bool, error) { return false, nil }
			}
			if mode == "drift" {
				d.empty = func(string, os.FileInfo) (bool, error) { return false, ErrUnavailable }
			}
			if mode == "authority" {
				d.authority = func(string) error { return ErrUnavailable }
			}
			r := probeBrokerAdmission(context.Background(), "linux", nativeBrokerAdmissionProbes(opts, d))
			want := "pass"
			if mode == "persisted" {
				want = "not_checked"
			}
			if mode == "drift" || mode == "authority" {
				want = "refused"
			}
			if r.Checks[8].Status != want || r.Supported != (want == "pass") {
				t.Fatal(r)
			}
		})
	}
}
