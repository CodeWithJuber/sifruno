//go:build linux

package hostaccounts

import (
	"errors"
	"os"
)

func brokerAdmissionProbes(opts BrokerOptions) [9]func() error {
	return nativeBrokerAdmissionProbes(opts, startupNativeDependencies{os.Geteuid, systemUsers, trustedUtilities, readBoundedSystemFile, supportedUseraddDefaults, admitBrokerPaths, os.Lstat, authority, brokerDirectoryEmpty})
}

// Per-call dependencies keep tests isolated without mutable process globals.
type startupNativeDependencies struct {
	euid      func() int
	users     func() ([]nativeUser, error)
	utilities func() (map[string]os.FileInfo, error)
	readFile  func(string, int64) ([]byte, error)
	defaults  func() error
	paths     func(BrokerOptions) error
	lstat     func(string) (os.FileInfo, error)
	authority func(string) error
	empty     func(string, os.FileInfo) (bool, error)
}

func nativeBrokerAdmissionProbes(opts BrokerOptions, d startupNativeDependencies) [9]func() error {
	var nss []byte
	return [9]func() error{
		func() error {
			if !validBrokerPaths(opts) {
				return ErrInvalid
			}
			return nil
		},
		func() error {
			if d.euid() != 0 {
				return ErrUnavailable
			}
			return nil
		},
		func() error {
			users, e := d.users()
			if e != nil {
				return e
			}
			count := 0
			for _, u := range users {
				if u.UID > 0 && uint64(u.UID) == uint64(opts.ControllerUID) {
					count++
				}
			}
			if count != 1 {
				return ErrInvalid
			}
			return nil
		},
		func() error { _, e := d.utilities(); return e },
		func() error {
			var e error
			nss, e = d.readFile("/etc/nsswitch.conf", maxNSSPolicyBytes)
			return e
		},
		func() error { return filesOnlyNSS(nss) },
		d.defaults,
		func() error { return d.paths(opts) },
		func() error {
			info, e := d.lstat(opts.StateDir)
			if errors.Is(e, os.ErrNotExist) {
				return nil
			}
			if e != nil || info == nil || info.Mode() != os.ModeDir|0700 || d.authority(opts.StateDir) != nil {
				return ErrUnavailable
			}
			empty, e := d.empty(opts.StateDir, info)
			if e != nil {
				return ErrUnavailable
			}
			if !empty {
				return errPersistedAdmissionState
			}
			return nil
		},
	}
}
