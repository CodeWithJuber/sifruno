//go:build !windows

package hostwebgeneration

import (
	"os"
	"syscall"
)

func guardOwner() error {
	if os.Geteuid() != 0 {
		return ErrUnavailable
	}
	return nil
}
func guardDirectory(path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || st.Uid != 0 {
		return ErrUnavailable
	}
	return nil
}
func guardFile(_ string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 {
		return ErrUnavailable
	}
	return nil
}
