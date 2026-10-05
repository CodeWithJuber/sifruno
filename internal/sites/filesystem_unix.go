//go:build !windows

package sites

import (
	"os"
	"syscall"
)

func guardHandle(_ *os.File, info os.FileInfo) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || (info.Mode().IsRegular() && stat.Nlink != 1) {
		return ErrUnavailable
	}
	return nil
}
func syncRoot(root *os.Root, name string) error {
	f, err := root.Open(name)
	if err != nil {
		return ErrUnavailable
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		return ErrUnavailable
	}
	return nil
}
