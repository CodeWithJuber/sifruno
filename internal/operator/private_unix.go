//go:build !windows

package operator

import (
	"errors"
	"os"
	"syscall"
)

func privateHandle(_ *os.File, st os.FileInfo) error {
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || stat.Nlink != 1 || st.Mode().Perm()&0077 != 0 {
		return errors.New("invalid private file")
	}
	return nil
}
