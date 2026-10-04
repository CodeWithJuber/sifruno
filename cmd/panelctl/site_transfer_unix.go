//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func guardTransferHandle(_ *os.File, info os.FileInfo) error {
	value, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (info.Mode().IsRegular() && value.Nlink != 1) {
		return errors.New("unsafe archive file")
	}
	return nil
}
func guardTransferPath(_ string) error { return nil }
