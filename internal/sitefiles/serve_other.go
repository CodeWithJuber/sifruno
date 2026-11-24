//go:build !linux

package sitefiles

import (
	"errors"
	"io"
	"os"
)

// Serve needs Linux's *at system calls; elsewhere it answers nothing.
func Serve(*os.File, io.Reader, io.Writer) error {
	return errors.New("the file helper runs only on Linux")
}
