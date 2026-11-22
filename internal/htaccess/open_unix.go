//go:build unix

package htaccess

import (
	"os"
	"syscall"
)

// O_NONBLOCK keeps a FIFO swapped in after Lstat from blocking the open; the
// SameFile check that follows rejects it.
const openFlags = os.O_RDONLY | syscall.O_NONBLOCK
