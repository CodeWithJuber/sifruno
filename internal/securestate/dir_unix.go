//go:build !windows

package securestate

import "os"

func protect(path string) error { return os.Chmod(path, 0700) }
