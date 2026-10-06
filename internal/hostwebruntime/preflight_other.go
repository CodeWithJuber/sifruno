//go:build !linux

package hostwebruntime

import "context"

func inspectInstallation(ctx context.Context, opts Options, record func(string, bool)) error {
	record("native_linux", false)
	return ErrUnavailable
}
