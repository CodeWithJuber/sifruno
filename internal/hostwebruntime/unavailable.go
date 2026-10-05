//go:build !linux

package hostwebruntime

import (
	"context"
	"sifruno/internal/hostwebgeneration"
)

type Runtime struct{}

var _ hostwebgeneration.Executor = (*Runtime)(nil)

func Open(Options) (*Runtime, error)                                           { return nil, ErrUnavailable }
func (*Runtime) Bootstrap(context.Context, hostwebgeneration.Generation) error { return ErrUnavailable }
func (*Runtime) Observe(context.Context) (hostwebgeneration.Identity, error) {
	return hostwebgeneration.Identity{}, ErrUnavailable
}
func (*Runtime) Apply(context.Context, hostwebgeneration.Transition) error { return ErrUnavailable }
func (*Runtime) Rollback(context.Context, hostwebgeneration.Transition, hostwebgeneration.Generation) error {
	return ErrUnavailable
}
func (*Runtime) Shutdown(context.Context) error { return ErrUnavailable }
func (*Runtime) Close() error                   { return nil }
