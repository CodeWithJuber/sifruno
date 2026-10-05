//go:build !linux

package hostwebruntime

import (
	"context"
	"sifruno/internal/hostwebgeneration"
)

type Runtime struct{}

var _ hostwebgeneration.Executor = (*Runtime)(nil)
var _ hostwebgeneration.DeniedRepairer = (*Runtime)(nil)

func (*Runtime) InspectRecovery(context.Context) (hostwebgeneration.RecoveryInspection, error) {
	return hostwebgeneration.RecoveryInspection{}, ErrUnavailable
}
func (*Runtime) RepairDenied(context.Context, hostwebgeneration.DeniedRepairRequest) (hostwebgeneration.DeniedRepairReceipt, error) {
	return hostwebgeneration.DeniedRepairReceipt{}, ErrUnavailable
}

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
