//go:build !linux

package hostaccounts

import "context"

func controllerLayout(ctx context.Context, _ LayoutOptions, prepare bool) LayoutReport {
	return probeControllerLayout(ctx, layoutPlatform(), prepare, layoutProbes{})
}
