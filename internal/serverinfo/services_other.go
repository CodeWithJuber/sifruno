//go:build !windows && !linux

package serverinfo

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
)

func localPartition(p disk.PartitionStat) bool { return localFilesystem(p) }
func serviceManager() string                   { return "unsupported" }
func collectServices(context.Context) Services {
	return Services{SampledAt: time.Now().UTC(), Manager: serviceManager(), Availability: Availability{Reason: "Native service inventory is not implemented on this platform"}, Items: []Service{}}
}
