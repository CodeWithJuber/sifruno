package serverinfo

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

func collectNative(ctx context.Context) observation {
	r := unavailableReport(time.Now().UTC(), "Host measurement unavailable")
	o := observation{report: r}
	if ctx.Err() != nil {
		o.report = unavailableReport(time.Now().UTC(), "Host observation canceled or deadline exceeded")
		return o
	}
	if times, err := cpu.TimesWithContext(ctx, false); err == nil && len(times) == 1 {
		t := times[0]
		total := t.Total()
		if runtime.GOOS == "linux" {
			total -= t.Guest + t.GuestNice
		}
		busy := total - t.Idle - t.Iowait
		if !math.IsNaN(total) && !math.IsNaN(busy) && !math.IsInf(total, 0) && !math.IsInf(busy, 0) && total > 0 && busy >= 0 && busy <= total {
			o.cpu = &counters{total: total, busy: busy}
			r.CPU.Available = true
			r.CPU.Reason = ""
		}
	}
	if v, err := cpu.CountsWithContext(ctx, true); err == nil && v > 0 {
		r.CPU.LogicalCores = ptr(v)
	}
	if v, err := cpu.CountsWithContext(ctx, false); err == nil && v > 0 {
		r.CPU.PhysicalCores = ptr(v)
	}
	if info, err := cpu.InfoWithContext(ctx); err == nil && len(info) > 0 {
		if model := publicText(info[0].ModelName, 160); model != "" {
			r.CPU.Model = ptr(model)
		}
	}
	if !r.CPU.Available {
		r.CPU.Reason = "CPU counters unavailable"
	}
	if r.CPU.LogicalCores == nil {
		r.CPU.Reason = joinReason(r.CPU.Reason, "CPU core count unavailable")
	}
	if r.CPU.PhysicalCores == nil {
		r.CPU.Reason = joinReason(r.CPU.Reason, "Physical CPU topology unavailable")
	}
	if r.CPU.Model == nil {
		r.CPU.Reason = joinReason(r.CPU.Reason, "CPU model unavailable")
	}
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil && v != nil && v.Total > 0 && v.Used <= v.Total && v.Available <= v.Total && finitePercent(v.UsedPercent) {
		r.Memory = Memory{Availability: Availability{Available: true}, TotalBytes: ptr(v.Total), UsedBytes: ptr(v.Used), AvailableBytes: ptr(v.Available), UsedPercent: ptr(v.UsedPercent)}
	} else {
		r.Memory.Reason = "Memory counters unavailable"
	}
	r.Storage = collectStorage(ctx)
	if v, err := host.UptimeWithContext(ctx); err == nil {
		r.Uptime = Uptime{Availability: Availability{Available: true}, Seconds: ptr(v)}
	} else {
		r.Uptime.Reason = "Host uptime unavailable"
	}
	if v, err := psnet.IOCountersWithContext(ctx, false); err == nil && len(v) == 1 {
		r.Network = Network{Availability: Availability{Available: true}, BytesReceived: ptr(v[0].BytesRecv), BytesSent: ptr(v[0].BytesSent)}
	} else {
		r.Network.Reason = "Aggregate network counters unavailable"
	}
	// Some native APIs cannot cancel in flight. Late results are withheld even
	// when that native call eventually succeeds; worker concurrency stays fixed.
	if ctx.Err() != nil {
		r = unavailableReport(time.Now().UTC(), "Host observation canceled or deadline exceeded")
		o.cpu = nil
	}
	// Timestamp denotes observation completion, not host boot time.
	r.SampledAt = time.Now().UTC()
	o.report = r
	return o
}

func collectStorage(ctx context.Context) Storage {
	s := Storage{Availability: Availability{Reason: "Local storage inventory unavailable"}, Disks: []Disk{}}
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil && len(parts) == 0 {
		return s
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Mountpoint < parts[j].Mountpoint })
	seen := map[string]bool{}
	var total, used, free uint64
	partial := err != nil
	for _, p := range parts {
		if ctx.Err() != nil {
			partial = true
			break
		}
		if !localPartition(p) {
			continue
		}
		key := p.Device
		if key == "" {
			key = p.Mountpoint
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(s.Disks) >= 16 {
			partial = true
			break
		}
		n := len(s.Disks) + 1
		item := Disk{ID: fmt.Sprintf("disk-%d", n), Label: fmt.Sprintf("Volume %d", n), Availability: Availability{Reason: "Volume usage unavailable"}}
		if v, e := disk.UsageWithContext(ctx, p.Mountpoint); e == nil && v != nil && v.Total > 0 && v.Used <= v.Total && v.Free <= v.Total && finitePercent(v.UsedPercent) && math.MaxUint64-total >= v.Total && math.MaxUint64-used >= v.Used && math.MaxUint64-free >= v.Free {
			item.Available = true
			item.Reason = ""
			item.TotalBytes = ptr(v.Total)
			item.UsedBytes = ptr(v.Used)
			item.FreeBytes = ptr(v.Free)
			item.UsedPercent = ptr(v.UsedPercent)
			total += v.Total
			used += v.Used
			free += v.Free
		} else {
			partial = true
		}
		s.Disks = append(s.Disks, item)
	}
	if total > 0 {
		s.Available = true
		s.TotalBytes = ptr(total)
		s.UsedBytes = ptr(used)
		s.FreeBytes = ptr(free)
		s.UsedPercent = ptr(float64(used) / float64(total) * 100)
		s.Reason = ""
		if partial {
			s.Reason = "Some local volumes are unavailable or outside the bounded inventory"
		}
	}
	return s
}

func localFilesystem(p disk.PartitionStat) bool {
	if strings.HasPrefix(p.Device, "//") || strings.HasPrefix(p.Device, "\\\\") {
		return false
	}
	switch strings.ToLower(p.Fstype) {
	case "ntfs", "refs", "fat", "fat32", "exfat", "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "jfs", "f2fs", "ufs", "apfs", "hfs", "hfs+", "overlay", "overlayfs":
		return true
	}
	return false
}
