//go:build windows

package serverinfo

import (
	"context"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func serviceManager() string { return "windows-scm" }
func localPartition(p disk.PartitionStat) bool {
	if !localFilesystem(p) {
		return false
	}
	path, err := windows.UTF16PtrFromString(p.Mountpoint)
	return err == nil && windows.GetDriveType(path) == windows.DRIVE_FIXED
}
func collectServices(ctx context.Context) Services {
	r := Services{SampledAt: time.Now().UTC(), Manager: serviceManager(), Availability: Availability{Reason: "Windows service inventory unavailable"}, Items: []Service{}}
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return r
	}
	m := mgr.Mgr{Handle: h}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return r
	}
	sort.Strings(names)
	r.Available = true
	r.Reason = ""
	partial := false
	for _, name := range names {
		if ctx.Err() != nil {
			r.Reason = "Service inventory deadline reached"
			r.Truncated = true
			break
		}
		if len(r.Items) >= ServiceLimit {
			r.Truncated = true
			r.Reason = "Service inventory limited to 256 services"
			break
		}
		p, e := windows.UTF16PtrFromString(name)
		if e != nil {
			continue
		}
		v := Service{Name: name, DisplayName: name, Status: "unknown", StartType: "unknown"}
		sh, e := windows.OpenService(h, p, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
		if e == nil {
			s := mgr.Service{Name: name, Handle: sh}
			if status, e := s.Query(); e == nil {
				switch status.State {
				case svc.Running:
					v.Status = "running"
				case svc.Stopped:
					v.Status = "stopped"
				case svc.Paused:
					v.Status = "paused"
				default:
					v.Status = "pending"
				}
			}
			if config, e := s.Config(); e == nil {
				v.DisplayName = config.DisplayName
				switch config.StartType {
				case mgr.StartAutomatic:
					v.StartType = "automatic"
				case mgr.StartManual:
					v.StartType = "manual"
				case mgr.StartDisabled:
					v.StartType = "disabled"
				}
			}
			s.Close()
		}
		if v.Status == "unknown" || v.StartType == "unknown" {
			partial = true
		}
		r.Items = append(r.Items, v)
	}
	if partial {
		r.Reason = joinReason(r.Reason, "Some service status or start types are unavailable")
	}
	r.SampledAt = time.Now().UTC()
	return r
}
