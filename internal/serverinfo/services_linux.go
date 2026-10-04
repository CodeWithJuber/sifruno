//go:build linux

package serverinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
)

func localPartition(p disk.PartitionStat) bool { return localFilesystem(p) }
func serviceManager() string                   { return "systemd" }

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("service output exceeds bounds")
	}
	return b.Buffer.Write(p)
}

// Only fixed read-only systemctl commands run, once per cached inventory.
// Environment, command output and descriptions never become raw API errors.
func systemctlJSON(ctx context.Context, command string) ([]byte, error) {
	binary := ""
	for _, candidate := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if info, e := os.Stat(candidate); e == nil && info.Mode().IsRegular() {
			binary = candidate
			break
		}
	}
	if binary == "" {
		return nil, errors.New("systemd unavailable")
	}
	cmd := exec.CommandContext(ctx, binary, command, "--type=service", "--all", "--no-pager", "--no-legend", "--plain", "--output=json")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	cmd.Dir = "/"
	cmd.WaitDelay = 250 * time.Millisecond
	out := &boundedOutput{limit: 1 << 20}
	cmd.Stdout = out
	cmd.Stderr = &boundedOutput{limit: 16 << 10}
	if err := cmd.Run(); err != nil {
		return nil, errors.New("read-only systemd query unavailable")
	}
	return out.Bytes(), nil
}
func collectServices(ctx context.Context) Services {
	r := Services{SampledAt: time.Now().UTC(), Manager: serviceManager(), Availability: Availability{Reason: "Read-only systemd inventory unavailable"}, Items: []Service{}}
	raw, err := systemctlJSON(ctx, "list-units")
	if err != nil {
		return r
	}
	var units []struct {
		Unit        string `json:"unit"`
		Description string `json:"description"`
		Active      string `json:"active"`
	}
	if err = json.Unmarshal(raw, &units); err != nil {
		return r
	}
	types := map[string]string{}
	if raw, e := systemctlJSON(ctx, "list-unit-files"); e == nil {
		var files []struct {
			Unit  string `json:"unit_file"`
			State string `json:"state"`
		}
		if json.Unmarshal(raw, &files) == nil {
			for _, f := range files {
				switch f.State {
				case "enabled", "enabled-runtime":
					types[f.Unit] = "automatic"
				case "disabled":
					types[f.Unit] = "manual"
				case "masked", "masked-runtime":
					types[f.Unit] = "disabled"
				default:
					types[f.Unit] = "unknown"
				}
			}
		}
	}
	sort.Slice(units, func(i, j int) bool { return units[i].Unit < units[j].Unit })
	partial := false
	for _, u := range units {
		if !strings.HasSuffix(u.Unit, ".service") {
			continue
		}
		if len(r.Items) >= ServiceLimit {
			r.Truncated = true
			break
		}
		v := Service{Name: u.Unit, DisplayName: u.Description, Status: "unknown", StartType: "unknown"}
		switch u.Active {
		case "active":
			v.Status = "running"
		case "inactive", "failed":
			v.Status = "stopped"
		case "activating", "deactivating", "reloading":
			v.Status = "pending"
		}
		if typ, ok := types[u.Unit]; ok {
			v.StartType = typ
		}
		if v.Status == "unknown" || v.StartType == "unknown" {
			partial = true
		}
		r.Items = append(r.Items, v)
	}
	r.Available = true
	r.Reason = ""
	if len(types) == 0 {
		r.Reason = "Service start types unavailable"
	} else if partial {
		r.Reason = "Some service status or start types are unavailable"
	}
	if r.Truncated {
		r.Reason = joinReason(r.Reason, "Service inventory limited to 256 services")
	}
	r.SampledAt = time.Now().UTC()
	return r
}
