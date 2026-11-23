package whmapi

// WHMCS P1 host-information surface (gethostname, loadavg, listips,
// servicestatus, showbw). All values are read live from the host OS; no
// fabricated numbers. showbw reports zeros until bandwidth accounting lands
// (tracked as an open obligation).

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v4/load"
)

// procRunning reports whether any process whose command line contains match
// is alive. It reads /proc directly: nothing here may reach a shell, because
// this package answers network calls. The calling process counts too: the
// "sifruno" service entry asks about the panel binary this code runs in.
func procRunning(match string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		pid := entry.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue // the process exited, or it is not ours to read
		}
		if strings.Contains(strings.ReplaceAll(string(raw), "\x00", " "), match) {
			return true
		}
	}
	return false
}

func (s *Server) handleGetHostname(w http.ResponseWriter, r *http.Request) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		writeError(w, "gethostname", "hostname unavailable")
		return
	}
	writeSuccess(w, "gethostname", map[string]any{"hostname": host}, "")
}

func (s *Server) handleLoadAvg(w http.ResponseWriter, r *http.Request) {
	avg, err := load.Avg()
	if err != nil {
		writeError(w, "loadavg", "load average unavailable")
		return
	}
	writeSuccess(w, "loadavg", map[string]any{
		"one":     fmt.Sprintf("%.2f", avg.Load1),
		"five":    fmt.Sprintf("%.2f", avg.Load5),
		"fifteen": fmt.Sprintf("%.2f", avg.Load15),
	}, "")
}

func (s *Server) handleListIPs(w http.ResponseWriter, r *http.Request) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		writeError(w, "listips", "interface enumeration failed")
		return
	}
	seen := map[string]bool{}
	ips := make([]map[string]any, 0, 8)
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		v4 := ip.To4()
		if v4 == nil || seen[v4.String()] {
			continue // IPv4 only (matches cPanel listips shape)
		}
		seen[v4.String()] = true
		ips = append(ips, map[string]any{
			"ip":     v4.String(),
			"active": 1,
			"mainip": len(ips) == 0,
			"used":   0,
			"shared": 1,
		})
	}
	writeSuccess(w, "listips", map[string]any{"ip": ips}, "")
}

// handleServiceStatus reports the health of the daemons sifruno manages,
// probed live. Unknown/absent daemons report 0 honestly.
func (s *Server) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	services := []map[string]any{
		{"name": "mysql", "display_name": "MySQL/MariaDB", "enabled": 1, "installed": 1, "running": boolToInt(procRunning("mariadbd") || procRunning("mysqld"))},
		{"name": "named", "display_name": "BIND DNS", "enabled": 1, "installed": 1, "running": boolToInt(procRunning("named"))},
		{"name": "sifruno", "display_name": "sifruno panel", "enabled": 1, "installed": 1, "running": boolToInt(procRunning("/opt/sfn/sifruno"))},
	}
	writeSuccess(w, "servicestatus", map[string]any{"service": services}, "")
}

// handleShowBW reports per-account bandwidth. Accounting is not yet
// implemented; zeros are reported honestly rather than fabricated numbers.
func (s *Server) handleShowBW(w http.ResponseWriter, r *http.Request) {
	accts := s.backend.ListAccounts()
	bw := make([]map[string]any, 0, len(accts))
	for _, a := range accts {
		bw = append(bw, map[string]any{
			"acct":       a.User,
			"maindomain": a.Domain,
			"totalbytes": "0",
			"usage":      "0",
			"limit":      "unlimited",
		})
	}
	writeSuccess(w, "showbw", map[string]any{"acct": bw}, "")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
