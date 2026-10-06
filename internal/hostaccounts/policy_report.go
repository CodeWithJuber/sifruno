package hostaccounts

import (
	"context"
	"runtime"
)

// PolicyCheck deliberately excludes host content, paths, identities and errors.
type PolicyCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// HostPolicyReport describes only the native account host-policy prerequisites.
// Supported is an observation, never a grant for broker startup or operations.
type HostPolicyReport struct {
	SchemaVersion int           `json:"schema_version"`
	Scope         string        `json:"scope"`
	Platform      string        `json:"platform"`
	Supported     bool          `json:"supported"`
	ReadOnly      bool          `json:"read_only"`
	Checks        []PolicyCheck `json:"checks"`
	Restrictions  []string      `json:"restrictions"`
}

// CheckHostPolicy reads bounded policy files and trusted utility metadata only.
// It opens no broker state/socket and executes no account utilities.
func CheckHostPolicy(ctx context.Context) HostPolicyReport {
	return probeHostPolicy(ctx, runtime.GOOS, hostPolicyProbes())
}

func uncheckedHostPolicy(platform, reason string) HostPolicyReport {
	return HostPolicyReport{
		SchemaVersion: 1,
		Scope:         "native_linux_account_host_policy",
		Platform:      platform,
		ReadOnly:      true,
		Checks: []PolicyCheck{
			{ID: "utilities", Status: "not_checked", Reason: reason},
			{ID: "nss", Status: "not_checked", Reason: reason},
			{ID: "useradd_defaults", Status: "not_checked", Reason: reason},
		},
		Restrictions: []string{"host_policy_only", "controller_paths_state_not_checked", "no_stock_host_or_cpanel_certification"},
	}
}

func probeHostPolicy(ctx context.Context, platform string, probes [3]func() error) HostPolicyReport {
	if ctx == nil || ctx.Err() != nil {
		return uncheckedHostPolicy(platform, "probe_context_unavailable")
	}
	report := uncheckedHostPolicy(platform, "linux_required")
	if platform != "linux" {
		return report
	}
	reasons := [3]string{"trusted_utilities_required", "files_only_nss_required", "supported_service_account_defaults_required"}
	report.Supported = true
	for i, probe := range probes {
		if ctx.Err() != nil {
			return uncheckedHostPolicy(platform, "probe_context_unavailable")
		}
		check := &report.Checks[i]
		check.Status, check.Reason = "refused", reasons[i]
		if probe != nil && probe() == nil {
			check.Status, check.Reason = "pass", "satisfied"
		} else {
			report.Supported = false
		}
		if ctx.Err() != nil {
			return uncheckedHostPolicy(platform, "probe_context_unavailable")
		}
	}
	return report
}
