package hostaccounts

import (
	"context"
	"errors"
	"runtime"
)

var errPersistedAdmissionState = errors.New("persisted state recovery not checked")

// BrokerAdmissionReport is a fresh-setup host snapshot, never a startup grant
// or certification of runtime readiness or persisted-state recovery.
type BrokerAdmissionReport struct {
	SchemaVersion int           `json:"schema_version"`
	Scope         string        `json:"scope"`
	Platform      string        `json:"platform"`
	Supported     bool          `json:"supported"`
	ReadOnly      bool          `json:"read_only"`
	Checks        []PolicyCheck `json:"checks"`
	Restrictions  []string      `json:"restrictions"`
}

func CheckBrokerAdmission(ctx context.Context, opts BrokerOptions) BrokerAdmissionReport {
	return probeBrokerAdmission(ctx, runtime.GOOS, brokerAdmissionProbes(opts))
}

func uncheckedBrokerAdmission(platform, reason string) BrokerAdmissionReport {
	r := BrokerAdmissionReport{SchemaVersion: 1, Scope: "native_linux_broker_startup_admission", Platform: platform, ReadOnly: true,
		Restrictions: []string{"fresh_setup_admission_only", "host_snapshot_not_startup_grant", "persisted_state_recovery_not_checked", "no_stock_host_or_cpanel_certification"}}
	for _, id := range []string{"configuration", "privilege", "controller", "utilities", "nss_file", "nss_policy", "useradd_defaults", "paths", "fresh_state"} {
		r.Checks = append(r.Checks, PolicyCheck{ID: id, Status: "not_checked", Reason: reason})
	}
	return r
}

// Probes are ordered prerequisites. Cancellation discards partial observations.
func probeBrokerAdmission(ctx context.Context, platform string, probes [9]func() error) BrokerAdmissionReport {
	if ctx == nil || ctx.Err() != nil {
		return uncheckedBrokerAdmission(platform, "probe_context_unavailable")
	}
	if platform != "linux" {
		return uncheckedBrokerAdmission(platform, "linux_required")
	}
	r := uncheckedBrokerAdmission(platform, "prerequisite_refused")
	reasons := [9]string{"dedicated_paths_and_nonroot_uid_required", "root_required", "unique_local_controller_uid_required", "trusted_utilities_required", "trusted_bounded_regular_nss_file_required", "files_only_nss_required", "supported_service_account_defaults_required", "dedicated_path_and_socket_admission_required", "persisted_state_recovery_not_checked"}
	for i, probe := range probes {
		if ctx.Err() != nil {
			return uncheckedBrokerAdmission(platform, "probe_context_unavailable")
		}
		var err error
		if probe == nil {
			err = ErrUnavailable
		} else {
			err = probe()
		}
		passed := err == nil
		if ctx.Err() != nil {
			return uncheckedBrokerAdmission(platform, "probe_context_unavailable")
		}
		if !passed {
			r.Checks[i].Status, r.Checks[i].Reason = "refused", reasons[i]
			if i == 8 && errors.Is(err, errPersistedAdmissionState) {
				r.Checks[i].Status = "not_checked"
			}
			return r
		}
		r.Checks[i].Status, r.Checks[i].Reason = "pass", "satisfied"
	}
	if ctx.Err() != nil {
		return uncheckedBrokerAdmission(platform, "probe_context_unavailable")
	}
	r.Supported = true
	return r
}
