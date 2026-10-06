package hostaccounts

import (
	"context"
	"errors"
	"runtime"
)

// LayoutOptions declares four dedicated directories for an existing controller.
// It never requests account creation or broker startup.
type LayoutOptions struct {
	BrokerOptions      BrokerOptions
	ControllerStateDir string
}

// LayoutDirectoryResult excludes configured paths and native identities.
type LayoutDirectoryResult struct {
	Role   string `json:"role"`
	Action string `json:"action"`
}

// Ready reports setup admission, not a broker startup grant. A read-only report
// can be ready with planned_create entries; Prepare reports completed additions.
type LayoutReport struct {
	SchemaVersion int                     `json:"schema_version"`
	Scope         string                  `json:"scope"`
	Platform      string                  `json:"platform"`
	Ready         bool                    `json:"ready"`
	ReadOnly      bool                    `json:"read_only"`
	Checks        []PolicyCheck           `json:"checks"`
	Directories   []LayoutDirectoryResult `json:"directories"`
	Restrictions  []string                `json:"restrictions"`
}

func CheckControllerLayout(ctx context.Context, opts LayoutOptions) LayoutReport {
	return controllerLayout(ctx, opts, false)
}

func PrepareControllerLayout(ctx context.Context, opts LayoutOptions) LayoutReport {
	return controllerLayout(ctx, opts, true)
}

type layoutProbes struct {
	valid     func() bool
	admission func(context.Context) BrokerAdmissionReport
	group     func() error
	access    func(context.Context) error
	inspect   func(context.Context) ([4]string, error)
	prepare   func(context.Context, *LayoutReport) error
}

type layoutFailure struct {
	directory int
	created   bool
}

func (layoutFailure) Error() string { return "controller layout refused" }

func uncheckedLayout(platform string, prepare bool, reason string) LayoutReport {
	r := LayoutReport{SchemaVersion: 1, Scope: "native_linux_controller_layout", Platform: platform, ReadOnly: !prepare,
		Restrictions: []string{"existing_local_nonroot_controller_only", "fresh_empty_directories_only", "no_existing_directory_adoption_or_metadata_repair", "descriptor_mode_assignment_only_for_exclusively_created_leaves", "no_users_policy_services_stores_or_sockets_changed", "partial_additions_preserved_no_automatic_rollback", "cooperative_metadata_checks_not_atomic_against_privileged_actor", "layout_admission_not_runtime_or_cpanel_certification"}}
	r.Checks = append(r.Checks, PolicyCheck{ID: "layout_configuration", Status: "not_checked", Reason: reason})
	r.Checks = append(r.Checks, uncheckedBrokerAdmission(platform, reason).Checks...)
	for _, id := range []string{"controller_access", "layout_directories", "layout_preparation", "layout_ownership"} {
		r.Checks = append(r.Checks, PolicyCheck{ID: id, Status: "not_checked", Reason: reason})
	}
	for _, role := range []string{"broker_state", "managed_homes", "socket_parent", "controller_state"} {
		r.Directories = append(r.Directories, LayoutDirectoryResult{Role: role, Action: "not_checked"})
	}
	return r
}

func probeControllerLayout(ctx context.Context, platform string, prepare bool, p layoutProbes) LayoutReport {
	if ctx == nil || ctx.Err() != nil {
		return uncheckedLayout(platform, prepare, "probe_context_unavailable")
	}
	if platform != "linux" {
		return uncheckedLayout(platform, prepare, "linux_required")
	}
	r := uncheckedLayout(platform, prepare, "prerequisite_refused")
	if p.valid == nil || !p.valid() {
		r.Checks[0].Status, r.Checks[0].Reason = "refused", "four_dedicated_paths_and_nonroot_uid_required"
		return r
	}
	r.Checks[0].Status, r.Checks[0].Reason = "pass", "satisfied"
	if ctx.Err() != nil {
		return uncheckedLayout(platform, prepare, "probe_context_unavailable")
	}
	if p.admission == nil {
		r.Checks[1].Status, r.Checks[1].Reason = "refused", "broker_admission_required"
		return r
	}
	a := p.admission(ctx)
	if ctx.Err() != nil {
		return uncheckedLayout(platform, prepare, "probe_context_unavailable")
	}
	// Copy only the bounded status vocabulary from the existing admission report.
	// Never append arbitrary provider errors or host-derived descriptions.
	for i := range a.Checks {
		if i < 9 {
			r.Checks[i+1] = a.Checks[i]
		}
	}
	if !a.Supported || len(a.Checks) != 9 {
		return r
	}
	if p.group == nil || p.group() != nil {
		r.Checks[13].Status, r.Checks[13].Reason = "refused", "root_effective_group_required"
		return r
	}
	r.Checks[13].Status, r.Checks[13].Reason = "pass", "satisfied"
	var accessErr error
	if p.access == nil {
		accessErr = ErrUnavailable
	} else {
		accessErr = p.access(ctx)
	}
	if ctx.Err() != nil {
		return uncheckedLayout(platform, prepare, "probe_context_unavailable")
	}
	if accessErr != nil {
		r.Checks[10].Status, r.Checks[10].Reason = "refused", "controller_traversable_ancestors_required"
		return r
	}
	r.Checks[10].Status, r.Checks[10].Reason = "pass", "satisfied"
	if p.inspect == nil {
		r.Checks[11].Status, r.Checks[11].Reason = "refused", "trusted_empty_directory_layout_required"
		return r
	}
	actions, err := p.inspect(ctx)
	if ctx.Err() != nil {
		return uncheckedLayout(platform, prepare, "probe_context_unavailable")
	}
	for i, action := range actions {
		if action == "planned_create" || action == "admitted_existing" || action == "refused" {
			r.Directories[i].Action = action
		}
	}
	if err != nil {
		r.Checks[11].Status, r.Checks[11].Reason = "refused", "trusted_empty_directory_layout_required"
		return r
	}
	r.Checks[11].Status, r.Checks[11].Reason = "pass", "satisfied"
	if !prepare {
		r.Checks[12].Reason = "read_only_check"
		r.Ready = true
		return r
	}
	if p.prepare == nil {
		err = ErrUnavailable
	} else {
		err = p.prepare(ctx, &r)
	}
	if err != nil || ctx.Err() != nil {
		r.Checks[12].Status, r.Checks[12].Reason = "refused", "directory_preparation_refused"
		var failed layoutFailure
		if errors.As(err, &failed) && failed.directory >= 0 && failed.directory < 4 {
			r.Directories[failed.directory].Action = "refused"
			if failed.created {
				r.Checks[12].Reason = "directory_preparation_refused_created_leaf_preserved"
			}
		}
		if ctx.Err() != nil {
			r.Checks[12].Reason = "preparation_context_unavailable_partial_additions_preserved"
		}
		return r
	}
	r.Checks[12].Status, r.Checks[12].Reason = "pass", "satisfied"
	r.Ready = true
	return r
}

func layoutPlatform() string { return runtime.GOOS }
