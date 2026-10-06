package hostwebruntime

import (
	"context"
	"path"

	"sifruno/internal/hostweb"
)

// InstallationReport describes only installation inputs observed by this check.
// It is not runtime health, a serving guarantee, or native qualification.
type InstallationReport struct {
	SchemaVersion       int                 `json:"schema_version"`
	Scope               string              `json:"scope"`
	Ready               bool                `json:"ready"`
	Status              string              `json:"status"`
	Profile             string              `json:"profile"`
	RuntimeAccountLimit int                 `json:"runtime_account_limit"`
	PreviewAccountLimit int                 `json:"preview_account_limit"`
	Checks              []InstallationCheck `json:"checks"`
	NotChecked          []string            `json:"not_checked"`
}

type InstallationCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

// CheckInstallation admits a fixed private layout selected by a local installer.
// It never opens the executor or creates files. Reads may update filesystem atime.
// Cancellation is cooperative; individual bounded filesystem reads cannot be preempted.
func CheckInstallation(ctx context.Context, root string, controllerUID uint32) InstallationReport {
	return checkInstallation(ctx, root, controllerUID, inspectInstallation)
}

func installationOptions(root string, uid uint32) Options {
	return Options{Root: root, Profile: hostweb.Profile{
		Name:        hostweb.RestrictedChrootV1,
		ManagedRoot: path.Join(root, "managed"), ManagedHomeRoot: path.Join(root, "homes"),
		FrontChroot: path.Join(root, "front-jail"), BackendChrootRoot: path.Join(root, "backend-jails"),
		RuntimeRoot: path.Join(root, "run"), TLSRoot: path.Join(root, "tls"), CAFile: path.Join(root, "tls/ca.pem"),
		ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", ApacheModuleRoot: "/usr/lib64/httpd/modules",
		FrontendIP: hostweb.DefaultFrontendIP, FrontendPort: hostweb.DefaultFrontendPort, BackendPort: hostweb.DefaultBackendPort,
		FrontUID: hostweb.DefaultFrontUID, FrontGID: hostweb.DefaultFrontGID, ControllerUID: uid,
	}}
}

func checkInstallation(ctx context.Context, root string, uid uint32, inspect func(context.Context, Options, func(string, bool)) error) InstallationReport {
	out := InstallationReport{SchemaVersion: 1, Scope: "web_runtime_installation_inputs", Status: "unavailable", Profile: hostweb.RestrictedChrootV1,
		RuntimeAccountLimit: MaxRuntimeAccounts, PreviewAccountLimit: hostweb.MaxManagedAccounts, Checks: []InstallationCheck{},
		NotChecked: []string{"kernel_and_namespaces", "jail_contents", "tls_validity_and_account_certificates", "account_snapshot_and_capacity", "runtime_state_and_lifecycle", "serving_and_health", "native_qualification"}}
	record := func(name string, passed bool) { out.Checks = append(out.Checks, InstallationCheck{name, passed}) }
	opts := installationOptions(root, uid)
	if uid == 0 || uid == ^uint32(0) || validateOptions(opts) != nil {
		out.Status = "invalid"
		record("profile", false)
		return out
	}
	record("profile", true)
	if ctx == nil {
		out.Status = "invalid"
		return out
	}
	if ctx.Err() != nil {
		out.Status = "cancelled"
		return out
	}
	err := inspect(ctx, opts, record)
	if ctx.Err() != nil {
		out.Status = "cancelled"
		return out
	}
	if err != nil {
		return out
	}
	out.Ready = true
	out.Status = "ready"
	return out
}
