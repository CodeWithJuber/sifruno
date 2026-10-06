package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func requireUncheckedPolicy(t *testing.T, report HostPolicyReport, reason string) {
	t.Helper()
	if report.Supported || !report.ReadOnly || report.SchemaVersion != 1 || report.Scope != "native_linux_account_host_policy" || len(report.Checks) != 3 {
		t.Fatal("invalid unchecked report", report)
	}
	for i, id := range []string{"utilities", "nss", "useradd_defaults"} {
		if report.Checks[i] != (PolicyCheck{ID: id, Status: "not_checked", Reason: reason}) {
			t.Fatal("unexpected unchecked policy", report.Checks)
		}
	}
}

func TestHostPolicyReportAdmissionAndRedaction(t *testing.T) {
	reasons := []string{"trusted_utilities_required", "files_only_nss_required", "supported_service_account_defaults_required"}
	for failures := 0; failures < 8; failures++ {
		probes := [3]func() error{}
		order := []int{}
		for i := range probes {
			probes[i] = func() error {
				order = append(order, i)
				if failures&(1<<i) != 0 {
					return errors.New("fixture_secret /fixture/host/path fixture_identity raw configuration")
				}
				return nil
			}
		}
		report := probeHostPolicy(context.Background(), "linux", probes)
		if report.Supported != (failures == 0) || !reflect.DeepEqual(order, []int{0, 1, 2}) {
			t.Fatal("admission or independent probe order changed", failures, report, order)
		}
		for i, check := range report.Checks {
			status, reason := "pass", "satisfied"
			if failures&(1<<i) != 0 {
				status, reason = "refused", reasons[i]
			}
			if check.Status != status || check.Reason != reason {
				t.Fatal("unstable policy check", failures, i, check)
			}
		}
		raw, e := json.Marshal(report)
		if e != nil || len(raw) > 1024 || strings.Contains(string(raw), "fixture_") || strings.Contains(string(raw), "configuration") {
			t.Fatal("unbounded or unredacted DTO", string(raw), e)
		}
	}
	if probeHostPolicy(context.Background(), "linux", [3]func() error{}).Supported {
		t.Fatal("missing probes admitted")
	}
}

func TestHostPolicyReportJSONContract(t *testing.T) {
	pass := func() error { return nil }
	fail := func() error { return ErrUnavailable }
	report := probeHostPolicy(context.Background(), "linux", [3]func() error{pass, fail, fail})
	raw, e := json.Marshal(report)
	const expected = `{"schema_version":1,"scope":"native_linux_account_host_policy","platform":"linux","supported":false,"read_only":true,"checks":[{"id":"utilities","status":"pass","reason":"satisfied"},{"id":"nss","status":"refused","reason":"files_only_nss_required"},{"id":"useradd_defaults","status":"refused","reason":"supported_service_account_defaults_required"}],"restrictions":["host_policy_only","controller_paths_state_not_checked","no_stock_host_or_cpanel_certification"]}`
	if e != nil || string(raw) != expected {
		t.Fatal("report JSON contract changed", string(raw), e)
	}
}

func TestHostPolicyReportUnavailableContextAndPlatform(t *testing.T) {
	panicProbe := func() error { t.Fatal("unavailable probe performed host access"); return nil }
	probes := [3]func() error{panicProbe, panicProbe, panicProbe}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		requireUncheckedPolicy(t, probeHostPolicy(input, "linux", probes), "probe_context_unavailable")
		report := CheckHostPolicy(input)
		requireUncheckedPolicy(t, report, "probe_context_unavailable")
		if report.Platform != runtime.GOOS {
			t.Fatal("platform mismatch", report.Platform)
		}
	}
	for _, platform := range []string{"windows", "darwin", "freebsd"} {
		report := probeHostPolicy(context.Background(), platform, probes)
		requireUncheckedPolicy(t, report, "linux_required")
		if report.Platform != platform {
			t.Fatal("unsupported platform mismatch", report.Platform)
		}
	}
	if runtime.GOOS != "linux" {
		requireUncheckedPolicy(t, CheckHostPolicy(context.Background()), "linux_required")
	}
}

func TestHostPolicyCancellationDiscardsPartialResults(t *testing.T) {
	for cancelAt := 0; cancelAt < 3; cancelAt++ {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		probes := [3]func() error{}
		for i := range probes {
			probes[i] = func() error {
				calls++
				if i == cancelAt {
					cancel()
				}
				return nil
			}
		}
		report := probeHostPolicy(ctx, "linux", probes)
		cancel()
		requireUncheckedPolicy(t, report, "probe_context_unavailable")
		if calls != cancelAt+1 {
			t.Fatal("host probing continued after cancellation", cancelAt, calls)
		}
	}
}

func TestHostPolicyReportsOwnTheirSlices(t *testing.T) {
	one := uncheckedHostPolicy("linux", "probe_context_unavailable")
	one.Checks[0].Reason = "changed"
	one.Restrictions[0] = "changed"
	two := uncheckedHostPolicy("linux", "probe_context_unavailable")
	requireUncheckedPolicy(t, two, "probe_context_unavailable")
	if two.Restrictions[0] != "host_policy_only" {
		t.Fatal("reports share mutable restrictions")
	}
}
