package stockpolicyreview

import (
	"context"
	"encoding/json"
	"reflect"
	"runtime"
	"sifruno/internal/hostaccounts"
	"testing"
)

func TestIndependentPublicUnavailableContextWire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		report := hostaccounts.CheckHostPolicy(input)
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || len(object) != 7 {
			t.Fatal("report field count")
		}
		wantKeys := []string{"schema_version", "scope", "platform", "supported", "read_only", "checks", "restrictions"}
		for _, key := range wantKeys {
			if _, ok := object[key]; !ok {
				t.Fatal("report field absent")
			}
		}
		if report.SchemaVersion != 1 || report.Scope != "native_linux_account_host_policy" || report.Platform != runtime.GOOS || report.Supported || !report.ReadOnly || len(raw) > 1024 {
			t.Fatal("unavailable report envelope")
		}
		if !reflect.DeepEqual(report.Restrictions, []string{"host_policy_only", "controller_paths_state_not_checked", "no_stock_host_or_cpanel_certification"}) {
			t.Fatal("restriction contract")
		}
		if len(report.Checks) != 3 {
			t.Fatal("check count")
		}
		for i, id := range []string{"utilities", "nss", "useradd_defaults"} {
			if report.Checks[i] != (hostaccounts.PolicyCheck{ID: id, Status: "not_checked", Reason: "probe_context_unavailable"}) {
				t.Fatal("unavailable check contract")
			}
			var row map[string]json.RawMessage
			b, _ := json.Marshal(report.Checks[i])
			if json.Unmarshal(b, &row) != nil || len(row) != 3 {
				t.Fatal("check field shape")
			}
		}
	}
}

func TestIndependentPublicPlatformRefusalWithoutHostAccess(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("no live Linux policy observation in portable reviewer tests")
	}
	report := hostaccounts.CheckHostPolicy(context.Background())
	if report.Supported || report.Platform != runtime.GOOS || len(report.Checks) != 3 {
		t.Fatal("unsupported platform admitted")
	}
	for _, row := range report.Checks {
		if row.Status != "not_checked" || row.Reason != "linux_required" {
			t.Fatal("unsupported platform probe")
		}
	}
}
