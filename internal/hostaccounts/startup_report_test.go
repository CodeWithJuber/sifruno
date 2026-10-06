package hostaccounts

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBrokerAdmissionOrderedPrerequisites(t *testing.T) {
	for fail := -1; fail < 9; fail++ {
		var calls []int
		var probes [9]func() error
		for i := range probes {
			i := i
			probes[i] = func() error {
				calls = append(calls, i)
				if i == fail {
					return ErrUnavailable
				}
				return nil
			}
		}
		r := probeBrokerAdmission(context.Background(), "linux", probes)
		wantCalls := 9
		if fail >= 0 {
			wantCalls = fail + 1
		}
		if len(calls) != wantCalls || r.Supported != (fail == -1) {
			t.Fatalf("fail %d: %#v calls %v", fail, r, calls)
		}
		for i, c := range r.Checks {
			status, reason := "pass", "satisfied"
			if fail >= 0 && i == fail {
				status = "refused"
				reason = []string{"dedicated_paths_and_nonroot_uid_required", "root_required", "unique_local_controller_uid_required", "trusted_utilities_required", "trusted_bounded_regular_nss_file_required", "files_only_nss_required", "supported_service_account_defaults_required", "dedicated_path_and_socket_admission_required", "persisted_state_recovery_not_checked"}[i]
			}
			if fail >= 0 && i > fail {
				status, reason = "not_checked", "prerequisite_refused"
			}
			if c.Status != status || c.Reason != reason {
				t.Fatalf("fail %d check %d: %#v", fail, i, c)
			}
		}
	}
}

func TestBrokerAdmissionContextAndPlatform(t *testing.T) {
	for cancelAt := -1; cancelAt < 9; cancelAt++ {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelAt == -1 {
			cancel()
		}
		var probes [9]func() error
		for i := range probes {
			i := i
			probes[i] = func() error {
				if i == cancelAt {
					cancel()
				}
				return nil
			}
		}
		r := probeBrokerAdmission(ctx, "linux", probes)
		if !reflect.DeepEqual(r, uncheckedBrokerAdmission("linux", "probe_context_unavailable")) {
			t.Fatalf("cancel %d: %#v", cancelAt, r)
		}
		cancel()
	}
	if got := probeBrokerAdmission(nil, "linux", [9]func() error{}); !reflect.DeepEqual(got, uncheckedBrokerAdmission("linux", "probe_context_unavailable")) {
		t.Fatal(got)
	}
	if got := probeBrokerAdmission(context.Background(), "windows", [9]func() error{}); !reflect.DeepEqual(got, uncheckedBrokerAdmission("windows", "linux_required")) {
		t.Fatal(got)
	}
	r := probeBrokerAdmission(context.Background(), "linux", [9]func() error{})
	if r.Supported || r.Checks[0].Status != "refused" || r.Checks[1].Status != "not_checked" {
		t.Fatal(r)
	}
}

func TestBrokerAdmissionEnvelopeAndPersistedState(t *testing.T) {
	var probes [9]func() error
	for i := range probes {
		probes[i] = func() error { return nil }
	}
	probes[8] = func() error { return errPersistedAdmissionState }
	r := probeBrokerAdmission(context.Background(), "linux", probes)
	if r.Supported || r.Checks[8].Status != "not_checked" || r.Checks[8].Reason != "persisted_state_recovery_not_checked" {
		t.Fatal(r)
	}
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(b, &envelope) != nil || len(envelope) != 7 {
		t.Fatalf("envelope %s", b)
	}
	wantIDs := []string{"configuration", "privilege", "controller", "utilities", "nss_file", "nss_policy", "useradd_defaults", "paths", "fresh_state"}
	for i, c := range r.Checks {
		if c.ID != wantIDs[i] {
			t.Fatal(r)
		}
	}
	if r.SchemaVersion != 1 || !r.ReadOnly || r.Scope != "native_linux_broker_startup_admission" || len(r.Restrictions) != 4 || strings.Contains(string(b), "/") {
		t.Fatalf("unexpected report %s", b)
	}
}
