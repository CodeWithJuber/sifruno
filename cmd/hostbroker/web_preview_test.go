package main

import (
	"bytes"
	"context"
	"sifruno/internal/hostaccounts"
	"testing"
)

func TestWebPreviewStartupOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		args := []string{"--state", "/private/state", "--socket", "/private/socket", "--homes", "/srv/managed", "--controller-uid", "2000"}
		if enabled {
			args = append(args, "--web-preview")
		}
		var out, errs bytes.Buffer
		calls := 0
		code := runWithPreviewServices(args, &out, &errs, func(context.Context) hostaccounts.HostPolicyReport {
			t.Fatal("host probe")
			return hostaccounts.HostPolicyReport{}
		}, func(context.Context, hostaccounts.BrokerOptions) hostaccounts.BrokerAdmissionReport {
			t.Fatal("startup probe")
			return hostaccounts.BrokerAdmissionReport{}
		}, func(_ context.Context, opts hostaccounts.BrokerOptions, on bool) error {
			calls++
			if on != enabled || opts.HomesDir != "/srv/managed" || opts.ControllerUID != 2000 {
				t.Fatal("startup profile authority changed")
			}
			return nil
		})
		if code != 0 || calls != 1 || out.Len() != 0 || errs.Len() != 0 {
			t.Fatal("opt-in grammar failed")
		}
	}
}
