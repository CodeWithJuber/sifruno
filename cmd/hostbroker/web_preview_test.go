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
		}, func(_ context.Context, opts hostaccounts.BrokerOptions, on features) error {
			calls++
			if on.webPreview != enabled || on.web != nil || opts.HomesDir != "/srv/managed" || opts.ControllerUID != 2000 {
				t.Fatal("startup profile authority changed")
			}
			return nil
		})
		if code != 0 || calls != 1 || out.Len() != 0 || errs.Len() != 0 {
			t.Fatal("opt-in grammar failed")
		}
	}
}

func TestWebUserEnablesTheWebOperation(t *testing.T) {
	args := []string{"--state", "/private/state", "--socket", "/private/socket", "--homes", "/srv/managed", "--controller-uid", "2000", "--web-user", "nobody"}
	var out, errs bytes.Buffer
	var got features
	code := runWithPreviewServices(args, &out, &errs, func(context.Context) hostaccounts.HostPolicyReport {
		return hostaccounts.HostPolicyReport{}
	}, func(context.Context, hostaccounts.BrokerOptions) hostaccounts.BrokerAdmissionReport {
		return hostaccounts.BrokerAdmissionReport{}
	}, func(_ context.Context, _ hostaccounts.BrokerOptions, on features) error {
		got = on
		return nil
	})
	if code != 0 || got.web == nil || got.web.ServerUser != "nobody" || got.webPreview {
		t.Fatalf("web opt-in not passed through: code %d, %+v", code, got)
	}
}
