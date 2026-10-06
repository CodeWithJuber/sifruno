package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sifruno/internal/hostaccounts"
	"strings"
	"testing"
	"time"
)

func TestStandaloneHostCheck(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(map[bool]string{false: "refused", true: "supported"}[supported], func(t *testing.T) {
			var out, errOut bytes.Buffer
			calls := 0
			want := hostaccounts.HostPolicyReport{
				SchemaVersion: 1, Scope: "native_linux_account_host_policy", Platform: "linux",
				Supported: supported, ReadOnly: true,
				Checks:       []hostaccounts.PolicyCheck{{ID: "utilities", Status: "pass", Reason: "satisfied"}},
				Restrictions: []string{"host_policy_only"},
			}
			code := runWithServices([]string{"--check-host"}, &out, &errOut, func(ctx context.Context) hostaccounts.HostPolicyReport {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second || ctx.Err() != nil {
					t.Fatal("host check must have a live bounded context")
				}
				return want
			}, func(context.Context, hostaccounts.BrokerOptions) error {
				t.Fatal("host check entered the serving path")
				return nil
			})
			wantCode := 1
			if supported {
				wantCode = 0
			}
			if code != wantCode || calls != 1 || errOut.Len() != 0 {
				t.Fatalf("code %d calls %d stderr %q", code, calls, errOut.String())
			}
			var got hostaccounts.HostPolicyReport
			decoder := json.NewDecoder(&out)
			if err := decoder.Decode(&got); err != nil || got.Supported != supported || !got.ReadOnly || got.Scope != want.Scope {
				t.Fatalf("invalid policy JSON: %#v, %v", got, err)
			}
			if err := decoder.Decode(&got); err != io.EOF {
				t.Fatalf("report must contain exactly one JSON object: %v", err)
			}
		})
	}
}

func TestInvalidArgumentsNeverEnterServices(t *testing.T) {
	cases := [][]string{
		nil, {"--controller-uid", "0"}, {"--controller-uid", "-1"},
		{"--controller-uid", "4294967296"}, {"--controller-uid"},
		{"--controller-uid", "7", "trailing"}, {"--unknown", "private-value"},
		{"--check-host", "--state", "/private/state"},
		{"--controller-uid", "7", "--check-host"},
		{"--check-host", "--check-host"}, {"--check-host=true"},
		{"--check-host=false"}, {"-check-host"}, {"--check-host", "trailing"},
		{"--state", "--check-host", "--controller-uid", "7"},
		{"--socket", "--check-host=false", "--controller-uid", "7"},
		{"--homes", "-check-host", "--controller-uid", "7"},
		{"--state", "-check-host=true", "--controller-uid", "7"},
	}
	for _, args := range cases {
		t.Run(testName(args), func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := runWithServices(args, &out, &errOut, func(context.Context) hostaccounts.HostPolicyReport {
				t.Fatal("invalid arguments reached policy probe")
				return hostaccounts.HostPolicyReport{}
			}, func(context.Context, hostaccounts.BrokerOptions) error {
				t.Fatal("invalid arguments reached broker")
				return nil
			})
			if code != 2 || out.Len() != 0 || errOut.String() != "Invalid native broker configuration\n" {
				t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errOut.String())
			}
		})
	}
}

func testName(args []string) string {
	if len(args) == 0 {
		return "empty"
	}
	return strings.Join(args, " ")
}

type unavailableWriter struct{}

func (unavailableWriter) Write([]byte) (int, error) { return 0, errors.New("private writer detail") }

func TestHostCheckOutputFailureIsGeneric(t *testing.T) {
	var errOut bytes.Buffer
	code := runWithServices([]string{"--check-host"}, unavailableWriter{}, &errOut,
		func(context.Context) hostaccounts.HostPolicyReport {
			return hostaccounts.HostPolicyReport{Supported: true, ReadOnly: true}
		}, func(context.Context, hostaccounts.BrokerOptions) error {
			t.Fatal("output failure entered broker")
			return nil
		})
	if code != 1 || errOut.String() != "Unable to write native host policy report\n" {
		t.Fatalf("code %d stderr %q", code, errOut.String())
	}
}

func TestServingOptionsAndGenericRefusalPreserved(t *testing.T) {
	for _, serveError := range []error{nil, errors.New("private native failure")} {
		var out, errOut bytes.Buffer
		calls := 0
		code := runWithServices([]string{"--controller-uid", "4294967295", "--state", "/owned/state", "--socket", "/owned/socket/broker.sock", "--homes", "/owned/homes"}, &out, &errOut,
			func(context.Context) hostaccounts.HostPolicyReport {
				t.Fatal("serving invoked the diagnostic probe as a grant")
				return hostaccounts.HostPolicyReport{}
			}, func(ctx context.Context, opts hostaccounts.BrokerOptions) error {
				calls++
				if ctx.Err() != nil || opts.ControllerUID != ^uint32(0) || opts.StateDir != "/owned/state" || opts.SocketPath != "/owned/socket/broker.sock" || opts.HomesDir != "/owned/homes" {
					t.Fatalf("serving options changed: %#v", opts)
				}
				return serveError
			})
		wantCode, wantError := 0, ""
		if serveError != nil {
			wantCode, wantError = 1, "Native broker unavailable or recovery required\n"
		}
		if code != wantCode || calls != 1 || out.Len() != 0 || errOut.String() != wantError {
			t.Fatalf("code %d calls %d stdout %q stderr %q", code, calls, out.String(), errOut.String())
		}
	}
}
