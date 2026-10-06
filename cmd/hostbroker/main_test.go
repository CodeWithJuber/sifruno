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

func TestStartupCheckGrammarAndIsolation(t *testing.T) {
	valid := []string{"--check-startup", "--state", "/private/state", "--socket", "/private/run/broker.sock", "--homes", "/private/homes", "--controller-uid", "4294967295"}
	cases := [][]string{valid, {"--check-startup"}, {"-check-startup"}, {"--check-startup=true"}}
	for _, replacement := range []string{"0", "-1", "+7", "0x7", "4294967296", "--check-host", "-check-host", "--check-startup", ""} {
		args := append([]string(nil), valid...)
		args[8] = replacement
		cases = append(cases, args)
	}
	for _, key := range []string{"-state", "--state=/private/state", "--unknown", "--homes", "--check-host"} {
		args := append([]string(nil), valid...)
		args[1] = key
		cases = append(cases, args)
	}
	cases = append(cases, append(append([]string(nil), valid...), "trailing"), append([]string{"--state", "--check-startup"}, valid[3:]...))
	for i, args := range cases {
		for _, supported := range []bool{true, false} {
			var out, errOut bytes.Buffer
			calls := 0
			code := runWithAllServices(args, &out, &errOut, func(context.Context) hostaccounts.HostPolicyReport {
				t.Fatal("host probe entered")
				return hostaccounts.HostPolicyReport{}
			}, func(ctx context.Context, opts hostaccounts.BrokerOptions) hostaccounts.BrokerAdmissionReport {
				calls++
				if opts.ControllerUID != ^uint32(0) || opts.StateDir != "/private/state" {
					t.Fatal(opts)
				}
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second || ctx.Err() != nil {
					t.Fatal("context")
				}
				return hostaccounts.BrokerAdmissionReport{Supported: supported, ReadOnly: true}
			}, func(context.Context, hostaccounts.BrokerOptions) error { t.Fatal("serve entered"); return nil })
			if i > 0 {
				if code != 2 || calls != 0 || out.Len() != 0 || errOut.String() != "Invalid native broker configuration\n" {
					t.Fatalf("invalid %v code %d calls %d out %q err %q", args, code, calls, out.String(), errOut.String())
				}
				continue
			}
			wantCode := 1
			if supported {
				wantCode = 0
			}
			if code != wantCode || calls != 1 || errOut.Len() != 0 {
				t.Fatal(code, calls, errOut.String())
			}
			var r hostaccounts.BrokerAdmissionReport
			d := json.NewDecoder(&out)
			if d.Decode(&r) != nil || r.Supported != supported || d.Decode(&r) != io.EOF {
				t.Fatal("one JSON report required")
			}
		}
	}
}

func TestStartupOutputFailureAndPairOrder(t *testing.T) {
	args := []string{"--check-startup", "--controller-uid", "7", "--homes", "/homes", "--socket", "/run/broker.sock", "--state", "/state"}
	var errOut bytes.Buffer
	code := runWithAllServices(args, unavailableWriter{}, &errOut, nil, func(context.Context, hostaccounts.BrokerOptions) hostaccounts.BrokerAdmissionReport {
		return hostaccounts.BrokerAdmissionReport{Supported: true}
	}, func(context.Context, hostaccounts.BrokerOptions) error { t.Fatal("serve"); return nil })
	if code != 1 || errOut.String() != "Unable to write native broker startup admission report\n" {
		t.Fatal(code, errOut.String())
	}
}

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
