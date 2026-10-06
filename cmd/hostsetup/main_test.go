package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
)

func validArgs(mode string) []string {
	return []string{mode, "--state", "/fixture/state", "--socket", "/fixture/socket/broker.sock", "--homes", "/fixture/homes", "--controller-uid", "42", "--controller-state", "/fixture/controller"}
}

func TestGrammarRefusesBeforeServices(t *testing.T) {
	cases := map[string][]string{
		"empty":        nil,
		"mode_only":    {"--apply"},
		"no_mode":      validArgs("--plan")[1:],
		"unknown_mode": validArgs("--serve"),
		"mode_alias":   validArgs("-plan"),
		"mode_equals":  validArgs("--plan=true"),
		"extra":        append(validArgs("--plan"), "private-extra"),
		"mixed":        append(validArgs("--plan"), "--apply"),
		"missing_pair": validArgs("--apply")[:9],
	}
	replacements := map[string]struct {
		index int
		value string
	}{
		"unknown": {1, "--private-unknown"}, "alias": {1, "-state"},
		"equals": {1, "--state=/private/path"}, "duplicate": {9, "--state"},
		"empty_value": {2, ""}, "mode_value": {2, "--apply"},
		"uid_zero": {8, "0"}, "uid_leading_zero": {8, "042"},
		"uid_plus": {8, "+42"}, "uid_negative": {8, "-42"},
		"uid_overflow": {8, "4294967296"}, "uid_space": {8, " 42"},
		"uid_hex": {8, "0x2a"}, "uid_exponent": {8, "4.2e1"},
		"uid_decimal": {8, "42.0"}, "uid_unicode": {8, "٤٢"},
	}
	for name, replacement := range replacements {
		args := validArgs("--apply")
		args[replacement.index] = replacement.value
		cases[name] = args
	}
	cases["mode_late"] = append(validArgs("--plan")[1:], "--plan")
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errout bytes.Buffer
			calls := 0
			service := func(context.Context, hostaccounts.LayoutOptions) hostaccounts.LayoutReport {
				calls++
				return hostaccounts.LayoutReport{Ready: true}
			}
			if code := runWithServices(context.Background(), args, &out, &errout, service, service); code != 2 {
				t.Fatalf("exit=%d", code)
			}
			if calls != 0 || out.Len() != 0 || errout.String() != "Invalid controller layout configuration\n" {
				t.Fatalf("invalid grammar dispatched or leaked: calls=%d stdout=%q stderr=%q", calls, out.String(), errout.String())
			}
		})
	}
}

func TestModesDispatchAndSerializeOnce(t *testing.T) {
	for _, mode := range []string{"--plan", "--apply"} {
		for _, ready := range []bool{false, true} {
			t.Run(mode+"/"+map[bool]string{false: "refused", true: "ready"}[ready], func(t *testing.T) {
				var out, errout bytes.Buffer
				planCalls, applyCalls := 0, 0
				var captured context.Context
				verify := func(ctx context.Context, opts hostaccounts.LayoutOptions) hostaccounts.LayoutReport {
					captured = ctx
					deadline, ok := ctx.Deadline()
					remaining := time.Until(deadline)
					if !ok || remaining <= 0 || remaining > 5*time.Second {
						t.Fatal("missing bounded context")
					}
					if opts.BrokerOptions.StateDir != "/fixture/state" || opts.BrokerOptions.SocketPath != "/fixture/socket/broker.sock" || opts.BrokerOptions.HomesDir != "/fixture/homes" || opts.BrokerOptions.ControllerUID != 42 || opts.ControllerStateDir != "/fixture/controller" {
						t.Fatal("options changed")
					}
					return hostaccounts.LayoutReport{Ready: ready}
				}
				plan := func(c context.Context, o hostaccounts.LayoutOptions) hostaccounts.LayoutReport {
					planCalls++
					return verify(c, o)
				}
				apply := func(c context.Context, o hostaccounts.LayoutOptions) hostaccounts.LayoutReport {
					applyCalls++
					return verify(c, o)
				}
				expected := 1
				if ready {
					expected = 0
				}
				if got := runWithServices(context.Background(), validArgs(mode), &out, &errout, plan, apply); got != expected {
					t.Fatalf("exit=%d", got)
				}
				if (mode == "--plan" && (planCalls != 1 || applyCalls != 0)) || (mode == "--apply" && (planCalls != 0 || applyCalls != 1)) {
					t.Fatal("wrong mode dispatched")
				}
				var report hostaccounts.LayoutReport
				decoder := json.NewDecoder(&out)
				if decoder.Decode(&report) != nil || report.Ready != ready || decoder.Decode(&report) != io.EOF || errout.Len() != 0 {
					t.Fatal("not exactly one report")
				}
				if captured.Err() != context.Canceled {
					t.Fatal("context not released")
				}
			})
		}
	}
}

func TestCanonicalUIDLimitsAndPairOrder(t *testing.T) {
	for _, uid := range []string{"1", "4294967295"} {
		args := validArgs("--plan")
		args[8] = uid
		reordered := append([]string{args[0]}, args[9:11]...)
		reordered = append(reordered, args[7:9]...)
		reordered = append(reordered, args[5:7]...)
		reordered = append(reordered, args[3:5]...)
		reordered = append(reordered, args[1:3]...)
		_, opts, ok := layoutOptions(reordered)
		if !ok || opts.ControllerStateDir != "/fixture/controller" || (uid == "1" && opts.BrokerOptions.ControllerUID != 1) || (uid != "1" && opts.BrokerOptions.ControllerUID != ^uint32(0)) {
			t.Fatal("valid canonical UID/order refused")
		}
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("private writer detail") }

func TestWriterFailureRedacted(t *testing.T) {
	var errout bytes.Buffer
	calls := 0
	service := func(context.Context, hostaccounts.LayoutOptions) hostaccounts.LayoutReport {
		calls++
		return hostaccounts.LayoutReport{Ready: true}
	}
	if code := runWithServices(context.Background(), validArgs("--plan"), brokenWriter{}, &errout, service, service); code != 1 || calls != 1 || errout.String() != "Unable to write controller layout report\n" {
		t.Fatal("write failure not generic")
	}
	if strings.Contains(errout.String(), "private") {
		t.Fatal("writer error leaked")
	}
}

func TestParentCancellationAndEarlierDeadline(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		parent, cancel := context.WithTimeout(context.Background(), time.Second)
		if cancelled {
			cancel()
		}
		defer cancel()
		var out, errout bytes.Buffer
		service := func(ctx context.Context, _ hostaccounts.LayoutOptions) hostaccounts.LayoutReport {
			if cancelled && ctx.Err() != context.Canceled {
				t.Fatal("parent cancellation lost")
			}
			pd, _ := parent.Deadline()
			cd, _ := ctx.Deadline()
			if !pd.Equal(cd) {
				t.Fatal("earlier deadline lost")
			}
			return hostaccounts.LayoutReport{Ready: false}
		}
		if code := runWithServices(parent, validArgs("--plan"), &out, &errout, service, service); code != 1 || errout.Len() != 0 {
			t.Fatal("cancellation refusal not serialized")
		}
	}
}
