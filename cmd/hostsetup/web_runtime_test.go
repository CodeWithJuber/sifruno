package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sifruno/internal/hostwebruntime"
	"testing"
	"time"
)

func runtimeArgs() []string {
	return []string{"--check-web-runtime", "--root", "/private/runtime", "--controller-uid", "42"}
}
func TestWebRuntimeGrammarRefusesBeforeService(t *testing.T) {
	cases := [][]string{nil, {"--check-web-runtime"}, append(runtimeArgs(), "--apply"), {"--check-web-runtime", "--root", "/a", "--root", "/b"}, {"--check-web-runtime", "--controller-uid", "42", "--controller-uid", "43"}}
	for _, replacement := range []struct {
		i int
		v string
	}{{0, "--plan"}, {1, "--root=/a"}, {1, "--socket"}, {2, "relative"}, {2, "/"}, {2, "/a/../b"}, {2, "/a/"}, {2, "/a\\b"}, {2, "/a\n"}, {3, "--controller-uid=42"}, {4, "0"}, {4, "+42"}, {4, "042"}, {4, "4294967296"}, {4, "-42"}, {4, "42 "}, {4, "0x2a"}} {
		args := runtimeArgs()
		args[replacement.i] = replacement.v
		cases = append(cases, args)
	}
	for i, args := range cases {
		var out, errout bytes.Buffer
		calls := 0
		code := runWebRuntimeCheck(context.Background(), args, &out, &errout, func(context.Context, string, uint32) hostwebruntime.InstallationReport {
			calls++
			return hostwebruntime.InstallationReport{Ready: true}
		})
		if code != 2 || calls != 0 || out.Len() != 0 || errout.String() != "Invalid web runtime check configuration\n" {
			t.Fatalf("case %d dispatched or leaked", i)
		}
	}
}
func TestWebRuntimeDispatchScopedReportAndDeadline(t *testing.T) {
	for _, ready := range []bool{false, true} {
		var out, errout bytes.Buffer
		calls := 0
		code := runWebRuntimeCheck(context.Background(), runtimeArgs(), &out, &errout, func(ctx context.Context, root string, uid uint32) hostwebruntime.InstallationReport {
			calls++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second || root != "/private/runtime" || uid != 42 {
				t.Fatal("dispatch changed")
			}
			return hostwebruntime.InstallationReport{Scope: "web_runtime_installation_inputs", Ready: ready}
		})
		var report hostwebruntime.InstallationReport
		if json.Unmarshal(out.Bytes(), &report) != nil || report.Ready != ready || calls != 1 || errout.Len() != 0 || (ready && code != 0) || (!ready && code != 1) {
			t.Fatal("report/exit mismatch")
		}
	}
	args := []string{"--check-web-runtime", "--controller-uid", "42", "--root", "/private/runtime"}
	root, uid, ok := webRuntimeOptions(args)
	if !ok || root != "/private/runtime" || uid != 42 {
		t.Fatal("permuted flags refused")
	}
}
func TestWebRuntimeCancelledSuccessAndWriterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out, errout bytes.Buffer
	code := runWebRuntimeCheck(ctx, runtimeArgs(), &out, &errout, func(context.Context, string, uint32) hostwebruntime.InstallationReport {
		cancel()
		return hostwebruntime.InstallationReport{Ready: true}
	})
	var report hostwebruntime.InstallationReport
	if code != 1 || json.Unmarshal(out.Bytes(), &report) != nil || report.Ready || report.Status != "cancelled" {
		t.Fatal("late success")
	}
	errout.Reset()
	code = runWebRuntimeCheck(context.Background(), runtimeArgs(), runtimeFailedWriter{}, &errout, func(context.Context, string, uint32) hostwebruntime.InstallationReport {
		return hostwebruntime.InstallationReport{Ready: true}
	})
	if code != 1 || errout.String() != "Unable to write web runtime installation report\n" {
		t.Fatal("writer failure lost")
	}
}

type runtimeFailedWriter struct{}

func (runtimeFailedWriter) Write([]byte) (int, error) { return 0, errors.New("private failure") }
