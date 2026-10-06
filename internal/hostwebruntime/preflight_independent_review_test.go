package hostwebruntime_test

import (
	"context"
	"encoding/json"
	"runtime"
	"sifruno/internal/hostwebruntime"
	"strings"
	"testing"
	"time"
)

func TestSolInstallationInvalidInputs(t *testing.T) {
	for _, v := range []struct {
		root string
		uid  uint32
	}{{"", 42}, {"relative", 42}, {"/", 42}, {"/a/../b", 42}, {"/a/", 42}, {"/safe", 0}, {"/safe", ^uint32(0)}} {
		r := hostwebruntime.CheckInstallation(context.Background(), v.root, v.uid)
		if r.Ready || r.Status != "invalid" {
			t.Fatalf("invalid input admitted: status=%s ready=%v", r.Status, r.Ready)
		}
	}
}
func TestSolInstallationCancelledContexts(t *testing.T) {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	d, done := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer done()
	for _, ctx := range []context.Context{nil, c, d} {
		r := hostwebruntime.CheckInstallation(ctx, "/sol-isolated-installation-root", 42)
		if r.Ready {
			t.Fatal("context admitted readiness")
		}
		if ctx != nil && r.Status != "cancelled" {
			t.Fatal("cancellation not retained")
		}
	}
}
func TestSolInstallationUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("This is the actual non-Linux refusal control, not native Linux success")
	}
	r := hostwebruntime.CheckInstallation(context.Background(), "/sol-isolated-installation-root", 42)
	if r.Ready || r.Status != "unavailable" || r.Scope != "web_runtime_installation_inputs" {
		t.Fatal("unsupported platform qualified")
	}
	if r.RuntimeAccountLimit != 8 || r.PreviewAccountLimit != 100 {
		t.Fatal("capacity scopes conflated")
	}
}
func TestSolInstallationReportPrivacy(t *testing.T) {
	root := "/sol-private-root-sentinel-74921"
	r := hostwebruntime.CheckInstallation(context.Background(), root, 42)
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	text := string(b)
	if strings.Contains(text, root) {
		t.Fatal("submitted root leaked")
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("invalid JSON")
	}
	for k := range m {
		if strings.Contains(k, "hash") || strings.Contains(k, "path") || strings.Contains(k, "uid") || strings.Contains(k, "error") {
			t.Fatal("sensitive diagnostic field")
		}
	}
	if len(r.NotChecked) < 7 {
		t.Fatal("acceptance exclusions omitted")
	}
}
