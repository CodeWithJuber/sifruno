//go:build windows

package serverinfo

import (
	"context"
	"testing"
	"time"
)

func TestNativeWindowsMeasurements(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), CollectionTimeout)
	defer cancel()
	o := collectNative(ctx)
	if !o.report.CPU.Available || o.report.CPU.LogicalCores == nil || *o.report.CPU.LogicalCores <= 0 {
		t.Fatal("native CPU counters/core count unavailable")
	}
	if !o.report.Memory.Available || o.report.Memory.TotalBytes == nil || *o.report.Memory.TotalBytes == 0 || o.report.Memory.UsedBytes == nil || *o.report.Memory.UsedBytes > *o.report.Memory.TotalBytes {
		t.Fatal("native memory counters unavailable or invalid")
	}
	if !o.report.Storage.Available || o.report.Storage.TotalBytes == nil || *o.report.Storage.TotalBytes == 0 || len(o.report.Storage.Disks) == 0 {
		t.Fatal("native local storage counters unavailable")
	}
	if !o.report.Uptime.Available || o.report.Uptime.Seconds == nil {
		t.Fatal("native uptime unavailable")
	}
	c := &Collector{}
	c.accept(o)
	time.Sleep(150 * time.Millisecond)
	ctx2, cancel2 := context.WithTimeout(context.Background(), CollectionTimeout)
	defer cancel2()
	c.accept(collectNative(ctx2))
	r := c.Snapshot(600)
	if r.CPU.UsagePercent == nil || !finitePercent(*r.CPU.UsagePercent) {
		t.Fatal("native second CPU observation did not produce valid usage")
	}
	if r.Network.Available && (r.Network.RXBytesPerSecond == nil || r.Network.TXBytesPerSecond == nil || *r.Network.RXBytesPerSecond < 0 || *r.Network.TXBytesPerSecond < 0) {
		t.Fatal("native network rates invalid")
	}
	t.Logf("Native Windows: logical cores=%d; memory bytes=%d; local volumes=%d; CPU usage=%.2f%%; uptime available=%v; aggregate network available=%v", *r.CPU.LogicalCores, *r.Memory.TotalBytes, len(r.Storage.Disks), *r.CPU.UsagePercent, r.Uptime.Available, r.Network.Available)
}

func TestNativeWindowsReadOnlyServices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), CollectionTimeout)
	defer cancel()
	r := collectServices(ctx)
	if r.Manager != "windows-scm" || r.Items == nil || len(r.Items) > ServiceLimit {
		t.Fatal("invalid native inventory contract")
	}
	if !r.Available {
		if r.Reason == "" || len(r.Items) != 0 {
			t.Fatal("unavailable SCM query hid its limitation")
		}
		t.Log("SCM access unavailable in this execution context; explicit availability reason returned")
		return
	}
	if len(r.Items) == 0 {
		t.Fatal("SCM inventory succeeded without services on native Windows host")
	}
	known := 0
	for _, v := range r.Items {
		if v.Status != "unknown" {
			known++
		}
	}
	if known == 0 {
		t.Fatal("SCM inventory has no observed current states")
	}
	t.Logf("Native read-only SCM: services=%d; known states=%d; truncated=%v", len(r.Items), known, r.Truncated)
}
