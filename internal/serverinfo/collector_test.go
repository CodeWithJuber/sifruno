package serverinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Counter fixtures exercise interpretation of observed deltas. They are not
// evidence of host readings; the platform smoke test collects those separately.
func measured(at time.Time, total, busy float64, rx, tx uint64) observation {
	r := unavailableReport(at, "")
	r.CPU = CPU{Availability: Availability{Available: true}, LogicalCores: ptr(4), PhysicalCores: ptr(2), Model: ptr("CPU fixture")}
	r.Memory = Memory{Availability: Availability{Available: true}, TotalBytes: ptr(uint64(1000)), UsedBytes: ptr(uint64(400)), AvailableBytes: ptr(uint64(600)), UsedPercent: ptr(40.0)}
	r.Storage = Storage{Availability: Availability{Available: true}, TotalBytes: ptr(uint64(5000)), UsedBytes: ptr(uint64(1000)), FreeBytes: ptr(uint64(4000)), UsedPercent: ptr(20.0), Disks: []Disk{}}
	r.Uptime = Uptime{Availability: Availability{Available: true}, Seconds: ptr(uint64(120))}
	r.Network = Network{Availability: Availability{Available: true}, BytesReceived: ptr(rx), BytesSent: ptr(tx)}
	return observation{report: r, cpu: &counters{total: total, busy: busy}}
}

func TestObservedRatesWarmupResetAndMissingBaseline(t *testing.T) {
	c := &Collector{}
	at := time.Now().UTC().Add(-5 * time.Second)
	c.accept(measured(at, 100, 30, 1000, 500))
	first := c.Snapshot(600)
	if first.CPU.UsagePercent != nil || first.Network.RXBytesPerSecond != nil || first.Network.TXBytesPerSecond != nil || len(first.History) != 1 || first.Collector.Status != "partial" {
		t.Fatal("first observation fabricated a rate")
	}
	c.accept(measured(at.Add(5*time.Second), 120, 35, 1500, 750))
	next := c.Snapshot(600)
	if next.CPU.UsagePercent == nil || *next.CPU.UsagePercent != 25 || next.Network.RXBytesPerSecond == nil || *next.Network.RXBytesPerSecond != 100 || *next.Network.TXBytesPerSecond != 50 || next.Collector.Status != "available" {
		t.Fatal("observed deltas were not calculated from elapsed time")
	}
	c.accept(measured(at.Add(10*time.Second), 2, 1, 1, 1))
	reset := c.Snapshot(600)
	if reset.CPU.UsagePercent != nil || reset.Network.RXBytesPerSecond != nil || !strings.Contains(reset.CPU.Reason, "reset") || !strings.Contains(reset.Network.Reason, "reset") {
		t.Fatal("counter reset fabricated a rate")
	}
	c.accept(observation{report: unavailableReport(at.Add(15*time.Second), "Unavailable fixture")})
	c.accept(measured(at.Add(20*time.Second), 25, 2, 100, 100))
	if r := c.Snapshot(600); r.CPU.UsagePercent != nil || r.Network.RXBytesPerSecond != nil {
		t.Fatal("failed observation did not break rate baseline")
	}
}

func TestMeasuredIdleZeroAndPartialMetadataRemainHonest(t *testing.T) {
	c := &Collector{}
	at := time.Now().UTC().Add(-5 * time.Second)
	c.accept(measured(at, 100, 20, 100, 50))
	next := measured(at.Add(5*time.Second), 110, 20, 100, 50)
	next.report.CPU.PhysicalCores = nil
	next.report.CPU.Reason = "Physical CPU topology unavailable"
	c.accept(next)
	r := c.Snapshot(600)
	if r.CPU.UsagePercent == nil || *r.CPU.UsagePercent != 0 || r.Network.RXBytesPerSecond == nil || *r.Network.RXBytesPerSecond != 0 || *r.Network.TXBytesPerSecond != 0 {
		t.Fatal("measured idle zero must remain distinguishable from unavailable")
	}
	if r.CPU.PhysicalCores != nil || r.CPU.Reason == "" || r.Collector.Status != "partial" {
		t.Fatal("successful rates concealed missing topology")
	}
}

func TestHistoryBoundRangeAndStaleNulls(t *testing.T) {
	c := &Collector{}
	now := time.Now().UTC()
	for i := 0; i < HistoryLimit+30; i++ {
		c.accept(measured(now.Add(time.Duration(i-HistoryLimit-29)*Interval), float64(100+i*10), float64(20+i*2), uint64(i*100), uint64(i*50)))
	}
	if r := c.Snapshot(600); len(r.History) != HistoryLimit || !r.History[len(r.History)-1].SampledAt.Equal(now) {
		t.Fatal("history was unbounded or included invented points")
	}
	if r := c.Snapshot(10); len(r.History) != 3 {
		t.Fatalf("range filtering: got %d points", len(r.History))
	}
	c.report.SampledAt = now.Add(-30 * time.Second)
	for i := range c.history {
		c.history[i].SampledAt = c.history[i].SampledAt.Add(-30 * time.Second)
	}
	r := c.Snapshot(10)
	if r.Collector.Status != "unavailable" || r.CPU.UsagePercent != nil || r.Memory.TotalBytes != nil || r.Storage.TotalBytes != nil || r.Uptime.Seconds != nil || r.Network.BytesReceived != nil || len(r.History) != 3 {
		t.Fatal("stale sample exposed current measurements or ignored history range")
	}
	c.services = Services{Availability: Availability{Available: true}, SampledAt: now.Add(-2 * time.Minute), Items: []Service{{Name: "fixture"}}}
	if s := c.Services(); s.Available || len(s.Items) != 0 || s.Reason == "" {
		t.Fatal("stale service inventory remained current")
	}
}

func TestConcurrentCachedReadsAndSampling(t *testing.T) {
	c := &Collector{}
	c.accept(measured(time.Now().UTC(), 100, 10, 100, 100))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = c.Snapshot(600)
				_ = c.Services()
			}
		}()
	}
	for i := 0; i < 100; i++ {
		c.mu.Lock()
		c.accept(measured(time.Now().UTC(), float64(110+i*10), float64(11+i), uint64(110+i), uint64(110+i)))
		c.mu.Unlock()
	}
	wg.Wait()
	if len(c.Snapshot(600).History) != 101 {
		t.Fatal("sampling lost observations during cached reads")
	}
}

func TestUnavailableJSONHasExplicitNullsAndNoIdentityFields(t *testing.T) {
	r := unavailableReport(time.Now().UTC(), "Counters unavailable")
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"usage_percent":null`, `"total_bytes":null`, `"seconds":null`, `"rx_bytes_per_second":null`, `"disks":[]`, `"history":[]`} {
		if !bytes.Contains(raw, []byte(field)) {
			t.Fatal("missing explicit unknown/empty contract", field)
		}
	}
	for _, field := range []string{`"hostname"`, `"username"`, `"mountpoint"`, `"device"`, `"address"`, `"command_line"`, `"environment"`} {
		if bytes.Contains(raw, []byte(field)) {
			t.Fatal("identity field in public schema", field)
		}
	}
}

func TestCanceledObservationReturnsUnknowns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := collectNative(ctx)
	if o.cpu != nil || o.report.CPU.UsagePercent != nil || o.report.Memory.TotalBytes != nil || o.report.Storage.TotalBytes != nil || o.report.Network.BytesReceived != nil || o.report.Collector.Status != "unavailable" || !strings.Contains(o.report.Collector.Reasons[0], "deadline") {
		t.Fatal("canceled observation published measurements")
	}
}

func TestServicesPrivacyDistinctInstancesAndBound(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	items := []Service{
		{Name: "Example_a1b2", DisplayName: "Example_a1b2", Status: "running", StartType: "automatic"},
		{Name: "Example_c3d4", DisplayName: "Example_c3d4", Status: "stopped", StartType: "manual"},
		{Name: "user@privateperson.service", DisplayName: "Private Person's Service", Status: "running", StartType: "manual"},
		{Name: "SafeService", DisplayName: "token=private", Status: "nonsense", StartType: "nonsense"},
		{Name: "10.20.30.40", Status: "running"},
		{Name: "secret/password"},
	}
	r := filterServices(items, key)
	if len(r) != 4 {
		t.Fatalf("privacy filter returned %d items", len(r))
	}
	seen := map[string]bool{}
	for _, s := range r {
		if len(s.ID) != 32 || seen[s.ID] || privateText.MatchString(s.Name) || privateText.MatchString(s.DisplayName) {
			t.Fatal("private or duplicate service identifier")
		}
		seen[s.ID] = true
	}
	if r[0].Name != r[1].Name || r[0].ID == r[1].ID || r[0].Status == r[1].Status {
		t.Fatal("redacted instances were conflated")
	}
	if !strings.HasSuffix(r[3].Name, "_instance.service") || r[3].DisplayName != r[3].Name {
		t.Fatal("instance description exposed private identity")
	}
	if again := filterServices(items, key); again[0].ID != r[0].ID {
		t.Fatal("identifier changed within collector lifetime")
	}
	if other := filterServices(items, bytes.Repeat([]byte{8}, 32)); other[0].ID == r[0].ID {
		t.Fatal("identifier is an enumerable unkeyed hash")
	}
	if r := filterServices(items, nil); len(r) != 0 {
		t.Fatal("missing privacy key did not fail closed")
	}
	items = nil
	for i := 0; i < ServiceLimit+20; i++ {
		items = append(items, Service{Name: fmt.Sprintf("Service%d", i)})
	}
	if len(filterServices(items, key)) != ServiceLimit {
		t.Fatal("service inventory is not bounded")
	}
}
