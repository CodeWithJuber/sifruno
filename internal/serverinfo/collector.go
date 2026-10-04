package serverinfo

import (
	"context"
	"crypto/rand"
	"math"
	"runtime"
	"strings"
	"sync"
	"time"
)

type counters struct{ total, busy float64 }
type observation struct {
	report Report
	cpu    *counters
}
type Collector struct {
	mu         sync.RWMutex
	report     Report
	services   Services
	previous   *observation
	history    []HistorySample
	serviceKey []byte
	stop       context.CancelFunc
	done       sync.WaitGroup
}

var defaultOnce sync.Once
var defaultCollector *Collector

// Default is lazy and process-wide: API requests never spawn native collectors.
func Default() *Collector {
	defaultOnce.Do(func() { defaultCollector = NewCollector() })
	return defaultCollector
}

// NewCollector starts exactly two serial workers. Snapshot methods only read
// memory. Native calls that cannot honor context cannot create new workers.
func NewCollector() *Collector {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Collector{report: unavailableReport(time.Now().UTC(), "First host sample is being collected"), services: Services{Availability: Availability{Reason: "First service inventory is being collected"}, SampledAt: time.Now().UTC(), Manager: serviceManager(), Items: []Service{}}, history: []HistorySample{}, stop: cancel}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err == nil {
		c.serviceKey = key
	}
	c.done.Add(2)
	go func() {
		defer c.done.Done()
		c.sample(ctx)
		ticker := time.NewTicker(Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.sample(ctx)
			}
		}
	}()
	go func() {
		defer c.done.Done()
		c.sampleServices(ctx)
		ticker := time.NewTicker(ServiceInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.sampleServices(ctx)
			}
		}
	}()
	return c
}
func (c *Collector) Close() {
	if c.stop != nil {
		c.stop()
	}
	c.done.Wait()
}
func (c *Collector) sample(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, CollectionTimeout)
	defer cancel()
	next := collectNative(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accept(next)
}
func (c *Collector) sampleServices(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, CollectionTimeout)
	defer cancel()
	result := Services{SampledAt: time.Now().UTC(), Manager: serviceManager(), Availability: Availability{Reason: "Service privacy identifiers unavailable"}, Items: []Service{}}
	if len(c.serviceKey) == 32 {
		result = collectServices(ctx)
		if ctx.Err() != nil {
			result = Services{SampledAt: time.Now().UTC(), Manager: serviceManager(), Availability: Availability{Reason: "Service observation canceled or deadline exceeded"}, Items: []Service{}}
		}
		before := len(result.Items)
		result.Items = filterServices(result.Items, c.serviceKey)
		if len(result.Items) < before {
			result.Reason = joinReason(result.Reason, "Some service labels were omitted for privacy")
		}
	}
	c.mu.Lock()
	c.services = result
	c.mu.Unlock()
}
func finitePercent(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 100 }
func ptr[T any](v T) *T            { return &v }
func joinReason(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a + "; " + b
}

func unavailableReport(at time.Time, reason string) Report {
	a := Availability{Reason: reason}
	return Report{SampledAt: at, OS: runtime.GOOS, Arch: runtime.GOARCH, Collector: CollectorInfo{Name: "gopsutil/v4", Version: LibraryVersion, IntervalSeconds: int(Interval / time.Second), HistoryLimit: HistoryLimit, Status: "unavailable", Reasons: []string{reason}}, CPU: CPU{Availability: a}, Memory: Memory{Availability: a}, Storage: Storage{Availability: a, Disks: []Disk{}}, Uptime: Uptime{Availability: a}, Network: Network{Availability: a}, History: []HistorySample{}}
}

// accept computes deltas only from this collector's observations. Failed or
// reset counters break the baseline; the next rate remains null until valid.
func (c *Collector) accept(next observation) {
	r := next.report
	if next.cpu != nil {
		metadataReason := r.CPU.Reason
		r.CPU.Reason = joinReason(metadataReason, "CPU usage needs two observations")
		if c.previous != nil && c.previous.cpu != nil {
			delta := next.cpu.total - c.previous.cpu.total
			busy := next.cpu.busy - c.previous.cpu.busy
			if delta > 0 && busy >= 0 && busy <= delta {
				r.CPU.UsagePercent = ptr(busy / delta * 100)
				r.CPU.Reason = metadataReason
			} else {
				r.CPU.Reason = joinReason(metadataReason, "CPU counters reset or did not advance")
			}
		}
	}
	if r.Network.Available {
		r.Network.Reason = "Network rates need two observations"
		if c.previous != nil {
			p := c.previous.report.Network
			seconds := r.SampledAt.Sub(c.previous.report.SampledAt).Seconds()
			if p.Available && p.BytesReceived != nil && p.BytesSent != nil && r.Network.BytesReceived != nil && r.Network.BytesSent != nil && seconds > 0 && *r.Network.BytesReceived >= *p.BytesReceived && *r.Network.BytesSent >= *p.BytesSent {
				r.Network.RXBytesPerSecond = ptr(float64(*r.Network.BytesReceived-*p.BytesReceived) / seconds)
				r.Network.TXBytesPerSecond = ptr(float64(*r.Network.BytesSent-*p.BytesSent) / seconds)
				r.Network.Reason = ""
			} else {
				r.Network.Reason = "Network counters reset or baseline is unavailable"
			}
		}
	}
	r.Collector.Status = "available"
	r.Collector.Reasons = []string{}
	for _, a := range []Availability{r.CPU.Availability, r.Memory.Availability, r.Storage.Availability, r.Uptime.Availability, r.Network.Availability} {
		if !a.Available || a.Reason != "" {
			r.Collector.Status = "partial"
			if a.Reason != "" {
				r.Collector.Reasons = append(r.Collector.Reasons, a.Reason)
			}
		}
	}
	if !r.CPU.Available && !r.Memory.Available && !r.Storage.Available && !r.Uptime.Available && !r.Network.Available {
		r.Collector.Status = "unavailable"
	}
	c.history = append(c.history, HistorySample{SampledAt: r.SampledAt, CPUUsagePercent: r.CPU.UsagePercent, MemoryUsedPercent: r.Memory.UsedPercent, StorageUsedPercent: r.Storage.UsedPercent, NetworkRXBytesPerSecond: r.Network.RXBytesPerSecond, NetworkTXBytesPerSecond: r.Network.TXBytesPerSecond})
	if len(c.history) > HistoryLimit {
		c.history = append([]HistorySample{}, c.history[len(c.history)-HistoryLimit:]...)
	}
	r.History = append([]HistorySample{}, c.history...)
	c.report = r
	next.report = r
	c.previous = &next
}

func (c *Collector) Snapshot(rangeSeconds int) Report {
	if rangeSeconds < 5 || rangeSeconds > 600 {
		rangeSeconds = 600
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	r := c.report
	r.Collector.Reasons = append([]string{}, r.Collector.Reasons...)
	r.Storage.Disks = append([]Disk{}, r.Storage.Disks...)
	r.History = []HistorySample{}
	cutoff := r.SampledAt.Add(-time.Duration(rangeSeconds) * time.Second)
	for _, p := range c.history {
		if !p.SampledAt.Before(cutoff) {
			r.History = append(r.History, p)
		}
	}
	if time.Since(r.SampledAt) > 3*Interval {
		history := r.History
		r = unavailableReport(r.SampledAt, "Host sample is stale; collector unavailable")
		r.History = history
	}
	return r
}
func (c *Collector) Services() Services {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r := c.services
	r.Items = append([]Service{}, r.Items...)
	if time.Since(r.SampledAt) > 3*ServiceInterval {
		r.Available = false
		r.Reason = "Service inventory is stale; collector unavailable"
		r.Items = []Service{}
	}
	return r
}
