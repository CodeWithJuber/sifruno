// Package serverinfo collects real host counters without exposing host identity,
// addresses, process arguments, environment variables or storage mount paths.
package serverinfo

import "time"

const Interval = 5 * time.Second
const HistoryLimit = 120
const ServiceLimit = 256
const ServiceInterval = 30 * time.Second
const CollectionTimeout = 4 * time.Second
const LibraryVersion = "v4.26.9"

type Availability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}
type CPU struct {
	Availability
	UsagePercent  *float64 `json:"usage_percent"`
	LogicalCores  *int     `json:"logical_cores"`
	PhysicalCores *int     `json:"physical_cores"`
	Model         *string  `json:"model"`
}
type Memory struct {
	Availability
	TotalBytes     *uint64  `json:"total_bytes"`
	UsedBytes      *uint64  `json:"used_bytes"`
	AvailableBytes *uint64  `json:"available_bytes"`
	UsedPercent    *float64 `json:"used_percent"`
}
type Disk struct {
	Availability
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	TotalBytes  *uint64  `json:"total_bytes"`
	UsedBytes   *uint64  `json:"used_bytes"`
	FreeBytes   *uint64  `json:"free_bytes"`
	UsedPercent *float64 `json:"used_percent"`
}
type Storage struct {
	Availability
	TotalBytes  *uint64  `json:"total_bytes"`
	UsedBytes   *uint64  `json:"used_bytes"`
	FreeBytes   *uint64  `json:"free_bytes"`
	UsedPercent *float64 `json:"used_percent"`
	Disks       []Disk   `json:"disks"`
}
type Uptime struct {
	Availability
	Seconds *uint64 `json:"seconds"`
}
type Network struct {
	Availability
	BytesReceived    *uint64  `json:"bytes_received"`
	BytesSent        *uint64  `json:"bytes_sent"`
	RXBytesPerSecond *float64 `json:"rx_bytes_per_second"`
	TXBytesPerSecond *float64 `json:"tx_bytes_per_second"`
}
type HistorySample struct {
	SampledAt               time.Time `json:"sampled_at"`
	CPUUsagePercent         *float64  `json:"cpu_usage_percent"`
	MemoryUsedPercent       *float64  `json:"memory_used_percent"`
	StorageUsedPercent      *float64  `json:"storage_used_percent"`
	NetworkRXBytesPerSecond *float64  `json:"network_rx_bytes_per_second"`
	NetworkTXBytesPerSecond *float64  `json:"network_tx_bytes_per_second"`
}
type CollectorInfo struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	IntervalSeconds int      `json:"interval_seconds"`
	HistoryLimit    int      `json:"history_limit"`
	Status          string   `json:"status"`
	Reasons         []string `json:"reasons"`
}
type Report struct {
	SampledAt time.Time       `json:"sampled_at"`
	OS        string          `json:"os"`
	Arch      string          `json:"arch"`
	Collector CollectorInfo   `json:"collector"`
	CPU       CPU             `json:"cpu"`
	Memory    Memory          `json:"memory"`
	Storage   Storage         `json:"storage"`
	Uptime    Uptime          `json:"uptime"`
	Network   Network         `json:"network"`
	History   []HistorySample `json:"history"`
}
type Service struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
}
type Services struct {
	Availability
	SampledAt time.Time `json:"sampled_at"`
	Manager   string    `json:"manager"`
	Truncated bool      `json:"truncated"`
	Items     []Service `json:"items"`
}
