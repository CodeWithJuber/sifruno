package brokerpathsreview

import (
	"context"
	"sifruno/internal/hostaccounts"
	"testing"
)

func TestIndependentUnavailableClientNeverNeedsHostState(t *testing.T) {
	for _, socket := range []string{"", "relative.sock", "relative\x00.sock"} {
		client := hostaccounts.NewClient(socket)
		capability, err := client.Capability(context.Background())
		if err != nil || capability.Available || capability.Reason != "linux_broker_not_configured" {
			t.Fatalf("fixed unavailable capability: %v %v", capability, err)
		}
	}
}
