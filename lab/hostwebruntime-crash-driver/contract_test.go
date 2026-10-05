package main

import (
	"context"
	"encoding/json"
	"sifruno/internal/hostwebgeneration"
	"strings"
	"testing"
)

func TestFixtureLeaseCopiesVerifiesAndExpires(t *testing.T) {
	rows := sample().Accounts
	raw, _ := json.Marshal(rows)
	p := fixtureProvider{read: func() ([]byte, error) { return append([]byte{}, raw...), nil }}
	var saved hostwebgeneration.SnapshotLease
	if e := p.WithSnapshot(context.Background(), func(l hostwebgeneration.SnapshotLease) error {
		saved = l
		copy := l.Accounts()
		copy[0].State = "suspended"
		if l.Accounts()[0].State != "active" {
			t.Fatal("lease alias")
		}
		return l.Verify(l.Context())
	}); e != nil {
		t.Fatal(e)
	}
	if len(saved.Accounts()) != 0 || saved.Verify(context.Background()) == nil {
		t.Fatal("expired lease usable")
	}
	if e := p.WithSnapshot(context.Background(), func(l hostwebgeneration.SnapshotLease) error { raw = append(raw, ' '); return nil }); e == nil {
		t.Fatal("postcallback mutation admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if p.WithSnapshot(ctx, func(hostwebgeneration.SnapshotLease) error { called = true; return nil }) == nil || called {
		t.Fatal("cancelled snapshot admitted")
	}
}
func TestSuspendedInventoryOnlyBravoChanges(t *testing.T) {
	in := sample()
	rows := suspendedInventory(in)
	if rows[0] != in.Accounts[0] || rows[1].State != "suspended" || rows[1].Revision != in.Accounts[1].Revision+1 || !rows[1].UpdatedAt.After(in.Accounts[1].UpdatedAt) || in.Accounts[1].State != "active" {
		t.Fatal("inventory change contract")
	}
}
func sampleBoundary(t *testing.T) boundary {
	t.Helper()
	in := sample()
	before, e := generation(in, "", true)
	if e != nil {
		t.Fatal(e)
	}
	after, e := generation(in, strings.Repeat("d", 32), false)
	if e != nil {
		t.Fatal(e)
	}
	binding := hostwebgeneration.ApplyCompletionBinding{Version: 1, Kind: "apply", OperationID: strings.Repeat("c", 32), Before: before.Identity(), After: after.Identity(), AdmittedStateSHA256: strings.Repeat("a", 64), InputsSHA256: strings.Repeat("b", 64), BootID: "11111111-1111-1111-1111-111111111111"}
	binding.IntentSHA256 = hostwebgeneration.ApplyIntentSHA(binding)
	ai := after.Identity()
	return boundary{strings.Repeat("e", 32), 9, "123", binding.OperationID, before.Identity(), ai, hostwebgeneration.RecoveryInspection{StateSHA256: strings.Repeat("f", 64), Revision: 1, LastOperationID: binding.OperationID, Configured: ai, Observed: &ai, CompletedApply: &hostwebgeneration.ApplyCompletion{Binding: binding, ResultRevision: 1}}}
}
func TestBoundaryRequiresApplyConsumptionAndFreshPredeathObservation(t *testing.T) {
	if !validBoundary(sampleBoundary(t)) {
		t.Fatal("valid boundary rejected")
	}
	for name, mutate := range map[string]func(*boundary){"missing completion": func(b *boundary) { b.Native.CompletedApply = nil }, "wrong result": func(b *boundary) { b.Native.CompletedApply.ResultRevision = 2 }, "missing observation": func(b *boundary) { b.Native.Observed = nil }, "rollback": func(b *boundary) { b.Native.CompletedApply.Binding.Kind = "rollback" }, "wrong operation": func(b *boundary) { b.OperationID = strings.Repeat("f", 32) }, "corrupt intent": func(b *boundary) { b.Native.CompletedApply.Binding.IntentSHA256 = strings.Repeat("f", 64) }, "native pending": func(b *boundary) { b.Native.Pending = &hostwebgeneration.RecoveryPending{} }} {
		t.Run(name, func(t *testing.T) {
			b := sampleBoundary(t)
			mutate(&b)
			if validBoundary(b) {
				t.Fatal("invalid boundary admitted")
			}
		})
	}
}
