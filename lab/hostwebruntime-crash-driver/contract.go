package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostwebgeneration"
)

type boundary struct {
	Nonce       string                               `json:"nonce"`
	PID         int                                  `json:"pid"`
	Start       string                               `json:"start"`
	OperationID string                               `json:"operation_id"`
	Before      hostwebgeneration.Identity           `json:"before"`
	After       hostwebgeneration.Identity           `json:"after"`
	Native      hostwebgeneration.RecoveryInspection `json:"native"`
}
type crashEvidence struct {
	Boundary              boundary `json:"boundary"`
	ParentPID             int      `json:"parent_pid"`
	ChildPID              int      `json:"child_pid"`
	ChildStart            string   `json:"child_start"`
	OwnedChild            bool     `json:"owned_child"`
	Signal                int      `json:"signal"`
	WaitSignaled          bool     `json:"wait_signaled"`
	NativeMetadataStable  bool     `json:"native_metadata_stable"`
	JournalBeforeSHA256   string   `json:"journal_before_sha256"`
	JournalAfterSHA256    string   `json:"journal_after_sha256"`
	StrictObserveRejected bool     `json:"strict_observe_rejected"`
	ListenersExtinct      bool     `json:"listeners_extinct"`
	NamespacesExtinct     bool     `json:"namespaces_extinct"`
}
type checkpoint struct {
	Stage         string                               `json:"stage"`
	Coordinator   hostwebgeneration.Status             `json:"coordinator"`
	Native        hostwebgeneration.RecoveryInspection `json:"native"`
	HistorySHA256 string                               `json:"history_sha256"`
}

// This adapter guards the sequential, root-owned disposable fixture inventory
// with a byte baseline and final verification. The parent changes inventory
// only after the child has died and between callbacks. It does not provide the
// actual broker's mutation mutex or qualify production SnapshotProvider wiring.
type fixtureProvider struct{ read func() ([]byte, error) }
type fixtureLease struct {
	p        fixtureProvider
	ctx      context.Context
	raw      []byte
	accounts []hostaccounts.Account
	active   bool
}

func (p fixtureProvider) WithSnapshot(ctx context.Context, fn func(hostwebgeneration.SnapshotLease) error) error {
	if ctx == nil || fn == nil {
		return errContract
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	raw, e := p.read()
	if e != nil {
		return e
	}
	var rows []hostaccounts.Account
	if json.Unmarshal(raw, &rows) != nil {
		return errContract
	}
	lease := &fixtureLease{p, ctx, raw, rows, true}
	defer func() { lease.active = false }()
	e = fn(lease)
	ve := lease.Verify(ctx)
	if ve != nil {
		return ve
	}
	return e
}
func (l *fixtureLease) Accounts() []hostaccounts.Account {
	if !l.active {
		return nil
	}
	return append([]hostaccounts.Account{}, l.accounts...)
}
func (l *fixtureLease) Context() context.Context { return l.ctx }
func (l *fixtureLease) Verify(ctx context.Context) error {
	if !l.active || ctx == nil {
		return errContract
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := l.ctx.Err(); e != nil {
		return e
	}
	raw, e := l.p.read()
	if e != nil || !bytes.Equal(raw, l.raw) {
		return errContract
	}
	return nil
}
func suspendedInventory(in fixtureInput) []hostaccounts.Account {
	rows := append([]hostaccounts.Account{}, in.Accounts...)
	rows[1].State = "suspended"
	rows[1].Revision++
	rows[1].UpdatedAt = rows[1].UpdatedAt.Add(1)
	return rows
}
func validBoundary(b boundary) bool {
	a := b.Native.CompletedApply
	return idRE.MatchString(b.Nonce) && b.PID > 1 && b.Start != "" && idRE.MatchString(b.OperationID) && a != nil && b.Native.Revision == 1 && a.ResultRevision == 1 && a.Binding.NativeBaseRevision == 0 && a.Binding.OriginalRevision == 0 && a.Binding.Kind == hostwebgeneration.ApplyCompletionKind && a.Binding.Version == 1 && a.Binding.IntentSHA256 == hostwebgeneration.ApplyIntentSHA(a.Binding) && a.Binding.OperationID == b.OperationID && a.Binding.Before == b.Before && a.Binding.After == b.After && b.Native.Configured == b.After && b.Native.Pending == nil && b.Native.Completed == nil && b.Native.LastOperationID == b.OperationID && b.Native.Observed != nil && *b.Native.Observed == b.After
}
