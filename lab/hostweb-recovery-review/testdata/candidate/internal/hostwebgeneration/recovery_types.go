package hostwebgeneration

import "context"

// DeniedRepairer is optional trusted recovery authority. Inspection attests
// owned durable metadata; only Observed attests freshly verified serving state.
// It does not weaken Executor.Observe or expose a remote execution API.
type DeniedRepairer interface {
	InspectRecovery(context.Context) (RecoveryInspection, error)
	RepairDenied(context.Context, DeniedRepairRequest) (DeniedRepairReceipt, error)
}

type RecoveryBinding struct {
	OperationID         string   `json:"operation_id"`
	AttemptID           string   `json:"attempt_id"`
	OriginalRevision    uint64   `json:"original_revision"`
	BaseRevision        uint64   `json:"base_revision"`
	Before              Identity `json:"before"`
	After               Identity `json:"after"`
	Source              Identity `json:"source"`
	Target              Identity `json:"target"`
	IntentSHA256        string   `json:"intent_sha256"`
	AdmittedStateSHA256 string   `json:"admitted_state_sha256"`
}

type RecoveryPending struct {
	OperationID string           `json:"operation_id"`
	Revision    uint64           `json:"revision"`
	Before      Identity         `json:"before"`
	After       Identity         `json:"after"`
	Target      Identity         `json:"target"`
	Repair      *RecoveryBinding `json:"repair,omitempty"`
}

type RecoveryInspection struct {
	StateSHA256     string           `json:"state_sha256"`
	Revision        uint64           `json:"revision"`
	LastOperationID string           `json:"last_operation_id"`
	Configured      Identity         `json:"configured"`
	Pending         *RecoveryPending `json:"pending,omitempty"`
	Completed       *RecoveryBinding `json:"completed,omitempty"`
	Observed        *Identity        `json:"observed,omitempty"`
}

type DeniedRepairRequest struct {
	ExpectedStateSHA256 string
	AttemptID           string
	Original            Transition
	BaseRevision        uint64
	Source              Identity
	Target              Generation
}

type DeniedRepairReceipt struct {
	Binding        RecoveryBinding `json:"binding"`
	ResultRevision uint64          `json:"result_revision"`
	Observed       Identity        `json:"observed"`
}

// RepairInput is operator-approved CAS metadata, never configuration bytes.
// PendingOperation is empty only for explicit clean-controller-death entry.
type RepairInput struct {
	ExpectedRevision uint64
	PendingOperation string
	Actor, Reason    string
}

// RecoveryIntentSHA binds the immutable attempt, including the actual admitted
// source identity. The mutable native state CAS is excluded; its ORIGINAL value
// is independently persisted in RecoveryBinding.AdmittedStateSHA256.
func RecoveryIntentSHA(req DeniedRepairRequest) string {
	return digest(struct {
		Domain                        string
		OperationID                   string
		OriginalRevision              uint64
		AttemptID                     string
		BaseRevision                  uint64
		Before, After, Source, Target Identity
	}{"sifruno-denied-repair-v1", req.Original.OperationID, req.Original.Revision,
		req.AttemptID, req.BaseRevision, req.Original.Before.Identity(), req.Original.After.Identity(), req.Source, req.Target.Identity()})
}

func recoveryBinding(req DeniedRepairRequest) RecoveryBinding {
	return RecoveryBinding{req.Original.OperationID, req.AttemptID, req.Original.Revision, req.BaseRevision,
		req.Original.Before.Identity(), req.Original.After.Identity(), req.Source, req.Target.Identity(), RecoveryIntentSHA(req), req.ExpectedStateSHA256}
}
