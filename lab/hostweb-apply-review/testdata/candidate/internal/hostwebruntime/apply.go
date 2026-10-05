package hostwebruntime

import (
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

// Only Apply constructs an intent. A completion is historical metadata, never
// a cached observation, and retains the exact original compiled generations.
type nativeApplyCompletion struct {
	Original   hostwebgeneration.Transition
	Completion hostwebgeneration.ApplyCompletion
}

func copyTransition(t hostwebgeneration.Transition) hostwebgeneration.Transition {
	t.Before = copyGeneration(t.Before)
	t.After = copyGeneration(t.After)
	return t
}

func applyBinding(t hostwebgeneration.Transition, stateSHA, inputsSHA, boot string) hostwebgeneration.ApplyCompletionBinding {
	b := hostwebgeneration.ApplyCompletionBinding{Version: 1, Kind: "apply", OperationID: t.OperationID, OriginalRevision: t.Revision, NativeBaseRevision: t.Revision, Before: t.Before.Identity(), After: t.After.Identity(), AdmittedStateSHA256: stateSHA, InputsSHA256: inputsSHA, BootID: boot}
	b.IntentSHA256 = hostwebgeneration.ApplyIntentSHA(b)
	return b
}

func validApplyBinding(t hostwebgeneration.Transition, b hostwebgeneration.ApplyCompletionBinding, inputsSHA, boot string) bool {
	return t.Revision != ^uint64(0) && b.Version == 1 && b.Kind == "apply" && b.OperationID == t.OperationID && b.OriginalRevision == t.Revision && b.NativeBaseRevision == t.Revision && b.Before == t.Before.Identity() && b.After == t.After.Identity() && hex64.MatchString(b.AdmittedStateSHA256) && hex64.MatchString(inputsSHA) && b.InputsSHA256 == inputsSHA && bootPattern.MatchString(boot) && b.BootID == boot && b.IntentSHA256 == hostwebgeneration.ApplyIntentSHA(b)
}

func validateApplyRecord(p hostweb.Profile, v record) error {
	if v.Pending != nil && v.Pending.ApplyIntent != nil {
		t := v.Pending
		if v.Repair != nil || v.CompletedApply != nil || v.CompletedRepair != nil || t.Target.Identity() != t.After.Identity() || v.Current.Identity() != t.Before.Identity() || v.Revision != t.Revision || v.LastOperation == t.OperationID || !validApplyBinding(nativeTransition(*t), *t.ApplyIntent, v.InputsSHA256, v.BootID) {
			return ErrRecovery
		}
	}
	if n := v.CompletedApply; n != nil {
		b := n.Completion.Binding
		if v.Pending != nil || v.CompletedRepair != nil || !validTransitionOptions(p, n.Original) || !validApplyBinding(n.Original, b, v.InputsSHA256, v.BootID) || n.Completion.ResultRevision != b.NativeBaseRevision+1 || v.Revision != n.Completion.ResultRevision || v.LastOperation != b.OperationID || v.Current.Identity() != b.After {
			return ErrRecovery
		}
		// Keep the original fact while its exact checkpointed denial is pending;
		// an unrelated operation cannot inherit historical Apply authority.
		if v.Repair != nil && (!transitionMatches(v.Repair.Request.Original, n.Original) || v.Repair.Request.BaseRevision != n.Completion.ResultRevision || v.Repair.Request.Source != b.After) {
			return ErrRecovery
		}
	}
	return nil
}

func replacementState(v record, t transaction) record {
	v.Current = copyGeneration(t.Target)
	v.Pending = nil
	v.Revision = t.Revision + 1
	v.LastOperation = t.OperationID
	v.CompletedRepair = nil
	v.CompletedApply = nil
	if t.ApplyIntent != nil {
		v.CompletedApply = &nativeApplyCompletion{Original: copyTransition(nativeTransition(t)), Completion: hostwebgeneration.ApplyCompletion{Binding: *t.ApplyIntent, ResultRevision: v.Revision}}
	}
	return v
}

func completedApplyRequestAdmission(v record, q hostwebgeneration.DeniedRepairRequest) error {
	n := v.CompletedApply
	if n == nil || !validApplyBinding(n.Original, n.Completion.Binding, v.InputsSHA256, v.BootID) || n.Completion.ResultRevision != n.Original.Revision+1 || v.Revision != n.Completion.ResultRevision || v.LastOperation != n.Original.OperationID || v.Current.Identity() != n.Original.After.Identity() {
		return ErrRecovery
	}
	if !transitionMatches(q.Original, n.Original) || q.BaseRevision != n.Completion.ResultRevision || q.Source != n.Original.After.Identity() {
		return ErrConflict
	}
	return nil
}
