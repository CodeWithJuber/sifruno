package hostwebgeneration

import (
	bolt "go.etcd.io/bbolt"
	"math"
	"regexp"
)

var applyBootPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type applyCheckpoint struct {
	Completion           ApplyCompletion `json:"completion"`
	InspectedStateSHA256 string          `json:"inspected_state_sha256"`
	CounterAdvanceOnly   bool            `json:"counter_advance_only"`
	CounterAdvanced      bool            `json:"counter_advanced"`
}

func validApplyBinding(b ApplyCompletionBinding) bool {
	return b.Version == ApplyCompletionVersion && b.Kind == ApplyCompletionKind && idPattern.MatchString(b.OperationID) && b.NativeBaseRevision != math.MaxUint64 && b.OriginalRevision == b.NativeBaseRevision && validIdentity(b.Before) && validIdentity(b.After) && b.Before.GenerationID != b.After.GenerationID && b.After.GenerationID != "" && b.Before.ProfileSHA256 == b.After.ProfileSHA256 && validHash(b.AdmittedStateSHA256) && validHash(b.InputsSHA256) && applyBootPattern.MatchString(b.BootID) && b.IntentSHA256 == ApplyIntentSHA(b)
}
func validApplyCompletion(a ApplyCompletion) bool {
	return validApplyBinding(a.Binding) && a.ResultRevision == a.Binding.NativeBaseRevision+1
}
func applyMatchesOriginal(a ApplyCompletion, t Transition) bool {
	return validApplyCompletion(a) && a.Binding.OperationID == t.OperationID && a.Binding.OriginalRevision == t.Revision && a.Binding.Before == t.Before.Identity() && a.Binding.After == t.After.Identity()
}

// checkpointApply synchronizes a proven consumed native counter only. It does
// not commit or attest the original active generation. Current stays unchanged.
func (p *persistence) checkpointApply(st *state, a ApplyCompletion, inspectedSHA string, t Transition, actor, reason string, c *Coordinator) error {
	if st.Sequence > MaxEvents-5 {
		return ErrLimit
	}
	if !applyMatchesOriginal(a, t) || !validHash(inspectedSHA) {
		return ErrConflict
	}
	if st.Revision == a.ResultRevision {
		events, err := c.historyLocked()
		if err != nil {
			return err
		}
		committed := false
		for _, event := range events {
			if event.Phase == "committed" && event.OperationID == t.OperationID && event.Revision == a.ResultRevision && event.Before == a.Binding.Before && event.After == a.Binding.After {
				committed = true
			}
		}
		if !committed {
			return ErrConflict
		}
	}
	return p.update(st, c, false, func(tx *bolt.Tx, next *state) error {
		if next.Pending == nil || next.Pending.Repair != nil || next.Pending.ApplyCheckpoint != nil || next.Pending.OperationID != t.OperationID || next.Pending.Before != t.Before.Identity() || next.Pending.After != t.After.ID {
			return ErrRecovery
		}
		advanced := false
		if next.Revision == a.Binding.NativeBaseRevision {
			next.Revision = a.ResultRevision
			advanced = true
		} else if next.Revision != a.ResultRevision || next.Current != a.Binding.After.GenerationID {
			return ErrConflict
		}
		next.Pending.AtRevision = next.Revision
		next.Pending.ApplyCheckpoint = &applyCheckpoint{a, inspectedSHA, true, advanced}
		next.Pending.Phase = "recovery_required"
		return writeState(tx, next, "apply_checkpoint", actor, reason, a.Binding.After)
	})
}
