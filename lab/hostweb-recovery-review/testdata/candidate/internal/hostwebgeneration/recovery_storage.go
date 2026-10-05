package hostwebgeneration

import (
	"fmt"
	bolt "go.etcd.io/bbolt"
	"math"
)

func (c *Coordinator) historyLocked() ([]Event, error) {
	var events []Event
	err := c.persistence.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(eventBucket).ForEach(func(_, raw []byte) error {
			var event Event
			if decode(raw, &event, maxMetadataBytes) != nil {
				return ErrRecovery
			}
			events = append(events, event)
			return nil
		})
	})
	return events, err
}

func (p *persistence) intentRepair(st *state, req DeniedRepairRequest, actor, reason string, c *Coordinator) error {
	if st.Sequence > MaxEvents-4 {
		return ErrLimit
	}
	return p.update(st, c, false, func(tx *bolt.Tx, next *state) error {
		if !req.Target.Denied || req.BaseRevision != next.Revision || req.BaseRevision == math.MaxUint64 {
			return ErrConflict
		}
		if err := putGeneration(tx, req.Target); err != nil {
			return err
		}
		if next.Pending == nil {
			next.Pending = &pending{OperationID: req.Original.OperationID, AtRevision: next.Revision, Before: req.Original.Before.Identity(), After: req.Original.After.ID, Actor: actor, Reason: reason}
		}
		if next.Pending.OperationID != req.Original.OperationID || next.Pending.Before != req.Original.Before.Identity() || next.Pending.After != req.Original.After.ID {
			return ErrConflict
		}
		next.Pending.Recovery = req.Target.ID
		next.Pending.Phase = "recovering"
		next.Pending.Repair = &repairAttempt{Binding: recoveryBinding(req)}
		return writeState(tx, next, "repair_intended", actor, reason, req.Target.Identity())
	})
}

func (p *persistence) completeRepair(st *state, intent *pending, reconfirm bool, actor, reason string, c *Coordinator) error {
	if st.Sequence > MaxEvents-2 {
		return ErrLimit
	}
	return p.update(st, c, false, func(tx *bolt.Tx, next *state) error {
		if next.Pending == nil || next.Pending.Repair == nil || intent == nil || intent.Repair == nil || next.Pending.Repair.Binding != intent.Repair.Binding {
			return ErrRecovery
		}
		b := intent.Repair.Binding
		if intent.Repair.CommittedRevision != b.BaseRevision+1 || intent.Repair.CounterAdvanceOnly {
			return ErrRecovery
		}
		g, err := loadGeneration(tx, b.Target.GenerationID, c)
		if err != nil || !g.Denied || g.Identity() != b.Target {
			return ErrRecovery
		}
		phase := "repair_completed"
		if reconfirm {
			if next.Revision != intent.Repair.CommittedRevision || next.Current != g.ID {
				return ErrConflict
			}
			phase = "reconfirmed"
		} else {
			if next.Revision != b.BaseRevision {
				return ErrConflict
			}
			next.Revision++
			next.Current = g.ID
		}
		next.Pending = clonePending(intent)
		next.Pending.AtRevision = next.Revision
		return writeState(tx, next, phase, actor, reason, g.Identity())
	})
}

// checkpointRepair advances only an exactly consumed native counter. It leaves
// Current unchanged and keeps recovery closed; it does not attest live serving.
func (p *persistence) checkpointRepair(st *state, result uint64, actor, reason string, c *Coordinator) error {
	if st.Sequence > MaxEvents-5 {
		return ErrLimit
	}
	return p.update(st, c, false, func(tx *bolt.Tx, next *state) error {
		if next.Pending == nil || next.Pending.Repair == nil || next.Pending.Repair.CommittedRevision != 0 {
			return ErrRecovery
		}
		b := next.Pending.Repair.Binding
		if next.Revision != b.BaseRevision || b.BaseRevision == math.MaxUint64 || result != b.BaseRevision+1 {
			return ErrConflict
		}
		next.Revision = result
		next.Pending.AtRevision = result
		next.Pending.Repair.CommittedRevision = result
		next.Pending.Repair.CounterAdvanceOnly = true
		next.Pending.Phase = "recovery_required"
		return writeState(tx, next, "repair_checkpoint", actor, reason, b.Target)
	})
}

func verifyRepairEvents(tx *bolt.Tx, st state, identities map[string]Identity, c *Coordinator) error {
	var seq, revision, originalRevision uint64
	previous, current, operation := "", "", ""
	var before, desired, recovering Identity
	var last Event
	completed := true
	seenOps, seenAttempts := map[string]bool{}, map[string]bool{}
	confirmed := map[string]uint64{}
	var repair *repairAttempt
	actor, reason := "", ""
	start := func(e Event) error {
		if !completed || seenOps[e.OperationID] || e.Before.GenerationID != current || e.After.GenerationID == current {
			return ErrRecovery
		}
		seenOps[e.OperationID] = true
		operation = e.OperationID
		before = e.Before
		desired = e.After
		originalRevision = revision
		actor = e.Actor
		reason = e.Reason
		completed = false
		repair = nil
		recovering = Identity{}
		if current == "" {
			g, err := loadGeneration(tx, e.After.GenerationID, c)
			if err != nil {
				return err
			}
			denied, err := c.generation("", g.Accounts, true)
			if err != nil || denied.Identity() != before {
				return ErrRecovery
			}
		}
		return nil
	}
	err := tx.Bucket(eventBucket).ForEach(func(k, raw []byte) error {
		var e Event
		if decode(raw, &e, maxMetadataBytes) != nil {
			return ErrRecovery
		}
		seq++
		if string(k) != fmt.Sprintf("%020d", seq) || e.Sequence != seq || e.PreviousSHA != previous || !idPattern.MatchString(e.OperationID) || !validText(e.Actor, 120) || !validText(e.Reason, 500) || e.At.IsZero() || !validIdentity(e.Before) || !validIdentity(e.After) || identities[e.After.GenerationID] != e.After {
			return ErrRecovery
		}
		if e.Before.GenerationID != "" && identities[e.Before.GenerationID] != e.Before {
			return ErrRecovery
		}
		if e.Phase == "intended" {
			if e.Repair != nil {
				return ErrRecovery
			}
			if err := start(e); err != nil {
				return err
			}
		} else if e.Phase == "repair_intended" && completed {
			if err := start(e); err != nil {
				return err
			}
		} else if operation != e.OperationID || before != e.Before {
			return ErrRecovery
		}
		switch e.Phase {
		case "intended":
		case "committed":
			if revision == math.MaxUint64 {
				return ErrRecovery
			}
			if completed || last.Phase != "intended" || e.After != desired || e.Repair != nil || repair != nil {
				return ErrRecovery
			}
			revision++
			current = e.After.GenerationID
			completed = true
		case "recovering":
			if completed || e.Repair != nil || repair != nil {
				return ErrRecovery
			}
			recovering = e.After
		case "recovered":
			if revision == math.MaxUint64 {
				return ErrRecovery
			}
			if completed || last.Phase != "recovering" || e.After != recovering || e.Repair != nil || repair != nil {
				return ErrRecovery
			}
			revision++
			current = e.After.GenerationID
			completed = true
		case "repair_intended":
			if completed || e.Repair == nil {
				return ErrRecovery
			}
			b := e.Repair.Binding
			if !validRecoveryBinding(b) || seenAttempts[b.AttemptID] || b.OperationID != operation || b.OriginalRevision != originalRevision || b.BaseRevision != revision || b.Before != before || b.After != desired || b.Target != e.After || !b.Target.Denied || !validHash(b.AdmittedStateSHA256) || !validIdentity(b.Source) || e.Repair.CommittedRevision != 0 || e.Repair.CounterAdvanceOnly {
				return ErrRecovery
			}
			if b.Source != before && b.Source != desired && (repair == nil || b.Source != repair.Binding.Target) {
				return ErrRecovery
			}
			after, err := loadGeneration(tx, desired.GenerationID, c)
			if err != nil {
				return err
			}
			var prior Generation
			if before.GenerationID == "" {
				prior, err = c.generation("", after.Accounts, true)
			} else {
				prior, err = loadGeneration(tx, before.GenerationID, c)
			}
			if err != nil || prior.Identity() != before {
				return ErrRecovery
			}
			target, err := loadGeneration(tx, b.Target.GenerationID, c)
			if err != nil || !target.Denied {
				return ErrRecovery
			}
			req := DeniedRepairRequest{b.AdmittedStateSHA256, b.AttemptID, Transition{operation, originalRevision, prior, after}, b.BaseRevision, b.Source, target}
			if recoveryBinding(req) != b {
				return ErrRecovery
			}
			seenAttempts[b.AttemptID] = true
			copy := *e.Repair
			repair = &copy
			recovering = b.Target
		case "repair_completed":
			if revision == math.MaxUint64 {
				return ErrRecovery
			}
			if completed || repair == nil || e.Repair == nil || e.Repair.Binding != repair.Binding || e.After != repair.Binding.Target || e.Repair.CommittedRevision != repair.Binding.BaseRevision+1 || e.Repair.CounterAdvanceOnly || revision != repair.Binding.BaseRevision {
				return ErrRecovery
			}
			revision++
			current = e.After.GenerationID
			completed = true
			copy := *e.Repair
			repair = &copy
			confirmed[repair.Binding.IntentSHA256] = revision
		case "repair_checkpoint":
			if revision == math.MaxUint64 {
				return ErrRecovery
			}
			if completed || repair == nil || e.Repair == nil || e.Repair.Binding != repair.Binding || repair.CommittedRevision != 0 || e.Repair.CommittedRevision != revision+1 || revision != repair.Binding.BaseRevision || !e.Repair.CounterAdvanceOnly || e.After != repair.Binding.Target {
				return ErrRecovery
			}
			revision++
			copy := *e.Repair
			repair = &copy // Current deliberately unchanged.
		case "reconfirmed":
			if completed || repair == nil || e.Repair == nil || *e.Repair != *repair || repair.CounterAdvanceOnly || repair.CommittedRevision != revision || current != repair.Binding.Target.GenerationID || e.After != repair.Binding.Target || confirmed[repair.Binding.IntentSHA256] != revision {
				return ErrRecovery
			}
			completed = true
		case "recovery_required":
			if e.After != desired {
				return ErrRecovery
			}
			if repair == nil {
				if e.Repair != nil {
					return ErrRecovery
				}
			} else if e.Repair == nil || *e.Repair != *repair {
				return ErrRecovery
			}
			completed = false
		default:
			return ErrRecovery
		}
		if e.Revision != revision {
			return ErrRecovery
		}
		hash := e.SHA
		e.SHA = ""
		if digest(e) != hash {
			return ErrRecovery
		}
		previous = hash
		e.SHA = hash
		last = e
		return nil
	})
	if err != nil || seq != st.Sequence || revision != st.Revision || current != st.Current || previous != st.LastEventSHA {
		return ErrRecovery
	}
	if st.Pending == nil {
		if !completed || last.Phase != "committed" && last.Phase != "recovered" && last.Phase != "repair_completed" && last.Phase != "reconfirmed" {
			return ErrRecovery
		}
		return nil
	}
	p := st.Pending
	if completed || p.OperationID != operation || p.AtRevision != revision || p.Before != before || p.After != desired.GenerationID || p.Actor != actor || p.Reason != reason {
		return ErrRecovery
	}
	if p.Recovery != "" && p.Recovery != recovering.GenerationID {
		return ErrRecovery
	}
	if repair == nil {
		if p.Repair != nil {
			return ErrRecovery
		}
	} else if p.Repair == nil || *p.Repair != *repair || p.Recovery != repair.Binding.Target.GenerationID {
		return ErrRecovery
	}
	if p.Phase == "applying" && last.Phase != "intended" || p.Phase == "recovering" && last.Phase != "recovering" && last.Phase != "repair_intended" || p.Phase == "recovery_required" && last.Phase != "recovery_required" && last.Phase != "repair_checkpoint" {
		return ErrRecovery
	}
	return nil
}
