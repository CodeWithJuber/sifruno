package hostwebgeneration

import (
	"context"
	"math"
)

type repairAttempt struct {
	Binding            RecoveryBinding `json:"binding"`
	CommittedRevision  uint64          `json:"committed_revision,omitempty"`
	CounterAdvanceOnly bool            `json:"counter_advance_only,omitempty"`
}

func clonePending(in *pending) *pending {
	if in == nil {
		return nil
	}
	out := *in
	if in.Repair != nil {
		r := *in.Repair
		out.Repair = &r
	}
	if in.ApplyCheckpoint != nil {
		cp := *in.ApplyCheckpoint
		out.ApplyCheckpoint = &cp
	}
	return &out
}

func validHash(s string) bool {
	return validIdentity(Identity{"", s, s, s, true})
}

func copiedRepair(req DeniedRepairRequest) DeniedRepairRequest {
	req.Original = copiedTransition(req.Original)
	req.Target = copied(req.Target)
	return req
}

func (c *Coordinator) inspectRecovery(ctx context.Context, executor DeniedRepairer) (RecoveryInspection, error) {
	bounded, cancel := context.WithTimeout(ctx, ExecutorTimeout)
	defer cancel()
	in, err := executor.InspectRecovery(bounded)
	if err != nil || bounded.Err() != nil {
		return RecoveryInspection{}, ErrRecovery
	}
	if !validHash(in.StateSHA256) || !validIdentity(in.Configured) || in.Configured.ProfileSHA256 != c.profileSHA || in.Revision == math.MaxUint64 || (in.LastOperationID != "" && !idPattern.MatchString(in.LastOperationID)) {
		return RecoveryInspection{}, ErrConflict
	}
	if in.Pending != nil {
		p := *in.Pending
		if !idPattern.MatchString(p.OperationID) || p.Revision != in.Revision || !validIdentity(p.Before) || !validIdentity(p.After) || !validIdentity(p.Target) {
			return RecoveryInspection{}, ErrConflict
		}
		if p.Repair != nil && p.Apply != nil {
			return RecoveryInspection{}, ErrConflict
		}
		if p.Apply != nil {
			b := *p.Apply
			if !validApplyBinding(b) || p.OperationID != b.OperationID || p.Revision != b.NativeBaseRevision || p.Before != b.Before || p.After != b.After || p.Target != b.After {
				return RecoveryInspection{}, ErrConflict
			}
			p.Apply = &b
		}
		if p.Repair != nil {
			b := *p.Repair
			if !validRecoveryBinding(b) || p.Target != b.Target || p.OperationID != b.OperationID || p.Revision != b.BaseRevision || p.Before != b.Before || p.After != b.After {
				return RecoveryInspection{}, ErrConflict
			}
			p.Repair = &b
		}
		in.Pending = &p
	}
	if in.Completed != nil {
		b := *in.Completed
		if !validRecoveryBinding(b) || in.Revision != b.BaseRevision+1 || in.LastOperationID != b.OperationID || in.Configured != b.Target || in.Pending != nil {
			return RecoveryInspection{}, ErrConflict
		}
		in.Completed = &b
	}
	if in.CompletedApply != nil {
		a := *in.CompletedApply
		if !validApplyCompletion(a) || in.Completed != nil || in.Revision != a.ResultRevision || in.LastOperationID != a.Binding.OperationID || in.Configured != a.Binding.After {
			return RecoveryInspection{}, ErrConflict
		}
		if in.Pending != nil {
			p := in.Pending
			if p.Apply != nil || p.Repair == nil || p.OperationID != a.Binding.OperationID || p.Revision != a.ResultRevision || p.Before != a.Binding.Before || p.After != a.Binding.After || p.Repair.OriginalRevision != a.Binding.OriginalRevision || p.Repair.Source != a.Binding.After {
				return RecoveryInspection{}, ErrConflict
			}
		}
		in.CompletedApply = &a
	}
	if in.Observed != nil {
		if *in.Observed != in.Configured && (in.Pending == nil || *in.Observed != in.Pending.Target) {
			return RecoveryInspection{}, ErrConflict
		}
		identity := *in.Observed
		in.Observed = &identity
	}
	return in, nil
}

func (c *Coordinator) original(st state) (Transition, error) {
	if st.Pending == nil {
		return Transition{}, ErrConflict
	}
	after, err := c.persistence.generation(st.Pending.After, c)
	if err != nil {
		return Transition{}, err
	}
	var before Generation
	if st.Pending.Before.GenerationID == "" {
		before, err = c.generation("", after.Accounts, true)
	} else {
		before, err = c.persistence.generation(st.Pending.Before.GenerationID, c)
	}
	if err != nil || before.Identity() != st.Pending.Before {
		return Transition{}, ErrRecovery
	}
	revision := st.Pending.AtRevision
	if st.Pending.Repair != nil {
		revision = st.Pending.Repair.Binding.OriginalRevision
	} else {
		// AtRevision can have advanced after a committed callback was quarantined.
		events, e := c.historyLocked()
		if e != nil {
			return Transition{}, e
		}
		found := false
		for _, event := range events {
			if event.OperationID == st.Pending.OperationID && event.Phase == "intended" {
				revision = event.Revision
				found = true
				break
			}
		}
		if !found {
			return Transition{}, ErrRecovery
		}
	}
	return Transition{st.Pending.OperationID, revision, before, after}, nil
}

// RepairDenied explicitly repairs only into a denial compiled from the current
// reserved inventory. It never relaxes Observe or restores an old active bundle.
func (c *Coordinator) RepairDenied(ctx context.Context, in RepairInput) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil || !validText(in.Actor, 120) || !validText(in.Reason, 500) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	executor, ok := c.executor.(DeniedRepairer)
	if !ok {
		return ErrUnavailable
	}
	st, err := c.read()
	if err != nil {
		return err
	}
	if st.Revision == math.MaxUint64 || in.ExpectedRevision != st.Revision || (st.Pending == nil && in.PendingOperation != "") || (st.Pending != nil && in.PendingOperation != st.Pending.OperationID) {
		return ErrConflict
	}
	var begun, committed bool
	var intent *pending
	err = c.provider.WithSnapshot(ctx, func(lease SnapshotLease) error {
		ctx = lease.Context()
		if ctx == nil {
			return ErrUnavailable
		}
		if e := lease.Verify(ctx); e != nil {
			return ErrRecovery
		}
		current, e := c.generation("", lease.Accounts(), true)
		if e != nil {
			return e
		}
		observed, e := c.inspectRecovery(ctx, executor)
		if e != nil {
			return e
		}
		var original Transition
		if st.Pending == nil {
			events, e := c.historyLocked()
			if e != nil {
				return e
			}
			if len(events) == 0 {
				if observed.LastOperationID != "" || observed.Completed != nil || observed.CompletedApply != nil {
					return ErrConflict
				}
			} else {
				terminal := events[len(events)-1]
				if observed.LastOperationID != terminal.OperationID {
					return ErrConflict
				}
				if observed.CompletedApply != nil {
					b := observed.CompletedApply.Binding
					if terminal.Phase != "committed" || b.OperationID != terminal.OperationID || b.Before != terminal.Before || b.After != terminal.After || observed.CompletedApply.ResultRevision != terminal.Revision {
						return ErrConflict
					}
				}
				if observed.Completed != nil && (terminal.Repair == nil || terminal.Repair.Binding != *observed.Completed) {
					return ErrConflict
				}
			}
		}
		if st.Pending == nil {
			before, e := c.current(st, current.Accounts)
			if e != nil {
				return e
			}
			if observed.Pending != nil || observed.Configured != before.Identity() || observed.Revision != st.Revision || observed.Observed != nil {
				return ErrConflict
			}
			// Healthy clean state is handled by ordinary account/apply workflows.
			current.ID, e = newID()
			if e != nil {
				return e
			}
			op, e := newID()
			if e != nil {
				return e
			}
			original = Transition{op, st.Revision, before, current}
		} else {
			original, e = c.original(st)
			if e != nil {
				return e
			}
		}
		if st.Pending != nil && observed.CompletedApply != nil {
			if !applyMatchesOriginal(*observed.CompletedApply, original) {
				return ErrConflict
			}
			if st.Pending.ApplyCheckpoint != nil {
				if st.Pending.ApplyCheckpoint.Completion != *observed.CompletedApply {
					return ErrConflict
				}
			} else {
				if st.Pending.Repair != nil || observed.Pending != nil {
					return ErrConflict
				}
				if e = lease.Verify(ctx); e != nil || ctx.Err() != nil {
					return ErrRecovery
				}
				if e = c.persistence.checkpointApply(&st, *observed.CompletedApply, observed.StateSHA256, original, in.Actor, in.Reason, c); e != nil {
					return e
				}
				begun = true
			}
		} else if st.Pending != nil && st.Pending.ApplyCheckpoint != nil && observed.Completed == nil {
			return ErrRecovery // Never replace a retained original completion with guessed metadata.
		}
		if st.Pending != nil && st.Pending.Repair != nil {
			prior := st.Pending.Repair.Binding
			if observed.Completed != nil && *observed.Completed == prior {
				if observed.Pending != nil || observed.Configured != prior.Target || observed.Revision != prior.BaseRevision+1 || observed.LastOperationID != prior.OperationID {
					return ErrConflict
				}
				if observed.Observed != nil && *observed.Observed == prior.Target && prior.Target.SnapshotSHA256 == current.SnapshotSHA256 && (st.Revision == prior.BaseRevision || st.Revision == observed.Revision && st.Current == prior.Target.GenerationID && !st.Pending.Repair.CounterAdvanceOnly) {
					if st.Sequence > MaxEvents-2 {
						return ErrLimit
					}
					target, e := c.persistence.generation(prior.Target.GenerationID, c)
					if e != nil {
						return e
					}
					request := DeniedRepairRequest{observed.StateSHA256, prior.AttemptID, original, prior.BaseRevision, prior.Source, target}
					if RecoveryIntentSHA(request) != prior.IntentSHA256 {
						return ErrRecovery
					}
					if e = lease.Verify(ctx); e != nil {
						return ErrRecovery
					}
					if e = c.validateRepairState(st); e != nil {
						return e
					}
					var receipt DeniedRepairReceipt
					if e = c.run(ctx, func(bounded context.Context) error {
						var err error
						receipt, err = executor.RepairDenied(bounded, copiedRepair(request))
						return err
					}); e != nil {
						return e
					}
					if receipt.Binding != prior || receipt.ResultRevision != prior.BaseRevision+1 || receipt.Observed != prior.Target {
						return ErrRecovery
					}
					got, e := c.observe(ctx)
					if e != nil || got != prior.Target {
						return ErrRecovery
					}
					if e = lease.Verify(ctx); e != nil || ctx.Err() != nil {
						return ErrRecovery
					}
					intent = clonePending(st.Pending)
					intent.Repair.CommittedRevision = observed.Revision
					if st.Revision == prior.BaseRevision {
						e = c.persistence.completeRepair(&st, intent, false, in.Actor, in.Reason, c)
					} else if st.Revision == observed.Revision && st.Current == prior.Target.GenerationID && !intent.Repair.CounterAdvanceOnly {
						e = c.persistence.completeRepair(&st, intent, true, in.Actor, in.Reason, c)
					} else {
						return ErrConflict
					}
					if e != nil {
						return e
					}
					committed = true
					begun = true
					return nil
				}
				if st.Revision == prior.BaseRevision {
					if e = lease.Verify(ctx); e != nil {
						return ErrRecovery
					}
					if e = c.persistence.checkpointRepair(&st, observed.Revision, in.Actor, in.Reason, c); e != nil {
						return e
					}
					begun = true
				} else if st.Revision != observed.Revision {
					return ErrConflict
				}
			} else if observed.Completed != nil && observed.Completed.AttemptID == prior.AttemptID {
				return ErrConflict
			}
		}
		if observed.Revision != st.Revision {
			return ErrRecovery
		} // No fabricated counter reconciliation.
		if observed.Completed != nil && (st.Pending == nil || st.Pending.Repair == nil || *observed.Completed != st.Pending.Repair.Binding) {
			// An unrelated historical receipt cannot authorize a new attempt.
			if st.Pending != nil {
				b := st.Pending.Repair
				if b == nil || observed.Completed.Target != b.Binding.Source || observed.Revision != b.Binding.BaseRevision || !c.knownRecoveryBinding(*observed.Completed, "repair_checkpoint", observed.Revision) {
					return ErrConflict
				}
			}
		}
		allowedSource := observed.Configured == original.Before.Identity() || observed.Configured == original.After.Identity()
		if st.Pending != nil && st.Pending.Repair != nil {
			allowedSource = allowedSource || observed.Configured == st.Pending.Repair.Binding.Target || observed.Configured == st.Pending.Repair.Binding.Source
		}
		if !allowedSource {
			return ErrConflict
		}
		if observed.Pending != nil {
			p := observed.Pending
			if p.OperationID != original.OperationID || p.Revision != observed.Revision || p.Before != original.Before.Identity() || p.After != original.After.Identity() {
				return ErrConflict
			}
			if p.Repair == nil {
				if p.Target != original.After.Identity() {
					return ErrConflict
				}
			} else if st.Pending == nil || st.Pending.Repair == nil || p.Target != p.Repair.Target {
				return ErrConflict
			} else if *p.Repair != st.Pending.Repair.Binding && (p.Repair.Source != observed.Configured || p.Repair.BaseRevision != st.Revision || !c.knownRecoveryBinding(*p.Repair, "repair_intended", st.Revision)) {
				return ErrConflict
			}
		}
		var request DeniedRepairRequest
		if st.Pending != nil && st.Pending.Repair != nil && st.Pending.Repair.CommittedRevision == 0 && st.Pending.Repair.Binding.Target.SnapshotSHA256 == current.SnapshotSHA256 {
			b := st.Pending.Repair.Binding
			if b.BaseRevision != st.Revision {
				return ErrConflict
			}
			target, e := c.persistence.generation(b.Target.GenerationID, c)
			if e != nil {
				return e
			}
			request = DeniedRepairRequest{observed.StateSHA256, b.AttemptID, original, b.BaseRevision, b.Source, target}
			if RecoveryIntentSHA(request) != b.IntentSHA256 {
				return ErrRecovery
			}
		} else {
			current.ID, e = newID()
			if e != nil {
				return e
			}
			if st.Pending == nil {
				current = original.After
			}
			attempt, e := newID()
			if e != nil {
				return e
			}
			request = DeniedRepairRequest{observed.StateSHA256, attempt, original, st.Revision, observed.Configured, current}
			if e = lease.Verify(ctx); e != nil {
				return ErrRecovery
			}
			if e = c.persistence.intentRepair(&st, request, in.Actor, in.Reason, c); e != nil {
				return e
			}
			begun = true
		}
		intent = clonePending(st.Pending)
		begun = true
		if st.Sequence > MaxEvents-2 {
			return ErrLimit
		}
		if e = lease.Verify(ctx); e != nil {
			return ErrRecovery
		}
		if e = c.validateRepairState(st); e != nil {
			return e
		}
		var receipt DeniedRepairReceipt
		if e = c.run(ctx, func(bounded context.Context) error {
			var err error
			receipt, err = executor.RepairDenied(bounded, copiedRepair(request))
			return err
		}); e != nil {
			return e
		}
		if receipt.Binding != intent.Repair.Binding || receipt.ResultRevision != request.BaseRevision+1 || receipt.Observed != request.Target.Identity() {
			return ErrRecovery
		}
		got, e := c.observe(ctx)
		if e != nil || got != request.Target.Identity() {
			return ErrRecovery
		}
		if e = lease.Verify(ctx); e != nil || ctx.Err() != nil {
			return ErrRecovery
		}
		intent.Repair.CommittedRevision = receipt.ResultRevision
		if e = c.persistence.completeRepair(&st, intent, false, in.Actor, in.Reason, c); e != nil {
			return e
		}
		committed = true
		return nil
	})
	if err != nil && (begun || st.Pending != nil) {
		if committed {
			intent.AtRevision = st.Revision
			st.Pending = clonePending(intent)
		}
		if e := c.persistence.markRecovery(&st, c); e != nil {
			return ErrRecovery
		}
		return ErrRecovery
	}
	return err
}

func validRecoveryBinding(b RecoveryBinding) bool {
	return idPattern.MatchString(b.OperationID) && idPattern.MatchString(b.AttemptID) && b.BaseRevision != math.MaxUint64 && b.OriginalRevision <= b.BaseRevision && validIdentity(b.Before) && validIdentity(b.After) && validIdentity(b.Source) && validIdentity(b.Target) && b.Target.Denied && validHash(b.IntentSHA256) && validHash(b.AdmittedStateSHA256)
}

// Native historical metadata must match an exact previously admitted journal
// binding. This does not turn it into a fresh serving observation.
func (c *Coordinator) knownRecoveryBinding(binding RecoveryBinding, phase string, revision uint64) bool {
	events, err := c.historyLocked()
	if err != nil {
		return false
	}
	for _, event := range events {
		if event.Phase == phase && event.Revision == revision && event.Repair != nil && event.Repair.Binding == binding {
			return true
		}
	}
	return false
}

func (c *Coordinator) validateRepairState(expected state) error {
	actual, err := c.read()
	if err != nil || digest(actual) != digest(expected) {
		return ErrRecovery
	}
	return nil
}
