//go:build linux

package hostwebruntime

import (
	"context"
	"encoding/json"
	"errors"
	"path"

	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

// Reserve pending and terminal bytes before staging/output/process effects.
func replacementMetadataCapacity(p hostweb.Profile, v record, t transaction) error {
	return replacementMetadataCapacityLimit(p, v, t, MaxMetadataBytes)
}

// maxStoragePins is a byte-budget inventory, never launched/persisted/observed.
// Paths and roles are exact; every numeric field uses its longest Go encoding,
// and Start uses its maximal admitted 20-digit encoding. A target can launch
// only one front plus backend/FPM masters for its active accounts.
func maxStoragePins(p hostweb.Profile, g hostwebgeneration.Generation, boot string) []processPin {
	base := path.Join(p.ManagedRoot, generationPath(g))
	pins := []processPin{}
	add := func(role, account, executable, config string) {
		i := len(pins)
		pins = append(pins, processPin{Role: role, AccountID: account, PID: int(^uint(0)>>1) - i, Start: "18446744073709551615", Boot: boot, Executable: executable, ExecutableSHA256: pHashBudget, Config: config, Namespace: ^uint64(0) - uint64(i), ExecutableDev: ^uint64(0), ExecutableIno: ^uint64(0)})
	}
	add("front", "", p.ApacheBinary, path.Join(base, "apache/front.conf"))
	for _, a := range g.Accounts {
		if a.State == "active" && !g.Denied {
			add("backend", a.ID, p.ApacheBinary, path.Join(base, "apache/backends/"+a.ID+".conf"))
			add("fpm", a.ID, p.FPMBinary, path.Join(base, "fpm/"+a.ID+".conf"))
		}
	}
	return pins
}

const pHashBudget = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// The private limit seam tests a near-bound refusal without admitting oversized
// or invalid product records. Production always supplies MaxMetadataBytes.
func replacementMetadataCapacityLimit(p hostweb.Profile, v record, t transaction, limit int) error {
	if limit <= 0 || limit > MaxMetadataBytes {
		return ErrLimit
	}
	v.Pending = &t
	v.CompletedApply = nil
	v.CompletedRepair = nil
	terminal := replacementState(v, t)
	boot := v.BootID
	if boot == "" && len(v.Processes) != 0 {
		boot = v.Processes[0].Boot
	}
	maximalPending := v
	maximalPending.Processes = maxStoragePins(p, t.Target, boot)
	terminal.Processes = maxStoragePins(p, t.Target, boot)
	for _, candidate := range []record{v, maximalPending, terminal} {
		if validateRecord(p, candidate) != nil {
			return ErrRecovery
		}
		data, e := json.Marshal(metadataCopy(candidate))
		if e != nil || len(data) > limit {
			return ErrLimit
		}
	}
	return nil
}

// Final state is reread from disk and freshly observed. A durable completion
// can survive failure/cancellation here, but cannot turn into cached success.
func (r *Runtime) finishReplacement(ctx context.Context, v *record, t transaction) error {
	final, e := r.load()
	if e != nil {
		return r.failedRepair(v, e)
	}
	if final.Current.Identity() != t.Target.Identity() || final.Revision != t.Revision+1 || final.LastOperation != t.OperationID || final.Pending != nil || final.Repair != nil {
		return r.failedRepair(v, ErrRecovery)
	}
	if t.ApplyIntent != nil {
		if final.CompletedApply == nil || final.CompletedApply.Completion.Binding != *t.ApplyIntent {
			return r.failedRepair(v, ErrRecovery)
		}
	} else if final.CompletedApply != nil {
		return r.failedRepair(v, ErrRecovery)
	}
	if _, e = r.recoveryAdmission(ctx, final); e != nil {
		return r.failedRepair(&final, e)
	}
	got, e := r.observe(ctx, final)
	if e != nil || got != t.Target.Identity() || ctx.Err() != nil {
		return r.failedRepair(&final, errors.Join(e, ctx.Err(), ErrRecovery))
	}
	*v = final
	return nil
}
