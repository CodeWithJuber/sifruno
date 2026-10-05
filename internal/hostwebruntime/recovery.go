package hostwebruntime

import (
	"encoding/hex"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
	"strconv"
	"strings"
)

// This executor supports IPv4 loopback only. Conservatively refuse every IPv6
// listener on a protected port, including mapped IPv4 and dual-stack wildcards.
// procNetwork bounds reads; this pure parser repeats the bound for callers.
func protectedIPv6Listener(data []byte, ports map[uint16]bool) (bool, error) {
	if len(data) > 1<<20 {
		return false, ErrLimit
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "local_address") {
		return false, ErrRecovery
	}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 4 {
			return false, ErrRecovery
		}
		address := strings.Split(f[1], ":")
		if len(address) != 2 || len(address[0]) != 32 || len(address[1]) != 4 {
			return false, ErrRecovery
		}
		if _, e := hex.DecodeString(address[0]); e != nil {
			return false, ErrRecovery
		}
		port, e := strconv.ParseUint(address[1], 16, 16)
		if e != nil {
			return false, ErrRecovery
		}
		if _, e := strconv.ParseUint(f[3], 16, 8); e != nil {
			return false, ErrRecovery
		}
		if f[3] == "0A" {
			if len(f) < 10 {
				return false, ErrRecovery
			}
			if _, e := strconv.ParseUint(f[9], 10, 64); e != nil {
				return false, ErrRecovery
			}
			if ports[uint16(port)] {
				return true, nil
			}
		}
	}
	return false, nil
}

type socketLifetime struct {
	PID       int
	Start     string
	Namespace uint64
}

func sameSocketLifetime(before, after socketLifetime) bool {
	return before.PID > 1 && decimal.MatchString(before.Start) && before.Namespace != 0 && before == after
}

// One current attempt and one historical completion are retained. Neither is
// a cached observation. Retained generations admit only already-owned partial
// launch pins while replacing an interrupted attempt with a newer denial.
type nativeRepair struct {
	Request  hostwebgeneration.DeniedRepairRequest
	Binding  hostwebgeneration.RecoveryBinding
	Retained []hostwebgeneration.Generation
}
type nativeCompletion struct {
	Request        hostwebgeneration.DeniedRepairRequest
	Binding        hostwebgeneration.RecoveryBinding
	ResultRevision uint64
	Retained       []hostwebgeneration.Generation
}

func copyRepairRequest(q hostwebgeneration.DeniedRepairRequest) hostwebgeneration.DeniedRepairRequest {
	q.Original.Before = copyGeneration(q.Original.Before)
	q.Original.After = copyGeneration(q.Original.After)
	q.Target = copyGeneration(q.Target)
	return q
}
func validRecoveryIdentity(i hostwebgeneration.Identity) bool {
	return ((i.GenerationID == "" && i.Denied) || idPattern.MatchString(i.GenerationID)) && hex64.MatchString(i.ProfileSHA256) && hex64.MatchString(i.SnapshotSHA256) && hex64.MatchString(i.BundleSHA256)
}
func validRepairRequest(p hostweb.Profile, q hostwebgeneration.DeniedRepairRequest) bool {
	if !(hex64.MatchString(q.ExpectedStateSHA256) && idPattern.MatchString(q.AttemptID) && q.BaseRevision != ^uint64(0) && q.Original.Revision <= q.BaseRevision && validTransitionOptions(p, q.Original) && validRecoveryIdentity(q.Source) && q.Source.ProfileSHA256 == digest(p) && q.Target.Denied && validateGeneration(p, q.Target, false) == nil && q.Target.Identity() != q.Source) {
		return false
	}
	// A logical ID is immutable even when a revision-only snapshot change
	// happens to compile to identical daemon bytes. Exact reuse (clean After
	// equals Target) is allowed; a second identity under that ID is not.
	known := map[string]hostwebgeneration.Identity{}
	for _, i := range []hostwebgeneration.Identity{q.Source, q.Original.Before.Identity(), q.Original.After.Identity(), q.Target.Identity()} {
		if previous, ok := known[i.GenerationID]; ok && previous != i {
			return false
		}
		known[i.GenerationID] = i
	}
	return true
}
func validTransitionOptions(p hostweb.Profile, t hostwebgeneration.Transition) bool {
	return t.Revision != ^uint64(0) && t.Before.ID != t.After.ID && idPattern.MatchString(t.OperationID) && validateGeneration(p, t.Before, t.Before.ID == "") == nil && validateGeneration(p, t.After, false) == nil
}
func repairBinding(q hostwebgeneration.DeniedRepairRequest) hostwebgeneration.RecoveryBinding {
	return hostwebgeneration.RecoveryBinding{OperationID: q.Original.OperationID, AttemptID: q.AttemptID, OriginalRevision: q.Original.Revision, BaseRevision: q.BaseRevision, Source: q.Source, Before: q.Original.Before.Identity(), After: q.Original.After.Identity(), Target: q.Target.Identity(), IntentSHA256: hostwebgeneration.RecoveryIntentSHA(q), AdmittedStateSHA256: q.ExpectedStateSHA256}
}
func sameRepair(q hostwebgeneration.DeniedRepairRequest, b hostwebgeneration.RecoveryBinding) bool {
	want := repairBinding(q)
	// CAS can be refreshed after reopening. The admitted original token remains
	// immutable and is checked separately, never folded into the stable intent.
	want.AdmittedStateSHA256 = b.AdmittedStateSHA256
	return want == b
}
func validateRecoveryRecord(p hostweb.Profile, v record) error {
	if validateApplyRecord(p, v) != nil {
		return ErrRecovery
	}
	// Validate every reference before path/ID deduplication can conceal a
	// different snapshot under an already-known logical generation ID.
	known := map[string]hostwebgeneration.Identity{}
	admit := func(i hostwebgeneration.Identity) bool {
		if previous, ok := known[i.GenerationID]; ok && previous != i {
			return false
		}
		known[i.GenerationID] = i
		return true
	}
	for _, g := range recordGenerationReferences(v) {
		if !admit(g.Identity()) {
			return ErrRecovery
		}
	}
	if v.Repair != nil && !admit(v.Repair.Request.Source) || v.CompletedRepair != nil && !admit(v.CompletedRepair.Request.Source) {
		return ErrRecovery
	}
	if v.BootID != "" && !bootPattern.MatchString(v.BootID) {
		return ErrRecovery
	}
	for _, p := range v.Processes {
		if v.BootID != "" && p.Boot != v.BootID {
			return ErrRecovery
		}
	}
	if v.Repair != nil {
		n := v.Repair
		if v.Pending != nil || !validRepairRequest(p, n.Request) || n.Binding != repairBinding(n.Request) || !bootPattern.MatchString(v.BootID) || v.Current.Identity() != n.Binding.Source || len(n.Retained) > MaxGenerations {
			return ErrRecovery
		}
		if v.Revision != n.Binding.BaseRevision {
			return ErrRecovery
		}
		seen := map[string]bool{}
		for _, g := range n.Retained {
			key := generationPath(g)
			if seen[key] || validateGeneration(p, g, g.ID == "") != nil {
				return ErrRecovery
			}
			seen[key] = true
		}
	}
	if v.CompletedRepair != nil {
		n := v.CompletedRepair
		if !validRepairRequest(p, n.Request) || n.Binding != repairBinding(n.Request) || n.ResultRevision != n.Binding.BaseRevision+1 || v.Revision != n.ResultRevision || v.LastOperation != n.Binding.OperationID || v.Current.Identity() != n.Binding.Target || !bootPattern.MatchString(v.BootID) || len(n.Retained) > MaxGenerations {
			return ErrRecovery
		}
		seen := map[string]bool{}
		for _, g := range n.Retained {
			key := generationPath(g)
			if seen[key] || validateGeneration(p, g, g.ID == "") != nil {
				return ErrRecovery
			}
			seen[key] = true
		}
	}
	return nil
}

func recordGenerationReferences(v record) []hostwebgeneration.Generation {
	out := []hostwebgeneration.Generation{v.Current}
	if v.Pending != nil {
		out = append(out, v.Pending.Before, v.Pending.After, v.Pending.Target)
	}
	if v.Repair != nil {
		out = append(out, v.Repair.Request.Original.Before, v.Repair.Request.Original.After, v.Repair.Request.Target)
		out = append(out, v.Repair.Retained...)
	}
	if v.CompletedRepair != nil {
		out = append(out, v.CompletedRepair.Request.Original.Before, v.CompletedRepair.Request.Original.After, v.CompletedRepair.Request.Target)
		out = append(out, v.CompletedRepair.Retained...)
	}
	if v.CompletedApply != nil {
		out = append(out, v.CompletedApply.Original.Before, v.CompletedApply.Original.After)
	}
	return out
}

func recordGenerations(v record) []hostwebgeneration.Generation {
	out := recordGenerationReferences(v)
	seen := map[string]bool{}
	unique := make([]hostwebgeneration.Generation, 0, len(out))
	for _, g := range out {
		key := generationPath(g)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, copyGeneration(g))
		}
	}
	return unique
}

func transitionMatches(a, b hostwebgeneration.Transition) bool {
	return a.OperationID == b.OperationID && a.Revision == b.Revision && a.Before.Identity() == b.Before.Identity() && a.After.Identity() == b.After.Identity()
}
func nativeTransition(t transaction) hostwebgeneration.Transition {
	return hostwebgeneration.Transition{OperationID: t.OperationID, Revision: t.Revision, Before: t.Before, After: t.After}
}
func repairRequestAdmission(v record, stateSHA string, q hostwebgeneration.DeniedRepairRequest) error {
	if q.ExpectedStateSHA256 != stateSHA {
		return ErrConflict
	}
	if v.Repair != nil && sameRepair(q, v.Repair.Binding) {
		return nil
	}
	if q.BaseRevision != v.Revision || q.Source != v.Current.Identity() {
		return ErrConflict
	}
	if v.Repair != nil {
		if q.AttemptID == v.Repair.Binding.AttemptID || !transitionMatches(q.Original, v.Repair.Request.Original) {
			return ErrConflict
		}
		return nil
	}
	if v.Pending != nil {
		if !transitionMatches(q.Original, nativeTransition(*v.Pending)) {
			return ErrConflict
		}
		return nil
	}
	if v.CompletedRepair != nil && q.Original.OperationID == v.CompletedRepair.Binding.OperationID {
		if q.AttemptID == v.CompletedRepair.Binding.AttemptID || !transitionMatches(q.Original, v.CompletedRepair.Request.Original) {
			return ErrConflict
		}
		return nil
	}
	if v.CompletedApply != nil && q.Original.OperationID == v.CompletedApply.Original.OperationID {
		return completedApplyRequestAdmission(v, q)
	}
	// Clean controller-death entry or coordinator intent created before native
	// Apply ran. The source must be the exact current configured generation.
	if q.Original.Revision != v.Revision || q.Original.Before.Identity() != v.Current.Identity() || q.Original.OperationID == v.LastOperation {
		return ErrConflict
	}
	return nil
}

// completedRequestAdmission validates only replay metadata/CAS. Its success
// is never a receipt: the Linux caller must still inspect and Observe afresh.
func completedRequestAdmission(v record, stateSHA string, q hostwebgeneration.DeniedRepairRequest) error {
	n := v.CompletedRepair
	if n == nil || v.Pending != nil || v.Repair != nil || !sameRepair(q, n.Binding) || (q.ExpectedStateSHA256 != stateSHA && q.ExpectedStateSHA256 != n.Binding.AdmittedStateSHA256) {
		return ErrConflict
	}
	if n.ResultRevision != q.BaseRevision+1 || v.Revision != n.ResultRevision || v.LastOperation != n.Binding.OperationID || v.Current.Identity() != n.Binding.Target {
		return ErrRecovery
	}
	return nil
}
