//go:build linux

package hostwebruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

var _ hostwebgeneration.DeniedRepairer = (*Runtime)(nil)

// recordedBoot never treats this boot as evidence of a previous execution.
// Older metadata can supply evidence through its recorded pins, even if every
// pinned PID is gone. An empty old record has no such evidence and is refused.
func recordedBoot(v record, current string) (string, error) {
	known := v.BootID
	if known == "" && len(v.Processes) > 0 {
		known = v.Processes[0].Boot
	}
	if !bootPattern.MatchString(known) || known != current {
		return "", ErrRecovery
	}
	for _, p := range v.Processes {
		if p.Boot != known {
			return "", ErrRecovery
		}
	}
	return known, nil
}

func recoveryMemberIdentity(pid int, expectedNamespace uint64) (socketLifetime, error) {
	start, e := startIdentity(pid)
	if e != nil {
		return socketLifetime{}, ErrRecovery
	}
	ns, e := namespaceID(pid)
	if e != nil || ns != expectedNamespace {
		return socketLifetime{}, ErrRecovery
	}
	again, e := startIdentity(pid)
	if e != nil || again != start {
		return socketLifetime{}, ErrRecovery
	}
	return socketLifetime{PID: pid, Start: start, Namespace: ns}, nil
}
func recoveryMemberSocket(ctx context.Context, pid int, ns uint64, inode string) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	before, e := recoveryMemberIdentity(pid, ns)
	if e != nil {
		return false, e
	}
	owned, e := recoveryMemberFD(ctx, pid, inode)
	if e != nil {
		return false, e
	}
	after, e := recoveryMemberIdentity(pid, ns)
	if e != nil || !sameSocketLifetime(before, after) {
		return false, ErrRecovery
	}
	if e := ctx.Err(); e != nil {
		return false, e
	}
	return owned, nil
}
func recoveryMemberFD(ctx context.Context, pid int, inode string) (bool, error) {
	f, e := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if e != nil {
		return false, ErrRecovery
	}
	defer f.Close()
	names, e := f.Readdirnames(257)
	if e != nil && e != io.EOF {
		return false, ErrRecovery
	}
	if len(names) > 256 {
		return false, ErrLimit
	}
	owned := false
	for _, name := range names {
		if e := ctx.Err(); e != nil {
			return false, e
		}
		if _, e := strconv.ParseUint(name, 10, 32); e != nil {
			return false, ErrRecovery
		}
		target, e := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", name))
		if e != nil {
			return false, ErrRecovery
		}
		owned = owned || target == "socket:["+inode+"]"
	}
	return owned, nil
}
func (r *Runtime) recoverySocketOwner(ctx context.Context, p processPin, ids []int, inode string) (bool, error) {
	if len(ids) == 0 || len(ids) > MaxGroupMembers || inode == "" || r.verifyPin(p) != nil {
		return false, ErrRecovery
	}
	owned := false
	for _, pid := range ids {
		member, e := recoveryMemberSocket(ctx, pid, p.Namespace, inode)
		if e != nil {
			return false, e
		}
		owned = owned || member
	}
	// Bracket the whole member scan with the exact namespace-init identity.
	if r.verifyPin(p) != nil {
		return false, ErrRecovery
	}
	return owned, ctx.Err()
}

// recoveryListeners checks the union before any write or signal. A listener
// may exist only in an exact surviving recorded namespace of the proper role;
// an unrecorded process on a removed account's address is still foreign.
func (r *Runtime) recoveryListeners(ctx context.Context, v record, generations []hostwebgeneration.Generation) error {
	members := map[int][]int{}
	for _, p := range v.Processes {
		if _, e := startIdentity(p.PID); os.IsNotExist(e) {
			continue
		}
		if r.verifyPin(p) != nil {
			return ErrRecovery
		}
		ids, e := namespaceMembers(p)
		if e != nil {
			return e
		}
		members[p.PID] = ids
	}
	type endpoint struct {
		ip       string
		port     uint16
		role, id string
	}
	endpoints := map[endpoint]bool{{r.opts.Profile.FrontendIP, r.opts.Profile.FrontendPort, "front", ""}: true}
	socketPaths := map[string]string{}
	for _, g := range generations {
		for _, a := range g.Accounts {
			endpoints[endpoint{backendIP(a.UID), r.opts.Profile.BackendPort, "backend", a.ID}] = true
			socketPaths[filepath.Join(r.opts.Profile.RuntimeRoot, a.ID, "php-fpm.sock")] = a.ID
		}
	}
	for point := range endpoints {
		wildcard, e := listener("0.0.0.0", point.port)
		if e != nil {
			return e
		}
		if wildcard != "" {
			return ErrConflict
		}
		inode, e := listener(point.ip, point.port)
		if e != nil {
			return e
		}
		if inode == "" {
			continue
		}
		owned := false
		for _, p := range v.Processes {
			if p.Role == point.role && p.AccountID == point.id && len(members[p.PID]) > 0 {
				match, err := r.recoverySocketOwner(ctx, p, members[p.PID], inode)
				if err != nil {
					return err
				}
				owned = owned || match
			}
		}
		if !owned {
			return ErrConflict
		}
		again, e := listener(point.ip, point.port)
		if e != nil {
			return e
		}
		if again != inode {
			return ErrConflict
		}
	}
	tcp6, e := procNetwork("tcp6")
	if e != nil {
		return e
	}
	ports := map[uint16]bool{}
	for point := range endpoints {
		ports[point.port] = true
	}
	covered, e := protectedIPv6Listener(tcp6, ports)
	if e != nil {
		return e
	}
	if covered {
		return ErrConflict
	}
	data, e := procNetwork("unix")
	if e != nil {
		return e
	}
	seenUnix := map[string]string{}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) != 8 {
			continue
		}
		id, known := socketPaths[fields[7]]
		if !known {
			continue
		}
		if seenUnix[fields[7]] != "" {
			return ErrRecovery
		}
		seenUnix[fields[7]] = fields[6]
		owned := false
		for _, p := range v.Processes {
			if p.Role == "fpm" && p.AccountID == id && len(members[p.PID]) > 0 {
				match, err := r.recoverySocketOwner(ctx, p, members[p.PID], fields[6])
				if err != nil {
					return err
				}
				owned = owned || match
			}
		}
		if !owned {
			return ErrConflict
		}
	}
	if len(seenUnix) > 0 {
		again, e := procNetwork("unix")
		if e != nil {
			return e
		}
		found := map[string]string{}
		for _, line := range strings.Split(string(again), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) == 8 && seenUnix[f[7]] != "" {
				if found[f[7]] != "" {
					return ErrRecovery
				}
				found[f[7]] = f[6]
			}
		}
		for path, inode := range seenUnix {
			if found[path] != inode {
				return ErrConflict
			}
		}
	}
	return r.verifyRecorded(v.Processes, true)
}

func (r *Runtime) recoveryAdmission(ctx context.Context, v record, extra ...hostwebgeneration.Generation) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if r.guard() != nil {
		return "", ErrRecovery
	}
	data, e := readBelow(r.fd, "state.json", 0600, MaxMetadataBytes)
	if e != nil || hash(data) != r.stateSHA {
		return "", ErrRecovery
	}
	for _, g := range ownedGenerations(v) {
		if r.disk(g) != nil {
			return "", ErrRecovery
		}
	}
	if fd, e := openBelow(r.fd, "state.next", unix.O_RDONLY, 0); e != unix.ENOENT {
		if e == nil {
			unix.Close(fd)
		}
		return "", ErrRecovery
	}
	boot, e := bootID()
	if e != nil {
		return "", e
	}
	boot, e = recordedBoot(v, boot)
	if e != nil {
		return "", e
	}
	if e = r.verifyRecorded(v.Processes, true); e != nil {
		return "", e
	}
	generations := recordGenerations(v)
	generations = append(generations, extra...)
	if e = r.recoveryListeners(ctx, v, generations); e != nil {
		return "", e
	}
	return boot, ctx.Err()
}

func (r *Runtime) InspectRecovery(ctx context.Context) (hostwebgeneration.RecoveryInspection, error) {
	ctx, cancel, e := bounded(ctx)
	if e != nil {
		return hostwebgeneration.RecoveryInspection{}, e
	}
	defer cancel()
	if e = r.acquire(ctx); e != nil {
		return hostwebgeneration.RecoveryInspection{}, e
	}
	defer r.release()
	if r.guard() != nil {
		return hostwebgeneration.RecoveryInspection{}, ErrRecovery
	}
	v, e := r.load()
	if e != nil {
		return hostwebgeneration.RecoveryInspection{}, ErrRecovery
	}
	if _, e = r.recoveryAdmission(ctx, v); e != nil {
		return hostwebgeneration.RecoveryInspection{}, e
	}
	out := hostwebgeneration.RecoveryInspection{StateSHA256: r.stateSHA, Revision: v.Revision, LastOperationID: v.LastOperation, Configured: v.Current.Identity()}
	if v.Pending != nil {
		p := v.Pending
		out.Pending = &hostwebgeneration.RecoveryPending{OperationID: p.OperationID, Revision: p.Revision, Before: p.Before.Identity(), After: p.After.Identity(), Target: p.Target.Identity()}
		if p.ApplyIntent != nil {
			b := *p.ApplyIntent
			out.Pending.Apply = &b
		}
	}
	if v.Repair != nil {
		b := v.Repair.Binding
		out.Pending = &hostwebgeneration.RecoveryPending{OperationID: b.OperationID, Revision: b.BaseRevision, Before: b.Before, After: b.After, Target: b.Target, Repair: &b}
	}
	if v.CompletedRepair != nil {
		b := v.CompletedRepair.Binding
		out.Completed = &b
	}
	if v.CompletedApply != nil {
		c := v.CompletedApply.Completion
		out.CompletedApply = &c
	}
	if observed, err := r.observe(ctx, v); err == nil {
		out.Observed = &observed
	}
	if ctx.Err() != nil {
		return hostwebgeneration.RecoveryInspection{}, ctx.Err()
	}
	// Neither the inspection nor its pointer fields alias retained runtime data.
	return out, nil
}

// ownedGenerations retains already-installed sources, not arbitrary intended
// config from Original.After when an Apply never reached disk staging.
func ownedGenerations(v record) []hostwebgeneration.Generation {
	out := []hostwebgeneration.Generation{v.Current}
	if v.Pending != nil {
		out = append(out, v.Pending.Before, v.Pending.After, v.Pending.Target)
	}
	if v.Repair != nil {
		out = append(out, v.Repair.Retained...)
		out = append(out, v.Repair.Request.Target)
	}
	if v.CompletedRepair != nil {
		out = append(out, v.CompletedRepair.Retained...)
		out = append(out, v.CompletedRepair.Request.Target)
	}
	if v.CompletedApply != nil {
		out = append(out, v.CompletedApply.Original.Before, v.CompletedApply.Original.After)
	}
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

func (r *Runtime) completedReceipt(ctx context.Context, q hostwebgeneration.DeniedRepairRequest, v record) (hostwebgeneration.DeniedRepairReceipt, error) {
	n := v.CompletedRepair
	if e := completedRequestAdmission(v, r.stateSHA, q); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	if _, e := r.recoveryAdmission(ctx, v); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	observed, e := r.observe(ctx, v)
	if e != nil || observed != n.Binding.Target {
		return hostwebgeneration.DeniedRepairReceipt{}, ErrRecovery
	}
	if e = ctx.Err(); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	return hostwebgeneration.DeniedRepairReceipt{Binding: n.Binding, ResultRevision: n.ResultRevision, Observed: observed}, nil
}

func (r *Runtime) RepairDenied(ctx context.Context, q hostwebgeneration.DeniedRepairRequest) (hostwebgeneration.DeniedRepairReceipt, error) {
	ctx, cancel, e := bounded(ctx)
	if e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	defer cancel()
	if e = r.acquire(ctx); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	defer r.release()
	q = copyRepairRequest(q)
	if !validRepairRequest(r.opts.Profile, q) {
		return hostwebgeneration.DeniedRepairReceipt{}, ErrInvalid
	}
	if r.guard() != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, ErrRecovery
	}
	v, e := r.load()
	if e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, ErrRecovery
	}
	boot, e := r.recoveryAdmission(ctx, v, q.Original.Before, q.Original.After, q.Target)
	if e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	if v.CompletedRepair != nil && q.AttemptID == v.CompletedRepair.Binding.AttemptID {
		return r.completedReceipt(ctx, q, v)
	}
	if e = repairRequestAdmission(v, r.stateSHA, q); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	n := v.Repair
	if n == nil || !sameRepair(q, n.Binding) {
		retained := ownedGenerations(v)
		if len(retained) > MaxGenerations {
			return hostwebgeneration.DeniedRepairReceipt{}, ErrLimit
		}
		n = &nativeRepair{Request: q, Binding: repairBinding(q), Retained: retained}
	} else {
		q = n.Request
	} // preserves the originally admitted token
	// Reserve both pending and terminal metadata capacity before staging or
	// touching daemon-owned output. No receipt journal grows without a bound.
	prospective := v
	prospective.BootID = boot
	prospective.Pending = nil
	prospective.Repair = n
	if prospective.CompletedApply != nil && !transitionMatches(q.Original, prospective.CompletedApply.Original) {
		prospective.CompletedApply = nil
	}
	if e = repairMetadataCapacity(r.opts.Profile, prospective, q, n); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	// Staging is immutable, bounded, and happens after ownership/CAS admission.
	if e = r.stage(q.Target); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	if e = r.prepareOutputs(q.Target); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	if e = r.syntax(ctx, q.Target); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	if _, e = r.recoveryAdmission(ctx, v, q.Original.Before, q.Original.After, q.Target); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	v.BootID = boot
	v.Pending = nil
	v.Repair = n
	if v.CompletedApply != nil && !transitionMatches(q.Original, v.CompletedApply.Original) {
		v.CompletedApply = nil
	}
	if e = r.persist(v); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	if _, e = r.recoveryAdmission(ctx, v); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	if e = r.stop(&v); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	if e = r.persist(v); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, e
	}
	for _, g := range recordGenerations(v) {
		if e = r.absent(g); e != nil {
			return hostwebgeneration.DeniedRepairReceipt{}, e
		}
	}
	if e = r.launch(ctx, &v, q.Target); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, r.failedRepair(&v, e)
	}
	observed, e := r.observe(ctx, v)
	if e != nil || observed != q.Target.Identity() || ctx.Err() != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, r.failedRepair(&v, errors.Join(ErrRecovery, e, ctx.Err()))
	}
	v.Current = copyGeneration(q.Target)
	v.Repair = nil
	v.Pending = nil
	v.Revision = q.BaseRevision + 1
	v.LastOperation = q.Original.OperationID
	v.CompletedRepair = &nativeCompletion{Request: copyRepairRequest(q), Binding: n.Binding, ResultRevision: v.Revision, Retained: n.Retained}
	v.CompletedApply = nil
	if e = r.persist(v); e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, ErrRecovery
	}
	// Do not reuse the pre-persist observation, especially after cancellation.
	final, e := r.load()
	if e != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, ErrRecovery
	}
	receipt, e := r.completedReceipt(ctx, q, final)
	if ctx.Err() != nil {
		return hostwebgeneration.DeniedRepairReceipt{}, r.failedRepair(&final, ctx.Err())
	}
	return receipt, e
}

func repairMetadataCapacity(profile hostweb.Profile, v record, q hostwebgeneration.DeniedRepairRequest, n *nativeRepair) error {
	return repairMetadataCapacityLimit(profile, v, q, n, MaxMetadataBytes)
}

func repairMetadataCapacityLimit(profile hostweb.Profile, v record, q hostwebgeneration.DeniedRepairRequest, n *nativeRepair, limit int) error {
	if limit <= 0 || limit > MaxMetadataBytes {
		return ErrLimit
	}
	maximalPending := v
	maximalPending.Processes = maxStoragePins(profile, q.Target, v.BootID)
	terminal := v
	terminal.Current = copyGeneration(q.Target)
	terminal.Processes = maxStoragePins(profile, q.Target, v.BootID)
	terminal.Repair = nil
	terminal.Pending = nil
	terminal.Revision = q.BaseRevision + 1
	terminal.LastOperation = q.Original.OperationID
	terminal.CompletedRepair = &nativeCompletion{Request: copyRepairRequest(q), Binding: n.Binding, ResultRevision: terminal.Revision, Retained: n.Retained}
	terminal.CompletedApply = nil
	for _, candidate := range []record{v, maximalPending, terminal} {
		if validateRecord(profile, candidate) != nil {
			return ErrRecovery
		}
		data, e := json.Marshal(metadataCopy(candidate))
		if e != nil || len(data) > limit {
			return ErrLimit
		}
	}
	return nil
}
func (r *Runtime) failedRepair(v *record, cause error) error {
	stopErr := r.stop(v)
	persistErr := r.persist(*v)
	return errors.Join(ErrRecovery, cause, stopErr, persistErr)
}
