//go:build linux

package hostwebruntime

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

// Synthetic ELF headers/modules are read-admission fixtures only. No command
// from this fixture is executed, and these tests do not prove Apache serving.
func recoveryFilesystem(t *testing.T) *Runtime {
	t.Helper()
	r := filesystemRuntime(t)
	root := r.opts.Root
	for _, dir := range []string{"bin", "modules", "tls"} {
		if e := os.Mkdir(filepath.Join(root, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	r.opts.Profile.ApacheBinary = filepath.Join(root, "bin/httpd")
	r.opts.Profile.FPMBinary = filepath.Join(root, "bin/fpm")
	r.opts.Profile.ApacheModuleRoot = filepath.Join(root, "modules")
	for _, name := range []string{r.opts.Profile.ApacheBinary, r.opts.Profile.FPMBinary} {
		if e := os.WriteFile(name, []byte("\x7fELFfixture-only"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"mpm_event", "unixd", "authz_core", "authz_host", "dir", "log_config", "proxy", "proxy_http", "proxy_fcgi", "ssl", "mime"} {
		if e := os.WriteFile(filepath.Join(root, "modules/mod_"+name+".so"), []byte("fixture-only"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(r.opts.Profile.CAFile, []byte("fixture-public-ca"), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := r.inputDigest()
	if e != nil {
		t.Fatal(e)
	}
	r.inputsSHA = h
	return r
}
func writeRecoveryState(t *testing.T, r *Runtime) (record, hostwebgeneration.DeniedRepairRequest) {
	t.Helper()
	before := testGeneration(t, r.opts, strings.Repeat("a", 32), false)
	target := testGeneration(t, r.opts, strings.Repeat("b", 32), true)
	if e := r.stage(before); e != nil {
		t.Fatal(e)
	}
	boot, e := bootID()
	if e != nil {
		t.Fatal(e)
	}
	v := record{Version: 1, Revision: 4, LastOperation: strings.Repeat("e", 32), Current: before, BootID: boot, InputsSHA256: r.inputsSHA}
	if e = r.persist(v); e != nil {
		t.Fatal(e)
	}
	q := hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: r.stateSHA, AttemptID: strings.Repeat("c", 32), Original: hostwebgeneration.Transition{OperationID: strings.Repeat("d", 32), Revision: 4, Before: before, After: target}, BaseRevision: 4, Source: before.Identity(), Target: target}
	return v, q
}
func TestRecoveryBootEvidenceWithMissingPins(t *testing.T) {
	boot, e := bootID()
	if e != nil {
		t.Fatal(e)
	}
	for name, v := range map[string]record{"explicit": {BootID: boot}, "oldpins": {Processes: []processPin{{Boot: boot}}}} {
		t.Run(name, func(t *testing.T) {
			if _, e := recordedBoot(v, boot); e != nil {
				t.Fatal(e)
			}
		})
	}
	for name, v := range map[string]record{"none": {}, "otherboot": {BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}, "mixed": {BootID: boot, Processes: []processPin{{Boot: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}}}} {
		t.Run(name, func(t *testing.T) {
			if _, e := recordedBoot(v, boot); e == nil {
				t.Fatal("missing or foreign boot accepted")
			}
		})
	}
}
func TestNativeRecoveryInspectDeadMetadataAndCAS(t *testing.T) {
	r := recoveryFilesystem(t)
	v, q := writeRecoveryState(t, r)
	got, e := r.InspectRecovery(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if got.Observed != nil || got.Configured != v.Current.Identity() || got.StateSHA256 != r.stateSHA {
		t.Fatal("dead metadata mislabeled")
	}
	wrong := copyRepairRequest(q)
	wrong.ExpectedStateSHA256 = strings.Repeat("0", 64)
	before := r.stateSHA
	if _, e = r.RepairDenied(context.Background(), wrong); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if r.stateSHA != before {
		t.Fatal("CAS failure mutated state")
	}
	if _, e = os.Stat(filepath.Join(r.opts.Profile.ManagedRoot, generationPath(q.Target))); !os.IsNotExist(e) {
		t.Fatal("CAS failure staged target")
	}
	// Mutation of returned value must not alter subsequent inspection.
	got.Configured.BundleSHA256 = strings.Repeat("0", 64)
	again, e := r.InspectRecovery(context.Background())
	if e != nil || again.Configured != v.Current.Identity() {
		t.Fatal(e)
	}
}
func TestNativeCompletionRoundTripIsHistoricalOnly(t *testing.T) {
	r := recoveryFilesystem(t)
	v, q := writeRecoveryState(t, r)
	if e := r.stage(q.Target); e != nil {
		t.Fatal(e)
	}
	v.Current = copyGeneration(q.Target)
	v.Revision = 5
	v.LastOperation = q.Original.OperationID
	v.CompletedRepair = &nativeCompletion{Request: copyRepairRequest(q), Binding: repairBinding(q), ResultRevision: 5, Retained: []hostwebgeneration.Generation{q.Original.Before}}
	if e := r.persist(v); e != nil {
		t.Fatal(e)
	}
	got, e := r.InspectRecovery(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if got.Completed == nil || got.Completed.IntentSHA256 != hostwebgeneration.RecoveryIntentSHA(q) || got.Observed != nil {
		t.Fatal("historical completion became healthy receipt")
	}
	got.Completed.IntentSHA256 = "changed"
	again, e := r.InspectRecovery(context.Background())
	if e != nil || again.Completed.IntentSHA256 != hostwebgeneration.RecoveryIntentSHA(q) {
		t.Fatal("completion alias", e)
	}
	before := r.stateSHA
	if _, e = r.RepairDenied(context.Background(), q); !errors.Is(e, ErrRecovery) {
		t.Fatal("dead completion cached success", e)
	}
	if before != r.stateSHA {
		t.Fatal("dead retry mutated state")
	}
	// Reopening load uses real admitted disk, not the in-memory request copy.
	r.stateSHA = ""
	if _, e = r.load(); e != nil {
		t.Fatal(e)
	}
}
func TestNativeRecoveryForeignListenerBeforeStage(t *testing.T) {
	r := recoveryFilesystem(t)
	owned, e := net.Listen("tcp4", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	defer owned.Close()
	r.opts.Profile.FrontendPort = uint16(owned.Addr().(*net.TCPAddr).Port)
	_, q := writeRecoveryState(t, r)
	before := r.stateSHA
	if _, e = r.InspectRecovery(context.Background()); !errors.Is(e, ErrConflict) {
		t.Fatal("foreign wildcard admitted", e)
	}
	if _, e = r.RepairDenied(context.Background(), q); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if r.stateSHA != before {
		t.Fatal("foreign listener changed state")
	}
	if _, e = os.Stat(filepath.Join(r.opts.Profile.ManagedRoot, generationPath(q.Target))); !os.IsNotExist(e) {
		t.Fatal("foreign listener staged target")
	}
	if c, e := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(int(r.opts.Profile.FrontendPort))); e != nil {
		t.Fatal("foreign listener was stopped", e)
	} else {
		c.Close()
	}
}
func TestNativeRecoveryPartialMetadataAndExclusiveNext(t *testing.T) {
	r := recoveryFilesystem(t)
	v, q := writeRecoveryState(t, r)
	if e := r.stage(q.Target); e != nil {
		t.Fatal(e)
	}
	v.Repair = &nativeRepair{Request: copyRepairRequest(q), Binding: repairBinding(q), Retained: []hostwebgeneration.Generation{v.Current}}
	if e := r.persist(v); e != nil {
		t.Fatal(e)
	}
	got, e := r.load()
	if e != nil || got.Repair.Binding != v.Repair.Binding {
		t.Fatal(e)
	}
	// metadataCopy must not erase the original hydrated request.
	copy := metadataCopy(got)
	if len(copy.Repair.Request.Target.Bundle.Files[0].Data) != 0 || len(got.Repair.Request.Target.Bundle.Files[0].Data) == 0 {
		t.Fatal("copy mutated live request")
	}
	if e = writeExclusive(r.fd, "state.next", []byte("interrupted")); e != nil {
		t.Fatal(e)
	}
	before := r.stateSHA
	if _, e = r.InspectRecovery(context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal("interrupted temp admitted", e)
	}
	if r.stateSHA != before {
		t.Fatal("inspection wrote state")
	}
}
func TestNativeRecoveryCancellationBeforeAdmission(t *testing.T) {
	r := recoveryFilesystem(t)
	_, q := writeRecoveryState(t, r)
	before := r.stateSHA
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := r.RepairDenied(ctx, q); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := r.InspectRecovery(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if before != r.stateSHA {
		t.Fatal("canceled admission mutated")
	}
}

func TestNativeRecoveryMetadataCorruptionOnReopen(t *testing.T) {
	r := recoveryFilesystem(t)
	_, _ = writeRecoveryState(t, r)
	file := filepath.Join(r.opts.Profile.ManagedRoot, "state.json")
	original, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string][]byte{
		"duplicate":  append([]byte("{\"Version\":1,"), original[1:]...),
		"unknown":    append([]byte("{\"Unknown\":true,"), original[1:]...),
		"trailing":   append(append([]byte(nil), original...), []byte(" {}")...),
		"whitespace": append(append([]byte(nil), original...), ' '),
		"oversize":   bytes.Repeat([]byte(" "), MaxMetadataBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if e := os.WriteFile(file, data, 0600); e != nil {
				t.Fatal(e)
			}
			r.stateSHA = ""
			if _, e := r.load(); e == nil {
				t.Fatal("corrupt reopened metadata")
			}
		})
	}
	if e = os.WriteFile(file, original, 0600); e != nil {
		t.Fatal(e)
	}
	r.stateSHA = ""
	if _, e = r.load(); e != nil {
		t.Fatal("original not admitted", e)
	}
	if e = os.Link(file, filepath.Join(r.opts.Profile.ManagedRoot, "state.alias")); e != nil {
		t.Fatal(e)
	}
	r.stateSHA = ""
	if _, e = r.load(); e == nil {
		t.Fatal("hardlinked state")
	}
}

func TestNativeRecoveryRefusesEmptyOldBootEvidence(t *testing.T) {
	r := recoveryFilesystem(t)
	v, _ := writeRecoveryState(t, r)
	v.BootID = ""
	if e := r.persist(v); e != nil {
		t.Fatal(e)
	}
	if _, e := r.InspectRecovery(context.Background()); !errors.Is(e, ErrRecovery) {
		t.Fatal("fabricated empty-record boot", e)
	}
}

func TestNativeRecoveryRemovedAddressListener(t *testing.T) {
	r := recoveryFilesystem(t)
	v, q := writeRecoveryState(t, r)
	// The desired denied inventory is empty, while Original.Before still carries
	// alpha's address. A foreign listener there must be refused before staging.
	q.Target.Accounts = q.Target.Accounts[:0]
	q.Target.ID = strings.Repeat("f", 32)
	q.Target.SnapshotSHA256 = digest(q.Target.Accounts)
	bundle, e := hostweb.Compile(r.opts.Profile, nil)
	if e != nil {
		t.Fatal(e)
	}
	q.Target.Bundle = bundle
	foreign, e := net.Listen("tcp4", backendIP(v.Current.Accounts[0].UID)+":18443")
	if e != nil {
		t.Fatal(e)
	}
	defer foreign.Close()
	before := r.stateSHA
	if _, e = r.RepairDenied(context.Background(), q); !errors.Is(e, ErrConflict) {
		t.Fatal("removed address listener accepted", e)
	}
	if r.stateSHA != before {
		t.Fatal("foreign removed listener mutated state")
	}
	if _, e = os.Stat(filepath.Join(r.opts.Profile.ManagedRoot, generationPath(q.Target))); !os.IsNotExist(e) {
		t.Fatal("foreign removed listener staged target")
	}
}

// Actual read-only /proc and loopback socket observations; this is not daemon
// activation or forced kernel PID-reuse fault qualification.
func TestRecoverySocketMemberReadOnlyProc(t *testing.T) {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	inode, e := listener("127.0.0.1", port)
	if e != nil || inode == "" {
		t.Fatal("owned socket inode", e)
	}
	pid := os.Getpid()
	ns, e := namespaceID(pid)
	if e != nil {
		t.Fatal(e)
	}
	owned, e := recoveryMemberSocket(context.Background(), pid, ns, inode)
	if e != nil || !owned {
		t.Fatal("own lifetime socket", e)
	}
	if _, e = recoveryMemberSocket(context.Background(), pid, ns+1, inode); !errors.Is(e, ErrRecovery) {
		t.Fatal("foreign namespace accepted", e)
	}
	if _, e = recoveryMemberSocket(context.Background(), 1<<30, ns, inode); !errors.Is(e, ErrRecovery) {
		t.Fatal("vanished PID accepted", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = recoveryMemberSocket(ctx, pid, ns, inode); !errors.Is(e, context.Canceled) {
		t.Fatal("canceled scan", e)
	}
}
