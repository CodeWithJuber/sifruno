package hostwebruntime

import (
	"fmt"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
	"strings"
	"testing"
	"time"
)

func TestRecoveryReviewProtectedIPv6ParserFailsClosed(t *testing.T) {
	header := "sl local_address rem_address st tx_queue rx_queue tr tm_when retrnsmt uid timeout inode\n"
	row := func(address string, port uint16) string {
		return fmt.Sprintf("0: %s:%04X %s:0000 0A 0:0 0:0 0 0 0 99\n", address, port, strings.Repeat("0", 32))
	}
	ports := map[uint16]bool{18082: true, 18443: true}
	for _, address := range []string{strings.Repeat("0", 32), "0000000000000000FFFF00000100007F", "00000000000000000000000001000000"} {
		for _, port := range []uint16{18082, 18443} {
			covered, e := protectedIPv6Listener([]byte(header+row(address, port)), ports)
			if e != nil || !covered {
				t.Fatalf("protected IPv6 escaped: %s/%d %v", address, port, e)
			}
		}
	}
	covered, e := protectedIPv6Listener([]byte(header+row(strings.Repeat("0", 32), 19000)), ports)
	if e != nil || covered {
		t.Fatalf("unrelated port rejected: %v", e)
	}
	for _, bad := range []string{"", "wrong header\n", header + "0: truncated\n", header + "0: " + strings.Repeat("0", 32) + ":46A2 ignored ZZ\n", header + "0: " + strings.Repeat("0", 32) + ":46A2 ignored 0A\n", header + row(strings.Repeat("Z", 32), 18082), strings.Repeat("x", (1<<20)+1)} {
		if _, e = protectedIPv6Listener([]byte(bad), ports); e == nil {
			t.Fatal("malformed/truncated/bounded IPv6 table accepted")
		}
	}
}

func TestRecoveryReviewNativeConsumedApplyAndReplayCAS(t *testing.T) {
	_, q := recoveryReviewRequest(t)
	v := record{Version: 1, Revision: 1, LastOperation: q.Original.OperationID, Current: q.Original.After, BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
	if repairRequestAdmission(v, q.ExpectedStateSHA256, q) == nil {
		t.Fatal("original consumed base reused")
	}
	newer := copyRepairRequest(q)
	newer.BaseRevision = 1
	newer.Source = v.Current.Identity()
	if repairRequestAdmission(v, q.ExpectedStateSHA256, newer) == nil {
		t.Fatal("invented original Apply checkpoint admitted")
	}
	completed := record{Version: 1, Revision: 1, LastOperation: q.Original.OperationID, Current: q.Target, BootID: v.BootID, CompletedRepair: &nativeCompletion{Request: copyRepairRequest(q), Binding: repairBinding(q), ResultRevision: 1}}
	current := strings.Repeat("2", 64)
	if completedRequestAdmission(completed, current, q) != nil {
		t.Fatal("exact original admitted replay token refused")
	}
	replay := copyRepairRequest(q)
	replay.ExpectedStateSHA256 = current
	if completedRequestAdmission(completed, current, replay) != nil {
		t.Fatal("current-token exact replay refused")
	}
	replay.ExpectedStateSHA256 = strings.Repeat("3", 64)
	if completedRequestAdmission(completed, current, replay) == nil {
		t.Fatal("arbitrary fresh token accepted")
	}
	replay = copyRepairRequest(q)
	replay.AttemptID = strings.Repeat("f", 32)
	if completedRequestAdmission(completed, current, replay) == nil {
		t.Fatal("foreign attempt accepted")
	}
	completed.Revision = 2
	if completedRequestAdmission(completed, current, q) == nil {
		t.Fatal("consumed result counter drift accepted")
	}
	// These successes are metadata admission only; no observed receipt is made.
}

// These checks execute pure admission/copy helpers, never native daemons.
func recoveryReviewOptions() Options {
	root := "/srv/recovery-review"
	return Options{Root: root, Profile: hostweb.Profile{Name: hostweb.RestrictedChrootV1, ManagedRoot: root + "/managed", ManagedHomeRoot: root + "/homes", FrontChroot: root + "/front", BackendChrootRoot: root + "/jails", RuntimeRoot: root + "/runtime", TLSRoot: root + "/tls", CAFile: root + "/tls/ca.pem", ApacheModuleRoot: "/usr/lib64/httpd/modules", ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", FrontendIP: "127.0.0.1", FrontendPort: 18082, BackendPort: 18443, FrontUID: 48, FrontGID: 48, ControllerUID: 2000}}
}
func recoveryReviewGeneration(t *testing.T, o Options, id string, denied bool) hostwebgeneration.Generation {
	t.Helper()
	stamp := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	rows := []hostaccounts.Account{{ID: strings.Repeat("a", 32), Username: "webalpha", Domain: "alpha.test", Home: o.Profile.ManagedHomeRoot + "/webalpha", PublicHTML: o.Profile.ManagedHomeRoot + "/webalpha/public_html", UID: 20001, GID: 20001, State: "active", Revision: 1, CreatedAt: stamp, UpdatedAt: stamp}}
	render := append([]hostaccounts.Account{}, rows...)
	if denied {
		render[0].State = "suspended"
	}
	bundle, e := hostweb.Compile(o.Profile, render)
	if e != nil {
		t.Fatal(e)
	}
	return hostwebgeneration.Generation{ID: id, ProfileSHA256: digest(o.Profile), SnapshotSHA256: digest(rows), Denied: denied, Accounts: rows, Bundle: bundle}
}
func recoveryReviewRequest(t *testing.T) (Options, hostwebgeneration.DeniedRepairRequest) {
	o := recoveryReviewOptions()
	before := recoveryReviewGeneration(t, o, "", true)
	after := recoveryReviewGeneration(t, o, strings.Repeat("b", 32), false)
	target := recoveryReviewGeneration(t, o, strings.Repeat("c", 32), true)
	return o, hostwebgeneration.DeniedRepairRequest{ExpectedStateSHA256: strings.Repeat("1", 64), AttemptID: strings.Repeat("e", 32), Original: hostwebgeneration.Transition{OperationID: strings.Repeat("d", 32), Revision: 0, Before: before, After: after}, BaseRevision: 0, Source: before.Identity(), Target: target}
}

func TestRecoveryReviewNativeLogicalIdentityCollision(t *testing.T) {
	o, q := recoveryReviewRequest(t)
	collision := copyRepairRequest(q)
	collision.Target.ID = collision.Original.After.ID
	if validRepairRequest(o.Profile, collision) {
		t.Fatal("same logical After ID with different full Identity admitted")
	}
	collision = copyRepairRequest(q)
	collision.Source.GenerationID = collision.Target.ID
	collision.Source.SnapshotSHA256 = strings.Repeat("0", 64)
	if validRepairRequest(o.Profile, collision) {
		t.Fatal("same logical Source ID with different full Identity admitted")
	}
	collision = copyRepairRequest(q)
	collision.Original.Before.ID = strings.Repeat("f", 32)
	collision.Source = collision.Original.Before.Identity()
	collision.Target.ID = collision.Original.Before.ID
	collision.Target.Accounts[0].Domain = "changed.example.test"
	collision.Target.Accounts[0].Revision++
	rows := append([]hostaccounts.Account(nil), collision.Target.Accounts...)
	for i := range rows {
		rows[i].State = "suspended"
	}
	bundle, e := hostweb.Compile(o.Profile, rows)
	if e != nil {
		t.Fatal(e)
	}
	collision.Target.Bundle = bundle
	collision.Target.SnapshotSHA256 = digest(collision.Target.Accounts)
	if validRepairRequest(o.Profile, collision) {
		t.Fatal("same logical Before ID with changed freshly compiled snapshot admitted")
	}
	// Clean-entry Original.After may itself be exactly the denied target.
	exact := copyRepairRequest(q)
	exact.Original.After = copyGeneration(exact.Target)
	if !validRepairRequest(o.Profile, exact) {
		t.Fatal("identical logical and full denied After/Target should remain valid")
	}
}

func TestRecoveryReviewNativeBootMetadataMatchesEveryPin(t *testing.T) {
	o, q := recoveryReviewRequest(t)
	v := record{Version: 1, Current: q.Target, Revision: 1, LastOperation: q.Original.OperationID, BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", CompletedRepair: &nativeCompletion{Request: copyRepairRequest(q), Binding: repairBinding(q), ResultRevision: 1}}
	v.Processes = []processPin{{Boot: v.BootID}, {Boot: v.BootID}}
	if validateRecoveryRecord(o.Profile, v) != nil {
		t.Fatal("matching boot metadata refused")
	}
	v.Processes[1].Boot = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if validateRecoveryRecord(o.Profile, v) == nil {
		t.Fatal("record metadata contradicts a retained pin's boot")
	}
	// This checks metadata consistency only; zero-value process fields do not
	// constitute admitted or measured process identity and are never executed.
}

func TestRecoveryReviewNativeRetainedIdentityCannotHideAlias(t *testing.T) {
	o, q := recoveryReviewRequest(t)
	alias := copyGeneration(q.Target)
	alias.Accounts[0].Domain = "changed.example.test"
	alias.Accounts[0].Revision++
	rows := append([]hostaccounts.Account(nil), alias.Accounts...)
	for i := range rows {
		rows[i].State = "suspended"
	}
	bundle, e := hostweb.Compile(o.Profile, rows)
	if e != nil {
		t.Fatal(e)
	}
	alias.Bundle = bundle
	alias.SnapshotSHA256 = digest(alias.Accounts)
	if alias.Identity() == q.Target.Identity() || alias.ID != q.Target.ID || validateGeneration(o.Profile, alias, false) != nil {
		t.Fatal("not a valid distinct identity alias fixture")
	}
	v := record{Version: 1, Current: q.Target, Revision: 1, LastOperation: q.Original.OperationID, BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", CompletedRepair: &nativeCompletion{Request: copyRepairRequest(q), Binding: repairBinding(q), ResultRevision: 1, Retained: []hostwebgeneration.Generation{alias}}}
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("retained logical identity alias concealed by later deduplication")
	}
	v.CompletedRepair.Retained = []hostwebgeneration.Generation{copyGeneration(q.Target)}
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("exact same retained identity should remain legitimate")
	}
}

func TestRecoveryReviewSocketMemberLifetimeRejectsReuse(t *testing.T) {
	before := socketLifetime{PID: 17, Start: "123456", Namespace: 42}
	if !sameSocketLifetime(before, before) {
		t.Fatal("same valid lifetime refused")
	}
	for _, after := range []socketLifetime{{PID: 18, Start: before.Start, Namespace: 42}, {PID: 17, Start: "123457", Namespace: 42}, {PID: 17, Start: before.Start, Namespace: 43}} {
		if sameSocketLifetime(before, after) {
			t.Fatal("changed PID/start/namespace accepted as same lifetime")
		}
	}
	for _, invalid := range []socketLifetime{{PID: 1, Start: before.Start, Namespace: 42}, {PID: 0, Start: before.Start, Namespace: 42}, {PID: 17, Start: "", Namespace: 42}, {PID: 17, Start: "0", Namespace: 42}, {PID: 17, Start: "01", Namespace: 42}, {PID: 17, Start: "not-start", Namespace: 42}, {PID: 17, Start: strings.Repeat("1", 21), Namespace: 42}, {PID: 17, Start: before.Start, Namespace: 0}} {
		if sameSocketLifetime(invalid, invalid) {
			t.Fatal("invalid identical fields admitted as process lifetime")
		}
	}
	// Pure comparison is Windows-executed evidence. Linux member FD scans and
	// kernel PID reuse remain separately compiled/native-unqualified behavior.
}
func TestRecoveryReviewNativeRepairRequiresRecompiledDenial(t *testing.T) {
	o, q := recoveryReviewRequest(t)
	if !validRepairRequest(o.Profile, q) {
		t.Fatal("canonical request rejected")
	}
	changes := map[string]func(*hostwebgeneration.DeniedRepairRequest){
		"active_target":               func(q *hostwebgeneration.DeniedRepairRequest) { q.Target = q.Original.After },
		"target_data_drift":           func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.Bundle.Files[0].Data[0] ^= 1 },
		"target_mode_drift":           func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.Bundle.Files[0].Mode = 0777 },
		"target_snapshot_drift":       func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.SnapshotSHA256 = strings.Repeat("2", 64) },
		"target_profile_drift":        func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.ProfileSHA256 = strings.Repeat("2", 64) },
		"source_profile_drift":        func(q *hostwebgeneration.DeniedRepairRequest) { q.Source.ProfileSHA256 = strings.Repeat("2", 64) },
		"same_source_target":          func(q *hostwebgeneration.DeniedRepairRequest) { q.Source = q.Target.Identity() },
		"malformed_state_cas":         func(q *hostwebgeneration.DeniedRepairRequest) { q.ExpectedStateSHA256 = "wrong" },
		"malformed_attempt":           func(q *hostwebgeneration.DeniedRepairRequest) { q.AttemptID = "../escape" },
		"base_overflow":               func(q *hostwebgeneration.DeniedRepairRequest) { q.BaseRevision = ^uint64(0) },
		"original_newer_than_base":    func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.Revision = 1 },
		"original_alias_before_after": func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.After = q.Original.Before },
		"original_operation_path":     func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.OperationID = "../escape" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			candidate := copyRepairRequest(q)
			change(&candidate)
			if validRepairRequest(o.Profile, candidate) {
				t.Fatal("malformed repair admitted")
			}
		})
	}
}
func TestRecoveryReviewStableIntentBindsEveryIdentityAndAttempt(t *testing.T) {
	_, q := recoveryReviewRequest(t)
	baseline := hostwebgeneration.RecoveryIntentSHA(q)
	differentCAS := copyRepairRequest(q)
	differentCAS.ExpectedStateSHA256 = strings.Repeat("2", 64)
	if hostwebgeneration.RecoveryIntentSHA(differentCAS) != baseline {
		t.Fatal("mutable CAS incorrectly changes stable intent")
	}
	changes := []func(*hostwebgeneration.DeniedRepairRequest){
		func(q *hostwebgeneration.DeniedRepairRequest) { q.AttemptID = strings.Repeat("f", 32) },
		func(q *hostwebgeneration.DeniedRepairRequest) { q.BaseRevision++ },
		func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.Revision++ },
		func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.OperationID = strings.Repeat("f", 32) },
		func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.Before.ID = strings.Repeat("f", 32) },
		func(q *hostwebgeneration.DeniedRepairRequest) { q.Original.After.ID = strings.Repeat("f", 32) },
		func(q *hostwebgeneration.DeniedRepairRequest) { q.Source.SnapshotSHA256 = strings.Repeat("f", 64) },
		func(q *hostwebgeneration.DeniedRepairRequest) { q.Target.ID = strings.Repeat("f", 32) },
	}
	for n, change := range changes {
		candidate := copyRepairRequest(q)
		change(&candidate)
		if hostwebgeneration.RecoveryIntentSHA(candidate) == baseline {
			t.Fatalf("intent omitted semantic field %d", n)
		}
	}
}
func TestRecoveryReviewRequestCopyProtectsActualConfigAndAccounts(t *testing.T) {
	_, q := recoveryReviewRequest(t)
	before := digest(q)
	copy := copyRepairRequest(q)
	copy.Original.Before.Accounts[0].Domain = "changed.test"
	copy.Original.After.Bundle.Files[0].Data[0] ^= 1
	copy.Target.Bundle.Files[0].Data[0] ^= 1
	if digest(q) != before {
		t.Fatal("copied request mutated caller generation/config data")
	}
}
func TestRecoveryReviewHistoricalCompletionMustMatchConsumedCounter(t *testing.T) {
	o, q := recoveryReviewRequest(t)
	binding := repairBinding(q)
	v := record{Version: 1, Revision: 1, LastOperation: q.Original.OperationID, Current: q.Target, BootID: "11111111-1111-1111-1111-111111111111", CompletedRepair: &nativeCompletion{Request: q, Binding: binding, ResultRevision: 1}}
	if validateRecoveryRecord(o.Profile, v) != nil {
		t.Fatal("exact historical completion rejected")
	}
	// Acceptance is metadata admission, not a serving observation or receipt.
	changes := map[string]func(*record){
		"result_counter":    func(v *record) { v.CompletedRepair.ResultRevision++ },
		"native_counter":    func(v *record) { v.Revision++ },
		"last_operation":    func(v *record) { v.LastOperation = strings.Repeat("f", 32) },
		"configured_source": func(v *record) { v.Current = q.Original.After },
		"intent_hash":       func(v *record) { v.CompletedRepair.Binding.IntentSHA256 = strings.Repeat("f", 64) },
		"admitted_cas":      func(v *record) { v.CompletedRepair.Binding.AdmittedStateSHA256 = strings.Repeat("f", 64) },
		"missing_boot":      func(v *record) { v.BootID = "" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			candidate := v
			completion := *v.CompletedRepair
			candidate.CompletedRepair = &completion
			change(&candidate)
			if validateRecoveryRecord(o.Profile, candidate) == nil {
				t.Fatal("unlinked historical completion admitted")
			}
		})
	}
}
