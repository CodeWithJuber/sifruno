# Disposable native controller-death driver

This new lab executable adapts the fixed two-account Apache/PHP setup in
`lab/hostwebruntime-serving` and `lab/hostwebruntime-serving-guest`. It does not
activate a production API. The earlier serving driver's source pins and receipt
are not current crash evidence. The new harness must freeze this driver and its
current transitive runtime/coordinator sources in a fresh source catalogue.

## Admission and invocation

The fixed root is `/opt/sifruno-runtime-fixture`, root-owned mode 0700. Install
the ELF as `qualification-driver` mode 0700 and run exactly:

```text
/opt/sifruno-runtime-fixture/qualification-driver --input /opt/sifruno-runtime-fixture/qualification-input.json
```

Input schema 1 is the existing serving input contract, with exactly
`schema_version`, `fixture_only`, `run_id`, `root`, `profile`, `accounts`.
The two active accounts are ordered webalpha/alpha.test UID/GID 20001 and
webbravo/bravo.test UID/GID 20002, sorted unique 32-hex account IDs. `run_id` is
32 lowercase hex. Profile paths, ports, binaries and IDs remain fixed. The
driver requires root-owned mode-0600 single-link input and `source_catalog.json`
(bounded to 2 MiB), hashes their actual bytes, and uses exclusive mode-0600
`qualification-report.json`. No report overwrite is admitted.

The parent creates its own `coordinator/` and `fixture-inventory.json`; admission
rejects existing paths. Its isolated inventory adapter guards a byte baseline,
copied accounts, context cancellation, expiration, and final verification. The
parent changes the file only between callbacks. This is an adapted fixture
inventory seam, not real hostaccounts broker mutation qualification.

## Actual crash and recovery sequence

1. The parent launches only its own same-ELF child with private pipe fd 3 and a
   fresh nonce. Child bootstraps native denial, opens a real durable coordinator,
   plans and calls Coordinator.Apply with real Runtime.Apply.
2. The executor wrapper waits for Runtime.Apply to return, then inspects real
   terminal native metadata plus fresh Observe. It sends the operation, before/
   after identities, native Apply-only completion and PID/start/nonce over the
   pipe. It blocks before returning to Coordinator.Apply, and exits with failure
   at deadline. It can never return success and reach coordinator Finish.
3. Parent rereads native bytes and hashes the durable coordinator DB while the
   callback is blocked. It verifies PID/start/nonce, SIGKILLs the owned Process,
   waits and requires actual signaled-9 status. It rereads both durable files and
   requires identical bytes. Reopened coordinator independently validates its
   journal: revision 0, current nil, pending applying, one intended event.
4. Existing parent-death SIGKILL behavior remains intact. All five old namespaces
   and old listener addresses must disappear. Strict native Observe must reject
   the dead generation; reopened native inspection retains historical Apply
   completion with no fresh Observed identity.
5. Parent atomically updates only bravo to suspended with increased account
   revision/time. Coordinator.RepairDenied checkpoints the consumed Apply counter
   at revision 1, preserving current nil and the pending operation. An adapter
   deliberately refuses native repair; repeat and reopen stay at revision 1.
   These are cooperative refusals, not additional crashes. Stale revision and
   operation CAS requests must fail without changing coordinator bytes.
6. Real guarded RepairDenied compiles denial from this current inventory and
   reaches revision 2 in both journals. Both tenant static/PHP routes and a
   foreign host are independently requested and must return 403 without fixture
   markers. Healthy repeat and native/coordinator reopen refuse further repair
   without consuming another native counter.
7. A separate ordinary Apply of current inventory reaches revision 3, permits
   alpha and denies suspended bravo. Real static bytes and exact PHP isolation
   response are checked; alpha's PHP worker is independently pinned through
   `/proc` PID/start/namespace/credentials/zero capability/chroot checks.
8. Owned shutdown, close, listener extinction, all observed namespace extinction,
   unchanged admission input and SELinux enforcing are required before success.

The driver performs one actual crash after native Apply completion. It does not
claim a second crash during repair, reboot resilience, stock/cPanel compatibility,
all-OS qualification, complete control-panel parity, or production composition.
No secrets, downloads, dependency additions, firewall changes, or capability
widening are involved. Recovery/rollback is disposal of this fresh offline guest;
the driver never touches running main workspace `.state`.

## Receipt contract

The JSON report schema is 2, `execution_kind` is
`native-linux-controller-crash-driver`, and terminal success requires
`stage: complete`, `passed: true` plus every cleanup/stability boolean. The new
harness must parse exact fields, bind driver/catalogue/input hashes to its own
frozen bytes, reconstruct expected PHP bytes using `namespace_pid`, validate
the actual journal history and counters, and scan namespace extinction itself.

`crash` carries the predeath `boundary`, parent/child PID/start ownership,
signaled-9 wait result, equal durable journal before/after hashes, native byte
stability, strict Observe rejection, listener and old namespace extinction.
`checkpoints` has exactly these ordered stages:

```text
after_kill
apply_checkpoint
repeated_checkpoint
reopened_checkpoint
stale_refused
denied_repaired
healthy_repair_refused
reopened_denied
selective_apply
```

There are four `intended_generations` (bootstrap, crash After, fresh denial,
separate selective Apply), ten `probes` (five denial then five selective), one
final `worker_evidence` entry for alpha, and three `namespace_epochs` with
5 old, 1 denial and 3 selective process pins. Namespace inodes may be reused
between epochs; `observed_namespace_ids` is their sorted unique union (5 to 9),
not a claim that nine distinct IDs must be allocated. Each epoch binds the exact
native state hash and role/account/PID/start/namespace pins. `namespace_drain`
at death and final Shutdown retains initial and terminal `/proc` scan matches,
errors, bounded attempts and elapsed time. Success requires an empty error-free
terminal scan within eight seconds and a separate guest namespace scan. These
diagnostics do not infer the cause of an earlier failed immediate scan.
Probe stages contain both tenant `/index.html` and
`/probe.php` entries then `/foreign.test` in that order. The history must have
one original `apply_checkpoint` and no original `committed` event.

## Local checks and limits

With primary `scripts/go.ps1`, worktree cwd, read-only module cache,
`GOFLAGS=-mod=readonly`, `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`:

```text
go test ./lab/hostwebruntime-crash-driver ./internal/hostwebgeneration ./internal/hostwebruntime
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o .cache/hostweb-crash/qualification-driver ./lab/hostwebruntime-crash-driver
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o .cache/hostweb-crash/qualification-driver.test ./lab/hostwebruntime-crash-driver
```

Windows admission/contract and canonical recovery unit suites passed; Linux ELF
and native unit ELF compiled. These checks do not establish native behavior.
Actual Linux unit and crash qualification execution belong to the root-owned
fresh disposable QEMU harness. The later accepted actual run, its exact hashes,
independent review, two retained failures and narrow limits are recorded in
[the controller-death guide](../../docs/archive/native-web-crash-recovery.md); the source
checks above are not that native receipt.

Source review caught an initial candidate event-name mismatch (`applying` status
versus `intended` journal event) before any native run. It was corrected in this
lab candidate; no demonstrated product defect or product source change resulted.
