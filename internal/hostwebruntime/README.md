# Unactivated Linux web runtime executor

This package implements `hostwebgeneration.Executor` with fixed Apache/PHP-FPM
process commands and real filesystem/process observations. It has no broker,
HTTP/CLI route, account installer, mount setup, certificate generation, service
unit, firewall operation or vendor compatibility claim. Production activation
requires independent review and qualification of each new behavior. The prior
frozen executor had mechanical and two-account serving qualification in an
adapted disposable Alma guest. That evidence does not qualify the new recovery
methods, fault windows, stock policy, reboot survival or product integration.

`Open(Options{Root, Profile})` accepts trusted root installation configuration.
Every writable compiler root must be an exact descendant of the explicit private
root. Home/jail/runtime/TLS directories, bind mappings, files-only jail NSS,
certificates, module files and daemon binaries already exist. Only loopback front
listeners are admitted. Constructor inputs must never come from an HTTP request.
The executor does not create accounts, tenant content, jails, bind mounts or keys.

Linux is required. Windows/macOS `Open` and methods return `ErrUnavailable`
without creating directories. Native prerequisites include effective UID 0,
trusted root-owned ancestors (root-owned sticky temporary ancestors permitted),
a root-owned 0700 managed directory, regular single-link root-owned inputs,
Linux `openat2` with beneath/no-symlink resolution, pidfds, PID namespaces and
exec tracing. SELinux and kernel capability policies must permit the admitted
operations. Missing support fails closed; this library never disables policy,
changes host capabilities, or substitutes a weaker implementation.

The narrow bound is eight accounts, seventeen namespace-init processes, at most
64 processes per namespace, 16 immutable generation directories and 512 KiB of
metadata. Compiler file/path/mode/hash limits still apply (256 KiB per file,
8 MiB total). Metadata stores account inventories and hashes, not duplicate
configuration payloads or private-key content. Binaries/modules have 64 MiB
individual admission bounds; /proc tables and HTTP responses have bounded reads.
Generation/log exhaustion or partial immutable staging requires explicit operator
maintenance; nothing automatically removes evidence or overwrites a staged tree.
New serving generations reserve two slots for denied recovery; existing exact
stages remain reusable. Repeated recovery exhaustion still needs maintenance.
Daemon log growth, disk quotas, resource accounting and log rotation are not
implemented or claimed bounded by these configuration limits.

Before first coordinator use, a trusted setup path explicitly calls
`Bootstrap(ctx, deniedGeneration)`. The generation has empty logical ID, the
actual reserved snapshot digest and exact profile digest; its bundle is
recompiled with all accounts suspended. No zero/absent identity is fabricated.
Bootstrap stages those exact bytes, syntax checks them, starts only the denied
front, and observes its owned listener, non-tenant workers and 403 for foreign
and known domain Host values. A failed bootstrap can be retried only for the
same exact denied identity after verifying/stopping its recorded processes.
Unhealthy metadata alone never passes `Observe`.

`Apply` validates/copies the whole transition, recompiles the canonical bundle,
checks runtime revision and exact independently observed prior identity, stages
the target and checks prepared assets/syntax before stopping the prior runtime.
Immutable staged config paths are passed directly through fixed `-f`/`-y`
arguments. Compiler content and absolute PID/log/socket/chroot references are
unchanged; this is not config rewriting or a different bundle hash. Root-owned
output directories/log files are admitted inside the managed root. No shell or
caller-supplied command options are available.

An fsynced pending record precedes stop/start. Each daemon is a separate PID
namespace init with a new session. A ptrace exec trap holds it before daemon
instructions run; the parent stays on one OS thread, records boot ID, host PID,
starttime, namespace, executable inode/hash and exact config path, fsyncs the
record, and then detaches. Parent-thread death uses retained `Pdeathsig=SIGKILL`;
`PTRACE_O_EXITKILL` additionally covers the registration gate. This deliberately
fails closed on controller/thread death rather than promising daemon survival.
The PID namespace's init exit gives kernel teardown of namespace descendants,
including children that change process group. Cleanup sends only exact pidfd
signals; it never sends a negative-PGID kill or signals a stale/recycled PID.
Native testing must verify these namespace/trace assumptions on the target
kernel and policy. Their presence in source is not isolation certification.

`Observe` accepts no requested identity. It reads strict bounded metadata,
rehydrates only the canonical inventory from disk, checks all bytes/modes and
rejects extra config files/directories. It detects changed metadata, root leaf
identity and pinned binaries/modules/CA. Process evidence includes boot/start,
namespace-init/session/group identity, root master identity, executable inode,
and exact argv (including FPM's exact rewritten master title). Listener inodes
must occur in admitted namespace processes' actual fd tables. Apache workers
must match all UID/GID fields, supplementary groups, chroot and zero effective,
permitted, ambient and inheritable capabilities. FPM socket ownership and every
present FPM worker are checked; an idle ondemand pool is not evidence that a PHP
worker executed. Actual PHP requests and their results remain native acceptance
checks. Backend TLS uses normal CA/IP-name/expiry verification and compares the
presented DER with the selected on-disk leaf; no insecure verification option.

During pending work, Observe returns the previous or target identity only when
that candidate's complete independently observed runtime matches. Mixed, absent,
foreign and stale processes fail with recovery required. Completion clears native
pending only after target observation. Metadata reads/writes compare the exact
previous stored SHA; atomic rename, file and containing-directory fsync preserve
the intended local crash protocol. Hashes detect drift, not malicious root edits.

`Rollback` is an explicit trusted repair primitive for the exact operation and
revision. It admits a known prior serving generation only with the same account
snapshot; a newly compiled denied target may use a newer snapshot. It verifies
all still-present process pins before mutation. It can repair a recorded partial
transaction or an unhealthy clean record after controller-thread death, but not
foreign/reused PID or boot identities. Reboot is quarantine, not automatic
restart/recovery. `Shutdown` stops and reaps recorded runtime; it does not create
a healthy denied observation. `Close` releases the controller lock and handles;
it is not a serving-state transition. Reopen can independently observe surviving
same-boot processes. Controller exit may kill them via parent-thread semantics.

The optional `hostwebgeneration.DeniedRepairer` adds `InspectRecovery` and
`RepairDenied`; it leaves `Observe` strict. Inspection returns independently read
configured metadata, pending bindings and historical completion. Only its
optional `Observed` field represents fresh serving evidence. A dead historical
completion is useful for a quarantined coordinator counter checkpoint, never a
successful repair receipt. The trusted coordinator owns the verified account
reservation, actor/reason journal and compilation of current-snapshot denial.

Repair rechecks canonical metadata encoding, bytes/modes, installation hashes,
state CAS, same boot and every surviving process before writes or signals. Old
metadata without a boot field needs nonempty recorded pins from the same boot;
an empty record cannot infer prior boot evidence. Every listener in the union of
current, pending, original and retained account addresses must belong to an exact
recorded namespace. IPv4 wildcards and all IPv6 listeners on these protected
ports are conservatively refused by this IPv4-only executor. External root races
remain unsupported; these repeated checks are not hostile-root authentication.
Recovery socket ownership additionally brackets each member's FD scan with its
starttime and exact namespace, and brackets the whole scan with the recorded
master identity. Vanished, reused or unreadable members fail closed. TCP and
named Unix socket mappings are rechecked after ownership inspection. Transient
worker/FD changes can therefore require a retry; the legacy observation helper
is not changed by this recovery-specific admission check.

Old-record admission does not mean old-binary rollback compatibility. The new
reader can admit an unchanged legacy record with usable same-boot pins. An older
binary's strict decoder rejects new `BootID`, `Repair`, `CompletedRepair`,
`CompletedApply` and pending `ApplyIntent`
fields even though the experimental record version remains 1. Rollback therefore
needs a matched source/state snapshot, or preservation and quarantine of new
records; there is no implicit downconversion. Current qualification state is
disposable and this package remains unactivated in the product.

A persisted immutable binding records operation, attempt, original/native base
revisions, source/before/after/denied-target identities, intent digest and the
originally admitted state digest. One active attempt and one historical
completion are retained, with at most 16 already-installed source generations.
Intent-only compiler data is recompiled but is not claimed installed. A refreshed
current CAS can resume the same pending attempt without replacing its original
admitted token. A completed exact replay admits only the current state token or
the exact original token, then performs fresh strict observation; it never stages,
relaunches or increments a revision. Changed requests and arbitrary stale tokens
refuse. A dead completed target needs a new attempt and cannot return cached
success or reuse its consumed base revision.
Logical generation IDs remain immutable across source, before, after and target;
different snapshot/config identities cannot reuse an ID, even with identical
compiler bytes. Explicit recorded boot IDs must match every retained process pin.

Native pending precedes stop/start, and completion follows a denied observation.
The final persisted record is reread and observed again before returning a
receipt. Cancellation after final persistence stops owned work and preserves a
historical, potentially dead completion for explicit reconciliation. Metadata
and generation capacity are checked before destructive action.
There is no broker/API/CLI wiring or automatic account-to-runtime suspension.

Apply now carries an Apply-only intent with version/kind, original operation,
equal original/native base revisions, full before/after identities, original
admitted native state SHA, installation input SHA and same-boot ID. Both original
generations remain canonically recompiled and disk-checked. Only `Apply` creates
this intent; `Rollback` and legacy records cannot infer or mint a completion from
LastOperation/Current. The final atomic state write promotes the exact intent to
historical `CompletedApply` together with Current=After, base+1, LastOperation
and Pending=nil. Final reread, ownership admission and fresh strict observation
precede success; cancellation/dead processes cannot return cached success.

Capacity is reserved before immutable staging and syntax checks. This preserves
the existing staging-before-Pending discipline: the Apply intent is durably
persisted before daemon stop/start or serving changes, not before every staging
file write. The reservation covers pending old pins, pending maximal target pins
and final maximal target pins, with exact paths/roles and worst-case admitted
numeric fields. Budget-only inventories are never launched or persisted.
Denied repair uses the same reservation for its future front master, including
the dead/no-pins completed-Apply checkpoint entry before staging or signaling.

An original Apply completion can authorize a separately journaled coordinator
counter-only checkpoint while Current remains the last committed coordinator
identity and recovery stays required. Subsequent explicit denial must match the
exact historical original operation/before/after/revision, use result revision as
its native base, Source=After and the current native CAS. Historical Apply remains
only during this exact same-original pending denial for retry validation; terminal
denial clears it. A new Apply/Rollback or unrelated repair clears the old marker
when its new intent is durably admitted. Inspection can expose the historical fact
with Observed=nil; it never attests that a dead target is serving. Old records
without the marker keep the consumed-original-counter branch fail-closed. These
new Apply/checkpoint/fault paths have portable/source evidence only; earlier
mechanics and serving qualification does not qualify their native execution.

Calls use a cancellable serialization gate and a 25-second operation context.
Cancellation of started work stops/reaps owned namespace inits; cleanup has one
shared three-second TERM grace plus one-second KILL wait, not one budget per
daemon. Kernel/file I/O, process start/reap and trusted caller code are not safely
preemptible Go callbacks, so no strict wall-clock return bound is claimed.
The managed-root lock is cross-process exclusive. External root writers and
filesystem races outside that private authority are not supported; this package
does not claim hostile-root protection or a namespace-based security sandbox.

Verification commands (root toolchain, worktree build cache, offline modules):

```powershell
$env:GOMODCACHE = '<primary>/.cache/go-mod'
$env:GOCACHE = '<worktree>/.cache/go-build'
$env:GOPROXY = 'off'; $env:GOSUMDB = 'off'
<primary>/.tools/go/bin/go.exe test -mod=readonly -buildvcs=false ./internal/hostwebruntime
<primary>/.tools/go/bin/go.exe vet -mod=readonly ./internal/hostwebruntime
$env:GOOS = 'linux'; $env:GOARCH = 'amd64'
<primary>/.tools/go/bin/go.exe test -mod=readonly -buildvcs=false -c -o .cache/hostwebruntime-linux.test ./internal/hostwebruntime
```

On an explicitly authorized disposable root Linux host, the compiled test binary
also contains real filesystem and opt-in kernel mechanics checks. Set
`SIFRUNO_NATIVE_RUNTIME_TEST=1` to require namespace/ptrace/pidfd registration and
descendant teardown tests. Test helpers are synthetic executable mechanics,
not Apache/FPM serving. Native qualified Apache/FPM serving, wrong certificate
refusal, suspension, failure/reopen repair and crash-window tests are still
required before production composition. No Windows, all-OS, graceful reload,
service/reboot durability, CloudLinux or cPanel certification follows from unit
tests, vet or cross-compilation. The new recovery tests cover protocol admission
and read-only filesystem/process preconditions. Synthetic ELF-header test inputs
are never executed and provide no Apache/FPM or recovery fault qualification.
