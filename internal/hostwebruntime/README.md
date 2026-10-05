# Unactivated Linux web runtime executor

This package implements `hostwebgeneration.Executor` with fixed Apache/PHP-FPM
process commands and real filesystem/process observations. It has no broker,
HTTP/CLI route, account installer, mount setup, certificate generation, service
unit, firewall operation or vendor compatibility claim. Production activation
requires independent review and fresh native qualification of this executor;
the earlier Python lab serving proof does not qualify these new Go mechanisms.

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

The current generation coordinator calls Observe before Rollback. Consequently,
it cannot itself repair an unhealthy partial runtime or a dead clean record.
Trusted integration must add a separately reviewed explicit native-repair step
under a fresh verified account reservation, then reconcile coordinator state.
This package does not fabricate an identity to bypass that integration gap and
does not claim account suspension is wired to runtime transitions.

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
tests, vet or cross-compilation.
