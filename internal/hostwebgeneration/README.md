# Unactivated web generation coordinator

This package implements durable configuration transition bookkeeping. No
production broker, HTTP route, CLI command, native executor, service manager,
certificate installer, or daemon activation is included. Executor tests simulate
protocol observations; they are not Linux serving or isolation evidence.

`Open` admits a root-selected compiler profile and a dedicated private absolute
state directory. Unix opens require root, a root-owned 0700 directory, and a
root-owned single-link 0600 database. Windows uses the existing securestate
protected directory ACL for isolated protocol tests and checks regular-file,
single-link, no-reparse identity; this is not Linux root admission. Trusted future
broker composition must admit safe root-owned ancestors before calling Open.
Neither directory nor profile is accepted from an HTTP/controller request.

The account provider/lease types alias hostaccounts' actual snapshot seam.
Its reservation covers broker mutations/reconciliation and verifies native
identity on admission, explicitly before executor writes and journal commit,
and after the callback. Work receives the lease's marked context. Callbacks
cannot reenter the account store or use captured unmarked contexts for store
calls. External root writers bypass this reservation; repeated verification
reduces but cannot eliminate their check/use race. A broker identity recovery
state can prevent acquiring a generation recovery lease; this library does not
then promise immediate native denial.

`Plan` compiles the reserved canonical account snapshot without touching a host.
It returns coordinator revision/current identity, profile digest, full account
identity/state/revision digest, and deterministic bundle digest. `Apply` acquires
a fresh verified reservation, recomputes every field, and rejects stale plans.
Actor/reason are validated, bounded journal metadata. Trusted future operator
authentication must supply the actor; this library supplies no authentication.

Before any executor Apply, the independently observed runtime must match the
known previous generation. With no committed generation, it must attest an
explicit denied bundle for the exact snapshot/profile, with no tenant serving.
The generation and pending intent are persisted in one synced Bolt transaction.
Apply never commits on a timeout or executor error, even if the desired runtime
was partially installed. A successful independent Observe must match generation
ID, profile, snapshot and configuration bundle before the revision is committed.
All executor inputs are copied, including configuration byte slices. Every
operation and every write validates the durable generations and journal first;
Status polling is not required for corruption detection.

Pending operations survive close/crash/reopen and block new Plan/Apply calls.
Recover requires the exact pending operation ID and coordinator revision. It
first freshly observes the runtime; unknown third-party identities are never
overwritten. A serving previous generation is restored only if its full snapshot
equals both the failed After generation and the newly reserved accounts.
Matching Before to current accounts alone cannot authorize serving rollback
across a different failed snapshot. Otherwise a new exact denied bundle is persisted
and passed to Rollback. The denied observation must match that bundle and the
current snapshot before recovery completes. A provider's postcallback failure
after provisional commit durably reopens recovery at the current revision.

Executor calls receive a maximum 30-second context, capped by caller and lease
deadlines. Expired results cannot commit. Go cannot safely preempt arbitrary
non-cooperative injected code while releasing an account reservation: the
separately qualified native executor must terminate/reap its owned process
groups on cancellation. This package makes no strict return-time claim for
uncooperative dependencies and does not start background callbacks that can
continue writing after a reservation is released.

The journal stores Ponytrail-inspired operation IDs, actor/reason and before/
after identity metadata, contiguous revision/phase transitions, and SHA256 hash
chains. It does not create Ponytrail encrypted file checkpoints or host backups.
These hashes detect accidental damage; they cannot authenticate against the
root database owner. Private persisted bundles and account inventories contain
domains, paths and UID/GID mappings and must not be returned wholesale through
status/API responses. No certificate private key bytes are stored.

Storage admits at most 16 generation records, 128 event rows, 16MiB per generation
record, 64KiB per metadata row, and a 512MiB database. Admission reserves capacity
for denial/recovery and provider-failure quarantine. There is no automatic pruning
or reset that could erase pending recovery evidence. Reaching a bound rejects
further writes; preserving and replacing exhausted private state is an explicit
operator maintenance decision outside this library.

Acceptance evidence is the isolated Go tests: full CAS/replay rejection, pending
crash recovery, observed denial after suspension, safe prior restoration,
unknown-runtime refusal, postverification quarantine, immutable executor inputs,
deadline/drift rejection, mandatory durable semantic validation, damage during
execution, and bounded generation/event storage. Actual Apache/FPM activation,
supplementary groups, SELinux policy, restart/reload, suspension integration and
reboot recovery still require native executor/peer-boundary qualification.
