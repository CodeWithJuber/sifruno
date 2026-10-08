# Trusted policy binding persistence

`NewStore(db)` borrows an already admitted, caller-owned bbolt database. It never
opens paths, closes the handle, initializes accounts, or supplies a default admin.
The caller owns private path permissions, database lifetime, and storage trust.
Nil, closed, read-only, NoSync, and NoGrowSync handles are refused. Do not change
handle options concurrently or directly modify the reserved `accesspolicy-v1`
bucket. Other buckets are untouched. Do not call these methods from a transaction
on the same database: nested transaction/close interactions can block.

`Initialize(policy)` creates the previously absent reserved bucket explicitly.
An existing empty or damaged bucket is an error, not an invitation to bootstrap.
`Load()` validates and returns a new immutable Policy and opaque StoreVersion.
`Replace(expected, policy)` commits the complete validated snapshot and its next
version in one transaction. Failed validation, stale/foreign versions, corruption,
and counter exhaustion return no version and preserve committed bindings.

The bucket contains exactly one canonical JSON `snapshot` record: schema 1,
random 128-bit repository identity, nonzero uint64 sequence, sorted actor bindings,
and sorted account ownership bindings. Reads reject records over 96 KiB before
decoding; after decoding the existing 256-actor/100-account limits and NewPolicy
validation apply. Re-encoding equality rejects unknown/duplicate/aliased fields,
noncanonical order, and alternate encodings. Unknown bucket records are refused.

Versions survive reopen and are distinct from process-local Authority revisions.
Separately initialized databases have independently random identities. A copied or
restored database retains its identity and revision: rollback/clone detection is
not provided. Trusted storage must prevent unauthorized rewrites/restoration.
No credentials, tenant authentication, native account existence checks, migration,
HTTP integration, or automatic Authority refresh are introduced. Persisting and
installing a policy into Authority are NOT one atomic operation; composition and
operation admission remain future work. Retained loaded Policies remain immutable
historical snapshots and do not revoke themselves.

Durability relies on bbolt's normal synchronized commit and the filesystem/device
honoring its guarantees. Hardware failure or hostile storage is not certified.
Transaction and database-lock waiting has no cancellation/deadline guarantee.
Errors intentionally omit database paths and stored contents.

Verification uses only temporary databases: reopen/matrix, replacement and ABA,
corruption, unavailable handles, overflow/isolation, and concurrent CAS. Use the
primary Go wrapper with GOPROXY=off and GOSUMDB=off for package tests and vet.
Recovery for a corrupt database requires an explicit trusted operator procedure;
there is no silent reset or repair API. Reverting this source addition does not
migrate or delete stored data. No production caller is activated by this commit.

## Transaction-backed admission

`Store.AuthorizeAt(expected, actor, action, resource)` validates a fresh bbolt
read snapshot and checks both its StoreVersion and the existing permission matrix
in that same transaction. It does not reuse a loaded Policy or an Authority cache.
A matching permitted request returns `(true, nil)`; a matching permission denial
returns `(false, nil)`. Zero, foreign, or stale versions return `(false,
ErrConflict)`. Unavailable, missing, or corrupt storage returns `(false, ErrStore)`
before version comparison. No error returns an allowed decision or repairs data.

Admission linearizes at the database read snapshot. Checks whose transactions
begin after a replacement commits see the replacement; old tokens fail even if
the same grants are subsequently restored or the database is reopened. An
already-running read may complete against its older snapshot. Replacement does
not lock, cancel, or undo effects following a successful check. Identity must
still be independently authenticated, and callers must establish their own
operation-admission contract. No caller wiring is introduced here. Existing
storage trust, clone/rollback limitations, and transaction waiting constraints
above still apply.

## Authorized policy replacement

`ManagePolicy` is an explicit server-scoped action appended after the existing
five actions, preserving their numeric values. Only a current ServerAdmin may
perform it on exactly ServerResource; resellers, account users, unknown actors,
and account resources deny. This extends the original foundation matrix with
policy management; it does not enable a tenant-facing route.

`ReplaceAuthorized(expected, actor, next)` uses one write transaction to validate
the current stored snapshot, compare its version, and authorize ManagePolicy using
that snapshot. Only then does it check exhaustion, validate the candidate and
commit the replacement. Candidate roles cannot authorize their own installation.
An administrator may demote or remove itself; subsequent writes by that actor
are denied unless a trusted authority grants permission again.

Admission and validation refusals return a zero version without changing committed state.
A commit I/O error also returns no version, but its durable outcome can be ambiguous.
Inspect and reload trusted stored state before deciding what to do next; do not
infer a grant from the error or blindly retry the write. Error precedence
is ErrStore for unavailable/corrupt storage, ErrConflict for zero/foreign/stale
versions, ErrDenied for an unauthorized current actor, then ErrExhausted or
ErrInvalid for exhaustion or an invalid candidate. Ordinary permission refusal
from Store.AuthorizeAt still returns false with no error.

The existing `Replace` remains a privileged trusted bootstrap/recovery API that
performs no actor authorization; it must not be exposed as a tenant route. Neither
method establishes the caller's identity. An independently authenticated actor
and trusted candidate bindings remain integration obligations. The transaction
covers only this database replacement, not callbacks or external effects. No
HTTP, session, native account, or production authentication wiring is added.

## Account inventory projection

`Store.VisibleAccountsAt(expected, actor)` returns only admitted account IDs for
which the existing policy permits `ReadAccount`. It validates storage, compares
the version, checks actor registration, and evaluates permissions in one bbolt
read transaction. ServerAdmins see all admitted accounts, Resellers see accounts
they own, and AccountUsers see their assigned account. `ListAccounts` remains an
admin-only server action; the projection introduces no new action or permission.
Results expose no owners, roles, global account counts, or other metadata.

IDs are sorted by their canonical strings. Each successful result is a separately
owned slice, including a nonnil empty slice for a registered actor with no visible
accounts. Only authorized IDs enter the slice, and its capacity equals its length.
Every error returns nil: unavailable, closed, missing, or corrupt
storage yields `ErrStore` first; zero, foreign, or stale versions yield
`ErrConflict` next; zero or unregistered actors yield `ErrDenied` last. Existing
snapshot validation bounds inventory to at most 100 admitted accounts. Reads do
not repair storage, and caller mutations of a returned slice cannot change policy.

Inventory linearizes at its read snapshot. A read overlapping replacement may
finish with the previous inventory; reads beginning after commit refuse its old
version. Retained lists are historical data and grant no permission for later
operations: those operations must recheck current authorization at admission.
The caller must independently authenticate the actor; a request-claimed ID is
not proof of identity. No tenant HTTP/CLI route or production caller is wired.
The storage trust, clone/rollback, waiting, and recovery limits above still apply.
Reverting the inventory source addition leaves persisted bindings unchanged.
