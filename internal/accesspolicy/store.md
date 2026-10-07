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
