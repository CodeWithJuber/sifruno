# Native hosting account access policy foundation

This package provides an immutable authorization policy and an in-memory revisioned authority. It is not connected to
HTTP, the local operator session, the host-account broker, or a database. It does
not provide tenant authentication, credential revocation, production multiuser
isolation, or vendor compatibility certification.

## Trust contract

`NewPolicy` accepts a complete snapshot of **trusted** actor role/assignment and
account ownership bindings. The caller must obtain these from an authoritative
server-controlled source. Existing `hostaccounts.Account` records contain no
owner field; this package does not add one or invent a source for it.

`Authorize(actor, action, resource)` requires the actor ID from independently
verified authentication. `ParseActorID` only validates syntax. A request body,
header, route parameter, cookie payload, key, or audit actor string does not
establish identity. `operator.Manager.Authorize` currently returns the fixed
`local-operator` audit label; it is not a tenant principal. No adapter promotes
that value to a policy actor. Requesters cannot supply roles/owners to
`Authorize`; those are resolved exclusively within the trusted snapshot.

Any future adapter must establish identity, load authoritative ownership and
assignments, and revalidate admission at the protected operation boundary.
Existing routes return a global account inventory: do not expose that inventory
to resellers or account users. This package neither filters lists nor authorizes
bulk work from an individual account decision. An allowed decision also does not
replace native input validation, lifecycle checks, revision/CAS checks, CSRF,
authentication expiry, or broker admission.

## Explicit permission matrix

| Action | Exact resource | ServerAdmin | Reseller | AccountUser |
| --- | --- | --- | --- | --- |
| ReadCapability | ServerResource | Allow | Deny | Deny |
| ListAccounts | ServerResource | Allow | Deny | Deny |
| CreateAccount | ServerResource | Allow | Deny | Deny |
| ReadAccount | Admitted AccountResource | Allow | Own admitted account | Assigned account |
| SetAccountState | Admitted AccountResource | Allow | Own admitted account | Deny |

All other action/resource/role combinations deny, including zero/unknown values
and unknown accounts for admins. Capability is server-scoped only. There is no
wildcard, default allow, ownership reassignment action, role management action,
credential action, arbitrary command, deletion, or other resource type.

Actor identifiers are 1–64 ASCII bytes, start with lowercase `a`–`z`, and contain
only lowercase letters, digits, `_`, or `-`. Account IDs preserve the native
32 lowercase hexadecimal format. Parsers reject aliases instead of normalizing.
Opaque identifier/resource fields prevent construction of malformed values by
ordinary package callers; zero values remain invalid. Parsing IDs is never proof
of identity or existence.

Each actor has exactly one role. Only account users have an assigned account,
which must exist in the snapshot. Each account has exactly one registered admin
or reseller owner. Duplicate bindings (even identical ones), missing owners,
unknown roles, and invalid assignments reject the entire constructor input and
return a nil policy. An empty account inventory is supported so an admitted admin
can create the first account; it does not grant access to nonexistent accounts.

## Bounds and lifetime

The pilot admits at most 100 accounts, matching `hostaccounts.MaxAccounts`, and
256 actors, a deliberately fixed pilot cap rather than an unbounded directory.
No dependency on the hostaccounts runtime is introduced. Increasing either cap
requires a deliberate review. Oversized slices are rejected before allocation.
Construction copies the bindings; caller slice mutation cannot change decisions.
Authorization uses a fixed number of map lookups, makes no allocations, and
performs no I/O, clock access, command execution, or state changes.

A policy is immutable and safe for concurrent reads. Role changes, ownership
changes, removal, and revocation of assignments require constructing/replacing
the trusted policy and disposing of stale references. An old policy still grants
its old permissions. This package has no credential/session revocation mechanism
for raw policy references. Future integration must synchronize policy replacement
with operation admission and authentication changes; retaining a snapshot is not
a revocation strategy. Nil and zero policies deny all operations.

## Verification and recovery

Tests enumerate all 256 action values across explicit actor/resource matrices;
cover cross-owner denials, account-user write/escalation denials, malformed and
ambiguous bindings, capacity boundaries, caller-slice isolation, policy replacement,
unrelated-admission invariance, zero policies, parsing, and zero request allocations.
The fuzz target exercises identifier parsing with no filesystem or live state.

Use the primary workspace `scripts/go.ps1` with this worktree as cwd and
`GOPROXY=off`, `GOSUMDB=off` for `test ./internal/accesspolicy`,
`vet ./internal/accesspolicy`, and bounded parser fuzzing. Only the package and
this README are added; recovery is reverting the standalone commit. No state
migration or running-process change is required because no existing caller uses
this package.

## Revisioned admission

`NewAuthority(policy)` validates and copies a complete trusted policy. `Revision()`
returns an opaque comparable token bound to that authority. `Replace(expected,
next)` performs a synchronized compare-and-swap, advancing the revision even for
identical bindings. Stale, zero, and foreign tokens fail; invalid snapshots and
revision exhaustion leave the previous state intact. Revisions never wrap or
revive after removal and re-addition. Copied Authority handles share one state.
Nil and zero authorities deny admission; no policy getter exposes a snapshot.

`AuthorizeAt(expected, actor, action, resource)` checks current revision and the
existing permission matrix together. Capture a revision before preparatory work
and recheck immediately before protected dispatch. Replacement invalidates old
tokens, including when the same grants are subsequently restored. A false result
requires fresh admission; it must not silently retry using old consent.

This is an admission checkpoint, not an execution lock. Replacement after a
successful check cannot cancel, undo, or synchronize a subsequent effect. There
are no callbacks, credential/session revocation, persistence, HTTP adapters, or
new identity/ownership sources. Independently authenticated identity remains a
caller obligation. Do not treat a revision as a credential or accept requester
claims as trusted bindings. Raw Policy references still retain their old grants.

Construction and replacement copy at most 256 actors and 100 accounts using the
existing policy validator. Admission allocates no memory and performs bounded
lookups under a read lock; lock waiting has no deadline guarantee. Tests cover
matrix equivalence, role/ownership changes, stale and foreign tokens, no ABA,
invalid snapshots, overflow, copies, and concurrent single-winner replacement.
Run `test -race ./internal/accesspolicy` when the existing toolchain supports it.
Recovery is reverting the authority addition; no production caller is activated.