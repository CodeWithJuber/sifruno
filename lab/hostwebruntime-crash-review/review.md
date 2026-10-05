# Independent review receipt, source and synthetic stage

Baseline: `18a97432be0c843ea8a26c76bf04047b0efa5a88`.
Reviewed driver commit: `ee37738b82852761f79ca84f46f4208eaf386e32`, nine additive
files under `lab/hostwebruntime-crash-driver`. No product files changed.

Evidence: inspection of the runtime Apply/terminal metadata, coordinator
Apply/checkpoint/denied recovery, guarded snapshot contract, earlier serving
lab, complete driver and root's new guest/parser/build adapter. This establishes
source behavior only. No native Linux guest was executed by this reviewer.

## Commands and observed results

- Forge `substrate_check` executed before editing. Its deterministic scope
  estimate was unknown; assigned additive review directory and read-only source
  review resolved the heuristic assumptions. No live mutation authorized.
- `node --test lab/hostwebruntime-crash-review/test_receipt.mjs`: exit 0,
  39/39 synthetic tests passed, zero skips/TODOs. These tests include forged
  consumed-only checkpoint and original-commit claims with a recomputed valid
  journal hash chain, source provenance, PID/nonce/signal, stale checkpoint
  prefixes, native reopen state, current inventory, PHP hash/PID, final worker
  UID/root/capabilities, unknown-host/tenant deny and cleanup failures.
- `node --check lab/hostwebruntime-crash-review/receipt.mjs`: exit 0.
- Primary `scripts/go.ps1 build -o
  .cache/hostweb-crash-review/hash-reference.exe
  ./lab/hostwebruntime-crash-review/hash_reference.go`: exit 0 with
  `GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly`. This builds a pure hash utility,
  not the native driver. The utility accepts only stdin and computes typed Go
  Apply intent, repair intent and Event JSON hashes.
- Node invoked that local hash utility with the synthetic JSON: exit 0; its
  Apply/repair intent and all nine event digests exactly matched independent JS
  values. Output: `Typed Go apply/repair/event hash references: PASS`.
- `git diff --check`: exit 0 at this review stage.

## Preserved failures and corrections

The first synthetic validator challenge run passed 33/34. It exposed a missing
equality check for the denied native state after reopen. The validator now
requires equal native inspection at `denied_repaired`, `healthy_repair_refused`
and `reopened_denied`; synthetic decoded snapshots were also separated through
JSON round-trip, avoiding shared JS object aliases. Expanded final checks pass
39/39. This was a local synthetic failure, not a native runtime failure.

A PowerShell `<` stdin redirection attempt was rejected before execution.
PowerShell pipeline into the wrapper then produced utility exit 2 because the
script did not forward stdin. Building the pure utility through the wrapper and
invoking its exe with Node's explicit stdin completed the reference check. These
command plumbing failures are distinct from the successful hash comparison.

The partial driver incorrectly expected Event phase `applying`. Review identified
that `applying` belongs to pending Status while the durable begin event is
`intended`. The owner corrected it before any native execution and included the
correction in the frozen driver commit. Earlier partial source is not native
proof.

Root's partial `freeze.mjs` initially collected test names from only main and
native Linux test files, omitting `contract_test.go`. This was communicated to
root as a pre-run blocker; final assembled freeze must include the complete
Linux-qualified test set.

Independent assembled parser challenge command:
`SIFRUNO_CRASH_CANDIDATE_ROOT=<web-crash-integration> node --test
lab/hostwebruntime-crash-review/test_assembled.mjs` passed 57/57 at its initial
review point (36 receipt tests plus 21 new guest/serial integration tests).
Unknown fields, nested duplicate JSON, marker alias/foreign nonce, contradictory
panic, nonzero terminal/test/driver exits, old serving proof, changed package/
policy/environment and cleanup failure were refused. No guest executed.

Before root's assembled freeze, the receipt authority was tightened to require
configured/operation equality at dead checkpoints, repair admitted-state equality,
selective Apply admitted-state/boot/input continuity, and exactly nine distinct
namespace IDs for this fixed 5-old + 1-denial + 3-selective lab. A kernel inode
reuse or omitted ID fails closed; preserve its actual report and diagnose it
without asserting a product defect.

## Limits and recovery

`receipt.mjs` validates an exact success schema under explicit source/input/nonce
pins and rejects unknown fields. It independently reconstructs PHP/static body
hashes and Go intent/event digests; its synthetic values are never execution
proof. Header framing, raw JSON duplicate rejection, QEMU/guest/test/driver
process exits, source/ELF/payload admission and independent guest `/proc`
extinction belong to root's assembled host/guest runner and are separate gates.

Deny-body hashes are actual driver measurements and the driver enforces HTTP
403 with no synthetic tenant marker. They are not independently observed network
packets or requests from a second actor. The final alpha worker `/proc` identity
is measured by the driver; guest cleanup independently scans the admitted
namespace IDs after driver exit. Fixture inventory uses a sequential root-file
byte guard, not production broker reservation, native account mutations, or a
concurrent adversarial root-writer qualification.

The requested native death/recovery behavior remains unqualified until root
executes the reviewed freeze and preserves actual serial/reports. No claim of
stock policy, reboot, other OS, cPanel parity or production API activation is
made. Revert additive lab commits to remove the lab; preserve failed ignored
guest artifacts and receipts for diagnosis.
