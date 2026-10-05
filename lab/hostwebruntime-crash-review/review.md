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

## First actual native attempt: failed, retained

Root ran `crash-1791218270997-97151f195c50f14c34065997` under catalogue
`38fd4353ae7f4f4b9ff6a563fbe1c970e47caafe15cfe77faf1e4169f5333a40`.
The host rejected terminal exit 1. Independent read-only raw serial inspection
found the actual owned/reaped SIGKILL 9, nine recovery checkpoints and history
events, ten HTTP probes, and passing shutdown/close/listener/input/SELinux gates.
The driver's final namespace extinction gate was false. Its five emitted
namespace inode values reused earlier values across stages. The previous
nine-distinct-ID assumption was invalid for this kernel run; the false cleanup
gate's exact cause remains unmeasured in that report. No product defect or
successful native qualification is inferred from this failed result.

`first-native-failure.json` retains the report, serial and compact driver SHA256,
actual counter sequence, namespace IDs and failed classification. Root preserved
the ignored run unchanged. A revised model must retain exact 5/1/3 process epochs
bound to native state hashes, permit inode reuse only across those epochs, and
provide bounded drain diagnostics plus an independent guest post-exit scan.

The read-only `audit_prepared.py` command against prepared run
`crash-1791218107015-7c2b4b45d3cb81d6ea487130`, using local Python with `-I -B`,
exited 0: 2542 source inputs, 14 runner files and 29 actual ISO payload entries
matched. The preparation-only ISO SHA256 was
`271ba47993ffb792afe515866fd28cd05ad8ec8c5981f70efd4ca0f7603be115`.
Preparation was never classified as native execution. `audit_result.mjs` is a
read-only helper for a future accepted result and has only syntax verification
at this point.

The explicit replacement receipt model has 67/67 synthetic challenge tests
(`node --test lab/hostwebruntime-crash-review/test_receipt.mjs`, exit 0).
Exactly three raw-metadata process epochs bind to the before-kill, denied and
selective native state hashes with 5/1/3 distinct current process/namespace pins.
The sorted union may have 5 through 9 IDs only through recorded cross-epoch
reuse. The final measured alpha worker must inhabit the selective FPM namespace.
Both crash-time and final drain receipts retain initial and terminal scans,
bounded attempts and elapsed time, matching PID/start/namespace identities and
fixed read-error/errno/PID diagnostics. Success requires empty error-free terminal
scans; initial measured errors or members may drain within the bound. The old
strict-nine schema is rejected. These are synthetic parser checks, not a second
native result.

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
