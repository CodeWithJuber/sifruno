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

## Accepted third actual native result

Root executed frozen source HEAD `cc72a5bbc9a4d65ae9bf312551325c77b8007651`
including product fix `fcdb93b`, under fresh catalog
`210656d6e062c7eea64122f5316f05712580136890d586900084869e71d12121`.
The focused regression's final prerequisites include five admitted temporary
roots, mechanics-only CA bytes and the actual test-binary/module input digest;
these were source-reviewed before freeze. Actual native run
`crash-1791220756529-4988ff3a904a72d7c23db277` exited 0 with QEMU exit 0.

From the review worktree, the command
`node lab/hostwebruntime-crash-review/audit_result.mjs
C:/Users/Administrator/Documents/Codex/2026-10-04/hi
C:/Users/Administrator/Documents/Codex/2026-10-04/hi/.worktrees/web-crash-integration
C:/Users/Administrator/Documents/Codex/2026-10-04/hi/.worktrees/web-crash-integration/.cache/hostwebruntime-crash-host/crash-1791220756529-4988ff3a904a72d7c23db277`
exited 0. It re-admitted 2544 current source/tool inputs and 16 runner sources,
checked exact report/serial hashes and framing, independently applied the
receipt authority, and rehashed all 30 payloads. A separate read-only Python312
`-I -B .cache/hostweb-crash-review/actual_iso.py` command with the same three path
arguments exited 0 after actual 30-entry ISO readback. Neither launched native
work. `third-native-review.json` retains the exact report/serial/catalog/ELF/ISO
hashes and acceptance scope.

Actual evidence includes the owned and reaped signal 9, 14 driver native tests,
one focused product test (`TestNamespaceReopenedHandlesReapOriginalChild`,
1.81 seconds), nine durable history events and counter checkpoints
`0,1,1,1,1,2,2,2,3`. Ten HTTP receipts separately cover all-denied repair and
current selective serving. Exact alpha static/PHP body hashes were independently
reconstructed. Epochs have 5/1/3 process pins and a five-ID union reflecting
recorded cross-epoch inode reuse. Both crash and final namespace scans were
empty/error-free on their first attempt; the final scan took 8 ms. The guest's
independent post-driver scan, listener and mount cleanup also passed.

This accepts the narrow requested adapted-fixture controller-death/recovery and
same-process reaping behavior. The preceding two failed results remain failed
and preserved; the first and second reports did not measure State/PPID, so their
precise process-state cause is still inferred from source and the corrected
regression rather than retroactively claimed as directly observed.

## Limits and recovery

The staged publication receipt is 15396 bytes with SHA256
`6c9638d2801c6cddb3bb9f8381b39e201815726e3ca1016dc5ea4772f2433d7d`.
Read-only Python312 `-I -B .cache/hostweb-crash-review/public_receipt_audit.py
<integration-root>` exited 0 after strict duplicate-free decoding and comparison
of every copied observation, artifact hash, counter sequence, native test name,
environment, cleanup and namespace field with the accepted raw run. Its retained
Go/vet/Linux-vet/protocol/audit output hashes matched their actual local files.
The reviewed projection contains fixture identities, safe hashes and process
observations; it reads no private key or credential source and contains no PEM
private key, bearer value or credential-token pattern. The narrow qualified scope
and false production/original compatibility flags remain accurate. Attachment
to a future source PR is still a publication action, not completed by this audit.

### Second actual native attempt: failed, retained

`second-native-failure.json` preserves root run
`crash-1791219476709-03b8aec1833696f1cbbbdfaa` under catalog `d841cc69...9019`.
Independent raw report/serial inspection exited 0 and found real signal 9 and
the same nine counter checkpoints. Both initial and final measured scans retained
PID 1597/start 22598/namespace 4026532184, exactly the denial-front epoch pin;
120 scans over 8053 ms reported no read errors but no extinction. Raw guest
cleanup after driver exit independently reported all four cleanup gates true.
That later cleanup does not turn failed driver exit into success. State and PPID
were not measured in this receipt, so zombie/parent ownership remains an inference.
The initial diagnostic reader guessed an absent RESULT_BEGIN marker and exited 1
before changing evidence; the corrected exact CRASH_BEGIN/END reader exited 0.

Source inspection found `Runtime.Close` leaves serving children while a new
`Open` starts with an empty child-handle map. Existing stop waited exact pidfds
but reaped only entries still present in that map. Root's proposed narrow fix
reaps a missing-map child using that same already admitted/polled pidfd through
nonblocking `Waitid(P_PIDFD, WEXITED|WNOHANG)`. It bounds EINTR, permits ECHILD,
requires actual SIGCHLD with zero errno and exited/killed/dumped code, and keeps
metadata uncertain on other outcomes. It uses no numeric-PID or wildcard wait.
Review accepted this source change and its Close/Open regression, conditional
on new linked-source pins and actual native execution. The third fixture will
add a separately pinned test ELF and exact focused regression frame: 14 driver
tests plus one product reaping test, 30 payloads. It has not executed at this
review-note point.

The strengthened receipt diagnostic schema requires measured process state and
parent PID. Its independent synthetic suite passes 71/71, exit 0. The renewed
Forge preflight attempt returned an EPERM scanning unrelated primary debug state;
impact remained unknown. Explicit owned scope and candidate source inspection
were used without reading or mutating that state.

The final assembled synthetic command with explicit integration root passes
100/100, exit 0, zero skips/TODO. It adds independent challenge closure for the
separate product reaping test receipt and REGRESSION frame (exit, skip, stderr,
wrong name, missing receipt, false contract, duplicate and alias markers).
Root's run/freeze/guest/make-ISO/parser changes were inspected together: new
read-only linked-source enumeration includes the product test, 30 actual payloads
include its distinct ELF, and execution is anchored to the one required test with
native mechanics opt-in, isolated temporary state and bounded process capture.
The read-only prepared/result helpers now require that new payload count and
separate driver/product test evidence. Guest-side catalog reaping hash/name
binding was sent to root before freeze as a concrete provenance tightening.

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

The requested adapted-fixture native death/recovery behavior is qualified by the
accepted third run and retained serial/reports. No claim of
stock policy, reboot, other OS, cPanel parity or production API activation is
made. Revert additive lab commits to remove the lab; preserve failed ignored
guest artifacts and receipts for diagnosis.
