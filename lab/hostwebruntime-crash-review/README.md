# Independent controller-death lab review

This directory records independent review of the disposable native Linux
controller-death lab. It does not qualify a production API, stock Alma identity
policy, reboot recovery, cPanel compatibility, or another operating system.

## Acceptance gates

1. The owned controller child reaches the exact window: native `Apply` has
   returned after durable terminal persistence, while coordinator `Apply` has
   not received the executor return. Parent proves child identity, sends real
   `SIGKILL`, and records/reaps signal 9 status. Deadline, normal exit, forged
   handoff, and cleanup failure do not qualify.
2. Durable native inspection binds the original operation, original/base
   revision, identities, input/admitted-state hashes, boot ID, intent digest,
   and result revision. Durable coordinator state/history still hold the
   original intent with no completed original commit.
3. Recovery under the current reserved account snapshot records an
   `apply_checkpoint` that consumes exactly one historical counter without
   adopting the original active target. `RepairDenied` then installs a fresh
   denied generation, records its receipt, and measures denial for both
   tenants and unknown host. Historical completion is not serving evidence.
4. A later ordinary apply independently serves alpha while current bravo is
   suspended. Revision and snapshot hashes distinguish this apply from the
   all-denied recovery. Reopen and idempotent recovery do not replay stale
   authority or consume another counter unexpectedly.
5. New driver/test/fixture/harness source and ELF hashes bind this execution;
   earlier serving proofs remain historical. Parser unknown/duplicate/alias
   fields or control markers, nonzero exits, contradictory failure output,
   incomplete cleanup and stale provenance fail closed.

## Evidence classification

- Source inspection explains a candidate; it is not execution proof.
- Windows unit/challenge tests and Linux cross-compilation are local synthetic
  or compilation evidence only.
- Root owns any offline disposable QEMU execution and retains each failed model
  and result alongside the eventual accepted receipt.
- Native acceptance requires exact source freeze, raw serial/report bytes,
  command exits, durable journal evidence, independently reconstructed alpha
  HTTP response hashes (same-driver requests),
  current inventory revisions, and owned cleanup.

Recovery path: the lab is additive. Root's separate runtime change reaps an
already exited admitted child by its held pidfd after same-process Close/Open.
Revert the lab commits and that runtime fix separately if removing this work;
failed guest disks/reports remain ignored artifacts for diagnosis. No live state,
daemon, firewall or dependencies are changed here.
