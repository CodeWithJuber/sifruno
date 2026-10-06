# Independent startup preflight review

Source gate for core `3893195e8720865a9a7ea394895528f74e58db1b`, against
baseline `67d527c76b8880f41b5481effc34003307de9df8`.

[acceptance.json](acceptance.json) pins all seven frozen raw source files and
their canonical Git bindings. Tests are private `.txt` overlays; no public Go
package or product files were added. `prepare.py` admits the original baseline
HEAD before an owned lab commit, checks source authority and every existing
output parent before writing, then prepares only owned immutable overlays and
snapshots under `artifacts/startup-preflight-review/build`. Its original output
is retained for recovery; it intentionally refuses a different checkout HEAD.

Focused primary-wrapper Windows execution passed 95 named tests in two
packages, with no failures or skips. The meaningful untouched-baseline CLI
control compiled and exited 1 because the new diagnostic route was unavailable;
that expected failure is retained separately. Focused Linux vet and test-ELF
compilation exited 0. Every command's raw stdout/stderr and actual status is
pinned in the receipt. Inputs remained unchanged after compilation, including
all five installed assembler headers pinned before it.

Protocol challenges verify seven fixed fields, nine ordered checks, four fixed
restrictions, exact first-refusal gating and redaction. Cancellation challenges
exercise nil/expired/public contexts and cancellation at all nine probes,
including the final probe. CLI callback challenges cover all 24 flag orders,
malformed/duplicate/alias/mixed/value-consuming options, numeric bounds,
separate authority callbacks, public fixed errors and output-write failure.
The old host diagnostic remains distinct.

The compiled hostaccounts ELF includes three exact families:
`TestIndependentStartupCancellation`, `TestIndependentStartupFreshAuthority`,
and `TestIndependentStartupProtocol`. Fresh-authority tests require an owned
root Linux TMPDIR with trusted ancestors and never skip. They exercise actual
directory admission and descriptor identity checks, missing/empty setup,
uninterpreted persisted marker/invalid database, socket symlink, mode/foreign
home conflicts and controlled local-identity/NSS refusals. Fixture setup writes
only owned temporary paths; admission must preserve tree entries, modes and
contents. Their native execution remains pending in this receipt.

Normal primary compilation cache was allowed; module/tool inputs were offline
and read-only. Generated test main, exhaustive Go distribution provenance,
atomic privileged-path stability, persisted recovery, installer setup, full
stock/CloudLinux/cPanel/vendor and all OS behavior remain outside this slice.
No VM, live process, account utility, host-policy or credential operations were
performed. Recovery preserves original source snapshots, ELF, raw logs and
expected control failure; source revert applies before activation.
