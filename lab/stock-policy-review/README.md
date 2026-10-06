# Independent native host-policy review

This lab challenges actual production parser/report/CLI functions using two
additional test files admitted through an owned Go overlay. The `.go.txt` files
are tests, not copied policy implementations. The ordinary lab tests separately
exercise the public DTO with unavailable contexts and unsupported platforms.
They do not inspect live Linux host policy.

`source-catalog.json` pins the exact reviewed core and CLI bytes. From this
review checkout, with offline modules and owned TEMP/TMP:

```powershell
python lab/stock-policy-review/prepare.py
& ../../scripts/go.ps1 test '-mod=readonly' '-overlay=.cache/stock-policy-review/overlay.json' '-run=^TestIndependent' '-count=1' '-timeout=60s' -json ./internal/hostaccounts ./cmd/hostbroker ./lab/stock-policy-review
python lab/stock-policy-review/audit_source.py
```

The primary Go wrapper location in the command is relative to this assigned
worktree; it uses the existing primary module/tool inputs and compilation cache.
The overlay changes no production file and adds no test to another checkout.
Output stays under this checkout's `.cache/stock-policy-review`.

Challenges cover every NUL insertion offset, foreign/ambiguous NSS providers and
duplicate required authorities, strict Shadow mail literals, inclusive total and
legacy line bounds, opaque raw-error refusal, cancellation during a blocked
probe, complete partial-result discard, fixed public JSON/reasons/restrictions,
CLI diagnostics consumed as serving-option values, fixed errors, bounded
deadline/cancellation and output failure. Positive parser cases preserve the
existing supported syntax; no provider/mail policy is rewritten.

The source auditor separately verifies that native guards from `authority`
through all later command/identity/create/recovery/state functions remain byte
identical after line-ending normalization, and the broker change is exactly the
constructor relocation before directory/store/socket creation.

Portable tests and source review are not native stock-host evidence, cPanel or
CloudLinux compatibility, account provisioning, all-OS support, service/reboot
readiness or an atomic policy-stability guarantee. Any signed guest observation
has separate source/binary/image/report authority. No live state, utility,
service, credentials, dependency input or provider setting is changed here.
