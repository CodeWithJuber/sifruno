# Independent operator session review

This lab exercises the actual isolated `operator.Manager` and `api.New` HTTP
handler through Go `httptest` requests. It does not copy the implementation's
private tests or modify live operator state. Every manager uses `t.TempDir`.

The challenge contract covers exact inventory fields and bounds, stable unique
public handles distinct from isolated authentication values, current-session
conflict, unknown-handle refusal, single and bulk revocation, strict empty-object
requests, origin/CSRF/loopback admission, login rotation, legacy logout and
restart invalidation. Two gated body readers pause requests while another
session revokes their authorizer; releasing either stale mutation must return
401 and leave other admissions intact.

The lab decodes only its own encrypted fixture cookie with its own temporary
session keys, to compare inventory against the private ID as well as CSRF,
cookie and access-key values. Neither success nor failure diagnostics print
those values. No IP/fingerprint metadata is accepted by the typed inventory
decoder.

Run the primary workspace's `scripts/go.ps1` with this worktree as the current
directory, `GOPROXY=off`, `GOSUMDB=off` and `-mod=readonly`. If implementation
commits have not yet been integrated here, pass an ignored `-overlay` map whose
source paths and SHA256 values are recorded in the review receipt. Run only
`./lab/operator-session-review`; root owns the broader package and UI checks.

These are in-process HTTP handler challenges on Windows, not browser execution,
native Linux acceptance, remote authentication, roles or original compatibility.
Advertised capacity is checked here; filling the private 128-record bound and
clock-driven expiry remain implementation tests and source-review evidence.
The public-preview proxy exclusion is separately reviewed and checked by root.

## Recorded review

The immutable 10-file candidate overlay passed four top-level tests and 38
subtests with exit 0, no failures/skips, in 0.312 seconds on Windows. Source
hashes, command, stdout/stderr digests and the precise scope are in
`handler-review.json`; current candidate bytes matched after execution.
An earlier identical narrow run also passed, but its console display was
truncated, so the retained run closes that output-capture gap.

The integrated source matched all ten tested inputs. The separate read-only
`audit_browser.py` run passed the actual root report and rehashed its executable,
91 complete UI assets, 11 source files and 18 screenshots. Four representative
images were independently inspected. `browser-review.json` records the real
TCP/browser flows separately from synthetic 503, browser-clock and public-mode
fixture checks. Root's final documentation/status/source archive receives a
separate audit; these receipts do not qualify that later delivery gate.
