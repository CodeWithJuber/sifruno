# Independent web recovery review

Run from a canonical Sifruno checkout or the exact assigned
`.worktrees/web-recovery-review-sol` checkout:

```powershell
powershell -NoProfile -File lab/hostweb-recovery-review/run.ps1 -CheckLayout
powershell -NoProfile -File lab/hostweb-recovery-review/test-layout.ps1
powershell -NoProfile -File lab/hostweb-recovery-review/run.ps1
```

The layout-only command performs no Go execution. The layout tests exercise
canonical and assigned-worktree admission, wrong module/worktree/lab rejection,
and an actual Windows junction refusal. They retain case evidence and remove
only their owned junction. No source, Git index, live state or process is changed.

The full runner uses the checkout's `.tools/go/bin/go.exe`, read-only
`.cache/go-mod` and an owned build cache. Dependency download is disabled.
It admits both complete frozen candidate packages from the portable catalog,
copies module files, overlays the actual compiler/account/secure-state sources,
and records hashes before and after execution. Source bytes, challenges,
catalog and runner are retained beside each dated receipt. New output lives
under `artifacts/testdata/`, so generated Go evidence is excluded from normal
`go test ./...` discovery. Test source and candidate snapshots also live under
`testdata/`; package declarations are never placed together in a discovered lab.
The lab-local `.gitattributes` declares
`testdata/** -text whitespace=cr-at-eol`, preserving the exact byte-hashed
candidate, reference and catalog inputs in Windows Git checkouts. The scoped
whitespace rule recognizes preserved CRLF endings in fixture diffs.
The runner admits that one scoped rule and pins the attribute file per run;
the source ZIP must retain it. No repository-wide attributes are changed.

The sequential checks run both packages' full Windows test suites, the exact
independent challenge inventory, Windows vet, Linux vet, and Linux test ELF
compilation. Challenges use the actual compiler and temporary coordinator
journal. Counter-bearing injected executors model partial application,
consumed counters, durable reopen, malformed receipts, counter-only checkpoint,
saved-attempt retry, postcallback quarantine, cancellation and lease failures.
The root snapshot regression is retained byte-for-byte, alongside independent
unchanged-snapshot serving restoration, changed-snapshot denial and unknown
observed-identity refusal. Runtime helper checks cover admission, copy isolation,
ID/full-identity uniqueness, replay CAS, boot consistency and protected-port
IPv6 parsing. Success requires every named challenge to pass without skips.

Historical evidence stays distinct. Freeze1 combined checks passed, then a
new logical generation ID collision test failed with exit 1 against immutable
freeze1 source. Freeze2 closes that admission gap and boot metadata consistency;
its dated receipt does not clear the subsequently identified recovery socket
member lifetime gap. Final adoption requires the separately pinned lifetime
guard candidate and a fresh combined receipt; old reports are never relabeled.

Final source review accepted runtime freeze4 (manifest
`2274c8970ab1db9df3a27dc2872eee264e864aeabbcffbc8355782a809570083`)
with coordinator freeze1. The portable 24-file candidate catalog is
`77875a360ca6ba136805d8fe58f7d0c9467ab8facbc1d0b642544a25ede02e83`.
The fresh receipt is
`artifacts/testdata/20261005T092814972-893d5c33/report.json`, SHA256
`bd9ced026a6ccc947230820a49866eef4b536ecd611476ebe951be1ff7cd5234`:
18 independent top-level tests passed without skips, both full legacy suites
and Windows/Linux vet exited 0, and Linux test compilation exited 0. All 49
input pins stayed unchanged. The exact root regression ran once at its actual
package path. Freeze4 additionally rejects conflicting identities hidden in
retained references before ID deduplication; the recovery-only socket scanner
brackets member lifetime/namespace and master identity. The common lifetime
comparison executed on Windows; Linux FD/proc scans were source-reviewed and
compiled. The separate freeze2 retained-alias regression reproduced exit 1,
preserving the red/green distinction. No known source blocker remains in this
reviewed slice. Source acceptance grants no runtime activation qualification.

The subsequent publication-only whitespace correction changed the scoped
attribute rule and its exact runner assertion, preserving every candidate and
challenge byte. Its separate closed receipt is
`artifacts/testdata/20261005T095101290-fd1dab10/report.json`, SHA256
`5b768903804b472e8ae5a4f08164e4712dfcf10512dff1667f53162b99f93627`:
the same 18 challenges passed without skips, all five command phases exited 0,
and all 49 input pins stayed unchanged. The earlier receipt and its exact
source inventory remain preserved in its source-evidence directory. Actual
read-only Git attribute checks confirm `text: unset` and
`whitespace: cr-at-eol`; all 25 staged-like fixture diffs had no whitespace
diagnostics. An outside-scope trailing-space control still failed with exit 3
(difference plus whitespace error). That separate check is recorded at
`artifacts/testdata/whitespace-check-20261005T095058207/report.json`, SHA256
`b20f88b56b31792978801450aabc98cb7ce49534f3977e03b5773fff7cdac554`.

Linux compilation and Windows protocol/helper tests do not execute Apache,
PHP-FPM, namespaces or guest recovery. The previously published two-account
positive serving proof remains tied to its older source/ELF pins. This lab
provides no native recovery fault, reboot, broker/API integration, hostile-root,
stock-system, cPanel or 100-account qualification. Original Apply committed
natively while coordinator finish failed, with no completed repair binding,
is explicitly rejected as reconciliation-required. A counter checkpoint keeps
recovery pending and preserves the previously verified Current identity; it
does not attest serving. A terminal receipt needs fresh strict observation;
historical completion metadata alone cannot return success.

No runtime activation, guest launch, provider call or live daemon operation is
performed. Candidate/catalog changes require a new reviewed freeze and receipt.
