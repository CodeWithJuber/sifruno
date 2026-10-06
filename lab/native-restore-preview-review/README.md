# Independent native static-site restore preview challenges

This lab owns only isolated temporary state and reviewer evidence. It exercises
the actual Store, private API handler, native ZIP export/import, signed trail and
an opt-in scheduler call. It does not execute native Linux guests or claim
original vendor compatibility, all-OS behavior, whole-panel qualification, live
activation, browser behavior or a real crash.

`preview_test.go` independently reconstructs selected archive metadata from actual
ZIP entries and checks exact seven-field wire objects, nullable sides, path order,
category counts and hashes. It captures every fixture file's hash, mode, size and
membership before/after successful and failed previews, including bbolt, archive,
signed journal and schedule bytes. Admission tests count attempted request-body
reads so rejected auth cannot be mistaken for parser rejection.

The 128-path union, case-alias, revision-ceiling, rehashed foreign ZIP and pending
fixtures explicitly construct synthetic durable metadata in owned closed
temporary databases. Resealed fixtures use the actual trail API. These fixtures
prove validation behavior, not observed interruption/recovery provenance. The
four-kind case uses actual ordinary backup/write/restore operations. Concurrent
challenges start one preview and one actual write, backup or due-scheduler call
together; valid results are an old complete preview or conflict. This is a
shared-start race challenge, not deterministic proof of both lock acquisition
orders or every interleaving. Source review separately checks the common mutex.

The historical receipt records the initial reviewer checkout execution. It stays
historical when adopted source undergoes Git line-ending conversion; raw catalog
hashes must never be silently replaced with later bytes. Integration execution and
browser receipts, if added later, have their own authority.

From the checkout containing this lab, prepare an overlay only if the candidate
still matches every exact catalog byte:

```powershell
$taskCandidateRoot = (Resolve-Path -LiteralPath '../restore-preview-integration').Path
python lab/native-restore-preview-review/prepare.py $taskCandidateRoot
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
& 'C:/Users/Administrator/Documents/Codex/2026-10-04/hi/scripts/go.ps1' test '-mod=readonly' '-overlay=.cache/native-restore-preview-review/prepared/overlay.json' '-count=1' '-timeout=90s' -json ./lab/native-restore-preview-review
```

The historical execution used the same 75 production source replacements at
`.cache/native-restore-preview-review/overlay.json`; the prepare helper exposes a
fresh reproducible path. All 83 catalog inputs include the frozen production Go,
module, CLI and UI bytes. Root's new spec/test files are outside this production
catalog and require separate execution evidence. No shared dependency writes or
downloads are authorized by these instructions; the primary wrapper's normal
shared Go compilation cache is allowed by the assigned batch.

Run the focused concurrency/four-kind case with `-race` only where the existing
compiler permits it. The receipt's race result is Windows CGO/gcc execution,
not a Linux or all-OS qualification. A first invocation failed before any tests
because PowerShell split the unquoted overlay option. Its raw output/status are
retained in ignored scratch and classified separately; corrected quoted commands
passed. Product source was not modified to resolve that invocation error.

Rollback is removal of the newly added lab files. Preview itself has no mutation
or recovery side effects; actual restore remains a separate revision-bound
operation which revalidates state. Private fixture keys/cookies stay in temporary
memory/files and are never printed or recorded in receipts.
