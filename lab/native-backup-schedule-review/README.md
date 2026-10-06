# Independent native static-site schedule challenges

Scope: actual isolated `sites.Store`, trail and operator/API handlers, against
the frozen candidate source. All mutable state belongs to `testing.T.TempDir`.
No live state/listener, shared dependency write, provider request or native
daemon activation is part of this lab. The feature is native Sifruno static
site backup scheduling, not a cPanel archive or whole-host scheduler.

## Acceptance design

- Exact schedule/envelope fields, three interval presets, UTC metadata and
  independent site/schedule revisions; absence, disabled runner and paused
  schedules remain distinguishable.
- GET/PUT actual local cookie admission, CSRF/Origin/peer/Host refusals,
  strict field/body types, duplicate and case aliases, unexpected properties,
  invalid IDs and stale revisions, without unintended mutation.
- Due boundaries and concurrent calls create one archive per consumed due
  point; long overdue schedules do not create a catch-up batch. Pausing and
  schedule edits serialize with a run through the same store lock.
- Close/open persistence and reserved-ID recovery: exact committed archive
  revision/hash adopts once, interrupted work pauses without automatic retry;
  unrelated/manual archive and malformed state cannot stand in for proof.
- Existing archive count/storage capacity remains enforced without deletion;
  failed or corrupted archives are never reported as a completed run.
- Exact source/hash catalog and full machine-readable actual commands/exits
  bind evidence to the candidate. Compilation, synthetic durable-state
  challenges, actual Store/API execution and later browser evidence remain
  separate authorities.

The frozen source passed 61 named tests (11 top-level tests), with no failures
or skips, on Windows. Three concurrency/cancellation tests also passed with
CGO/gcc race instrumentation; the focused lab vet passed. Exact commands,
exit statuses, source pins and raw-output hashes are in [acceptance.json](acceptance.json)
and [source-catalog.json](source-catalog.json). No failed actual challenge
attempt preceded these results.

Tests used actual isolated Store/API handlers and real ZIP bytes. Pending,
corrupt and untracked archive states were deliberately seeded synthetic
fixtures. Exact committed bytes were adopted once; proven current absence
closed an interrupted run while remaining paused. Unprovable archive outcomes
retained the exact stopped marker across reopen and refused an unsafe edit.
This does not prove historical nonexecution or an observed process crash.

Test commands use the primary
`scripts/go.ps1`, reviewer working directory, `GOPROXY=off`, `GOSUMDB=off`,
`-mod=readonly` and a bounded timeout. An immutable reviewer-owned 35-file Go
overlay admitted candidate source without editing implementation files. All
37 catalogued source/module hashes remained unchanged after test/vet/race.
The catalog includes main/CLI source reviewed as source only; these binaries
were not executed by this lab. UI commits e1a20b4 and 0cfa09b received a
read-only lifecycle/DTO review; their worker checks and future browser evidence
have separate authority.

The actual archive-count limit and retained byte hashes were challenged. The
128 MiB storage bound was reviewed in source; this lab did not fill that bound.

Recovery: revert this lab directory. Test cleanup closes owned stores before
temporary directories are removed; any cleanup failure is a failed test.
No all-OS, native service lifecycle or original compatibility acceptance
follows from portable Store/API tests.

Forge preflight was invoked before authoring. It reported unknown impact and
missing exact IO; the root's explicit route/DTO/recovery contract supplies
that information. Impact analysis is advisory, not acceptance evidence.
