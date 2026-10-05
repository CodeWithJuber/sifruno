# Independent hostweb generation review

This review uses only isolated temporary state and pinned source.
No native daemon, account, public endpoint or running state is activated or
changed. Injected native systems and executors are protocol test doubles;
passing these tests does not qualify Apache/PHP isolation or activation.

Acceptance challenges:

- Snapshot reservation excludes broker mutations, rejects pending/recovery
  state, and detects native identity drift without relying only on revisions.
- Callback cancellation and reentry have explicit behavior; a callback that
  ignores its context must not be described as safely preemptible.
- Plans require exact profile, bundle, snapshot, generation and revision CAS.
- Pending intent survives a close/reopen. A failed executor or failed
  observation cannot be silently marked committed or replayed.
- Recovery observes current state first. It cannot overwrite an unexpected
  third-party generation, and cannot restore a prior active snapshot after a
  suspension or identity change.
- State files reject unsafe paths, identities and modes at the platform's
  supported boundary. Hash validation is distinct from ownership validation.
- A post-callback snapshot failure cannot leave a falsely clean generation
  ledger. Observed commit and uncertain execution remain distinguishable.

## Observed results

Eight account snapshot challenges passed against the integrated canonical
source (Go package time 0.964s, exit 0):
defensive copy and expired lease, cancellation and callback error, scoped
reentry, concurrent broker mutation exclusion, late native drift quarantine,
pending operation rejection, damaged durable history rejection, and a shorter
caller deadline during native verification.

Nine generation challenges passed against the integrated canonical source
(Go package time 1.006s, exit 0): full CAS
and replay rejection, partial failure plus close/reopen and changed-snapshot
denied recovery, unknown observation refusal, late provider failure quarantine
after observed commit, copied executor inputs, state-only ledger corruption,
executor-time journal damage, generation count exhaustion before execution,
and an actual Windows filesystem hardlink rejected before the provider runs.

After canonical integration, run from the repository root:

```powershell
& .\scripts\bootstrap-tools.ps1
& .\lab\hostweb-generation-review\run.ps1 -SourceRoot (Get-Location).Path -Package hostaccounts
& .\lab\hostweb-generation-review\run.ps1 -SourceRoot (Get-Location).Path -Package hostwebgeneration
```

Bootstrap installs the pinned Go toolchain in the primary checkout and checks
its archive hash. It needs network access when that toolchain is absent. A fresh
checkout must include its tracked Go source, go.mod/go.sum, scripts, and review
testdata; no operator state, keys, global tools or credentials are needed.

The runner derives the primary checkout from its verified
`lab/hostweb-generation-review` location. If located under `.worktrees`, only
`native-transfer-review` is admitted and its fixed parent layout identifies the
primary checkout. Primary, runner and source roots must each have the bounded
`module sifruno` identity in go.mod. Root, input, wrapper, tool and ancestor
paths reject reparse points. There is no PrimaryRoot or ScriptRoot override.

SourceRoot accepts only primary, `.worktrees/native-transfer-ui`, or
`.worktrees/native-transfer-cli` relative to that derived primary. Artifacts
follow the runner location: canonical execution writes canonical `artifacts`,
review execution writes review `artifacts`. Both review packages can also run
from a matching review-worktree checkout using its reviewed copy of this runner:

```powershell
# From <primary>/.worktrees/native-transfer-review:
$reviewPrimary = (Resolve-Path ..\..).Path
& .\lab\hostweb-generation-review\run.ps1 -SourceRoot $reviewPrimary -Package hostaccounts
& .\lab\hostweb-generation-review\run.ps1 -SourceRoot $reviewPrimary -Package hostwebgeneration
```

To check a relocated layout without executing Go or creating test artifacts:

```powershell
& .\lab\hostweb-generation-review\run.ps1 -SourceRoot (Get-Location).Path -Package hostaccounts -CheckLayout
```

This read-only mode verifies root derivation, source admission, module identity,
required wrapper/bootstrap files, package directory and challenge input. Its
JSON reports `execution: false`; it does not qualify source compilation or
bootstrap. It admits the same fixed source roots and adds no execution-root
parameter. Full runs require the primary pinned toolchain and still invoke only
the verified relative scripts/go.ps1.

The unchanged challenge source files live in `testdata/`; normal Go package
discovery ignores that directory. `scripts/go.ps1 list
./lab/hostweb-generation-review/...` exited 0 with "matched no packages" after
the move, so these different test packages do not enter `go test ./...`.

Current reports relative to the review worktree:

- `artifacts/hostweb-generation-review/20261005T042733549-c022c6ac-hostaccounts/report.json`
  SHA256 `0772fb29007c1a0415f42cb85b3b23a8ab34f940e0eb7a9cf5c7b29593fbac4c`.
- `artifacts/hostweb-generation-review/20261005T042733556-9bda0301-hostwebgeneration/report.json`
  SHA256 `8300c2141a9eb8ea127c4318a56b9e144c3633d16be29dabbf1accdf43dc8bcb`.

Every canonical Go source hash remained unchanged during each run. Worker
source runs overlay and pin the canonical account/securestate dependencies and
compiler; canonical source runs use the integrated packages directly. The
current compiler SHA256 is
`8ee9eabd9c39e8b53b19d62e0f8b794af72f02bea89d5e932496e1a5a83ee17b`.
Snapshot source SHA256 is
`16c17754793c8255bd5869253ae194892fd779e8668333d9abda6ee19f1961cb`;
store SHA256 is
`689d4c75be7c13e67dac2e051fd4fe75cf55d7801d0fdb44a4988de0ab13dd43`.
The report manifests contain each individual source pin. Overlays inject
review-owned tests and read-only canonical dependencies; worker source
directories and Git indexes remain unchanged. Earlier worker-source reports
remain available under run IDs `20261005T041430313-f7451c8a-hostaccounts` and
`20261005T041958537-70be50f4-hostwebgeneration`.

## Portable runner verification

After replacing the machine-specific root with verified relative derivation,
both canonical reviews passed again with unchanged source pins:

- Eight account challenges, package time 1.065s, exit 0:
  `artifacts/hostweb-generation-review/20261005T044921090-3aa05acb-hostaccounts/report.json`,
  SHA256 `2e593baffa2f0c5595e07e4da83d8b4ac960d0f323306edafe88e796aedc4846`.
- Nine generation challenges, package time 0.993s, exit 0:
  `artifacts/hostweb-generation-review/20261005T044925211-5578ee08-hostwebgeneration/report.json`,
  SHA256 `5acccad20cad7136b5dd0148577f3a124216d3f7554638d225b32fd64d9c4874`.

A separate fresh layout under ignored artifacts copied only public runner,
challenge inputs, go.mod and wrapper/bootstrap scripts. Its ten admission
probes passed: canonical relocation, fixed review worktree, UI/CLI source roots,
rejection of another runner worktree, review-as-source, foreign source, wrong
module, unexpected lab location and an actual Windows junction ancestor.
The relocated layout contained no toolchain, private state or secrets; every
successful probe reported execution false. This proves layout derivation and
admission, not a fresh network bootstrap or compilation there.

The local report is
`artifacts/hostweb-generation-review/portability-96b45ed5/portability-report.json`,
SHA256 `36e6546903a77cca14ec8d937978264998a7a40b658b4b8908c89068c1d23dea`.
Its source runner SHA256 equals its freshly copied runner SHA256:
`c9387590096ca6adf2656e7861d996ed481a6b4af787e7f4d2fc3f1d06b84cc5`.
The owned probe junction was removed without deleting its target. Reverting
this runner and README is the recovery path; there is no persistent account,
generation or production operation from the layout probe.

## Limits and recovery boundary

These runs use real temporary Bolt databases, real file links, and injected
native/account/runtime doubles. Test state uses `testing.T.TempDir` cleanup.
The crash challenge is a failed transition followed by close/reopen, rather
than killing a process during a filesystem or Bolt sync. Only the generation
count storage bound is independently saturated; the 128-event and 512MiB
database bounds are not saturation-qualified by this review.

Unix root ownership/modes, trusted immutable ancestors, broker integration,
native daemon activation, serving isolation, SELinux, reload/reboot durability,
and killing owned processes on cancellation remain separate qualifications.
The callback and mutex wait are cooperative; unrelated captured contexts can
still deadlock on reentry. External root edits cannot be excluded by the broker
mutex. A broker identity recovery state may prevent a generation recovery lease.

Within the reviewed library, failed transitions retain durable pending state,
block new plans/applies, and require explicit operation/revision recovery. The
fresh observation must be known, and stale active snapshots cannot be restored
after an account snapshot change. There is no state reset/pruning, activation,
or production rollback operation in this review harness.
