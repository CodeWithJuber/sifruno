# Sifruno documentation index

This index covers every tracked Markdown document in the source tree, including older delivery notes, module references and frozen test-fixture copies. Start with installation and current project state; historical receipts are evidence for their recorded source and environment, not a claim about a live installation.

The 2026-10-07 reconciliation inspected main `f4735ccd10c2d9443d9c62eaafceb86f5a6d9dea`. All 45 repository PRs were observed merged to their recorded targets. The [PR history](PR-HISTORY.md) preserves that dated snapshot and distinguishes target merges from direct main ancestry and later source carries. The user subsequently resumed development after main `bf95edf`; current delivery and remaining gates are in project state.

## How to read status and evidence

- [Current project state](PROJECT-STATE.md) governs the present handoff and remaining acceptance gates. [Machine-readable status](WORKSTREAM-STATUS.json) keeps current publication fields separate from historical observations.
- [Installation](installation.md) is a source-build/local-panel guide, not a production hosting installer. Commands were reviewed against source; a new clean-machine installation was not run for this update.
- The delivery plan's `pr-*` IDs identify planned scopes, not GitHub PR numbers. A merge does not certify a scope, a vendor, an operating system or a deployment.
- `docs/evidence/*.json` and dated guide sections retain original source pins and failed/successful outcomes. Local-only `artifacts/`, `.cache/` and worktree paths are provenance, not downloadable files. Their private contents are excluded from Git.
- The merged [runtime-input guest archive](../lab/runtime-input-guest/README.md) is **non-runnable WIP**. Its missing parser and unresolved approval remain open. Historical preview URLs have no current availability assurance.

## Start here and delivery planning

| Guide | File |
| --- | --- |
| [Install and run from source](installation.md) | `installation.md` |
| [Sifruno delivery state](PROJECT-STATE.md) | `PROJECT-STATE.md` |
| [Sifruno delivery plan](DELIVERY-PLAN.md) | `DELIVERY-PLAN.md` |
| [Website workflow main integration](website-main-integration.md) | `website-main-integration.md` |
| [Parallel development](parallel-development.md) | `parallel-development.md` |
| [Development closeout — 7 October 2026](CLOSEOUT.md) | `CLOSEOUT.md` |
| [Server monitoring and local workbench](workbench.md) | `workbench.md` |
| [JEV decision preparation](jev-decisions.md) | `jev-decisions.md` |

## Interface and approved brand

| Guide | File |
| --- | --- |
| [Sifruno server dashboard](dashboard-design.md) | `dashboard-design.md` |
| [Sifruno](brand-guidelines.md) | `brand-guidelines.md` |
| [Hosting workspace UI](hosting-workspace-ui.md) | `hosting-workspace-ui.md` |
| [Accounts workflow](accounts-workflow.md) | `accounts-workflow.md` |
| [Accounts web configuration preview](accounts-web-preview.md) | `accounts-web-preview.md` |
| [Accounts preview delivery to main](accounts-preview-main.md) | `accounts-preview-main.md` |
| [Website inventory and workflow](websites-workflow.md) | `websites-workflow.md` |
| [Private static-site File Manager](file-manager-ui.md) | `file-manager-ui.md` |
| [Download a saved website file](site-file-download.md) | `site-file-download.md` |
| [Rename or move a saved website file](site-file-rename.md) | `site-file-rename.md` |
| [Private website backups](backups-ui.md) | `backups-ui.md` |
| [Public panel tour](public-panel-preview.md) | `public-panel-preview.md` |

## Accounts, sessions and installation boundaries

| Guide | File |
| --- | --- |
| [Native Linux account operations](hosting-accounts.md) | `hosting-accounts.md` |
| [Hosting account privilege review](hosting-accounts-review.md) | `hosting-accounts-review.md` |
| [Storage and network views](host-resources.md) | `host-resources.md` |
| [Local Access and sessions](operator-sessions.md) | `operator-sessions.md` |
| [Revisioned account-policy admission](access-policy-admission.md) | `access-policy-admission.md` |
| [Trusted account-policy persistence and durable admission](access-policy-store.md) | `access-policy-store.md` |
| [Account mutation session admission](account-session-admission.md) | `account-session-admission.md` |
| [Site request session admission](site-session-admission.md) | `site-session-admission.md` |
| [Native account host-policy admission](stock-account-preflight.md) | `stock-account-preflight.md` |
| [Native broker startup path admission](broker-path-admission.md) | `broker-path-admission.md` |
| [Managed service accounts without rewriting mail defaults](service-account-mail-policy.md) | `service-account-mail-policy.md` |
| [Read-only broker startup preflight](broker-startup-preflight.md) | `broker-startup-preflight.md` |
| [Fresh controller directory layout](controller-layout.md) | `controller-layout.md` |
| [Local controller layout CLI](controller-layout-cli.md) | `controller-layout-cli.md` |
| [Hostsetup delivery on main](hostsetup-main-delivery.md) | `hostsetup-main-delivery.md` |

## Static websites, backups and transfer

| Guide | File |
| --- | --- |
| [Working website slice](sites-slice.md) | `sites-slice.md` |
| [Native static-site transfers](native-transfers.md) | `native-transfers.md` |
| [Local static-file upload](site-file-upload.md) | `site-file-upload.md` |
| [Confirmed file replacement](site-file-replacement.md) | `site-file-replacement.md` |
| [Binary assets in Websites](website-assets.md) | `website-assets.md` |
| [Native Sifruno transfer review](native-transfer-review.md) | `native-transfer-review.md` |
| [Native static-site backup schedules](native-backup-schedules.md) | `native-backup-schedules.md` |
| [Native restore preview](native-restore-preview.md) | `native-restore-preview.md` |
| [Restore an existing website from an uploaded ZIP](uploaded-zip-restore.md) | `uploaded-zip-restore.md` |
| [Original backup characterization for migration](cpanel-backup-inspection.md) | `cpanel-backup-inspection.md` |
| [Independent review: original backup characterization](cpanel-backup-review.md) | `cpanel-backup-review.md` |

## Native web runtime and qualification

| Guide | File |
| --- | --- |
| [Web runtime plan for managed Linux accounts](web-runtime-plan.md) | `web-runtime-plan.md` |
| [Native hostweb compiler review and runtime fixture](web-runtime-review.md) | `web-runtime-review.md` |
| [Hostweb snapshot and generation protocol](hostweb-generation.md) | `hostweb-generation.md` |
| [Hostweb activation and native lifecycle review](hostweb-activation-review.md) | `hostweb-activation-review.md` |
| [Native web runtime candidate](native-web-runtime.md) | `native-web-runtime.md` |
| [Native executor serving evidence](native-web-serving.md) | `native-web-serving.md` |
| [Native web qualification tools](native-web-qualification.md) | `native-web-qualification.md` |
| [Explicit denied runtime repair](native-web-recovery.md) | `native-web-recovery.md` |
| [Native controller-death and reopened-child recovery](native-web-crash-recovery.md) | `native-web-crash-recovery.md` |
| [Native Apply completion and counter recovery](native-apply-checkpoint.md) | `native-apply-checkpoint.md` |
| [Recovery snapshot guard](web-recovery-snapshot.md) | `web-recovery-snapshot.md` |
| [Native web configuration preview](native-web-preview.md) | `native-web-preview.md` |
| [Populated native web-preview composition](native-web-preview-composition.md) | `native-web-preview-composition.md` |
| [Check native web runtime installation inputs](web-runtime-input-check.md) | `web-runtime-input-check.md` |

## Platforms, reusable tooling and source checks

| Guide | File |
| --- | --- |
| [Sifruno platform contract](platform-support.md) | `platform-support.md` |
| [Portable runtime build contract](runtime-builds.md) | `runtime-builds.md` |
| [Linux hostsetup runtime packages](runtime-hostsetup-package.md) | `runtime-hostsetup-package.md` |
| [Disposable Linux guest toolchain (Windows workspace-local)](linux-guest-toolchain.md) | `linux-guest-toolchain.md` |
| [Disposable Linux runtime independent review](linux-runtime-review.md) | `linux-runtime-review.md` |
| [Artifact investigation](analysis-tools.md) | `analysis-tools.md` |
| [Reusable edge, terminal and build candidates](edge-stack-evaluation.md) | `edge-stack-evaluation.md` |
| [PR source checks](source-checks.md) | `source-checks.md` |

## Historical main reconciliation

| Guide | File |
| --- | --- |
| [Main merge history and documentation reconciliation](main-promotion.md) | `main-promotion.md` |
| [Main source reconciliation](main-source-reconciliation.md) | `main-source-reconciliation.md` |

## Repository and implementation references

These describe local development, licensing, architecture or historical UI review. Installation remains the entry point for running the panel.

- [AGENTS.md](../AGENTS.md) — Sifruno development
- [DESIGN.md](../DESIGN.md) — Sifruno visual direction
- [LICENSING.md](../LICENSING.md) — Sifruno Community and Pro licensing
- [README.md](../README.md) — Sifruno
- [design-qa.md](../design-qa.md) — Accounts preview design QA
- [internal/accesspolicy/README.md](../internal/accesspolicy/README.md) — Native hosting account access policy foundation
- [internal/accesspolicy/store.md](../internal/accesspolicy/store.md) — Trusted policy binding persistence
- [internal/hostaccounts/README.md](../internal/hostaccounts/README.md) — Native Linux account foundation
- [internal/hostweb/README.md](../internal/hostweb/README.md) — Native hostweb compiler
- [internal/hostwebgeneration/README.md](../internal/hostwebgeneration/README.md) — Unactivated web generation coordinator
- [internal/hostwebruntime/README.md](../internal/hostwebruntime/README.md) — Unactivated Linux web runtime executor
- [scripts/mobile-preview.md](../scripts/mobile-preview.md) — Temporary Sifruno mobile HTTPS preview
- [web/NOTICE.md](../web/NOTICE.md) — Reused UI sources and assets
- [web/README.md](../web/README.md) — Sifruno server panel UI

## Lab and review references

These are characterization, isolated qualification or source-review tools with their own prerequisites and limits. Listing a harness does not mean it ran on current main or authorize its execution. In particular, the runtime-input archive remains blocked and non-runnable.

- [lab/README.md](../lab/README.md) — Disposable characterization lab
- [lab/broker-paths-guest/README.md](../lab/broker-paths-guest/README.md) — ADAPTED disposable broker-path observation
- [lab/broker-paths-review/README.md](../lab/broker-paths-review/README.md) — Independent broker startup-path review
- [lab/hostweb-apply-review/README.md](../lab/hostweb-apply-review/README.md) — Independent native Apply completion review
- [lab/hostweb-generation-review/README.md](../lab/hostweb-generation-review/README.md) — Independent hostweb generation review
- [lab/hostweb-lifecycle-review/review.md](../lab/hostweb-lifecycle-review/review.md) — Frozen hostweb lifecycle review
- [lab/hostweb-recovery-review/README.md](../lab/hostweb-recovery-review/README.md) — Independent web recovery review
- [lab/hostweb-review/README.md](../lab/hostweb-review/README.md) — Hostweb independent challenges
- [lab/hostwebruntime-crash-driver/README.md](../lab/hostwebruntime-crash-driver/README.md) — Disposable native controller-death driver
- [lab/hostwebruntime-crash-host/README.md](../lab/hostwebruntime-crash-host/README.md) — Disposable controller-death qualification
- [lab/hostwebruntime-crash-review/README.md](../lab/hostwebruntime-crash-review/README.md) — Independent controller-death lab review
- [lab/hostwebruntime-crash-review/review.md](../lab/hostwebruntime-crash-review/review.md) — Independent review receipt, source and synthetic stage
- [lab/hostwebruntime-mechanics/README.md](../lab/hostwebruntime-mechanics/README.md) — Disposable Linux runtime mechanics
- [lab/hostwebruntime-review/README.md](../lab/hostwebruntime-review/README.md) — Independent native executor challenges
- [lab/hostwebruntime-serving-guest/README.md](../lab/hostwebruntime-serving-guest/README.md) — Prepared Alma9 serving guest fixture
- [lab/hostwebruntime-serving-host/README.md](../lab/hostwebruntime-serving-host/README.md) — Disposable native-runtime serving host gate
- [lab/hostwebruntime-serving/README.md](../lab/hostwebruntime-serving/README.md) — Disposable native executor serving qualification
- [lab/linuxruntime/README.md](../lab/linuxruntime/README.md) — Disposable Linux guest runtime qualification
- [lab/native-backup-schedule-review/README.md](../lab/native-backup-schedule-review/README.md) — Independent native static-site schedule challenges
- [lab/native-restore-preview-review/README.md](../lab/native-restore-preview-review/README.md) — Independent native static-site restore preview challenges
- [lab/native-web-preview-guest/README.md](../lab/native-web-preview-guest/README.md) — Offline populated native preview composition
- [lab/operator-session-review/README.md](../lab/operator-session-review/README.md) — Independent operator session review
- [lab/runtime-input-guest/README.md](../lab/runtime-input-guest/README.md) — WIP archive: native runtime input guest
- [lab/runtime-input-review/README.md](../lab/runtime-input-review/README.md) — Preserved independent test-log checks
- [lab/service-accounts-guest/README.md](../lab/service-accounts-guest/README.md) — NSS-only adapted service-account guest fixture
- [lab/service-accounts-review/README.md](../lab/service-accounts-review/README.md) — Independent managed-service account core review
- [lab/startup-preflight-guest/README.md](../lab/startup-preflight-guest/README.md) — Offline startup preflight fixture
- [lab/startup-preflight-isolation-review/README.md](../lab/startup-preflight-isolation-review/README.md) — Restricted corrected fixture review
- [lab/startup-preflight-review/README.md](../lab/startup-preflight-review/README.md) — Independent startup preflight review
- [lab/stock-policy-guest/README.md](../lab/stock-policy-guest/README.md) — Disposable stock-policy observation
- [lab/stock-policy-review/README.md](../lab/stock-policy-review/README.md) — Independent native host-policy review

## Frozen fixture documentation

The following copies belong to recorded test inputs. They are intentionally preserved, not current setup instructions; their assertions apply only to the fixture source they accompany.

- [lab/hostweb-apply-review/testdata/candidate/internal/hostwebgeneration/README.md](../lab/hostweb-apply-review/testdata/candidate/internal/hostwebgeneration/README.md)
- [lab/hostweb-apply-review/testdata/candidate/internal/hostwebruntime/README.md](../lab/hostweb-apply-review/testdata/candidate/internal/hostwebruntime/README.md)
- [lab/hostweb-recovery-review/testdata/candidate/internal/hostwebgeneration/README.md](../lab/hostweb-recovery-review/testdata/candidate/internal/hostwebgeneration/README.md)
- [lab/hostweb-recovery-review/testdata/candidate/internal/hostwebruntime/README.md](../lab/hostweb-recovery-review/testdata/candidate/internal/hostwebruntime/README.md)
- [lab/hostwebruntime-review/testdata/candidate/README.md](../lab/hostwebruntime-review/testdata/candidate/README.md)

The inventory contains 115 Markdown files, including this index and PR history.
All are linked here; this index is the only self-entry omitted. Stable technical
contracts and historical receipts retain their original verification scope.
