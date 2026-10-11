# Sifruno

Sifruno is a modern hosting-panel project with the original WHM/cPanel ecosystem compatibility contract. The approved V3 brand and local engineering panel are implemented. The hosting engine remains incomplete; this is not a production cPanel replacement.

Start with the [installation guide](docs/installation.md). The
[historical closeout](docs/CLOSEOUT.md) records the earlier delivered source
and unfinished work. Current progress is maintained in the project state below.

Before replacing the Windows server, use the [recovery guide](docs/server-recovery.md)
and [GitHub source/artifact backup](https://github.com/CodeWithJuber/sifruno/releases/tag/recovery-2026-10-11-v1).
It contains the Git history bundle, 130 recovery branches, screenshots, reports,
local artifacts, checksums and restore instructions. Secrets and runtime state
are excluded by the user's choice.

The [initial local source publication index](docs/local-source-publication.md) links
the preserved development history, uncommitted source snapshots and exact
coverage manifest published on 2026-10-11. Recovery branches retain unfinished
work and are not installation targets.

Use [the documentation index](docs/README.md) and [current project state](docs/PROJECT-STATE.md)
for the delivered source and remaining acceptance gates. Evidence below describes
recorded commits and isolated environments, not a fresh checkout test or current
deployment. Historical public preview URLs are not availability assurances.
Main includes the Accounts metadata-preview UI, broker/API/CLI web preview,
controller layout preparation and runtime input diagnostic. Preview metadata is
not applied configuration or serving health. The merged runtime-input guest
archive remains **non-runnable**: its parser is absent and approval is unresolved.
Development resumed on the user's 2026-10-07 instruction. The recurring loop uses
one focused delivery per run, existing dependencies, bounded implementation and
independent review. The [policy admission foundation](docs/access-policy-admission.md)
adds revision-aware authorization checks, and [trusted policy persistence](docs/access-policy-store.md)
stores validated bindings across restarts, checks permissions against a
versioned database snapshot and admits policy updates using current admin
permissions. A scoped projection returns only account IDs readable by the
authenticated actor. Production tenant integration remains open.

## Combined website workflow

The [native website lifecycle guide](docs/website-lifecycle-integration.md)
combines the reviewed PR62–67 features in one build: name editing, multiple-file
upload, saved-file preview, single-file backup restore, recovery as a separate
website and confirmed removal. The integrated browser flow passed with real
HTTP bytes and a retained backup download; desktop/mobile screenshots and exact
checks are linked in the guide. Follow the existing installation steps for this
branch. This source was merged through [PR #68](https://github.com/CodeWithJuber/sifruno/pull/68)
and is present in observed main `7425578`. No deployment was performed by the
source publication task.

## Community and Pro

Original Sifruno Community code uses [AGPL-3.0-only](LICENSE), with commercial
use permitted under its terms. Paid hosting, support and managed-service plans
can coexist with Community. A future Pro commercial license requires a separate
written agreement and sufficient rights to the covered code; this repository
does not grant that agreement. Third-party libraries, fonts, icons and tools
retain their own licenses. See [licensing and contribution policy](LICENSING.md).

## Local panel

Start with the numbered [source installation guide](docs/installation.md): install
Git, Node.js 24.19.0 and Go 1.27.1; install both locked npm dependency sets;
build the UI and binaries; then run the panel as an ordinary user on loopback
with dedicated private state. The guide covers Windows and manual Linux/macOS
builds, private sign-in, response/CLI checks, stopping and troubleshooting.
No automatic service installer or prebuilt release download is promised.

Open `http://127.0.0.1:8080`. The compact dashboard shows real CPU, memory, local volume capacity, uptime, network rates and service inventory. Actual Meta Astryx 0.6.5 components provide the sidebar, cards, buttons, progress bars, theme and time-range controls, alongside React/TypeScript/Tailwind and reused shadcn/Base UI tools. Search, service-state filters, details, pagination, mobile navigation and light/dark themes work. Compatibility, change trail, AI budget and platforms remain secondary tools. Go/Huma provides typed APIs; local `panelctl` commands operate recovery, budget and authenticated website workflows. See [commands and limitations](docs/workbench.md) and [dashboard design](docs/dashboard-design.md).

The Websites section manages actual app-owned static files: persisted sites, explicit file saves with revision/hash checks, suspend/resume, bounded ZIP backups and validated restores using scoped Ponytrail checkpoints. It requires the private operator key at `operator/access.key` beneath the chosen `--state` directory; open it privately on the server and never post it in chat. Signed/encrypted cookies and CSRF protect local writes. Static previews use `http://site-<id>.localhost:8082/`. Native Windows filesystem/API/CLI tests and isolated real browser workflows pass; Linux/macOS native execution remains unverified. It does not provision Linux users, PHP, DNS, TLS, mail or databases. Public monitoring previews hide Websites and block its APIs. See [website scope and evidence](docs/sites-slice.md).

Storage and Network have dedicated views backed by real collector values.
Private File Manager adds folder navigation, search, hash-checked UTF-8 editing,
nested new files and revision-conflict comparison for app-owned static sites.
Its [Upload file workflow](docs/site-file-upload.md) adds local static assets
(including images, fonts and PDFs) at a new relative path, with a 2 MiB file
limit and explicit revision checks. Existing paths are refused.
Select a saved file and use [Replace file](docs/site-file-replacement.md) to
confirm new content against its current hash and revision. A prior native ZIP
backup can restore the earlier content. [Single-file recovery](docs/single-file-restore.md)
lets you preview and restore one archived file while retaining the other saved
website files.
Websites shows [saved asset details](docs/website-assets.md) when a selected file
cannot be read as text, including when an image is the first or only file.
The [website workflow integration](docs/website-main-integration.md) carries
domain changes, selected-site navigation, ZIP recovery and these file actions
onto the main baseline while preserving its account-policy inventory.
Private Backups adds actual ZIP creation, hash-matched downloads and confirmed
restore with conflict handling. Historical isolated browser/API tests and actual
public HTTPS privacy checks pass at390/768/1440px in both themes. These private
tools require the local operator session and are excluded from the approved
public monitoring preview. See [File Manager](docs/file-manager-ui.md),
[Backups](docs/backups-ui.md) and [host resources](docs/host-resources.md).

Use [Recover as new website](docs/backup-copy.md) on a saved snapshot to prepare
its verified ZIP in the import form. Choose a new name/domain and confirm; the
original website keeps its current files and backups.

[Remove a native website](docs/website-removal.md) explicitly after exporting any
ZIPs you need to retain. Removal clears its current files and local snapshots,
keeps the audit history and releases the domain; unrelated websites are preserved.

[Edit a website display name](docs/website-name.md) in Websites without changing
its domain, files or backup contents. Conflicting changes require explicit review.

[Upload multiple static files](docs/multi-file-upload.md) from File Manager after
reviewing destinations and limits. Uploads are sequential, never overwrite and
stop on the first failure with explicit per-file results.

[Open a saved file](docs/saved-file-preview.md) directly from File Manager in
the local HTTP preview while keeping any unsaved editor draft.

The approved public dashboard now offers **Explore panel** on Overview and
**Panel preview** in navigation. Its Files, Backups and Websites tour uses
clearly labelled sample content with local selection/search only. It exposes
no customer files, operator login, write actions or private APIs. Six historical
HTTPS viewport/theme checks passed. See [public panel tour](docs/public-panel-preview.md).

The private **Access** page lists local operator sessions with confirmed
single/bulk revocation and sign-out. Historical isolated TCP/browser flows, replay
refusal, race tests and six responsive theme cases pass; public mode excludes
the page and session calls. This source is in main, with remote
roles/ingress still required. See [session controls](docs/operator-sessions.md).

Portable builds target Windows/Linux/macOS amd64/arm64: `npm run runtime:build`. Build verification and runtime qualification are separate. Historical systems remain connector/remote candidates, not guaranteed native targets. See [platform scope](docs/platform-support.md) and [archive contract](docs/runtime-builds.md).

Accounts adds an optional local Linux root broker, private operator UI/API and
authenticated CLI. It creates native identities, private primary groups, homes
and `public_html`, with locked passwords, `nologin`, revision-checked account
expiry and visible recovery. Actual disposable AlmaLinux9.8/XFS/SELinux Enforcing
execution passed creation, expiry/resume, broker restart, conflict and peer
admission checks. The fixture explicitly adapted NSS and mail-default policies;
stock zero-configuration Alma support is not qualified. Domain is metadata and
web/PHP/DNS/TLS/mail/databases remain required. Windows/macOS account brokers are
unavailable. See [operation guide](docs/hosting-accounts.md) and
[independent review](docs/hosting-accounts-review.md).

The next hosting layer contains a bounded Apache/PHP-FPM configuration compiler,
an account snapshot reservation and a persisted web-generation recovery library.
Independent snapshot/generation challenges pass against canonical source. The
generation library is not connected to production broker operations or public
API/CLI routes yet. Actual signed AlmaLinux Apache/PHP packages are installed in
a disposable guest; two-account static/PHP serving, identity/chroot, backend TLS
refusal and suspended-domain checks pass there. This remains separate from
production hosting activation and original compatibility. See
[generation protocol](docs/hostweb-generation.md) and
[native web evidence](docs/web-runtime-review.md).

The delivered source is `deliverables/sifruno-source.zip` with a file manifest and sibling SHA256. Source packaging excludes private state, tooling caches and dependencies and compares inputs locally against inherited credential values without printing them. Windows native archive verification is `node scripts/verify-runtime.mjs`; its report is `artifacts/runtime/native-windows.json`. Other OS archives remain build-verified only.

Native Sifruno v1 ZIP export/import uses the same authenticated API from the local UI and CLI. Imports create a new static site after full bounded validation; downloads retain the recorded backup hash. Original cPanel account restoration and migration remain unimplemented. A separate `panelctl backup inspect --from ORIGINAL.tar.gz --out NEW.jsonl` streams original-format TAR/gzip hashes and metadata for migration characterization, without extracting files or exposing their contents. See [native transfers](docs/native-transfers.md) and [original backup inspection](docs/cpanel-backup-inspection.md).

Development uses isolated Git worktrees for UI, CLI and review. The session permits four concurrent agents including the integrating root; the [twenty-four workstreams](docs/parallel-development.md) run in batches. This base checkout is connected to [CodeWithJuber/sifruno](https://github.com/CodeWithJuber/sifruno), with reviewed changes proposed on feature branches. Running private state is excluded from Git and source snapshots.

The [full delivery plan](docs/DELIVERY-PLAN.md) maps focused PR scopes to
service, compatibility, migration, vendor, AI, platform and release gates.
[Machine-readable status](docs/WORKSTREAM-STATUS.json) tracks evidence and
dependencies separately from implementation or qualification claims.

## Branding

Open `assets/brand/index.html` directly, or run `npm run brand:preview` and visit `http://127.0.0.1:4173`. Download `deliverables/sifruno-brand-kit.zip`. The ZIP includes the complete `assets` directory, brand guide and visual direction; keep that directory structure when extracting. The archive preview hides its self-download link when opened as a file.

The kit contains the original geometric S mark; three wordmark directions including the custom Sifruno Display logo lettering; light, dark, mono and two-color logos; SVG/PNG/ICO favicons; app icons; a social avatar, cover and typography/comparison sheets; Inter interface fonts; 12 reused Lucide interface icons; JSON/CSS tokens and usage guidance. The custom lettering contains the seven logo glyphs, not an installable full-alphabet font. Fonts and icon licenses are included. See `docs/brand-guidelines.md` for integration.

Regenerate and verify:

```powershell
npm ci --ignore-scripts --no-audit --no-fund
npm run brand:build
.\scripts\package-brand.ps1
npm run brand:check
npm run brand:browser-check
forge uicheck design assets/brand/index.html assets/brand/preview.css --taste editorial
```

Browser checks need Playwright's Chromium installed (`npx playwright install chromium`) or the matching existing browser cache. Asset checks verify export sizes, SVG outlines, ICO frame data, SHA-256, maskable-icon safe area and text contrast. Browser checks verify 1440px and 390px layouts, local images, real downloads, color copying, keyboard theme control and light/dark screenshots. Reports and screenshots are saved under `artifacts/brand/`.

## Engine implementation status

`config/baseline.json` records the targets and explicit unknowns. The initial 30-obligation inventory is incomplete; `internal/compat` reports every obligation untested. `internal/trail` implements encrypted scoped checkpoints, linked authenticated history, conflict-aware rollback and interrupted rollback recovery. Windows filesystem/ACL/concurrency tests pass; it is not a host backup or database journal. `internal/budget` provides process-safe $10 UTC-calendar reservations with expiring operation/revision-bound single-use approvals and corruption/reconciliation guards. No paid provider adapter is shipped by the workbench.

Actual packaged runtime slices have executed on Windows Server2025 and trusted Alpine3.24.2 amd64. The Alpine probe verifies synthetic TAR/gzip inspection, real telemetry, HTTP guards, private permissions and owned cleanup on tmpfs; independent Unix challenges passed. It does not qualify other Linux families, macOS, durable hosting or original vendor compatibility. See [Linux execution and tool reuse](docs/linux-guest-toolchain.md) and [independent review](docs/linux-runtime-review.md).

The first original-hosting targets remain AlmaLinux 9 / CloudLinux 9 x86_64 on a fresh server, followed by a 100-account pilot. Existing API/CLI clients, original installers, plugins, hooks, paths and WHMCS cPanel integrations must work with zero compatibility-related user edits. Existing hosting daemons, SDKs and tools are reused where they match observable behavior.

Full compatibility cannot be certified from these open source repositories. The next external evidence required is a disposable Linux test host with legitimately licensed cPanel and the seven launch-vendor test environments: WHMCS, Cloudflare, CloudLinux, LiteSpeed, JetBackup, Softaculous and Imunify360. Pin the exact cPanel build, OS, packages, enabled features and artifact hashes before differential testing. Current reference fields intentionally remain empty and unverified. The limited native account broker does not implement the original hosting account/runtime contract.

`internal/evidence` and `lab/` implement bounded hash-checked bundles, a fixed read-only Linux collector and differential comparison. Two synthetic fixtures produce one match and one detected difference; neither certifies compatibility.

REA 3.2.1 is pinned for artifact investigation. Official Ghidra 12.1.4 and Temurin JDK 21 are installed locally with verified archive SHA256s and actual headless launch evidence. Analysis children use a credential-free environment and workspace-local homes/cache/temp. `npm run tools:doctor` records the upstream Windows batch-probe defect; `npm run tools:analyze -- bin/panelctl.exe` still fails closed because REA has not implemented its required Windows native isolation controls. All eight installation checks pass; provider availability and compatibility remain separate. No cPanel artifact analysis has run. See [analysis setup and limits](docs/analysis-tools.md). `Awesome-Hacking` is a resource index, not a hosting implementation.

A separate owned-artifact Ghidra smoke successfully imported the package-hash-matched `panelctl.exe` and exported static function/instruction/data counts. Go 1.27 metadata warnings make this partial coverage. It proves an actual owned-artifact investigation ran, while REA isolation and product compatibility remain unverified.

User requested JEV proposals for routine technical choices. Forgekit/Hikmah adapters exist, but the checked environment has no callable JEV MCP or TypeSafe credential. A prepared question batch is not a model answer; see `docs/jev-decisions.md`.

Before product release, implement and verify the complete inventory, privileged broker authorization and containment, original runtime structures, account/reseller lifecycle, hosting services, faithful backups/restores/migrations, vendor integrations, upgrade rollback and the pilot. AI changes require operator approval and a combined $10/calendar-month paid AI/JEV cap. The brand kit makes no compatibility claim.
