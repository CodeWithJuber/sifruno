# Sifruno

Sifruno is a modern hosting-panel project with the original WHM/cPanel ecosystem compatibility contract. The approved V3 brand and local engineering panel are implemented. The hosting engine remains incomplete; this is not a production cPanel replacement.

## Local panel

```powershell
npm run panel:build
./scripts/go.ps1 build -buildvcs=false -o bin/sifruno.exe ./cmd/sifruno
./scripts/go.ps1 build -buildvcs=false -o bin/panelctl.exe ./cmd/panelctl
./bin/sifruno.exe --listen 127.0.0.1:8080 --state .state/sifruno --ui web/dist
```

Open `http://127.0.0.1:8080`. The compact dashboard shows real CPU, memory, local volume capacity, uptime, network rates and service inventory. Actual Meta Astryx 0.6.5 components provide the sidebar, cards, buttons, progress bars, theme and time-range controls, alongside React/TypeScript/Tailwind and reused shadcn/Base UI tools. Search, service-state filters, details, pagination, mobile navigation and light/dark themes work. Compatibility, change trail, AI budget and platforms remain secondary tools. Go/Huma provides typed APIs; local `panelctl` commands operate recovery, budget and authenticated website workflows. See [commands and limitations](docs/workbench.md) and [dashboard design](docs/dashboard-design.md).

The new Websites section manages actual app-owned static files: persisted sites, explicit file saves with revision/hash checks, suspend/resume, bounded ZIP backups and validated restores using scoped Ponytrail checkpoints. It requires the private operator key at `.state/sifruno/operator/access.key`; open it privately on the server and never post it in chat. Signed/encrypted cookies and CSRF protect local writes. Static previews use `http://site-<id>.localhost:8082/`. Native Windows filesystem/API/CLI tests and isolated real browser workflows pass; Linux/macOS native execution remains unverified. It does not provision Linux users, PHP, DNS, TLS, mail or databases. Public monitoring previews hide Websites and block its APIs. See [website scope and evidence](docs/sites-slice.md).

Portable builds target Windows/Linux/macOS amd64/arm64: `npm run runtime:build`. Build verification and runtime qualification are separate. Historical systems remain connector/remote candidates, not guaranteed native targets. See [platform scope](docs/platform-support.md) and [archive contract](docs/runtime-builds.md).

The delivered source is `deliverables/sifruno-source.zip` with a file manifest and sibling SHA256. Source packaging excludes private state, tooling caches and dependencies and compares inputs locally against inherited credential values without printing them. Windows native archive verification is `node scripts/verify-runtime.mjs`; its report is `artifacts/runtime/native-windows.json`. Other OS archives remain build-verified only.

Native Sifruno v1 ZIP export/import uses the same authenticated API from the local UI and CLI. Imports create a new static site after full bounded validation; downloads retain the recorded backup hash. Original cPanel backups and account migration remain unsupported. See [transfer contract](docs/native-transfers.md).

Development now uses isolated Git worktrees for UI, CLI and review. The session permits four concurrent agents including the integrating root; the [twenty-four workstreams](docs/parallel-development.md) run in batches. No Git remote or publication is configured, and running private state is excluded from source snapshots.

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

The first original-hosting targets remain AlmaLinux 9 / CloudLinux 9 x86_64 on a fresh server, followed by a 100-account pilot. Existing API/CLI clients, original installers, plugins, hooks, paths and WHMCS cPanel integrations must work with zero compatibility-related user edits. Existing hosting daemons, SDKs and tools are reused where they match observable behavior.

Full compatibility cannot be certified from these open source repositories. The next external evidence required is a disposable Linux test host with legitimately licensed cPanel and the seven launch-vendor test environments: WHMCS, Cloudflare, CloudLinux, LiteSpeed, JetBackup, Softaculous and Imunify360. Pin the exact cPanel build, OS, packages, enabled features and artifact hashes before differential testing. Current reference fields intentionally remain empty and unverified. No hosting account lifecycle or privileged broker is shipped yet.

`internal/evidence` and `lab/` implement bounded hash-checked bundles, a fixed read-only Linux collector and differential comparison. Two synthetic fixtures produce one match and one detected difference; neither certifies compatibility.

REA 3.2.1 is pinned for artifact investigation. Official Ghidra 12.1.4 and Temurin JDK 21 are installed locally with verified archive SHA256s and actual headless launch evidence. Analysis children use a credential-free environment and workspace-local homes/cache/temp. `npm run tools:doctor` records the upstream Windows batch-probe defect; `npm run tools:analyze -- bin/panelctl.exe` still fails closed because REA has not implemented its required Windows native isolation controls. All eight installation checks pass; provider availability and compatibility remain separate. No cPanel artifact analysis has run. See [analysis setup and limits](docs/analysis-tools.md). `Awesome-Hacking` is a resource index, not a hosting implementation.

A separate owned-artifact Ghidra smoke successfully imported the package-hash-matched `panelctl.exe` and exported static function/instruction/data counts. Go 1.27 metadata warnings make this partial coverage. It proves an actual owned-artifact investigation ran, while REA isolation and product compatibility remain unverified.

User requested JEV proposals for routine technical choices. Forgekit/Hikmah adapters exist, but the checked environment has no callable JEV MCP or TypeSafe credential. A prepared question batch is not a model answer; see `docs/jev-decisions.md`.

Before product release, implement and verify the complete inventory, privileged broker authorization and containment, original runtime structures, account/reseller lifecycle, hosting services, faithful backups/restores/migrations, vendor integrations, upgrade rollback and the pilot. AI changes require operator approval and a combined $10/calendar-month paid AI/JEV cap. The brand kit makes no compatibility claim.
