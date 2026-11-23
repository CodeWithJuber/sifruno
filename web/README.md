# Sifruno server panel UI

For prerequisites and a complete source build, use the [installation guide](../docs/installation.md).
The [documentation index](../docs/archive/README.md) covers each UI workflow and its
historical evidence. Current publication and remaining acceptance gates are in
[project state](../docs/archive/PROJECT-STATE.md); no live preview is certified here.

React 19, TypeScript, Vite and Tailwind render the approved V3 Sifruno identity with local Inter fonts. The dashboard reuses actual Meta Astryx 0.6.5 components: Button, Card, SideNav, SegmentedControl, ProgressBar and the precompiled neutral Theme. Secondary tools retain official shadcn source and Base UI primitives. See NOTICE.md for source and license attribution.

```powershell
cd web
npm ci --ignore-scripts --no-audit --no-fund
npm run dev
```

Vite binds to `127.0.0.1:5173` and proxies `/api` to the local Go service at `127.0.0.1:8080`. `npm run build` produces `web/dist`, served by that Go service at the same origin. Canonical `assets/brand` assets are copied by `npm run sync:brand` before builds. No deployment occurs in this build command.

| Read-only route | View |
| --- | --- |
| `GET /api/v1/server?range_seconds=60` | Real CPU, memory, storage, uptime and network readings; actual 5-second history, maximum 10 minutes |
| `GET /api/v1/services` | Native service inventory, search, state filter, facts and pagination |
| `GET /api/v1/status` | Compatibility counts, blockers, reference baseline and searchable obligations |
| `GET /api/v1/trail` | Experimental scoped-file recovery summaries |
| `GET /api/v1/budget` | Monthly USD-micro ledger and operator approval policy |
| `GET /api/v1/platform` | Actual control-plane target and modern/legacy feasibility profiles |

The local Websites view loads separately when opened. `GET /api/v1/session` checks the operator session; `POST /api/v1/session/login` signs in and `POST /api/v1/session/logout` signs out. The access key stays in a password input and is cleared after submission; the UI never stores it, cookies or CSRF tokens in localStorage. Authenticated requests use same-origin cookies; writes send JSON and the session's CSRF token. Use the Go-served same-origin panel for these operator flows.

| Authenticated site route | Actual operation |
| --- | --- |
| `GET/POST /api/v1/sites`, `GET /api/v1/sites/{id}` | List, create and inspect persisted app-owned static websites |
| `GET /api/v1/sites/{id}/files`, `GET/PUT /api/v1/sites/{id}/file` | Read actual files and explicitly save UTF-8 text using the expected revision and SHA-256 |
| `POST /api/v1/sites/{id}/state` | Suspend or resume this slice's local serving |
| `GET/POST /api/v1/sites/{id}/backups` | List or create actual ZIP backups of this site's files |
| `POST /api/v1/sites/{id}/restore` | Confirm replacement of site files from a recorded ZIP with an expected revision |

Each site's preview links to its registered `site-<id>.localhost:8082` host using local HTTP. A save conflict keeps the draft, fetches actual server metadata/content, and requires an explicit revision update followed by Save. Refresh and panel navigation preserve unsaved editor drafts. Site changes, state controls, restore and sign-out require a saved or discarded draft. Restore needs a separate confirmation checkbox; recovery-required sites block managed writes. This slice does not provision Linux users, DNS, TLS, PHP, mail or databases, and its ZIP backups do not cover a host or database.

Each response is validated against its typed contract, with a ten-second timeout, retry states and explicit missing measurements. Server readings poll every five seconds; services poll every thirty seconds and honor the native collector's cache. Chart controls request 60/300/600-second ranges. History starts with this server process; unavailable values create chart gaps. No estimated history or hosted-account statistics are seeded. Service rows use opaque process-lifetime IDs because privacy-normalized names can repeat.

Default Overview is a real monitoring screen. Services are inspected read-only; this UI does not expose placeholder provisioning/restart actions. Compatibility remains uncertified unless the service's actual evidence changes. Scoped-file recovery is experimental and does not certify server/database backups or migration. Platforms distinguish compiled targets from unverified legacy candidates. No paid-model calls occur from these screens.

The slim white/slate interface follows the approved dashboard concept at `../assets/design/sifruno-dashboard-concept.png`, replacing all illustration values with API data. Local CSS deliberately orders reset/Tailwind/Astryx layers and overrides only product tokens and layout. Astryx's built neutral theme avoids runtime stylesheet injection and custom StyleX compilation. The optional `sifruno-public-preview` meta marker visibly identifies a public preview and excludes private workspaces and their requests; backend authorization remains responsible for route access. Its explicitly labelled sample tour is separate from private Files, Backups, Websites, Accounts and Access workflows.

The private UI also includes [session controls](../docs/archive/operator-sessions.md),
[File Manager](../docs/archive/file-manager-ui.md), [Backups](../docs/archive/backups-ui.md),
[backup schedules](../docs/archive/native-backup-schedules.md) and
[restore preview](../docs/archive/native-restore-preview.md) for app-owned static sites.
The [Accounts workspace](../docs/archive/accounts-workflow.md) requires a separately
admitted broker. Its [web-configuration preview](../docs/archive/accounts-web-preview.md)
shows metadata only; it neither applies configuration nor proves serving health.

```powershell
npm run typecheck
npm run build
```

Build success is separate from browser verification. Validate real collectors, missing/error states, filters/details, each available workspace, time ranges, theme persistence and 390/768/1440-pixel layouts. Test operator and website mutations against isolated fixture state, including actual preview, stale-draft preservation, ZIP restore confirmation and zero private requests in public preview. Recorded UI evidence belongs to its original source and fixtures; no new browser run was made for this documentation update. The package lock pins dependencies. The Astryx package's optional postinstall CLI nudge is not required for its precompiled exports.
