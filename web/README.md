# Sifruno server panel UI

For prerequisites and a complete source build, use the [installation guide](../docs/installation.md).
The [documentation index](../docs/archive/README.md) covers each UI workflow and its
historical evidence. Current publication and remaining acceptance gates are in
[project state](../docs/archive/PROJECT-STATE.md); no live preview is certified here.

React 19, TypeScript, Vite and Tailwind render the approved V3 Sifruno identity with local Inter fonts. Colours come from `assets/design-tokens.css`. The panel shell (sidebar, top bar, Ctrl+K search and page URLs) is shadcn/ui on Base UI with TanStack Router. The screens inside it still reuse Meta Astryx 0.6.5 components (Button, Card, SegmentedControl, ProgressBar and the precompiled neutral Theme) until each is rebuilt. See NOTICE.md for source and license attribution.

Every page has its own URL: `/` Home, `/websites`, `/websites/files`, `/websites/backups`, `/activity`, `/customers`, `/server` (with `/server/storage` and `/server/network`), `/security` and `/settings`. The Go service answers these paths with `index.html`. Websites, Files, Backups and Customers stay mounted once opened, so unsaved drafts survive navigation.

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
| `GET /api/v1/trail` | Experimental scoped-file recovery summaries |
| `GET /api/v1/budget` | Monthly USD-micro ledger and operator approval policy |
| `GET /api/v1/platform` | Actual control-plane target and modern/legacy feasibility profiles |

Private pages show the shell's sign-in until someone is signed in. `GET /api/v1/session/setup` says whether first-run admin setup is needed; `POST /api/v1/session/setup/totp` and `/setup/admin` create the first admin; `GET /api/v1/session` checks the session; `POST /api/v1/session/login` signs in with a username, password and code (or the local access key) and `POST /api/v1/session/logout` signs out. See [internal/operator](../internal/operator/README.md). The access key stays in a password input and is cleared after submission; the UI never stores it, cookies or CSRF tokens in localStorage. Authenticated requests use same-origin cookies; writes send JSON and the session's CSRF token. Use the Go-served same-origin panel for these operator flows.

| Authenticated site route | Actual operation |
| --- | --- |
| `GET/POST /api/v1/sites`, `GET /api/v1/sites/{id}` | List, create and inspect persisted app-owned static websites |
| `GET /api/v1/sites/{id}/files`, `GET/PUT /api/v1/sites/{id}/file` | Read actual files and explicitly save UTF-8 text using the expected revision and SHA-256 |
| `POST /api/v1/sites/{id}/state` | Suspend or resume this slice's local serving |
| `GET/POST /api/v1/sites/{id}/backups` | List or create actual ZIP backups of this site's files |
| `POST /api/v1/sites/{id}/restore` | Confirm replacement of site files from a recorded ZIP with an expected revision |

Each site's preview links to its registered `site-<id>.localhost:8082` host using local HTTP. A save conflict keeps the draft, fetches actual server metadata/content, and requires an explicit revision update followed by Save. Refresh and panel navigation preserve unsaved editor drafts. Site changes, state controls, restore and sign-out require a saved or discarded draft. Restore needs a separate confirmation checkbox; recovery-required sites block managed writes. This slice does not provision Linux users, DNS, TLS, PHP, mail or databases, and its ZIP backups do not cover a host or database.

Each response is validated against its typed contract, with a ten-second timeout, retry states and explicit missing measurements. Server readings poll every five seconds; services poll every thirty seconds and honor the native collector's cache. Chart controls request 60/300/600-second ranges. History starts with this server process; unavailable values create chart gaps. No estimated history or hosted-account statistics are seeded. Service rows use opaque process-lifetime IDs because privacy-normalized names can repeat.

Home is a real monitoring screen. Services are inspected read-only; this UI does not expose placeholder provisioning/restart actions. Compatibility evidence and platform profiles are no longer panel screens; `GET /api/v1/status` and `GET /api/v1/platform` still answer for developers. Scoped-file recovery (Activity) is experimental and does not certify server/database backups or migration. No paid-model calls occur from these screens.

The slim white/slate interface follows the approved dashboard concept at `../assets/design/sifruno-dashboard-concept.png`, replacing all illustration values with API data. Local CSS deliberately orders reset/Tailwind/Astryx layers and overrides only product tokens and layout. Astryx's built neutral theme avoids runtime stylesheet injection and custom StyleX compilation. The optional `sifruno-public-preview` meta marker visibly identifies a public preview and excludes private workspaces and their requests; backend authorization remains responsible for route access. Its explicitly labelled sample tour (`/tour`, public preview only) is separate from private Websites, Files, Backups, Customers and Security workflows.

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
