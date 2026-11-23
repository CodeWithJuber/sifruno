# Changelog

## [Unreleased]

### Changed

- The product plan (`docs/PRODUCT-PLAN.md`) replaces the zero-edit cPanel
  compatibility target. Earlier delivery notes moved to `docs/archive/`, the
  README is one page, and `internal/whmapi` is frozen.
- The account broker creates regular Linux users with subordinate ID ranges
  instead of system users, and the 100-account bound is now 2000.
- `--dns-reload-cmd` runs without a shell: give an absolute program and plain
  arguments, for example `/usr/sbin/rndc reload`. Shell syntax is refused at
  startup.

### Removed

- The Compatibility and Platforms screens and the "hosting engine in
  development" notice. Their API routes remain.
- The Ghidra and REA analysis tooling and the `rea-agents` dev dependency.

### Added

- Broker web operation (needs human review): `SetWeb` (`hostbroker
  --web-user`) gives OpenLiteSpeed read access to an account's site through
  an ACL written on no-follow directory handles, sets an XFS quota, renders
  the account's vhost with olsweb, tests it with `openlitespeed -t` and
  reloads gracefully. A config that fails its test is restored and
  journaled as rejected, leaving the account unchanged; delete takes the
  site out before removing the user. `proof.sh broker-web` proves it on the
  dev VM.
- The panel over HTTPS beyond loopback (needs human review):
  `--https-listen` with `--panel-host`, and `--tls-cert`/`--tls-key` or a
  self-signed certificate kept in the state directory (fingerprint printed
  at start). Over that listener only admin sign-in works, every API route
  needs an admin session, and the access key and first-run setup are
  refused. Loopback behaviour is unchanged.
- Admin sign-in with a password and a 6-digit authenticator code (needs
  human review). A new panel asks for first-run setup on its first private
  page: the server's access key, then a username and password, then an
  authenticator app. Passwords are Argon2id hashes in the private state
  directory; each code works once; each account allows five tries, then one a
  minute. The access key still signs in locally. New dependency:
  golang.org/x/crypto v0.57.0, approved by the owner.
- Phase 1 panel shell: a shadcn/ui sidebar and top bar, Ctrl+K search over
  pages and actions, and a URL for every page (TanStack Router). The menu
  names the job: Home, Websites (Files, Backups), Activity, and under
  Administration: Customers, Server, Security, Settings. Panel colours come
  from the brand tokens.
- Broker-managed SFTP keys: `SetSSHKeys` writes a root-owned key file per
  account, each key restricted to `internal-sftp`.
- `panelctl htaccess scan`: classifies every `.htaccess` directive and sorts
  sites into Native, Convertible or Compat for OpenLiteSpeed.
- `panelctl migrate verify`: compares an old site with its new copy, pages
  and closed (401/403) URLs, and keeps the cutover gate closed on any failure
  or unaccepted warning.
- `internal/olsweb`: renders OpenLiteSpeed config for a site from a typed spec.
- `scripts/devvm`: a disposable AlmaLinux 9 dev VM, the Phase 0 proofs and
  the Phase 1 panel shell proof (`proof.sh panel-shell`).

- Recovery archive v1 (`recovery-2026-10-11-v1`) for the Windows-server handoff:
  all 270 original dirty source paths, 130 recovery branches, an offline Git
  bundle and 11,995 additional artifact paths with checksums and a tested restore
  helper. User-selected secrets/runtime-state exclusions are explicit in
  `docs/server-recovery.md`. This is an archival prerelease, not a product release.

- Combined native static website lifecycle from reviewed PR62–67: display-name
  editing, sequential multiple-file upload, saved-file HTTP preview, single-file
  snapshot restore, snapshot recovery as a separate website and exact-confirmed
  website removal. Original feature evidence and combined browser evidence are
  linked in `docs/website-lifecycle-integration.md`.

- Confirmed removal of a selected saved native ZIP, freeing backup capacity while
  preserving the website's served files and remaining snapshots.
- Preview and explicitly restore a downloaded native Sifruno ZIP into an existing
  static website, preserving its identity, domain, backup history and schedule.
- Confirmed rename/move of a saved website file in File Manager, preserving
  bytes and refusing stale revisions, changed checksums and occupied paths.
- Download a saved text or binary file from File Manager, verified against the
  displayed revision, byte count and SHA-256 while retaining unsaved drafts.
- Main integration of the reviewed website domain-routing update, selected-site
  File Manager/Backups navigation and downloaded native ZIP recovery workflow.
- Local static-file upload and confirmed replacement bound to a file checksum
  and site revision, with existing backup restoration for recovery.

### Fixed

- Websites' saved ZIP restore now uses Backups' verified file comparison and
  explicit confirmation, retaining editor drafts and rejecting stale targets.
- Websites can display saved binary-asset details when the first or only file
  cannot be opened as UTF-8 text. Text editing, File Manager navigation and
  backup recovery remain available in the same website workflow.

Earlier deliveries and their original evidence are recorded in
[the delivery plan](docs/archive/DELIVERY-PLAN.md). This section is an unreleased source
change, not a production release or hosting-compatibility qualification.
