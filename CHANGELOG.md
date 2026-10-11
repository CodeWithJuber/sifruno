# Changelog

## [Unreleased]

### Added

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
[the delivery plan](docs/DELIVERY-PLAN.md). This section is an unreleased source
change, not a production release or hosting-compatibility qualification.
