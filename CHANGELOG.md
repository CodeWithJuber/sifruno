# Changelog

## [Unreleased]

### Added

- Reviewed multiple-file uploads in File Manager, using existing revisioned
  uploads with upfront limit/collision checks and explicit partial outcomes.
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
