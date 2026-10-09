import { SiteApiError, validBackup, validSite } from "./sites-api";
import type { Site, SiteBackup } from "./sites-api";

export interface RestoreHandoff { backupId: string; backupSHA256: string; expectedRevision: number }

// A handoff selects an exact archive and saved site revision. Fresh inventory
// may reject it; selecting another archive or advancing it silently is forbidden.
export function resolveRestoreHandoff(request: RestoreHandoff, siteId: string, site: Site, backups: SiteBackup[]): SiteBackup {
  const keys = ["backupId", "backupSHA256", "expectedRevision"];
  if (!request || Object.keys(request).length !== keys.length || !keys.every(key => Object.hasOwn(request, key)) || !/^[a-f0-9]{32}$/.test(request.backupId) || !/^[a-f0-9]{64}$/.test(request.backupSHA256) || !Number.isSafeInteger(request.expectedRevision) || request.expectedRevision < 1 || !validSite(site) || site.id !== siteId || site.state === "recovery_required") throw new SiteApiError(422, "invalid_handoff", "The requested restore target is unavailable. Your Websites editor draft is kept. Refresh its backup records and review restore again.");
  if (site.revision !== request.expectedRevision) throw new SiteApiError(409, "stale_handoff", "The saved website revision changed. This restore request is invalid. Your Websites editor draft is kept. Refresh its backup records and review restore again.");
  const matches = backups.filter(backup => backup.id === request.backupId);
  const backup = matches[0];
  if (matches.length !== 1 || !validBackup(backup) || backup.site_id !== siteId || backup.sha256 !== request.backupSHA256 || backup.revision < 1 || backup.revision > site.revision || backup.files < 1 || backup.files > 64 || backup.bytes < 1) throw new SiteApiError(404, "archive_handoff_changed", "The requested ZIP is missing or its recorded identity changed. No replacement archive was selected. Your Websites editor draft is kept. Refresh its backup records and review restore again.");
  return backup;
}

export function restoreHandoffFor(site: Site, backup: SiteBackup): RestoreHandoff {
  const request = { backupId: backup.id, backupSHA256: backup.sha256, expectedRevision: site.revision };
  resolveRestoreHandoff(request, site.id, site, [backup]);
  return request;
}
