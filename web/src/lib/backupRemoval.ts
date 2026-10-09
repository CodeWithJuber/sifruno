import { SiteApiError, siteRequest, siteURL, validSite } from "./sites-api";
import type { Site, SiteBackup } from "./sites-api";

export function canRemoveBackup(site: Site | undefined, backup: SiteBackup | undefined): boolean {
  return Boolean(site && backup && /^[a-f0-9]{32}$/.test(site.id) && backup.site_id === site.id && /^[a-f0-9]{32}$/.test(backup.id) && /^[a-f0-9]{64}$/.test(backup.sha256) && site.state !== "recovery_required" && Number.isSafeInteger(site.revision) && site.revision > 0 && site.revision < Number.MAX_SAFE_INTEGER && Number.isSafeInteger(backup.revision) && backup.revision > 0 && backup.revision <= site.revision);
}

export async function removeSiteBackup(site: Site, backup: SiteBackup, csrf: string, isLive: () => boolean): Promise<Site> {
  if (!canRemoveBackup(site, backup) || !csrf) throw new SiteApiError(422, "invalid_removal", "Refresh backup records and review the selected native ZIP before confirming removal.");
  if (!isLive()) throw new SiteApiError(401, "session_changed", "The removal context changed. Review the backup again.");
  const result = await siteRequest(siteURL(site.id, "/remove-backup"), validSite, { method: "POST", csrf, body: { backup_id: backup.id, expected_backup_sha256: backup.sha256, expected_revision: site.revision, confirmed: true } });
  if (!isLive()) throw new SiteApiError(401, "session_changed", "The removal result belongs to an earlier context. Refresh backup records.");
  if (result.id !== site.id || result.revision !== site.revision + 1 || result.name !== site.name || result.domain !== site.domain || result.preview_host !== site.preview_host || result.state !== site.state || result.created_at !== site.created_at) throw new SiteApiError(0, "invalid_response", "The removal response did not confirm the expected website. Refresh backup records.");
  return result;
}

export function backupRemovalError(error: unknown): string {
  if (error instanceof SiteApiError && error.status === 409) return "The website revision or selected ZIP hash changed. This confirmation is invalid. Close this dialog, refresh backup records and review removal again.";
  if (error instanceof SiteApiError && error.status === 503) return "Removal could not be confirmed. Cleanup may require recovery; further website operations are blocked while cleanup is unresolved. Refresh backup records after recovery. The request is not retried.";
  return "Removal could not be confirmed. Close this dialog and refresh backup records before reviewing again. The request is not retried.";
}
