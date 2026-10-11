import { downloadSiteBackup, SiteApiError, siteRequest, siteURL, validBackupList, validSite } from "./sites-api";
import type { Site, SiteBackup } from "./sites-api";
import { resolveRestoreHandoff, restoreHandoffFor } from "./restoreHandoff";
import type { RestoreHandoff } from "./restoreHandoff";

export interface BackupCopySelection extends RestoreHandoff { siteId: string }
export interface ZIPImportRequest { requestId: number; snapshot?: BackupCopySelection }
export interface PreparedBackupCopy { site: Site; backup: SiteBackup; archive: File }

export function backupCopySelection(site: Site, backup: SiteBackup): BackupCopySelection {
  return { siteId: site.id, ...restoreHandoffFor(site, backup) };
}

// Read-only preparation. The caller owns the session/context lifetime; no import
// or replacement selection occurs here, including after a late download.
export async function prepareBackupCopy(selection: BackupCopySelection, sites: Site[], isLive: () => boolean): Promise<PreparedBackupCopy> {
  const checkLive = () => { if (!isLive()) throw new SiteApiError(409, "copy_context_changed", "The snapshot request is no longer active. Select it again from Backups."); };
  checkLive();
  const { siteId, ...request } = selection;
  const source = sites.filter(site => site.id === siteId);
  if (source.length !== 1) throw new SiteApiError(404, "copy_source_missing", "The source website is no longer available. Refresh Backups and select the snapshot again.");
  const [site, inventory] = await Promise.all([
    siteRequest(siteURL(siteId), validSite),
    siteRequest(siteURL(siteId, "/backups"), validBackupList),
  ]);
  checkLive();
  if (source[0].revision !== site.revision) throw new SiteApiError(409, "copy_source_changed", "The source website changed while checking records. Refresh Backups and select the snapshot again.");
  let backup: SiteBackup;
  try { backup = resolveRestoreHandoff(request, siteId, site, inventory.items); }
  catch (failure) {
    if (failure instanceof SiteApiError) throw new SiteApiError(failure.status, failure.code, "The selected snapshot or source revision changed. No replacement ZIP was selected. Refresh Backups and select it again. Your editor draft is kept.");
    throw failure;
  }
  const blob = await downloadSiteBackup(siteId, backup.id, backup.sha256);
  checkLive();
  if (blob.size !== backup.bytes) throw new SiteApiError(0, "copy_archive_changed", "The verified ZIP size does not match the selected snapshot. Refresh Backups and select it again.");
  return { site, backup, archive: new File([blob], `sifruno-${backup.id}.zip`, { type: "application/zip" }) };
}
