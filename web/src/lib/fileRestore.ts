import { SiteApiError, siteRequest, siteURL, validSite } from "./sites-api";
import type { Site, SiteBackup } from "./sites-api";
import { validRestorePath, validRestorePreview } from "./restorePreview";
import type { RestorePreviewFile } from "./restorePreview";

export interface FileRestorePreview {
  site_id: string; current_revision: number; backup_id: string; backup_sha256: string; backup_revision: number;
  file: RestorePreviewFile; preserved_files: number;
}
export function validFileRestorePreview(value: unknown): value is FileRestorePreview {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const v = value as FileRestorePreview;
  const keys = ["site_id", "current_revision", "backup_id", "backup_sha256", "backup_revision", "file", "preserved_files"];
  if (Object.keys(v).length !== keys.length || !keys.every(key => Object.hasOwn(v, key)) || !v.file || !["added", "modified", "unchanged"].includes(v.file.kind) || !Number.isSafeInteger(v.preserved_files) || v.preserved_files < 0 || v.preserved_files > 63) return false;
  return validRestorePreview({ site_id: v.site_id, current_revision: v.current_revision, backup_id: v.backup_id, backup_sha256: v.backup_sha256, backup_revision: v.backup_revision, files: [v.file], counts: { added: Number(v.file.kind === "added"), modified: Number(v.file.kind === "modified"), unchanged: Number(v.file.kind === "unchanged"), removed: 0 } });
}
export function fileRestoreMatches(value: unknown, site: Site, backup: SiteBackup, path: string): value is FileRestorePreview {
  return validFileRestorePreview(value) && value.site_id === site.id && value.current_revision === site.revision && backup.site_id === site.id && value.backup_id === backup.id && value.backup_sha256 === backup.sha256 && value.backup_revision === backup.revision && value.file.path === path;
}
const body = (site: Site, backup: SiteBackup, path: string) => ({ backup_id: backup.id, expected_backup_sha256: backup.sha256, expected_revision: site.revision, path });
export async function previewFileRestore(site: Site, backup: SiteBackup, path: string, csrf: string) {
  if (!validRestorePath(path) || !csrf || backup.site_id !== site.id) throw new SiteApiError(422, "invalid_request", "Choose one archived file and review the current website records.");
  return siteRequest(siteURL(site.id, "/restore-file-preview"), (value): value is FileRestorePreview => fileRestoreMatches(value, site, backup, path), { method: "POST", csrf, body: body(site, backup, path) });
}
export async function confirmFileRestore(input: { site: Site; backup: SiteBackup; path: string; preview: FileRestorePreview; confirmed: boolean; csrf: string; isLive: () => boolean }): Promise<Site> {
  if (!input.confirmed || !input.csrf || !fileRestoreMatches(input.preview, input.site, input.backup, input.path) || input.site.revision >= Number.MAX_SAFE_INTEGER || !input.isLive()) throw new SiteApiError(409, "invalid_context", "Review and confirm the selected file again.");
  const site = await siteRequest(siteURL(input.site.id, "/restore-file"), validSite, { method: "POST", csrf: input.csrf, body: { ...body(input.site, input.backup, input.path), confirmed: true } });
  if (!input.isLive() || site.id !== input.site.id || site.revision !== input.site.revision + 1) throw new SiteApiError(0, "invalid_response", "The single-file restore result could not be confirmed. Refresh records before another attempt.");
  return site;
}
