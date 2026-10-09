import { SiteApiError, siteRequest, siteURL } from "./sites-api";
import type { SiteBackup, SiteFile } from "./sites-api";

export const restoreKinds = ["added", "modified", "removed", "unchanged"] as const;
export type RestoreKind = typeof restoreKinds[number];
export interface RestorePreviewFile { path: string; kind: RestoreKind; before: SiteFile | null; after: SiteFile | null }
export interface RestorePreview {
  site_id: string; current_revision: number; backup_id: string; backup_sha256: string; backup_revision: number;
  files: RestorePreviewFile[]; counts: Record<RestoreKind, number>;
}
type ObjectValue = Record<string, unknown>;
const object = (value: unknown): value is ObjectValue => typeof value === "object" && value !== null && !Array.isArray(value);
const exact = (value: ObjectValue, keys: readonly string[]) => Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number => Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
const id = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
const sha = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
// Matches the native static-file policy; never admits host paths or credential names.
export function validRestorePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 200) return false;
  const parts = value.split("/");
  return parts.length <= 8 && /\.(html|htm|css|js|mjs|txt|svg|png|jpg|jpeg|gif|webp|ico|woff|woff2|ttf|pdf)$/i.test(value) && parts.every(part => {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$/.test(part) || part.endsWith(".")) return false;
    const base = part.split(".", 1)[0].toLowerCase();
    return !["con", "prn", "aux", "nul", "credentials", "password", "secrets", "kubeconfig", "key"].includes(base) && !/^(com|lpt)[0-9]$/.test(base) && !base.startsWith("id_rsa") && !base.startsWith("id_ed25519");
  });
}
const fileInfo = (value: unknown, path: string): value is SiteFile => object(value) && exact(value, ["path", "bytes", "sha256"]) && value.path === path && integer(value.bytes, 0, 2 << 20) && sha(value.sha256);
export function validRestorePreview(value: unknown): value is RestorePreview {
  return validPreview(value, true);
}
export function validUploadedRestorePreview(value: unknown): value is RestorePreview {
  return validPreview(value, false);
}
function validPreview(value: unknown, saved: boolean): value is RestorePreview {
  if (!object(value) || !exact(value, ["site_id", "current_revision", "backup_id", "backup_sha256", "backup_revision", "files", "counts"]) ||
      !id(value.site_id) || !id(value.backup_id) || !sha(value.backup_sha256) || !integer(value.current_revision, 1) || !integer(value.backup_revision, 1, saved ? value.current_revision : Number.MAX_SAFE_INTEGER) ||
      !Array.isArray(value.files) || value.files.length < 1 || value.files.length > 128 || !object(value.counts) || !exact(value.counts, restoreKinds) || !restoreKinds.every(kind => integer((value.counts as ObjectValue)[kind], 0, 128))) return false;
  const counts = { added: 0, modified: 0, removed: 0, unchanged: 0 };
  const aliases = new Set<string>(); let previous = "", beforeCount = 0, afterCount = 0, beforeBytes = 0, afterBytes = 0;
  for (const entry of value.files) {
    if (!object(entry) || !exact(entry, ["path", "kind", "before", "after"]) || !validRestorePath(entry.path) || entry.path <= previous || aliases.has(entry.path.toLowerCase()) || !restoreKinds.includes(entry.kind as RestoreKind)) return false;
    const path = entry.path, kind = entry.kind as RestoreKind;
    if (entry.before !== null && !fileInfo(entry.before, path) || entry.after !== null && !fileInfo(entry.after, path)) return false;
    const before = entry.before as SiteFile | null, after = entry.after as SiteFile | null;
    if (kind === "added" && (before !== null || after === null) || kind === "removed" && (before === null || after !== null) ||
        (kind === "modified" || kind === "unchanged") && (before === null || after === null || ((before.bytes === after.bytes && before.sha256 === after.sha256) !== (kind === "unchanged")))) return false;
    counts[kind]++; aliases.add(path.toLowerCase()); previous = path;
    if (before) { beforeCount++; beforeBytes += before.bytes; }
    if (after) { afterCount++; afterBytes += after.bytes; }
  }
  return beforeCount <= 64 && afterCount >= 1 && afterCount <= 64 && beforeBytes <= 32 << 20 && afterBytes <= 32 << 20 && restoreKinds.every(kind => counts[kind] === (value.counts as ObjectValue)[kind]);
}
export function restorePreviewMatches(value: unknown, siteId: string, revision: number, backup: SiteBackup): value is RestorePreview {
  return validRestorePreview(value) && value.site_id === siteId && value.current_revision === revision && backup.site_id === siteId &&
    value.backup_id === backup.id && value.backup_sha256 === backup.sha256 && value.backup_revision === backup.revision &&
    value.counts.added + value.counts.modified + value.counts.unchanged === backup.files;
}
export function canConfirmRestorePreview(value: unknown, siteId: string, revision: number, backup: SiteBackup): value is RestorePreview {
  return integer(revision, 1, Number.MAX_SAFE_INTEGER - 1) && restorePreviewMatches(value, siteId, revision, backup);
}
export function getRestorePreview(siteId: string, revision: number, backup: SiteBackup, csrf: string) {
  if (!id(siteId) || !integer(revision, 1) || backup.site_id !== siteId || !id(backup.id) || !sha(backup.sha256) || !integer(backup.revision, 1, revision) || !integer(backup.files, 1, 64) || !csrf) throw new SiteApiError(0, "invalid_preview", "Refresh the website and backup records before reviewing a restore.");
  return siteRequest(siteURL(siteId, "/restore-preview"), (value): value is RestorePreview => restorePreviewMatches(value, siteId, revision, backup), { method: "POST", csrf, body: { backup_id: backup.id, expected_revision: revision } });
}
export function restorePreviewError(failure: unknown): string {
  if (failure instanceof SiteApiError && failure.status === 409) return "The saved website revision changed. This preview and confirmation are invalid. Refresh backup records, then review a new preview. Your Websites editor draft is kept.";
  if (failure instanceof SiteApiError && failure.status === 503) return "Restore preview is unavailable or the file and archive hashes could not be verified. No restore was sent. Refresh records explicitly before reviewing again; this page does not retry automatically.";
  if (failure instanceof SiteApiError && failure.status === 401) return "Your local session expired or was revoked. Sign in again before reviewing a restore.";
  return "A matching restore preview could not be verified. Confirmation is disabled. Refresh backup records before reviewing again. Your Websites editor draft is kept.";
}
