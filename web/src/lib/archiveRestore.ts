import { SiteApiError, readBoundedJson, siteURL, validSite } from "./sites-api";
import type { Site } from "./sites-api";
import { validUploadedRestorePreview } from "./restorePreview";
import type { RestorePreview } from "./restorePreview";

export type ArchiveRestorePreview = Omit<RestorePreview, "backup_sha256"> & { archive_sha256: string };
export function validArchiveRestorePreview(value: unknown): value is ArchiveRestorePreview {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (!Object.hasOwn(record, "archive_sha256") || Object.hasOwn(record, "backup_sha256")) return false;
  const { archive_sha256, ...rest } = record;
  return validUploadedRestorePreview({ ...rest, backup_sha256: archive_sha256 });
}
type Input = { site: Site; archive: File; csrf: string; isLive: () => boolean };
function current(input: Input) {
  if (!input.isLive()) throw new SiteApiError(0, "context_changed", "The website or operator session changed. Review a fresh preview.");
}
async function transfer(input: Input, preview?: ArchiveRestorePreview): Promise<unknown> {
  current(input);
  if (!/^[a-f0-9]{32}$/.test(input.site.id) || !Number.isSafeInteger(input.site.revision) || input.site.revision < 1 || !input.csrf || !input.archive || input.archive.size < 1 || input.archive.size > 34 << 20) throw new SiteApiError(422, "invalid_request", "Choose a native Sifruno ZIP up to 34 MiB and an available website.");
  if (preview && (!validArchiveRestorePreview(preview) || preview.site_id !== input.site.id || preview.current_revision !== input.site.revision || input.site.revision >= Number.MAX_SAFE_INTEGER)) throw new SiteApiError(0, "invalid_preview", "Review a fresh preview before replacing files.");
  const form = new FormData();
  form.append("archive", input.archive.slice(0, input.archive.size, "application/zip"), input.archive.name || "site.zip");
  form.append("expected_revision", String(input.site.revision));
  if (preview) form.append("expected_archive_sha256", preview.archive_sha256);
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 60000);
  try {
    current(input);
    const response = await fetch(siteURL(input.site.id, preview ? "/archive-restore" : "/archive-restore-preview"), { method: "POST", credentials: "same-origin", cache: "no-store", signal: controller.signal, headers: { Accept: "application/json", "X-CSRF-Token": input.csrf }, body: form });
    current(input);
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new SiteApiError(response.status, "archive_restore_failed", response.status === 409 ? "The website revision or uploaded ZIP changed. Close this dialog and preview the ZIP again before confirming." : `Uploaded ZIP request returned HTTP ${response.status}. No successful restore was confirmed. Close and preview again.`);
    }
    const value = await readBoundedJson(response, 128 * 1024);
    current(input);
    return value;
  } catch (error) {
    if (error instanceof SiteApiError) throw error;
    throw new SiteApiError(0, "connection_failed", "The restore result could not be confirmed. Close and explicitly preview again to check current files.");
  } finally { clearTimeout(timer); }
}
export async function previewArchiveRestore(input: Input): Promise<ArchiveRestorePreview> {
  const value = await transfer(input);
  if (!validArchiveRestorePreview(value) || value.site_id !== input.site.id || value.current_revision !== input.site.revision) throw new SiteApiError(0, "invalid_response", "The preview did not match the selected website revision.");
  return value;
}
export async function confirmArchiveRestore(input: Input & { preview: ArchiveRestorePreview }): Promise<Site> {
  const value = await transfer(input, input.preview), before = input.site;
  if (!validSite(value) || value.id !== before.id || value.revision !== before.revision + 1 || value.name !== before.name || value.domain !== before.domain || value.state !== before.state || value.preview_host !== before.preview_host || value.created_at !== before.created_at) throw new SiteApiError(0, "invalid_response", "The restore did not confirm preserved website identity and the next revision. Refresh records before trying again.");
  return value;
}
