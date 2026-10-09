import { SiteApiError, uploadSiteFile } from "./sites-api";
import type { Site, SiteFile } from "./sites-api";

export interface UploadEntry { file: File; path: string }
export interface UploadOutcome { path: string; bytes: number; status: "uploading" | "saved" | "failed_or_unconfirmed" | "not_attempted"; revision?: number }
export interface UploadReview { entries: (UploadEntry & { problem?: string })[]; addedBytes: number; problem?: string }
const maxFileBytes = 2 * 1024 * 1024, maxSiteBytes = 32 * 1024 * 1024, maxFiles = 64;

// Shared parent folders must use identical casing, even on case-sensitive hosts.
function collides(a: string, b: string): boolean {
  const left = a.split("/"), right = b.split("/");
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    if (left[index].toLowerCase() !== right[index].toLowerCase()) return false;
    if (left[index] !== right[index]) return true;
  }
  return true;
}

export function reviewMultiUpload(entries: readonly UploadEntry[], catalog: readonly SiteFile[], validPath: (path: string) => boolean): UploadReview {
  if (entries.length > maxFiles || catalog.length + entries.length > maxFiles) return { entries: [], addedBytes: 0, problem: `The selection exceeds the 64-file site limit. Choose at most ${Math.max(0, maxFiles - catalog.length)} files.` };
  const reviewed = entries.map((entry) => ({ ...entry, problem: undefined as string | undefined }));
  const catalogBytes = catalog.reduce((sum, file) => sum + file.bytes, 0);
  const addedBytes = entries.reduce((sum, entry) => sum + entry.file.size, 0);
  let problem: string | undefined;
  if (catalog.length > maxFiles || catalogBytes > maxSiteBytes || catalog.some((file, index) => !validPath(file.path) || !Number.isSafeInteger(file.bytes) || file.bytes < 0 || file.bytes > maxFileBytes || catalog.slice(0, index).some((other) => collides(file.path, other.path)))) problem = "Refresh file records; the current catalog does not meet the static-site limits.";
  else if (!entries.length) problem = "Choose local static files to review.";
  else if (!Number.isSafeInteger(addedBytes) || catalogBytes + addedBytes > maxSiteBytes) problem = "The selection would exceed the 32 MiB site limit.";
  for (let index = 0; index < reviewed.length; index++) {
    const entry = reviewed[index];
    if (!entry.file.name || /[/\\]/.test(entry.file.name) || !validPath(entry.path)) entry.problem = "Use a supported static filename and a valid relative destination.";
    else if (!Number.isSafeInteger(entry.file.size) || entry.file.size < 0 || entry.file.size > maxFileBytes) entry.problem = "This file exceeds the 2 MiB limit.";
    else if (catalog.some((file) => collides(entry.path, file.path))) entry.problem = "Destination exists or conflicts with a file, folder or its casing. Upload never overwrites.";
    else if (reviewed.some((other, otherIndex) => otherIndex !== index && collides(entry.path, other.path))) entry.problem = "Selected destinations conflict with one another, including casing or file/folder aliases.";
  }
  if (!problem && reviewed.some((entry) => entry.problem)) problem = "Resolve the selected-file problems before uploading. No files have been sent.";
  return { entries: reviewed, addedBytes, problem };
}

export async function uploadMultipleFiles(input: {
  site: Site; entries: readonly UploadEntry[]; catalog: readonly SiteFile[]; validPath: (path: string) => boolean;
  csrf: string; isLive: () => boolean; shouldStop: () => boolean; onProgress: (outcomes: UploadOutcome[]) => void;
}): Promise<{ outcomes: UploadOutcome[]; lastSite: Site; failure?: unknown }> {
  if (input.entries.length > maxFiles || input.catalog.length + input.entries.length > maxFiles) return { outcomes: [], lastSite: input.site, failure: new SiteApiError(422, "invalid_selection", "The selection exceeds the 64-file site limit. Choose fewer files.") };
  const entries = input.entries.map((entry) => ({ ...entry }));
  const outcomes: UploadOutcome[] = entries.map((entry) => ({ path: entry.path, bytes: entry.file.size, status: "not_attempted" }));
  let lastSite = input.site;
  const review = reviewMultiUpload(entries, input.catalog, input.validPath);
  if (review.problem || !input.csrf || !/^[a-f0-9]{32}$/.test(input.site.id) || !["active", "suspended"].includes(input.site.state) || !Number.isSafeInteger(input.site.revision) || input.site.revision < 1 || input.site.revision + entries.length > Number.MAX_SAFE_INTEGER) {
    return { outcomes, lastSite, failure: new SiteApiError(422, "invalid_selection", review.problem ?? "Refresh the website revision and review the selected files.") };
  }
  for (let index = 0; index < entries.length; index++) {
    if (!input.isLive() || input.shouldStop()) break;
    const entry = entries[index];
    outcomes[index] = { ...outcomes[index], status: "uploading" };
    input.onProgress(outcomes.map((outcome) => ({ ...outcome })));
    try {
      const site = await uploadSiteFile({ siteId: lastSite.id, path: entry.path, file: entry.file, expectedRevision: lastSite.revision, csrf: input.csrf, isLive: input.isLive });
      if (!input.isLive()) throw new SiteApiError(0, "context_changed", "The pending upload result belongs to an earlier context. Refresh records to learn whether it was saved.");
      if (site.name !== lastSite.name || site.domain !== lastSite.domain || site.preview_host !== lastSite.preview_host || site.state !== lastSite.state || site.created_at !== lastSite.created_at) throw new SiteApiError(0, "invalid_response", "The upload response changed unrelated website metadata. Refresh records before choosing files again.");
      lastSite = site;
      outcomes[index] = { ...outcomes[index], status: "saved", revision: site.revision };
      if (input.isLive()) input.onProgress(outcomes.map((outcome) => ({ ...outcome })));
    } catch (failure) {
      outcomes[index] = { ...outcomes[index], status: "failed_or_unconfirmed" };
      if (input.isLive()) input.onProgress(outcomes.map((outcome) => ({ ...outcome })));
      return { outcomes, lastSite, failure };
    }
  }
  return { outcomes, lastSite };
}
