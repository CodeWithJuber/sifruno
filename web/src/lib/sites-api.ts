export interface Site {
  id: string;
  name: string;
  domain: string;
  preview_host: string;
  state: "active" | "suspended" | "recovery_required";
  revision: number;
  created_at: string;
  updated_at: string;
}
export interface SiteFile { path: string; bytes: number; sha256: string }
export interface SiteFileContent { path: string; content: string; sha256: string; revision: number }
export interface SiteBackup {
  id: string; site_id: string; created_at: string; bytes: number;
  files: number; sha256: string; revision: number;
}
export type OperatorSession =
  | { authenticated: true; csrf_token: string; expires_at: string }
  | { authenticated: false };

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const date = (v: unknown) => text(v) && Number.isFinite(Date.parse(v));
const sha = (v: unknown) => text(v) && /^[a-f0-9]{64}$/.test(v);
const id = (v: unknown) => text(v) && /^[a-f0-9]{32}$/.test(v);
const path = (v: unknown) => text(v) && v.length > 0 && !v.startsWith("/") && !v.includes("\\") && !v.split("/").some((part) => part === "." || part === ".." || !part);

export function validSite(v: unknown): v is Site {
  return object(v) && id(v.id) && text(v.name) && text(v.domain) &&
    v.preview_host === `site-${v.id}.localhost` &&
    ["active", "suspended", "recovery_required"].includes(String(v.state)) &&
    count(v.revision) && date(v.created_at) && date(v.updated_at);
}
export function validSiteList(v: unknown): v is { items: Site[] } {
  return object(v) && Array.isArray(v.items) && v.items.every(validSite);
}
export function validFileList(v: unknown): v is { items: SiteFile[] } {
  return object(v) && Array.isArray(v.items) && v.items.every((f) => object(f) && path(f.path) && count(f.bytes) && sha(f.sha256));
}
export function validFileContent(v: unknown): v is SiteFileContent {
  return object(v) && path(v.path) && text(v.content) && sha(v.sha256) && count(v.revision);
}
export function validBackup(v: unknown): v is SiteBackup {
  return object(v) && text(v.id) && v.id.length > 0 && v.id.length <= 256 && id(v.site_id) && date(v.created_at) &&
    count(v.bytes) && count(v.files) && sha(v.sha256) && count(v.revision);
}
export function validBackupList(v: unknown): v is { items: SiteBackup[] } {
  return object(v) && Array.isArray(v.items) && v.items.every(validBackup);
}
export function validSession(v: unknown): v is OperatorSession {
  return object(v) && (v.authenticated === false || (v.authenticated === true && text(v.csrf_token) && v.csrf_token.length > 0 && date(v.expires_at)));
}

export class SiteApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}
function message(status: number): string {
  if (status === 401) return "Operator authentication is required. Sign in again; your editor draft is kept.";
  if (status === 403) return "The session or request origin was rejected. Refresh your session and try again.";
  if (status === 404) return "This website, file or backup could not be found. Your editor draft is kept.";
  if (status === 409) return "The website changed on the server. Your editor draft is kept; compare the latest version before saving.";
  if (status === 422) return "Check the values and static-file limits. No successful result was confirmed.";
  if (status === 429) return "Too many sign-in attempts. Wait before trying again.";
  if (status === 503) return "This local capability is unavailable. No successful result was confirmed.";
  return `The local service returned HTTP ${status}. No successful result was confirmed.`;
}

/* Called only by the lazy, local Websites view. Credentials and CSRF remain
   in this browser session; no bodies, tokens or keys are logged or persisted. */
export async function siteRequest<T>(
  url: string,
  validate: (value: unknown) => value is T,
  options: { method?: "GET" | "POST" | "PUT" | "DELETE"; body?: unknown; csrf?: string; unauthenticatedSession?: boolean } = {},
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  const method = options.method ?? "GET";
  try {
    const response = await fetch(url, {
      method, credentials: "same-origin", cache: "no-store", signal: controller.signal,
      headers: { Accept: "application/json", ...(method !== "GET" ? { "Content-Type": "application/json" } : {}), ...(options.csrf ? { "X-CSRF-Token": options.csrf } : {}) },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
    });
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok && !(options.unauthenticatedSession && response.status === 401 && validSession(value) && !value.authenticated)) {
      const code = object(value) && text(value.error) && /^[a-z_]+$/.test(value.error) ? value.error : "request_failed";
      throw new SiteApiError(response.status, code, message(response.status));
    }
    if (!validate(value)) throw new SiteApiError(0, "invalid_response", "The response did not match the website data contract. No successful result was confirmed.");
    return value;
  } catch (error) {
    if (error instanceof SiteApiError) throw error;
    throw new SiteApiError(0, "connection_failed", "The request did not confirm its result. Your draft is kept. Refresh records before trying again.");
  } finally { clearTimeout(timer); }
}

export const siteURL = (siteId: string, suffix = "") => `/api/v1/sites/${encodeURIComponent(siteId)}${suffix}`;
export async function renameSiteFile(input: { siteId: string; path: string; destination: string; expectedSHA256: string; expectedRevision: number; csrf: string; isLive: () => boolean }): Promise<Site> {
  if (!id(input.siteId) || !path(input.path) || !path(input.destination) || input.path.toLowerCase() === input.destination.toLowerCase() || !sha(input.expectedSHA256) || !count(input.expectedRevision) || input.expectedRevision < 1 || !input.csrf) throw new SiteApiError(422, "invalid_request", "Review the source, new relative path and website revision before renaming.");
  if (!input.isLive()) throw new SiteApiError(401, "session_changed", "The rename context changed. Sign in and review the file again.");
  try {
    const site = await siteRequest(siteURL(input.siteId, "/rename"), validSite, { method: "POST", csrf: input.csrf, body: { path: input.path, destination: input.destination, expected_sha256: input.expectedSHA256, expected_revision: input.expectedRevision } });
    if (!input.isLive()) throw new SiteApiError(401, "session_changed", "The rename context changed. Refresh the file records before continuing.");
    if (site.id !== input.siteId || site.revision !== input.expectedRevision + 1) throw new SiteApiError(0, "invalid_response", "Rename did not confirm the expected website revision. Refresh file records before retrying.");
    return site;
  } catch (error) {
    if (error instanceof SiteApiError && error.status === 409) throw new SiteApiError(409, error.code, "The saved source, destination or website revision changed. Your destination path is kept; refresh the rename target and review it before confirming again.");
    throw error;
  }
}
export function sitePreviewPort(): number | undefined {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="sifruno-sites-port"]');
  if (!meta) return 8082;
  const value = meta.content.trim();
  if (!/^\d{1,5}$/.test(value)) return undefined;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : undefined;
}
export const previewURL = (site: Site) => {
  const port = sitePreviewPort();
  return validSite(site) && port ? `http://${site.preview_host}:${port}/` : undefined;
};
export function savedFilePreviewURL(site: Site, savedPath: string, validPath: (value: string) => boolean): string | undefined {
  if (!path(savedPath) || !validPath(savedPath)) return undefined;
  const base = previewURL(site);
  return base ? base + savedPath : undefined;
}

const maxTransferArchive = 34 * 1024 * 1024;

function transferMessage(status: number): string {
  if (status === 401) return message(401);
  if (status === 403) return message(403);
  if (status === 404) return message(404);
  if (status === 409) return message(409);
  if (status === 413) return "The ZIP archive exceeds the 34 MiB transfer limit.";
  if (status === 422) return "This is not a valid native Sifruno site archive, or its site values are invalid.";
  if (status === 503) return message(503);
  return `The local transfer returned HTTP ${status}. No successful result was confirmed.`;
}

async function transferError(response: Response): Promise<SiteApiError> {
  // Transfer failures are JSON problems; successful transfer bodies stay binary.
  await response.body?.cancel().catch(() => undefined);
  return new SiteApiError(response.status, "website_transfer_failed", transferMessage(response.status));
}

export async function readBoundedJson(response: Response, limit: number): Promise<unknown> {
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
  const body = response.body;
  if (contentType !== "application/json" || !body) {
    await body?.cancel().catch(() => undefined);
    throw new SiteApiError(0, "invalid_response", "The import did not return a readable JSON website record.");
  }
  const lengthHeader = response.headers.get("Content-Length");
  let expectedLength: number | undefined;
  if (lengthHeader !== null) {
    if (!/^\d+$/.test(lengthHeader)) {
      await body.cancel().catch(() => undefined);
      throw new SiteApiError(0, "invalid_response", "The import response has an invalid length header.");
    }
    expectedLength = Number(lengthHeader);
    if (!Number.isSafeInteger(expectedLength) || expectedLength > limit) {
      await body.cancel().catch(() => undefined);
      throw new SiteApiError(0, "invalid_response", "The import response exceeds the 16 KiB response limit.");
    }
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => undefined);
      throw new SiteApiError(0, "invalid_response", "The import response exceeds the 16 KiB response limit.");
    }
    chunks.push(value);
  }
  if (expectedLength !== undefined && size !== expectedLength) {
    throw new SiteApiError(0, "invalid_response", "The import response did not match its length header.");
  }
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data)); }
  catch { throw new SiteApiError(0, "invalid_response", "The import response was not valid JSON."); }
}

export async function downloadSiteBackup(siteId: string, backupId: string, expectedSha256: string): Promise<Blob> {
  if (!sha(expectedSha256)) throw new SiteApiError(0, "invalid_response", "The backup hash is invalid.");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);
  try {
    const response = await fetch(siteURL(siteId, `/backups/${encodeURIComponent(backupId)}/download`), {
      method: "GET", credentials: "same-origin", cache: "no-store", signal: controller.signal,
      headers: { Accept: "application/zip" },
    });
    if (!response.ok) throw await transferError(response);
    const contentType = response.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
    const body = response.body;
    if (contentType !== "application/zip" || !body) {
      await body?.cancel().catch(() => undefined);
      throw new SiteApiError(0, "invalid_response", "The download did not return a readable application/zip stream.");
    }
    const lengthHeader = response.headers.get("Content-Length");
    let expectedLength: number | undefined;
    if (lengthHeader !== null) {
      if (!/^\d+$/.test(lengthHeader)) {
        await body.cancel().catch(() => undefined);
        throw new SiteApiError(0, "invalid_response", "The ZIP download has an invalid length header.");
      }
      expectedLength = Number(lengthHeader);
      if (!Number.isSafeInteger(expectedLength) || expectedLength <= 0 || expectedLength > maxTransferArchive) {
        await body.cancel().catch(() => undefined);
        throw new SiteApiError(0, "invalid_response", "The ZIP download exceeds the 34 MiB transfer limit.");
      }
    }
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      size += value.byteLength;
      if (size > maxTransferArchive) {
        await reader.cancel().catch(() => undefined);
        throw new SiteApiError(0, "invalid_response", "The ZIP download exceeds the 34 MiB transfer limit.");
      }
      chunks.push(value);
    }
    if (size === 0 || (expectedLength !== undefined && size !== expectedLength)) {
      throw new SiteApiError(0, "invalid_response", "The ZIP download was empty or did not match its length header.");
    }
    const archive = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { archive.set(chunk, offset); offset += chunk.byteLength; }
    const digest = await crypto.subtle.digest("SHA-256", archive);
    const actualSha256 = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (actualSha256 !== expectedSha256) throw new SiteApiError(0, "invalid_response", "The downloaded ZIP hash does not match the selected backup record.");
    return new Blob([archive], { type: "application/zip" });
  } catch (error) {
    if (error instanceof SiteApiError) throw error;
    throw new SiteApiError(0, "connection_failed", "The ZIP download could not be confirmed. Refresh the backup list before trying again.");
  } finally { clearTimeout(timer); }
}

// Saved file downloads use raw bytes, never editor drafts or text decoding.
export async function downloadSiteFile(input: { siteId: string; file: SiteFile; expectedRevision: number; isLive: () => boolean }): Promise<Blob> {
  const maxBytes = 2 * 1024 * 1024, filename = input.file.path.split("/").at(-1);
  if (!id(input.siteId) || !path(input.file.path) || input.file.path.length > 200 || !input.file.path.split("/").every((part) => /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$/.test(part)) || !filename || !sha(input.file.sha256) || !count(input.file.bytes) || input.file.bytes > maxBytes || !count(input.expectedRevision) || input.expectedRevision < 1) {
    throw new SiteApiError(422, "invalid_request", "Review the saved file record before downloading.");
  }
  if (!input.isLive()) throw new SiteApiError(401, "session_changed", "The download context changed. Sign in and review the file again.");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);
  try {
    const query = new URLSearchParams({ path: input.file.path, expected_revision: String(input.expectedRevision), expected_sha256: input.file.sha256 });
    const response = await fetch(siteURL(input.siteId, `/files/download?${query}`), {
      method: "GET", credentials: "same-origin", cache: "no-store", signal: controller.signal,
      headers: { Accept: "application/octet-stream" },
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new SiteApiError(response.status, "website_transfer_failed", message(response.status));
    }
    const body = response.body, length = response.headers.get("Content-Length");
    if (response.headers.get("Content-Type") !== "application/octet-stream" || response.headers.get("Content-Disposition") !== `attachment; filename="${filename}"` || !body || length === null || !/^\d+$/.test(length) || Number(length) !== input.file.bytes) {
      await body?.cancel().catch(() => undefined);
      throw new SiteApiError(0, "invalid_response", "The download did not match the saved file attachment or size.");
    }
    const reader = body.getReader(), chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      size += value.byteLength;
      if (size > maxBytes || size > input.file.bytes || !input.isLive()) {
        await reader.cancel().catch(() => undefined);
        throw new SiteApiError(0, "invalid_response", "The download exceeded its saved size or its context changed.");
      }
      chunks.push(value);
    }
    if (size !== input.file.bytes) throw new SiteApiError(0, "invalid_response", "The download did not match the saved file size.");
    const raw = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.byteLength; }
    const digest = await crypto.subtle.digest("SHA-256", raw);
    const actualSha256 = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (actualSha256 !== input.file.sha256) throw new SiteApiError(0, "invalid_response", "The downloaded file hash does not match the saved record. Your draft is kept.");
    if (!input.isLive()) throw new SiteApiError(401, "session_changed", "The download context changed. Review the file again.");
    return new Blob([raw], { type: "application/octet-stream" });
  } catch (error) {
    if (error instanceof SiteApiError) throw error;
    throw new SiteApiError(0, "connection_failed", "The file download could not be confirmed. Your draft is kept; refresh file records before trying again.");
  } finally { clearTimeout(timer); }
}

export async function importSiteArchive(input: { name: string; domain: string; archive: File; csrf: string }): Promise<Site> {
  const nameBytes = new TextEncoder().encode(input.name.trim()).length;
  const domainBytes = new TextEncoder().encode(input.domain.trim()).length;
  if (!input.name.trim() || nameBytes > 80 || !input.domain.trim() || input.domain.trim().length > 253 || domainBytes > 253 || !input.csrf) {
    throw new SiteApiError(422, "invalid_request", "Check the website name, domain and operator session before importing.");
  }
  if (!input.archive || input.archive.size === 0 || input.archive.size > maxTransferArchive) {
    throw new SiteApiError(413, "invalid_request", "Choose a nonempty ZIP archive up to 34 MiB.");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);
  const form = new FormData();
  form.append("name", input.name);
  form.append("domain", input.domain);
  // Windows choosers may label ZIPs application/x-zip-compressed. The server
  // validates archive bytes; normalize only this multipart part's MIME type.
  form.append("archive", input.archive.slice(0, input.archive.size, "application/zip"), input.archive.name || "site.zip");
  try {
    const response = await fetch("/api/v1/sites/import", {
      method: "POST", credentials: "same-origin", cache: "no-store", signal: controller.signal,
      headers: { Accept: "application/json", "X-CSRF-Token": input.csrf },
      body: form,
    });
    if (!response.ok) throw await transferError(response);
    const value = await readBoundedJson(response, 16 * 1024);
    if (!validSite(value)) throw new SiteApiError(0, "invalid_response", "The import response did not confirm a persisted website.");
    return value;
  } catch (error) {
    if (error instanceof SiteApiError) throw error;
    throw new SiteApiError(0, "connection_failed", "The import result could not be confirmed. Refresh websites before trying again.");
  } finally { clearTimeout(timer); }
}

// File bytes are encoded without text decoding, preserving arbitrary binary assets.
type SiteByteInput = { siteId: string; path: string; file: Blob; expectedRevision: number; csrf: string; isLive: () => boolean };
export const uploadSiteFile = (input: SiteByteInput): Promise<Site> => writeSiteFileBytes(input);
export function replaceSiteFile(input: SiteByteInput & { expectedSHA256: string }): Promise<Site> {
  if (!sha(input.expectedSHA256)) return Promise.reject(new SiteApiError(422, "invalid_request", "Review the saved file hash before replacing it."));
  return writeSiteFileBytes(input, input.expectedSHA256);
}
async function writeSiteFileBytes(input: SiteByteInput, expectedSHA256?: string): Promise<Site> {
  if (!id(input.siteId) || !path(input.path) || !count(input.expectedRevision) || input.expectedRevision < 1 || !input.csrf) throw new SiteApiError(422, "invalid_request", "Check the destination and website revision before uploading.");
  if (input.file.size > 2 * 1024 * 1024) throw new SiteApiError(413, "invalid_request", "Choose one static file up to 2 MiB.");
  const raw = new Uint8Array(await input.file.arrayBuffer());
  if (!input.isLive()) throw new SiteApiError(401, "session_changed", "The operator session changed before upload. Sign in and review the destination again.");
  if (raw.length !== input.file.size || raw.length > 2 * 1024 * 1024) throw new SiteApiError(413, "invalid_request", "The local file exceeded its expected size.");
  let binary = "";
  for (let offset = 0; offset < raw.length; offset += 8192) binary += String.fromCharCode(...raw.subarray(offset, offset + 8192));
  try {
    const site = await siteRequest(siteURL(input.siteId, "/upload"), validSite, { method: expectedSHA256 === undefined ? "POST" : "PUT", csrf: input.csrf, body: { path: input.path, content: btoa(binary), expected_revision: input.expectedRevision, ...(expectedSHA256 === undefined ? {} : { expected_sha256: expectedSHA256 }) } });
    if (site.id !== input.siteId || site.revision !== input.expectedRevision + 1) throw new SiteApiError(0, "invalid_response", "The upload did not confirm the expected website revision. Refresh file records before retrying.");
    return site;
  } catch (error) {
    if (error instanceof SiteApiError && error.status === 409) throw new SiteApiError(409, error.code, expectedSHA256 === undefined ? "The destination already exists or the website revision changed. Your selected file and path are kept; refresh file records and review them before confirming again." : "The saved file or website revision changed. Your selected replacement is kept; refresh records and explicitly review the latest target before confirming again.");
    if (error instanceof SiteApiError && error.status === 413) throw new SiteApiError(413, error.code, "The upload exceeds the request or 2 MiB file limit.");
    throw error;
  }
}
