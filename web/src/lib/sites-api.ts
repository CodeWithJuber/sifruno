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
  options: { method?: "GET" | "POST" | "PUT"; body?: unknown; csrf?: string; unauthenticatedSession?: boolean } = {},
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
export const previewURL = (site: Site) => validSite(site) ? `http://${site.preview_host}:8082/` : undefined;
