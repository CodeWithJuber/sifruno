import { SiteApiError, siteRequest, validSession } from "./sites-api";

// expires_at is the hard limit: 12 hours, or 7 days for "Keep me signed in on this
// device". A session ends sooner after idle_seconds (kept: kept_idle_seconds) unused.
export interface AccessSession { id: string; created_at: string; expires_at: string; current: boolean; kept_signed_in: boolean }
export interface AccessInventory { items: AccessSession[]; capacity: 128; idle_seconds: 1800; kept_idle_seconds: 86400 }
const hardLimit = { normal: 12 * 3600_000, kept: 7 * 24 * 3600_000 };
export interface Revocation { revoked_count: number }

const object = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const exact = (value: Record<string, unknown>, fields: string[]) => Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const handle = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
const isoDate = (value: unknown): value is string => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value.replace(/Z$/, ".000Z");

export function validAccessSession(value: unknown): value is AccessSession {
  return object(value) && exact(value, ["id", "created_at", "expires_at", "current", "kept_signed_in"]) && handle(value.id) && isoDate(value.created_at) && isoDate(value.expires_at) && typeof value.kept_signed_in === "boolean" && Date.parse(value.expires_at) - Date.parse(value.created_at) === (value.kept_signed_in ? hardLimit.kept : hardLimit.normal) && typeof value.current === "boolean";
}
export function validAccessInventory(value: unknown): value is AccessInventory {
  return object(value) && exact(value, ["items", "capacity", "idle_seconds", "kept_idle_seconds"]) && value.capacity === 128 && value.idle_seconds === 1800 && value.kept_idle_seconds === 86400 && Array.isArray(value.items) && value.items.length >= 1 && value.items.length <= 128 && value.items.every(validAccessSession) && new Set(value.items.map((item) => item.id)).size === value.items.length && value.items.filter((item) => item.current).length === 1;
}
export function validRevocation(value: unknown): value is Revocation {
  return object(value) && exact(value, ["revoked_count"]) && Number.isSafeInteger(value.revoked_count) && (value.revoked_count as number) >= 0 && (value.revoked_count as number) <= 127;
}

export const getAccessSession = () => siteRequest("/api/v1/session", validSession, { unauthenticatedSession: true });
export const loginAccessSession = (accessKey: string) => siteRequest("/api/v1/session/login", validSession, { method: "POST", body: { access_key: accessKey } });
export const logoutAccessSession = (csrf: string) => siteRequest("/api/v1/session/logout", validSession, { method: "POST", csrf, body: {} });
export const getAccessInventory = () => siteRequest("/api/v1/session/sessions", validAccessInventory);
export function revokeAccessSession(id: string, csrf: string) {
  if (!handle(id)) throw new SiteApiError(400, "invalid_session", "The selected session is invalid. Refresh the session list.");
  return siteRequest(`/api/v1/session/sessions/${id}/revoke`, (value): value is Revocation => validRevocation(value) && value.revoked_count === 1, { method: "POST", csrf, body: {} });
}
export const revokeOtherAccessSessions = (csrf: string) => siteRequest("/api/v1/session/revoke-others", validRevocation, { method: "POST", csrf, body: {} });

export function accessError(failure: unknown): string {
  if (failure instanceof SiteApiError) {
    if (failure.status === 401) return "Your local operator session expired or was revoked. Sign in again to manage access.";
    if (failure.status === 403) return "Your session or request origin was rejected. Refresh your session before trying again.";
    if (failure.status === 404) return "That session has expired or was already revoked. Refresh the session list.";
    if (failure.status === 409) return "The current session cannot be revoked here. Use Sign out locally to end it.";
    if (failure.status === 400) return "The session request was rejected. Refresh the session list before trying again.";
    if (failure.status === 429) return "Too many sign-in attempts. Wait before trying again.";
  }
  return "The access request could not be confirmed. Refresh the session list before trying again.";
}
