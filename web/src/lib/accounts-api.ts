import { validSession } from "@/lib/sites-api";
import type { OperatorSession } from "@/lib/sites-api";

export interface Account {
  id: string;
  username: string;
  domain: string;
  home: string;
  public_html: string;
  state: "active" | "suspended" | "recovery_required";
  uid: number;
  gid: number;
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface AccountsCapability {
  available: boolean;
  reason: string;
  backend: string;
  restrictions: string[];
}
export const ACCOUNT_RECOVERY_REQUIRED = "managed_account_recovery_required";

type AccountResponse = { items: Account[] };
type ObjectValue = Record<string, unknown>;
const object = (value: unknown): value is ObjectValue => typeof value === "object" && value !== null && !Array.isArray(value);
const text = (value: unknown): value is string => typeof value === "string";
const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const date = (value: unknown) => text(value) && Number.isFinite(Date.parse(value));
const domainLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function validAccountDomain(value: string): boolean {
  const domain = value.trim();
  if (!domain || new TextEncoder().encode(domain).length > 253) return false;
  const labels = domain.split(".");
  if (labels.length < 2 || labels.some((label) => !domainLabel.test(label))) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain) && domain.split(".").every((part) => Number(part) <= 255)) return false;
  return true;
}

export function validAccountReason(value: string): boolean {
  const reason = value.trim();
  return new TextEncoder().encode(reason).length >= 1 && new TextEncoder().encode(reason).length <= 500 && !/[\u0000-\u001f\u007f-\u009f]/.test(reason);
}

export function validAccount(value: unknown): value is Account {
  return object(value) && text(value.id) && value.id.length > 0 && value.id.length <= 128 &&
    text(value.username) && text(value.domain) && text(value.home) && text(value.public_html) &&
    ["active", "suspended", "recovery_required"].includes(String(value.state)) &&
    count(value.uid) && count(value.gid) && count(value.revision) && date(value.created_at) && date(value.updated_at);
}

export function validAccountList(value: unknown): value is AccountResponse {
  return object(value) && Array.isArray(value.items) && value.items.every(validAccount);
}

export function validAccountsCapability(value: unknown): value is AccountsCapability {
  return object(value) && typeof value.available === "boolean" && text(value.reason) && text(value.backend) &&
    Array.isArray(value.restrictions) && value.restrictions.every(text);
}

export const validAccountsSession = validSession;
export type AccountsSession = OperatorSession;

export class AccountsApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}

function message(status: number): string {
  if (status === 401) return "Your local operator session is missing or expired. Sign in again; your form values are kept.";
  if (status === 403) return "The local operator session or request origin was rejected. Refresh the session and try again.";
  if (status === 404) return "The account was not found. Refresh the account list before trying again.";
  if (status === 409) return "The account changed or already exists. Your form values are kept; refresh and review before retrying.";
  if (status === 422) return "Check the username, domain and action reason. No change was confirmed.";
  if (status === 429) return "Too many sign-in attempts. Wait before trying again.";
  if (status === 503) return "The Linux account broker is unavailable. No account change was confirmed.";
  return `The local account service returned HTTP ${status}. No change was confirmed.`;
}

async function request<T>(
  url: string,
  validate: (value: unknown) => value is T,
  options: { method?: "GET" | "POST"; body?: unknown; csrf?: string; allowSignedOut?: boolean } = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 50000);
  try {
    const response = await fetch(url, {
      method,
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(method === "POST" ? { "Content-Type": "application/json" } : {}),
        ...(options.csrf ? { "X-CSRF-Token": options.csrf } : {}),
      },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
    });
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok && !(options.allowSignedOut && response.status === 401 && validAccountsSession(value) && !value.authenticated)) {
      const code = object(value) && text(value.error) && /^[a-z_]+$/.test(value.error) ? value.error : "request_failed";
      throw new AccountsApiError(response.status, code, message(response.status));
    }
    if (!validate(value)) throw new AccountsApiError(0, "invalid_response", "The local service returned data outside the Accounts contract. No change was confirmed.");
    return value;
  } catch (error) {
    if (error instanceof AccountsApiError) throw error;
    throw new AccountsApiError(0, "connection_failed", "The local operation could not be confirmed. Your form values are kept; refresh before retrying.");
  } finally {
    clearTimeout(timer);
  }
}

export const getAccountsSession = () => request("/api/v1/session", validAccountsSession, { allowSignedOut: true });
export const loginAccountsSession = (accessKey: string) => request("/api/v1/session/login", validAccountsSession, { method: "POST", body: { access_key: accessKey } });
export const logoutAccountsSession = (csrf: string) => request("/api/v1/session/logout", validAccountsSession, { method: "POST", body: {}, csrf });
export const getAccountsCapability = () => request("/api/v1/accounts/capability", validAccountsCapability);
export const getAccounts = () => request("/api/v1/accounts", validAccountList);
export const createAccount = (body: { username: string; domain: string; reason: string }, csrf: string) => request("/api/v1/accounts", validAccount, { method: "POST", body, csrf });
export const setAccountState = (account: Account, state: "active" | "suspended", reason: string, csrf: string) =>
  request(`/api/v1/accounts/${encodeURIComponent(account.id)}/state`, validAccount, {
    method: "POST", csrf, body: { state, expected_revision: account.revision, reason },
  });
