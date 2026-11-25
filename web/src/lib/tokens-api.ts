import { validSession } from "./sites-api";

// Client for the API tokens page. The server makes each token, keeps only a
// keyed hash of it and returns it once, in the create answer. The panel holds
// it in memory until the person hides it: never in storage, the URL, a log or
// an error message. The checks here mirror the server's so the form can say
// what is wrong before anything is sent; the server stays the authority.

export interface ApiToken {
  id: string;
  name: string;
  // The token's first 10 characters, to tell tokens apart.
  prefix: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  expired: boolean;
}
export interface TokenList { items: ApiToken[]; capacity: number }
export interface CreatedToken extends ApiToken { token: string }

export const expiryChoices = [7, 30, 90, 180, 365] as const;
export const defaultExpiryDays = 90;
export const maxExpiryDays = 365;
export const maxTokenName = 64;
export const readTimeoutMs = 10000;
export const writeTimeoutMs = 20000;

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const exact = (v: ObjectValue, fields: readonly string[]) => Object.keys(v).length === fields.length && fields.every((field) => Object.hasOwn(v, field));
const timestamp = (v: unknown): v is string => text(v) && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v));
export const validTokenId = (v: unknown): v is string => text(v) && /^[0-9a-f]{32}$/.test(v);
const validPrefix = (v: unknown): v is string => text(v) && /^sfr_[A-Za-z0-9_-]{6}$/.test(v);
const validSecret = (v: unknown): v is string => text(v) && /^sfr_[A-Za-z0-9_-]{43}$/.test(v);

// ---- Checks that mirror the server ----------------------------------------

export function checkTokenName(value: string): string | undefined {
  if (!value.trim()) return "Give the token a name that says where it is used, such as WHMCS.";
  if ([...value].length > maxTokenName) return `Use a name of at most ${maxTokenName} characters.`;
  if (value !== value.trim()) return "Remove the spaces at the start and end of the name.";
  if (/[\p{Cc}\p{Cf}]/u.test(value)) return "Remove line breaks, tabs and other invisible characters from the name.";
  return undefined;
}

export function checkExpiryDays(days: number): string | undefined {
  return Number.isInteger(days) && days >= 1 && days <= maxExpiryDays ? undefined : "Choose an expiry from 1 to 365 days. A token cannot last longer than a year.";
}

// When a token made now with this expiry stops working, for the form's hint.
export function expiresOn(days: number, from: Date = new Date()): Date {
  return new Date(from.getTime() + days * 24 * 60 * 60 * 1000);
}

// ---- Reading the server's answers -------------------------------------------

const tokenFields = ["id", "name", "prefix", "created_at", "expires_at", "last_used_at", "expired"] as const;

function tokenShape(v: ObjectValue): boolean {
  return validTokenId(v.id) && text(v.name) && checkTokenName(v.name) === undefined && validPrefix(v.prefix) && timestamp(v.created_at) && timestamp(v.expires_at)
    && Date.parse(v.expires_at) > Date.parse(v.created_at) && (v.last_used_at === null || timestamp(v.last_used_at)) && typeof v.expired === "boolean";
}

export function parseToken(v: unknown): ApiToken | undefined {
  if (!object(v) || !exact(v, tokenFields) || !tokenShape(v)) return undefined;
  return { id: v.id as string, name: v.name as string, prefix: v.prefix as string, created_at: v.created_at as string, expires_at: v.expires_at as string, last_used_at: v.last_used_at as string | null, expired: v.expired as boolean };
}

export function parseCreatedToken(v: unknown): CreatedToken | undefined {
  if (!object(v) || !exact(v, [...tokenFields, "token"]) || !tokenShape(v) || !validSecret(v.token) || !v.token.startsWith(v.prefix as string)) return undefined;
  const { token, ...rest } = v;
  const listed = parseToken(rest);
  return listed && { ...listed, token };
}

export function parseTokenList(v: unknown): TokenList | undefined {
  if (!object(v) || !exact(v, ["items", "capacity"]) || !Array.isArray(v.items) || !Number.isSafeInteger(v.capacity) || (v.capacity as number) < 1 || v.items.length > (v.capacity as number)) return undefined;
  const items: ApiToken[] = [];
  for (const item of v.items as unknown[]) {
    const token = parseToken(item);
    if (!token) return undefined;
    items.push(token);
  }
  if (new Set(items.map((item) => item.id)).size !== items.length) return undefined;
  return { items, capacity: v.capacity as number };
}

// ---- Errors -----------------------------------------------------------------

export type Operation = "list" | "create" | "revoke";

export const whatFailed: Record<Operation, string> = {
  list: "The API tokens could not be loaded.",
  create: "The token was not created.",
  revoke: "The token was not revoked.",
};

// message is what happened; why and next are shown under it; technical goes
// under "Technical details". None of them ever holds a token.
export class TokensApiError extends Error {
  readonly status: number;
  readonly why: string;
  readonly next: string;
  readonly technical: string;
  constructor(status: number, what: string, why: string, next: string, technical: string) {
    super(what);
    this.name = "TokensApiError";
    this.status = status; this.why = why; this.next = next; this.technical = technical;
  }
}

function serverText(v: unknown, limit = 300): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

function explain(operation: Operation, status: number, code: string, detail: string): { why: string; next: string } {
  const versions = "Reload the page and try again. If it happens again, the panel and the server may be different versions.";
  switch (status) {
    case 400: return { why: detail || "The server could not read the request.", next: versions };
    case 401: return { why: "Your sign-in has ended.", next: operation === "list" ? "Sign in again to see the tokens." : "Sign in again, then try again." };
    case 403: return { why: "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return { why: "That token is not on the list. It may have been revoked already.", next: "Refresh the list." };
    case 409: return code === "token_limit"
      ? { why: "The panel keeps at most 32 API tokens.", next: "Revoke a token you no longer use, then try again." }
      : { why: "Another token already has this name.", next: "Choose a different name, then try again." };
    case 422: return { why: detail || "The server did not accept the name or the expiry.", next: "Fix the marked value, then try again." };
    case 429: return { why: "Too many requests in a short time.", next: "Wait a minute, then try again." };
    case 503: return { why: "The server could not save or read the tokens right now.", next: "Try again in a minute. If it keeps failing, check the panel's disk and the Sifruno service." };
    default: return { why: `The server answered with an error (HTTP ${status}).`, next: "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

const unexpected = (operation: Operation, where: string) =>
  new TokensApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", operation === "list" ? "Reload the page. If it happens again, the panel and the server may be different versions." : "Refresh the list to see whether the change was made before you try again.", `${where}: response did not match the API tokens contract`);

const notSent = (operation: Operation, why: string) =>
  new TokensApiError(422, whatFailed[operation], why, "Fix the marked field, then try again.", "not sent: the value failed the panel's checks");

// ---- Requests ---------------------------------------------------------------

interface RequestOptions { method?: "GET" | "POST"; body?: unknown; csrf?: string; timeoutMs: number; signal?: AbortSignal }

async function request(operation: Operation, url: string, options: RequestOptions): Promise<unknown> {
  const method = options.method ?? "GET";
  const where = `${method} ${url}`;
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, options.timeoutMs);
  const cancel = () => controller.abort();
  if (options.signal?.aborted) controller.abort();
  options.signal?.addEventListener("abort", cancel, { once: true });
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        method, credentials: "same-origin", cache: "no-store", signal: controller.signal,
        headers: {
          Accept: "application/json",
          ...(method === "POST" ? { "Content-Type": "application/json" } : {}),
          ...(options.csrf ? { "X-CSRF-Token": options.csrf } : {}),
        },
        ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      });
    } catch {
      const seconds = Math.round(options.timeoutMs / 1000);
      if (timedOut) {
        const written = method === "POST" && Boolean(options.csrf);
        throw new TokensApiError(0, written ? "The panel could not confirm the change." : whatFailed[operation], `The server did not answer within ${seconds} seconds.`, written ? "Refresh the list to see whether the change was made before you try again." : "Try again. If it keeps happening, check the server's load.", `${where}: no answer within ${seconds} s`);
      }
      const cancelled = Boolean(options.signal?.aborted);
      throw new TokensApiError(0, whatFailed[operation], cancelled ? "The request was cancelled." : "The panel could not reach its server.", "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const code = text(problem.error) && /^[a-z_]+$/.test(problem.error) ? problem.error : "";
      const detail = serverText(problem.detail);
      const { why, next } = explain(operation, response.status, code, detail);
      throw new TokensApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${code ? ` (${code})` : ""}${detail && detail !== why ? `: ${detail}` : ""}`);
    }
    return value;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}

// The CSRF token comes from the current session, as for every other change
// the panel makes.
async function csrfToken(operation: Operation, signal?: AbortSignal): Promise<string> {
  const ended = (technical: string) => new TokensApiError(401, whatFailed[operation], "Your sign-in has ended.", "Sign in again, then try again.", technical);
  let value: unknown;
  try {
    value = await request(operation, "/api/v1/session", { timeoutMs: readTimeoutMs, signal });
  } catch (error) {
    if (error instanceof TokensApiError && error.status === 401) throw ended("GET /api/v1/session returned HTTP 401");
    throw error;
  }
  if (!validSession(value)) throw unexpected(operation, "GET /api/v1/session");
  if (!value.authenticated) throw ended("GET /api/v1/session: not signed in");
  return value.csrf_token;
}

const base = "/api/v1/session/tokens";

export async function listApiTokens(options: { signal?: AbortSignal } = {}): Promise<TokenList> {
  const list = parseTokenList(await request("list", base, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!list) throw unexpected("list", `GET ${base}`);
  return list;
}

export async function createApiToken(name: string, days: number, options: { signal?: AbortSignal } = {}): Promise<CreatedToken> {
  const problem = checkTokenName(name) ?? checkExpiryDays(days);
  if (problem) throw notSent("create", problem);
  const csrf = await csrfToken("create", options.signal);
  // Exactly the two keys the server accepts.
  const created = parseCreatedToken(await request("create", base, { method: "POST", body: { name, expires_in_days: days }, csrf, timeoutMs: writeTimeoutMs, signal: options.signal }));
  if (!created || created.name !== name) throw unexpected("create", `POST ${base}`);
  return created;
}

export async function revokeApiToken(id: string, options: { signal?: AbortSignal } = {}): Promise<ApiToken> {
  if (!validTokenId(id)) throw new TokensApiError(404, whatFailed.revoke, "That is not a token the panel made.", "Refresh the list.", "the token id is not in the expected form; nothing was sent");
  const csrf = await csrfToken("revoke", options.signal);
  const url = `${base}/${id}/revoke`;
  const revoked = parseToken(await request("revoke", url, { method: "POST", body: {}, csrf, timeoutMs: writeTimeoutMs, signal: options.signal }));
  if (!revoked || revoked.id !== id) throw unexpected("revoke", `POST ${url}`);
  return revoked;
}
