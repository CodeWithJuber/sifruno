// Client for the Websites list: the WordPress sites the New website wizard
// made. The server joins the account broker (domain, state, certificate) with
// the wizard's jobs (versions, links, creation time). Reads only.

export interface WebsiteHttps {
  on: boolean;
  // RFC 3339, or empty when there is no certificate.
  not_after: string;
}
export interface Website {
  account_id: string;
  username: string;
  domain: string;
  // "active", "suspended" or "recovery_required" today; any other word is shown as unknown.
  state: string;
  https: WebsiteHttps;
  // Empty for a site made before the panel recorded it.
  php_version: string;
  wordpress_version: string;
  url: string;
  admin_url: string;
  created_at: string;
}

export const readTimeoutMs = 10000;

// ---- Reading the server's answers -----------------------------------------

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const date = (v: unknown): v is string => text(v) && Number.isFinite(Date.parse(v));
const shortText = (v: unknown, limit: number): v is string => text(v) && v.length <= limit && !/\p{Cc}/u.test(v);
export const validAccountId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);

// Only http and https links are ever offered to the person.
function webURL(v: unknown): v is string {
  if (!text(v)) return false;
  try { const url = new URL(v); return url.protocol === "http:" || url.protocol === "https:"; } catch { return false; }
}

export function parseWebsite(v: unknown): Website | undefined {
  if (!object(v) || !validAccountId(v.account_id) || !text(v.username) || !/^[a-z][a-z0-9_]{2,31}$/.test(v.username)) return undefined;
  if (!shortText(v.domain, 253) || !v.domain || !text(v.state) || !/^[a-z_]{1,40}$/.test(v.state)) return undefined;
  const https = v.https;
  if (!object(https) || typeof https.on !== "boolean" || !(https.not_after === "" || date(https.not_after))) return undefined;
  if (!shortText(v.php_version, 10) || !shortText(v.wordpress_version, 40) || !webURL(v.url) || !webURL(v.admin_url) || !date(v.created_at)) return undefined;
  return {
    account_id: v.account_id, username: v.username, domain: v.domain, state: v.state,
    https: { on: https.on, not_after: https.not_after as string },
    php_version: v.php_version, wordpress_version: v.wordpress_version, url: v.url, admin_url: v.admin_url, created_at: v.created_at,
  };
}

// The broker holds at most 2000 accounts.
export function parseWebsiteList(v: unknown): Website[] | undefined {
  if (!object(v) || !Array.isArray(v.sites) || v.sites.length > 2000) return undefined;
  const sites = v.sites.map(parseWebsite);
  return sites.some((site) => !site) ? undefined : sites as Website[];
}

// ---- What the page shows ------------------------------------------------------

export type StatusTone = "live" | "suspended" | "attention";

export function siteStatus(state: string): { label: string; tone: StatusTone } {
  switch (state) {
    case "active": return { label: "Live", tone: "live" };
    case "suspended": return { label: "Suspended", tone: "suspended" };
    case "recovery_required": return { label: "Needs review", tone: "attention" };
    default: return { label: "Unknown status", tone: "attention" };
  }
}

// "on": a certificate is installed and still valid. "expired": installed, but
// past its date. "off": none, the site uses http.
export type HttpsState = { kind: "on"; until?: Date } | { kind: "expired"; since: Date } | { kind: "off" };

export function httpsState(https: WebsiteHttps, now: Date = new Date()): HttpsState {
  if (!https.on) return { kind: "off" };
  if (!https.not_after) return { kind: "on" };
  const until = new Date(https.not_after);
  return until.getTime() <= now.getTime() ? { kind: "expired", since: until } : { kind: "on", until };
}

// A date without the time, in the reader's language and time zone.
export function dayLabel(value: Date | string, locale?: string): string {
  const day = typeof value === "string" ? new Date(value) : value;
  return Number.isNaN(day.getTime()) ? "Date unavailable" : new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(day);
}

// ---- Errors -----------------------------------------------------------------

type Operation = "list" | "read";

const whatFailed: Record<Operation, string> = {
  list: "Your websites could not be loaded.",
  read: "This website could not be loaded.",
};

// message is what happened; why and next are shown under it; technical goes
// under "Technical details".
export class WebsitesApiError extends Error {
  readonly status: number;
  readonly why: string;
  readonly next: string;
  readonly technical: string;
  constructor(status: number, what: string, why: string, next: string, technical: string) {
    super(what);
    this.name = "WebsitesApiError";
    this.status = status; this.why = why; this.next = next; this.technical = technical;
  }
}

// Server text is shown as text. Keep it short and on one line.
function serverText(v: unknown, limit = 500): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  switch (status) {
    case 401: return { why: "Your sign-in has ended.", next: "Sign in again to see your websites." };
    case 403: return { why: detail || "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return operation === "read"
      ? { why: detail || "That website was not found.", next: "Go back to Websites and choose it again. If it is not listed, it was removed." }
      : { why: detail || "The server does not know this request.", next: "Reload the page. If it happens again, the panel and the server may be different versions." };
    case 429: return { why: detail || "Too many requests in a short time.", next: "Wait a minute, then try again." };
    case 503: return { why: detail || "The account service or the website setup service is not available right now.", next: "Try again in a minute. If it keeps failing, check the Sifruno services on this server." };
    default: return { why: detail || `The server answered with an error (HTTP ${status}).`, next: "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

const unexpected = (operation: Operation, where: string) =>
  new WebsitesApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", `${where}: response did not match the websites contract`);

// ---- Requests ---------------------------------------------------------------

async function read(operation: Operation, url: string, signal?: AbortSignal): Promise<unknown> {
  const where = `GET ${url}`;
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, readTimeoutMs);
  const cancel = () => controller.abort();
  if (signal?.aborted) controller.abort();
  signal?.addEventListener("abort", cancel, { once: true });
  try {
    let response: Response;
    try {
      response = await fetch(url, { method: "GET", credentials: "same-origin", cache: "no-store", signal: controller.signal, headers: { Accept: "application/json" } });
    } catch {
      const seconds = Math.round(readTimeoutMs / 1000);
      if (timedOut) throw new WebsitesApiError(0, whatFailed[operation], `The server did not answer within ${seconds} seconds.`, "Try again. If it keeps happening, check the server's load.", `${where}: no answer within ${seconds} s`);
      const cancelled = Boolean(signal?.aborted);
      throw new WebsitesApiError(0, whatFailed[operation], cancelled ? "The request was cancelled." : "The panel could not reach its server.", "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const title = serverText(problem.title, 100);
      const { why, next } = explain(operation, response.status, serverText(problem.detail));
      throw new WebsitesApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${title ? ` (${title})` : ""}`);
    }
    return value;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
  }
}

export async function listWebsites(options: { signal?: AbortSignal } = {}): Promise<Website[]> {
  const url = "/api/v1/websites/sites";
  const sites = parseWebsiteList(await read("list", url, options.signal));
  if (!sites) throw unexpected("list", `GET ${url}`);
  return sites;
}

export async function getWebsite(accountId: string, options: { signal?: AbortSignal } = {}): Promise<Website> {
  if (!validAccountId(accountId)) throw new WebsitesApiError(404, whatFailed.read, "This address does not point to a website.", "Go back to Websites and choose the website there.", "account id in the address is not 32 lowercase hex characters; nothing was sent");
  const url = `/api/v1/websites/sites/${accountId}`;
  const site = parseWebsite(await read("read", url, options.signal));
  if (!site || site.account_id !== accountId) throw unexpected("read", `GET ${url}`);
  return site;
}
