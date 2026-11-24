import { validSession } from "./sites-api";

// Client for Websites: the WordPress sites the New website wizard made. The
// server joins the account broker (domain, state, certificate, PHP version)
// with the wizard's jobs (WordPress version, links, creation time). The site
// page's three changes are here too: PHP version, suspend or resume, delete.

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
  // Empty when the account service reports none.
  php_version: string;
  wordpress_version: string;
  url: string;
  admin_url: string;
  created_at: string;
  // The hosting account's revision. A change sends it back, so the server
  // can refuse a change made from a page that is out of date.
  revision: number;
}
// One site as its own page reads it: with the PHP versions installed on the
// server, which are the ones it can change to.
export interface WebsiteDetail extends Website {
  php_versions: string[];
}
// What a finished delete removed, in order, and what it left alone: a
// database or database user with the site's name that is not registered to it.
export interface WebsiteDeleted {
  domain: string;
  removed: string[];
  kept: string[];
}

export const readTimeoutMs = 10000;
// A change waits for the server, which waits for the account service: on a
// busy host a web server change takes minutes. The server answers a site
// action within 11 minutes.
export const actionTimeoutMs = 11.5 * 60 * 1000;

// ---- Reading the server's answers -----------------------------------------

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const date = (v: unknown): v is string => text(v) && Number.isFinite(Date.parse(v));
const shortText = (v: unknown, limit: number): v is string => text(v) && v.length <= limit && !/\p{Cc}/u.test(v);
const shortList = (v: unknown, limit: number): v is string[] => Array.isArray(v) && v.length <= 10 && v.every((item) => shortText(item, limit) && item !== "");
export const validAccountId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);
const phpVersion = (v: unknown): v is string => text(v) && /^\d\.\d$/.test(v);

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
  if (!Number.isSafeInteger(v.revision) || (v.revision as number) < 1) return undefined;
  return {
    account_id: v.account_id, username: v.username, domain: v.domain, state: v.state,
    https: { on: https.on, not_after: https.not_after as string },
    php_version: v.php_version, wordpress_version: v.wordpress_version, url: v.url, admin_url: v.admin_url, created_at: v.created_at,
    revision: v.revision as number,
  };
}

export function parseWebsiteDetail(v: unknown): WebsiteDetail | undefined {
  const site = parseWebsite(v);
  if (!site || !object(v) || !Array.isArray(v.php_versions) || v.php_versions.length > 10 || !v.php_versions.every(phpVersion)) return undefined;
  return { ...site, php_versions: [...v.php_versions] };
}

// The broker holds at most 2000 accounts.
export function parseWebsiteList(v: unknown): Website[] | undefined {
  if (!object(v) || !Array.isArray(v.sites) || v.sites.length > 2000) return undefined;
  const sites = v.sites.map(parseWebsite);
  return sites.some((site) => !site) ? undefined : sites as Website[];
}

export function parseWebsiteDeleted(v: unknown): WebsiteDeleted | undefined {
  if (!object(v) || !shortText(v.domain, 253) || !v.domain || !shortList(v.removed, 200) || !shortList(v.kept, 200)) return undefined;
  return { domain: v.domain, removed: [...v.removed], kept: [...v.kept] };
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

// What the site page's PHP action can do now. Only a live site can change,
// and only to a version installed on the server.
export type PhpChange = { kind: "ready"; versions: string[] } | { kind: "blocked"; why: string };

export function phpChange(site: WebsiteDetail): PhpChange {
  if (site.state === "suspended") return { kind: "blocked", why: "Resume the website to change its PHP version." };
  if (site.state !== "active") return { kind: "blocked", why: "The PHP version cannot change until the hosting account has been checked." };
  if (site.php_versions.length === 0) return { kind: "blocked", why: "The panel found no PHP versions installed on this server." };
  const versions = site.php_versions.filter((version) => version !== site.php_version);
  if (versions.length === 0) return { kind: "blocked", why: `PHP ${site.php_version} is the only version installed on this server.` };
  return { kind: "ready", versions };
}

// A sentence for the end of a delete: what went, and what was left alone.
export function deletedSummary(done: WebsiteDeleted): string {
  const removed = done.removed.length ? `Removed: ${done.removed.join(", ")}.` : "";
  const kept = done.kept.length ? ` Left on the server, because it is not registered to this website: ${done.kept.join(", ")}.` : "";
  return `${removed}${kept}`.trim();
}

// ---- Errors -----------------------------------------------------------------

type Operation = "list" | "read" | "php" | "suspend" | "resume" | "delete";
const changes: readonly Operation[] = ["php", "suspend", "resume", "delete"];
const isChange = (operation: Operation) => changes.includes(operation);

const whatFailed: Record<Operation, string> = {
  list: "Your websites could not be loaded.",
  read: "This website could not be loaded.",
  php: "The PHP version was not changed.",
  suspend: "The website was not suspended.",
  resume: "The website was not resumed.",
  delete: "The website was not deleted.",
};
const notConfirmed = "The panel could not confirm the change.";
const seeItNow = "Reload the page to see the website as it is now before you try again.";

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

const rejectedNext: Partial<Record<Operation, string>> = {
  php: "Choose another PHP version, or ask whoever runs this server to check the web server.",
  suspend: "Try again after the web server has been checked.",
  resume: "Try again after the web server has been checked.",
  delete: "Type the website's domain exactly as it is shown, then try again.",
};

function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  const change = isChange(operation);
  const versions = "Reload the page. If it happens again, the panel and the server may be different versions.";
  switch (status) {
    case 400: case 415: return { why: detail || "The server could not read the request.", next: versions };
    case 401: return { why: "Your sign-in has ended.", next: change ? "Sign in again, then try again." : "Sign in again to see your websites." };
    case 403: return { why: detail || "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return operation === "list"
      ? { why: detail || "The server does not know this request.", next: versions }
      : { why: detail || "That website was not found.", next: "Go back to Websites and choose it again. If it is not listed, it was removed." };
    case 409: return { why: detail || "The website changed or was busy.", next: seeItNow };
    case 422: return { why: detail || "The server did not accept the request.", next: rejectedNext[operation] ?? versions };
    case 429: return { why: detail || "Too many requests in a short time.", next: "Wait a minute, then try again." };
    case 503: return { why: detail || "The account service or the website setup service is not available right now.", next: change ? `${seeItNow} If it keeps failing, check the Sifruno services on this server.` : "Try again in a minute. If it keeps failing, check the Sifruno services on this server." };
    default: return { why: detail || `The server answered with an error (HTTP ${status}).`, next: change ? seeItNow : "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

// After a change was sent, an answer the panel cannot read does not mean
// nothing happened.
const unexpected = (operation: Operation, where: string) => isChange(operation)
  ? new WebsitesApiError(0, notConfirmed, "The server's answer was not in the form the panel expects, so the panel cannot tell whether the change was made.", seeItNow, `${where}: response did not match the websites contract`)
  : new WebsitesApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", `${where}: response did not match the websites contract`);

// ---- Requests ---------------------------------------------------------------

interface RequestOptions { method?: "GET" | "POST"; body?: unknown; csrf?: string; timeoutMs: number; signal?: AbortSignal; note?: string }

function waited(ms: number): string {
  return ms < 60000 ? `${Math.round(ms / 1000)} seconds` : `${Math.round(ms / 60000)} minutes`;
}

async function request(operation: Operation, url: string, options: RequestOptions): Promise<unknown> {
  const method = options.method ?? "GET";
  const where = `${method} ${url}`;
  const note = options.note ? `; ${options.note}` : "";
  // Once a change is on its way, a lost answer leaves its outcome unknown.
  const sent = method === "POST";
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
          ...(sent ? { "Content-Type": "application/json" } : {}),
          ...(options.csrf ? { "X-CSRF-Token": options.csrf } : {}),
        },
        ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      });
    } catch {
      const what = sent ? notConfirmed : whatFailed[operation];
      if (timedOut) throw new WebsitesApiError(0, what, `The server did not answer within ${waited(options.timeoutMs)}.`, sent ? seeItNow : "Try again. If it keeps happening, check the server's load.", `${where}: no answer within ${Math.round(options.timeoutMs / 1000)} s${note}`);
      const cancelled = Boolean(options.signal?.aborted);
      const why = cancelled ? "The request was cancelled." : sent ? "The panel lost its connection to the server before it answered. The change may still finish." : "The panel could not reach its server.";
      throw new WebsitesApiError(0, what, why, sent ? seeItNow : "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}${note}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const title = serverText(problem.title, 100);
      // The server puts its own word for the failure in the first error.
      const first = Array.isArray(problem.errors) && object(problem.errors[0]) ? serverText(problem.errors[0].message, 300) : "";
      const { why, next } = explain(operation, response.status, serverText(problem.detail, 900));
      throw new WebsitesApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${title ? ` (${title})` : ""}${first ? `; ${first}` : ""}${note}`);
    }
    return value;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}

export async function listWebsites(options: { signal?: AbortSignal } = {}): Promise<Website[]> {
  const url = "/api/v1/websites/sites";
  const sites = parseWebsiteList(await request("list", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!sites) throw unexpected("list", `GET ${url}`);
  return sites;
}

export async function getWebsite(accountId: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteDetail> {
  if (!validAccountId(accountId)) throw new WebsitesApiError(404, whatFailed.read, "This address does not point to a website.", "Go back to Websites and choose the website there.", "account id in the address is not 32 lowercase hex characters; nothing was sent");
  const url = `/api/v1/websites/sites/${accountId}`;
  const site = parseWebsiteDetail(await request("read", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!site || site.account_id !== accountId) throw unexpected("read", `GET ${url}`);
  return site;
}

// The CSRF token comes from the current session, as for every other change
// the panel makes. Nothing has been sent yet if this fails.
async function csrfToken(operation: Operation, signal?: AbortSignal): Promise<string> {
  const ended = (technical: string) => new WebsitesApiError(401, whatFailed[operation], "Your sign-in has ended.", "Sign in again, then try again.", technical);
  let value: unknown;
  try {
    value = await request(operation, "/api/v1/session", { timeoutMs: readTimeoutMs, signal });
  } catch (error) {
    if (error instanceof WebsitesApiError && error.status === 401) throw ended("GET /api/v1/session returned HTTP 401");
    throw error;
  }
  if (!validSession(value)) throw new WebsitesApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", "GET /api/v1/session: response did not match the session contract; nothing was changed");
  if (!value.authenticated) throw ended("GET /api/v1/session: not signed in");
  return value.csrf_token;
}

// One change to one site: the body's own field plus the revision the page
// has. The revision is named under "Technical details" when it fails.
async function change(operation: Operation, site: Website, action: "php" | "state" | "delete", field: Record<string, string>, signal?: AbortSignal): Promise<unknown> {
  if (!validAccountId(site.account_id)) throw new WebsitesApiError(404, whatFailed[operation], "This page does not point to a website.", "Go back to Websites and choose the website there.", "account id is not 32 lowercase hex characters; nothing was sent");
  const csrf = await csrfToken(operation, signal);
  const url = `/api/v1/websites/sites/${site.account_id}/${action}`;
  return request(operation, url, { method: "POST", body: { ...field, expected_revision: site.revision }, csrf, timeoutMs: actionTimeoutMs, signal, note: `expected revision ${site.revision}` });
}

function changedSite(operation: Operation, site: Website, action: string, value: unknown): WebsiteDetail {
  const next = parseWebsiteDetail(value);
  if (!next || next.account_id !== site.account_id) throw unexpected(operation, `POST /api/v1/websites/sites/${site.account_id}/${action}`);
  return next;
}

// Runs the site with another PHP version; its disk quota stays as it is.
export async function changePhpVersion(site: Website, version: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteDetail> {
  return changedSite("php", site, "php", await change("php", site, "php", { php_version: version }, options.signal));
}

// Suspended, the site answers every visitor with an error page; active, it
// serves again.
export async function setWebsiteState(site: Website, state: "active" | "suspended", options: { signal?: AbortSignal } = {}): Promise<WebsiteDetail> {
  const operation = state === "suspended" ? "suspend" : "resume";
  return changedSite(operation, site, "state", await change(operation, site, "state", { state }, options.signal));
}

// Deletes the site: its database, its hosting account and its files. The
// person types the domain; the server checks it again.
export async function deleteWebsite(site: Website, confirmDomain: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteDeleted> {
  const done = parseWebsiteDeleted(await change("delete", site, "delete", { confirm_domain: confirmDomain }, options.signal));
  if (!done || done.domain !== site.domain) throw unexpected("delete", `POST /api/v1/websites/sites/${site.account_id}/delete`);
  return done;
}
