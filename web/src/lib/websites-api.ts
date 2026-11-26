import { validSession } from "./sites-api";

// Client for Websites: the WordPress and PHP sites the New website wizard
// made. The
// server joins the account broker (domain, state, certificate, PHP version)
// with the wizard's jobs (WordPress version, links, creation time). The site
// page's changes are here too: PHP version, suspend or resume (or suspend
// again), using the account's current public_html, and delete.

export interface WebsiteHttps {
  on: boolean;
  // RFC 3339, or empty when there is no certificate.
  not_after: string;
  // "copied": the certificate in force was copied from the old server when
  // the website moved here.
  source?: "copied";
}
// What all of the hosting account's processes may use together. The plan
// sets them; the site page only shows them.
export interface WebsiteLimits {
  processes: number;
  memory_mib: number;
  // 100 is one CPU.
  cpu_percent: number;
}
export interface Website {
  account_id: string;
  username: string;
  domain: string;
  // What the wizard made. A PHP site has no WordPress: its
  // wordpress_version and admin_url are empty.
  kind: "wordpress" | "php";
  // "active", "suspended", "recovery_required" or "partly_deleted" (a delete
  // removed the hosting account but not yet the database) today; any other
  // word is shown as unknown.
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
  // The hosting account itself renamed, replaced or removed public_html, or
  // changed the permissions of its home or public_html. It concerns this
  // site only.
  site_folder_changed: boolean;
  // Left out when the server reports none (a partly deleted site).
  limits?: WebsiteLimits;
  // In the list only, and only when the account service answered in time.
  usage?: WebsiteUsage;
  // The site's other domains, which serve the same site, and how many
  // redirects it has; empty and 0 from a server before domains.
  aliases: WebsiteAliasSummary[];
  redirect_count: number;
}
// Disk use against the quota, and the response bytes the site served this
// month by its access log. traffic_complete is false while older log lines
// are still being counted, so the number can still grow.
export interface WebsiteUsage {
  disk_used_bytes: number;
  // 0 when no quota is set.
  disk_limit_bytes: number;
  // YYYY-MM on the server's clock.
  traffic_month: string;
  traffic_bytes: number;
  traffic_complete: boolean;
}
const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
export function parseWebsiteUsage(v: unknown): WebsiteUsage | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const u = v as Record<string, unknown>;
  if (!count(u.disk_used_bytes) || !count(u.disk_limit_bytes) || !count(u.traffic_bytes) || typeof u.traffic_complete !== "boolean") return undefined;
  if (typeof u.traffic_month !== "string" || !/^\d{4}-(0[1-9]|1[0-2])$/.test(u.traffic_month)) return undefined;
  return { disk_used_bytes: u.disk_used_bytes, disk_limit_bytes: u.disk_limit_bytes, traffic_month: u.traffic_month, traffic_bytes: u.traffic_bytes, traffic_complete: u.traffic_complete };
}
// One of the site's other domains and what its HTTPS is: "on" (the
// certificate covers it), "waiting_for_dns", "pending" or "off".
export interface WebsiteAliasSummary { name: string; https: string }
// One site as its own page reads it: with the PHP versions installed on the
// server, which are the ones it can change to.
export interface WebsiteDetail extends Website {
  php_versions: string[];
}
// What a finished delete removed, in order, and what it left alone: a
// database or database user with the site's name that is not registered to it.
// suspended_first: the site's processes kept running, so the panel suspended
// the site and asked for the delete again.
export interface WebsiteDeleted {
  domain: string;
  removed: string[];
  kept: string[];
  suspended_first?: true;
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
  if (!object(https) || typeof https.on !== "boolean" || !(https.not_after === "" || date(https.not_after)) || !(https.source === undefined || https.source === "copied")) return undefined;
  if (v.kind !== "wordpress" && v.kind !== "php") return undefined;
  if (!shortText(v.php_version, 10) || !shortText(v.wordpress_version, 40) || !webURL(v.url) || !date(v.created_at)) return undefined;
  if (v.kind === "wordpress" ? !webURL(v.admin_url) : v.admin_url !== "" || v.wordpress_version !== "") return undefined;
  if (!Number.isSafeInteger(v.revision) || (v.revision as number) < 1 || typeof v.site_folder_changed !== "boolean") return undefined;
  const limits = v.limits === undefined ? undefined : parseLimits(v.limits);
  if (v.limits !== undefined && !limits) return undefined;
  const usage = v.usage === undefined ? undefined : parseWebsiteUsage(v.usage);
  if (v.usage !== undefined && !usage) return undefined;
  const aliases = parseAliasSummaries(v.aliases);
  const redirectCount = v.redirect_count === undefined ? 0 : v.redirect_count;
  if (!aliases || !Number.isSafeInteger(redirectCount) || (redirectCount as number) < 0) return undefined;
  return {
    account_id: v.account_id, username: v.username, domain: v.domain, kind: v.kind, state: v.state,
    https: { on: https.on, not_after: https.not_after as string, ...(https.source === "copied" ? { source: "copied" as const } : {}) },
    php_version: v.php_version, wordpress_version: v.wordpress_version, url: v.url, admin_url: v.admin_url as string, created_at: v.created_at,
    revision: v.revision as number, site_folder_changed: v.site_folder_changed,
    ...(limits ? { limits } : {}),
    ...(usage ? { usage } : {}),
    aliases, redirect_count: redirectCount as number,
  };
}

// The site's other domains as the list shows them. A server before domains
// sends neither key.
function parseAliasSummaries(v: unknown): WebsiteAliasSummary[] | undefined {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > 15) return undefined;
  const out: WebsiteAliasSummary[] = [];
  for (const item of v) {
    if (!object(item) || !shortText(item.name, 253) || !item.name || !text(item.https) || !/^[a-z_]{1,20}$/.test(item.https)) return undefined;
    out.push({ name: item.name, https: item.https });
  }
  return out;
}

const positive = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0;
function parseLimits(v: unknown): WebsiteLimits | undefined {
  if (!object(v) || !positive(v.processes) || !positive(v.memory_mib) || !positive(v.cpu_percent)) return undefined;
  return { processes: v.processes, memory_mib: v.memory_mib, cpu_percent: v.cpu_percent };
}

// The limits in plain words: "up to 100 processes, 1 GB of memory and 1 CPU".
export function limitsSummary(limits: WebsiteLimits): string {
  const gb = limits.memory_mib / 1024;
  const memory = limits.memory_mib >= 1024 ? `${Number.isInteger(gb) ? gb : gb.toFixed(1)} GB` : `${limits.memory_mib} MB`;
  const cpus = limits.cpu_percent / 100;
  const cpu = Number.isInteger(cpus) ? `${cpus} CPU${cpus === 1 ? "" : "s"}` : `${limits.cpu_percent}% of one CPU`;
  return `Up to ${limits.processes} processes, ${memory} of memory and ${cpu}`;
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
  if (v.suspended_first !== undefined && typeof v.suspended_first !== "boolean") return undefined;
  return { domain: v.domain, removed: [...v.removed], kept: [...v.kept], ...(v.suspended_first ? { suspended_first: true as const } : {}) };
}

// ---- What the page shows ------------------------------------------------------

export type StatusTone = "live" | "suspended" | "attention";

export function siteStatus(state: string): { label: string; tone: StatusTone } {
  switch (state) {
    case "active": return { label: "Live", tone: "live" };
    case "suspended": return { label: "Suspended", tone: "suspended" };
    case "recovery_required": return { label: "Needs review", tone: "attention" };
    case "partly_deleted": return { label: "Partly deleted", tone: "attention" };
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
  if (site.state === "partly_deleted") return { kind: "blocked", why: "The hosting account is already deleted, so the PHP version cannot change." };
  if (site.state !== "active") return { kind: "blocked", why: "The PHP version cannot change until the hosting account has been checked." };
  if (site.site_folder_changed) return { kind: "blocked", why: "The PHP version cannot change while the site's folder is changed. Fix the folder first." };
  if (site.php_versions.length === 0) return { kind: "blocked", why: "The panel found no PHP versions installed on this server." };
  const versions = site.php_versions.filter((version) => version !== site.php_version);
  if (versions.length === 0) return { kind: "blocked", why: `PHP ${site.php_version} is the only version installed on this server.` };
  return { kind: "ready", versions };
}

// What the site page says about the site's folder, and whether it offers to
// use the account's current public_html. "changed": the hosting account
// changed its own public_html or permissions. "review": the account needs a
// check; an earlier account service also marked an account that way when
// only its public_html changed, and using the current folder ends that. If
// the cause is something else, the account service refuses and nothing
// changes.
export type FolderNotice = { kind: "changed" | "review"; what: string; why: string; next: string };

export function folderNotice(site: Website): FolderNotice | undefined {
  if (site.state === "partly_deleted") return undefined;
  if (site.site_folder_changed) return {
    kind: "changed",
    what: "The site's folder was changed from inside the hosting account.",
    why: "public_html in the account's home was renamed, replaced or removed, or the permissions of the home or public_html changed. Sifruno only works on the folder it recorded, so the PHP version, HTTPS and WordPress of this site cannot change, and the site may not load. Other websites are not affected, and you can still suspend or delete this one.",
    next: "Ask the site's owner to put the old public_html back. If it is gone, check that the new public_html holds the site, then use it.",
  };
  if (site.state === "recovery_required") return {
    kind: "review",
    what: "The hosting account needs a check.",
    why: "The account service found a change it did not make, or has a change it did not finish, and refuses changes until it is checked. Earlier versions also marked an account this way when only its public_html folder changed.",
    next: "If public_html was changed, use the account's current public_html. Otherwise ask whoever runs this server to check the hosting account.",
  };
  return undefined;
}

// A sentence for the end of a delete: the suspend the panel did first, if
// any, what went, and what was left alone.
export function deletedSummary(done: WebsiteDeleted): string {
  const suspended = done.suspended_first ? "The site's processes kept running, so the panel suspended the site first, then deleted it. " : "";
  const removed = done.removed.length ? `Removed: ${done.removed.join(", ")}.` : "";
  const kept = done.kept.length ? ` Left on the server, because it is not registered to this website: ${done.kept.join(", ")}.` : "";
  return `${suspended}${removed}${kept}`.trim();
}

// ---- Errors -----------------------------------------------------------------

type Operation = "list" | "read" | "php" | "suspend" | "resuspend" | "resume" | "folder" | "delete";
const changes: readonly Operation[] = ["php", "suspend", "resuspend", "resume", "folder", "delete"];
const isChange = (operation: Operation) => changes.includes(operation);

const whatFailed: Record<Operation, string> = {
  list: "Your websites could not be loaded.",
  read: "This website could not be loaded.",
  php: "The PHP version was not changed.",
  suspend: "The website was not suspended.",
  resuspend: "The suspension was not applied again.",
  resume: "The website was not resumed.",
  folder: "The current public_html was not used.",
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
  resuspend: "Try again after the web server has been checked.",
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
async function change(operation: Operation, site: Website, action: "php" | "state" | "folder" | "delete", field: Record<string, string>, signal?: AbortSignal): Promise<unknown> {
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
// serves again. Suspending a suspended site installs its suspended web
// server settings again.
export async function setWebsiteState(site: Website, state: "active" | "suspended", options: { signal?: AbortSignal } = {}): Promise<WebsiteDetail> {
  const operation = state === "active" ? "resume" : site.state === "suspended" ? "resuspend" : "suspend";
  return changedSite(operation, site, "state", await change(operation, site, "state", { state }, options.signal));
}

// Records the hosting account's current public_html as the site's folder,
// after the account replaced the one Sifruno recorded.
export async function adoptCurrentFolder(site: Website, options: { signal?: AbortSignal } = {}): Promise<WebsiteDetail> {
  return changedSite("folder", site, "folder", await change("folder", site, "folder", {}, options.signal));
}

// Deletes the site: its database, its hosting account and its files. The
// person types the domain; the server checks it again.
export async function deleteWebsite(site: Website, confirmDomain: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteDeleted> {
  const done = parseWebsiteDeleted(await change("delete", site, "delete", { confirm_domain: confirmDomain }, options.signal));
  if (!done || done.domain !== site.domain) throw unexpected("delete", `POST /api/v1/websites/sites/${site.account_id}/delete`);
  return done;
}
