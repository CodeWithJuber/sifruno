import { validSession } from "./sites-api";

// Client for a website's Domains page: its other domains (aliases, which
// serve the same site), its redirects and its "Always use HTTPS" switch. The
// server sends each change to
// the account broker, which renders them into the web server's config; after
// a domain change the panel asks for a certificate that covers the new set.
// The checks here mirror the server's so the form can say what is wrong
// before anything is sent; the server checks everything again.

// on: the site's certificate covers the domain. waiting_for_dns: the last
// certificate request left it out, because it does not reach this server
// yet. pending: no certificate covers it yet. off: certificates are not set
// up on this server.
export type AliasHttps = "on" | "waiting_for_dns" | "pending" | "off";
export interface WebsiteAlias { name: string; https: AliasHttps }
export interface WebsiteRedirect { from: string; to: string; status: 301 | 302 }
export interface SiteDomains {
  account_id: string;
  domain: string;
  username: string;
  // "active", "suspended", "recovery_required" or "partly_deleted".
  state: string;
  // The hosting account's revision: a change sends it back.
  revision: number;
  https: { on: boolean; not_after: string };
  // Always use HTTPS: true unless the site's owner turned it off. It sends
  // plain http to https only while a valid certificate is in force.
  always_https: boolean;
  aliases: WebsiteAlias[];
  // How many redirects the site has. The server lists them in redirects; if
  // it could not read them, redirects is shorter than this.
  redirect_count: number;
  redirects: WebsiteRedirect[];
}

export const maxAliases = 15;
export const maxRedirects = 100;
export const maxPathLength = 128;
export const maxTargetLength = 256;
export const readTimeoutMs = 10000;
// A change waits for the account service, whose web server change can take
// minutes on a busy host. The server answers within 11 minutes.
export const actionTimeoutMs = 11.5 * 60 * 1000;

// ---- Checks -------------------------------------------------------------------

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
export const validAccountId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);

// A lowercase host name of at least two labels, as the broker takes it.
export function validDomain(s: string): boolean {
  if (s.length === 0 || s.length > 253 || /^[0-9.]+$/.test(s)) return false;
  const labels = s.split(".");
  return labels.length >= 2 && labels.every((l) => l.length > 0 && l.length <= 63 && /^[a-z0-9-]+$/.test(l) && !l.startsWith("-") && !l.endsWith("-"));
}

// What the person typed, as the server reads it.
export const normalizeDomain = (value: string) => value.trim().toLowerCase();

// Why a domain cannot be added to the site, or undefined when it can.
export function checkDomain(value: string, site?: Pick<SiteDomains, "domain" | "aliases">): string | undefined {
  const domain = normalizeDomain(value);
  if (!domain) return "Enter the domain to add, such as www.example.com.";
  const key = domain.replace(/^www\./, "");
  if (!validDomain(domain) || key.startsWith("www.") || !key.includes(".")) return "Enter a domain such as www.example.com or example.net: letters, digits and hyphens, in two or more parts separated by dots.";
  if (site && domain === site.domain) return `${domain} is already this website's main domain.`;
  if (site?.aliases.some((alias) => alias.name === domain)) return `${domain} is already a domain of this website.`;
  if (site && site.aliases.length >= maxAliases) return `A website can have at most ${maxAliases} other domains. Remove one first.`;
  return undefined;
}

// A redirect's source: a path (it starts with /) or a domain of the site.
export const redirectKind = (from: string): "path" | "domain" => from.trim().startsWith("/") ? "path" : "domain";

export function validRedirectPath(p: string): boolean {
  if (p.length > maxPathLength || !/^\/[A-Za-z0-9._~/-]*$/.test(p) || p.includes("//")) return false;
  return p.slice(1).split("/").every((part) => !part.startsWith("."));
}

interface Target { scheme: string; host: string; path: string }

// A redirect's target: http or https, a host that is a domain name, an
// optional port, then for a path redirect an optional path and query of
// letters, digits and - . _ ~ / ? & = + , : ; @ only.
export function parseTarget(to: string, hostOnly: boolean): Target | undefined {
  if (to.length > maxTargetLength) return undefined;
  const m = /^(https?):\/\/([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?((?:\/[A-Za-z0-9._~/?&=+,:;@-]*)?)$/.exec(to);
  if (!m || !validDomain(m[2]) || (hostOnly && m[4] !== "") || (m[3] && Number(m[3]) > 65535)) return undefined;
  return { scheme: m[1], host: m[2], path: m[4] };
}

const pathRule = "The path must start with / and use only letters, digits and - . _ ~ /, at most 128 characters, with no part that starts with a dot. For example /old-page.";
const targetRule = "The address must start with http:// or https://, then a domain name, and may go on with a path. Use only letters, digits and - . _ ~ / ? & = + , : ; @, at most 256 characters: no spaces, quotes, #, $ or %.";

// Why a redirect's source cannot be used, or undefined when it can.
export function checkRedirectFrom(value: string, site: Pick<SiteDomains, "domain" | "aliases" | "redirects">): string | undefined {
  const from = value.trim();
  if (!from) return "Enter a path such as /old-page, or one of this website's domains.";
  if (redirectKind(from) === "path") {
    if (!validRedirectPath(from)) return pathRule;
    if (site.redirects.some((r) => r.from === from)) return `There is already a redirect from ${from}. Remove it first to change where it goes.`;
    return undefined;
  }
  const domain = from.toLowerCase();
  if (domain !== site.domain && !site.aliases.some((alias) => alias.name === domain)) return `${from} is not a path or a domain of this website. A path starts with /; to redirect another domain, add it to the website first.`;
  if (site.redirects.some((r) => r.from === domain)) return `${domain} is already redirected. Remove that redirect first to change where it goes.`;
  return undefined;
}

// Why a redirect's target cannot be used for this source, or undefined.
export function checkRedirectTo(value: string, from: string, site?: Pick<SiteDomains, "domain" | "aliases">): string | undefined {
  const to = value.trim();
  if (!to) return "Enter the address to send visitors to, such as https://example.com/new-page.";
  if (redirectKind(from) === "domain") {
    if (parseTarget(to.replace(/\/$/, ""), true)) return undefined;
    return parseTarget(to, false) ? "A whole domain is redirected with each visitor's path kept, so give only the address of the other domain, such as https://example.com." : targetRule;
  }
  const target = parseTarget(to, false);
  if (!target) return targetRule;
  const path = target.path.split("?")[0];
  const own = site && (target.host === site.domain || site.aliases.some((alias) => alias.name === target.host));
  const source = from.trim();
  if (own && (path === source || (path === "" && source === "/") || (!source.endsWith("/") && path === `${source}/`))) return "This redirect would send visitors in a loop, to the same address. Choose another address.";
  return undefined;
}

// What the server will store for a redirect: a domain redirect's target
// loses one trailing slash.
export function redirectBody(from: string, to: string, status: 301 | 302): { from: string; to: string; status: 301 | 302 } {
  const source = from.trim();
  const target = to.trim();
  return { from: redirectKind(source) === "domain" ? source.toLowerCase() : source, to: redirectKind(source) === "domain" ? target.replace(/\/$/, "") : target, status };
}

// ---- What the page shows ------------------------------------------------------

export function aliasHttps(https: AliasHttps): { label: string; detail: string; tone: "on" | "waiting" | "off" } {
  switch (https) {
    case "on": return { label: "https", detail: "The site's certificate covers this domain.", tone: "on" };
    case "waiting_for_dns": return { label: "http only", detail: "Its DNS does not point at this server yet, so the certificate leaves it out. Add the DNS record below; the panel tries again every few hours.", tone: "waiting" };
    case "pending": return { label: "http for now", detail: "No certificate covers it yet. The panel is asking for one; reload the page in a few minutes.", tone: "waiting" };
    default: return { label: "http", detail: "Certificates are not set up on this server, so the domain uses http.", tone: "off" };
  }
}

export const statusLabel = (status: 301 | 302) => status === 301 ? "301, moved for good" : "302, moved for now";

// What "Always use HTTPS" can do now. ready: the switch works, and while it
// is on it is in force. Otherwise the switch shows the setting but cannot
// change, with why and what to do next.
export type AlwaysHttps =
  | { kind: "ready" }
  | { kind: "not-live" | "no-certificates-here" | "no-certificate" | "expired"; why: string; next: string };

export function alwaysHttps(site: Pick<SiteDomains, "domain" | "state" | "https" | "aliases">, now: Date = new Date()): AlwaysHttps {
  if (site.state !== "active") {
    return site.state === "suspended"
      ? { kind: "not-live", why: "This website is suspended, so its domains answer with an error page.", next: "Resume the website in its Settings tab to change this." }
      : { kind: "not-live", why: "The hosting account needs a check by whoever runs this server.", next: "Ask whoever runs this server to check the website." };
  }
  if (!site.https.on) {
    // An alias says "off" only when this server has no certificate manager.
    if (site.aliases.some((alias) => alias.https === "off")) {
      return { kind: "no-certificates-here", why: "Certificates are not set up on this server, so the website has none and stays on http://.", next: "Ask whoever runs this server to set up certificates." };
    }
    return { kind: "no-certificate", why: "This website has no certificate yet, so visitors cannot be sent to https:// without a security warning.", next: `Get a certificate on this tab first: point ${site.domain} at this server with the DNS record below. The panel asks for a certificate every few hours until it has one.` };
  }
  const until = site.https.not_after ? new Date(site.https.not_after) : undefined;
  if (until && !Number.isNaN(until.getTime()) && until.getTime() <= now.getTime()) {
    return { kind: "expired", why: "This website's certificate has expired, so visitors stay on http:// until a new one is in force.", next: `Check on this tab that ${site.domain} still points at this server with the DNS record below. The panel asks for a new certificate every few hours.` };
  }
  return { kind: "ready" };
}

// What a change of the switch did, said once the server has saved it.
export function alwaysHttpsOutcome(next: Pick<SiteDomains, "domain" | "state" | "https" | "aliases" | "always_https">, now: Date = new Date()): string {
  if (!next.always_https) return "Always use HTTPS is off. Visitors can use both http:// and https://.";
  return alwaysHttps(next, now).kind === "ready"
    ? "Always use HTTPS is on. Visitors on http:// now go to https://."
    : "Always use HTTPS is on. It starts once a valid certificate is in force.";
}

// ---- Reading the server's answers -----------------------------------------------

const httpsValues: readonly AliasHttps[] = ["on", "waiting_for_dns", "pending", "off"];

export function parseAliases(v: unknown): WebsiteAlias[] | undefined {
  if (!Array.isArray(v) || v.length > maxAliases) return undefined;
  const out: WebsiteAlias[] = [];
  for (const item of v) {
    if (!object(item) || !text(item.name) || !validDomain(item.name) || !httpsValues.includes(item.https as AliasHttps)) return undefined;
    out.push({ name: item.name, https: item.https as AliasHttps });
  }
  return out;
}

export function parseRedirects(v: unknown): WebsiteRedirect[] | undefined {
  if (!Array.isArray(v) || v.length > maxRedirects) return undefined;
  const out: WebsiteRedirect[] = [];
  for (const item of v) {
    if (!object(item) || !text(item.from) || !text(item.to) || (item.status !== 301 && item.status !== 302)) return undefined;
    const domain = redirectKind(item.from) === "domain";
    if (domain ? !validDomain(item.from) || !parseTarget(item.to, true) : !validRedirectPath(item.from) || !parseTarget(item.to, false)) return undefined;
    out.push({ from: item.from, to: item.to, status: item.status });
  }
  return out;
}

export function parseSiteDomains(v: unknown): SiteDomains | undefined {
  if (!object(v) || !validAccountId(v.account_id) || !text(v.domain) || !validDomain(v.domain) || !text(v.username) || !text(v.state) || !/^[a-z_]{1,40}$/.test(v.state)) return undefined;
  if (!Number.isSafeInteger(v.revision) || (v.revision as number) < 1) return undefined;
  const https = v.https;
  if (!object(https) || typeof https.on !== "boolean" || !text(https.not_after)) return undefined;
  const aliases = parseAliases(v.aliases);
  const redirects = parseRedirects(v.redirects);
  const count = v.redirect_count;
  if (!aliases || !redirects || !Number.isSafeInteger(count) || (count as number) < redirects.length || (count as number) > maxRedirects) return undefined;
  if (typeof v.always_https !== "boolean") return undefined;
  return {
    account_id: v.account_id, domain: v.domain, username: v.username, state: v.state, revision: v.revision as number,
    https: { on: https.on, not_after: https.not_after }, always_https: v.always_https, aliases, redirect_count: count as number, redirects,
  };
}

// ---- Errors -------------------------------------------------------------------

export type Operation = "read" | "addDomain" | "removeDomain" | "addRedirect" | "removeRedirect" | "setAlwaysHttps";

export const whatFailed: Record<Operation, string> = {
  read: "This website's domains could not be loaded.",
  addDomain: "The domain was not added.",
  removeDomain: "The domain was not removed.",
  addRedirect: "The redirect was not added.",
  removeRedirect: "The redirect was not removed.",
  setAlwaysHttps: "Always use HTTPS did not change.",
};
const notConfirmed = "The panel could not confirm the change.";
const seeItNow = "Reload the page to see the website as it is now before you try again.";

// message is what happened; why and next are shown under it; technical goes
// under "Technical details".
export class SiteDomainsApiError extends Error {
  readonly status: number;
  readonly why: string;
  readonly next: string;
  readonly technical: string;
  constructor(status: number, what: string, why: string, next: string, technical: string) {
    super(what);
    this.name = "SiteDomainsApiError";
    this.status = status; this.why = why; this.next = next; this.technical = technical;
  }
}

function serverText(v: unknown, limit = 600): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  const change = operation !== "read";
  const versions = "Reload the page. If it happens again, the panel and the server may be different versions.";
  switch (status) {
    case 400: case 415: return { why: detail || "The server could not read the request.", next: versions };
    case 401: return { why: "Your sign-in has ended.", next: change ? "Sign in again, then try again." : "Sign in again to see this website." };
    case 403: return { why: detail || "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return { why: detail || "That website was not found.", next: "Go back to Websites and choose it again. If it is not listed, it was removed." };
    // The switch's page reads the website again by itself after a 409; the
    // server's words go under Technical details.
    case 409: return operation === "setAlwaysHttps"
      ? { why: "The website changed after the page read it, or another change to it was still running, so nothing changed.", next: "The page has read the website again and shows it as it is now. Check the switch, then try again if you still want the change." }
      : { why: detail || "The website changed or was busy.", next: seeItNow };
    case 422: return { why: detail || "The server did not accept the request.", next: "Change what you entered, then try again." };
    case 429: return { why: detail || "Too many requests in a short time.", next: "Wait a minute, then try again." };
    case 503: return { why: detail || "The account service is not available right now.", next: change ? `${seeItNow} If it keeps failing, check the Sifruno services on this server.` : "Try again in a minute. If it keeps failing, check the Sifruno services on this server." };
    default: return { why: detail || `The server answered with an error (HTTP ${status}).`, next: change ? seeItNow : "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

// ---- Requests -----------------------------------------------------------------

interface RequestOptions { method?: "GET" | "POST"; body?: unknown; csrf?: string; timeoutMs: number; signal?: AbortSignal; note?: string }

async function request(operation: Operation, url: string, options: RequestOptions): Promise<unknown> {
  const method = options.method ?? "GET";
  const where = `${method} ${url}`;
  const note = options.note ? `; ${options.note}` : "";
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
        headers: { Accept: "application/json", ...(sent ? { "Content-Type": "application/json" } : {}), ...(options.csrf ? { "X-CSRF-Token": options.csrf } : {}) },
        ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      });
    } catch {
      const what = sent ? notConfirmed : whatFailed[operation];
      if (timedOut) throw new SiteDomainsApiError(0, what, `The server did not answer within ${Math.round(options.timeoutMs / 1000)} seconds.`, sent ? seeItNow : "Try again. If it keeps happening, check the server's load.", `${where}: no answer within ${Math.round(options.timeoutMs / 1000)} s${note}`);
      const cancelled = Boolean(options.signal?.aborted);
      const why = cancelled ? "The request was cancelled." : sent ? "The panel lost its connection to the server before it answered. The change may still finish." : "The panel could not reach its server.";
      throw new SiteDomainsApiError(0, what, why, sent ? seeItNow : "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}${note}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const title = serverText(problem.title, 100);
      const first = Array.isArray(problem.errors) && object(problem.errors[0]) ? serverText(problem.errors[0].message, 300) : "";
      const detail = serverText(problem.detail, 900);
      const { why, next } = explain(operation, response.status, detail);
      const said = detail && why !== detail ? `; the server said: ${detail}` : "";
      throw new SiteDomainsApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${title ? ` (${title})` : ""}${first ? `; ${first}` : ""}${said}${note}`);
    }
    return value;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}

const unexpected = (operation: Operation, where: string) => operation === "read"
  ? new SiteDomainsApiError(0, whatFailed.read, "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", `${where}: response did not match the websites contract`)
  : new SiteDomainsApiError(0, notConfirmed, "The server's answer was not in the form the panel expects, so the panel cannot tell whether the change was made.", seeItNow, `${where}: response did not match the websites contract`);

export async function getSiteDomains(accountId: string, options: { signal?: AbortSignal } = {}): Promise<SiteDomains> {
  if (!validAccountId(accountId)) throw new SiteDomainsApiError(404, whatFailed.read, "This address does not point to a website.", "Go back to Websites and choose the website there.", "account id in the address is not 32 lowercase hex characters; nothing was sent");
  const url = `/api/v1/websites/sites/${accountId}`;
  const site = parseSiteDomains(await request("read", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!site || site.account_id !== accountId) throw unexpected("read", `GET ${url}`);
  return site;
}

// The CSRF token comes from the current session. Nothing was sent if this fails.
async function csrfToken(operation: Operation, signal?: AbortSignal): Promise<string> {
  const ended = (technical: string) => new SiteDomainsApiError(401, whatFailed[operation], "Your sign-in has ended.", "Sign in again, then try again.", technical);
  let value: unknown;
  try {
    value = await request(operation, "/api/v1/session", { timeoutMs: readTimeoutMs, signal });
  } catch (error) {
    if (error instanceof SiteDomainsApiError && error.status === 401) throw ended("GET /api/v1/session returned HTTP 401");
    throw error;
  }
  if (!validSession(value)) throw new SiteDomainsApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", "GET /api/v1/session: response did not match the session contract; nothing was changed");
  if (!value.authenticated) throw ended("GET /api/v1/session: not signed in");
  return value.csrf_token;
}

type Action = "domain-add" | "domain-remove" | "redirect-add" | "redirect-remove" | "always-https";

async function change(operation: Operation, site: SiteDomains, action: Action, body: Record<string, string | number | boolean>, signal?: AbortSignal): Promise<SiteDomains> {
  if (!validAccountId(site.account_id)) throw new SiteDomainsApiError(404, whatFailed[operation], "This page does not point to a website.", "Go back to Websites and choose the website there.", "account id is not 32 lowercase hex characters; nothing was sent");
  const csrf = await csrfToken(operation, signal);
  const url = `/api/v1/websites/sites/${site.account_id}/${action}`;
  const value = await request(operation, url, { method: "POST", body: { ...body, expected_revision: site.revision }, csrf, timeoutMs: actionTimeoutMs, signal, note: `expected revision ${site.revision}` });
  const next = parseSiteDomains(value);
  if (!next || next.account_id !== site.account_id) throw unexpected(operation, `POST ${url}`);
  return next;
}

export const addDomain = (site: SiteDomains, domain: string, options: { signal?: AbortSignal } = {}) =>
  change("addDomain", site, "domain-add", { domain: normalizeDomain(domain) }, options.signal);
export const removeDomain = (site: SiteDomains, domain: string, options: { signal?: AbortSignal } = {}) =>
  change("removeDomain", site, "domain-remove", { domain }, options.signal);
export const addRedirect = (site: SiteDomains, from: string, to: string, status: 301 | 302, options: { signal?: AbortSignal } = {}) =>
  change("addRedirect", site, "redirect-add", redirectBody(from, to, status), options.signal);
export const removeRedirect = (site: SiteDomains, from: string, options: { signal?: AbortSignal } = {}) =>
  change("removeRedirect", site, "redirect-remove", { from }, options.signal);
export const setAlwaysHttps = (site: SiteDomains, on: boolean, options: { signal?: AbortSignal } = {}) =>
  change("setAlwaysHttps", site, "always-https", { always_https: on }, options.signal);
