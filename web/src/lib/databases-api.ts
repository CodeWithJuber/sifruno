import { validSession } from "./sites-api";

// Client for one website's Databases page. The server is the authority on
// every rule and on which website a database belongs to; the checks here
// mirror it so a form can say what is wrong before anything is sent. A
// password is sent once, in a POST body, and is never logged, stored, shown
// again or put in an error.

export interface SiteDatabase {
  name: string;
  // The database users that were given access to it.
  users: string[];
}
export interface DatabaseUser { name: string }
export interface SiteDatabases { databases: SiteDatabase[]; users: DatabaseUser[] }

// What WordPress or another app on the site connects to.
export const databaseHost = "127.0.0.1";
export const databaseNameLimit = 64;
export const databaseUserLimit = 47;
export const readTimeoutMs = 10000;
// The server gives the database server up to 30 s, and up to 15 s more to
// undo a half-made user.
export const writeTimeoutMs = 50000;

// ---- Checks that mirror the server ----------------------------------------

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const control = /\p{Cc}/u;
const utf8Bytes = (value: string) => new TextEncoder().encode(value).length;
export const validAccountId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);
const validUsername = (v: unknown): v is string => text(v) && /^[a-z][a-z0-9_]{2,31}$/.test(v);
// A name as dbhost stores it.
const validName = (v: unknown, limit: number): v is string => text(v) && v.length <= limit && /^[A-Za-z0-9_]+$/.test(v);

export type NameKind = "database" | "user";
const nameLimit: Record<NameKind, number> = { database: databaseNameLimit, user: databaseUserLimit };

// The full name the server will make: the hosting account's name, an
// underscore, then what the person typed.
export const fullName = (username: string, suffix: string) => `${username}_${suffix}`;

// How many characters the person can type after "<username>_".
export function suffixLimit(kind: NameKind, username: string): number {
  return Math.max(0, Math.min(16, nameLimit[kind] - username.length - 1));
}

export function checkSuffix(kind: NameKind, username: string, value: string): string | undefined {
  if (!value) return kind === "database" ? "Enter a name for the database." : "Enter a name for the user.";
  if (value !== value.toLowerCase()) return "Use lowercase letters only.";
  if (!/^[a-z0-9_]+$/.test(value)) return "Use only letters a to z, digits and underscores.";
  const limit = suffixLimit(kind, username);
  if (value.length > limit) return `Use at most ${limit} characters after ${username}_.`;
  return undefined;
}

// The same rule as the wizard's passwords: 12 to 128 bytes, no control
// characters, no space at either end.
export function checkPassword(value: string): string | undefined {
  if (!value) return "Enter a password.";
  if (control.test(value)) return "Remove line breaks, tabs and other control characters.";
  if (value !== value.replace(/^ +| +$/g, "")) return "Remove the space at the start or end.";
  const size = utf8Bytes(value);
  if (size < 12) return "Use at least 12 characters.";
  if (size > 128) return "The password is too long: use at most 128 bytes. Letters with accents or from other scripts take 2 to 4 bytes each.";
  return undefined;
}

export function checkDatabaseChoice(databases: readonly SiteDatabase[], value: string): string | undefined {
  return databases.some((database) => database.name === value) ? undefined : "Choose the database this user can use.";
}

// A delete goes ahead only when the name was typed again, exactly.
export function checkConfirmName(name: string, typed: string): string | undefined {
  if (!typed) return `Type ${name} to confirm.`;
  return typed === name ? undefined : `That does not match. Type ${name} exactly.`;
}

// The New website wizard names WordPress's database and its user
// <username>_wp. Deleting either, or changing that user's password, stops the
// site until wp-config.php is changed to match.
export const usedByWordPress = (username: string, name: string) => name === `${username}_wp`;

// The databases a user was given access to.
export function databasesFor(databases: readonly SiteDatabase[], user: string): string[] {
  return databases.filter((database) => database.users.includes(user)).map((database) => database.name);
}

// ---- Reading the server's answers -----------------------------------------

export function parseSiteDatabases(v: unknown): SiteDatabases | undefined {
  if (!object(v) || !Array.isArray(v.databases) || !Array.isArray(v.users) || v.databases.length > 5000 || v.users.length > 5000) return undefined;
  const databases: SiteDatabase[] = [];
  for (const item of v.databases as unknown[]) {
    if (!object(item) || !validName(item.name, databaseNameLimit) || !Array.isArray(item.users) || item.users.length > 5000) return undefined;
    const users = item.users as unknown[];
    if (!users.every((user): user is string => validName(user, databaseUserLimit))) return undefined;
    databases.push({ name: item.name, users: [...users] });
  }
  const users: DatabaseUser[] = [];
  for (const item of v.users as unknown[]) {
    if (!object(item) || !validName(item.name, databaseUserLimit)) return undefined;
    users.push({ name: item.name });
  }
  return { databases, users };
}

// Every POST answers with the name it created, changed or deleted.
export function parseNamed(v: unknown, limit = databaseNameLimit): string | undefined {
  return object(v) && validName(v.name, limit) ? v.name : undefined;
}

// Opening phpMyAdmin answers a one-time link to its sign-in script on
// phpMyAdmin's own HTTPS address: the panel's host name on another port,
// never the panel's own origin. The link signs in once, within a minute; the
// temporary database user behind it lasts until loginExpiresAt.
export interface PhpMyAdminLink { url: string; linkExpiresAt: Date; loginExpiresAt: Date }
const phpMyAdminLink = /^https:\/\/[A-Za-z0-9.:[\]-]+\/sifruno-signon\.php\?code=[A-Za-z0-9_-]{43}$/;
const time = (v: unknown): Date | undefined => {
  if (!text(v)) return undefined;
  const date = new Date(v);
  return Number.isNaN(date.getTime()) ? undefined : date;
};

// panelOrigin is the page's own origin, which phpMyAdmin may never share.
export function parsePhpMyAdminLink(v: unknown, panelOrigin = globalThis.location?.origin): PhpMyAdminLink | undefined {
  if (!object(v) || !text(v.url) || !phpMyAdminLink.test(v.url)) return undefined;
  let origin: string;
  try { origin = new URL(v.url).origin; } catch { return undefined; }
  if (origin === panelOrigin) return undefined;
  const linkExpiresAt = time(v.link_expires_at);
  const loginExpiresAt = time(v.login_expires_at);
  if (!linkExpiresAt || !loginExpiresAt) return undefined;
  return { url: v.url, linkExpiresAt, loginExpiresAt };
}

// ---- Errors -----------------------------------------------------------------

export type Operation = "list" | "createDatabase" | "createUser" | "setPassword" | "deleteDatabase" | "deleteUser" | "openPhpMyAdmin";

export const whatFailed: Record<Operation, string> = {
  list: "The databases could not be loaded.",
  createDatabase: "The database was not created.",
  createUser: "The database user was not created.",
  setPassword: "The password was not changed.",
  deleteDatabase: "The database was not deleted.",
  deleteUser: "The database user was not deleted.",
  openPhpMyAdmin: "phpMyAdmin did not open.",
};

// message is what happened; why and next are shown under it; technical goes
// under "Technical details".
export class DatabasesApiError extends Error {
  readonly status: number;
  readonly why: string;
  readonly next: string;
  readonly technical: string;
  constructor(status: number, what: string, why: string, next: string, technical: string) {
    super(what);
    this.name = "DatabasesApiError";
    this.status = status; this.why = why; this.next = next; this.technical = technical;
  }
}

// Server text is shown as text. Keep it short and on one line.
function serverText(v: unknown, limit = 600): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

// The database server's own words, which the server has already scrubbed of
// the password.
function serverTechnical(problem: ObjectValue): string {
  if (!Array.isArray(problem.errors)) return "";
  return (problem.errors as unknown[]).slice(0, 3).map((item) => object(item) ? serverText(item.message) : "").filter(Boolean).join("; ");
}

function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  const versions = "Reload the page and try again. If it happens again, the panel and the server may be different versions.";
  if (operation === "openPhpMyAdmin") {
    switch (status) {
      case 409: return { why: detail || "This website has no database yet.", next: "Create a database below, then choose Open phpMyAdmin again." };
      case 503: return { why: detail || "phpMyAdmin or the database server is not available right now.", next: "If phpMyAdmin is not set up, run Sifruno's installer (install.sh) on the server again. Otherwise check the database server, then try again." };
      case 502: return { why: detail || "The database server refused to make phpMyAdmin's temporary user.", next: "Try again. If it keeps failing, check the database server's log." };
    }
  }
  switch (status) {
    case 400: return { why: detail || "The server could not read the request.", next: versions };
    case 401: return { why: "Your sign-in has ended.", next: operation === "list" ? "Sign in again to see the databases." : "Sign in again, then try again." };
    case 403: return { why: detail || "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return { why: detail || "The website, database or user was not found.", next: "Refresh the list. If it is no longer listed, it was removed." };
    case 409: return { why: detail || "That name is already in use on this server.", next: "Choose another name, then try again." };
    case 413: return { why: detail || "The request was too large for the server.", next: "Shorten the password, then try again." };
    case 415: return { why: detail || "The server did not accept the request format.", next: versions };
    case 422: return { why: detail || "The server did not accept one of the values.", next: "Fix the value the message names, then try again." };
    case 429: return { why: detail || "Too many requests in a short time.", next: "Wait a minute, then try again." };
    case 502: return { why: detail || "The database server refused the request.", next: "Refresh the list, then try again. If it keeps failing, check the database server's log." };
    case 503: return { why: detail || "The database server or the account service is not available right now.", next: "Try again in a minute. If it keeps failing, check the database server and the Sifruno services on this server." };
    default: return { why: detail || `The server answered with an error (HTTP ${status}).`, next: "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

const unexpected = (operation: Operation, where: string) =>
  new DatabasesApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", operation === "list" || operation === "openPhpMyAdmin" ? "Reload the page and try again. If it happens again, the panel and the server may be different versions." : "Refresh the list to see whether the change was made before you try again.", `${where}: response did not match the databases contract`);

const notSent = (operation: Operation, why: string, technical: string) =>
  new DatabasesApiError(422, whatFailed[operation], why, "Fix the marked field, then try again.", `not sent: ${technical}`);

const notAWebsite = (operation: Operation) =>
  new DatabasesApiError(404, whatFailed[operation], "This address does not point to a website.", "Go back to Websites and choose the website there.", "the account id or the hosting account's name is not in the expected form; nothing was sent");

const notListed = (operation: Operation) =>
  new DatabasesApiError(404, whatFailed[operation], "That name is not one of this website's databases or users.", "Refresh the list. If it is no longer listed, it was removed.", "the name is not in the form the server uses; nothing was sent");

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
        // Opening phpMyAdmin changes nothing the page shows.
        const written = method === "POST" && Boolean(options.csrf) && operation !== "openPhpMyAdmin";
        throw new DatabasesApiError(0, written ? "The panel could not confirm the change." : whatFailed[operation], `The server did not answer within ${seconds} seconds.`, written ? "Refresh the list to see whether the change was made before you try again." : "Try again. If it keeps happening, check the server's load.", `${where}: no answer within ${seconds} s`);
      }
      const cancelled = Boolean(options.signal?.aborted);
      throw new DatabasesApiError(0, whatFailed[operation], cancelled ? "The request was cancelled." : "The panel could not reach its server.", "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const title = serverText(problem.title, 100);
      const technical = serverTechnical(problem);
      const { why, next } = explain(operation, response.status, serverText(problem.detail));
      throw new DatabasesApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${title ? ` (${title})` : ""}${technical ? `: ${technical}` : ""}`);
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
  const ended = (technical: string) => new DatabasesApiError(401, whatFailed[operation], "Your sign-in has ended.", "Sign in again, then try again.", technical);
  let value: unknown;
  try {
    value = await request(operation, "/api/v1/session", { timeoutMs: readTimeoutMs, signal });
  } catch (error) {
    if (error instanceof DatabasesApiError && error.status === 401) throw ended("GET /api/v1/session returned HTTP 401");
    throw error;
  }
  if (!validSession(value)) throw unexpected(operation, "GET /api/v1/session");
  if (!value.authenticated) throw ended("GET /api/v1/session: not signed in");
  return value.csrf_token;
}

const base = (accountId: string) => `/api/v1/websites/sites/${accountId}/databases`;

// One change: the token, the POST, and the name the server answers with.
async function change(operation: Operation, url: string, body: Record<string, string>, expected: string | undefined, limit: number, signal?: AbortSignal): Promise<string> {
  const csrf = await csrfToken(operation, signal);
  const name = parseNamed(await request(operation, url, { method: "POST", body, csrf, timeoutMs: writeTimeoutMs, signal }), limit);
  if (!name || (expected !== undefined && name !== expected)) throw unexpected(operation, `POST ${url}`);
  return name;
}

export async function listSiteDatabases(accountId: string, options: { signal?: AbortSignal } = {}): Promise<SiteDatabases> {
  if (!validAccountId(accountId)) throw notAWebsite("list");
  const url = base(accountId);
  const value = parseSiteDatabases(await request("list", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!value) throw unexpected("list", `GET ${url}`);
  return value;
}

// username is the hosting account's name, used only for the panel's own
// checks: the server takes the owner from the account in the address.
export async function createSiteDatabase(accountId: string, username: string, suffix: string, options: { signal?: AbortSignal } = {}): Promise<string> {
  if (!validAccountId(accountId) || !validUsername(username)) throw notAWebsite("createDatabase");
  const problem = checkSuffix("database", username, suffix);
  if (problem) throw notSent("createDatabase", problem, "the database name failed the panel's checks");
  return change("createDatabase", base(accountId), { name_suffix: suffix }, fullName(username, suffix), databaseNameLimit, options.signal);
}

export interface NewDatabaseUser { name_suffix: string; password: string; database: string }

export async function createDatabaseUser(accountId: string, username: string, input: NewDatabaseUser, options: { signal?: AbortSignal } = {}): Promise<string> {
  if (!validAccountId(accountId) || !validUsername(username)) throw notAWebsite("createUser");
  const problem = checkSuffix("user", username, input.name_suffix) ?? checkPassword(input.password);
  if (problem) throw notSent("createUser", problem, "the user name or the password failed the panel's checks");
  if (!validName(input.database, databaseNameLimit)) throw notSent("createUser", "Choose the database this user can use.", "no database was chosen");
  // Exactly the three keys the server accepts, nothing else.
  const body = { name_suffix: input.name_suffix, password: input.password, database: input.database };
  return change("createUser", `${base(accountId)}/users`, body, fullName(username, input.name_suffix), databaseUserLimit, options.signal);
}

export async function setDatabaseUserPassword(accountId: string, user: string, password: string, options: { signal?: AbortSignal } = {}): Promise<string> {
  if (!validAccountId(accountId)) throw notAWebsite("setPassword");
  if (!validName(user, databaseUserLimit)) throw notListed("setPassword");
  const problem = checkPassword(password);
  if (problem) throw notSent("setPassword", problem, "the password failed the panel's checks");
  return change("setPassword", `${base(accountId)}/users/${user}/password`, { password }, user, databaseUserLimit, options.signal);
}

// typed is what the person typed to confirm; the server compares it again.
export async function deleteSiteDatabase(accountId: string, name: string, typed: string, options: { signal?: AbortSignal } = {}): Promise<string> {
  if (!validAccountId(accountId)) throw notAWebsite("deleteDatabase");
  if (!validName(name, databaseNameLimit)) throw notListed("deleteDatabase");
  const problem = checkConfirmName(name, typed);
  if (problem) throw notSent("deleteDatabase", problem, "the typed name does not match");
  return change("deleteDatabase", `${base(accountId)}/${name}/delete`, { confirm_name: typed }, name, databaseNameLimit, options.signal);
}

export async function deleteDatabaseUser(accountId: string, user: string, typed: string, options: { signal?: AbortSignal } = {}): Promise<string> {
  if (!validAccountId(accountId)) throw notAWebsite("deleteUser");
  if (!validName(user, databaseUserLimit)) throw notListed("deleteUser");
  const problem = checkConfirmName(user, typed);
  if (problem) throw notSent("deleteUser", problem, "the typed name does not match");
  return change("deleteUser", `${base(accountId)}/users/${user}/delete`, { confirm_name: typed }, user, databaseUserLimit, options.signal);
}

// One click: a temporary database user for this website's databases and a
// one-time link that opens phpMyAdmin signed in as it. The server picks the
// databases; nothing in the request names them.
export async function openPhpMyAdmin(accountId: string, options: { signal?: AbortSignal } = {}): Promise<PhpMyAdminLink> {
  if (!validAccountId(accountId)) throw notAWebsite("openPhpMyAdmin");
  const url = `${base(accountId)}/phpmyadmin`;
  const csrf = await csrfToken("openPhpMyAdmin", options.signal);
  const link = parsePhpMyAdminLink(await request("openPhpMyAdmin", url, { method: "POST", body: {}, csrf, timeoutMs: writeTimeoutMs, signal: options.signal }));
  if (!link) throw unexpected("openPhpMyAdmin", `POST ${url}`);
  return link;
}
