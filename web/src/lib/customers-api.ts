// Client for the Customers page: an admin gives a customer (a site owner) a
// login for some of the server's websites, sends it the one-time setup link,
// changes its websites, turns it off or on, makes a new link, or removes it.
// The setup link is held in memory until the admin hides it: never in
// storage, the URL, a log or an error message. The checks here mirror the
// server's so the form can say what is wrong first; the server decides.

export interface CustomerLogin {
  username: string;
  websites: string[];
  disabled: boolean;
  // done: the customer chose a password and connected its app; pending: the
  // setup link works; expired: the link is more than a day old.
  setup: "done" | "pending" | "expired";
  setup_expires_at: string | null;
  created_at: string;
}
export interface CustomerList { items: CustomerLogin[]; capacity: number }
export interface CustomerSetupLink extends CustomerLogin { setup_link: string }

export const maxWebsites = 64;
export const readTimeoutMs = 10000;
// Giving websites asks the account service whether they exist.
export const writeTimeoutMs = 30000;

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const exact = (v: ObjectValue, fields: readonly string[]) => Object.keys(v).length === fields.length && fields.every((field) => Object.hasOwn(v, field));
const timestamp = (v: unknown): v is string => text(v) && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v));
export const validUsername = (v: unknown): v is string => text(v) && /^[a-z][a-z0-9._-]{2,31}$/.test(v);
export const validAccountId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);
// The secret after # in a setup link: 43 base64url characters.
export const validLinkSecret = (v: unknown): v is string => text(v) && /^[A-Za-z0-9_-]{43}$/.test(v);

// ---- Checks that mirror the server ----------------------------------------

export function checkUsername(value: string): string | undefined {
  return validUsername(value) ? undefined : "Use 3 to 32 lowercase letters, digits, dots, dashes or underscores, starting with a letter.";
}

export function checkWebsites(ids: readonly string[]): string | undefined {
  if (ids.length === 0) return "Choose at least one website for this login.";
  if (ids.length > maxWebsites) return `Choose at most ${maxWebsites} websites.`;
  return ids.every(validAccountId) ? undefined : "Choose the websites from the list.";
}

// The secret in a setup link's fragment (#...), or undefined.
export function linkSecret(hash: string): string | undefined {
  const value = hash.startsWith("#") ? hash.slice(1) : hash;
  return validLinkSecret(value) ? value : undefined;
}

// The link to send: the server's absolute link, or its path on this panel's
// own address when the server does not know its public one.
export function setupLinkURL(link: string, origin: string): string {
  return new URL(link, origin).href;
}

export type LoginTone = "ready" | "waiting" | "attention" | "off";

export function loginState(login: CustomerLogin): { label: string; tone: LoginTone } {
  if (login.disabled) return { label: "Turned off", tone: "off" };
  if (login.setup === "done") return { label: "Ready", tone: "ready" };
  if (login.setup === "pending") return { label: "Waiting for setup", tone: "waiting" };
  return { label: "Setup link expired", tone: "attention" };
}

// ---- Reading the server's answers -------------------------------------------

const loginFields = ["username", "websites", "disabled", "setup", "setup_expires_at", "created_at"] as const;

function loginShape(v: ObjectValue): boolean {
  return validUsername(v.username) && Array.isArray(v.websites) && v.websites.length <= maxWebsites && v.websites.every(validAccountId)
    && new Set(v.websites).size === v.websites.length && typeof v.disabled === "boolean" && (v.setup === "done" || v.setup === "pending" || v.setup === "expired")
    && (v.setup === "done" ? v.setup_expires_at === null : timestamp(v.setup_expires_at)) && timestamp(v.created_at);
}

function login(v: ObjectValue): CustomerLogin {
  return { username: v.username as string, websites: [...(v.websites as string[])], disabled: v.disabled as boolean, setup: v.setup as CustomerLogin["setup"], setup_expires_at: v.setup_expires_at as string | null, created_at: v.created_at as string };
}

export function parseCustomer(v: unknown): CustomerLogin | undefined {
  return object(v) && exact(v, loginFields) && loginShape(v) ? login(v) : undefined;
}

export function parseSetupLink(v: unknown): CustomerSetupLink | undefined {
  if (!object(v) || !exact(v, [...loginFields, "setup_link"]) || !loginShape(v) || !text(v.setup_link)) return undefined;
  const [path, secret] = v.setup_link.split("#");
  if (!path.endsWith("/setup") || !validLinkSecret(secret)) return undefined;
  return { ...login(v), setup_link: v.setup_link };
}

export function parseCustomerList(v: unknown): CustomerList | undefined {
  if (!object(v) || !exact(v, ["items", "capacity"]) || !Array.isArray(v.items) || !Number.isSafeInteger(v.capacity) || (v.capacity as number) < 1 || v.items.length > (v.capacity as number)) return undefined;
  const items: CustomerLogin[] = [];
  for (const item of v.items as unknown[]) {
    const parsed = parseCustomer(item);
    if (!parsed) return undefined;
    items.push(parsed);
  }
  if (new Set(items.map((item) => item.username)).size !== items.length) return undefined;
  return { items, capacity: v.capacity as number };
}

// ---- Errors -----------------------------------------------------------------

export type Operation = "list" | "create" | "websites" | "state" | "link" | "remove";

export const whatFailed: Record<Operation, string> = {
  list: "The customer logins could not be loaded.",
  create: "The login was not made.",
  websites: "The websites were not changed.",
  state: "The login was not changed.",
  link: "No new setup link was made.",
  remove: "The login was not removed.",
};

// message is what happened; why and next are shown under it; technical goes
// under "Technical details". None of them ever holds a setup link.
export class CustomersApiError extends Error {
  readonly status: number;
  readonly why: string;
  readonly next: string;
  readonly technical: string;
  constructor(status: number, what: string, why: string, next: string, technical: string) {
    super(what);
    this.name = "CustomersApiError";
    this.status = status; this.why = why; this.next = next; this.technical = technical;
  }
}

function serverText(v: unknown, limit = 300): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

// The server's details are written for people, so they are the why when
// there is one; the next step follows from the status.
function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  switch (status) {
    case 401: return { why: "Your sign-in has ended.", next: "Sign in again, then try again." };
    case 403: return { why: detail || "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in as an admin if asked, and try again." };
    case 404: return { why: detail || "That login is not on the list. It may have been removed.", next: "Reload the page." };
    case 409: return { why: detail || "The change conflicts with the logins as they are now.", next: "Change the marked value, then try again." };
    case 413: case 422: return { why: detail || "The server did not accept the values.", next: "Fix the marked value, then try again." };
    case 429: return { why: "Too many requests in a short time.", next: "Wait a minute, then try again." };
    case 503: return { why: detail || "The server could not save or read the logins right now.", next: operation === "list" ? "Try again in a minute." : "Try again in a minute. If it keeps failing, check the Sifruno service." };
    default: return { why: detail || `The server answered with an error (HTTP ${status}).`, next: "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

const unexpected = (operation: Operation, where: string) =>
  new CustomersApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page to see the logins as they are now. If it happens again, the panel and the server may be different versions.", `${where}: response did not match the customer logins contract`);

const notSent = (operation: Operation, why: string) =>
  new CustomersApiError(422, whatFailed[operation], why, "Fix the marked value, then try again.", "not sent: the value failed the panel's checks");

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
        const written = method === "POST";
        throw new CustomersApiError(0, written ? "The panel could not confirm the change." : whatFailed[operation], `The server did not answer within ${seconds} seconds.`, written ? "Reload the page to see whether the change was made before you try again." : "Try again. If it keeps happening, check the server's load.", `${where}: no answer within ${seconds} s`);
      }
      const cancelled = Boolean(options.signal?.aborted);
      throw new CustomersApiError(0, whatFailed[operation], cancelled ? "The request was cancelled." : "The panel could not reach its server.", "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const code = text(problem.error) && /^[a-z_]+$/.test(problem.error) ? problem.error : "";
      const detail = serverText(problem.detail);
      const { why, next } = explain(operation, response.status, detail);
      throw new CustomersApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${code ? ` (${code})` : ""}`);
    }
    return value;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}

async function csrfToken(operation: Operation): Promise<string> {
  let value: unknown;
  try {
    value = await request(operation, "/api/v1/session", { timeoutMs: readTimeoutMs });
  } catch (error) {
    if (error instanceof CustomersApiError && error.status === 401) throw new CustomersApiError(401, whatFailed[operation], "Your sign-in has ended.", "Sign in again, then try again.", "GET /api/v1/session returned HTTP 401");
    throw error;
  }
  if (!object(value) || !text(value.csrf_token) || !/^[A-Za-z0-9_-]{43}$/.test(value.csrf_token)) throw unexpected(operation, "GET /api/v1/session");
  return value.csrf_token;
}

const base = "/api/v1/session/customers";
const target = (username: string) => `${base}/${encodeURIComponent(username)}`;

async function change<T>(operation: Operation, url: string, body: unknown, parse: (v: unknown) => T | undefined): Promise<T> {
  const csrf = await csrfToken(operation);
  const value = await request(operation, url, { method: "POST", body, csrf, timeoutMs: writeTimeoutMs });
  const parsed = parse(value);
  if (!parsed) throw unexpected(operation, `POST ${url}`);
  return parsed;
}

export async function listCustomers(options: { signal?: AbortSignal } = {}): Promise<CustomerList> {
  const value = await request("list", base, { timeoutMs: readTimeoutMs, signal: options.signal });
  const list = parseCustomerList(value);
  if (!list) throw unexpected("list", `GET ${base}`);
  return list;
}

export async function createCustomer(username: string, websites: readonly string[]): Promise<CustomerSetupLink> {
  const problem = checkUsername(username) ?? checkWebsites(websites);
  if (problem) throw notSent("create", problem);
  return change("create", base, { username, websites: [...websites] }, parseSetupLink);
}

export async function setCustomerWebsites(username: string, websites: readonly string[]): Promise<CustomerLogin> {
  const problem = checkWebsites(websites);
  if (problem) throw notSent("websites", problem);
  return change("websites", `${target(username)}/websites`, { websites: [...websites] }, parseCustomer);
}

export async function setCustomerDisabled(username: string, disabled: boolean): Promise<CustomerLogin> {
  return change("state", `${target(username)}/state`, { disabled }, parseCustomer);
}

export async function newSetupLink(username: string): Promise<CustomerSetupLink> {
  return change("link", `${target(username)}/setup-link`, {}, parseSetupLink);
}

export async function removeCustomer(username: string): Promise<CustomerLogin> {
  return change("remove", `${target(username)}/delete`, {}, parseCustomer);
}
