import { validSession } from "./sites-api";

// Client for the "New website" wizard (WordPress). The server is the
// authority on every rule; the checks here mirror it so the form can say what
// is wrong before anything is sent. The admin password is sent once, in the
// POST body, and is never logged, stored or put in an error.

export const phpVersions = ["8.1", "8.2", "8.3", "8.4"] as const;
export type PhpVersion = (typeof phpVersions)[number];
export const defaultPhpVersion: PhpVersion = "8.3";

export interface WordPressInput {
  domain: string;
  title: string;
  admin_user: string;
  admin_email: string;
  admin_password: string;
  php_version: string;
}
export type WordPressField = keyof WordPressInput;

export type JobState = "running" | "succeeded" | "failed";
export type StepState = "pending" | "running" | "done" | "failed" | "undone" | "skipped";
export interface JobStep { name: string; title: string; state: StepState; message: string; started_at: string; finished_at: string }
export interface JobError { step: string; what: string; why: string; next: string; technical: string }
export interface JobResult { url: string; admin_url: string; wordpress_version: string; account_id: string }
export interface WebsiteJob {
  id: string;
  kind: "wordpress";
  domain: string;
  username: string;
  state: JobState;
  steps: JobStep[];
  error: JobError | null;
  result: JobResult | null;
  // For now always "local-operator", not a person, so the UI does not show it.
  actor: string;
  created_at: string;
  updated_at: string;
}

export const createTimeoutMs = 20000;
export const readTimeoutMs = 10000;

// ---- Checks that mirror the server ----------------------------------------

// Go's unicode.IsPrint: letters, marks, numbers, punctuation, symbols and the
// ASCII space. Everything else (tabs, line breaks, zero-width and
// non-breaking spaces) is not printable.
const printable = /^[\p{L}\p{M}\p{N}\p{P}\p{S} ]$/u;
const control = /\p{Cc}/u;
const allPrintable = (value: string) => [...value].every((c) => printable.test(c));
// The broker counts title and password limits in UTF-8 bytes, not characters.
const utf8Bytes = (value: string) => new TextEncoder().encode(value).length;

// IPv4 the way Go's net.ParseIP reads it: four decimal parts, 0 to 255, no
// leading zeros.
function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

export function checkDomain(value: string): string | undefined {
  if (!value) return "Enter the domain, for example example.com.";
  if (value.includes("/")) return "Enter only the domain, without http:// or a slash.";
  if (/^[0-9a-fA-F:.]+$/.test(value) && (value.match(/:/g) ?? []).length >= 2) return "Enter a domain name, not an IP address.";
  if (value.includes(":")) return "Enter only the domain, without a port number.";
  if (value !== value.toLowerCase()) return "Use lowercase letters only.";
  if (value.length > 253) return "The domain is too long. Use at most 253 characters.";
  if (isIPv4(value)) return "Enter a domain name, not an IP address.";
  const labels = value.split(".");
  if (labels.length < 2) return "Enter the full domain with its ending, for example example.com.";
  for (const label of labels) {
    if (!label) return "Remove the extra dot.";
    if (!/^[a-z0-9-]+$/.test(label)) return "Use only letters a to z, digits, dots and dashes.";
    if (label.length > 63) return "Each part between dots can have at most 63 characters.";
    if (label.startsWith("-") || label.endsWith("-")) return "A part between dots cannot start or end with a dash.";
  }
  return undefined;
}

// The server trims spaces at both ends first, then checks what is left.
export function checkTitle(value: string): string | undefined {
  const title = value.trim();
  if (!title) return value ? "Enter a site title, not only spaces." : "Enter a site title.";
  if (control.test(title)) return "Remove line breaks, tabs and other control characters.";
  if (!allPrintable(title)) return "Remove invisible characters, such as zero-width or non-breaking spaces.";
  const size = utf8Bytes(title);
  if (size > 200) return `The title is too long: ${size} of 200 bytes. Letters with accents or from other scripts take 2 to 4 bytes each.`;
  return undefined;
}

export function checkAdminUser(value: string): string | undefined {
  if (!value) return "Enter a username for the WordPress admin.";
  if (value.length > 60) return "Use at most 60 characters.";
  if (!/^[A-Za-z0-9_.@-]+$/.test(value)) return "Use only letters, digits and the characters . _ @ -";
  if (value.startsWith("-")) return "Start with a letter, a digit, or one of . _ @";
  return undefined;
}

// The address must be plain (no display name). This is the same pattern the
// browser uses for type="email", so the two never disagree.
const emailPattern = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export function checkAdminEmail(value: string): string | undefined {
  if (!value) return "Enter an email address.";
  if (value.length > 100) return "Use an email address of at most 100 characters.";
  if (!emailPattern.test(value)) return "Enter an email address in the format you@example.com.";
  return undefined;
}

export function checkAdminPassword(value: string): string | undefined {
  if (!value) return "Enter a password.";
  if (control.test(value)) return "Remove line breaks, tabs and other control characters.";
  if (value !== value.trim()) return "Remove the space at the start or end.";
  const size = utf8Bytes(value);
  if (size < 12) return "Use at least 12 characters.";
  if (size > 128) return "The password is too long: use at most 128 bytes. Letters with accents or from other scripts take 2 to 4 bytes each.";
  return undefined;
}

export function checkPhpVersion(value: string): string | undefined {
  return (phpVersions as readonly string[]).includes(value) ? undefined : "Choose PHP 8.1, 8.2, 8.3 or 8.4.";
}

export const fieldChecks: Record<WordPressField, (value: string) => string | undefined> = {
  domain: checkDomain,
  title: checkTitle,
  admin_user: checkAdminUser,
  admin_email: checkAdminEmail,
  admin_password: checkAdminPassword,
  php_version: checkPhpVersion,
};

export function checkWordPressInput(input: WordPressInput): Partial<Record<WordPressField, string>> {
  const problems: Partial<Record<WordPressField, string>> = {};
  for (const field of Object.keys(fieldChecks) as WordPressField[]) {
    const problem = fieldChecks[field](typeof input[field] === "string" ? input[field] : "");
    if (problem) problems[field] = problem;
  }
  return problems;
}

// ---- Reading the server's answers -----------------------------------------

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const optionalText = (v: unknown) => v === undefined || text(v);
const date = (v: unknown): v is string => text(v) && Number.isFinite(Date.parse(v));
const optionalDate = (v: unknown) => v === undefined || v === "" || date(v);
export const validJobId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);
const jobStates: readonly string[] = ["running", "succeeded", "failed"];
const stepStates: readonly string[] = ["pending", "running", "done", "failed", "undone", "skipped"];

// Only http and https links are ever offered to the person.
function webURL(v: unknown): v is string {
  if (!text(v)) return false;
  try { const url = new URL(v); return url.protocol === "http:" || url.protocol === "https:"; } catch { return false; }
}

function parseStep(v: unknown): JobStep | undefined {
  if (!object(v) || !text(v.name) || !v.name || !text(v.title) || !v.title || !stepStates.includes(String(v.state))) return undefined;
  if (!optionalText(v.message) || !optionalDate(v.started_at) || !optionalDate(v.finished_at)) return undefined;
  return { name: v.name, title: v.title, state: v.state as StepState, message: (v.message as string | undefined) ?? "", started_at: (v.started_at as string | undefined) ?? "", finished_at: (v.finished_at as string | undefined) ?? "" };
}

function parseError(v: unknown): JobError | null | undefined {
  if (v === null || v === undefined) return null;
  if (!object(v) || ![v.step, v.what, v.why, v.next, v.technical].every(optionalText)) return undefined;
  const field = (value: unknown) => (value as string | undefined) ?? "";
  return { step: field(v.step), what: field(v.what), why: field(v.why), next: field(v.next), technical: field(v.technical) };
}

function parseResult(v: unknown): JobResult | null | undefined {
  if (v === null || v === undefined) return null;
  if (!object(v) || !webURL(v.url) || !webURL(v.admin_url) || !text(v.wordpress_version) || !optionalText(v.account_id)) return undefined;
  return { url: v.url, admin_url: v.admin_url, wordpress_version: v.wordpress_version, account_id: (v.account_id as string | undefined) ?? "" };
}

export function parseJob(v: unknown): WebsiteJob | undefined {
  if (!object(v) || !validJobId(v.id) || v.kind !== "wordpress" || !text(v.domain) || !v.domain || v.domain.length > 253) return undefined;
  if (!text(v.username) || !/^(?:[a-z][a-z0-9_]{2,31})?$/.test(v.username) || !jobStates.includes(String(v.state))) return undefined;
  if (!Array.isArray(v.steps) || v.steps.length < 1 || v.steps.length > 20) return undefined;
  const steps = v.steps.map(parseStep);
  if (steps.some((step) => !step)) return undefined;
  const error = parseError(v.error), result = parseResult(v.result);
  if (error === undefined || result === undefined) return undefined;
  if (!optionalText(v.actor) || !date(v.created_at) || !date(v.updated_at)) return undefined;
  if (v.state === "succeeded" && !result) return undefined;
  return {
    id: v.id, kind: "wordpress", domain: v.domain, username: v.username, state: v.state as JobState,
    steps: steps as JobStep[], error, result, actor: (v.actor as string | undefined) ?? "",
    created_at: v.created_at, updated_at: v.updated_at,
  };
}

export function parseJobResponse(v: unknown): WebsiteJob | undefined {
  return object(v) ? parseJob(v.job) : undefined;
}

export function parseJobList(v: unknown): WebsiteJob[] | undefined {
  if (!object(v) || !Array.isArray(v.jobs) || v.jobs.length > 20) return undefined;
  const jobs = v.jobs.map(parseJob);
  return jobs.some((job) => !job) ? undefined : jobs as WebsiteJob[];
}

// ---- Errors -----------------------------------------------------------------

// message is what happened; detail is why (the server's problem detail when it
// sent one); next is what the person can do; technical goes under
// "Technical details".
export class WordPressApiError extends Error {
  constructor(
    public readonly status: number,
    what: string,
    public readonly detail: string,
    public readonly next: string,
    public readonly technical: string,
  ) { super(what); this.name = "WordPressApiError"; }
}

type Operation = "create" | "read" | "list";

const whatFailed: Record<Operation, string> = {
  create: "The website was not created.",
  read: "The setup progress could not be loaded.",
  list: "Recent website setups could not be loaded.",
};

// Server text is shown as text. Keep it short and on one line.
function serverText(v: unknown, limit = 500): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  const read = operation !== "create";
  const keepsRunning = read ? " The setup keeps running on the server." : "";
  // The server's detail is the reason whenever it sent one.
  const versions = "Reload the page and try again. If it happens again, the panel and the server may be different versions.";
  switch (status) {
    case 400: return { why: detail || "The server could not read the request.", next: versions };
    case 401: return { why: "Your sign-in has ended.", next: read ? `Sign in again to see the progress.${keepsRunning}` : "Sign in again, then press Create website. Your entries are kept." };
    case 403: return { why: detail || "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return { why: detail || "The address may be wrong, or the setup record was removed.", next: "Check the address, or start again from New website." };
    case 409: return { why: detail || "Another setup is using this domain, the domain is already in use, or too many setups are running.", next: "Wait for the running setups to finish, or use a domain that is not in use yet." };
    case 413: return { why: detail || "The request was too large for the server.", next: "Shorten the site title or the password, then try again." };
    case 415: return { why: detail || "The server did not accept the request format.", next: versions };
    case 422: return { why: detail || "The server did not accept one of the values.", next: "Fix the value the message names, then press Create website again." };
    case 429: return { why: detail || "Too many requests in a short time.", next: "Wait a minute, then try again." };
    case 503: return { why: detail || "The part of the server that creates accounts or databases is not available right now.", next: `Try again in a minute. If it keeps failing, check the Sifruno services and this server's website setup.${keepsRunning}` };
    default: return { why: detail || `The server answered with an error (HTTP ${status}).`, next: `Try again. If it keeps failing, check the Sifruno service log.${keepsRunning}` };
  }
}

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
        const next = operation === "create"
          ? "Wait a minute, then try again. If the domain is reported as in use, the first try worked."
          : "This page tries again by itself. The setup keeps running on the server.";
        throw new WordPressApiError(0, operation === "create" ? "The panel could not confirm the new website." : whatFailed[operation], `The server did not answer within ${seconds} seconds.`, next, `${where}: no answer within ${seconds} s`);
      }
      throw new WordPressApiError(0, whatFailed[operation], options.signal?.aborted ? "The request was cancelled." : "The panel could not reach its server.", "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${options.signal?.aborted ? "cancelled" : "network error"}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const detail = serverText(problem.detail);
      const title = serverText(problem.title, 100);
      const { why, next } = explain(operation, response.status, detail);
      throw new WordPressApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${title ? ` (${title})` : ""}`);
    }
    return value;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}

const unexpected = (operation: Operation, where: string) =>
  new WordPressApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", `${where}: response did not match the website job contract`);

// The CSRF token comes from the current session, as for every other change
// the panel makes.
async function csrfToken(signal?: AbortSignal): Promise<string> {
  let value: unknown;
  try {
    value = await request("create", "/api/v1/session", { timeoutMs: readTimeoutMs, signal });
  } catch (error) {
    if (error instanceof WordPressApiError && error.status === 401) throw new WordPressApiError(401, whatFailed.create, "Your sign-in has ended.", "Sign in again, then press Create website. Your entries are kept.", "GET /api/v1/session returned HTTP 401");
    throw error;
  }
  if (!validSession(value)) throw unexpected("create", "GET /api/v1/session");
  if (!value.authenticated) throw new WordPressApiError(401, whatFailed.create, "Your sign-in has ended.", "Sign in again, then press Create website. Your entries are kept.", "GET /api/v1/session: not signed in");
  return value.csrf_token;
}

export async function createWordPressSite(input: WordPressInput, options: { signal?: AbortSignal } = {}): Promise<WebsiteJob> {
  const problems = checkWordPressInput(input);
  const fields = Object.keys(problems) as WordPressField[];
  if (fields.length) throw new WordPressApiError(422, whatFailed.create, problems[fields[0]] ?? "", "Fix the marked fields, then press Create website again.", `not sent: ${fields.join(", ")} failed the panel's checks`);
  const csrf = await csrfToken(options.signal);
  // Exactly the six keys the server accepts, nothing else. The title is sent
  // trimmed, as the server would store it.
  const body = { domain: input.domain, title: input.title.trim(), admin_user: input.admin_user, admin_email: input.admin_email, admin_password: input.admin_password, php_version: input.php_version };
  const url = "/api/v1/websites/wordpress";
  const job = parseJobResponse(await request("create", url, { method: "POST", body, csrf, timeoutMs: createTimeoutMs, signal: options.signal }));
  if (!job || job.domain !== input.domain) throw unexpected("create", `POST ${url}`);
  return job;
}

export async function getWebsiteJob(id: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteJob> {
  if (!validJobId(id)) throw new WordPressApiError(404, whatFailed.read, "This address does not point to a website setup.", "Check the address, or start again from New website.", "job id is not 32 lowercase hex characters; nothing was sent");
  const url = `/api/v1/websites/jobs/${id}`;
  const job = parseJobResponse(await request("read", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!job || job.id !== id) throw unexpected("read", `GET ${url}`);
  return job;
}

export async function listWebsiteJobs(options: { signal?: AbortSignal } = {}): Promise<WebsiteJob[]> {
  const url = "/api/v1/websites/jobs";
  const jobs = parseJobList(await request("list", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!jobs) throw unexpected("list", `GET ${url}`);
  return jobs;
}

// Counts for the progress bar: finished steps out of all steps.
export function jobProgress(job: WebsiteJob): { done: number; total: number } {
  return { done: job.steps.filter((step) => step.state === "done" || step.state === "skipped").length, total: job.steps.length };
}
