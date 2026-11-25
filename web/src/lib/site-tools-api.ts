import { validSession } from "./sites-api";
import { parseWebsiteUsage, validAccountId } from "./websites-api";
import type { WebsiteUsage } from "./websites-api";

// Client for a website's scheduled jobs, logs and usage. The server asks the
// hosting account service, which writes the account's crontab and reads the
// site's logs and quota; the jobs run as the site's own user.

export interface CronJob { schedule: string; command: string }
// next_run: RFC 3339 on the server's clock, or empty when the schedule names
// no date that comes (31 February).
export interface CronEntry extends CronJob { next_run: string }
export interface WebsiteCron {
  jobs: CronEntry[];
  max_jobs: number;
  // The server's clock, RFC 3339 with its UTC offset: schedules run on it.
  server_time: string;
  // The hosting account's revision; a change sends it back.
  revision: number;
  state: string;
}
export type LogKind = "access" | "error";
// lines hold what visitors sent: they are shown as text, never as markup.
export interface WebsiteLog {
  kind: LogKind;
  lines: string[];
  truncated: boolean;
  size_bytes: number;
  missing: boolean;
}

export const maxJobs = 50;
export const maxCommandBytes = 1024;
export const readTimeoutMs = 15000;
export const changeTimeoutMs = 60000;

// ---- The job grammar, as the account service checks it -------------------

// minute, hour, day of month, month, day of week (0 and 7 are Sunday).
const fields: readonly { name: string; lo: number; hi: number }[] = [
  { name: "minute", lo: 0, hi: 59 }, { name: "hour", lo: 0, hi: 23 }, { name: "day of month", lo: 1, hi: 31 },
  { name: "month", lo: 1, hi: 12 }, { name: "day of week", lo: 0, hi: 7 },
];

function number(text: string): number | undefined {
  return /^[0-9]{1,2}$/.test(text) ? Number(text) : undefined;
}

function fieldValid(field: string, lo: number, hi: number): boolean {
  if (field === "") return false;
  return field.split(",").every((item) => {
    const [range, step, extra] = item.split("/");
    if (extra !== undefined) return false;
    if (step !== undefined) {
      const n = number(step);
      if (n === undefined || n < 1 || n > hi) return false;
    }
    if (range === "*") return true;
    const [a, b, more] = range.split("-");
    if (more !== undefined) return false;
    const first = number(a);
    if (first === undefined) return false;
    if (b === undefined) return step === undefined && first >= lo && first <= hi;
    const last = number(b);
    return last !== undefined && first >= lo && last <= hi && first <= last;
  });
}

// Spaces and tabs between fields become one space, as the server needs.
export const normalizeSchedule = (value: string): string => value.trim().split(/[ \t]+/).join(" ");

// What is wrong with a schedule, in words, or undefined. The same rules as
// the account service: five fields, each *, */step, n, n-m, n-m/step or a
// comma list of these; no names, no @ shortcuts.
export function scheduleProblem(value: string): string | undefined {
  const schedule = normalizeSchedule(value);
  if (schedule === "") return "Enter a schedule, or choose one from the list.";
  if (schedule.length > 100) return "The schedule is longer than 100 characters.";
  if (schedule.startsWith("@")) return "Shortcuts such as @daily are not supported. Choose a schedule from the list instead.";
  const parts = schedule.split(" ");
  if (parts.length !== 5) return "A schedule has five fields: minute, hour, day of month, month and day of week.";
  for (let i = 0; i < 5; i++) {
    const { name, lo, hi } = fields[i];
    if (!fieldValid(parts[i], lo, hi)) return `The ${name} field "${parts[i]}" is not valid. Use *, */step, a number from ${lo} to ${hi}, a range such as ${lo}-${Math.min(lo + 4, hi)}, or a comma list.`;
  }
  return undefined;
}

const encoder = new TextEncoder();

// What is wrong with a command, in words, or undefined.
export function commandProblem(value: string): string | undefined {
  if (value.trim() === "") return "Enter the command to run.";
  if (value !== value.trim()) return "Remove the spaces at the start or end of the command.";
  if (encoder.encode(value).length > maxCommandBytes) return "The command is longer than 1024 bytes. Put it in a script in the site's home and run the script.";
  if (/[\p{Cc}\u2028\u2029]/u.test(value)) return "The command must be one line, without tabs.";
  if (value.includes("%")) return "The command contains %, which cron turns into a new line. Put the command in a script and schedule the script.";
  if (value.startsWith("-") || value.startsWith("*")) return "The command starts with - or *, which cron reads as part of the schedule line. Start it with the program to run.";
  return undefined;
}

// ---- Presets ----------------------------------------------------------------

export interface CronPreset { id: string; label: string; schedule: string }
export const cronPresets: readonly CronPreset[] = [
  { id: "every-5-minutes", label: "Every 5 minutes", schedule: "*/5 * * * *" },
  { id: "every-15-minutes", label: "Every 15 minutes", schedule: "*/15 * * * *" },
  { id: "hourly", label: "Every hour", schedule: "0 * * * *" },
  { id: "daily", label: "Every day at 03:00", schedule: "0 3 * * *" },
  { id: "weekly", label: "Every Sunday at 03:00", schedule: "0 3 * * 0" },
  { id: "monthly", label: "On the 1st of every month at 03:00", schedule: "0 3 1 * *" },
];

// A schedule in words when it is one of the presets.
export function scheduleLabel(schedule: string): string | undefined {
  return cronPresets.find((preset) => preset.schedule === schedule)?.label;
}

// ---- Showing values ----------------------------------------------------------

// Bytes in the panel's units: 1024 bytes to a KB, as limits are shown.
export function bytesLabel(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "unknown";
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  if (unit === 0) return `${bytes} ${bytes === 1 ? "byte" : "bytes"}`;
  return `${value >= 100 || Number.isInteger(value) ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

// The server's UTC offset from its clock, such as "UTC+04:00".
export function serverZone(serverTime: string): string {
  const m = /([+-]\d{2}:\d{2}|Z)$/.exec(serverTime);
  if (!m) return "the server's time zone";
  return m[1] === "Z" || m[1] === "+00:00" ? "UTC" : `UTC${m[1]}`;
}

// A run time on the server's own clock, as cron reads schedules: the
// wall-clock part of the RFC 3339 text, which carries the server's offset.
export function serverClock(value: string, locale?: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(value);
  if (!m) return "Never: the schedule names no date that comes";
  const [, y, mo, d, h, mi] = m.map(Number);
  const wall = new Date(Date.UTC(y, mo - 1, d, h, mi));
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(wall);
}

export interface DiskUse { used: string; limit?: string; percent?: number; full: boolean }
export function diskUse(usage: WebsiteUsage): DiskUse {
  const used = bytesLabel(usage.disk_used_bytes);
  if (usage.disk_limit_bytes <= 0) return { used, full: false };
  const percent = Math.min(100, Math.round((usage.disk_used_bytes / usage.disk_limit_bytes) * 100));
  return { used, limit: bytesLabel(usage.disk_limit_bytes), percent, full: usage.disk_used_bytes >= usage.disk_limit_bytes };
}

// "November 2026" from "2026-11".
export function monthLabel(month: string, locale?: string): string {
  const m = /^(\d{4})-(\d{2})$/.exec(month);
  if (!m) return month;
  return new Intl.DateTimeFormat(locale, { month: "long", year: "numeric", timeZone: "UTC" }).format(new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, 1)));
}

// ---- Reading the server's answers ----------------------------------------------

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const whole = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const runTime = (v: unknown): v is string => v === "" || (text(v) && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$/.test(v));

export function parseWebsiteCron(v: unknown): WebsiteCron | undefined {
  if (!object(v) || !Array.isArray(v.jobs) || v.jobs.length > maxJobs || v.max_jobs !== maxJobs || !runTime(v.server_time) || v.server_time === "") return undefined;
  if (!whole(v.revision) || v.revision < 1 || !text(v.state) || !/^[a-z_]{1,40}$/.test(v.state)) return undefined;
  const jobs: CronEntry[] = [];
  for (const j of v.jobs) {
    if (!object(j) || !text(j.schedule) || !text(j.command) || !runTime(j.next_run)) return undefined;
    if (scheduleProblem(j.schedule) || commandProblem(j.command)) return undefined;
    jobs.push({ schedule: j.schedule, command: j.command, next_run: j.next_run as string });
  }
  return { jobs, max_jobs: maxJobs, server_time: v.server_time as string, revision: v.revision, state: v.state };
}

export function parseWebsiteLog(v: unknown, kind: LogKind): WebsiteLog | undefined {
  if (!object(v) || v.kind !== kind || !Array.isArray(v.lines) || v.lines.length > 200 || !v.lines.every(text)) return undefined;
  if (typeof v.truncated !== "boolean" || typeof v.missing !== "boolean" || !whole(v.size_bytes)) return undefined;
  return { kind, lines: [...v.lines], truncated: v.truncated, size_bytes: v.size_bytes, missing: v.missing };
}

// ---- Errors -------------------------------------------------------------------

type Operation = "jobs" | "save-jobs" | "log" | "usage";
const whatFailed: Record<Operation, string> = {
  jobs: "The scheduled jobs could not be loaded.",
  "save-jobs": "The scheduled jobs were not saved.",
  log: "The log could not be loaded.",
  usage: "The usage could not be loaded.",
};
const seeItNow = "Reload the page to see the jobs as they are now before you try again.";

// message is what happened; why and next are shown under it; technical goes
// under "Technical details".
export class SiteToolsApiError extends Error {
  readonly status: number;
  readonly why: string;
  readonly next: string;
  readonly technical: string;
  constructor(status: number, what: string, why: string, next: string, technical: string) {
    super(what);
    this.name = "SiteToolsApiError";
    this.status = status; this.why = why; this.next = next; this.technical = technical;
  }
}

function serverText(v: unknown, limit = 500): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  const change = operation === "save-jobs";
  switch (status) {
    case 401: return { why: "Your sign-in has ended.", next: "Sign in again, then try again." };
    case 403: return { why: detail || "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return { why: detail || "That website was not found.", next: "Go back to Websites and choose it again." };
    case 409: return { why: detail || "The website changed or was busy.", next: seeItNow };
    case 413: case 422: return { why: detail || "The server did not accept the jobs.", next: "Correct the job named above, then save again." };
    case 503: return { why: detail || "The account service is not available right now.", next: change ? seeItNow : "Try again in a minute. If it keeps failing, check the Sifruno services on this server." };
    default: return { why: detail || `The server answered with an error (HTTP ${status}).`, next: change ? seeItNow : "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

const unexpected = (operation: Operation, where: string) => new SiteToolsApiError(0,
  operation === "save-jobs" ? "The panel could not confirm the change." : whatFailed[operation],
  "The server's answer was not in the form the panel expects.",
  operation === "save-jobs" ? seeItNow : "Reload the page. If it happens again, the panel and the server may be different versions.",
  `${where}: response did not match the contract`);

async function request(operation: Operation, url: string, options: { method?: "GET" | "POST"; body?: unknown; csrf?: string; timeoutMs: number; signal?: AbortSignal }): Promise<unknown> {
  const method = options.method ?? "GET";
  const where = `${method} ${url}`;
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
      const what = sent ? "The panel could not confirm the change." : whatFailed[operation];
      if (timedOut) throw new SiteToolsApiError(0, what, `The server did not answer within ${Math.round(options.timeoutMs / 1000)} seconds.`, sent ? seeItNow : "Try again.", `${where}: no answer in time`);
      const cancelled = Boolean(options.signal?.aborted);
      throw new SiteToolsApiError(0, what, cancelled ? "The request was cancelled." : "The panel could not reach its server.", sent ? seeItNow : "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const first = Array.isArray(problem.errors) && object(problem.errors[0]) ? serverText(problem.errors[0].message, 300) : "";
      const { why, next } = explain(operation, response.status, serverText(problem.detail, 900));
      throw new SiteToolsApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${first ? `; ${first}` : ""}`);
    }
    return value;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}

function siteURL(operation: Operation, accountId: string, suffix: string): string {
  if (!validAccountId(accountId)) throw new SiteToolsApiError(404, whatFailed[operation], "This page does not point to a website.", "Go back to Websites and choose the website there.", "account id is not 32 lowercase hex characters; nothing was sent");
  return `/api/v1/websites/sites/${accountId}${suffix}`;
}

export async function getCron(accountId: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteCron> {
  const url = siteURL("jobs", accountId, "/cron");
  const cron = parseWebsiteCron(await request("jobs", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!cron) throw unexpected("jobs", `GET ${url}`);
  return cron;
}

// Saves the whole job list at the revision the section read. Nothing has
// been sent when the session check fails.
export async function saveCron(accountId: string, revision: number, jobs: CronJob[], options: { signal?: AbortSignal } = {}): Promise<WebsiteCron> {
  const url = siteURL("save-jobs", accountId, "/cron");
  const session = await request("save-jobs", "/api/v1/session", { timeoutMs: readTimeoutMs, signal: options.signal }).catch((error) => {
    if (error instanceof SiteToolsApiError && error.status === 401) throw new SiteToolsApiError(401, whatFailed["save-jobs"], "Your sign-in has ended.", "Sign in again, then try again.", "GET /api/v1/session returned HTTP 401; nothing was sent");
    throw error;
  });
  if (!validSession(session) || !session.authenticated) throw new SiteToolsApiError(401, whatFailed["save-jobs"], "Your sign-in has ended.", "Sign in again, then try again.", "GET /api/v1/session: not signed in; nothing was sent");
  const body = { jobs: jobs.map((j) => ({ schedule: j.schedule, command: j.command })), expected_revision: revision };
  const cron = parseWebsiteCron(await request("save-jobs", url, { method: "POST", body, csrf: session.csrf_token, timeoutMs: changeTimeoutMs, signal: options.signal }));
  if (!cron) throw unexpected("save-jobs", `POST ${url}`);
  return cron;
}

export async function getLog(accountId: string, kind: LogKind, options: { signal?: AbortSignal } = {}): Promise<WebsiteLog> {
  const url = siteURL("log", accountId, `/logs/${kind}`);
  const log = parseWebsiteLog(await request("log", url, { timeoutMs: readTimeoutMs, signal: options.signal }), kind);
  if (!log) throw unexpected("log", `GET ${url}`);
  return log;
}

export async function getUsage(accountId: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteUsage> {
  const url = siteURL("usage", accountId, "/usage");
  const usage = parseWebsiteUsage(await request("usage", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!usage) throw unexpected("usage", `GET ${url}`);
  return usage;
}
