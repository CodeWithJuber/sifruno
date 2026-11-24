import { validSession } from "./sites-api";

// Client for website backups: the Backup storage page and a website's
// Backups page. The broker does the work and the server is the authority on
// every rule; the checks here mirror it so a form can say what is wrong
// before anything is sent. The repository password arrives once, in the
// answer to the first save, and is never stored, logged or put in an error.

export type JobKind = "backup" | "restore" | "drill";
export type RestoreWhat = "files" | "database" | "both";

export interface BackupTarget { host: string; port: number; user: string; path: string; host_keys: string[] }
export interface DrillRecord {
  account_id: string; domain: string; passed: boolean; checked_at: string;
  snapshot?: string; snapshot_time?: string; files: number; subset?: string;
  message: string; step?: string; detail?: string;
}
export interface PruneRecord { at: string; passed: boolean; removed: number; message: string; step?: string; detail?: string }
export interface BackupStorage {
  ready: boolean; public_key: string; configured: boolean; target: BackupTarget | null;
  nightly_at: string; timezone: string; last_drill: DrillRecord | null; last_prune: PruneRecord | null;
}
export interface BackupStorageSaved extends BackupStorage { initialized: boolean; password?: string }
export interface RunningJob { kind: JobKind; started_at: string; actor: string }
export interface JobResult {
  kind: JobKind; status: "succeeded" | "failed"; started_at: string; finished_at: string; actor: string;
  snapshot?: string; what?: RestoreWhat; message: string; step?: string; detail?: string;
}
export interface Snapshot { id: string; time: string; bytes: number; files: number; databases: string[] }
export interface SiteBackups {
  configured: boolean; ready: boolean; domain: string; revision: number; nightly_at: string; timezone: string;
  running: RunningJob | null; last_backup: JobResult | null; last_restore: JobResult | null; last_drill: DrillRecord | null;
  snapshots: Snapshot[]; snapshots_error: string;
}
export interface TargetForm { host: string; port: string; user: string; path: string; known_hosts: string }

export const readTimeoutMs = 150000; // the server waits up to 2 minutes for the snapshot list
export const saveTimeoutMs = 300000; // opening or making a repository may take 3 minutes
export const pollIntervalMs = 5000;
export const retention = "7 daily and 4 weekly";

// ---- Checks that mirror the server ----------------------------------------

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const bool = (v: unknown): v is boolean => typeof v === "boolean";
const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const date = (v: unknown): v is string => text(v) && v.length <= 64 && !Number.isNaN(Date.parse(v));
const optionalText = (v: unknown, limit = 2000) => v === undefined || (text(v) && v.length <= limit);
export const validAccountId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);
export const validSnapshotId = (v: unknown): v is string => text(v) && /^[a-f0-9]{64}$/.test(v);
const kinds: readonly string[] = ["backup", "restore", "drill"];
const whats: readonly string[] = ["files", "database", "both"];
const dbName = (v: unknown): v is string => text(v) && /^[A-Za-z0-9_]{1,64}$/.test(v);

const hostName = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const ipv6 = /^[0-9a-f:]+$/;

// Each field's rule, as the broker checks it. A message says how to fix it.
export function checkHost(value: string): string | undefined {
  if (!value) return "Enter the storage server's DNS name or IP address.";
  if (value.length > 253) return "Use at most 253 characters.";
  if (value !== value.toLowerCase()) return "Use lowercase letters.";
  if (value.startsWith("-")) return "A host name cannot start with a hyphen.";
  if (value === "0.0.0.0" || value === "::") return "Enter the storage server's own address.";
  if (ipv4.test(value) || (value.includes(":") && ipv6.test(value)) || hostName.test(value)) return undefined;
  return "Use a DNS name such as backup.example.com, or an IP address.";
}

export function checkPort(value: string): string | undefined {
  if (!value) return "Enter the SSH port. It is usually 22.";
  if (!/^\d{1,5}$/.test(value) || Number(value) < 1 || Number(value) > 65535) return "Use a whole number from 1 to 65535.";
  return undefined;
}

export function checkUser(value: string): string | undefined {
  if (!value) return "Enter the user the backups sign in as on the storage server.";
  if (!/^[a-z_][a-z0-9_.-]{0,31}$/.test(value)) return "Use up to 32 lowercase letters, digits, _ . or -, starting with a letter or _.";
  return undefined;
}

export function checkPath(value: string): string | undefined {
  if (!value) return "Enter the folder on the storage server, such as /srv/backups/this-server.";
  if (!value.startsWith("/")) return "Start the folder with / (an absolute path).";
  if (value.length > 512) return "Use at most 512 characters.";
  if (value.endsWith("/") || value.includes("//")) return "Remove the extra or trailing /.";
  if (!/^(\/[A-Za-z0-9._-]+)+$/.test(value)) return "Use only letters, digits and . _ - / in the folder. Spaces and quotes are not allowed.";
  if (value.split("/").some((part) => part === "." || part === "..")) return "Remove . and .. from the folder.";
  return undefined;
}

const keyTypes = new Set(["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"]);

// ssh-keyscan's lines: "[host] type base64", comments skipped. The server
// checks each key in full; this only catches a paste of the wrong thing.
export function checkKnownHosts(value: string): string | undefined {
  if (!value.trim()) return "Paste the storage server's host key. Run ssh-keyscan on a trusted machine to get it.";
  if (value.length > 3500) return "The host key text is too long. Paste only the lines ssh-keyscan prints for this host.";
  const lines = value.split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
  if (lines.length === 0) return "Only comments were pasted. Paste the lines that hold a key.";
  for (const line of lines) {
    const fields = line.split(/\s+/);
    const type = keyTypes.has(fields[0]) ? fields[0] : fields[1];
    const key = keyTypes.has(fields[0]) ? fields[1] : fields[2];
    if (!type || !keyTypes.has(type) || !key || !/^[A-Za-z0-9+/]+={0,2}$/.test(key)) return "Each line must hold a key type (such as ssh-ed25519) and the key, as ssh-keyscan prints them.";
  }
  if (lines.length > 8) return "Paste at most 8 keys.";
  return undefined;
}

export type TargetField = keyof TargetForm;
export const targetChecks: Record<TargetField, (value: string) => string | undefined> = {
  host: checkHost, port: checkPort, user: checkUser, path: checkPath, known_hosts: checkKnownHosts,
};

// The first problem by field, or the exact body the server takes.
export function targetBody(form: TargetForm): { body: { host: string; port: number; user: string; path: string; known_hosts: string } } | { field: TargetField; problem: string } {
  const trimmed = { ...form, host: form.host.trim(), port: form.port.trim(), user: form.user.trim(), path: form.path.trim() };
  for (const field of Object.keys(targetChecks) as TargetField[]) {
    const problem = targetChecks[field](trimmed[field]);
    if (problem) return { field, problem };
  }
  return { body: { host: trimmed.host, port: Number(trimmed.port), user: trimmed.user, path: trimmed.path, known_hosts: trimmed.known_hosts.replace(/\r\n?/g, "\n") } };
}

// A form filled from the saved target, so a change keeps what is there.
export function formFromTarget(target: BackupTarget | null): TargetForm {
  if (!target) return { host: "", port: "22", user: "", path: "", known_hosts: "" };
  return { host: target.host, port: String(target.port), user: target.user, path: target.path, known_hosts: target.host_keys.join("\n") };
}

// A restore goes ahead only when the domain was typed again, exactly.
export function checkConfirmDomain(domain: string, typed: string): string | undefined {
  if (!typed) return `Type ${domain} to confirm.`;
  return typed === domain ? undefined : `That does not match. Type ${domain} exactly.`;
}

export function restoreBody(site: Pick<SiteBackups, "domain" | "revision">, snapshot: Snapshot, what: RestoreWhat, typed: string): { body: { snapshot: string; what: RestoreWhat; confirm_domain: string; expected_revision: number } } | { problem: string } {
  if (!whats.includes(what)) return { problem: "Choose what to restore: files, database or both." };
  if (what !== "files" && snapshot.databases.length === 0) return { problem: "This backup holds no database. Restore the files only." };
  const problem = checkConfirmDomain(site.domain, typed);
  if (problem) return { problem };
  return { body: { snapshot: snapshot.id, what, confirm_domain: typed, expected_revision: site.revision } };
}

// What a restore changes, said before the person confirms it.
export function restoreEffect(what: RestoreWhat): string {
  const files = "The site's files are replaced by the backup's copies. Files added since the backup stay.";
  const database = "The database is replaced by the backup's copy: changes made since the backup, such as new posts or orders, are lost.";
  return what === "files" ? files : what === "database" ? database : `${files} ${database}`;
}

// The page asks again every 5 s while a job runs, and stops when it ends.
export const shouldPoll = (site: Pick<SiteBackups, "running"> | undefined) => Boolean(site?.running);

// The password is shown once: only the answer that carries it opens the
// dialog, and the dialog closes only after the person says it is saved.
export const passwordFrom = (saved: BackupStorageSaved): string | undefined => text(saved.password) && saved.password.length > 0 ? saved.password : undefined;
export const canClosePassword = (confirmed: boolean) => confirmed;

// ---- Words and numbers --------------------------------------------------------

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown size";
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  if (unit === 0) return value === 1 ? "1 byte" : `${value} bytes`;
  return `${value >= 10 ? Math.round(value) : Math.round(value * 10) / 10} ${units[unit]}`;
}

// A valid IANA name is used as is; anything else falls back to the
// browser's zone, named so the person is not misled.
function zoneOrUndefined(timezone: string): string | undefined {
  try { new Intl.DateTimeFormat("en-GB", { timeZone: timezone }); return timezone; } catch { return undefined; }
}

export function formatWhen(iso: string, timezone: string): string {
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return "Unknown time";
  const zone = timezone ? zoneOrUndefined(timezone) : undefined;
  const label = new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", ...(zone ? { timeZone: zone } : {}) }).format(time);
  return zone ? `${label} (${zone})` : `${label} (this browser's time)`;
}

export function scheduleLine(nightlyAt: string, timezone: string): string {
  return `Every night at ${nightlyAt || "02:30"}, ${timezone || "server time"}. Kept: ${retention}.`;
}

export const kindLabel: Record<JobKind, string> = { backup: "Backup", restore: "Restore", drill: "Restore drill" };
export const whatLabel: Record<RestoreWhat, string> = { files: "Files", database: "Database", both: "Files and database" };

export function runningLine(job: RunningJob, timezone: string): string {
  const who = job.actor === "scheduler" ? "the nightly schedule" : job.actor || "someone";
  const verb = job.kind === "backup" ? "A backup" : job.kind === "restore" ? "A restore" : "A restore drill";
  return `${verb} is running. Started by ${who} at ${formatWhen(job.started_at, timezone)}.`;
}

export function drillLine(drill: DrillRecord | null, timezone: string): string {
  if (!drill) return "No restore drill has run yet. The first runs after the first nightly backup.";
  return `${drill.passed ? "Passed" : "Failed"}, ${formatWhen(drill.checked_at, timezone)}, ${drill.domain || "a site"}.`;
}

// Technical details of a result: the step and the broker's words, then the
// backup's id, which only belongs here.
export function resultTechnical(result: { step?: string; detail?: string; snapshot?: string; subset?: string }): string {
  return [result.step ? `step: ${result.step}` : "", result.detail ?? "", result.snapshot ? `backup id: ${result.snapshot}` : "", result.subset ? `data checked: ${result.subset} of the repository` : ""].filter(Boolean).join("\n");
}

// ---- Reading the server's answers -----------------------------------------

function parseTarget(v: unknown): BackupTarget | null | undefined {
  if (v === null || v === undefined) return null;
  if (!object(v) || !text(v.host) || !count(v.port) || !text(v.user) || !text(v.path)) return undefined;
  const keys = v.host_keys === null || v.host_keys === undefined ? [] : v.host_keys;
  if (!Array.isArray(keys) || keys.length > 16 || !keys.every((key) => text(key) && key.length < 2000)) return undefined;
  return { host: v.host, port: v.port, user: v.user, path: v.path, host_keys: [...keys] as string[] };
}

function parseDrill(v: unknown): DrillRecord | null | undefined {
  if (v === null || v === undefined) return null;
  if (!object(v) || !text(v.account_id) || !text(v.domain) || !bool(v.passed) || !date(v.checked_at) || !count(v.files) || !text(v.message)) return undefined;
  if (!optionalText(v.snapshot, 64) || !optionalText(v.subset, 16) || !optionalText(v.step, 32) || !optionalText(v.detail) || (v.snapshot_time !== undefined && !date(v.snapshot_time))) return undefined;
  return { account_id: v.account_id, domain: v.domain, passed: v.passed, checked_at: v.checked_at, snapshot: v.snapshot as string | undefined, snapshot_time: v.snapshot_time as string | undefined, files: v.files, subset: v.subset as string | undefined, message: v.message, step: v.step as string | undefined, detail: v.detail as string | undefined };
}

function parsePrune(v: unknown): PruneRecord | null | undefined {
  if (v === null || v === undefined) return null;
  if (!object(v) || !date(v.at) || !bool(v.passed) || !count(v.removed) || !text(v.message) || !optionalText(v.step, 32) || !optionalText(v.detail)) return undefined;
  return { at: v.at, passed: v.passed, removed: v.removed, message: v.message, step: v.step as string | undefined, detail: v.detail as string | undefined };
}

export function parseBackupStorage(v: unknown): BackupStorage | undefined {
  if (!object(v) || !bool(v.ready) || !text(v.public_key) || !bool(v.configured) || !text(v.nightly_at) || !text(v.timezone)) return undefined;
  const target = parseTarget(v.target);
  const drill = parseDrill(v.last_drill);
  const prune = parsePrune(v.last_prune);
  if (target === undefined || drill === undefined || prune === undefined) return undefined;
  return { ready: v.ready, public_key: v.public_key, configured: v.configured, target, nightly_at: v.nightly_at, timezone: v.timezone, last_drill: drill, last_prune: prune };
}

export function parseBackupStorageSaved(v: unknown): BackupStorageSaved | undefined {
  const storage = parseBackupStorage(v);
  if (!storage || !object(v) || !bool(v.initialized) || !optionalText(v.password, 200)) return undefined;
  return { ...storage, initialized: v.initialized, ...(text(v.password) && v.password ? { password: v.password } : {}) };
}

function parseRunning(v: unknown): RunningJob | null | undefined {
  if (v === null || v === undefined) return null;
  if (!object(v) || !text(v.kind) || !kinds.includes(v.kind) || !date(v.started_at) || !text(v.actor)) return undefined;
  return { kind: v.kind as JobKind, started_at: v.started_at, actor: v.actor };
}

function parseResult(v: unknown): JobResult | null | undefined {
  if (v === null || v === undefined) return null;
  if (!object(v) || !text(v.kind) || !kinds.includes(v.kind) || (v.status !== "succeeded" && v.status !== "failed") || !date(v.started_at) || !date(v.finished_at) || !text(v.actor) || !text(v.message)) return undefined;
  if (!optionalText(v.snapshot, 64) || (v.what !== undefined && !(text(v.what) && whats.includes(v.what))) || !optionalText(v.step, 32) || !optionalText(v.detail)) return undefined;
  return { kind: v.kind as JobKind, status: v.status, started_at: v.started_at, finished_at: v.finished_at, actor: v.actor, snapshot: v.snapshot as string | undefined, what: v.what as RestoreWhat | undefined, message: v.message, step: v.step as string | undefined, detail: v.detail as string | undefined };
}

function parseSnapshot(v: unknown): Snapshot | undefined {
  if (!object(v) || !validSnapshotId(v.id) || !date(v.time) || !count(v.bytes) || !count(v.files)) return undefined;
  const dbs = v.databases === null || v.databases === undefined ? [] : v.databases;
  if (!Array.isArray(dbs) || dbs.length > 64 || !dbs.every(dbName)) return undefined;
  return { id: v.id, time: v.time, bytes: v.bytes, files: v.files, databases: [...dbs] as string[] };
}

export function parseSiteBackups(v: unknown): SiteBackups | undefined {
  if (!object(v) || !bool(v.configured) || !bool(v.ready) || !text(v.domain) || !count(v.revision) || !text(v.nightly_at) || !text(v.timezone) || !text(v.snapshots_error)) return undefined;
  if (!Array.isArray(v.snapshots) || v.snapshots.length > 1000) return undefined;
  const snapshots = (v.snapshots as unknown[]).map(parseSnapshot);
  if (snapshots.some((s) => s === undefined)) return undefined;
  const running = parseRunning(v.running);
  const lastBackup = parseResult(v.last_backup);
  const lastRestore = parseResult(v.last_restore);
  const drill = parseDrill(v.last_drill);
  if (running === undefined || lastBackup === undefined || lastRestore === undefined || drill === undefined) return undefined;
  return { configured: v.configured, ready: v.ready, domain: v.domain, revision: v.revision, nightly_at: v.nightly_at, timezone: v.timezone, running, last_backup: lastBackup, last_restore: lastRestore, last_drill: drill, snapshots: snapshots as Snapshot[], snapshots_error: v.snapshots_error };
}

export function parseStarted(v: unknown): RunningJob | undefined {
  if (!object(v)) return undefined;
  return parseRunning(v.running) ?? undefined;
}

// ---- Errors -----------------------------------------------------------------

export type Operation = "storage" | "saveStorage" | "list" | "backup" | "drill" | "restore";

export const whatFailed: Record<Operation, string> = {
  storage: "The backup storage settings could not be loaded.",
  saveStorage: "The backup storage was not saved.",
  list: "The backups could not be loaded.",
  backup: "The backup did not start.",
  drill: "The restore drill did not start.",
  restore: "The restore did not start.",
};

// message is what happened; why and next are shown under it; technical goes
// under "Technical details".
export class BackupsApiError extends Error {
  readonly status: number;
  readonly why: string;
  readonly next: string;
  readonly technical: string;
  constructor(status: number, what: string, why: string, next: string, technical: string) {
    super(what);
    this.name = "BackupsApiError";
    this.status = status; this.why = why; this.next = next; this.technical = technical;
  }
}

function serverText(v: unknown, limit = 800): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

function serverTechnical(problem: ObjectValue): string {
  if (!Array.isArray(problem.errors)) return "";
  return (problem.errors as unknown[]).slice(0, 4).map((item) => object(item) ? serverText(item.message) : "").filter(Boolean).join("; ");
}

// The server's detail already says why and what next; the panel adds a
// next step only where the server gave none.
function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  const read = operation === "storage" || operation === "list";
  switch (status) {
    case 401: return { why: "Your sign-in has ended.", next: "Sign in again, then try again." };
    case 403: return { why: detail || "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return { why: detail || "The website or backup was not found.", next: "Go back to Websites and open the website again." };
    case 409: return { why: detail || "Something else is running for this site.", next: "Wait for it to finish, reload the page, then try again." };
    case 422: return { why: detail || "The server did not accept one of the values.", next: "Fix the value the message names, then try again." };
    case 429: return { why: detail || "Too many requests in a short time.", next: "Wait a minute, then try again." };
    case 503: return { why: detail || "The account service is not available right now.", next: read ? "Reload the page in a minute." : "Try again in a minute. If it keeps failing, check the Sifruno services on this server." };
    default: return { why: detail || `The server answered with an error (HTTP ${status}).`, next: "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

const unexpected = (operation: Operation, where: string) =>
  new BackupsApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", `${where}: response did not match the backups contract`);

const notSent = (operation: Operation, why: string, technical: string) =>
  new BackupsApiError(422, whatFailed[operation], why, "Fix the marked field, then try again.", `not sent: ${technical}`);

const notAWebsite = (operation: Operation) =>
  new BackupsApiError(404, whatFailed[operation], "This address does not point to a website.", "Go back to Websites and choose the website there.", "the account id is not 32 lowercase hex characters; nothing was sent");

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
        throw new BackupsApiError(0, written ? "The panel could not confirm the change." : whatFailed[operation], `The server did not answer within ${seconds} seconds.`, written ? "Reload the page to see whether it was made before you try again." : "Try again. If it keeps happening, check the server's load.", `${where}: no answer within ${seconds} s`);
      }
      const cancelled = Boolean(options.signal?.aborted);
      throw new BackupsApiError(0, whatFailed[operation], cancelled ? "The request was cancelled." : "The panel could not reach its server.", "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const problem = object(value) ? value : {};
      const title = serverText(problem.title, 100);
      const technical = serverTechnical(problem);
      const { why, next } = explain(operation, response.status, serverText(problem.detail));
      throw new BackupsApiError(response.status, whatFailed[operation], why, next, `${where} returned HTTP ${response.status}${title ? ` (${title})` : ""}${technical ? `: ${technical}` : ""}`);
    }
    return value;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}

async function csrfToken(operation: Operation, signal?: AbortSignal): Promise<string> {
  const ended = (technical: string) => new BackupsApiError(401, whatFailed[operation], "Your sign-in has ended.", "Sign in again, then try again.", technical);
  let value: unknown;
  try {
    value = await request(operation, "/api/v1/session", { timeoutMs: 10000, signal });
  } catch (error) {
    if (error instanceof BackupsApiError && error.status === 401) throw ended("GET /api/v1/session returned HTTP 401");
    throw error;
  }
  if (!validSession(value)) throw unexpected(operation, "GET /api/v1/session");
  if (!value.authenticated) throw ended("GET /api/v1/session: not signed in");
  return value.csrf_token;
}

const storageURL = "/api/v1/websites/backup-storage";
const siteURL = (accountId: string) => `/api/v1/websites/sites/${accountId}/backups`;

export async function getBackupStorage(options: { signal?: AbortSignal } = {}): Promise<BackupStorage> {
  const value = parseBackupStorage(await request("storage", storageURL, { timeoutMs: 30000, signal: options.signal }));
  if (!value) throw unexpected("storage", `GET ${storageURL}`);
  return value;
}

// The answer to the first save carries the repository password; it is
// handed to the caller once and kept nowhere here.
export async function saveBackupStorage(form: TargetForm, options: { signal?: AbortSignal } = {}): Promise<BackupStorageSaved> {
  const checked = targetBody(form);
  if ("problem" in checked) throw notSent("saveStorage", checked.problem, `the ${checked.field} field failed the panel's checks`);
  const csrf = await csrfToken("saveStorage", options.signal);
  const value = parseBackupStorageSaved(await request("saveStorage", storageURL, { method: "POST", body: checked.body, csrf, timeoutMs: saveTimeoutMs, signal: options.signal }));
  if (!value) throw unexpected("saveStorage", `POST ${storageURL}`);
  return value;
}

export async function getSiteBackups(accountId: string, options: { signal?: AbortSignal } = {}): Promise<SiteBackups> {
  if (!validAccountId(accountId)) throw notAWebsite("list");
  const url = siteURL(accountId);
  const value = parseSiteBackups(await request("list", url, { timeoutMs: readTimeoutMs, signal: options.signal }));
  if (!value) throw unexpected("list", `GET ${url}`);
  return value;
}

async function start(operation: Operation, url: string, body: object, signal?: AbortSignal): Promise<RunningJob> {
  const csrf = await csrfToken(operation, signal);
  const running = parseStarted(await request(operation, url, { method: "POST", body, csrf, timeoutMs: readTimeoutMs, signal }));
  if (!running) throw unexpected(operation, `POST ${url}`);
  return running;
}

export async function startBackup(accountId: string, options: { signal?: AbortSignal } = {}): Promise<RunningJob> {
  if (!validAccountId(accountId)) throw notAWebsite("backup");
  return start("backup", siteURL(accountId), {}, options.signal);
}

export async function startDrill(accountId: string, options: { signal?: AbortSignal } = {}): Promise<RunningJob> {
  if (!validAccountId(accountId)) throw notAWebsite("drill");
  return start("drill", `${siteURL(accountId)}/drill`, {}, options.signal);
}

export async function startRestore(accountId: string, site: Pick<SiteBackups, "domain" | "revision">, snapshot: Snapshot, what: RestoreWhat, typed: string, options: { signal?: AbortSignal } = {}): Promise<RunningJob> {
  if (!validAccountId(accountId)) throw notAWebsite("restore");
  if (!validSnapshotId(snapshot.id)) throw notSent("restore", "That backup is not one the panel listed.", "the backup id is not 64 lowercase hex characters");
  const checked = restoreBody(site, snapshot, what, typed);
  if ("problem" in checked) throw notSent("restore", checked.problem, "the restore form failed the panel's checks");
  return start("restore", `${siteURL(accountId)}/restore`, checked.body, options.signal);
}
