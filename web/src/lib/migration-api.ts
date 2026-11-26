import { csrfToken, getWebsiteJob, parseJobResponse, readTimeoutMs, request, WordPressApiError } from "./wordpress-api";
import type { WebsiteJob } from "./wordpress-api";

// Client for "Move a website here": migration v1 from a cPanel server over
// root SSH. The old server's key and passwords never reach this page: the
// page shows the key line the admin adds there and the host keys'
// fingerprints, and names the account to move.

export interface HostKey { type: string; fingerprint: string }
export interface MigrationSource {
  id: string;
  host: string;
  port: number;
  key_line: string;
  install_command: string;
  host_keys: HostKey[];
  pinned_fingerprint: string;
  expires_at: string;
}
export interface SourceAccount {
  user: string;
  domain: string;
  disk_used_mib: number;
  disk_limit_mib: number;
  suspended: boolean;
  problem: string;
}

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown, max = 4096): v is string => typeof v === "string" && v.length <= max;
const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const sourceId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);

// A key line a migration could not prove removed from an old server: the
// line ending in `line` is in root's authorized_keys on host, maybe.
export interface StaleKey { id: string; host: string; port: number; line: string; detail: string; since: string }

export function parseStaleKeys(v: unknown): StaleKey[] | undefined {
  if (!object(v) || !Array.isArray(v.keys) || v.keys.length > 256) return undefined;
  const out: StaleKey[] = [];
  for (const k of v.keys) {
    if (!object(k) || !sourceId(k.id) || !text(k.host, 253) || !count(k.port) || !text(k.line, 64) || k.line !== `sifruno-migration-${k.id}` || !text(k.detail, 1100) || !text(k.since, 40)) return undefined;
    out.push({ id: k.id, host: k.host, port: k.port, line: k.line, detail: k.detail, since: k.since });
  }
  return out;
}

export function parseSource(v: unknown): MigrationSource | undefined {
  const s = object(v) ? v.source : undefined;
  if (!object(s) || !sourceId(s.id) || !text(s.host, 253) || !count(s.port) || !text(s.key_line) || !text(s.install_command) || !text(s.pinned_fingerprint, 80) || !text(s.expires_at, 40)) return undefined;
  if (!Array.isArray(s.host_keys) || s.host_keys.length > 8 || !s.host_keys.every((k) => object(k) && text(k.type, 40) && text(k.fingerprint, 80) && k.fingerprint.startsWith("SHA256:"))) return undefined;
  if (!s.key_line.includes(`sifruno-migration-${s.id}`)) return undefined;
  return { id: s.id, host: s.host, port: s.port, key_line: s.key_line, install_command: s.install_command, host_keys: s.host_keys as HostKey[], pinned_fingerprint: s.pinned_fingerprint, expires_at: s.expires_at };
}

export function parseAccounts(v: unknown): SourceAccount[] | undefined {
  if (!object(v) || !Array.isArray(v.accounts) || v.accounts.length > 5000) return undefined;
  const out: SourceAccount[] = [];
  for (const a of v.accounts) {
    if (!object(a) || !text(a.user, 64) || !text(a.domain, 253) || !count(a.disk_used_mib) || !count(a.disk_limit_mib) || typeof a.suspended !== "boolean" || !(a.problem === undefined || text(a.problem, 500))) return undefined;
    out.push({ user: a.user, domain: a.domain, disk_used_mib: a.disk_used_mib, disk_limit_mib: a.disk_limit_mib, suspended: a.suspended, problem: (a.problem as string | undefined) ?? "" });
  }
  return out;
}

// What the person types: a host name or IPv4 address, and the SSH port.
export function checkSourceHost(value: string): string | undefined {
  if (!value) return "Enter the old server's host name or IP address.";
  if (value.includes("/") || value.includes("@")) return "Enter only the host name or IP address, without a user name or path.";
  if (value.includes(":")) return "Enter the port in its own field. IPv6 addresses are not supported yet.";
  if (value !== value.toLowerCase()) return "Use lowercase letters only.";
  if (!/^[a-z0-9.-]+$/.test(value) || !value.includes(".") || value.startsWith("-") || value.startsWith(".") || value.endsWith(".")) return "Enter a host name such as server1.example.com, or an IPv4 address.";
  if (value === "127.0.0.1" || value.startsWith("127.")) return "That is this server itself. Enter the old server's address.";
  return undefined;
}
export function checkSourcePort(value: string): string | undefined {
  if (!/^[1-9][0-9]{0,4}$/.test(value) || Number(value) > 65535) return "Enter the SSH port, a number from 1 to 65535 (usually 22).";
  return undefined;
}
export function checkAcceptReason(value: string): string | undefined {
  const reason = value.trim();
  if (!reason) return "Write why you accept the red lines. The activity log keeps it.";
  if (/\p{Cc}/u.test(reason)) return "Remove line breaks and tabs.";
  if (new TextEncoder().encode(reason).length > 500) return "Use at most 500 characters.";
  return undefined;
}

const unexpected = (what: string, where: string) =>
  new WordPressApiError(0, what, "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", `${where}: response did not match the migration contract`);

const slowMs = 4 * 60 * 1000;
const base = "/api/v1/websites/migrations";

export async function openSource(host: string, port: number, options: { signal?: AbortSignal } = {}): Promise<MigrationSource> {
  const what = "Sifruno could not connect to the old server.";
  const csrf = await csrfToken(options.signal);
  const url = `${base}/sources`;
  const source = parseSource(await request("move", url, { method: "POST", body: { host, port }, csrf, timeoutMs: slowMs, signal: options.signal, what }));
  if (!source) throw unexpected(what, `POST ${url}`);
  return source;
}

export async function getSource(id: string, options: { signal?: AbortSignal } = {}): Promise<MigrationSource> {
  const what = "The connection to the old server could not be loaded.";
  const url = `${base}/sources/${id}`;
  const source = parseSource(await request("move", url, { timeoutMs: readTimeoutMs, signal: options.signal, what }));
  if (!source || source.id !== id) throw unexpected(what, `GET ${url}`);
  return source;
}

export async function confirmFingerprint(id: string, fingerprint: string, options: { signal?: AbortSignal } = {}): Promise<MigrationSource> {
  const what = "The fingerprint was not confirmed.";
  const csrf = await csrfToken(options.signal);
  const url = `${base}/sources/${id}/host-key`;
  const source = parseSource(await request("move", url, { method: "POST", body: { fingerprint }, csrf, timeoutMs: readTimeoutMs, signal: options.signal, what }));
  if (!source || source.pinned_fingerprint !== fingerprint) throw unexpected(what, `POST ${url}`);
  return source;
}

export async function listSourceAccounts(id: string, options: { signal?: AbortSignal } = {}): Promise<SourceAccount[]> {
  const what = "The old server's accounts could not be listed.";
  const url = `${base}/sources/${id}/accounts`;
  const accounts = parseAccounts(await request("move", url, { timeoutMs: slowMs, signal: options.signal, what }));
  if (!accounts) throw unexpected(what, `GET ${url}`);
  return accounts;
}

export async function cancelSource(id: string, options: { signal?: AbortSignal } = {}): Promise<{ removed_from_source: boolean; detail: string }> {
  const what = "The migration key was not removed.";
  const csrf = await csrfToken(options.signal);
  const url = `${base}/sources/${id}/cancel`;
  const value = await request("move", url, { method: "POST", body: {}, csrf, timeoutMs: slowMs, signal: options.signal, what });
  if (!object(value) || typeof value.removed_from_source !== "boolean" || !text(value.detail)) throw unexpected(what, `POST ${url}`);
  return { removed_from_source: value.removed_from_source, detail: value.detail };
}

export async function listStaleKeys(options: { signal?: AbortSignal } = {}): Promise<StaleKey[]> {
  const what = "The key lines left on old servers could not be listed.";
  const url = `${base}/stale-keys`;
  const keys = parseStaleKeys(await request("move", url, { timeoutMs: readTimeoutMs, signal: options.signal, what }));
  if (!keys) throw unexpected(what, `GET ${url}`);
  return keys;
}

export async function clearStaleKey(id: string, options: { signal?: AbortSignal } = {}): Promise<void> {
  const what = "The key line was not taken off the list.";
  const csrf = await csrfToken(options.signal);
  const url = `${base}/stale-keys/${id}/cleared`;
  const value = await request("move", url, { method: "POST", body: {}, csrf, timeoutMs: readTimeoutMs, signal: options.signal, what });
  if (!object(value) || value.cleared !== id) throw unexpected(what, `POST ${url}`);
}

async function jobChange(what: string, url: string, body: unknown, signal?: AbortSignal): Promise<WebsiteJob> {
  const csrf = await csrfToken(signal);
  const job = parseJobResponse(await request("move", url, { method: "POST", body, csrf, timeoutMs: 20000, signal, what }));
  if (!job || job.kind !== "migration" || !job.migration) throw unexpected(what, `POST ${url}`);
  return job;
}

export function startMigration(source: string, username: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteJob> {
  return jobChange("The move was not started.", base, { source, username }, options.signal);
}
export function verifyMigration(id: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteJob> {
  return jobChange("The comparison was not started.", `${base}/${id}/verify`, {}, options.signal);
}
export function acceptMigration(id: string, reason: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteJob> {
  return jobChange("The red lines were not accepted.", `${base}/${id}/accept`, { reason: reason.trim() }, options.signal);
}
export function readyMigration(id: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteJob> {
  return jobChange("The website was not marked ready.", `${base}/${id}/ready`, {}, options.signal);
}
export async function getMigrationJob(id: string, options: { signal?: AbortSignal } = {}): Promise<WebsiteJob> {
  const job = await getWebsiteJob(id, options);
  if (job.kind !== "migration" || !job.migration) throw new WordPressApiError(404, "This move was not found.", "The address points to a website setup, not a move.", "Open it from Websites, or start again from Move a website here.", "job kind is not migration");
  return job;
}
