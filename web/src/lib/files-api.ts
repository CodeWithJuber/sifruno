import { validSession } from "./sites-api";

// Client for a website's Files page: the hosting account's real home
// folder. The server runs every operation as the site's own user and is the
// authority on every rule; the checks here mirror it so the page can say
// what is wrong before anything is sent. Paths are relative to the home:
// "" is the home itself.

export type EntryType = "file" | "folder" | "link" | "other";
export interface FileEntry {
  name: string;
  // link: a symbolic link, shown as itself; the server never follows it.
  // other: a device, socket or pipe.
  type: EntryType;
  size: number;
  // Four octal digits, such as "0644".
  mode: string;
  // RFC 3339 in UTC.
  modified: string;
  // Files only: changes whenever the file changes. A save sends it back.
  version?: string;
}
export interface Folder { path: string; entries: FileEntry[]; skipped: number; truncated: boolean }
export interface FileText { path: string; file: FileEntry; content: string }

// The server's bounds.
export const maxTextBytes = 1 << 20;
export const maxUploadBytes = 64 << 20;
export const maxPathBytes = 1024;
export const maxNameBytes = 255;
export const maxDepth = 64;
export const maxEntries = 5000;
// The folder the website serves. The page does not delete, rename or
// re-permission it; the server refuses that too.
export const siteFolder = "public_html";

export const readTimeoutMs = 20000;
// The server gives a change 3 minutes, and an upload 16.
export const changeTimeoutMs = 3.5 * 60 * 1000;
export const uploadTimeoutMs = 16.5 * 60 * 1000;

// ---- Names and paths ----------------------------------------------------------

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";
const control = /\p{Cc}/u;
const utf8Bytes = (value: string) => new TextEncoder().encode(value).length;
export const validAccountId = (v: unknown): v is string => text(v) && /^[a-f0-9]{32}$/.test(v);

// A string that UTF-8 can carry: no lone surrogate. JSON would send one as
// an escape the server turns into a replacement character.
export function wellFormed(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

// What is wrong with a new name for a file or folder, or undefined.
export function checkName(name: string): string | undefined {
  if (!name) return "Enter a name.";
  if (name === "." || name === "..") return "A name cannot be . or .. on its own.";
  if (name.includes("/")) return "A name cannot hold a slash (/). Open the folder first, then make the new one there.";
  if (control.test(name) || !wellFormed(name)) return "Remove line breaks, tabs and other control characters.";
  if (utf8Bytes(name) > maxNameBytes) return `The name is too long: use at most ${maxNameBytes} bytes. Letters with accents or from other scripts take 2 to 4 bytes each.`;
  return undefined;
}

// A path as the server accepts it: names joined by "/", none of them empty,
// "." or "..", within the bounds.
export function validPath(path: string): boolean {
  if (path === "") return true;
  if (utf8Bytes(path) > maxPathBytes) return false;
  const names = path.split("/");
  return names.length <= maxDepth && names.every((name) => checkName(name) === undefined);
}

export const joinPath = (folder: string, name: string) => folder ? `${folder}/${name}` : name;
export const parentPath = (path: string) => path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
export const baseName = (path: string) => path.slice(path.lastIndexOf("/") + 1);

// The breadcrumb: the home, then each folder down to path.
export function pathTrail(path: string): { name: string; path: string }[] {
  const trail = [{ name: "Home folder", path: "" }];
  if (!path) return trail;
  let current = "";
  for (const name of path.split("/")) {
    current = joinPath(current, name);
    trail.push({ name, path: current });
  }
  return trail;
}

// ---- What the page shows --------------------------------------------------------

export function sizeLabel(bytes: number, locale?: string): string {
  if (bytes < 1024) return `${bytes} ${bytes === 1 ? "byte" : "bytes"}`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: value < 10 ? 1 : 0 }).format(value)} ${units[unit]}`;
}

export function modifiedLabel(modified: string, locale?: string): string {
  const when = new Date(modified);
  return Number.isNaN(when.getTime()) ? "Unknown" : new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(when);
}

export interface Permissions { owner: Triple; group: Triple; others: Triple }
export interface Triple { read: boolean; write: boolean; execute: boolean }
const tripleOf = (digit: number): Triple => ({ read: (digit & 4) !== 0, write: (digit & 2) !== 0, execute: (digit & 1) !== 0 });
const digitOf = (t: Triple) => (t.read ? 4 : 0) + (t.write ? 2 : 0) + (t.execute ? 1 : 0);

// The permission bits of a listed mode; setuid, setgid and sticky are
// shown by modeLabel but the page never sets them.
export function permissionsOf(mode: string): Permissions {
  const bits = Number.parseInt(mode, 8) & 0o777;
  return { owner: tripleOf(bits >> 6), group: tripleOf((bits >> 3) & 7), others: tripleOf(bits & 7) };
}
export const modeOf = (p: Permissions) => `0${digitOf(p.owner)}${digitOf(p.group)}${digitOf(p.others)}`;
export const specialBits = (mode: string) => (Number.parseInt(mode, 8) & 0o7000) !== 0;

// "rw-r--r--", as ls shows it.
export function modeLabel(mode: string): string {
  const p = permissionsOf(mode);
  return [p.owner, p.group, p.others].map((t) => `${t.read ? "r" : "-"}${t.write ? "w" : "-"}${t.execute ? "x" : "-"}`).join("");
}

export function typeLabel(entry: FileEntry): string {
  switch (entry.type) {
    case "folder": return "Folder";
    case "link": return "Link";
    case "other": return "Special file";
    default: return "File";
  }
}

// Folders first, then by name as the reader's language sorts it.
export function sortEntries(entries: readonly FileEntry[], locale?: string): FileEntry[] {
  const collator = new Intl.Collator(locale, { numeric: true, sensitivity: "base" });
  return [...entries].sort((a, b) => (a.type === "folder" ? 0 : 1) - (b.type === "folder" ? 0 : 1) || collator.compare(a.name, b.name));
}

// What can be done with an entry. A link or special file can only be
// renamed or deleted; a file small enough opens in the editor.
export function actionsFor(entry: FileEntry, path: string, writable: boolean) {
  const own = path === siteFolder;
  return {
    open: entry.type === "folder",
    edit: entry.type === "file" && entry.size <= maxTextBytes,
    download: entry.type === "file",
    rename: writable && !own,
    permissions: writable && !own && (entry.type === "file" || entry.type === "folder"),
    remove: writable && !own,
  };
}

// ---- Reading the server's answers -------------------------------------------------

const modeForm = /^[0-7]{4}$/;
const versionForm = /^[0-9a-f]{16}$/;
const types: readonly string[] = ["file", "folder", "link", "other"];

export function parseEntry(v: unknown): FileEntry | undefined {
  if (!object(v) || !text(v.name) || checkName(v.name) !== undefined || !text(v.type) || !types.includes(v.type)) return undefined;
  if (!Number.isSafeInteger(v.size) || (v.size as number) < 0 || !text(v.mode) || !modeForm.test(v.mode) || !text(v.modified) || Number.isNaN(Date.parse(v.modified))) return undefined;
  const type = v.type as EntryType;
  if (type === "file" ? !(text(v.version) && versionForm.test(v.version)) : v.version !== undefined || v.size !== 0) return undefined;
  return { name: v.name, type, size: v.size as number, mode: v.mode, modified: v.modified, ...(type === "file" ? { version: v.version as string } : {}) };
}

export function parseFolder(v: unknown, path: string): Folder | undefined {
  if (!object(v) || v.path !== path || !Array.isArray(v.entries) || v.entries.length > maxEntries || !Number.isSafeInteger(v.skipped) || (v.skipped as number) < 0 || typeof v.truncated !== "boolean") return undefined;
  const entries: FileEntry[] = [];
  const seen = new Set<string>();
  for (const item of v.entries as unknown[]) {
    const entry = parseEntry(item);
    if (!entry || seen.has(entry.name)) return undefined;
    seen.add(entry.name);
    entries.push(entry);
  }
  return { path, entries, skipped: v.skipped as number, truncated: v.truncated };
}

export function parseFileText(v: unknown, path: string): FileText | undefined {
  if (!object(v) || v.path !== path || !text(v.content)) return undefined;
  const file = parseEntry(v.file);
  if (!file || file.type !== "file" || file.name !== baseName(path) || utf8Bytes(v.content) !== file.size) return undefined;
  return { path, file, content: v.content };
}

// ---- Errors ---------------------------------------------------------------------------

export type Operation = "list" | "read" | "save" | "upload" | "folder" | "rename" | "delete" | "mode";
const changes: readonly Operation[] = ["save", "upload", "folder", "rename", "delete", "mode"];

export const whatFailed: Record<Operation, string> = {
  list: "The folder could not be opened.",
  read: "The file could not be opened.",
  save: "The file was not saved.",
  upload: "The file was not uploaded.",
  folder: "The folder was not made.",
  rename: "The name was not changed.",
  delete: "Nothing was deleted.",
  mode: "The permissions were not changed.",
};
const notConfirmed = "The panel could not confirm the change.";
const seeItNow = "Reload the folder to see it as it is now, then try again.";

// message is what happened; why says why and, from the server, what to do;
// next is the step when the server gave none; technical goes under
// "Technical details".
export class FilesApiError extends Error {
  readonly status: number;
  readonly why: string;
  readonly next: string;
  readonly technical: string;
  constructor(status: number, what: string, why: string, next: string, technical: string) {
    super(what);
    this.name = "FilesApiError";
    this.status = status; this.why = why; this.next = next; this.technical = technical;
  }
}

function serverText(v: unknown, limit = 600): string {
  return text(v) ? v.replace(/\p{Cc}+/gu, " ").trim().slice(0, limit) : "";
}

// The server's detail already says why and what to do; these stand in when
// it sent none (an older server, a proxy's error page).
function explain(operation: Operation, status: number, detail: string): { why: string; next: string } {
  if (detail) return { why: detail, next: "" };
  const change = changes.includes(operation);
  switch (status) {
    case 401: return { why: "Your sign-in has ended.", next: "Sign in again, then try again." };
    case 403: return { why: "The panel refused the request because the session or page origin did not match.", next: "Reload the page, sign in if asked, and try again." };
    case 404: return { why: "That website, file or folder was not found.", next: seeItNow };
    case 409: return { why: "The website or the file changed, or the website was busy.", next: seeItNow };
    case 413: return { why: "The file is larger than the file manager allows.", next: "Use SFTP for large files." };
    case 503: return { why: "The account service is not available right now.", next: change ? seeItNow : "Try again in a minute. If it keeps failing, check the Sifruno services on this server." };
    default: return { why: `The server answered with an error (HTTP ${status}).`, next: change ? seeItNow : "Try again. If it keeps failing, check the Sifruno service log." };
  }
}

function problem(operation: Operation, status: number, value: unknown, where: string): FilesApiError {
  const body = object(value) ? value : {};
  const title = serverText(body.title, 100);
  const first = Array.isArray(body.errors) && object(body.errors[0]) ? serverText(body.errors[0].message, 300) : "";
  // A refusal by the panel's own admission has {error, message}.
  const detail = serverText(body.detail, 900) || serverText(body.message, 300);
  const { why, next } = explain(operation, status, detail);
  return new FilesApiError(status, whatFailed[operation], why, next, `${where} returned HTTP ${status}${title ? ` (${title})` : ""}${first ? `; ${first}` : ""}`);
}

const unexpected = (operation: Operation, where: string) => changes.includes(operation)
  ? new FilesApiError(0, notConfirmed, "The server's answer was not in the form the panel expects, so the panel cannot tell whether the change was made.", seeItNow, `${where}: response did not match the files contract`)
  : new FilesApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page. If it happens again, the panel and the server may be different versions.", `${where}: response did not match the files contract`);

const refused = (operation: Operation, why: string, technical: string) => new FilesApiError(0, whatFailed[operation], why, "", `${technical}; nothing was sent`);

// ---- Requests -------------------------------------------------------------------------

const base = (accountId: string) => `/api/v1/websites/sites/${accountId}/files`;
const query = (path: string) => `?path=${encodeURIComponent(path)}`;

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
      const what = sent ? notConfirmed : whatFailed[operation];
      if (timedOut) throw new FilesApiError(0, what, `The server did not answer within ${Math.round(options.timeoutMs / 1000)} seconds.`, sent ? seeItNow : "Try again. If it keeps happening, check the server's load.", `${where}: no answer in time`);
      const cancelled = Boolean(options.signal?.aborted);
      throw new FilesApiError(0, what, cancelled ? "The request was cancelled." : sent ? "The panel lost its connection to the server before it answered. The change may still finish." : "The panel could not reach its server.", sent ? seeItNow : "Check that Sifruno is running and this computer is online, then try again.", `${where}: ${cancelled ? "cancelled" : "network error"}`);
    }
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) throw problem(operation, response.status, value, where);
    return value;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}

// The CSRF token of the current session, as for every other change.
async function csrfToken(operation: Operation, signal?: AbortSignal): Promise<string> {
  const value = await request(operation, "/api/v1/session", { timeoutMs: readTimeoutMs, signal });
  if (!validSession(value)) throw new FilesApiError(0, whatFailed[operation], "The server's answer was not in the form the panel expects.", "Reload the page.", "GET /api/v1/session: response did not match the session contract; nothing was changed");
  if (!value.authenticated) throw new FilesApiError(401, whatFailed[operation], "Your sign-in has ended.", "Sign in again, then try again.", "GET /api/v1/session: not signed in");
  return value.csrf_token;
}

function checkRequest(operation: Operation, accountId: string, paths: string[], target = true) {
  if (!validAccountId(accountId)) throw refused(operation, "This page does not point to a website. Go back to Websites and choose it there.", "account id is not 32 lowercase hex characters");
  for (const path of paths) {
    if (!validPath(path) || (target && path === "")) throw refused(operation, "That path cannot be used: a name is empty, . or .., holds a control character, or is too long. Choose another name.", "path outside the files contract");
  }
}

export async function listFolder(accountId: string, path: string, options: { signal?: AbortSignal } = {}): Promise<Folder> {
  checkRequest("list", accountId, [path], false);
  const url = base(accountId) + (path ? query(path) : "");
  const folder = parseFolder(await request("list", url, { timeoutMs: readTimeoutMs, signal: options.signal }), path);
  if (!folder) throw unexpected("list", `GET ${url}`);
  return folder;
}

export async function readText(accountId: string, path: string, options: { signal?: AbortSignal } = {}): Promise<FileText> {
  checkRequest("read", accountId, [path]);
  const url = `${base(accountId)}/content${query(path)}`;
  const file = parseFileText(await request("read", url, { timeoutMs: readTimeoutMs, signal: options.signal }), path);
  if (!file) throw unexpected("read", `GET ${url}`);
  return file;
}

// What is wrong with editor text, or undefined.
export function checkText(content: string): string | undefined {
  if (!wellFormed(content)) return "The text holds a broken character (half of an emoji or symbol). Remove it, then save.";
  if (content.includes("\u0000")) return "The text holds a NUL character, which a text file cannot. Remove it, then save.";
  if (utf8Bytes(content) > maxTextBytes) return "The text is larger than 1 MB, the most the editor saves. Shorten it, or upload the file instead.";
  return undefined;
}

async function change(operation: Operation, accountId: string, action: string, body: Record<string, string>, signal?: AbortSignal): Promise<FileEntry> {
  const csrf = await csrfToken(operation, signal);
  const url = `${base(accountId)}/${action}`;
  const entry = parseEntry(await request(operation, url, { method: "POST", body, csrf, timeoutMs: changeTimeoutMs, signal }));
  if (!entry) throw unexpected(operation, `POST ${url}`);
  return entry;
}

// Saves the whole file. expectedVersion is the version the editor opened,
// or "" for a new file; a file changed since is refused, not overwritten.
export async function saveText(accountId: string, path: string, content: string, expectedVersion: string, options: { signal?: AbortSignal } = {}): Promise<FileEntry> {
  checkRequest("save", accountId, [path]);
  const problemText = checkText(content);
  if (problemText) throw refused("save", problemText, "text outside the files contract");
  return change("save", accountId, "save", { path, content, expected_version: expectedVersion }, options.signal);
}

export async function makeFolder(accountId: string, path: string, options: { signal?: AbortSignal } = {}): Promise<FileEntry> {
  checkRequest("folder", accountId, [path]);
  return change("folder", accountId, "folder", { path }, options.signal);
}

export async function renameEntry(accountId: string, from: string, to: string, options: { signal?: AbortSignal } = {}): Promise<FileEntry> {
  checkRequest("rename", accountId, [from, to]);
  return change("rename", accountId, "rename", { path: from, to }, options.signal);
}

export async function deleteEntry(accountId: string, path: string, options: { signal?: AbortSignal } = {}): Promise<FileEntry> {
  checkRequest("delete", accountId, [path]);
  return change("delete", accountId, "delete", { path }, options.signal);
}

export async function setPermissions(accountId: string, path: string, mode: string, options: { signal?: AbortSignal } = {}): Promise<FileEntry> {
  checkRequest("mode", accountId, [path]);
  if (!/^0[0-7]{3}$/.test(mode)) throw refused("mode", "Choose read, write and run permissions; special bits cannot be set here.", "mode outside the files contract");
  return change("mode", accountId, "mode", { path, mode }, options.signal);
}

// A download is an ordinary link: the browser streams the file to disk
// with the session cookie, so nothing large passes through the page.
export function downloadURL(accountId: string, path: string): string {
  return `${base(accountId)}/download${query(path)}`;
}

// Uploads one file into folder, reporting progress. XMLHttpRequest is used
// because fetch() reports no upload progress. The file's own bytes are the
// body, so the browser sends its exact size as Content-Length.
export async function uploadFile(accountId: string, folder: string, file: File, overwrite: boolean, onProgress: (sent: number, total: number) => void, options: { signal?: AbortSignal } = {}): Promise<FileEntry> {
  const nameProblem = checkName(file.name);
  if (nameProblem) throw refused("upload", `The file's name cannot be used here: ${nameProblem}`, "file name outside the files contract");
  const path = joinPath(folder, file.name);
  checkRequest("upload", accountId, [path]);
  if (file.size > maxUploadBytes) throw refused("upload", `${file.name} is ${sizeLabel(file.size)}, larger than the 64 MB one upload can be. Use SFTP for large files.`, "file over the upload bound");
  const csrf = await csrfToken("upload", options.signal);
  const url = `${base(accountId)}/upload${query(path)}&overwrite=${overwrite ? "true" : "false"}`;
  const where = `POST ${url}`;
  return new Promise<FileEntry>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.timeout = uploadTimeoutMs;
    xhr.withCredentials = true;
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("Accept", "application/json");
    xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.upload.addEventListener("progress", (event) => onProgress(event.loaded, event.lengthComputable ? event.total : file.size));
    const abort = () => xhr.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    const done = () => options.signal?.removeEventListener("abort", abort);
    xhr.addEventListener("load", () => {
      done();
      let value: unknown;
      try { value = JSON.parse(xhr.responseText); } catch { value = undefined; }
      if (xhr.status < 200 || xhr.status > 299) { reject(problem("upload", xhr.status, value, where)); return; }
      const entry = parseEntry(value);
      if (!entry || entry.name !== file.name) { reject(unexpected("upload", where)); return; }
      resolve(entry);
    });
    const lost = (why: string, technical: string) => { done(); reject(new FilesApiError(0, notConfirmed, why, seeItNow, `${where}: ${technical}`)); };
    xhr.addEventListener("error", () => lost("The panel lost its connection to the server during the upload. Part of the file may not have arrived; the server keeps nothing half-written.", "network error"));
    xhr.addEventListener("timeout", () => lost("The upload did not finish in time.", "no answer in time"));
    xhr.addEventListener("abort", () => lost("The upload was cancelled. The server keeps nothing half-written.", "cancelled"));
    xhr.send(file);
  });
}
