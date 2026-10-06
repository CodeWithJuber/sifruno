export interface AccountsWebPreviewFile { path: string; mode: number; bytes: number; sha256: string }
export interface AccountsWebPreview {
  profile: string; profile_sha256: string; snapshot_sha256: string; bundle_sha256: string;
  accounts: number; active_accounts: number; suspended_accounts: number; files: AccountsWebPreviewFile[];
}
const rootKeys = ["profile", "profile_sha256", "snapshot_sha256", "bundle_sha256", "accounts", "active_accounts", "suspended_accounts", "files"];
const fileKeys = ["path", "mode", "bytes", "sha256"];
const hash = /^[a-f0-9]{64}$/;
function exact(value: unknown, keys: string[]): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
const boundedCount = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0 && (v as number) <= 100;
export function validAccountsWebPreview(v: unknown): v is AccountsWebPreview {
  if (!exact(v, rootKeys) || v.profile !== "restricted-chroot-v1" ||
    !["profile_sha256", "snapshot_sha256", "bundle_sha256"].every((k) => typeof v[k] === "string" && hash.test(v[k] as string)) ||
    !boundedCount(v.accounts) || !boundedCount(v.active_accounts) || !boundedCount(v.suspended_accounts) ||
    v.active_accounts + v.suspended_accounts !== v.accounts || !Array.isArray(v.files) || v.files.length !== 1 + 2 * v.active_accounts) return false;
  const paths = new Set<string>(); const pairs = new Map<string, number>(); let total = 0;
  for (const f of v.files) {
    if (!exact(f, fileKeys) || typeof f.path !== "string" || paths.has(f.path) || f.mode !== 384 ||
      !Number.isSafeInteger(f.bytes) || (f.bytes as number) < 1 || (f.bytes as number) > 262144 ||
      typeof f.sha256 !== "string" || !hash.test(f.sha256)) return false;
    if (f.path !== "apache/front.conf") {
      const match = /^(apache\/backends|fpm)\/([a-f0-9]{32})\.conf$/.exec(f.path);
      if (!match) return false;
      pairs.set(match[2], (pairs.get(match[2]) ?? 0) | (match[1] === "fpm" ? 2 : 1));
    }
    paths.add(f.path); total += f.bytes as number;
  }
  return paths.has("apache/front.conf") && pairs.size === v.active_accounts && [...pairs.values()].every((pair) => pair === 3) && total <= 8 * 1024 * 1024;
}
export class AccountsWebPreviewError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}
export function previewErrorMessage(status: number): string {
  if (status === 401) return "Your local operator session expired. Sign in again to request a new preview.";
  if (status === 403) return "Preview access was denied. Check your local operator session and request origin.";
  if (status === 409) return "The broker inventory changed. Refresh the accounts and request a new preview.";
  if (status === 503) return "Native web preview is unavailable. Check the broker opt-in and recovery status; this is not a serving-health result.";
  return "The preview could not be read. Retry after checking the local connection.";
}
export function parseAccountsWebPreview(raw: string): AccountsWebPreview {
  let value: unknown;
  try {
    value = JSON.parse(raw);
    // JSON.parse alone silently accepts duplicate object keys.
    const tokens = raw.match(/"(?:[^"\\]|\\.)*"|[{}\[\],:]|[^\s{}\[\],:]+/g) ?? [];
    const objects: Array<Set<string> | null> = [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token === "{") objects.push(new Set());
      else if (token === "[") objects.push(null);
      else if (token === "}" || token === "]") objects.pop();
      else if (token.startsWith('"') && tokens[i + 1] === ":") {
        const key = JSON.parse(token) as string; const seen = objects.at(-1);
        if (!seen || seen.has(key)) throw new Error("duplicate key");
        seen.add(key);
      }
    }
    if (!validAccountsWebPreview(value)) throw new Error("invalid metadata");
  } catch {
    throw new AccountsWebPreviewError(0, "invalid_response", "The service returned invalid preview metadata. No preview is shown; retry or inspect the broker.");
  }
  return value;
}
export async function fetchAccountsWebPreview(signal: AbortSignal, timeoutMs = 50000): Promise<AccountsWebPreview> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal.addEventListener("abort", abort, { once: true });
  if (signal.aborted) abort();
  const timer = setTimeout(abort, timeoutMs);
  try {
    const response = await fetch("/api/v1/accounts/web-preview", {
      method: "GET", credentials: "same-origin", cache: "no-store", signal: controller.signal, headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new AccountsWebPreviewError(response.status, "preview_unavailable", previewErrorMessage(response.status));
    if (!response.body) throw new Error("missing body");
    const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 256 * 1024) { await reader.cancel(); throw new Error("oversized"); }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    if (controller.signal.aborted) throw new Error("obsolete");
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return parseAccountsWebPreview(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    if (error instanceof AccountsWebPreviewError) throw error;
    throw new AccountsWebPreviewError(0, controller.signal.aborted ? "cancelled" : "connection_failed", controller.signal.aborted ? "The preview request ended. Request it again when ready." : "The preview could not be read. Retry after checking the local connection.");
  } finally { clearTimeout(timer); signal.removeEventListener("abort", abort); }
}
// Epoch identity also protects against fetch implementations that resolve after abort.
export class PreviewRequestGate {
  private epoch = 0; private controller?: AbortController;
  invalidate() { this.epoch++; this.controller?.abort(); this.controller = undefined; }
  begin() {
    this.invalidate(); const epoch = this.epoch; const controller = new AbortController(); this.controller = controller;
    return { signal: controller.signal, current: () => this.epoch === epoch && !controller.signal.aborted };
  }
}
