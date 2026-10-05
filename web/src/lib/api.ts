import { useEffect, useState } from "react";

export interface Obligation {
  id: string;
  category: string;
  title: string;
  vendor?: string;
  source: string;
  status: string;
  reason: string;
}
export interface StatusReport {
  product: string;
  stage: string;
  ready: boolean;
  reference: {
    family: string;
    documentation_version: string;
    exact_build: string;
    os: string;
    artifact_sha256: string;
    licensed_reference_verified: boolean;
  };
  inventory_complete: boolean;
  total: number;
  passed: number;
  untested: number;
  blockers: string[];
  entries: Obligation[];
  ai_monthly_cap_usd_micros: number;
  pilot_accounts: number;
}
export interface TrailItem {
  id: string;
  reason: string;
  actor: string;
  parent?: string;
  created: string;
  state: string;
  files: number;
}
export interface TrailReport {
  items: TrailItem[];
}
export interface BudgetReport {
  month: string;
  cap_usd_micros: number;
  reserved_usd_micros: number;
  spent_usd_micros: number;
  remaining_usd_micros: number;
  approval_required: boolean;
  over_cap?: boolean;
  reconciliation_required?: boolean;
}
export interface PlatformReport {
  os: string;
  arch: string;
  os_name: string;
  mode: string;
  control_plane_supported: boolean;
  hosting_runtime: string;
  compatibility_verified: boolean;
  profiles: {
    id: string;
    os: string;
    label: string;
    status: string;
    notes: string;
  }[];
}

interface Measurement {
  available: boolean;
  reason: string;
}
export interface ServerSample {
  sampled_at: string;
  cpu_usage_percent: number | null;
  memory_used_percent: number | null;
  storage_used_percent: number | null;
  network_rx_bytes_per_second: number | null;
  network_tx_bytes_per_second: number | null;
}
export interface ServerReport {
  sampled_at: string;
  os: string;
  arch: string;
  collector: {
    name: string;
    version: string;
    interval_seconds: number;
    history_limit: number;
    status: "available" | "partial" | "unavailable";
    reasons: string[];
  };
  cpu: Measurement & {
    usage_percent: number | null;
    logical_cores: number | null;
    physical_cores: number | null;
    model: string | null;
  };
  memory: Measurement & {
    total_bytes: number | null;
    used_bytes: number | null;
    available_bytes: number | null;
    used_percent: number | null;
  };
  storage: Measurement & {
    total_bytes: number | null;
    used_bytes: number | null;
    free_bytes: number | null;
    used_percent: number | null;
    disks: (Measurement & {
      id: string;
      label: string;
      total_bytes: number | null;
      used_bytes: number | null;
      free_bytes: number | null;
      used_percent: number | null;
    })[];
  };
  uptime: Measurement & { seconds: number | null };
  network: Measurement & {
    bytes_received: number | null;
    bytes_sent: number | null;
    rx_bytes_per_second: number | null;
    tx_bytes_per_second: number | null;
  };
  history: ServerSample[];
}
export interface ServiceItem {
  id: string;
  name: string;
  display_name: string;
  status: "running" | "stopped" | "paused" | "pending" | "unknown";
  start_type: "automatic" | "manual" | "disabled" | "unknown";
}
export interface ServicesReport {
  sampled_at: string;
  available: boolean;
  reason: string;
  manager: "windows-scm" | "systemd" | "unsupported";
  truncated: boolean;
  items: ServiceItem[];
}

type ObjectValue = Record<string, unknown>;
const isObject = (v: unknown): v is ObjectValue =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const strings = (v: ObjectValue, keys: string[]) =>
  keys.every((k) => typeof v[k] === "string");
const money = (v: ObjectValue, keys: string[]) =>
  keys.every((k) => Number.isSafeInteger(v[k]) && (v[k] as number) >= 0);

export function validStatus(v: unknown): v is StatusReport {
  if (
    !isObject(v) ||
    !strings(v, ["product", "stage"]) ||
    typeof v.ready !== "boolean" ||
    typeof v.inventory_complete !== "boolean"
  )
    return false;
  if (
    !money(v, [
      "total",
      "passed",
      "untested",
      "ai_monthly_cap_usd_micros",
      "pilot_accounts",
    ])
  )
    return false;
  if (
    !Array.isArray(v.blockers) ||
    !v.blockers.every((x) => typeof x === "string")
  )
    return false;
  if (
    !isObject(v.reference) ||
    !strings(v.reference, [
      "family",
      "documentation_version",
      "exact_build",
      "os",
      "artifact_sha256",
    ]) ||
    typeof v.reference.licensed_reference_verified !== "boolean"
  )
    return false;
  return (
    Array.isArray(v.entries) &&
    v.entries.every(
      (e) =>
        isObject(e) &&
        strings(e, ["id", "category", "title", "source", "status", "reason"]) &&
        (e.vendor === undefined || typeof e.vendor === "string"),
    )
  );
}
export function validTrail(v: unknown): v is TrailReport {
  return (
    isObject(v) &&
    Array.isArray(v.items) &&
    v.items.every(
      (e) =>
        isObject(e) &&
        strings(e, ["id", "reason", "actor", "created", "state"]) &&
        (e.parent === undefined || typeof e.parent === "string") &&
        money(e, ["files"]),
    )
  );
}
export function validBudget(v: unknown): v is BudgetReport {
  return (
    isObject(v) &&
    strings(v, ["month"]) &&
    money(v, [
      "cap_usd_micros",
      "reserved_usd_micros",
      "spent_usd_micros",
      "remaining_usd_micros",
    ]) &&
    typeof v.approval_required === "boolean" &&
    (v.over_cap === undefined || typeof v.over_cap === "boolean") &&
    (v.reconciliation_required === undefined || typeof v.reconciliation_required === "boolean")
  );
}
export function validPlatform(v: unknown): v is PlatformReport {
  return (
    isObject(v) &&
    strings(v, ["os", "arch", "os_name", "mode", "hosting_runtime"]) &&
    typeof v.control_plane_supported === "boolean" &&
    typeof v.compatibility_verified === "boolean" &&
    Array.isArray(v.profiles) &&
    v.profiles.every(
      (p) =>
        isObject(p) && strings(p, ["id", "os", "label", "status", "notes"]),
    )
  );
}

const timestamp = (v: unknown) => typeof v === "string" && Number.isFinite(Date.parse(v));
const nullableNumber = (v: unknown, maximum = Infinity) =>
  v === null || (typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= maximum);
const numbers = (v: ObjectValue, keys: string[], maximum = Infinity) =>
  keys.every((k) => nullableNumber(v[k], maximum));
const measurement = (v: unknown): v is ObjectValue =>
  isObject(v) && typeof v.available === "boolean" && typeof v.reason === "string";
const byteKeys = ["total_bytes", "used_bytes"];
export function validServer(v: unknown): v is ServerReport {
  if (!isObject(v) || !timestamp(v.sampled_at) || !strings(v, ["os", "arch"])) return false;
  const c = v.collector;
  if (!isObject(c) || !strings(c, ["name", "version"]) ||
      !money(c, ["interval_seconds", "history_limit"]) ||
      !["available", "partial", "unavailable"].includes(String(c.status)) ||
      !Array.isArray(c.reasons) || !c.reasons.every((r) => typeof r === "string")) return false;
  if (!measurement(v.cpu) || !nullableNumber(v.cpu.usage_percent, 100) ||
      !numbers(v.cpu, ["logical_cores", "physical_cores"]) ||
      !(v.cpu.model === null || typeof v.cpu.model === "string")) return false;
  if (!measurement(v.memory) || !numbers(v.memory, [...byteKeys, "available_bytes"]) ||
      !nullableNumber(v.memory.used_percent, 100)) return false;
  if (!measurement(v.storage) || !numbers(v.storage, [...byteKeys, "free_bytes"]) ||
      !nullableNumber(v.storage.used_percent, 100) || !Array.isArray(v.storage.disks) ||
      !v.storage.disks.every((d) => measurement(d) && strings(d, ["id", "label"]) &&
        numbers(d, [...byteKeys, "free_bytes"]) && nullableNumber(d.used_percent, 100))) return false;
  if (!measurement(v.uptime) || !nullableNumber(v.uptime.seconds) ||
      !measurement(v.network) || !numbers(v.network, ["bytes_received", "bytes_sent", "rx_bytes_per_second", "tx_bytes_per_second"])) return false;
  return Array.isArray(v.history) && v.history.every((s) => isObject(s) && timestamp(s.sampled_at) &&
    numbers(s, ["cpu_usage_percent", "memory_used_percent", "storage_used_percent"], 100) &&
    numbers(s, ["network_rx_bytes_per_second", "network_tx_bytes_per_second"]));
}
export function validServices(v: unknown): v is ServicesReport {
  return isObject(v) && timestamp(v.sampled_at) && measurement(v) &&
    ["windows-scm", "systemd", "unsupported"].includes(String(v.manager)) &&
    typeof v.truncated === "boolean" && Array.isArray(v.items) && v.items.every((s) =>
      isObject(s) && strings(s, ["id", "name", "display_name"]) &&
      ["running", "stopped", "paused", "pending", "unknown"].includes(String(s.status)) &&
      ["automatic", "manual", "disabled", "unknown"].includes(String(s.start_type)));
}

export interface Resource<T> {
  data?: T;
  loading: boolean;
  error?: string;
  loadedAt?: Date;
}
export function useResource<T>(
  url: string | null,
  validate: (data: unknown) => data is T,
  revision: number,
  pollMilliseconds = 0,
): Resource<T> {
  const [resource, setResource] = useState<Resource<T>>({ loading: true });
  useEffect(() => {
    if (!url) {
      setResource({ loading: false });
      return;
    }
    let live = true;
    let pending = false;
    let controller: AbortController | undefined;
    const read = async () => {
      if (pending) return;
      pending = true;
      const request = new AbortController();
      controller = request;
      let timedOut = false;
      const timeout = setTimeout(() => { timedOut = true; request.abort(); }, 10000);
      setResource((previous) => ({ ...previous, loading: true }));
      await fetch(url, {
      signal: request.signal,
      headers: { Accept: "application/json" },
      cache: "no-store",
    })
      .then(async (response) => {
        if (!response.ok)
          throw new Error(
            `The server service returned HTTP ${response.status}.`,
          );
        const data: unknown = await response.json();
        if (!validate(data))
          throw new Error(
            "The service response did not match the expected data contract.",
          );
        if (live && !request.signal.aborted)
          setResource({ data, loading: false, loadedAt: new Date() });
      })
      .catch((error) => {
        if (!live || (request.signal.aborted && !timedOut)) return;
        setResource((previous) => ({
          ...previous,
          loading: false,
          error: timedOut
            ? "The server service did not respond within 10 seconds."
            : error instanceof Error
              ? error.message
              : "The server service could not be reached.",
        }));
      })
      .finally(() => { clearTimeout(timeout); pending = false; });
    };
    void read();
    const interval = pollMilliseconds ? setInterval(() => void read(), pollMilliseconds) : undefined;
    return () => {
      live = false;
      clearInterval(interval);
      controller?.abort();
    };
  }, [url, validate, revision, pollMilliseconds]);
  return resource;
}

export function safeSource(source: string): string | undefined {
  try {
    const url = new URL(source);
    return url.protocol === "https:" && !url.username && !url.password
      ? url.href
      : undefined;
  } catch {
    return undefined;
  }
}

export const usd = (micros: number) =>
  new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  }).format(micros / 1000000);
export function dateLabel(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Date unavailable"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}
