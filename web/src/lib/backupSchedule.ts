import { SiteApiError, siteRequest, siteURL } from "./sites-api";

export const backupIntervals = ["hourly", "daily", "weekly"] as const;
export type BackupInterval = typeof backupIntervals[number];
export interface BackupSchedule {
  site_id: string; revision: number; interval: BackupInterval; enabled: boolean;
  created_at: string; updated_at: string; next_run_at: string; last_run_at: string | null;
  last_status: "never" | "completed" | "failed" | "interrupted";
  last_backup_id: string; last_error: "" | "archive_capacity" | "backup_failed" | "interrupted"; pending: boolean;
}
export interface BackupScheduleEnvelope { schedule: BackupSchedule | null; intervals: ["hourly", "daily", "weekly"]; max_archives: 8; runner_enabled: boolean }
export interface BackupScheduleInput { expected_revision: number; expected_schedule_revision: number; interval: BackupInterval; enabled: boolean }
const object = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const exact = (value: Record<string, unknown>, fields: string[]) => Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const id = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
const integer = (value: unknown, minimum: number): value is number => Number.isSafeInteger(value) && (value as number) >= minimum;
const date = (value: unknown): value is string => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value.replace(/Z$/, ".000Z");
export const validBackupInterval = (value: unknown): value is BackupInterval => backupIntervals.some((interval) => interval === value);

export function validBackupSchedule(value: unknown): value is BackupSchedule {
  if (!(object(value) && exact(value, ["site_id", "revision", "interval", "enabled", "created_at", "updated_at", "next_run_at", "last_run_at", "last_status", "last_backup_id", "last_error", "pending"]) &&
    id(value.site_id) && integer(value.revision, 1) && validBackupInterval(value.interval) && typeof value.enabled === "boolean" &&
    date(value.created_at) && date(value.updated_at) && date(value.next_run_at) && (value.last_run_at === null || date(value.last_run_at)) &&
    typeof value.last_status === "string" && ["never", "completed", "failed", "interrupted"].includes(value.last_status) && (value.last_backup_id === "" || id(value.last_backup_id)) &&
    typeof value.last_error === "string" && ["", "archive_capacity", "backup_failed", "interrupted"].includes(value.last_error) && typeof value.pending === "boolean")) return false;
  const created = Date.parse(value.created_at), updated = Date.parse(value.updated_at);
  if (updated < created || Date.parse(value.next_run_at) < created || (value.last_run_at !== null && (Date.parse(value.last_run_at) < created || Date.parse(value.last_run_at) > updated))) return false;
  if (value.last_status === "never") return value.last_run_at === null && value.last_backup_id === "" && value.last_error === "";
  if (value.last_run_at === null) return false;
  if (value.last_status === "completed") return id(value.last_backup_id) && value.last_error === "";
  return value.last_backup_id === "" && (value.last_status === "failed" ? ["archive_capacity", "backup_failed"].includes(value.last_error) : value.last_error === "interrupted");
}
export function validBackupScheduleEnvelope(value: unknown): value is BackupScheduleEnvelope {
  return object(value) && exact(value, ["schedule", "intervals", "max_archives", "runner_enabled"]) &&
    (value.schedule === null || validBackupSchedule(value.schedule)) && Array.isArray(value.intervals) && value.intervals.length === 3 && backupIntervals.every((interval, index) => (value.intervals as unknown[])[index] === interval) &&
    value.max_archives === 8 && typeof value.runner_enabled === "boolean";
}
export function validBackupScheduleInput(value: unknown): value is BackupScheduleInput {
  return object(value) && exact(value, ["expected_revision", "expected_schedule_revision", "interval", "enabled"]) && integer(value.expected_revision, 1) && integer(value.expected_schedule_revision, 0) && validBackupInterval(value.interval) && typeof value.enabled === "boolean";
}
const boundEnvelope = (siteId: string) => (value: unknown): value is BackupScheduleEnvelope => validBackupScheduleEnvelope(value) && (value.schedule === null || value.schedule.site_id === siteId);
export function getBackupSchedule(siteId: string) {
  if (!id(siteId)) throw new SiteApiError(400, "invalid_site", "Refresh the website records before reading its schedule.");
  return siteRequest(siteURL(siteId, "/backup-schedule"), boundEnvelope(siteId));
}
export function putBackupSchedule(siteId: string, input: BackupScheduleInput, csrf: string) {
  if (!id(siteId) || !validBackupScheduleInput(input) || !csrf) throw new SiteApiError(400, "invalid_schedule", "Refresh the website and review the schedule values before saving.");
  return siteRequest(siteURL(siteId, "/backup-schedule"), (value): value is BackupScheduleEnvelope => boundEnvelope(siteId)(value) && value.schedule !== null && value.schedule.revision > input.expected_schedule_revision && value.schedule.interval === input.interval && value.schedule.enabled === input.enabled, { method: "PUT", csrf, body: input });
}
export function backupScheduleError(failure: unknown): string {
  if (failure instanceof SiteApiError) {
    if (failure.status === 401) return "Your local operator session expired or was revoked. Sign in again to manage schedules.";
    if (failure.status === 403) return "Your session or request origin was rejected. Refresh your session before saving.";
    if (failure.status === 409) return "The website or schedule changed. Your interval and enabled draft is kept. Refresh both records, review the latest schedule, then confirm again.";
    if (failure.status === 503) return "Scheduling is unavailable, or this server's runner is disabled. No save was confirmed. Refresh records; an existing schedule can still be paused when the runner is disabled.";
    if (failure.status === 422) return "The schedule values or website state were rejected. Review the latest records before saving.";
  }
  return "The schedule result could not be confirmed. Your draft is kept. Refresh backup records before trying again.";
}
