import { dayLabel, httpsState } from "./websites-api";
import type { WebsiteDetail, WebsiteUsage } from "./websites-api";
import { diskUse } from "./site-tools-api";
import { actorLabel, formatWhen } from "./site-backups-api";
import type { SiteBackups } from "./site-backups-api";

// One website's page: which tabs it shows in Simple and Advanced view, the
// Overview's health checklist and its recent activity. Everything here is
// built from what the API reports; nothing is guessed.

// ---- Tabs ---------------------------------------------------------------------

export type ViewMode = "simple" | "advanced";
export type SiteTabId = "overview" | "domains" | "files" | "databases" | "backups" | "cron" | "logs" | "settings";

export interface SiteTab {
  id: SiteTabId;
  label: string;
  // The last part of the tab's address; "" is the site's own address.
  segment: string;
  // Simple view keeps cron jobs and logs inside Settings.
  advancedOnly?: true;
  // The API routes the tab reads to show itself, as the server's customer
  // table names them. A customer sees every tab, so each of these must be
  // open to customers (customer-routes.test.mjs checks it against the table).
  needs: readonly string[];
}

// Every tab shows the site's name and state, read by the website's layout.
const siteRead = "GET /api/v1/websites/sites/{account_id}";

export const siteTabs: readonly SiteTab[] = [
  { id: "overview", label: "Overview", segment: "", needs: [siteRead, `${siteRead}/usage`, `${siteRead}/backups`] },
  { id: "domains", label: "Domains and SSL", segment: "domains", needs: [siteRead] },
  { id: "files", label: "Files", segment: "files", needs: [siteRead, `${siteRead}/files`] },
  { id: "databases", label: "Databases", segment: "databases", needs: [siteRead, `${siteRead}/databases`] },
  { id: "backups", label: "Backups", segment: "backups", needs: [`${siteRead}/backups`] },
  { id: "cron", label: "Cron jobs", segment: "cron", advancedOnly: true, needs: [siteRead, `${siteRead}/cron`] },
  { id: "logs", label: "Logs", segment: "logs", advancedOnly: true, needs: [siteRead, `${siteRead}/logs/{kind}`] },
  // In Simple view Settings also shows the cron jobs and logs.
  { id: "settings", label: "Settings", segment: "settings", needs: [siteRead, `${siteRead}/cron`, `${siteRead}/logs/{kind}`] },
];

export function siteTab(id: SiteTabId): SiteTab {
  const tab = siteTabs.find((t) => t.id === id);
  if (!tab) throw new Error(`Unknown website tab ${id}`);
  return tab;
}

// The router path of a tab, with the account id left as a parameter.
export const tabRoute = (id: SiteTabId): string => {
  const { segment } = siteTab(id);
  return segment ? `/websites/sites/$accountId/${segment}` : "/websites/sites/$accountId";
};

// Which tab an address is on, or undefined when it is not a website's page.
export function tabFromPath(pathname: string): SiteTabId | undefined {
  const m = /^\/websites\/sites\/[^/]+(?:\/([^/]+))?\/*$/.exec(pathname);
  if (!m) return undefined;
  return siteTabs.find((t) => t.segment === (m[1] ?? ""))?.id;
}

// The tabs a site shows. A partly deleted site has no hosting account, so
// only its Overview and Settings (where it is deleted again) are there. An
// Advanced tab opened by its address in Simple view stays in the bar while it
// is the current page, so a shared link opens what was shared. siteActions is
// false for a viewer who may not change PHP, suspend or delete (a customer's
// login): its Settings tab then holds only Simple view's cron jobs and logs,
// and is left out where it would be empty, unless it is the current page.
export function tabsFor(mode: ViewMode, state: string, current?: SiteTabId, siteActions = true): SiteTab[] {
  const settings = siteActions || (mode === "simple" && state !== "partly_deleted") || current === "settings";
  if (state === "partly_deleted") return siteTabs.filter((t) => t.id === "overview" || (t.id === "settings" && settings));
  return siteTabs.filter((t) => (!t.advancedOnly || mode === "advanced" || t.id === current) && (t.id !== "settings" || settings));
}

// Settings holds cron jobs and logs in Simple view; in Advanced view they
// are tabs of their own. The repair action and technical facts are Advanced.
export function viewShows(mode: ViewMode): { cronInSettings: boolean; logsInSettings: boolean; repair: boolean; technical: boolean } {
  const advanced = mode === "advanced";
  return { cronInSettings: !advanced, logsInSettings: !advanced, repair: advanced, technical: advanced };
}

// ---- The person's view, remembered in this browser ----------------------------

export const viewModeKey = "sifruno-site-view";

// storage is a function because reading localStorage itself can throw (a
// private window or blocked site data); then the view is Simple.
export function readViewMode(storage: () => Pick<Storage, "getItem">): ViewMode {
  try {
    return storage().getItem(viewModeKey) === "advanced" ? "advanced" : "simple";
  } catch {
    return "simple";
  }
}

// False when the browser refused to store it: the view still changes for
// this visit, and the next visit starts in Simple view.
export function saveViewMode(mode: ViewMode, storage: () => Pick<Storage, "setItem">): boolean {
  try {
    storage().setItem(viewModeKey, mode);
    return true;
  } catch {
    return false;
  }
}

// ---- Health checklist ---------------------------------------------------------

export type HealthState = "ok" | "attention" | "problem" | "checking" | "unknown";
export type HealthId = "serving" | "https" | "php" | "backups" | "disk";

export interface HealthLine {
  id: HealthId;
  label: string;
  state: HealthState;
  detail: string;
  // The tab where the person can act on it, for a line that is not ok.
  fix?: SiteTabId;
}

// A read the checklist waits for: no data and not failed is still checking.
export interface Reading<T> { data?: T; failed: boolean }

const day = 24 * 60 * 60 * 1000;
// Backups run every night, so one older than two days means a night was missed.
export const recentBackupHours = 48;
// The panel renews a certificate once less than 30 days are left; with under
// 14 days left, renewal has been failing for over two weeks.
export const certificateWarningDays = 14;

function servingLine(site: WebsiteDetail): HealthLine {
  const line = (state: HealthState, detail: string, fix?: SiteTabId): HealthLine => ({ id: "serving", label: "Serving visitors", state, detail, fix });
  switch (site.state) {
    case "active":
      // From the account's state: the panel does not fetch the site itself.
      return site.site_folder_changed
        ? line("problem", "The site's folder was changed from inside the hosting account, so the site may not load.", "settings")
        : line("ok", "The web server is set to serve this site.");
    case "suspended": return line("attention", "Suspended: visitors get an error page instead of the site.", "settings");
    case "recovery_required": return line("problem", "The hosting account needs a check before the site can change.", "settings");
    case "partly_deleted": return line("problem", "Partly deleted: the site no longer serves visitors, and its database is still on this server.", "settings");
    default: return line("unknown", "The panel does not know this site's state.");
  }
}

function httpsLine(site: WebsiteDetail, now: Date): HealthLine {
  const line = (state: HealthState, detail: string): HealthLine => ({ id: "https", label: "HTTPS certificate", state, detail, ...(state === "ok" ? {} : { fix: "domains" as const }) });
  const https = httpsState(site.https, now);
  if (https.kind === "off") return line("problem", "No certificate yet: visitors reach the site over http.");
  if (https.kind === "expired") return line("problem", `The certificate expired on ${dayLabel(https.since)}. Visitors see a security warning.`);
  if (!https.until) return line("ok", "On.");
  const left = Math.ceil((https.until.getTime() - now.getTime()) / day);
  if (left < certificateWarningDays) return line("attention", `Valid until ${dayLabel(https.until)}, ${left === 1 ? "1 day" : `${left} days`} from now. The panel renews certificates 30 days before they end, so renewal has not worked yet.`);
  return line("ok", `Valid until ${dayLabel(https.until)}.`);
}

function phpLine(site: WebsiteDetail): HealthLine {
  const line = (state: HealthState, detail: string, fix?: SiteTabId): HealthLine => ({ id: "php", label: "PHP version", state, detail, fix });
  if (!site.php_version) return line("unknown", "Not reported for this site.");
  if (site.php_versions.length === 0) return line("unknown", `PHP ${site.php_version}. The panel found no PHP versions installed on this server, so it cannot check it.`);
  if (site.php_versions.includes(site.php_version)) return line("ok", `PHP ${site.php_version}, installed on this server.`);
  return line("problem", `PHP ${site.php_version} is not one of the versions installed on this server (${site.php_versions.join(", ")}). Change the site to an installed version.`, "settings");
}

function diskLine(usage: Reading<WebsiteUsage>): HealthLine {
  const line = (state: HealthState, detail: string): HealthLine => ({ id: "disk", label: "Disk space", state, detail, ...(state === "attention" || state === "problem" ? { fix: "files" as const } : {}) });
  if (!usage.data) return usage.failed ? line("unknown", "The disk use could not be read.") : line("checking", "Checking…");
  const disk = diskUse(usage.data);
  if (disk.percent === undefined) return line("ok", `${disk.used} used. No quota is set.`);
  if (disk.full) return line("problem", `${disk.used} of ${disk.limit}: full. New files cannot be written.`);
  if (disk.percent >= 90) return line("attention", `${disk.used} of ${disk.limit} (${disk.percent}%). Almost full.`);
  return line("ok", `${disk.used} of ${disk.limit} (${disk.percent}%).`);
}

// When the site was last backed up: the newer of the last successful backup
// job and the newest backup in the list.
export function lastBackupAt(backups: SiteBackups): number | undefined {
  const times = backups.snapshots.map((s) => Date.parse(s.time));
  if (backups.last_backup?.status === "succeeded") times.push(Date.parse(backups.last_backup.finished_at));
  const valid = times.filter((t) => Number.isFinite(t));
  return valid.length ? Math.max(...valid) : undefined;
}

function backupLine(backups: Reading<SiteBackups>, now: Date): HealthLine {
  const line = (state: HealthState, detail: string): HealthLine => ({ id: "backups", label: "Recent backup", state, detail, ...(state === "attention" || state === "problem" ? { fix: "backups" as const } : {}) });
  const data = backups.data;
  if (!data) return backups.failed ? line("unknown", "The backups could not be read.") : line("checking", "Checking…");
  if (!data.configured) return line("problem", "Backup storage is not set up, so this site is not backed up.");
  if (!data.ready) return line("problem", "Backups cannot run on this server right now: restic is missing or is not the expected version.");
  const last = lastBackupAt(data);
  const failed = data.last_backup?.status === "failed" ? Date.parse(data.last_backup.finished_at) : NaN;
  if (Number.isFinite(failed) && (last === undefined || failed > last)) {
    return line("problem", `The last backup failed, ${formatWhen(data.last_backup!.finished_at, data.timezone)}.`);
  }
  const nightly = `Backups run every night at ${data.nightly_at || "02:30"}.`;
  if (last === undefined) return line("attention", `No backup yet. ${nightly}`);
  const when = formatWhen(new Date(last).toISOString(), data.timezone);
  if (now.getTime() - last > recentBackupHours * 60 * 60 * 1000) {
    const days = Math.floor((now.getTime() - last) / day);
    return line("attention", `The last backup is ${days === 1 ? "1 day" : `${days} days`} old, ${when}. ${nightly}`);
  }
  return line("ok", `Last backup ${when}.`);
}

// The Overview's checklist, in a fixed order. A partly deleted site has no
// hosting account left to check, so it has the one line that says so.
export function healthChecklist(site: WebsiteDetail, usage: Reading<WebsiteUsage>, backups: Reading<SiteBackups>, now: Date = new Date()): HealthLine[] {
  if (site.state === "partly_deleted") return [servingLine(site)];
  return [servingLine(site), httpsLine(site, now), phpLine(site), backupLine(backups, now), diskLine(usage)];
}

// ---- Recent activity ------------------------------------------------------------

export interface ActivityItem { id: "created" | "backup" | "restore" | "drill"; at: string; title: string; detail: string; ok: boolean }

const restored: Record<string, string> = { files: "Restored the files from a backup", database: "Restored the database from a backup", both: "Restored the files and database from a backup" };
const actorName = actorLabel;

// What the API records for one site: its last backup, restore and restore
// drill, and when it was made, newest first. It is not a full change log.
// The server's last drill may be of another site; then it is left out.
export function recentActivity(site: Pick<WebsiteDetail, "account_id" | "created_at">, backups?: SiteBackups): ActivityItem[] {
  const items: ActivityItem[] = [{ id: "created", at: site.created_at, title: "Website created", detail: "", ok: true }];
  const backup = backups?.last_backup;
  if (backup) items.push({ id: "backup", at: backup.finished_at, ok: backup.status === "succeeded", title: backup.status === "succeeded" ? "Backup made" : "Backup failed", detail: `Started by ${actorName(backup.actor)}.${backup.status === "failed" && backup.message ? ` ${backup.message}` : ""}` });
  const restore = backups?.last_restore;
  if (restore) items.push({ id: "restore", at: restore.finished_at, ok: restore.status === "succeeded", title: restore.status === "succeeded" ? restored[restore.what ?? "both"] ?? restored.both : "Restore failed", detail: `Started by ${actorName(restore.actor)}.${restore.status === "failed" && restore.message ? ` ${restore.message}` : ""}` });
  const drill = backups?.last_drill;
  if (drill && drill.account_id === site.account_id) items.push({ id: "drill", at: drill.checked_at, ok: drill.passed, title: drill.passed ? "Restore test passed" : "Restore test failed", detail: drill.message });
  return items.filter((item) => Number.isFinite(Date.parse(item.at))).sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
}
