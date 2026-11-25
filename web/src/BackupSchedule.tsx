import { useCallback, useEffect, useRef, useState } from "react";
import { CalendarClock, CircleCheck, LoaderCircle, RefreshCw } from "lucide-react";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { ProblemAlert } from "@/components/problem-alert";
import type { Problem } from "@/components/problem-alert";
import { dateLabel } from "@/lib/api";
import { SiteApiError } from "@/lib/sites-api";
import type { OperatorSession, Site } from "@/lib/sites-api";
import { backupIntervals, backupScheduleError, getBackupSchedule, putBackupSchedule, stoppedBackupRecovery } from "@/lib/backupSchedule";
import type { BackupInterval, BackupScheduleEnvelope, BackupScheduleInput } from "@/lib/backupSchedule";

type Props = {
  site: Site; session: OperatorSession; active: boolean; fresh: boolean; busy: boolean; archives: number;
  onRefresh: () => void;
  onAction: (label: string, action: (isLive: () => boolean) => Promise<void>) => Promise<void>;
  onUnauthorized: (failure: unknown) => void;
  onDirtyChange: (dirty: boolean) => void;
};
const intervalLabel = { hourly: "Hourly · every 1 hour", daily: "Daily · every 24 hours", weekly: "Weekly · every 168 hours" };
const statusLabel = { never: "No scheduled run yet", completed: "Completed", failed: "Failed", interrupted: "Interrupted" };
const runError = { "": "", archive_capacity: "Archive limit reached. No archive was removed.", backup_failed: "The backup could not be completed.", interrupted: "The previous run was interrupted. Review the current backup records." };

// An error on the Backups page as the panel shows it: what happened (the
// action that failed), why (the message the page already had), what to do
// next, and the error's code and status under "Technical details". The API
// client's messages stay as they are; the next step follows from the status.
// The Backups page uses these too.
export function siteNextStep(status: number, code: string): string {
  if (status === 401) return "Sign in again with the operator access key.";
  if (status === 403) return "Reload the page, sign in again, then try again.";
  if (status === 404) return "Use Refresh backup records and choose the website again.";
  if (status === 409) return "Use Refresh backup records, review the current revision, then try again.";
  if (status === 413) return "Choose a smaller native ZIP file.";
  if (status === 422) return "Check the values and the static-file limits, then try again.";
  if (status === 429) return "Wait a minute before signing in again.";
  if (status === 503) return "Use Refresh backup records. If it keeps failing, check this server's panel log.";
  if (status === 0 && code === "invalid_response") return "Use Refresh backup records. If it happens again, the panel and the server may be different versions.";
  if (status === 0) return "Check that Sifruno is running and this computer is online, then use Refresh backup records.";
  return "Use Refresh backup records and try again.";
}
export function siteProblem(message: string, what: string, failure?: unknown, next?: string): Problem {
  if (failure instanceof SiteApiError) return { what, why: message, next: next ?? siteNextStep(failure.status, failure.code), technical: `${failure.code}${failure.status ? ` · status ${failure.status}` : ""}`, status: failure.status };
  return { what, why: message, next: next ?? "Use Refresh backup records and try again.", technical: failure === undefined ? "Checked in this browser; nothing was sent to the server." : "The page could not read the failure.", status: 0 };
}

const panel = "rounded-lg border border-border bg-card";
const rowControl = "h-9 pointer-coarse:h-11";

export default function BackupSchedule({ site, session, active, fresh: siteFresh, busy: parentBusy, archives, onRefresh, onAction, onUnauthorized, onDirtyChange }: Props) {
  const [records, setRecords] = useState<BackupScheduleEnvelope>();
  const [interval, setInterval] = useState<BackupInterval>("daily");
  const [enabled, setEnabled] = useState(false);
  const [fresh, setFresh] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [confirmation, setConfirmation] = useState<BackupScheduleInput>();
  const edited = useRef(false);
  const mounted = useRef(false);
  const readEpoch = useRef(0);
  const submitting = useRef(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const latest = useRef({ siteId: site.id, active, session });
  latest.current = { siteId: site.id, active, session };
  // Each error message the schedule shows, with what failed and the codes
  // behind it; say() files one and hands the message back for setError.
  const problems = useRef(new Map<string, Problem>());
  const say = useCallback((message: string, what: string, failure?: unknown) => { problems.current.set(message, siteProblem(message, what, failure)); return message; }, []);
  const authenticated = session.authenticated;
  const csrf = session.authenticated ? session.csrf_token : undefined;
  const draftSession = useRef(csrf);
  const schedule = records?.schedule;
  const recovery = stoppedBackupRecovery(schedule);
  const changed = recovery || (schedule ? interval !== schedule.interval || enabled !== schedule.enabled : true);
  const canSave = active && authenticated && siteFresh && fresh && Boolean(records) && changed && !parentBusy && !loading && !saving && (!schedule?.pending || recovery) && site.state !== "recovery_required" && (!enabled || records?.runner_enabled === true);
  const draftDirty = edited.current && (schedule ? interval !== schedule.interval || enabled !== schedule.enabled : interval !== "daily" || enabled);
  useEffect(() => { onDirtyChange(draftDirty); }, [draftDirty, onDirtyChange]);

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; ++readEpoch.current; }; }, []);
  useEffect(() => {
    const generation = ++readEpoch.current;
    setFresh(false); if (!submitting.current) setConfirmation(undefined);
    if (draftSession.current !== csrf) { draftSession.current = csrf; edited.current = false; setRecords(undefined); setInterval("daily"); setEnabled(false); setError(undefined); setNotice(undefined); }
    if (!authenticated) {
      setRecords(undefined); setInterval("daily"); setEnabled(false); setError(undefined); setNotice(undefined); setLoading(false); edited.current = false;
      return;
    }
    if (!active) { setLoading(false); return; }
    if (!siteFresh || parentBusy) { setLoading(false); return; }
    const isLive = () => mounted.current && latest.current.active && generation === readEpoch.current;
    setLoading(true);
    void (async () => {
      try {
        const value = await getBackupSchedule(site.id);
        if (!isLive()) return;
        setRecords(value); setFresh(true); setError(undefined);
        if (!edited.current) { setInterval(value.schedule?.interval ?? "daily"); setEnabled(value.schedule?.enabled ?? false); }
      } catch (failure) {
        if (!isLive()) return;
        setError(say(backupScheduleError(failure), "The backup schedule could not be loaded.", failure));
        if (failure instanceof SiteApiError && failure.status === 401) onUnauthorized(failure);
      } finally { if (isLive()) setLoading(false); }
    })();
    return () => { if (generation === readEpoch.current) ++readEpoch.current; };
  }, [active, authenticated, csrf, site.id, site.revision, siteFresh, parentBusy, onUnauthorized, say]);
  useEffect(() => {
    if (confirmation && active && authenticated && dialog.current && !dialog.current.open) { dialog.current.showModal(); dialog.current.querySelector<HTMLButtonElement>("button")?.focus(); }
    else if ((!confirmation || !active || !authenticated) && dialog.current?.open) dialog.current.close();
  }, [confirmation, active, authenticated]);

  function review(event: React.FormEvent) {
    event.preventDefault();
    if (!canSave || submitting.current) return;
    setConfirmation({ expected_revision: site.revision, expected_schedule_revision: schedule?.revision ?? 0, interval, enabled });
  }
  async function confirmSave() {
    if (!confirmation || !canSave || !csrf || submitting.current || confirmation.expected_revision !== site.revision || confirmation.expected_schedule_revision !== (schedule?.revision ?? 0) || confirmation.interval !== interval || confirmation.enabled !== enabled) return;
    const target = confirmation, targetId = site.id, token = csrf;
    submitting.current = true; setSaving(true); setError(undefined); setNotice(undefined);
    await onAction("Saving backup schedule", async (parentLive) => {
      const isLive = () => parentLive() && mounted.current && latest.current.active && latest.current.siteId === targetId && latest.current.session.authenticated && latest.current.session.csrf_token === token;
      try {
        const value = await putBackupSchedule(targetId, target, token);
        if (!isLive()) return;
        edited.current = false; setRecords(value); setInterval(target.interval); setEnabled(target.enabled); setFresh(true); setConfirmation(undefined);
        setNotice(target.enabled ? "Backup schedule saved and enabled." : "Backup schedule saved and paused.");
      } catch (failure) {
        if (isLive()) { setFresh(false); setConfirmation(undefined); setError(say(backupScheduleError(failure), "The backup schedule was not saved.", failure)); }
        throw failure;
      }
    });
    submitting.current = false;
    if (mounted.current) setSaving(false);
  }

  if (!active || !authenticated) return null;
  const status = (text: string) => <div className="text-sm text-foreground" role="status">{text}</div>;
  return <section className={`${panel} flex min-w-0 flex-col gap-4 p-4`} aria-labelledby="backup-schedule-heading" data-testid="backup-schedule" data-fresh={fresh}>
    <div className="flex flex-wrap items-start gap-3">
      <CalendarClock className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <div className="min-w-0 flex-1 basis-56"><h2 id="backup-schedule-heading" className="text-base! wrap-anywhere">Scheduled ZIP backups</h2><div className="mt-1 text-sm text-muted-foreground">Saved static website files only. Scheduling uses this server’s opt-in runner.</div></div>
      <Button variant="ghost" size="sm" className="ms-auto pointer-coarse:h-11" disabled={parentBusy || saving || loading} onClick={onRefresh}><RefreshCw aria-hidden="true" />Refresh schedule<span className="sr-only"> and website records</span></Button>
    </div>
    {error && <ProblemAlert problem={problems.current.get(error) ?? { what: "The backup schedule did not update.", why: error, next: "Use Refresh backup records and try again.", technical: "", status: 0 }} testId="backup-schedule-problem" />}
    {notice && <Alert role="status" className="text-start"><CircleCheck className="text-primary" aria-hidden="true" /><AlertTitle className="text-sm! wrap-anywhere">{notice}</AlertTitle></Alert>}
    {loading && status("Reading the actual backup schedule…")}
    {records ? <>
      <dl className="grid gap-4 grid-cols-2 @3xl:grid-cols-4">
        <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Schedule</dt><dd className="text-sm wrap-anywhere text-foreground">{schedule ? schedule.enabled ? "Enabled" : "Paused" : "Not configured"}{recovery ? " · Recovery needs review" : schedule?.pending && " · Run pending"}</dd></div>
        <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">{recovery ? "Retained due time" : "Next run"}</dt><dd className="text-sm wrap-anywhere text-foreground">{schedule && (schedule.enabled || recovery) ? <time dateTime={schedule.next_run_at}>{dateLabel(schedule.next_run_at)}</time> : "No run while paused"}</dd></div>
        <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Last run</dt><dd className="flex flex-col text-sm wrap-anywhere text-foreground">{schedule ? statusLabel[schedule.last_status] : "No scheduled run yet"}{schedule?.last_run_at && <small className="text-xs text-muted-foreground"><time dateTime={schedule.last_run_at}>{dateLabel(schedule.last_run_at)}</time></small>}</dd></div>
        <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Archive capacity</dt><dd className="text-sm text-foreground">{archives} / {records.max_archives} snapshots</dd></div>
      </dl>
      {schedule?.last_error && status(runError[schedule.last_error])}
      {!records.runner_enabled && status("The server’s schedule runner is disabled. Enabling is unavailable; you can pause an existing schedule.")}
      {recovery ? status("The interrupted run is paused with recovery evidence retained. Refresh both records, then explicitly review a save or resume. The server must verify the exact previous outcome; if recovery is unresolved, it keeps the marker and rejects the save. This page does not automatically retry or delete evidence.") : schedule?.pending && status("A scheduled backup is running. Refresh records after it finishes before changing this schedule.")}
      {!fresh && !loading && status("Refresh website and schedule records before confirming a change. Your schedule draft is kept.")}
      <form className="flex flex-wrap items-end gap-x-4 gap-y-3" onSubmit={review} aria-labelledby="backup-schedule-heading">
        <div className="flex min-w-0 flex-1 basis-56 flex-col gap-1.5"><label htmlFor="backup-schedule-interval" className="text-sm font-medium text-foreground">Interval</label><NativeSelect id="backup-schedule-interval" className="w-full" value={interval} disabled={parentBusy || saving || loading || !fresh} onChange={(event) => { edited.current = true; setInterval(event.target.value as BackupInterval); setConfirmation(undefined); setNotice(undefined); }}>
          {backupIntervals.map((value) => <NativeSelectOption key={value} value={value}>{intervalLabel[value]}</NativeSelectOption>)}
        </NativeSelect></div>
        <label className="flex min-h-9 items-center gap-2 text-sm text-foreground pointer-coarse:min-h-11"><input type="checkbox" className="size-4 accent-primary" checked={enabled} disabled={parentBusy || saving || loading || !fresh || (!enabled && !records.runner_enabled)} onChange={(event) => { edited.current = true; setEnabled(event.target.checked); setConfirmation(undefined); setNotice(undefined); }} />Enable scheduled backups</label>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" variant="outline" className={rowControl} disabled={!canSave} data-testid="backup-schedule-review">{recovery ? "Review interrupted recovery" : !schedule ? "Review new schedule" : enabled ? "Review schedule change" : "Review schedule pause"}</Button>
          <Button type="button" variant="ghost" className={rowControl} disabled={!draftDirty || parentBusy || saving || loading || !fresh} onClick={() => { edited.current = false; setInterval(schedule?.interval ?? "daily"); setEnabled(schedule?.enabled ?? false); setConfirmation(undefined); setError(undefined); setNotice(undefined); }}>Discard schedule draft</Button>
        </div>
      </form>
      <div className="text-xs text-muted-foreground">One schedule per website; up to 100 website schedules. Manual and scheduled snapshots share the 8-archive and 128 MiB storage limits. Existing archives are not automatically deleted. Scheduled backups do not include server, database, mail or cPanel backups.</div>
    </> : !loading && <div className="text-sm text-muted-foreground">{error ? "Schedule records are unavailable. Refresh to retry." : "Waiting for current website records."}</div>}
    <dialog ref={dialog} className="fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-[min(32rem,calc(100vw-1.75rem))] overflow-auto overscroll-contain rounded-xl border border-border bg-card p-5 text-foreground shadow-xl backdrop:overflow-hidden backdrop:overscroll-contain backdrop:bg-[rgb(8_14_22/58%)]" data-testid="backup-schedule-confirm" aria-labelledby="backup-schedule-title" aria-describedby="backup-schedule-description" onCancel={(event) => { if (saving) event.preventDefault(); else setConfirmation(undefined); }}>{confirmation && <div className="flex flex-col gap-3">
      <h1 id="backup-schedule-title" className="text-lg! tracking-tight!">{confirmation.enabled ? "Save and enable backup schedule?" : schedule ? "Pause backup schedule?" : "Save a paused backup schedule?"}</h1>
      <div id="backup-schedule-description" className="text-sm text-foreground wrap-anywhere">{confirmation.enabled ? <>Save a <strong className="font-semibold">{confirmation.interval}</strong> schedule for <strong className="font-semibold">{site.name}</strong>. The opted-in server runner will create native ZIP snapshots of saved static files.</> : <>Save a paused <strong className="font-semibold">{confirmation.interval}</strong> schedule for <strong className="font-semibold">{site.name}</strong>. Existing snapshots and manual backups are kept.</>}</div>
      {recovery && <div className="text-sm text-muted-foreground">The server must verify the interrupted run’s exact outcome before accepting this save. Unresolved recovery keeps its evidence and returns no confirmed save; no archive is deleted by this action.</div>}
      <div className="text-sm text-muted-foreground">Website revision {confirmation.expected_revision} · {confirmation.expected_schedule_revision ? `schedule revision ${confirmation.expected_schedule_revision}` : "new schedule"}. The archive limit remains 8.</div>
      <div className="mt-2 flex flex-wrap justify-end gap-2"><Button type="button" variant="ghost" className={rowControl} disabled={saving} onClick={() => setConfirmation(undefined)}>Cancel schedule change</Button><Button type="button" className={rowControl} disabled={!canSave} onClick={() => void confirmSave()} data-testid="backup-schedule-save">{saving && <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" />}Confirm backup schedule</Button></div>
    </div>}</dialog>
  </section>;
}
