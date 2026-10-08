import { useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { CalendarClock, Info, RefreshCw } from "lucide-react";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { dateLabel } from "@/lib/api";
import { SiteApiError } from "@/lib/sites-api";
import type { OperatorSession, Site } from "@/lib/sites-api";
import { backupIntervals, backupScheduleError, getBackupSchedule, putBackupSchedule, stoppedBackupRecovery } from "@/lib/backupSchedule";
import type { BackupInterval, BackupScheduleEnvelope, BackupScheduleInput } from "@/lib/backupSchedule";
import "./backup-schedule.css";

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
        setError(backupScheduleError(failure));
        if (failure instanceof SiteApiError && failure.status === 401) onUnauthorized(failure);
      } finally { if (isLive()) setLoading(false); }
    })();
    return () => { if (generation === readEpoch.current) ++readEpoch.current; };
  }, [active, authenticated, csrf, site.id, site.revision, siteFresh, parentBusy, onUnauthorized]);
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
        if (isLive()) { setFresh(false); setConfirmation(undefined); setError(backupScheduleError(failure)); }
        throw failure;
      }
    });
    submitting.current = false;
    if (mounted.current) setSaving(false);
  }

  if (!active || !authenticated) return null;
  return <Card className="dashboard-card backup-schedule" padding={0} data-testid="backup-schedule" data-fresh={fresh}>
    <div className="backup-schedule-heading"><CalendarClock aria-hidden="true" /><div><h2>Scheduled ZIP backups</h2><p>Saved static website files only. Scheduling uses this server’s opt-in runner.</p></div><Button label="Refresh schedule and website records" variant="ghost" size="sm" icon={<RefreshCw />} isDisabled={parentBusy || saving || loading} onClick={onRefresh} /></div>
    {error && <p className="website-message website-error" role="alert"><Info aria-hidden="true" />{error}</p>}
    {notice && <p className="website-message" role="status"><Info aria-hidden="true" />{notice}</p>}
    {loading && <p role="status">Reading the actual backup schedule…</p>}
    {records ? <>
      <dl className="backup-schedule-summary">
        <div><dt>Schedule</dt><dd>{schedule ? schedule.enabled ? "Enabled" : "Paused" : "Not configured"}{recovery ? " · Recovery needs review" : schedule?.pending && " · Run pending"}</dd></div>
        <div><dt>{recovery ? "Retained due time" : "Next run"}</dt><dd>{schedule && (schedule.enabled || recovery) ? <time dateTime={schedule.next_run_at}>{dateLabel(schedule.next_run_at)}</time> : "No run while paused"}</dd></div>
        <div><dt>Last run</dt><dd>{schedule ? statusLabel[schedule.last_status] : "No scheduled run yet"}{schedule?.last_run_at && <small><time dateTime={schedule.last_run_at}>{dateLabel(schedule.last_run_at)}</time></small>}</dd></div>
        <div><dt>Archive capacity</dt><dd>{archives} / {records.max_archives} snapshots</dd></div>
      </dl>
      {schedule?.last_error && <p className="backup-status" role="status">{runError[schedule.last_error]}</p>}
      {!records.runner_enabled && <p className="backup-status" role="status">The server’s schedule runner is disabled. Enabling is unavailable; you can pause an existing schedule.</p>}
      {recovery ? <p className="backup-status" role="status">The interrupted run is paused with recovery evidence retained. Refresh both records, then explicitly review a save or resume. The server must verify the exact previous outcome; if recovery is unresolved, it keeps the marker and rejects the save. This page does not automatically retry or delete evidence.</p> : schedule?.pending && <p className="backup-status" role="status">A scheduled backup is running. Refresh records after it finishes before changing this schedule.</p>}
      {!fresh && !loading && <p className="backup-status" role="status">Refresh website and schedule records before confirming a change. Your schedule draft is kept.</p>}
      <form className="backup-schedule-form" onSubmit={review}>
        <div><label htmlFor="backup-schedule-interval">Interval</label><NativeSelect id="backup-schedule-interval" value={interval} disabled={parentBusy || saving || loading || !fresh} onChange={(event) => { edited.current = true; setInterval(event.target.value as BackupInterval); setConfirmation(undefined); setNotice(undefined); }}>
          {backupIntervals.map((value) => <NativeSelectOption key={value} value={value}>{intervalLabel[value]}</NativeSelectOption>)}
        </NativeSelect></div>
        <label className="backup-schedule-toggle"><input type="checkbox" checked={enabled} disabled={parentBusy || saving || loading || !fresh || (!enabled && !records.runner_enabled)} onChange={(event) => { edited.current = true; setEnabled(event.target.checked); setConfirmation(undefined); setNotice(undefined); }} />Enable scheduled backups</label>
        <Button label={recovery ? "Review interrupted recovery" : !schedule ? "Review new schedule" : enabled ? "Review schedule change" : "Review schedule pause"} type="submit" variant="secondary" isDisabled={!canSave} data-testid="backup-schedule-review" />
        <Button label="Discard schedule draft" variant="ghost" isDisabled={!draftDirty || parentBusy || saving || loading || !fresh} onClick={() => { edited.current = false; setInterval(schedule?.interval ?? "daily"); setEnabled(schedule?.enabled ?? false); setConfirmation(undefined); setError(undefined); setNotice(undefined); }} />
      </form>
      <p className="website-help">One schedule per website; up to 100 website schedules. Manual and scheduled snapshots share the 8-archive and 128 MiB storage limits. Existing archives are not automatically deleted. Scheduled backups do not include server, database, mail or cPanel backups.</p>
    </> : !loading && <p className="backup-status">{error ? "Schedule records are unavailable. Refresh to retry." : "Waiting for current website records."}</p>}
    <dialog ref={dialog} className="website-restore-dialog backup-schedule-dialog" data-testid="backup-schedule-confirm" aria-labelledby="backup-schedule-title" aria-describedby="backup-schedule-description" onCancel={(event) => { if (saving) event.preventDefault(); else setConfirmation(undefined); }}>{confirmation && <>
      <h2 id="backup-schedule-title">{confirmation.enabled ? "Save and enable backup schedule?" : schedule ? "Pause backup schedule?" : "Save a paused backup schedule?"}</h2>
      <p id="backup-schedule-description">{confirmation.enabled ? <>Save a <strong>{confirmation.interval}</strong> schedule for <strong>{site.name}</strong>. The opted-in server runner will create native ZIP snapshots of saved static files.</> : <>Save a paused <strong>{confirmation.interval}</strong> schedule for <strong>{site.name}</strong>. Existing snapshots and manual backups are kept.</>}</p>
      {recovery && <p>The server must verify the interrupted run’s exact outcome before accepting this save. Unresolved recovery keeps its evidence and returns no confirmed save; no archive is deleted by this action.</p>}
      <p>Website revision {confirmation.expected_revision} · {confirmation.expected_schedule_revision ? `schedule revision ${confirmation.expected_schedule_revision}` : "new schedule"}. The archive limit remains 8.</p>
      <div><Button label="Cancel schedule change" variant="ghost" isDisabled={saving} onClick={() => setConfirmation(undefined)} /><Button label="Confirm backup schedule" variant="primary" isDisabled={!canSave} isLoading={saving} onClick={() => void confirmSave()} data-testid="backup-schedule-save" /></div>
    </>}</dialog>
  </Card>;
}
