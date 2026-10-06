import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Archive, ArrowDownToLine, Globe, Info, LockKeyhole, LogOut, RefreshCw } from "lucide-react";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { bytes } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import { downloadSiteBackup, SiteApiError, siteRequest, siteURL, validBackup, validBackupList, validSession, validSite, validSiteList } from "@/lib/sites-api";
import type { OperatorSession, Site, SiteBackup } from "@/lib/sites-api";
import { canConfirmRestorePreview, getRestorePreview, restorePreviewError, restorePreviewMatches, restoreKinds } from "@/lib/restorePreview";
import type { RestorePreview } from "@/lib/restorePreview";
import "./backups.css";
import BackupSchedule from "./BackupSchedule";

type Restore = { site: Site; backup: SiteBackup };
const backupError = (error: unknown) => error instanceof SiteApiError && error.status === 409
  ? "The website changed on the server. Refresh backup records and review the current revision before confirming again. Your Websites editor draft is kept."
  : error instanceof SiteApiError ? error.message : "The backup operation could not be confirmed. Refresh backup records before trying again.";

export default function Backups({ revision, active, onStatus }: { revision: number; active: boolean; onStatus: (value: Resource<unknown>) => void }) {
  const [session, setSession] = useState<OperatorSession>();
  const [accessKey, setAccessKey] = useState("");
  const [sites, setSites] = useState<Site[]>([]);
  const [selected, setSelected] = useState<Site>();
  const [backups, setBackups] = useState<SiteBackup[]>([]);
  const [fresh, setFresh] = useState(false);
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [restore, setRestore] = useState<Restore>();
  const [confirmed, setConfirmed] = useState(false);
  const [preview, setPreview] = useState<RestorePreview>();
  const [previewError, setPreviewError] = useState<string>();
  const dialog = useRef<HTMLDialogElement>(null);
  const restoreOpener = useRef<HTMLButtonElement | null>(null);
  const restoreReturnFocus = useRef(false);
  const previewEpoch = useRef(0);
  const selectedId = useRef<string | undefined>(undefined);
  const epoch = useRef(0);
  const actionPending = useRef(false);
  const activeRef = useRef(active);
  activeRef.current = active;
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const authenticated = session?.authenticated === true;
  const canChange = Boolean(active && authenticated && fresh && selected && selected.state !== "recovery_required" && !busy);
  const previewVerified = Boolean(restore && selected && selected.id === restore.site.id && selected.revision === restore.site.revision && restorePreviewMatches(preview, selected.id, selected.revision, restore.backup) && backups.some(item => item.id === restore.backup.id && item.sha256 === restore.backup.sha256 && item.revision === restore.backup.revision && item.files === restore.backup.files));
  const canRestore = Boolean(canChange && previewVerified && selected && restore && canConfirmRestorePreview(preview, selected.id, selected.revision, restore.backup));

  const clearRestore = useCallback(() => { ++previewEpoch.current; restoreReturnFocus.current = false; setRestore(undefined); setPreview(undefined); setPreviewError(undefined); setConfirmed(false); }, []);
  const clearPrivateRecords = useCallback(() => { setSites([]); setSelected(undefined); setBackups([]); setFresh(false); clearRestore(); }, [clearRestore]);
  const fail = useCallback((failure: unknown) => {
    setError(backupError(failure)); setFresh(false); setConfirmed(false); setPreview(undefined);
    if (failure instanceof SiteApiError && failure.status === 401) { setSession({ authenticated: false }); clearPrivateRecords(); setNotice(undefined); }
  }, [clearPrivateRecords]);

  const loadInventory = useCallback(async (preferredId?: string, isLive: () => boolean = () => true) => {
    const list = await siteRequest("/api/v1/sites", validSiteList);
    if (!isLive()) return;
    const chosen = list.items.find((site) => site.id === (preferredId ?? selectedId.current)) ?? list.items[0];
    if (!chosen) { setSites(list.items); setSelected(undefined); setBackups([]); setFresh(true); setLoadedAt(new Date()); return; }
    const [site, listBackups] = await Promise.all([siteRequest(siteURL(chosen.id), validSite), siteRequest(siteURL(chosen.id, "/backups"), validBackupList)]);
    if (!isLive()) return;
    if (site.id !== chosen.id || listBackups.items.some((backup) => backup.site_id !== chosen.id)) throw new SiteApiError(0, "invalid_response", "The backup inventory did not match the selected website. Refresh before trying again.");
    selectedId.current = site.id;
    setSites(list.items.map((item) => item.id === site.id ? site : item));
    setSelected(site); setBackups(listBackups.items); setFresh(true); setLoadedAt(new Date());
  }, []);

  useEffect(() => {
    const generation = ++epoch.current;
    clearRestore();
    if (!active) { setAccessKey(""); return; }
    if (actionPending.current) return;
    const isLive = () => activeRef.current && generation === epoch.current;
    setBusy("Checking backup records"); setFresh(false); setError(undefined);
    void (async () => {
      try {
        const next = await siteRequest("/api/v1/session", validSession, { unauthenticatedSession: true });
        if (!isLive()) return;
        setSession(next);
        if (next.authenticated) await loadInventory(undefined, isLive);
        else clearPrivateRecords();
        if (isLive()) setLoadedAt(new Date());
      } catch (failure) { if (isLive()) fail(failure); }
      finally { if (isLive()) setBusy(undefined); }
    })();
    return () => { if (generation === epoch.current) ++epoch.current; };
  }, [active, revision, attempt, loadInventory, fail, clearPrivateRecords, clearRestore]);
  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => { setSession({ authenticated: false }); clearPrivateRecords(); setError("Your local operator session expired. Sign in again to access backups. Your Websites editor draft is kept."); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session, clearPrivateRecords]);
  useEffect(() => {
    if (restore && active && authenticated && dialog.current && !dialog.current.open) { dialog.current.showModal(); dialog.current.querySelector<HTMLButtonElement>("button")?.focus(); }
    else if ((!restore || !active || !authenticated) && dialog.current?.open) dialog.current.close();
  }, [restore, active, authenticated]);
  useEffect(() => {
    if (!restore && !busy && active && authenticated && restoreReturnFocus.current) {
      restoreReturnFocus.current = false;
      if (restoreOpener.current?.isConnected) restoreOpener.current.focus();
    }
  }, [restore, busy, active, authenticated]);

  async function run(label: string, action: (isLive: () => boolean) => Promise<void>) {
    if (!activeRef.current || actionPending.current || busy) return;
    actionPending.current = true;
    const generation = epoch.current;
    const isLive = () => activeRef.current && generation === epoch.current;
    setBusy(label); setError(undefined); setNotice(undefined);
    try { await action(isLive); if (isLive()) setLoadedAt(new Date()); }
    catch (failure) { if (isLive()) fail(failure); }
    finally {
      actionPending.current = false;
      if (isLive()) setBusy(undefined);
      else if (activeRef.current) setAttempt((value) => value + 1);
    }
  }

  const refreshRecords = () => { if (actionPending.current || busy) return; clearRestore(); setNotice(undefined); setAttempt((value) => value + 1); };
  function closeRestore() {
    if (busy === "Restoring ZIP backup") return;
    clearRestore(); restoreReturnFocus.current = true;
  }
  async function openRestore(backup: SiteBackup, opener: HTMLButtonElement) {
    if (!canChange || !session?.authenticated || !selected || actionPending.current || restore) return;
    const target = { site: selected, backup }, token = session.csrf_token, generation = ++previewEpoch.current;
    restoreOpener.current = opener;
    setError(undefined); setPreviewError(undefined); setPreview(undefined); setConfirmed(false); setRestore(target);
    await run("Verifying restore preview", async parentLive => {
      const isLive = () => parentLive() && generation === previewEpoch.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      try {
        const value = await getRestorePreview(target.site.id, target.site.revision, target.backup, token);
        if (isLive()) setPreview(value);
      } catch (failure) {
        if (isLive()) { setPreview(undefined); setConfirmed(false); setPreviewError(restorePreviewError(failure)); throw failure; }
      }
    });
  }
  async function login(event: React.FormEvent) {
    event.preventDefault();
    if (!accessKey.trim()) return;
    const key = accessKey; setAccessKey("");
    await run("Signing in", async (isLive) => {
      const next = await siteRequest("/api/v1/session/login", validSession, { method: "POST", body: { access_key: key } });
      if (!isLive()) return;
      if (!next.authenticated) throw new SiteApiError(401, "unauthorized", "The operator access key was not accepted.");
      setSession(next); await loadInventory(undefined, isLive);
    });
  }
  async function createBackup() {
    if (!canChange || !session?.authenticated || !selected || restore) return;
    const target = selected;
    await run("Creating ZIP backup", async (isLive) => {
      const backup = await siteRequest(siteURL(target.id, "/backups"), validBackup, { method: "POST", csrf: session.csrf_token, body: { expected_revision: target.revision } });
      if (!isLive()) return;
      if (backup.site_id !== target.id || backup.revision !== target.revision) throw new SiteApiError(0, "invalid_response", "The backup response did not match this website revision. Refresh records before trying again.");
      setFresh(false); setNotice(`Created ZIP backup of ${target.name}, revision ${backup.revision}.`);
      await loadInventory(target.id, isLive);
    });
  }
  async function downloadBackup(backup: SiteBackup) {
    if (!authenticated || !selected || !fresh || restore) return;
    const target = selected;
    await run("Downloading ZIP backup", async (isLive) => {
      const archive = await downloadSiteBackup(target.id, backup.id, backup.sha256);
      if (!isLive()) return;
      const url = URL.createObjectURL(archive), link = document.createElement("a");
      link.href = url; link.download = "sifruno-site.zip"; link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice(`Verified ZIP hash for ${target.name}. Download started.`);
    });
  }
  async function confirmRestore() {
    if (!restore || !confirmed || !canRestore || !session?.authenticated || Date.parse(session.expires_at) <= Date.now()) return;
    const target = restore;
    const token = session.csrf_token, generation = previewEpoch.current;
    await run("Restoring ZIP backup", async (parentLive) => {
      const sessionLive = () => parentLive() && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      const isLive = () => sessionLive() && generation === previewEpoch.current;
      const site = await siteRequest(siteURL(target.site.id, "/restore"), validSite, { method: "POST", csrf: token, body: { backup_id: target.backup.id, expected_revision: target.site.revision } });
      if (!isLive()) return;
      if (site.id !== target.site.id || site.revision <= target.site.revision) throw new SiteApiError(0, "invalid_response", "The restore response did not confirm an updated website revision. Refresh records before trying again.");
      clearRestore(); setFresh(false);
      setNotice(`Restored saved files for ${site.name}. Current revision ${site.revision}. Your Websites editor draft is kept.`);
      await loadInventory(site.id, sessionLive);
    });
  }

  return <section className="backups-page websites-view" data-testid="backups-page">
    <div className="hosting-notice"><Info aria-hidden="true" /><span>Native Sifruno ZIP snapshots of app-owned static site files only. These archives do not contain server, database, mail or cPanel backups.</span></div>
    {error && <div className="website-message website-error" role="alert"><Info /><span>{error}</span></div>}
    {notice && <div className="website-message" role="status"><Info /><span>{notice}</span></div>}
    {!session ? <Card className="dashboard-card website-auth" padding={0}><p role="status">{busy || "Operator session could not be checked."}</p>{error && <Button label="Retry operator session" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={refreshRecords} />}</Card> : !authenticated ? <Card className="dashboard-card website-auth" padding={0}>
      <div className="auth-heading"><LockKeyhole /><div><h2>Local operator sign-in</h2><p>Use the access key created by this server in its private state directory.</p></div></div>
      <form onSubmit={login} data-testid="operator-login" autoComplete="off"><label htmlFor="backup-access-key">Operator access key</label><input id="backup-access-key" type="password" autoComplete="off" spellCheck={false} value={accessKey} onChange={(event) => setAccessKey(event.target.value)} disabled={Boolean(busy)} required /><Button label="Sign in locally" type="submit" variant="primary" isLoading={busy === "Signing in"} isDisabled={Boolean(busy) || !accessKey.trim()} /></form>
      <p className="website-help">Uses the same local operator session as Websites. The key is cleared after submission; no credentials are stored in this page.</p>
    </Card> : <>
      <div className="website-session"><span><LockKeyhole />Signed in locally · expires {dateLabel(session?.authenticated ? session.expires_at : "")}</span><Button label="Sign out locally" icon={<LogOut />} variant="ghost" size="sm" isDisabled={Boolean(busy)} onClick={() => void run("Signing out", async (isLive) => {
        if (!session?.authenticated) return;
        const next = await siteRequest("/api/v1/session/logout", validSession, { method: "POST", csrf: session.csrf_token, body: {} });
        if (!isLive()) return;
        if (next.authenticated) throw new SiteApiError(0, "invalid_response", "Sign-out was not confirmed.");
        setSession(next); clearPrivateRecords();
      })} /></div>
      <Card className="dashboard-card backup-picker" padding={0}><div><label htmlFor="backups-site-picker">Website</label><NativeSelect id="backups-site-picker" data-testid="backups-site-picker" aria-label="Website for backups" value={selected?.id ?? ""} disabled={Boolean(busy) || Boolean(restore) || !sites.length} onChange={(event) => { if (actionPending.current || busy || restore) return; const id = event.target.value; clearRestore(); setFresh(false); void run("Loading website backups", (isLive) => loadInventory(id, isLive)); }}>
        {!sites.length && <NativeSelectOption value="">No websites available</NativeSelectOption>}{sites.map((site) => <NativeSelectOption key={site.id} value={site.id}>{site.name} · {site.domain}</NativeSelectOption>)}
      </NativeSelect></div><Button label="Refresh backup records" variant="secondary" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={refreshRecords} /></Card>
      {selected ? <>
        <div className="backup-site-context"><span><Globe aria-hidden="true" />{selected.domain}</span><span>Current revision {selected.revision} · {selected.state.replaceAll("_", " ")}</span></div>
        {!fresh && !busy && <p className="backup-status" role="status">Records need to be refreshed before another backup or restore.</p>}
        {selected.state === "recovery_required" && <p className="backup-status" role="alert">This website requires recovery. Backup creation and restore are disabled until its recovery is resolved.</p>}
        <div className="backup-summary"><Card className="dashboard-card" padding={0}><span>Recorded snapshots</span><strong>{backups.length}</strong></Card><Card className="dashboard-card" padding={0}><span>Archive storage</span><strong>{bytes(backups.reduce((sum, backup) => sum + backup.bytes, 0))}</strong></Card><Card className="dashboard-card" padding={0}><span>Latest snapshot</span><strong className="backup-latest">{backups.length ? dateLabel([...backups].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0].created_at) : "No backups yet"}</strong></Card></div>
        <BackupSchedule key={selected.id} site={selected} session={session} active={active} fresh={fresh} busy={Boolean(busy) || Boolean(restore)} archives={backups.length} onRefresh={refreshRecords} onAction={run} onUnauthorized={fail} />
        <Card className="dashboard-card" padding={0} data-testid="backups-inventory" data-site-id={selected.id} data-revision={selected.revision} data-fresh={fresh}>
          <div className="card-heading backup-inventory-heading"><div><h2>ZIP backups · {selected.name}</h2><p>Saved site files only. Unsaved Websites editor drafts stay in the editor.</p></div><Button label="Create ZIP backup" icon={<Archive />} variant="secondary" size="sm" isDisabled={!canChange || Boolean(restore) || backups.length >= 8} isLoading={busy === "Creating ZIP backup"} onClick={() => void createBackup()} /></div>
          {backups.length ? <div className="backup-records">{[...backups].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).map((backup) => <article key={backup.id} data-testid="backup-row" data-backup-id={backup.id}>
            <Archive aria-hidden="true" /><div className="backup-record-info"><h3><time dateTime={backup.created_at}>{dateLabel(backup.created_at)}</time></h3><p>{backup.files} files · {bytes(backup.bytes)} · snapshot revision {backup.revision}</p><details><summary>Backup ID and SHA-256</summary><dl><div><dt>Backup ID</dt><dd>{backup.id}</dd></div><div><dt>SHA-256</dt><dd><code>{backup.sha256}</code></dd></div></dl></details></div>
            <div className="backup-record-actions"><Button label={`Download ZIP backup ${backup.id}`} icon={<ArrowDownToLine />} size="sm" variant="ghost" isDisabled={Boolean(busy) || Boolean(restore) || !fresh} onClick={() => void downloadBackup(backup)}>Download ZIP</Button><Button label={`Restore backup ${backup.id}`} variant="secondary" size="sm" isDisabled={!canChange || Boolean(restore)} onClick={event => void openRestore(backup, event.currentTarget)}>Restore</Button></div>
          </article>)}</div> : <div className="inventory-empty"><Archive /><h3>No ZIP backups recorded</h3><p>Create a snapshot of this website’s saved static files.</p></div>}
          <div className="table-footer"><span>{backups.length} / 8 snapshots for this site</span><span>{loadedAt ? `Checked ${loadedAt.toLocaleTimeString()}` : "Waiting for backup records"}</span></div>
        </Card>
      </> : <Card className="dashboard-card" padding={0}><div className="inventory-empty"><Globe /><h2>{busy ? "Loading website backups" : error ? "Website records unavailable" : "No websites available"}</h2><p>{busy ? "Reading the actual website and backup inventory." : error ? "Refresh backup records to check the current inventory." : "Create an app-owned static website in Websites before creating a ZIP backup."}</p></div></Card>}
    </>}
    {busy && <p className="website-busy" role="status">{busy}…</p>}
    {restore && active && authenticated && <dialog ref={dialog} className="website-restore-dialog backup-restore-dialog" data-testid="backup-restore-confirm" aria-labelledby="backup-restore-title" aria-describedby="backup-restore-description" onCancel={event => { event.preventDefault(); closeRestore(); }}>
      <h2 id="backup-restore-title">Review ZIP restore</h2>
      <p id="backup-restore-description">Replace the saved app-owned static files of <strong>{restore.site.name}</strong> with the snapshot from {dateLabel(restore.backup.created_at)}. This does not restore a server, database or mail system.</p>
      <dl><div><dt>Snapshot</dt><dd>{restore.backup.files} files · {bytes(restore.backup.bytes)} · revision {restore.backup.revision}</dd></div><div><dt>Expected current revision</dt><dd>{restore.site.revision}</dd></div></dl>
      {busy === "Verifying restore preview" && <p className="restore-preview-status" role="status" data-testid="restore-preview-loading">Verifying current saved files and the selected archive. No restore has been sent…</p>}
      {previewVerified && preview && <section className="restore-preview" data-testid="restore-preview-verified" aria-label="Verified restore preview">
        <p className="restore-preview-status" role="status">Verified preview · current revision {preview.current_revision} and selected snapshot revision {preview.backup_revision}</p>
        <dl className="restore-preview-counts">{restoreKinds.map(kind => <div key={kind}><dt>{kind}</dt><dd data-testid={`restore-count-${kind}`}>{preview.counts[kind]}</dd></div>)}</dl>
        {preview.counts.added + preview.counts.modified + preview.counts.removed === 0 && <p className="restore-preview-status" data-testid="restore-preview-no-changes">No file content changes were found. Confirmation still sends a restore request.</p>}
        <ul className="restore-preview-files" aria-label="File changes">{preview.files.map(file => <li key={file.path} data-kind={file.kind}><div><code>{file.path}</code><span>{file.kind}</span></div><small>Current: {file.before ? bytes(file.before.bytes) : "absent"} · snapshot: {file.after ? bytes(file.after.bytes) : "absent"}</small></li>)}</ul>
        <p className="restore-preview-help">Hashes were checked by the server. Only file paths and metadata are shown; a new server change can still reject confirmation.</p>
      </section>}
      {previewError && <p role="alert" className="website-error" data-testid="restore-preview-error">{previewError}</p>}
      {previewVerified && restore.site.revision === Number.MAX_SAFE_INTEGER && <p className="restore-preview-status" role="status">The website revision limit was reached. This preview is readable, but a further restore cannot be confirmed.</p>}
      {!previewVerified && !busy && !previewError && <p className="restore-preview-status">A matching verified preview is required. Refresh records and review the restore again.</p>}
      <p>Your unsaved Websites editor draft will be kept. Compare it with the restored files before saving it.</p>
      <label><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={!canRestore} />I reviewed the verified preview and understand that the current saved files will be replaced.</label>
      <div><Button label="Cancel restore" variant="ghost" isDisabled={busy === "Restoring ZIP backup"} onClick={closeRestore} />{(!fresh || previewError) && <Button label="Refresh backup records" variant="secondary" isDisabled={Boolean(busy)} onClick={refreshRecords} />}<Button label="Confirm restore" variant="primary" isDisabled={!confirmed || !canRestore} isLoading={busy === "Restoring ZIP backup"} onClick={() => void confirmRestore()} data-testid="restore-confirm" /></div>
      {error && !previewError && <p role="alert" className="website-error">{error}</p>}
    </dialog>}
  </section>;
}
