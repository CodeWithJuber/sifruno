import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Archive, ArrowDownToLine, Globe, Info, LockKeyhole, LogOut, RefreshCw, Upload } from "lucide-react";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { bytes } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import type { SiteHandoff } from "@/App";
import { downloadSiteBackup, SiteApiError, siteRequest, siteURL, validBackup, validBackupList, validSession, validSite, validSiteList } from "@/lib/sites-api";
import type { OperatorSession, Site, SiteBackup } from "@/lib/sites-api";
import { canConfirmRestorePreview, getRestorePreview, restorePreviewError, restorePreviewMatches, restoreKinds } from "@/lib/restorePreview";
import type { RestorePreview } from "@/lib/restorePreview";
import { previewArchiveRestore, confirmArchiveRestore } from "@/lib/archiveRestore";
import type { ArchiveRestorePreview } from "@/lib/archiveRestore";
import "./backups.css";
import BackupSchedule from "./BackupSchedule";
import { backupRemovalError, canRemoveBackup, removeSiteBackup } from "@/lib/backupRemoval";
import { resolveRestoreHandoff } from "@/lib/restoreHandoff";
import { backupCopySelection } from "@/lib/backupCopy";
import type { BackupCopySelection } from "@/lib/backupCopy";

type Restore = { site: Site; backup: SiteBackup };
const backupError = (error: unknown) => error instanceof SiteApiError && error.status === 409
  ? "The website changed on the server. Refresh backup records and review the current revision before confirming again. Your Websites editor draft is kept."
  : error instanceof SiteApiError ? error.message : "The backup operation could not be confirmed. Refresh backup records before trying again.";

export default function Backups({ revision, active, onStatus, siteHandoff, onHandoffConsumed, onImportZIP }: { revision: number; active: boolean; onStatus: (value: Resource<unknown>) => void; siteHandoff?: SiteHandoff; onHandoffConsumed: (requestId: number) => void; onImportZIP: (snapshot?: BackupCopySelection) => void }) {
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
  const [removal, setRemoval] = useState<Restore>();
  const [removalConfirmed, setRemovalConfirmed] = useState(false);
  const [removalError, setRemovalError] = useState<string>();
  const removalDialog = useRef<HTMLDialogElement>(null);
  const removalOpener = useRef<HTMLButtonElement | null>(null);
  const removalEpoch = useRef(0);
  const clearRemoval = useCallback(() => { ++removalEpoch.current; setRemoval(undefined); setRemovalConfirmed(false); setRemovalError(undefined); }, []);
  const [confirmed, setConfirmed] = useState(false);
  const [preview, setPreview] = useState<RestorePreview>();
  const [previewError, setPreviewError] = useState<string>();
  const [uploadFile, setUploadFile] = useState<File>();
  const [uploadTarget, setUploadTarget] = useState<Site>();
  const [uploadPreview, setUploadPreview] = useState<ArchiveRestorePreview>();
  const [uploadConfirmed, setUploadConfirmed] = useState(false);
  const [uploadError, setUploadError] = useState<string>();
  const uploadDialog = useRef<HTMLDialogElement>(null);
  const uploadInput = useRef<HTMLInputElement>(null);
  const uploadEpoch = useRef(0);
  const clearUpload = useCallback(() => { ++uploadEpoch.current; setUploadFile(undefined); setUploadTarget(undefined); setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(undefined); if (uploadInput.current) uploadInput.current.value = ""; }, []);
  const dialog = useRef<HTMLDialogElement>(null);
  const restoreOpener = useRef<HTMLButtonElement | null>(null);
  const restoreReturnFocus = useRef(false);
  const previewEpoch = useRef(0);
  const restoreSessionToken = useRef<string | undefined>(undefined);
  const selectedId = useRef<string | undefined>(undefined);
  const handoff = useRef(siteHandoff), handledHandoff = useRef(0);
  if (siteHandoff) handoff.current = siteHandoff;
  const handoffRequestId = handoff.current?.requestId;
  const scheduleDraft = useRef(false);
  const [scheduleDirty, setScheduleDirty] = useState(false);
  const onScheduleDirty = useCallback((dirty: boolean) => { scheduleDraft.current = dirty; setScheduleDirty(dirty); }, []);
  const epoch = useRef(0);
  const actionPending = useRef(false);
  const activeRef = useRef(active);
  activeRef.current = active;
  const authEpoch = useRef(0);
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const authenticated = session?.authenticated === true;
  const canChange = Boolean(active && authenticated && fresh && selected && selected.state !== "recovery_required" && !busy && !uploadTarget && !removal);
  const canConfirmRemoval = Boolean(active && authenticated && fresh && selected && removal && !busy && !restore && !uploadTarget && !scheduleDirty && !removalError && selected.id === removal.site.id && selected.revision === removal.site.revision && canRemoveBackup(selected, removal.backup) && backups.some(item => item.id === removal.backup.id && item.sha256 === removal.backup.sha256));
  const previewVerified = Boolean(restore && session?.authenticated && session.csrf_token === restoreSessionToken.current && Date.parse(session.expires_at) > Date.now() && selected && selected.id === restore.site.id && selected.revision === restore.site.revision && restorePreviewMatches(preview, selected.id, selected.revision, restore.backup) && backups.some(item => item.id === restore.backup.id && item.sha256 === restore.backup.sha256 && item.revision === restore.backup.revision && item.files === restore.backup.files));
  const canRestore = Boolean(canChange && !scheduleDirty && previewVerified && selected && restore && canConfirmRestorePreview(preview, selected.id, selected.revision, restore.backup));

  const clearRestore = useCallback(() => { ++previewEpoch.current; restoreSessionToken.current = undefined; restoreReturnFocus.current = false; setRestore(undefined); setPreview(undefined); setPreviewError(undefined); setConfirmed(false); }, []);
  const reviewRestore = useCallback(async (target: Restore, token: string, parentLive: () => boolean) => {
    const generation = ++previewEpoch.current;
    const isLive = () => parentLive() && generation === previewEpoch.current && selectedId.current === target.site.id && !scheduleDraft.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
    if (!isLive()) return;
    restoreSessionToken.current = token;
    setError(undefined); setPreviewError(undefined); setPreview(undefined); setConfirmed(false); setRestore(target);
    try {
      const value = await getRestorePreview(target.site.id, target.site.revision, target.backup, token);
      if (isLive()) setPreview(value);
    } catch (failure) {
      if (isLive()) { setPreview(undefined); setConfirmed(false); setPreviewError(restorePreviewError(failure)); throw failure; }
    }
  }, []);
  const clearPrivateRecords = useCallback(() => { setSites([]); setSelected(undefined); setBackups([]); setFresh(false); scheduleDraft.current = false; setScheduleDirty(false); clearRestore(); clearUpload(); clearRemoval(); }, [clearRestore, clearUpload, clearRemoval]);
  const fail = useCallback((failure: unknown) => {
    setError(backupError(failure)); setFresh(false); setConfirmed(false); setPreview(undefined);
    setUploadPreview(undefined); setUploadConfirmed(false);
    setRemovalConfirmed(false);
    if (failure instanceof SiteApiError && failure.status === 401) { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); clearPrivateRecords(); setNotice(undefined); }
  }, [clearPrivateRecords]);

  const loadInventory = useCallback(async (preferredId?: string, isLive: () => boolean = () => true) => {
    if (!isLive()) return;
    const wanted = preferredId ?? selectedId.current;
    if (wanted !== undefined && !/^[a-f0-9]{32}$/.test(wanted)) { selectedId.current = wanted; clearPrivateRecords(); throw new SiteApiError(404, "not_found", "The requested website is unavailable. Choose a website explicitly."); }
    const list = await siteRequest("/api/v1/sites", validSiteList);
    if (!isLive()) return;
    const chosen = wanted === undefined ? list.items[0] : list.items.find((site) => site.id === wanted);
    if (wanted !== undefined && !chosen) { selectedId.current = wanted; clearPrivateRecords(); setSites(list.items); throw new SiteApiError(404, "not_found", "The requested website is no longer in the inventory. Choose a website explicitly."); }
    if (!chosen) { setSites(list.items); setSelected(undefined); setBackups([]); setFresh(true); setLoadedAt(new Date()); return; }
    const [site, listBackups] = await Promise.all([siteRequest(siteURL(chosen.id), validSite), siteRequest(siteURL(chosen.id, "/backups"), validBackupList)]);
    if (!isLive()) return;
    if (site.id !== chosen.id || listBackups.items.some((backup) => backup.site_id !== chosen.id)) throw new SiteApiError(0, "invalid_response", "The backup inventory did not match the selected website. Refresh before trying again.");
    if (scheduleDraft.current && selectedId.current !== site.id) throw new SiteApiError(409, "draft_kept", "Your backup schedule draft is kept. Save or discard it, then open the requested website again from Websites.");
    selectedId.current = site.id;
    setSites(list.items.map((item) => item.id === site.id ? site : item));
    setSelected(site); setBackups(listBackups.items); setFresh(true); setLoadedAt(new Date());
    return { site, backups: listBackups.items };
  }, [clearPrivateRecords]);

  useEffect(() => {
    const generation = ++epoch.current;
    clearRestore();
    const request = handoff.current && handoff.current.requestId !== handledHandoff.current ? handoff.current : undefined;
    if (!active) { setAccessKey(""); if (request?.restore) { handledHandoff.current = request.requestId; onHandoffConsumed(request.requestId); } return; }
    if (actionPending.current) return;
    if (request) {
      handledHandoff.current = request.requestId;
      if (scheduleDraft.current) { setBusy(undefined); setError(`Cannot open ${request.siteName}: your backup schedule draft is kept. Save or discard it, then request the website or restore review again from Websites.`); onHandoffConsumed(request.requestId); return; }
      selectedId.current = request.siteId; setNotice(undefined); clearPrivateRecords();
    }
    const authGeneration = authEpoch.current;
    let token: string | undefined;
    const isLive = () => activeRef.current && generation === epoch.current && authGeneration === authEpoch.current && (token === undefined || (sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now()));
    setBusy("Checking backup records"); setFresh(false); setError(undefined);
    void (async () => {
      try {
        const next = await siteRequest("/api/v1/session", validSession, { unauthenticatedSession: true });
        if (!isLive()) return;
        sessionRef.current = next; setSession(next);
        if (next.authenticated) {
          token = next.csrf_token;
          const inventory = await loadInventory(request?.siteId, isLive);
          if (request?.restore && isLive() && inventory) {
            const backup = resolveRestoreHandoff(request.restore, request.siteId, inventory.site, inventory.backups);
            setBusy("Verifying restore preview"); restoreOpener.current = null;
            await reviewRestore({ site: inventory.site, backup }, token, isLive);
          }
        }
        else clearPrivateRecords();
        if (isLive()) setLoadedAt(new Date());
      } catch (failure) { if (isLive()) { fail(failure); if (request?.restore && failure instanceof SiteApiError && ["invalid_handoff", "stale_handoff", "archive_handoff_changed"].includes(failure.code)) setError(failure.message); } }
      finally { if (activeRef.current && generation === epoch.current) setBusy(undefined); if (request) onHandoffConsumed(request.requestId); }
    })();
    return () => { if (generation === epoch.current) ++epoch.current; };
  }, [active, revision, attempt, handoffRequestId, onHandoffConsumed, loadInventory, fail, clearPrivateRecords, clearRestore, reviewRestore]);
  useEffect(() => {
    if (restore && (!session?.authenticated || session.csrf_token !== restoreSessionToken.current || selected?.id !== restore.site.id || selected.revision !== restore.site.revision)) clearRestore();
  }, [restore, session, selected, clearRestore]);
  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => { clearUpload(); }, [active, revision, handoffRequestId, selected?.id, clearUpload]);
  useEffect(() => { clearRemoval(); }, [active, revision, handoffRequestId, selected?.id, session?.authenticated === true ? session.csrf_token : undefined, clearRemoval]);
  useEffect(() => {
    if (removal && active && authenticated && removalDialog.current && !removalDialog.current.open) { removalDialog.current.showModal(); removalDialog.current.querySelector<HTMLButtonElement>("button")?.focus(); }
    else if ((!removal || !active || !authenticated) && removalDialog.current?.open) removalDialog.current.close();
  }, [removal, active, authenticated]);
  useEffect(() => {
    if (uploadTarget && active && authenticated && uploadDialog.current && !uploadDialog.current.open) { uploadDialog.current.showModal(); uploadDialog.current.querySelector<HTMLButtonElement>("button")?.focus(); }
    else if ((!uploadTarget || !active || !authenticated) && uploadDialog.current?.open) uploadDialog.current.close();
  }, [uploadTarget, active, authenticated]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); clearPrivateRecords(); setError("Your local operator session expired. Sign in again to access backups. Your Websites editor draft is kept."); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
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

  const refreshRecords = () => { if (actionPending.current || busy || uploadTarget || removal) return; clearRestore(); setNotice(undefined); setAttempt((value) => value + 1); };
  function closeRemoval() {
    if (busy === "Removing ZIP backup") return;
    clearRemoval(); if (removalOpener.current?.isConnected) removalOpener.current.focus();
  }
  function openRemoval(backup: SiteBackup, opener: HTMLButtonElement) {
    if (!canChange || !selected || !session?.authenticated || Date.parse(session.expires_at) <= Date.now() || restore || uploadTarget || scheduleDirty || actionPending.current || !canRemoveBackup(selected, backup)) return;
    removalOpener.current = opener; setRemovalError(undefined); setRemovalConfirmed(false); setRemoval({ site: selected, backup });
  }
  async function confirmRemoval() {
    if (!canConfirmRemoval || !removal || !removalConfirmed || !session?.authenticated || Date.parse(session.expires_at) <= Date.now()) return;
    const target = removal, token = session.csrf_token, generation = removalEpoch.current, authGeneration = authEpoch.current;
    await run("Removing ZIP backup", async parentLive => {
      const sessionLive = () => parentLive() && selectedId.current === target.site.id && authGeneration === authEpoch.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      const isLive = () => sessionLive() && generation === removalEpoch.current && !scheduleDraft.current;
      try {
        const site = await removeSiteBackup(target.site, target.backup, token, isLive);
        if (!isLive()) return;
        clearRemoval(); setFresh(false); setNotice(`Removed one saved native ZIP from ${site.name}. Current files, routing, other ZIPs and schedule are preserved. If the schedule paused at capacity, review and re-enable it separately.`);
        await loadInventory(site.id, sessionLive);
      } catch (failure) { if (isLive()) { setRemovalConfirmed(false); setRemovalError(backupRemovalError(failure)); throw failure; } }
    });
  }
  function closeRestore() {
    if (busy === "Restoring ZIP backup") return;
    clearRestore(); restoreReturnFocus.current = true;
  }
  async function openRestore(backup: SiteBackup, opener: HTMLButtonElement) {
    if (!canChange || !session?.authenticated || !selected || actionPending.current || restore || scheduleDirty || Date.parse(session.expires_at) <= Date.now()) return;
    const target = { site: selected, backup }, token = session.csrf_token;
    restoreOpener.current = opener;
    await run("Verifying restore preview", parentLive => reviewRestore(target, token, parentLive));
  }
  async function login(event: React.FormEvent) {
    event.preventDefault();
    if (!accessKey.trim()) return;
    const key = accessKey; setAccessKey("");
    await run("Signing in", async (isLive) => {
      const next = await siteRequest("/api/v1/session/login", validSession, { method: "POST", body: { access_key: key } });
      if (!isLive()) return;
      if (!next.authenticated) throw new SiteApiError(401, "unauthorized", "The operator access key was not accepted.");
      sessionRef.current = next; setSession(next); await loadInventory(undefined, isLive);
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
    if (!authenticated || !selected || !fresh || restore || uploadTarget || removal) return;
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

  function closeUploadedRestore() {
    if (busy === "Restoring uploaded ZIP") return;
    ++uploadEpoch.current; setUploadTarget(undefined); setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(undefined);
    uploadInput.current?.focus();
  }
  async function reviewUploadedRestore() {
    if (!active || !authenticated || !selected || !uploadFile || busy || restore || uploadTarget || removal || scheduleDirty || selected.state === "recovery_required" || !session?.authenticated) return;
    const file = uploadFile, target = selected, token = session.csrf_token, generation = ++uploadEpoch.current;
    setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(undefined); setUploadTarget(target);
    await run("Previewing uploaded ZIP", async parentLive => {
      const isLive = () => parentLive() && generation === uploadEpoch.current && selectedId.current === target.id && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      try {
        const latest = await siteRequest(siteURL(target.id), validSite);
        if (!isLive()) return;
        if (latest.id !== target.id || latest.state === "recovery_required") throw new SiteApiError(409, "invalid_context", "The selected website is unavailable for restore.");
        setSelected(latest); setUploadTarget(latest);
        const result = await previewArchiveRestore({ site: latest, archive: file, csrf: token, isLive });
        if (isLive()) { setUploadPreview(result); setFresh(true); }
      } catch (failure) { if (isLive()) { setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(backupError(failure)); throw failure; } }
    });
  }
  async function restoreUploadedZIP() {
    if (!uploadTarget || !uploadFile || !uploadPreview || !uploadConfirmed || busy || !active || !fresh || !session?.authenticated || selected?.id !== uploadTarget.id || selected.revision !== uploadPreview.current_revision) return;
    const target = uploadTarget, file = uploadFile, verified = uploadPreview, token = session.csrf_token, generation = uploadEpoch.current;
    await run("Restoring uploaded ZIP", async parentLive => {
      const sessionLive = () => parentLive() && selectedId.current === target.id && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      const isLive = () => sessionLive() && generation === uploadEpoch.current;
      try {
        const site = await confirmArchiveRestore({ site: target, archive: file, preview: verified, csrf: token, isLive });
        if (!isLive()) return;
        clearUpload(); setFresh(false); setNotice(`Restored uploaded ZIP files for ${site.name}. Website routing, backup history and schedule are preserved. Current revision ${site.revision}. Your Websites editor draft is kept.`);
        await loadInventory(site.id, sessionLive);
      } catch (failure) { if (isLive()) { setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(backupError(failure)); throw failure; } }
    });
  }

  return <section className="backups-page websites-view" data-testid="backups-page">
    <div className="hosting-notice"><Info aria-hidden="true" /><span>Native Sifruno ZIP snapshots of app-owned static site files only. These archives do not contain server, database, mail or cPanel backups.</span></div>
    {error && <div className="website-message website-error" role="alert" data-testid="backup-handoff-error"><Info /><span>{error}</span></div>}
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
      <div className="website-actions"><Button label="Import native ZIP" icon={<Upload />} variant="secondary" size="sm" isDisabled={!active || !fresh || Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || !session?.authenticated || Date.parse(session.expires_at) <= Date.now()} onClick={() => { if (!activeRef.current || actionPending.current || busy || restore || uploadTarget || removal || !fresh || !sessionRef.current?.authenticated || Date.parse(sessionRef.current.expires_at) <= Date.now()) return; clearRestore(); onImportZIP(); }} /></div>
      <p className="website-help">Import creates a new website. Restore from an uploaded native ZIP below replaces static files in the selected existing website. Your schedule draft stays here while you navigate.</p>
      <Card className="dashboard-card backup-picker" padding={0}><div><label htmlFor="backups-site-picker">Website</label><NativeSelect id="backups-site-picker" data-testid="backups-site-picker" aria-label="Website for backups" value={selected?.id ?? ""} disabled={Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || scheduleDirty || !sites.length} onChange={(event) => { if (actionPending.current || busy || restore || uploadTarget || removal || scheduleDraft.current) return; const id = event.target.value; if (!id) return; clearRestore(); setFresh(false); void run("Loading website backups", async (isLive) => { await loadInventory(id, isLive); }); }}>
        {!selected && <NativeSelectOption value="">{sites.length ? "Choose a website" : "No websites available"}</NativeSelectOption>}{sites.map((site) => <NativeSelectOption key={site.id} value={site.id}>{site.name} · {site.domain}</NativeSelectOption>)}
      </NativeSelect></div><Button label="Refresh backup records" variant="secondary" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={refreshRecords} /></Card>
      {selected ? <>
        <div className="backup-site-context"><span><Globe aria-hidden="true" />{selected.domain}</span><span>Current revision {selected.revision} · {selected.state.replaceAll("_", " ")}</span></div>
        <Card className="dashboard-card uploaded-restore-card" padding={0}>
          <h2>Restore from a downloaded ZIP</h2><p>Replace the static files of <strong>{selected.name}</strong> · {selected.domain}. Website identity, routing, backup history and schedule are preserved. Native Sifruno ZIP files only.</p>
          <label htmlFor="uploaded-restore-file">Choose native ZIP</label><input ref={uploadInput} id="uploaded-restore-file" data-testid="uploaded-restore-file" type="file" accept=".zip,application/zip" disabled={Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || scheduleDirty || selected.state === "recovery_required"} onChange={event => { ++uploadEpoch.current; setUploadFile(event.target.files?.[0]); setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(undefined); }} />
          {uploadFile && <p>{uploadFile.name} · {bytes(uploadFile.size)}</p>}
          <Button label="Preview uploaded ZIP" icon={<Upload />} variant="secondary" isDisabled={!active || !uploadFile || Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || scheduleDirty || selected.state === "recovery_required"} onClick={() => void reviewUploadedRestore()} />
          {scheduleDirty && <p className="website-help">Save or discard your schedule draft before reviewing an uploaded ZIP.</p>}
        </Card>
        {!fresh && !busy && <p className="backup-status" role="status">Records need to be refreshed before another backup or restore.</p>}
        {selected.state === "recovery_required" && <p className="backup-status" role="alert">This website requires recovery. Backup creation and restore are disabled until its recovery is resolved.</p>}
        <div className="backup-summary"><Card className="dashboard-card" padding={0}><span>Recorded snapshots</span><strong>{backups.length}</strong></Card><Card className="dashboard-card" padding={0}><span>Archive storage</span><strong>{bytes(backups.reduce((sum, backup) => sum + backup.bytes, 0))}</strong></Card><Card className="dashboard-card" padding={0}><span>Latest snapshot</span><strong className="backup-latest">{backups.length ? dateLabel([...backups].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0].created_at) : "No backups yet"}</strong></Card></div>
        <BackupSchedule key={selected.id} site={selected} session={session} active={active} fresh={fresh} busy={Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal)} archives={backups.length} onRefresh={refreshRecords} onAction={run} onUnauthorized={fail} onDirtyChange={onScheduleDirty} />
        <Card className="dashboard-card" padding={0} data-testid="backups-inventory" data-site-id={selected.id} data-revision={selected.revision} data-fresh={fresh}>
          <div className="card-heading backup-inventory-heading"><div><h2>ZIP backups · {selected.name}</h2><p>Saved site files only. Unsaved Websites editor drafts stay in the editor.</p></div><Button label="Create ZIP backup" icon={<Archive />} variant="secondary" size="sm" isDisabled={!canChange || Boolean(restore) || backups.length >= 8} isLoading={busy === "Creating ZIP backup"} onClick={() => void createBackup()} /></div>
          {backups.length ? <div className="backup-records">{[...backups].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).map((backup) => <article key={backup.id} data-testid="backup-row" data-backup-id={backup.id}>
            <Archive aria-hidden="true" /><div className="backup-record-info"><h3><time dateTime={backup.created_at}>{dateLabel(backup.created_at)}</time></h3><p>{backup.files} files · {bytes(backup.bytes)} · snapshot revision {backup.revision}</p><details><summary>Backup ID and SHA-256</summary><dl><div><dt>Backup ID</dt><dd>{backup.id}</dd></div><div><dt>SHA-256</dt><dd><code>{backup.sha256}</code></dd></div></dl></details></div>
            <div className="backup-record-actions"><Button label={`Download ZIP backup ${backup.id}`} icon={<ArrowDownToLine />} size="sm" variant="ghost" isDisabled={Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || !fresh} onClick={() => void downloadBackup(backup)}>Download ZIP</Button><Button label={`Recover as new website backup ${backup.id}`} data-testid="backup-recover-new" data-backup-id={backup.id} variant="secondary" size="sm" isDisabled={!active || !fresh || Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || !authenticated} onClick={() => { if (!selected || !activeRef.current || actionPending.current || busy || restore || uploadTarget || removal || !fresh || !sessionRef.current?.authenticated || Date.parse(sessionRef.current.expires_at) <= Date.now()) return; try { onImportZIP(backupCopySelection(selected, backup)); } catch (failure) { fail(failure); } }}>Recover as new website</Button><Button label={`Restore backup ${backup.id}`} variant="secondary" size="sm" isDisabled={!canChange || Boolean(restore) || scheduleDirty} onClick={event => void openRestore(backup, event.currentTarget)}>Restore</Button><Button label={`Remove ZIP backup ${backup.id}`} data-testid="backup-remove-open" variant="ghost" size="sm" isDisabled={!canChange || Boolean(restore) || scheduleDirty || !canRemoveBackup(selected, backup)} onClick={event => openRemoval(backup, event.currentTarget)}>Remove ZIP</Button></div>
          </article>)}</div> : <div className="inventory-empty"><Archive /><h3>No ZIP backups recorded</h3><p>Create a snapshot of this website’s saved static files.</p></div>}
          <div className="table-footer"><span>{backups.length} / 8 snapshots for this site</span><span>{loadedAt ? `Checked ${loadedAt.toLocaleTimeString()}` : "Waiting for backup records"}</span></div>
        </Card>
      </> : <Card className="dashboard-card" padding={0}><div className="inventory-empty"><Globe /><h2>{busy ? "Loading website backups" : error ? "Website records unavailable" : "No websites available"}</h2><p>{busy ? "Reading the actual website and backup inventory." : error ? "Refresh backup records to check the current inventory." : "Create an app-owned static website in Websites before creating a ZIP backup."}</p></div></Card>}
    </>}
    {busy && <p className="website-busy" role="status">{busy}…</p>}
    {removal && active && authenticated && <dialog ref={removalDialog} className="website-restore-dialog backup-restore-dialog" data-testid="backup-remove-confirm" aria-labelledby="backup-remove-title" onCancel={event => { event.preventDefault(); closeRemoval(); }}>
      <h2 id="backup-remove-title">Remove saved native ZIP</h2>
      <p>Permanently remove this one ZIP snapshot from <strong>{removal.site.name}</strong> · {removal.site.domain}. The current saved website files, routing, other ZIPs and schedule are preserved.</p>
      <dl><div><dt>Backup ID</dt><dd data-testid="backup-remove-id"><code>{removal.backup.id}</code></dd></div><div><dt>SHA-256</dt><dd><code>{removal.backup.sha256}</code></dd></div><div><dt>Expected website revision</dt><dd>{removal.site.revision}</dd></div><div><dt>Snapshot</dt><dd>{dateLabel(removal.backup.created_at)} · {bytes(removal.backup.bytes)} · {removal.backup.files} files</dd></div></dl>
      <p>Download the ZIP first if you need to keep it. Removal frees its saved archive storage and slot. Your unsaved Websites editor draft is kept. A schedule paused at capacity stays paused; review and re-enable it separately.</p>
      {removalError && <p role="alert" className="website-error" data-testid="backup-remove-error">{removalError}</p>}
      <label><input type="checkbox" data-testid="backup-remove-checkbox" checked={removalConfirmed} disabled={!canConfirmRemoval} onChange={event => setRemovalConfirmed(event.target.checked)} />I understand this selected saved ZIP will be permanently removed.</label>
      <div><Button label="Cancel ZIP removal" variant="ghost" isDisabled={busy === "Removing ZIP backup"} onClick={closeRemoval} /><Button label="Confirm ZIP removal" data-testid="backup-remove-submit" variant="primary" isDisabled={!removalConfirmed || !canConfirmRemoval} isLoading={busy === "Removing ZIP backup"} onClick={() => void confirmRemoval()} /></div>
    </dialog>}
    {uploadTarget && active && authenticated && <dialog ref={uploadDialog} className="website-restore-dialog backup-restore-dialog" data-testid="uploaded-restore-confirm" aria-labelledby="uploaded-restore-title" onCancel={event => { event.preventDefault(); closeUploadedRestore(); }}>
      <h2 id="uploaded-restore-title">Review uploaded ZIP restore</h2><p>Replace saved static files in <strong>{uploadTarget.name}</strong> · {uploadTarget.domain} with <strong>{uploadFile?.name}</strong>. Routing, backup history and schedule stay with this website.</p>
      {busy === "Previewing uploaded ZIP" && <p role="status">Verifying current files and uploaded ZIP. No restore has been sent…</p>}
      {uploadPreview && <section className="restore-preview" data-testid="uploaded-restore-preview" aria-label="Verified uploaded ZIP preview">
        <p>Current website revision {uploadPreview.current_revision} · archive source revision {uploadPreview.backup_revision}</p>
        <dl className="restore-preview-counts">{restoreKinds.map(kind => <div key={kind}><dt>{kind}</dt><dd data-testid={`uploaded-restore-count-${kind}`}>{uploadPreview.counts[kind]}</dd></div>)}</dl>
        <ul className="restore-preview-files" aria-label="Uploaded ZIP file changes">{uploadPreview.files.map(file => <li key={file.path} data-kind={file.kind}><div><code>{file.path}</code><span>{file.kind}</span></div><small>Current: {file.before ? bytes(file.before.bytes) : "absent"} · ZIP: {file.after ? bytes(file.after.bytes) : "absent"}</small></li>)}</ul>
        <details><summary>Verified archive SHA-256</summary><code>{uploadPreview.archive_sha256}</code></details>
      </section>}
      {uploadError && <p role="alert" className="website-error" data-testid="uploaded-restore-error">{uploadError} Close this dialog and use Preview uploaded ZIP to review a fresh comparison.</p>}
      <p>Your unsaved Websites editor draft is kept. Compare it with the restored files before saving.</p>
      <label><input data-testid="uploaded-restore-checkbox" type="checkbox" checked={uploadConfirmed} disabled={!uploadPreview || Boolean(busy) || !fresh || uploadTarget.revision >= Number.MAX_SAFE_INTEGER} onChange={event => setUploadConfirmed(event.target.checked)} />I reviewed the uploaded ZIP preview and understand that this website’s current saved files will be replaced.</label>
      <div><Button label="Cancel uploaded ZIP restore" variant="ghost" isDisabled={busy === "Restoring uploaded ZIP"} onClick={closeUploadedRestore} /><Button label="Confirm uploaded ZIP restore" data-testid="uploaded-restore-submit" variant="primary" isDisabled={!uploadPreview || !uploadConfirmed || Boolean(busy) || !fresh || uploadTarget.revision >= Number.MAX_SAFE_INTEGER} isLoading={busy === "Restoring uploaded ZIP"} onClick={() => void restoreUploadedZIP()} /></div>
    </dialog>}
    {restore && active && authenticated && session.csrf_token === restoreSessionToken.current && <dialog ref={dialog} className="website-restore-dialog backup-restore-dialog" data-testid="backup-restore-confirm" data-site-id={restore.site.id} data-backup-id={restore.backup.id} data-backup-sha={restore.backup.sha256} aria-labelledby="backup-restore-title" aria-describedby="backup-restore-description" onCancel={event => { event.preventDefault(); closeRestore(); }}>
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
      <label><input type="checkbox" data-testid="restore-confirm-checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={!canRestore} />I reviewed the verified preview and understand that the current saved files will be replaced.</label>
      <div><Button label="Cancel restore" variant="ghost" isDisabled={busy === "Restoring ZIP backup"} onClick={closeRestore} />{(!fresh || previewError) && <Button label="Refresh backup records" variant="secondary" isDisabled={Boolean(busy)} onClick={refreshRecords} />}<Button label="Confirm restore" variant="primary" isDisabled={!confirmed || !canRestore} isLoading={busy === "Restoring ZIP backup"} onClick={() => void confirmRestore()} data-testid="restore-confirm" /></div>
      {error && !previewError && <p role="alert" className="website-error">{error}</p>}
    </dialog>}
  </section>;
}
