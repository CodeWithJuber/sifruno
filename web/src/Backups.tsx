import { useCallback, useEffect, useRef, useState } from "react";
import { Archive, ArrowDownToLine, CircleCheck, Globe, Info, LoaderCircle, LockKeyhole, LogOut, RefreshCw, TriangleAlert, Upload } from "lucide-react";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { ProblemAlert } from "@/components/problem-alert";
import type { Problem } from "@/components/problem-alert";
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
import BackupSchedule, { siteProblem } from "./BackupSchedule";
import { backupRemovalError, canRemoveBackup, removeSiteBackup } from "@/lib/backupRemoval";
import { resolveRestoreHandoff } from "@/lib/restoreHandoff";
import { backupCopySelection } from "@/lib/backupCopy";
import type { BackupCopySelection } from "@/lib/backupCopy";

import { previewFileRestore, confirmFileRestore, fileRestoreMatches } from "@/lib/fileRestore";
import type { FileRestorePreview } from "@/lib/fileRestore";

type Restore = { site: Site; backup: SiteBackup };
const backupError = (error: unknown) => error instanceof SiteApiError && error.status === 409
  ? "The website changed on the server. Refresh backup records and review the current revision before confirming again. Your Websites editor draft is kept."
  : error instanceof SiteApiError ? error.message : "The backup operation could not be confirmed. Refresh backup records before trying again.";
// What failed, for an error's title, by the label of the action that ran.
const failedAction: Record<string, string> = {
  "Checking backup records": "The backup records could not be loaded.",
  "Loading website backups": "The website's backups could not be loaded.",
  "Signing in": "You were not signed in.",
  "Signing out": "You were not signed out.",
  "Creating ZIP backup": "The ZIP backup was not created.",
  "Downloading ZIP backup": "The ZIP backup was not downloaded.",
  "Verifying restore preview": "The restore preview could not be verified.",
  "Verifying selected file": "The file's restore preview could not be verified.",
  "Restoring ZIP backup": "The website was not restored.",
  "Restoring selected file": "The file was not restored.",
  "Removing ZIP backup": "The ZIP backup was not removed.",
  "Previewing uploaded ZIP": "The uploaded ZIP could not be previewed.",
  "Restoring uploaded ZIP": "The uploaded ZIP was not restored.",
  "Saving backup schedule": "The backup schedule was not saved.",
};

const panel = "rounded-lg border border-border bg-card";
const control = "h-10! text-sm! pointer-coarse:h-12!";
const rowControl = "h-9 pointer-coarse:h-11";
const dialogClass = "fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-[min(40rem,calc(100vw-1.75rem))] overflow-auto overscroll-contain rounded-xl border border-border bg-card p-5 text-foreground shadow-xl backdrop:overflow-hidden backdrop:overscroll-contain backdrop:bg-[rgb(8_14_22/58%)]";
const dialogTitle = "text-lg! tracking-tight! wrap-anywhere";
const checkLabel = "flex items-start gap-2.5 text-sm text-foreground wrap-anywhere [&>input]:mt-0.5 [&>input]:size-4 [&>input]:shrink-0 [&>input]:accent-primary";
const Busy = ({ when }: { when: boolean }) => when ? <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" /> : null;
const fileCount = (count: number) => `${count} ${count === 1 ? "file" : "files"}`;
const Fact = ({ term, children }: { term: string; children: React.ReactNode }) => <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">{term}</dt><dd className="text-sm wrap-anywhere text-foreground">{children}</dd></div>;

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
  const [filePath, setFilePath] = useState("");
  const [filePreview, setFilePreview] = useState<FileRestorePreview>();
  const [fileConfirmed, setFileConfirmed] = useState(false);
  const fileEpoch = useRef(0);
  const clearFileRestore = useCallback(() => { ++fileEpoch.current; setFilePath(""); setFilePreview(undefined); setFileConfirmed(false); }, []);
  // Each error message the page shows, with what failed and the codes behind
  // it; say() files one and hands the message back for its setter.
  const problems = useRef(new Map<string, Problem>());
  const say = useCallback((message: string, what: string, failure?: unknown, next?: string) => { problems.current.set(message, siteProblem(message, what, failure, next)); return message; }, []);
  const problemFor = (message: string): Problem => problems.current.get(message) ?? { what: "The backup action did not finish.", why: message, next: "Use Refresh backup records and try again.", technical: "", status: 0 };
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
  const canRestore = Boolean(!filePath && canChange && !scheduleDirty && previewVerified && selected && restore && canConfirmRestorePreview(preview, selected.id, selected.revision, restore.backup));

  const canRestoreFile = Boolean(filePath && canChange && !scheduleDirty && previewVerified && selected && restore && fileRestoreMatches(filePreview, selected, restore.backup, filePath) && selected.revision < Number.MAX_SAFE_INTEGER && !previewError);

  const clearRestore = useCallback(() => { clearFileRestore(); ++previewEpoch.current; restoreSessionToken.current = undefined; restoreReturnFocus.current = false; setRestore(undefined); setPreview(undefined); setPreviewError(undefined); setConfirmed(false); }, [clearFileRestore]);
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
      if (isLive()) { setPreview(undefined); setConfirmed(false); setPreviewError(say(restorePreviewError(failure), "The restore preview could not be verified.", failure)); throw failure; }
    }
  }, [say]);
  const clearPrivateRecords = useCallback(() => { setSites([]); setSelected(undefined); setBackups([]); setFresh(false); scheduleDraft.current = false; setScheduleDirty(false); clearRestore(); clearUpload(); clearRemoval(); }, [clearRestore, clearUpload, clearRemoval]);
  const fail = useCallback((failure: unknown, what: string) => {
    setError(say(backupError(failure), what, failure)); setFresh(false); setConfirmed(false); setPreview(undefined); setFilePreview(undefined); setFileConfirmed(false); ++fileEpoch.current;
    setUploadPreview(undefined); setUploadConfirmed(false);
    setRemovalConfirmed(false);
    if (failure instanceof SiteApiError && failure.status === 401) { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); clearPrivateRecords(); setNotice(undefined); }
  }, [clearPrivateRecords, say]);
  const failSchedule = useCallback((failure: unknown) => fail(failure, "The backup schedule could not be loaded."), [fail]);

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
      if (scheduleDraft.current) { setBusy(undefined); setError(say(`Cannot open ${request.siteName}: your backup schedule draft is kept. Save or discard it, then request the website or restore review again from Websites.`, "The website was not opened.", undefined, "Save or discard the schedule draft below, then open the website again.")); onHandoffConsumed(request.requestId); return; }
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
      } catch (failure) { if (isLive()) { fail(failure, request?.restore ? "The restore review could not be opened." : "The backup records could not be loaded."); if (request?.restore && failure instanceof SiteApiError && ["invalid_handoff", "stale_handoff", "archive_handoff_changed"].includes(failure.code)) setError(say(failure.message, "The restore review could not be opened.", failure)); } }
      finally { if (activeRef.current && generation === epoch.current) setBusy(undefined); if (request) onHandoffConsumed(request.requestId); }
    })();
    return () => { if (generation === epoch.current) ++epoch.current; };
  }, [active, revision, attempt, handoffRequestId, onHandoffConsumed, loadInventory, fail, clearPrivateRecords, clearRestore, reviewRestore, say]);
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
    const timer = setTimeout(() => { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); clearPrivateRecords(); setError(say("Your local operator session expired. Sign in again to access backups. Your Websites editor draft is kept.", "Your sign-in ended.", undefined, "Sign in again with the operator access key.")); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session, clearPrivateRecords, say]);
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
    catch (failure) { if (isLive()) fail(failure, failedAction[label] ?? "The backup action did not finish."); }
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
      } catch (failure) { if (isLive()) { setRemovalConfirmed(false); setRemovalError(say(backupRemovalError(failure), "The ZIP backup was not removed.", failure)); throw failure; } }
    });
  }
  function closeRestore() {
    if (busy === "Restoring ZIP backup" || busy === "Restoring selected file") return;
    clearRestore(); restoreReturnFocus.current = true;
  }
  async function openRestore(backup: SiteBackup, opener: HTMLButtonElement) {
    if (!canChange || !session?.authenticated || !selected || actionPending.current || restore || scheduleDirty || Date.parse(session.expires_at) <= Date.now()) return;
    const target = { site: selected, backup }, token = session.csrf_token;
    restoreOpener.current = opener;
    await run("Verifying restore preview", parentLive => reviewRestore(target, token, parentLive));
  }
  async function chooseRestoreFile(path: string) {
    if (busy || actionPending.current || !previewVerified || !restore || !session?.authenticated || !fresh) return;
    const target = restore, token = session.csrf_token, generation = ++fileEpoch.current;
    setFilePath(path); setFilePreview(undefined); setFileConfirmed(false); setConfirmed(false); setPreviewError(undefined);
    if (!path) return;
    await run("Verifying selected file", async parentLive => {
      const isLive = () => parentLive() && generation === fileEpoch.current && selectedId.current === target.site.id && !scheduleDraft.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      try {
        const value = await previewFileRestore(target.site, target.backup, path, token);
        if (isLive()) setFilePreview(value);
      } catch (failure) { if (isLive()) { setPreviewError(say(restorePreviewError(failure), "The file's restore preview could not be verified.", failure)); throw failure; } }
    });
  }
  async function restoreSelectedFile() {
    if (!canRestoreFile || !fileConfirmed || !filePreview || !restore || !session?.authenticated || Date.parse(session.expires_at) <= Date.now()) return;
    const target = restore, path = filePath, verified = filePreview, token = session.csrf_token, generation = fileEpoch.current;
    await run("Restoring selected file", async parentLive => {
      const sessionLive = () => parentLive() && selectedId.current === target.site.id && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      const isLive = () => sessionLive() && generation === fileEpoch.current && !scheduleDraft.current;
      const site = await confirmFileRestore({ site: target.site, backup: target.backup, path, preview: verified, confirmed: true, csrf: token, isLive });
      if (!isLive()) return;
      clearRestore(); setFresh(false);
      setNotice(`Restored only ${path} for ${site.name}. All other saved files are preserved. Current revision ${site.revision}. Your Websites editor draft is kept.`);
      await loadInventory(site.id, sessionLive);
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
      } catch (failure) { if (isLive()) { setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(say(backupError(failure), "The uploaded ZIP could not be previewed.", failure)); throw failure; } }
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
      } catch (failure) { if (isLive()) { setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(say(backupError(failure), "The uploaded ZIP was not restored.", failure)); throw failure; } }
    });
  }

  return <div className="@container flex w-full max-w-[90rem] min-w-0 flex-col gap-4" data-testid="backups-page">
    <div className="flex items-start gap-2 text-sm text-muted-foreground"><Info className="mt-0.5 size-4 shrink-0" aria-hidden="true" /><span>Native Sifruno ZIP snapshots of app-owned static site files only. These archives do not contain server, database, mail or cPanel backups.</span></div>
    {error && <ProblemAlert problem={problemFor(error)} testId="backup-handoff-error" />}
    {notice && <Alert role="status" className="text-start"><CircleCheck className="text-primary" aria-hidden="true" /><AlertTitle className="text-sm! wrap-anywhere">{notice}</AlertTitle></Alert>}
    {!session ? <section className={`${panel} max-w-xl p-5`} aria-label="Operator session"><div role="status" className="text-sm text-foreground">{busy || "Operator session could not be checked."}</div>{error && <Button variant="outline" className={`mt-3 ${rowControl}`} disabled={Boolean(busy)} onClick={refreshRecords}><RefreshCw aria-hidden="true" />Retry operator session</Button>}</section> : !authenticated ? <section className={`${panel} max-w-xl p-5`} aria-labelledby="backups-sign-in-heading">
      <div className="flex items-start gap-3.5">
        <LockKeyhole className="size-6 shrink-0 text-primary" aria-hidden="true" />
        <div className="min-w-0"><h2 id="backups-sign-in-heading">Local operator sign-in</h2><div className="mt-1.5 text-sm text-muted-foreground wrap-anywhere">Use the access key created by this server in its private state directory.</div></div>
      </div>
      <form onSubmit={login} data-testid="operator-login" autoComplete="off" className="mt-6 flex flex-col items-start gap-2.5"><label htmlFor="backup-access-key" className="text-sm font-medium text-foreground">Operator access key</label><Input id="backup-access-key" type="password" autoComplete="off" spellCheck={false} value={accessKey} onChange={(event) => setAccessKey(event.target.value)} disabled={Boolean(busy)} required className={`${control} max-w-sm`} /><Button type="submit" className={rowControl} disabled={Boolean(busy) || !accessKey.trim()}><Busy when={busy === "Signing in"} />Sign in locally</Button></form>
      <div className="mt-5 text-xs text-muted-foreground">Uses the same local operator session as Websites. The key is cleared after submission; no credentials are stored in this page.</div>
    </section> : <>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 text-sm text-muted-foreground"><span className="flex min-w-0 items-center gap-2 wrap-anywhere"><LockKeyhole className="size-4 shrink-0" aria-hidden="true" />Signed in locally · expires {dateLabel(session?.authenticated ? session.expires_at : "")}</span><Button variant="ghost" size="sm" className="pointer-coarse:h-11" disabled={Boolean(busy)} onClick={() => void run("Signing out", async (isLive) => {
        if (!session?.authenticated) return;
        const next = await siteRequest("/api/v1/session/logout", validSession, { method: "POST", csrf: session.csrf_token, body: {} });
        if (!isLive()) return;
        if (next.authenticated) throw new SiteApiError(0, "invalid_response", "Sign-out was not confirmed.");
        setSession(next); clearPrivateRecords();
      })}><LogOut aria-hidden="true" />Sign out locally</Button></div>
      <section className={`${panel} flex min-w-0 flex-wrap items-end gap-3 p-4`} aria-label="Website and ZIP import">
        <div className="flex min-w-0 flex-1 basis-64 flex-col gap-1.5 @3xl:max-w-xl"><label htmlFor="backups-site-picker" className="text-sm font-medium text-foreground">Website</label><NativeSelect id="backups-site-picker" data-testid="backups-site-picker" aria-label="Website for backups" className="w-full" value={selected?.id ?? ""} disabled={Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || scheduleDirty || !sites.length} onChange={(event) => { if (actionPending.current || busy || restore || uploadTarget || removal || scheduleDraft.current) return; const id = event.target.value; if (!id) return; clearRestore(); setFresh(false); void run("Loading website backups", async (isLive) => { await loadInventory(id, isLive); }); }}>
          {!selected && <NativeSelectOption value="">{sites.length ? "Choose a website" : "No websites available"}</NativeSelectOption>}{sites.map((site) => <NativeSelectOption key={site.id} value={site.id}>{site.name} · {site.domain}</NativeSelectOption>)}
        </NativeSelect></div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" className={rowControl} disabled={Boolean(busy)} onClick={refreshRecords}><RefreshCw aria-hidden="true" />Refresh backup records</Button>
          <Button variant="outline" className={rowControl} disabled={!active || !fresh || Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || !session?.authenticated || Date.parse(session.expires_at) <= Date.now()} onClick={() => { if (!activeRef.current || actionPending.current || busy || restore || uploadTarget || removal || !fresh || !sessionRef.current?.authenticated || Date.parse(sessionRef.current.expires_at) <= Date.now()) return; clearRestore(); onImportZIP(); }}><Upload aria-hidden="true" />Import native ZIP</Button>
        </div>
        <div className="basis-full text-xs text-muted-foreground">Import creates a new website. Restore from an uploaded native ZIP below replaces static files in the selected existing website. Your schedule draft stays here while you navigate.</div>
      </section>
      {selected ? <>
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-sm text-muted-foreground"><span className="flex min-w-0 items-center gap-2 wrap-anywhere"><Globe className="size-4 shrink-0" aria-hidden="true" />{selected.domain}</span><span>Current revision {selected.revision} · {selected.state.replaceAll("_", " ")}</span></div>
        {!fresh && !busy && <div className="text-sm text-foreground" role="status">Records need to be refreshed before another backup or restore.</div>}
        {selected.state === "recovery_required" && <Alert variant="destructive" className="text-start"><TriangleAlert aria-hidden="true" /><AlertTitle className="text-sm! wrap-anywhere">This website requires recovery. Backup creation and restore are disabled until its recovery is resolved.</AlertTitle></Alert>}
        <dl className="grid grid-cols-2 gap-3 @3xl:grid-cols-3">
          <div className={`${panel} flex min-w-0 flex-col gap-1.5 p-4`}><dt className="text-xs text-muted-foreground">Recorded snapshots</dt><dd className="text-2xl font-semibold tabular-nums text-foreground">{backups.length}</dd></div>
          <div className={`${panel} flex min-w-0 flex-col gap-1.5 p-4`}><dt className="text-xs text-muted-foreground">Archive storage</dt><dd className="text-2xl font-semibold tabular-nums wrap-anywhere text-foreground">{bytes(backups.reduce((sum, backup) => sum + backup.bytes, 0))}</dd></div>
          <div className={`${panel} col-span-2 flex min-w-0 flex-col gap-1.5 p-4 @3xl:col-span-1`}><dt className="text-xs text-muted-foreground">Latest snapshot</dt><dd className="text-base font-semibold wrap-anywhere text-foreground">{backups.length ? dateLabel([...backups].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0].created_at) : "No backups yet"}</dd></div>
        </dl>
        <section className={`${panel} min-w-0`} aria-labelledby="backups-inventory-heading" data-testid="backups-inventory" data-site-id={selected.id} data-revision={selected.revision} data-fresh={fresh}>
          <div className="flex flex-wrap items-start justify-between gap-3 p-4">
            <div className="min-w-0 flex-1 basis-64"><h2 id="backups-inventory-heading" className="text-base! wrap-anywhere">ZIP backups · {selected.name}</h2><div className="mt-1 text-sm text-muted-foreground">Saved site files only. Unsaved Websites editor drafts stay in the editor.</div></div>
            <Button className={rowControl} disabled={!canChange || Boolean(restore) || backups.length >= 8} onClick={() => void createBackup()}>{busy === "Creating ZIP backup" ? <Busy when /> : <Archive aria-hidden="true" />}Create ZIP backup</Button>
          </div>
          {backups.length ? <ul className="m-0 list-none p-0" aria-label={`ZIP backups of ${selected.name}`}>{[...backups].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).map((backup) => <li key={backup.id} className="flex flex-wrap items-start gap-x-4 gap-y-3 border-t border-border p-4" data-testid="backup-row" data-backup-id={backup.id}>
            <Archive className="mt-0.5 hidden size-4 shrink-0 text-muted-foreground @xl:block" aria-hidden="true" />
            <div className="min-w-0 flex-1 basis-64">
              <h3 className="text-sm! font-medium"><time dateTime={backup.created_at}>{dateLabel(backup.created_at)}</time></h3>
              <div className="mt-1 text-sm text-muted-foreground">{fileCount(backup.files)} · {bytes(backup.bytes)} · snapshot revision {backup.revision}</div>
              <details className="mt-2 text-xs"><summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Backup ID and SHA-256</summary><dl className="mt-2 flex flex-col gap-2"><Fact term="Backup ID">{backup.id}</Fact><Fact term="SHA-256"><code className="font-mono text-xs break-all">{backup.sha256}</code></Fact></dl></details>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="ghost" size="sm" className="pointer-coarse:h-11" disabled={Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || !fresh} onClick={() => void downloadBackup(backup)}><ArrowDownToLine aria-hidden="true" />Download ZIP<span className="sr-only"> backup {backup.id}</span></Button>
              <Button variant="outline" size="sm" className="pointer-coarse:h-11" data-testid="backup-recover-new" data-backup-id={backup.id} disabled={!active || !fresh || Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || !authenticated} onClick={() => { if (!selected || !activeRef.current || actionPending.current || busy || restore || uploadTarget || removal || !fresh || !sessionRef.current?.authenticated || Date.parse(sessionRef.current.expires_at) <= Date.now()) return; try { onImportZIP(backupCopySelection(selected, backup)); } catch (failure) { fail(failure, "The ZIP could not be opened as a new website."); } }}>Recover as new website<span className="sr-only"> backup {backup.id}</span></Button>
              <Button variant="outline" size="sm" className="pointer-coarse:h-11" disabled={!canChange || Boolean(restore) || scheduleDirty} onClick={event => void openRestore(backup, event.currentTarget)}>Restore<span className="sr-only"> backup {backup.id}</span></Button>
              <Button variant="destructive" size="sm" className="pointer-coarse:h-11" data-testid="backup-remove-open" disabled={!canChange || Boolean(restore) || scheduleDirty || !canRemoveBackup(selected, backup)} onClick={event => openRemoval(backup, event.currentTarget)}>Remove ZIP<span className="sr-only"> backup {backup.id}</span></Button>
            </div>
          </li>)}</ul> : <Empty className="border-t border-border px-4 py-8"><EmptyHeader><EmptyMedia variant="icon"><Archive aria-hidden="true" /></EmptyMedia><EmptyTitle>No ZIP backups recorded</EmptyTitle><EmptyDescription>Create a snapshot of this website’s saved static files.</EmptyDescription></EmptyHeader></Empty>}
          <div className="flex flex-wrap justify-between gap-x-4 gap-y-1 border-t border-border px-4 py-2.5 text-xs text-muted-foreground"><span>{backups.length} / 8 snapshots for this site</span><span>{loadedAt ? `Checked ${loadedAt.toLocaleTimeString()}` : "Waiting for backup records"}</span></div>
        </section>
        <BackupSchedule key={selected.id} site={selected} session={session} active={active} fresh={fresh} busy={Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal)} archives={backups.length} onRefresh={refreshRecords} onAction={run} onUnauthorized={failSchedule} onDirtyChange={onScheduleDirty} />
        <section className={`${panel} flex min-w-0 flex-col items-start gap-3 p-4`} aria-labelledby="uploaded-restore-heading">
          <h2 id="uploaded-restore-heading" className="text-base!">Restore from a downloaded ZIP</h2>
          <div className="text-sm text-muted-foreground wrap-anywhere">Replace the static files of <strong className="font-semibold text-foreground">{selected.name}</strong> · {selected.domain}. Website identity, routing, backup history and schedule are preserved. Native Sifruno ZIP files only.</div>
          <label htmlFor="uploaded-restore-file" className="text-sm font-medium text-foreground">Choose native ZIP</label>
          <input ref={uploadInput} id="uploaded-restore-file" data-testid="uploaded-restore-file" type="file" accept=".zip,application/zip" className="block w-full max-w-md min-w-0 text-sm text-foreground file:me-3 file:h-9 file:cursor-pointer file:rounded-lg file:border file:border-solid file:border-border file:bg-background file:px-3 file:text-sm file:font-medium file:text-foreground hover:file:bg-muted disabled:opacity-50 pointer-coarse:file:h-11" disabled={Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || scheduleDirty || selected.state === "recovery_required"} onChange={event => { ++uploadEpoch.current; setUploadFile(event.target.files?.[0]); setUploadPreview(undefined); setUploadConfirmed(false); setUploadError(undefined); }} />
          {uploadFile && <div className="text-sm text-foreground wrap-anywhere">{uploadFile.name} · {bytes(uploadFile.size)}</div>}
          <Button variant="outline" className={rowControl} disabled={!active || !uploadFile || Boolean(busy) || Boolean(restore) || Boolean(uploadTarget) || Boolean(removal) || scheduleDirty || selected.state === "recovery_required"} onClick={() => void reviewUploadedRestore()}><Upload aria-hidden="true" />Preview uploaded ZIP</Button>
          {scheduleDirty && <div className="text-xs text-muted-foreground">Save or discard your schedule draft before reviewing an uploaded ZIP.</div>}
        </section>
      </> : <Empty className={`${panel} border-solid py-10`}><EmptyHeader><EmptyMedia variant="icon"><Globe aria-hidden="true" /></EmptyMedia><EmptyTitle>{busy ? "Loading website backups" : error ? "Website records unavailable" : "No websites available"}</EmptyTitle><EmptyDescription>{busy ? "Reading the actual website and backup inventory." : error ? "Refresh backup records to check the current inventory." : "Create a static website under Static sites (old) before creating a ZIP backup."}</EmptyDescription></EmptyHeader></Empty>}
    </>}
    {busy && <div className="text-xs text-muted-foreground" role="status">{busy}…</div>}
    {removal && active && authenticated && <dialog ref={removalDialog} className={dialogClass} data-testid="backup-remove-confirm" aria-labelledby="backup-remove-title" onCancel={event => { event.preventDefault(); closeRemoval(); }}><div className="flex flex-col gap-3">
      <h1 id="backup-remove-title" className={dialogTitle}>Remove saved native ZIP</h1>
      <div className="text-sm text-foreground wrap-anywhere">Permanently remove this one ZIP snapshot from <strong className="font-semibold">{removal.site.name}</strong> · {removal.site.domain}. The current saved website files, routing, other ZIPs and schedule are preserved.</div>
      <dl className="grid gap-3 sm:grid-cols-2">
        <div className="flex min-w-0 flex-col gap-1 sm:col-span-2"><dt className="text-xs text-muted-foreground">Backup ID</dt><dd className="text-sm wrap-anywhere text-foreground" data-testid="backup-remove-id"><code className="font-mono text-xs break-all">{removal.backup.id}</code></dd></div>
        <div className="flex min-w-0 flex-col gap-1 sm:col-span-2"><dt className="text-xs text-muted-foreground">SHA-256</dt><dd className="text-sm text-foreground"><code className="font-mono text-xs break-all">{removal.backup.sha256}</code></dd></div>
        <Fact term="Expected website revision">{removal.site.revision}</Fact>
        <Fact term="Snapshot">{dateLabel(removal.backup.created_at)} · {bytes(removal.backup.bytes)} · {fileCount(removal.backup.files)}</Fact>
      </dl>
      <div className="text-sm text-muted-foreground wrap-anywhere">Download the ZIP first if you need to keep it. Removal frees its saved archive storage and slot. Your unsaved Websites editor draft is kept. A schedule paused at capacity stays paused; review and re-enable it separately.</div>
      {removalError && <ProblemAlert problem={problemFor(removalError)} testId="backup-remove-error" />}
      <label className={checkLabel}><input type="checkbox" data-testid="backup-remove-checkbox" checked={removalConfirmed} disabled={!canConfirmRemoval} onChange={event => setRemovalConfirmed(event.target.checked)} />I understand this selected saved ZIP will be permanently removed.</label>
      <div className="mt-2 flex flex-wrap justify-end gap-2"><Button variant="ghost" className={rowControl} disabled={busy === "Removing ZIP backup"} onClick={closeRemoval}>Cancel ZIP removal</Button><Button variant="destructive" className={rowControl} data-testid="backup-remove-submit" disabled={!removalConfirmed || !canConfirmRemoval} onClick={() => void confirmRemoval()}><Busy when={busy === "Removing ZIP backup"} />Confirm ZIP removal</Button></div>
    </div></dialog>}
    {uploadTarget && active && authenticated && <dialog ref={uploadDialog} className={dialogClass} data-testid="uploaded-restore-confirm" aria-labelledby="uploaded-restore-title" onCancel={event => { event.preventDefault(); closeUploadedRestore(); }}><div className="flex flex-col gap-3">
      <h1 id="uploaded-restore-title" className={dialogTitle}>Review uploaded ZIP restore</h1><div className="text-sm text-foreground wrap-anywhere">Replace saved static files in <strong className="font-semibold">{uploadTarget.name}</strong> · {uploadTarget.domain} with <strong className="font-semibold">{uploadFile?.name}</strong>. Routing, backup history and schedule stay with this website.</div>
      {busy === "Previewing uploaded ZIP" && <div className="text-sm text-foreground" role="status">Verifying current files and uploaded ZIP. No restore has been sent…</div>}
      {uploadPreview && <section className="flex min-w-0 flex-col gap-3" data-testid="uploaded-restore-preview" aria-label="Verified uploaded ZIP preview">
        <div className="text-sm text-foreground">Current website revision {uploadPreview.current_revision} · archive source revision {uploadPreview.backup_revision}</div>
        <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">{restoreKinds.map(kind => <div key={kind} className="min-w-0 rounded-md border border-border p-2"><dt className="text-xs capitalize text-muted-foreground">{kind}</dt><dd className="mt-1 text-lg font-semibold tabular-nums text-foreground" data-testid={`uploaded-restore-count-${kind}`}>{uploadPreview.counts[kind]}</dd></div>)}</dl>
        <ul className="m-0 max-h-60 list-none overflow-y-auto overscroll-contain border-y border-border p-0" aria-label="Uploaded ZIP file changes">{uploadPreview.files.map(file => <li key={file.path} data-kind={file.kind} className="border-b border-border py-2.5 last:border-b-0"><div className="flex items-baseline justify-between gap-3"><code className="min-w-0 font-mono text-xs wrap-anywhere text-foreground">{file.path}</code><span className="shrink-0 text-xs capitalize text-muted-foreground">{file.kind}</span></div><small className="mt-1 block text-xs text-muted-foreground">Current: {file.before ? bytes(file.before.bytes) : "absent"} · ZIP: {file.after ? bytes(file.after.bytes) : "absent"}</small></li>)}</ul>
        <details className="text-xs"><summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Verified archive SHA-256</summary><code className="mt-2 block font-mono text-xs break-all text-foreground">{uploadPreview.archive_sha256}</code></details>
      </section>}
      {uploadError && <ProblemAlert problem={{ ...problemFor(uploadError), next: "Close this dialog and use Preview uploaded ZIP to review a fresh comparison." }} testId="uploaded-restore-error" />}
      <div className="text-sm text-muted-foreground">Your unsaved Websites editor draft is kept. Compare it with the restored files before saving.</div>
      <label className={checkLabel}><input data-testid="uploaded-restore-checkbox" type="checkbox" checked={uploadConfirmed} disabled={!uploadPreview || Boolean(busy) || !fresh || uploadTarget.revision >= Number.MAX_SAFE_INTEGER} onChange={event => setUploadConfirmed(event.target.checked)} />I reviewed the uploaded ZIP preview and understand that this website’s current saved files will be replaced.</label>
      <div className="mt-2 flex flex-wrap justify-end gap-2"><Button variant="ghost" className={rowControl} disabled={busy === "Restoring uploaded ZIP"} onClick={closeUploadedRestore}>Cancel uploaded ZIP restore</Button><Button className={rowControl} data-testid="uploaded-restore-submit" disabled={!uploadPreview || !uploadConfirmed || Boolean(busy) || !fresh || uploadTarget.revision >= Number.MAX_SAFE_INTEGER} onClick={() => void restoreUploadedZIP()}><Busy when={busy === "Restoring uploaded ZIP"} />Confirm uploaded ZIP restore</Button></div>
    </div></dialog>}
    {restore && active && authenticated && session.csrf_token === restoreSessionToken.current && <dialog ref={dialog} className={dialogClass} data-testid="backup-restore-confirm" data-site-id={restore.site.id} data-backup-id={restore.backup.id} data-backup-sha={restore.backup.sha256} aria-labelledby="backup-restore-title" aria-describedby="backup-restore-description" onCancel={event => { event.preventDefault(); closeRestore(); }}><div className="flex flex-col gap-3">
      <h1 id="backup-restore-title" className={dialogTitle}>{filePath ? "Review single-file restore" : "Review ZIP restore"}</h1>
      <div id="backup-restore-description" className="text-sm text-foreground wrap-anywhere">{filePath ? <>Restore only <strong className="font-semibold">{filePath}</strong> in <strong className="font-semibold">{restore.site.name}</strong>. Every other currently saved file stays unchanged.</> : <>Replace the saved app-owned static files of <strong className="font-semibold">{restore.site.name}</strong> with the snapshot from {dateLabel(restore.backup.created_at)}, or choose one file below. This does not restore a server, database or mail system.</>}</div>
      <dl className="grid gap-3 sm:grid-cols-2"><Fact term="Snapshot">{fileCount(restore.backup.files)} · {bytes(restore.backup.bytes)} · revision {restore.backup.revision}</Fact><Fact term="Expected current revision">{restore.site.revision}</Fact></dl>
      {busy === "Verifying restore preview" && <div className="text-sm text-foreground" role="status" data-testid="restore-preview-loading">Verifying current saved files and the selected archive. No restore has been sent…</div>}
      {previewVerified && preview && <div className="flex min-w-0 flex-col gap-1.5"><label htmlFor="backup-restore-file-picker" className="text-sm font-medium text-foreground">Restore scope</label><NativeSelect id="backup-restore-file-picker" data-testid="backup-restore-file-picker" className="w-full" value={filePath} disabled={Boolean(busy)} onChange={event => void chooseRestoreFile(event.target.value)}><NativeSelectOption value="">All files from this ZIP</NativeSelectOption>{preview.files.filter(file => file.after).map(file => <NativeSelectOption key={file.path} value={file.path}>Only {file.path}</NativeSelectOption>)}</NativeSelect><div className="text-xs text-muted-foreground">Select one archived file to preserve all other current saved files.</div></div>}
      {busy === "Verifying selected file" && <div className="text-sm text-foreground" role="status">Verifying the selected file and merged website limits…</div>}
      {filePath && filePreview && previewVerified && <section className="flex min-w-0 flex-col gap-1.5 rounded-md border border-border p-3 text-sm text-foreground" data-testid="backup-file-restore-preview" aria-label="Verified single-file restore preview"><div className="wrap-anywhere">Only <code className="font-mono text-xs">{filePreview.file.path}</code> will be {filePreview.file.kind === "added" ? "added" : filePreview.file.kind === "unchanged" ? "restored with identical bytes" : "replaced"}.</div><div>Current: {filePreview.file.before ? bytes(filePreview.file.before.bytes) : "absent"} / snapshot: {bytes(filePreview.file.after!.bytes)}</div><div className="text-muted-foreground">{filePreview.preserved_files} other saved files preserved. Website routing, state, saved ZIPs and schedule stay unchanged.</div></section>}
      {!filePath && previewVerified && preview && <section className="flex min-w-0 flex-col gap-3" data-testid="restore-preview-verified" aria-label="Verified restore preview">
        <div className="text-sm text-foreground" role="status">Verified preview · current revision {preview.current_revision} and selected snapshot revision {preview.backup_revision}</div>
        <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">{restoreKinds.map(kind => <div key={kind} className="min-w-0 rounded-md border border-border p-2"><dt className="text-xs capitalize text-muted-foreground">{kind}</dt><dd className="mt-1 text-lg font-semibold tabular-nums text-foreground" data-testid={`restore-count-${kind}`}>{preview.counts[kind]}</dd></div>)}</dl>
        {preview.counts.added + preview.counts.modified + preview.counts.removed === 0 && <div className="text-sm text-foreground" data-testid="restore-preview-no-changes">No file content changes were found. Confirmation still sends a restore request.</div>}
        <ul className="m-0 max-h-60 list-none overflow-y-auto overscroll-contain border-y border-border p-0" aria-label="File changes">{preview.files.map(file => <li key={file.path} data-kind={file.kind} className="border-b border-border py-2.5 last:border-b-0"><div className="flex items-baseline justify-between gap-3"><code className="min-w-0 font-mono text-xs wrap-anywhere text-foreground">{file.path}</code><span className="shrink-0 text-xs capitalize text-muted-foreground">{file.kind}</span></div><small className="mt-1 block text-xs text-muted-foreground">Current: {file.before ? bytes(file.before.bytes) : "absent"} · snapshot: {file.after ? bytes(file.after.bytes) : "absent"}</small></li>)}</ul>
        <div className="text-xs text-muted-foreground">Hashes were checked by the server. Only file paths and metadata are shown; a new server change can still reject confirmation.</div>
      </section>}
      {previewError && <ProblemAlert problem={problemFor(previewError)} testId="restore-preview-error" />}
      {previewVerified && restore.site.revision === Number.MAX_SAFE_INTEGER && <div className="text-sm text-foreground" role="status">The website revision limit was reached. This preview is readable, but a further restore cannot be confirmed.</div>}
      {!previewVerified && !busy && !previewError && <div className="text-sm text-foreground">A matching verified preview is required. Refresh records and review the restore again.</div>}
      <div className="text-sm text-muted-foreground">Your unsaved Websites editor draft will be kept. Compare it with the restored files before saving it.</div>
      {!filePath && <label className={checkLabel}><input type="checkbox" data-testid="restore-confirm-checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={!canRestore} />I reviewed the verified preview and understand that the current saved files will be replaced.</label>}
      {filePath && <label className={checkLabel}><input type="checkbox" data-testid="backup-file-restore-checkbox" checked={fileConfirmed} disabled={!canRestoreFile} onChange={event => setFileConfirmed(event.target.checked)} />I reviewed this preview and confirm restoring only {filePath}. All other saved files will be preserved.</label>}
      <div className="mt-2 flex flex-wrap justify-end gap-2"><Button variant="ghost" className={rowControl} disabled={busy === "Restoring ZIP backup" || busy === "Restoring selected file"} onClick={closeRestore}>Cancel restore</Button>{(!fresh || previewError) && <Button variant="outline" className={rowControl} disabled={Boolean(busy)} onClick={refreshRecords}>Refresh backup records</Button>}{filePath ? <Button className={rowControl} data-testid="backup-file-restore-submit" disabled={!fileConfirmed || !canRestoreFile} onClick={() => void restoreSelectedFile()}><Busy when={busy === "Restoring selected file"} />Restore only selected file</Button> : <Button className={rowControl} disabled={!confirmed || !canRestore} onClick={() => void confirmRestore()} data-testid="restore-confirm"><Busy when={busy === "Restoring ZIP backup"} />Confirm restore</Button>}</div>
      {error && !previewError && <ProblemAlert problem={problemFor(error)} testId="backup-restore-problem" />}
    </div></dialog>}
  </div>;
}
