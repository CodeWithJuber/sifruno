import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { cn } from "cn";
import { Archive, ArrowDownToLine, ArrowUpRight, Check, CircleAlert, File, FilePlus, Folder, Globe, Info, LoaderCircle, LockKeyhole, LogOut, Plus, RefreshCw, Save, Search, Upload } from "lucide-react";
import { bytes, panel, Segments, TechnicalDetails } from "@/Dashboard";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import { downloadSiteBackup, importSiteArchive, previewURL, sitePreviewPort, SiteApiError, siteRequest, siteURL, validBackup, validBackupList, validFileContent, validFileList, validSession, validSite, validSiteList } from "@/lib/sites-api";
import type { OperatorSession, Site, SiteBackup, SiteFile, SiteFileContent } from "@/lib/sites-api";
import { restoreHandoffFor } from "@/lib/restoreHandoff";
import type { RestoreHandoff } from "@/lib/restoreHandoff";
import { prepareBackupCopy } from "@/lib/backupCopy";
import type { PreparedBackupCopy, ZIPImportRequest } from "@/lib/backupCopy";

interface Editor {
  path: string;
  draft: string;
  savedContent: string;
  sha256: string;
  revision: number;
  isNew: boolean;
}
interface FileConflict { revision: number; file?: SiteFileContent }
const fromFile = (file: SiteFileContent): Editor => ({ path: file.path, draft: file.content, savedContent: file.content, sha256: file.sha256, revision: file.revision, isNew: false });
const errorText = (error: unknown) => error instanceof SiteApiError ? error.message : "The local operation could not be confirmed. Your editor draft is kept.";

// The base styles colour <p> and size inputs and buttons outside Tailwind's
// layers, so coloured text uses div or span and a few sizes carry "!", as on
// the other rebuilt screens.
const muted = "text-xs text-muted-foreground wrap-anywhere";
const fieldLabel = "text-sm font-medium text-foreground";
const field = "flex min-w-0 flex-col gap-1.5";
const input = "h-9! text-base! md:text-sm! pointer-coarse:h-11!";
const touch = "pointer-coarse:h-11";
const dialogClass = "fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-[min(32.5rem,calc(100vw-1.75rem))] overflow-auto overscroll-contain rounded-xl border border-border bg-card p-5 text-foreground shadow-xl backdrop:overflow-hidden backdrop:overscroll-contain backdrop:bg-[rgb(8_14_22/58%)]";
const dialogTitle = "pb-1 text-lg! tracking-tight!";
const dialogText = "mt-2 text-sm text-muted-foreground wrap-anywhere";
const dialogForm = "mt-5 flex flex-col gap-3.5";
const dialogActions = "mt-2 flex flex-wrap justify-end gap-2";
const dialogError = "text-sm text-destructive wrap-anywhere";
// A refresh-and-review box inside a dialog, shown when its target changed.
const refreshBox = "flex flex-col items-start gap-2.5 rounded-md border border-input bg-muted p-3 text-sm text-foreground wrap-anywhere";
const spinner = <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" />;
const stateLabels: Record<Site["state"], string> = { active: "Active", suspended: "Suspended", recovery_required: "Needs recovery" };

function SiteState({ state, className }: { state: Site["state"]; className?: string }) {
  return <Badge variant={state === "active" ? "secondary" : state === "recovery_required" ? "destructive" : "outline"} className={cn(state === "active" ? "text-primary" : state === "suspended" && "text-muted-foreground", className)}>{stateLabels[state]}</Badge>;
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return <div className="min-w-0"><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 text-sm text-foreground wrap-anywhere">{children}</dd></div>;
}

export default function Websites({ revision, active, onStatus, onOpenSiteTool, importRequest, onImportRequestConsumed }: { revision: number; active: boolean; onStatus: (value: Resource<unknown>) => void; onOpenSiteTool: (destination: "files" | "backups", siteId: string, siteName: string, restore?: RestoreHandoff) => void; importRequest?: ZIPImportRequest; onImportRequestConsumed: (requestId: number) => void }) {
  const [session, setSession] = useState<OperatorSession>();
  const [accessKey, setAccessKey] = useState("");
  const [sites, setSites] = useState<Site[]>([]);
  const [inventoryLoaded, setInventoryLoaded] = useState(false);
  const [selected, setSelected] = useState<Site>();
  const [files, setFiles] = useState<SiteFile[]>([]);
  const [backups, setBackups] = useState<SiteBackup[]>([]);
  const [editor, setEditor] = useState<Editor>();
  const [asset, setAsset] = useState<{ siteId: string; revision: number; file: SiteFile }>();
  const fileReadEpoch = useRef(0);
  const latestAsset = useRef(asset); latestAsset.current = asset;
  const clearAsset = useCallback(() => { setAsset(undefined); latestAsset.current = undefined; }, []);
  const [conflict, setConflict] = useState<FileConflict>();
  const [sessionAttempt, setSessionAttempt] = useState(0);
  const [query, setQuery] = useState("");
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [createOpen, setCreateOpen] = useState(false);
  const [section, setSection] = useState("files");
  const [importOpen, setImportOpen] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<Site>();
  const [removeDomain, setRemoveDomain] = useState("");
  const [removeNeedsRefresh, setRemoveNeedsRefresh] = useState(false);
  const removeDialog = useRef<HTMLDialogElement>(null);
  const removeGeneration = useRef(0), removePending = useRef(false);
  const uncertainRemovals = useRef(new Set<string>());
  const [domainTarget, setDomainTarget] = useState<Site>();
  const [nextDomain, setNextDomain] = useState("");
  const [domainNeedsRefresh, setDomainNeedsRefresh] = useState(false);
  const [nameTarget, setNameTarget] = useState<Site>();
  const [nextName, setNextName] = useState("");
  const [nameNeedsRefresh, setNameNeedsRefresh] = useState(false);
  const [nameSettling, setNameSettling] = useState(false);
  const [importName, setImportName] = useState("");
  const [importDomain, setImportDomain] = useState("");
  const [importArchive, setImportArchive] = useState<File>();
  const [discardDraftForImport, setDiscardDraftForImport] = useState(false);
  const [preparedCopy, setPreparedCopy] = useState<PreparedBackupCopy>();
  const importInput = useRef<HTMLInputElement>(null);
  const importFormPending = useRef(false);
  importFormPending.current = Boolean(importArchive || importName || importDomain);
  const clearImportForm = useCallback(() => { setPreparedCopy(undefined); setImportArchive(undefined); setImportName(""); setImportDomain(""); setDiscardDraftForImport(false); if (importInput.current) importInput.current.value = ""; }, []);
  const closeImport = () => { ++importGeneration.current; setImportOpen(false); clearImportForm(); };
  const createDialog = useRef<HTMLDialogElement>(null);
  const importDialog = useRef<HTMLDialogElement>(null);
  const domainDialog = useRef<HTMLDialogElement>(null);
  const domainGeneration = useRef(0), domainPending = useRef(false);
  const nameDialog = useRef<HTMLDialogElement>(null);
  const nameGeneration = useRef(0), namePending = useRef(false);
  const importGeneration = useRef(0), importPending = useRef(false), authEpoch = useRef(0);
  const requestedImport = useRef(importRequest), handledImport = useRef(0);
  if (importRequest !== undefined) requestedImport.current = importRequest;
  const importRequestId = requestedImport.current?.requestId;
  const activeRef = useRef(active), sessionRef = useRef(session); activeRef.current = active; sessionRef.current = session;
  const dialogReturnFocus = useRef<HTMLElement | null>(null);
  const latestEditor = useRef(editor);
  const latestSelected = useRef(selected);
  latestEditor.current = editor;
  latestSelected.current = selected;
  const dirty = Boolean(editor && (editor.isNew || editor.draft !== editor.savedContent));
  const nameBytes = new TextEncoder().encode(name.trim()).length;
  const domainBytes = new TextEncoder().encode(domain.trim()).length;
  const importNameBytes = new TextEncoder().encode(importName.trim()).length;
  const importDomainLength = importDomain.trim().length;
  const importDomainBytes = new TextEncoder().encode(importDomain.trim()).length;
  const previewPort = sitePreviewPort();
  const maxTransferArchive = 34 * 1024 * 1024;
  const authenticated = session?.authenticated === true;
  const editable = authenticated && selected && selected.state !== "recovery_required";
  const nextDomainBytes = new TextEncoder().encode(nextDomain.trim()).length;
  const removeReady = Boolean(active && authenticated && removeTarget && selected?.id === removeTarget.id && selected.revision === removeTarget.revision && selected.state !== "recovery_required" && !dirty && !conflict && !busy && !removeNeedsRefresh && removeDomain === removeTarget.domain);
  const domainReady = Boolean(active && authenticated && domainTarget && selected?.id === domainTarget.id && selected.revision === domainTarget.revision && selected.state !== "recovery_required" && !dirty && !conflict && !busy && !domainNeedsRefresh && nextDomain.trim() && nextDomainBytes <= 253);
  const nextNameBytes = new TextEncoder().encode(nextName.trim()).length;
  const nameReady = Boolean(active && authenticated && nameTarget && selected?.id === nameTarget.id && selected.revision === nameTarget.revision && selected.state !== "recovery_required" && !dirty && !conflict && !busy && !nameSettling && !nameNeedsRefresh && nextName.trim() && nextNameBytes <= 80 && !/[\u0000-\u001f\u007f]/.test(nextName.trim()));

  const fail = useCallback((failure: unknown) => {
    setError(errorText(failure));
    if (failure instanceof SiteApiError && failure.status === 401) { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); setNotice(undefined); }
  }, []);
  const updateSite = (site: Site) => {
    setSelected(site);
    setSites((old) => old.some((s) => s.id === site.id) ? old.map((s) => s.id === site.id ? site : s) : [...old, site]);
  };
  const readFile = (site: Site, path: string) => siteRequest(siteURL(site.id, `/file?path=${encodeURIComponent(path)}`), validFileContent);

  async function openFile(site: Site, file: SiteFile, isLive: () => boolean = () => true) {
    const generation = ++fileReadEpoch.current, authGeneration = authEpoch.current;
    const token = sessionRef.current?.authenticated ? sessionRef.current.csrf_token : undefined;
    const live = () => isLive() && activeRef.current && generation === fileReadEpoch.current && authGeneration === authEpoch.current && (token === undefined || (sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now()));
    if (!live()) return;
    clearAsset(); setEditor(undefined); latestEditor.current = undefined; setConflict(undefined);
    try {
      const value = await readFile(site, file.path);
      if (!live()) return;
      if (value.path !== file.path) throw new SiteApiError(0, "invalid_response", "The file response did not match the selected path.");
      const next = fromFile(value); setEditor(next); latestEditor.current = next;
    } catch (failure) {
      if (!live()) return;
      if (!(failure instanceof SiteApiError && failure.status === 422)) throw failure;
      const next = { siteId: site.id, revision: site.revision, file: { ...file } }; setAsset(next); latestAsset.current = next;
    }
  }
  async function loadSite(siteId: string, preserveDraft = false, isLive: () => boolean = () => true) {
    const previous = latestEditor.current;
    const previousAsset = latestAsset.current;
    ++fileReadEpoch.current;
    if (!preserveDraft && isLive()) { clearAsset(); setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); }
    const [site, fileList, backupList] = await Promise.all([
      siteRequest(siteURL(siteId), validSite),
      siteRequest(siteURL(siteId, "/files"), validFileList),
      siteRequest(siteURL(siteId, "/backups"), validBackupList),
    ]);
    if (!isLive()) return;
    updateSite(site);
    setFiles(fileList.items);
    setBackups(backupList.items);
    if (!preserveDraft) {
      const previousPath = previous && !previous.isNew ? previous.path : previousAsset?.siteId === site.id ? previousAsset.file.path : undefined;
      const file = fileList.items.find((item) => item.path === previousPath) ?? fileList.items[0];
      if (file) await openFile(site, file, isLive);
    }
    setLoadedAt(new Date());
  }

  useEffect(() => {
    const request = requestedImport.current !== undefined && requestedImport.current.requestId !== handledImport.current ? requestedImport.current : undefined;
    if (!active) { if (request !== undefined) { handledImport.current = request.requestId; onImportRequestConsumed(request.requestId); } return; }
    if (request?.snapshot && importFormPending.current) { handledImport.current = request.requestId; onImportRequestConsumed(request.requestId); setError("An import ZIP or target form is already pending. Open Import native ZIP in Websites and choose Cancel import to discard it, then select the snapshot again in Backups. Your editor draft is kept."); return; }
    let live = true, csrf: string | undefined, inventoryCount = 0;
    const authGeneration = authEpoch.current;
    let listForImport: Site[] = [];
    if (request !== undefined) { handledImport.current = request.requestId; setDiscardDraftForImport(false); setNotice(undefined); setImportOpen(false); }
    const isLive = () => live && activeRef.current && authGeneration === authEpoch.current && (csrf === undefined || (sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === csrf && Date.parse(sessionRef.current.expires_at) > Date.now()));
    setBusy("Loading websites");
    setError(undefined);
    (async () => {
      try {
        const nextSession = await siteRequest("/api/v1/session", validSession, { unauthenticatedSession: true });
        if (!isLive()) return;
        sessionRef.current = nextSession; setSession(nextSession);
        if (nextSession.authenticated) {
          csrf = nextSession.csrf_token;
          if (!isLive()) return;
          const list = await siteRequest("/api/v1/sites", validSiteList);
          if (!isLive()) return;
          inventoryCount = list.items.length; listForImport = list.items; setSites(list.items);
          setInventoryLoaded(true);
          const previous = latestSelected.current;
          const draft = latestEditor.current;
          if (request === undefined && previous && draft && (draft.isNew || draft.draft !== draft.savedContent) && !list.items.some((s) => s.id === previous.id)) throw new SiteApiError(404, "not_found", "The selected website is no longer in the inventory. Your draft is kept.");
          const chosen = list.items.find((s) => s.id === previous?.id) ?? list.items[0];
          if (request === undefined && chosen) await loadSite(chosen.id, Boolean(draft && (draft.isNew || draft.draft !== draft.savedContent)), isLive);
          else if (request === undefined && (!draft || (!draft.isNew && draft.draft === draft.savedContent))) { setSelected(undefined); setFiles([]); setBackups([]); setEditor(undefined); clearAsset(); }
        }
        if (!isLive()) return;
        setLoadedAt(new Date());
        if (request !== undefined && nextSession.authenticated) {
          if (importPending.current || domainPending.current || namePending.current) throw new SiteApiError(409, "operation_pending", "The previous operation is still settling. Open Import native ZIP again after it completes.");
          if (inventoryCount >= 100) throw new SiteApiError(422, "capacity", "The website inventory is full. A ZIP import creates a new website.");
          if (request.snapshot) {
            setBusy("Verifying saved snapshot");
            const prepared = await prepareBackupCopy(request.snapshot, listForImport, isLive);
            if (!isLive()) return;
            setPreparedCopy(prepared); setImportArchive(prepared.archive); setImportName(""); setImportDomain("");
          }
          setCreateOpen(false); setDomainTarget(undefined); closeName(); setImportOpen(true);
        }
      } catch (failure) { if (isLive()) fail(failure); }
      finally { if (live && activeRef.current) setBusy(undefined); if (request !== undefined) onImportRequestConsumed(request.requestId); }
    })();
    return () => { live = false; };
  }, [revision, active, fail, sessionAttempt, importRequestId, onImportRequestConsumed]);

  useEffect(() => { ++fileReadEpoch.current; if (!authenticated) clearAsset(); }, [active, authenticated, session?.authenticated ? session.csrf_token : undefined, clearAsset]);
  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => { if (!active) setAccessKey(""); }, [active]);
  useEffect(() => {
    if (active && authenticated) return;
    for (const ref of [createDialog, importDialog, domainDialog, removeDialog, nameDialog]) if (ref.current?.open) ref.current.close();
    setCreateOpen(false); setImportOpen(false);
    if (!authenticated) { clearImportForm(); }
    dialogReturnFocus.current = null;
  }, [active, authenticated, clearImportForm]);
  useEffect(() => {
    ++removeGeneration.current;
    setRemoveTarget(undefined); setRemoveDomain(""); setRemoveNeedsRefresh(false);
    setBusy((current) => current === "Removing website" || current === "Refreshing removal details" ? undefined : current);
  }, [active, authenticated, selected?.id, session?.authenticated ? session.csrf_token : undefined, revision]);
  useEffect(() => {
    if (active && authenticated && removeTarget && removeDialog.current && !removeDialog.current.open) removeDialog.current.showModal();
    else if (!removeTarget && removeDialog.current?.open) removeDialog.current.close();
  }, [removeTarget, active, authenticated]);
  useEffect(() => {
    ++domainGeneration.current;
    if (!active || !authenticated || domainTarget?.id !== selected?.id) { setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false); }
  }, [active, authenticated, selected?.id, session?.authenticated ? session.csrf_token : undefined, revision]);
  useEffect(() => {
    if (active && authenticated && domainTarget && domainDialog.current && !domainDialog.current.open) domainDialog.current.showModal();
    else if (!domainTarget && domainDialog.current?.open) domainDialog.current.close();
  }, [domainTarget, active, authenticated]);
  useEffect(() => {
    ++nameGeneration.current;
    setNameTarget(undefined); setNextName(""); setNameNeedsRefresh(false);
    setBusy((current) => current === "Saving website name" || current === "Refreshing name revision" ? undefined : current);
  }, [active, authenticated, selected?.id, session?.authenticated ? session.csrf_token : undefined, revision, importRequestId]);
  useEffect(() => {
    if (active && authenticated && nameTarget && nameDialog.current && !nameDialog.current.open) nameDialog.current.showModal();
    else if (!nameTarget && nameDialog.current?.open) nameDialog.current.close();
  }, [nameTarget, active, authenticated]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); setNotice(undefined); setError("Your operator session expired. Sign in again; your editor draft is kept."); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session]);
  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
  useEffect(() => {
    ++importGeneration.current; setImportOpen(false); setDiscardDraftForImport(false);
    if (preparedCopy) clearImportForm();
    setBusy((current) => current === "Importing native ZIP" ? undefined : current);
  }, [active, authenticated, session?.authenticated ? session.csrf_token : undefined, revision, clearImportForm]);
  useEffect(() => {
    if (active && authenticated && importOpen && importDialog.current && !importDialog.current.open) importDialog.current.showModal();
    else if (!importOpen && importDialog.current?.open) importDialog.current.close();
  }, [importOpen, active, authenticated]);
  useEffect(() => {
    if (active && authenticated && createOpen && createDialog.current && !createDialog.current.open) createDialog.current.showModal();
    else if (!createOpen && createDialog.current?.open) createDialog.current.close();
  }, [createOpen, active, authenticated]);
  useEffect(() => {
    if (active && authenticated && !busy && !createOpen && !importOpen && !domainTarget && !removeTarget && !nameTarget && dialogReturnFocus.current) {
      if (dialogReturnFocus.current.isConnected) dialogReturnFocus.current.focus();
      dialogReturnFocus.current = null;
    }
  }, [active, authenticated, busy, createOpen, importOpen, domainTarget, removeTarget, nameTarget]);
  const rememberDialogTrigger = () => { dialogReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; };

  async function run(label: string, action: () => Promise<void>) {
    if (busy) return;
    setBusy(label); setError(undefined); setNotice(undefined);
    try { await action(); setLoadedAt(new Date()); } catch (failure) { fail(failure); }
    finally { setBusy(undefined); }
  }
  const requireClean = () => {
    if (!dirty) return true;
    setError("Save or discard your editor draft before switching websites, creating a website, changing its name, domain or state, restoring or signing out.");
    return false;
  };
  async function removeWebsite(refresh = false) {
    if (!removeTarget || !session?.authenticated || busy || removePending.current || !active || !requireClean() || (!refresh && !removeReady)) return;
    const target = removeTarget, csrf = session.csrf_token, generation = removeGeneration.current;
    const isLive = () => activeRef.current && generation === removeGeneration.current && latestSelected.current?.id === target.id && sessionRef.current?.authenticated && sessionRef.current.csrf_token === csrf && Date.parse(sessionRef.current.expires_at) > Date.now();
    removePending.current = true; setBusy(refresh ? "Refreshing removal details" : "Removing website"); setError(undefined); setNotice(undefined);
    try {
      if (refresh) {
        const site = await siteRequest(siteURL(target.id), validSite);
        if (!isLive()) return;
        if (site.id !== target.id || site.revision < target.revision) throw new SiteApiError(0, "invalid_response", "Removal details did not match the selected website. Refresh records before continuing.");
        updateSite(site); latestSelected.current = site; setRemoveTarget(site); setRemoveDomain(""); setRemoveNeedsRefresh(site.state === "recovery_required");
        if (site.state !== "recovery_required") uncertainRemovals.current.delete(target.id);
      } else {
        const validRemoval = (value: unknown): value is { id: string; domain: string; revision: number; removed: true } => {
          if (!value || typeof value !== "object") return false;
          const result = value as Record<string, unknown>;
          return result.id === target.id && result.domain === target.domain && result.revision === target.revision && result.removed === true;
        };
        await siteRequest(siteURL(target.id), validRemoval, { method: "DELETE", csrf, body: { expected_revision: target.revision, confirmation_domain: removeDomain, confirmed: true } });
        if (!isLive()) return;
        ++fileReadEpoch.current;
        setSites((old) => old.filter((site) => site.id !== target.id));
        setSelected(undefined); latestSelected.current = undefined; setEditor(undefined); latestEditor.current = undefined;
        setFiles([]); setBackups([]); clearAsset(); setConflict(undefined); setRemoveTarget(undefined); setRemoveDomain(""); setRemoveNeedsRefresh(false);
        setNotice(`Removed ${target.domain}, its static files, native ZIP backups, schedule and local routing.`);
      }
      setLoadedAt(new Date());
    } catch (failure) {
      uncertainRemovals.current.add(target.id);
      if (isLive()) { setRemoveNeedsRefresh(true); fail(failure); }
    } finally { removePending.current = false; if (generation === removeGeneration.current) setBusy(undefined); }
  }
  function closeName() {
    ++nameGeneration.current;
    setNameTarget(undefined); setNextName(""); setNameNeedsRefresh(false);
    setBusy((current) => current === "Saving website name" || current === "Refreshing name revision" ? undefined : current);
  }
  async function changeName(refresh = false) {
    if (!nameTarget || !session?.authenticated || busy || namePending.current || !active || !requireClean() || (!refresh && !nameReady)) return;
    const target = nameTarget, requested = nextName.trim(), csrf = session.csrf_token, generation = nameGeneration.current, authGeneration = authEpoch.current, observedRevision = latestSelected.current?.revision;
    const contextLive = () => activeRef.current && generation === nameGeneration.current && authGeneration === authEpoch.current && latestSelected.current?.id === target.id && sessionRef.current?.authenticated && sessionRef.current.csrf_token === csrf && Date.parse(sessionRef.current.expires_at) > Date.now();
    const isLive = () => contextLive() && latestSelected.current?.revision === observedRevision;
    namePending.current = true; setNameSettling(true); setBusy(refresh ? "Refreshing name revision" : "Saving website name"); setError(undefined); setNotice(undefined);
    try {
      const site = refresh ? await siteRequest(siteURL(target.id), validSite) : await siteRequest(siteURL(target.id, "/name"), validSite, { method: "PUT", csrf, body: { name: requested, expected_revision: target.revision } });
      if (!isLive()) return;
      const expectedRevision = target.revision + (requested === target.name ? 0 : 1);
      if (site.id !== target.id || site.revision < target.revision || site.revision < (observedRevision ?? 0) || (refresh && site.revision < 1) || (!refresh && (site.name !== requested || site.revision !== expectedRevision || site.domain !== target.domain || site.preview_host !== target.preview_host || site.state !== target.state || site.created_at !== target.created_at || (site.revision === target.revision && site.updated_at !== target.updated_at)))) throw new SiteApiError(0, "invalid_response", "The name operation did not confirm its website, name and revision. Refresh the name revision before saving again.");
      updateSite(site); latestSelected.current = site; setLoadedAt(new Date());
      if (refresh) { setNameTarget(site); setNameNeedsRefresh(false); }
      else {
        setEditor((previous) => previous && previous.revision === target.revision ? { ...previous, revision: site.revision } : previous);
        setNotice(site.revision === target.revision ? `Website name already ${site.name} · revision ${site.revision} unchanged.` : `Website name changed to ${site.name} · revision ${site.revision}.`);
        closeName();
      }
    } catch (failure) {
      if (isLive()) { setNameNeedsRefresh(true); fail(failure); }
    } finally {
      namePending.current = false; setNameSettling(false);
      if (contextLive()) setBusy(undefined);
    }
  }
  async function changeDomain(refresh = false) {
    if (!domainTarget || !session?.authenticated || busy || domainPending.current || !active || !requireClean() || (!refresh && !domainReady)) return;
    const target = domainTarget, requested = nextDomain.trim(), csrf = session.csrf_token, generation = domainGeneration.current;
    const isLive = () => activeRef.current && generation === domainGeneration.current && latestSelected.current?.id === target.id && sessionRef.current?.authenticated && sessionRef.current.csrf_token === csrf;
    domainPending.current = true; setBusy(refresh ? "Refreshing domain revision" : "Changing website domain"); setError(undefined); setNotice(undefined);
    try {
      const site = refresh ? await siteRequest(siteURL(target.id), validSite) : await siteRequest(siteURL(target.id, "/domain"), validSite, { method: "PUT", csrf, body: { domain: requested, expected_revision: target.revision } });
      if (!isLive()) return;
      if (site.id !== target.id || site.revision < target.revision || (!refresh && site.revision !== target.revision && site.revision !== target.revision + 1) || (!refresh && site.revision === target.revision && site.domain !== target.domain)) throw new SiteApiError(0, "invalid_response", "The domain operation did not confirm its website and revision. Refresh records before retrying.");
      updateSite(site); latestSelected.current = site; setLoadedAt(new Date());
      if (refresh) { setDomainTarget(site); setDomainNeedsRefresh(false); }
      else {
        setEditor((previous) => previous && previous.revision === target.revision ? { ...previous, revision: site.revision } : previous);
        setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false);
        setNotice(site.revision === target.revision ? `Domain already ${site.domain} · revision ${site.revision} unchanged.` : `Local routing changed from ${target.domain} to ${site.domain} · revision ${site.revision}. DNS and TLS were not changed.`);
      }
    } catch (failure) { if (isLive()) { if (failure instanceof SiteApiError && failure.status === 409) setDomainNeedsRefresh(true); fail(failure); } }
    finally { domainPending.current = false; if (isLive()) setBusy(undefined); }
  }
  async function login(event: React.FormEvent) {
    event.preventDefault();
    if (busy || !accessKey.trim()) return;
    const key = accessKey;
    setAccessKey("");
    await run("Signing in", async () => {
      const next = await siteRequest("/api/v1/session/login", validSession, { method: "POST", body: { access_key: key } });
      if (!next.authenticated) throw new SiteApiError(401, "unauthorized", "The operator access key was not accepted.");
      setSession(next);
      const list = await siteRequest("/api/v1/sites", validSiteList);
      setSites(list.items);
      setInventoryLoaded(true);
      if (dirty && latestSelected.current && !list.items.some((s) => s.id === latestSelected.current?.id)) throw new SiteApiError(404, "not_found", "The selected website is no longer in the inventory. Your draft is kept.");
      const chosen = list.items.find((s) => s.id === latestSelected.current?.id) ?? list.items[0];
      if (chosen) await loadSite(chosen.id, dirty);
    });
  }
  async function create(event: React.FormEvent) {
    event.preventDefault();
    if (busy || !active) return;
    if (nameBytes > 80) { setError("The website name must fit within 80 UTF-8 bytes."); return; }
    if (domain.trim().length > 253 || domainBytes > 253) { setError("The domain must fit within 253 UTF-8 bytes."); return; }
    if (!session?.authenticated || !requireClean()) return;
    await run("Creating website", async () => {
      const site = await siteRequest("/api/v1/sites", validSite, { method: "POST", csrf: session.csrf_token, body: { name: name.trim(), domain: domain.trim() } });
      updateSite(site); setEditor(undefined); latestEditor.current = undefined;
      await loadSite(site.id);
      setName(""); setDomain(""); setCreateOpen(false); setSection("files");
      setNotice(`Created ${site.name}.`);
    });
  }
  async function exportBackup(site: Site, backup: SiteBackup) {
    await run("Downloading ZIP backup", async () => {
      const archive = await downloadSiteBackup(site.id, backup.id, backup.sha256);
      const url = URL.createObjectURL(archive);
      const link = document.createElement("a");
      link.href = url;
      link.download = "sifruno-site.zip";
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice(`Downloaded ZIP backup from ${site.name}.`);
    });
  }
  async function submitImportArchive(event: React.FormEvent) {
    event.preventDefault();
    if (!activeRef.current || !importOpen || importPending.current || !session?.authenticated || busy || Date.parse(session.expires_at) <= Date.now()) return;
    if (dirty && !discardDraftForImport) { setError("Save or explicitly discard your editor draft before importing a website."); return; }
    if (importNameBytes > 80) { setError("The website name must fit within 80 UTF-8 bytes."); return; }
    if (importDomainLength > 253 || importDomainBytes > 253) { setError("The domain must fit within 253 UTF-8 bytes."); return; }
    if (!importArchive || importArchive.size === 0 || importArchive.size > maxTransferArchive) { setError("Choose a nonempty native Sifruno ZIP archive up to 34 MiB."); return; }
    const csrf = session.csrf_token, generation = importGeneration.current;
    const isLive = () => activeRef.current && generation === importGeneration.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === csrf && Date.parse(sessionRef.current.expires_at) > Date.now();
    importPending.current = true; setBusy("Importing native ZIP"); setError(undefined); setNotice(undefined);
    try {
      const site = await importSiteArchive({ name: importName.trim(), domain: importDomain.trim(), archive: importArchive, csrf });
      if (!isLive()) return;
      if (sites.some(existing => existing.id === site.id) || (preparedCopy && site.id === preparedCopy.site.id)) throw new SiteApiError(0, "invalid_response", "The import did not acknowledge a new website identity. Your editor draft, selected ZIP and inputs are kept. Refresh records before retrying.");
      if (dirty) { setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); }
      updateSite(site);
      setImportOpen(false); clearImportForm();
      setSection("files"); setNotice(`Imported native Sifruno ZIP as new website ${site.name}.`);
      await loadSite(site.id, false, isLive);
      if (isLive()) setLoadedAt(new Date());
    } catch (failure) {
      if (isLive()) fail(failure instanceof SiteApiError && failure.status === 409
        ? new SiteApiError(failure.status, failure.code, "The import conflicts with the current website inventory. Choose an available domain and try again. Your selected ZIP and inputs are kept.")
        : failure);
    }
    finally { importPending.current = false; if (isLive()) setBusy(undefined); }
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!session?.authenticated || !selected || !editor) return;
    await run("Saving file", async () => {
      try {
        const site = await siteRequest(siteURL(selected.id, "/file"), validSite, { method: "PUT", csrf: session.csrf_token, body: { path: editor.path, content: editor.draft, expected_sha256: editor.sha256, expected_revision: editor.revision } });
        updateSite(site);
        const [actual, fileList] = await Promise.all([readFile(site, editor.path), siteRequest(siteURL(site.id, "/files"), validFileList)]);
        setEditor(fromFile(actual)); setFiles(fileList.items); setConflict(undefined);
        setNotice(`Saved ${actual.path}.`);
      } catch (failure) {
        if (failure instanceof SiteApiError && failure.status === 409) {
          try {
            const site = await siteRequest(siteURL(selected.id), validSite);
            updateSite(site);
            const fileList = await siteRequest(siteURL(site.id, "/files"), validFileList);
            setFiles(fileList.items);
            const actual = fileList.items.some((file) => file.path === editor.path) ? await readFile(site, editor.path) : undefined;
            setConflict({ revision: actual?.revision ?? site.revision, file: actual });
          } catch { /* Keep the original draft and useful conflict response. */ }
        }
        throw failure;
      }
    });
  }
  const filtered = sites.filter((s) => `${s.name} ${s.domain}`.toLowerCase().includes(query.toLowerCase().trim()));
  const stateCounts = (state: Site["state"]) => sites.filter((site) => site.state === state).length;

  return <section data-testid="websites-view" className="@container flex min-w-0 flex-col gap-3">
    {error && !domainTarget && !nameTarget && !importOpen && <Alert variant="destructive" className="text-start"><CircleAlert aria-hidden="true" /><AlertTitle className="wrap-anywhere">{error}</AlertTitle></Alert>}
    {notice && <Alert role="status" className="text-start"><Check className="text-primary" aria-hidden="true" /><AlertTitle className="wrap-anywhere">{notice}</AlertTitle></Alert>}
    {!session ? <section className={cn(panel, "max-w-xl p-5")} aria-label="Operator session">
      <div role="status" className="text-sm text-foreground">{busy || (error ? "Operator session could not be checked." : "Checking operator session…")}</div>
      {error && <Button variant="outline" className={cn("mt-3 h-9", touch)} disabled={Boolean(busy)} onClick={() => setSessionAttempt((attempt) => attempt + 1)}><RefreshCw aria-hidden="true" />Retry operator session</Button>}
    </section> : !authenticated ? <section className={cn(panel, "max-w-xl p-5")} aria-labelledby="websites-sign-in-heading">
      <div className="flex items-start gap-3.5">
        <LockKeyhole className="size-6 shrink-0 text-primary" aria-hidden="true" />
        <div className="min-w-0"><h2 id="websites-sign-in-heading">Local operator sign-in</h2><div className="mt-1.5 text-sm text-muted-foreground wrap-anywhere">Use the access key created by this server in its private state directory.</div></div>
      </div>
      <form onSubmit={login} data-testid="operator-login" autoComplete="off" className="mt-6 flex flex-col items-start gap-2.5">
        <label htmlFor="operator-access-key" className={fieldLabel}>Operator access key</label>
        <Input id="operator-access-key" type="password" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} required autoComplete="off" spellCheck={false} disabled={Boolean(busy)} className={cn("max-w-sm", input)} />
        <Button type="submit" className={cn("mt-1 h-9", touch)} disabled={Boolean(busy) || !accessKey.trim()}>{busy === "Signing in" && spinner}Sign in locally</Button>
      </form>
      <div className="mt-5 text-xs text-muted-foreground">The key is cleared after submission. Overview stays available without sign-in. This operator session is local; production roles and remote authentication are not qualified yet.</div>
    </section> : <>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span className="flex min-w-0 flex-1 basis-56 items-center gap-2 wrap-anywhere"><LockKeyhole className="size-4 shrink-0" aria-hidden="true" />Signed in locally · expires {dateLabel(session.expires_at)}</span>
        <Button variant="ghost" size="sm" className={touch} disabled={Boolean(busy)} onClick={() => { if (!requireClean()) return; void run("Signing out", async () => {
          const next = await siteRequest("/api/v1/session/logout", validSession, { method: "POST", csrf: session.csrf_token, body: {} });
          if (next.authenticated) throw new SiteApiError(0, "invalid_response", "Sign-out was not confirmed.");
          setSession(next); setSites([]); setInventoryLoaded(false); setSelected(undefined); setFiles([]); setBackups([]); setEditor(undefined); clearAsset(); setConflict(undefined);
        }); }}><LogOut aria-hidden="true" />Sign out locally</Button>
      </div>
      <section className={cn(panel, "flex flex-wrap items-center justify-between gap-x-5 gap-y-3 px-4 py-3.5")} aria-labelledby="websites-inventory-heading">
        <div className="min-w-0">
          <h2 id="websites-inventory-heading" className="text-sm!">Website inventory</h2>
          <div className="mt-1 text-xs text-muted-foreground">{inventoryLoaded ? <><strong className="font-semibold text-foreground">{sites.length}</strong> {sites.length === 1 ? "website" : "websites"}<span> · {stateCounts("active")} active · {stateCounts("suspended")} suspended{stateCounts("recovery_required") > 0 && <> · {stateCounts("recovery_required")} need recovery</>}</span></> : busy ? "Loading inventory…" : "Inventory could not be loaded. Refresh to try again."}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="ghost" size="sm" className={touch} disabled={Boolean(busy)} onClick={() => setSessionAttempt((attempt) => attempt + 1)}><RefreshCw aria-hidden="true" />Refresh websites</Button>
          <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || sites.length >= 100} onClick={() => { rememberDialogTrigger(); setDiscardDraftForImport(false); setError(undefined); setImportOpen(true); }}><Upload aria-hidden="true" />Import native ZIP</Button>
          <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || dirty || sites.length >= 100} onClick={() => { if (!requireClean()) return; rememberDialogTrigger(); setError(undefined); setCreateOpen(true); }}><Plus aria-hidden="true" />Create website</Button>
          {/* Base link styles inherit colour, so the primary text colour is marked important;
              text-sm font-normal match the buttons, whose font the base styles inherit. */}
          <Link to="/websites/new" className={buttonVariants({ size: "sm", className: cn("text-sm font-normal text-primary-foreground!", touch) })} data-testid="new-website-link"><Plus aria-hidden="true" />New website</Link>
        </div>
      </section>
      <div className="flex items-start gap-2 text-xs text-muted-foreground"><Info className="mt-px size-4 shrink-0" aria-hidden="true" /><span className="wrap-anywhere">Static websites and native site ZIPs · local HTTP preview. DNS, TLS, PHP, mail and databases are unavailable.</span></div>
      {dirty && <div className="flex items-start gap-2 border-s-2 border-primary bg-secondary px-3 py-2 text-xs text-foreground" role="status"><Save className="mt-px size-4 shrink-0" aria-hidden="true" /><span className="wrap-anywhere">Unsaved file draft kept. You can switch between Files and ZIP backups; save or discard before changing websites or their state.</span></div>}
      {sites.length >= 100 && <div className="text-xs text-muted-foreground">This local inventory has reached its 100-website limit.</div>}
      <div className="grid min-w-0 grid-cols-1 items-start gap-3 @4xl:grid-cols-[minmax(14.5rem,17.5rem)_minmax(0,1fr)]">
        <section className={cn(panel, "min-w-0")} aria-labelledby="websites-list-heading">
          <div className="flex items-center justify-between gap-3 p-3"><h2 id="websites-list-heading" className="text-sm!">Websites</h2>{inventoryLoaded && <span className="text-xs text-muted-foreground tabular-nums">{filtered.length}{query.trim() && <> of {sites.length}</>}</span>}</div>
          <div className="relative mx-3 mb-2">
            <Search className="pointer-events-none absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input type="search" name="website-search" autoComplete="off" spellCheck={false} aria-label="Search websites" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Name or domain…" className="ps-8 pointer-coarse:h-11!" />
          </div>
          {/* Rows sit in a scrolling list, so their focus outline is drawn inside them. */}
          <div className="grid max-h-130 grid-cols-1 gap-0.5 overflow-y-auto px-1.5 pb-1.5 @max-4xl:max-h-56 @lg:@max-4xl:grid-cols-2">{filtered.map((site) => <button key={site.id} type="button" className="grid w-full grid-cols-[1rem_minmax(0,1fr)_auto] items-start gap-x-2.5 rounded-md border-s-2 border-transparent p-2.5 text-start text-sm text-foreground focus-visible:-outline-offset-2! enabled:hover:bg-muted disabled:cursor-default aria-[current=true]:border-primary aria-[current=true]:bg-secondary" aria-label={`Open website ${site.name}`} aria-current={selected?.id === site.id ? "true" : undefined} disabled={Boolean(busy)} onClick={() => { if (site.id === selected?.id || !requireClean()) return; void run("Loading website", () => loadSite(site.id)); }}>
            <Globe className="mt-0.5 size-4 text-muted-foreground" aria-hidden="true" />
            <span className="min-w-0"><strong className="block font-medium wrap-anywhere">{site.name}</strong><span className="mt-0.5 block text-xs text-muted-foreground wrap-anywhere">{site.domain}</span></span>
            <SiteState state={site.state} className="mt-0.5" />
          </button>)}{!filtered.length && <div className="col-span-full p-2.5 text-sm text-muted-foreground">{!inventoryLoaded ? <div>{busy ? "Loading website records…" : "Website inventory is unavailable. Use Refresh websites to retry."}</div> : sites.length ? <><div>No matching websites.</div><Button variant="link" size="sm" className="mt-1 h-auto px-0" onClick={() => setQuery("")}>Clear search</Button></> : <div>No websites yet. Create a website or import a native site ZIP to get started.</div>}</div>}</div>
        </section>
        {selected ? <div className="@container flex min-w-0 flex-col gap-3">
          <section className={cn(panel, "min-w-0")} data-testid="website-details" data-site-id={selected.id} data-revision={selected.revision} aria-labelledby="website-selected-heading">
            <div className="flex items-start justify-between gap-3 px-4 pt-3.5 pb-3">
              <div className="min-w-0"><div className="mb-0.5 text-xs text-muted-foreground">Selected website</div><h2 id="website-selected-heading" className="wrap-anywhere">{selected.name}</h2><div className="mt-0.5 text-sm text-muted-foreground wrap-anywhere">{selected.domain}</div></div>
              <SiteState state={selected.state} />
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 px-4 pb-3">
              <Fact label="Created">{dateLabel(selected.created_at)}</Fact>
              <Fact label="Updated">{dateLabel(selected.updated_at)}</Fact>
            </dl>
            <div className="flex flex-wrap items-center gap-2 px-4 pb-2">
              {selected.state === "active" && previewPort && previewURL(selected) ? <a href={previewURL(selected)} target="_blank" rel="noopener noreferrer" className={buttonVariants({ variant: "outline", size: "sm", className: cn("text-sm font-normal", touch) })}><ArrowUpRight className="rtl:-scale-x-100" aria-hidden="true" />Local HTTP preview</a> : <Button variant="outline" size="sm" className={touch} disabled><ArrowUpRight className="rtl:-scale-x-100" aria-hidden="true" />Local HTTP preview</Button>}
              <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || !active || !authenticated} onClick={() => onOpenSiteTool("files", selected.id, selected.name)}><Folder aria-hidden="true" />Open File Manager</Button>
              <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || !active || !authenticated} onClick={() => onOpenSiteTool("backups", selected.id, selected.name)}><Archive aria-hidden="true" />Open Backups</Button>
            </div>
            <div className="px-4 pb-3 text-xs text-muted-foreground wrap-anywhere">{previewPort ? <>Preview serves the site's actual files at {selected.preview_host}:{previewPort} using local HTTP.</> : "Preview serving is disabled in this local runtime."}</div>
            <div className="flex flex-wrap items-center gap-2 border-t border-border px-4 py-3">
              <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || nameSettling || dirty || Boolean(conflict) || !editable || !active} onClick={() => { if (!active || !session.authenticated || namePending.current || !requireClean()) return; rememberDialogTrigger(); ++nameGeneration.current; setError(undefined); setNameTarget(selected); setNextName(selected.name); setNameNeedsRefresh(false); }}>Edit website name</Button>
              <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || dirty || Boolean(conflict) || !editable} onClick={() => { if (!requireClean()) return; rememberDialogTrigger(); setError(undefined); setDomainTarget(selected); setNextDomain(selected.domain); setDomainNeedsRefresh(false); }}><Globe aria-hidden="true" />Change domain</Button>
              <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || dirty || !editable} onClick={() => { if (!session.authenticated || !requireClean()) return; void run("Changing website state", async () => { const site = await siteRequest(siteURL(selected.id, "/state"), validSite, { method: "POST", csrf: session.csrf_token, body: { state: selected.state === "suspended" ? "active" : "suspended", expected_revision: selected.revision } }); updateSite(site); await loadSite(site.id); setNotice(`Website is ${site.state}.`); }); }}>{selected.state === "suspended" ? "Resume website" : "Suspend website"}</Button>
              <Button variant="destructive" size="sm" className={touch} data-testid="website-remove-open" disabled={Boolean(busy) || removePending.current || dirty || Boolean(conflict) || !editable} onClick={() => { if (!requireClean()) return; rememberDialogTrigger(); setError(undefined); setNotice(undefined); setRemoveTarget({ ...selected }); setRemoveDomain(""); setRemoveNeedsRefresh(uncertainRemovals.current.has(selected.id)); }}>Remove website</Button>
            </div>
            {dirty && <div className="px-4 pb-3 text-xs text-muted-foreground">Save or discard your editor draft before removing this website.</div>}
            <div className="px-4 pb-4"><TechnicalDetails>Revision {selected.revision}</TechnicalDetails></div>
            {selected.state === "recovery_required" && <div className="px-4 pb-4"><Alert variant="destructive" className="text-start"><CircleAlert aria-hidden="true" /><AlertTitle>This website needs recovery</AlertTitle><AlertDescription className="text-start">This website requires scoped recovery. Serving and managed changes are disabled until its recovery is resolved.</AlertDescription></Alert></div>}
          </section>
          <div className="flex flex-wrap items-center justify-between gap-2"><Segments label="Website section" value={section} onChange={setSection} options={[{ value: "files", label: "Files" }, { value: "backups", label: "ZIP backups" }]} /><span className="ms-auto text-xs text-muted-foreground tabular-nums">{section === "files" ? `${files.length} files` : `${backups.length} ZIP backups`}</span></div>
          <div className="min-w-0" hidden={section !== "files"}>
          <section className={cn(panel, "min-w-0")} aria-labelledby="website-files-heading">
            <div className="flex flex-wrap items-center justify-between gap-2.5 px-3.5 py-3"><h2 id="website-files-heading" className="flex items-center gap-2 text-sm!"><Folder className="size-4" aria-hidden="true" />Files</h2><Button variant="ghost" size="sm" className={touch} disabled={Boolean(busy) || dirty || !editable || files.length >= 64} onClick={() => { if (!requireClean()) return; clearAsset(); setEditor({ path: "", draft: "", savedContent: "", sha256: "", revision: selected.revision, isNew: true }); setConflict(undefined); setError(undefined); }}><FilePlus aria-hidden="true" />Add text file</Button></div>
            <div className="max-h-45 overflow-y-auto px-2 pb-2">{files.map((file) => <button key={file.path} type="button" className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-start text-sm text-foreground focus-visible:-outline-offset-2! enabled:hover:bg-muted disabled:cursor-default aria-pressed:bg-secondary aria-pressed:text-primary" aria-label={`View file ${file.path}`} aria-pressed={(editor?.path === file.path && !editor.isNew) || (asset?.siteId === selected.id && asset.file.path === file.path)} disabled={Boolean(busy)} onClick={() => { if ((editor?.path === file.path && !editor.isNew) || (asset?.siteId === selected.id && asset.file.path === file.path)) return; if (!requireClean()) return; void run("Reading file", () => openFile(selected, file)); }}><File className="size-3.5 shrink-0" aria-hidden="true" /><span className="min-w-0 wrap-anywhere">{file.path}</span><span className="ms-auto shrink-0 text-xs text-muted-foreground">{bytes(file.bytes)}</span></button>)}{!files.length && <div className="p-2 text-sm text-muted-foreground">No files returned for this website.</div>}</div>
            {asset && asset.siteId === selected.id && <section className="flex flex-col gap-3 border-t border-border p-4" data-testid="website-asset-details" data-site-id={asset.siteId} data-file-path={asset.file.path} data-revision={asset.revision} aria-label="Saved asset details">
              <h3>Saved asset</h3>
              <div className="text-sm text-muted-foreground">This file is not readable as UTF-8 text. Its saved bytes remain available for preview and File Manager.</div>
              <dl className="grid grid-cols-1 gap-3 @lg:grid-cols-2"><Fact label="Relative path">{asset.file.path}</Fact><Fact label="Saved bytes">{bytes(asset.file.bytes)}</Fact></dl>
              <TechnicalDetails>Inventory revision {asset.revision}{"\n"}SHA-256 {asset.file.sha256}</TechnicalDetails>
              <div className="text-xs text-muted-foreground">Use Open File Manager above to replace or delete this asset.</div>
            </section>}
            {editor && <form className="flex flex-col gap-3 border-t border-border px-3.5 py-3" onSubmit={save} data-testid="website-editor">
              {editor.isNew ? <div className={field}><label htmlFor="new-file-path" className={fieldLabel}>Relative file path</label><Input id="new-file-path" value={editor.path} onChange={(e) => { setEditor({ ...editor, path: e.target.value }); setConflict(undefined); }} placeholder="assets/style.css" required disabled={Boolean(busy)} autoComplete="off" spellCheck={false} className={input} /><div className={muted}>New UTF-8 text file. Use a relative static-file path; PHP, private and source files are rejected.</div></div> : <label htmlFor="site-file-content" className="text-sm font-medium text-foreground wrap-anywhere">{editor.path}</label>}
              <textarea id="site-file-content" aria-label="File content" dir="ltr" value={editor.draft} onChange={(e) => setEditor({ ...editor, draft: e.target.value })} spellCheck={false} disabled={Boolean(busy) || !editable} className="block h-70 min-h-60 w-full min-w-0 resize-y rounded-lg border border-input bg-card px-2.5 py-2 text-start font-mono text-xs leading-relaxed text-foreground [tab-size:2] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary disabled:opacity-65" />
              <div className="flex flex-wrap items-center justify-between gap-3"><span className="text-xs text-muted-foreground">{bytes(new TextEncoder().encode(editor.draft).length)} / 2 MiB · {dirty ? "Unsaved draft" : "Saved version"}</span><div className="ms-auto flex items-center gap-2"><Button variant="ghost" size="sm" className={touch} disabled={Boolean(busy) || !dirty} onClick={() => { if (editor.isNew) { setEditor(undefined); setConflict(undefined); setError(undefined); } else void run("Reading saved version", async () => { const site = await siteRequest(siteURL(selected.id), validSite); updateSite(site); setEditor(fromFile(await readFile(site, editor.path))); setConflict(undefined); }); }}>Discard draft</Button><Button type="submit" size="sm" className={touch} disabled={Boolean(busy) || !dirty || !editor.path || !editable || new TextEncoder().encode(editor.draft).length > 2 * 1024 * 1024}>{busy === "Saving file" ? spinner : <Save aria-hidden="true" />}Save file</Button></div></div>
              {!editor.isNew && <TechnicalDetails>Read revision {editor.revision}</TechnicalDetails>}
              {conflict && <div className="flex flex-col items-start gap-2.5 rounded-lg border border-input bg-muted p-3.5" role="status">
                <h3>Draft kept: the website changed after this file was read</h3>
                <div className="text-sm text-foreground wrap-anywhere">{conflict.file ? "Compare the server content below." : "No file exists at this path in the latest inventory."} Updating the revision keeps your draft; Save remains an explicit action.</div>
                {conflict.file && <details className="w-full text-sm"><summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Compare latest server content</summary><pre dir="ltr" className="mt-2 max-h-60 overflow-auto rounded-md border border-border bg-card p-3 text-start font-mono text-xs whitespace-pre-wrap text-foreground wrap-anywhere">{conflict.file.content}</pre></details>}
                <div className="w-full"><TechnicalDetails>Server revision {conflict.revision}{conflict.file && <>{"\n"}SHA-256 {conflict.file.sha256}</>}</TechnicalDetails></div>
                <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy)} onClick={() => { setEditor({ ...editor, savedContent: conflict.file?.content ?? "", sha256: conflict.file?.sha256 ?? "", revision: conflict.revision, isNew: !conflict.file }); setConflict(undefined); setError(undefined); }}>Keep draft and use latest revision</Button>
              </div>}
            </form>}
          </section>
          </div>
          <div className="min-w-0" hidden={section !== "backups"}>
          <section className={cn(panel, "@container min-w-0")} aria-labelledby="website-backups-heading">
            <div className="flex flex-wrap items-start justify-between gap-2.5 px-3.5 py-3"><div className="min-w-0"><h2 id="website-backups-heading" className="flex items-center gap-2 text-sm!"><Archive className="size-4" aria-hidden="true" />ZIP backups</h2><div className="mt-1 text-xs text-muted-foreground">App-owned site files only · {backups.length} recorded</div></div><Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || !editable || dirty} onClick={() => { if (!session.authenticated) return; void run("Creating backup", async () => { const backup = await siteRequest(siteURL(selected.id, "/backups"), validBackup, { method: "POST", csrf: session.csrf_token, body: { expected_revision: selected.revision } }); await loadSite(selected.id); setNotice(`Created ZIP backup with ${backup.files} files.`); }); }}>{busy === "Creating backup" ? spinner : <Archive aria-hidden="true" />}Create ZIP backup</Button></div>
            {!backups.length ? <div className="px-3.5 pb-4 text-sm text-muted-foreground">No ZIP backups recorded. Create a backup of this site's current files.</div> : <ul className="m-0 list-none px-3.5 pb-1.5" aria-label="ZIP backups">{backups.map((backup) => <li key={backup.id} className="flex flex-col gap-2 border-t border-border py-3 @xl:flex-row @xl:items-start @xl:justify-between">
              <div className="min-w-0 flex-1"><strong className="text-sm font-medium text-foreground">{dateLabel(backup.created_at)}</strong><div className="mt-0.5 mb-1.5 text-xs text-muted-foreground">{backup.files} files · {bytes(backup.bytes)}</div><TechnicalDetails>Revision {backup.revision}{"\n"}SHA-256 {backup.sha256}</TechnicalDetails></div>
              <div className="flex shrink-0 flex-wrap gap-1.5"><Button variant="ghost" size="sm" className={touch} disabled={Boolean(busy) || !authenticated} onClick={() => { if (authenticated) void exportBackup(selected, backup); }}>{busy === "Downloading ZIP backup" ? spinner : <ArrowDownToLine aria-hidden="true" />}Download ZIP<span className="sr-only"> backup {backup.id}</span></Button><Button variant="outline" size="sm" className={touch} data-testid="website-restore-review" data-backup-id={backup.id} disabled={Boolean(busy) || !active || !editable} onClick={() => { if (!activeRef.current || busy || !sessionRef.current?.authenticated || Date.parse(sessionRef.current.expires_at) <= Date.now()) return; try { onOpenSiteTool("backups", selected.id, selected.name, restoreHandoffFor(selected, backup)); } catch (failure) { fail(failure); } }}>Review restore<span className="sr-only"> backup {backup.id}</span></Button></div>
            </li>)}</ul>}
          </section>
          </div>
        </div> : <section className={cn(panel, "flex flex-col items-start gap-2 px-6 py-8")} aria-labelledby="website-none-heading"><Globe className="size-7 text-muted-foreground" aria-hidden="true" /><h2 id="website-none-heading" className="text-base!">{busy ? "Loading website records" : !inventoryLoaded ? "Website records unavailable" : sites.length ? "Select a website" : "Your website workspace"}</h2><div className="max-w-[52ch] text-sm text-muted-foreground">{!inventoryLoaded ? "Check the operator session and inventory before working with website files." : sites.length ? "Choose a website to manage its files, state and native ZIP backups." : "Create a static website or import a native site ZIP. Its files and backups will appear here."}</div></section>}
      </div>
    </>}
    {busy && session && <div className="text-xs text-muted-foreground" role="status">{busy}…</div>}
    {authenticated && <dialog ref={removeDialog} className={dialogClass} data-testid="website-remove-dialog" data-site-id={removeTarget?.id} data-revision={removeTarget?.revision} aria-labelledby="remove-website-title" aria-describedby="remove-website-description" onClose={() => { setRemoveTarget(undefined); setRemoveDomain(""); setRemoveNeedsRefresh(false); }} onCancel={(event) => { if (busy) event.preventDefault(); else { setRemoveTarget(undefined); setRemoveDomain(""); setRemoveNeedsRefresh(false); } }}>
      <h1 id="remove-website-title" className={dialogTitle}>Remove website</h1><div id="remove-website-description" className="mt-2 text-sm text-foreground">Permanently remove this website's static files, all native ZIP backups, backup schedule and local routing. Download any backups you need before continuing. The signed operation history is retained.</div>
      <div className="mt-3 text-sm text-foreground wrap-anywhere"><strong className="font-semibold">{removeTarget?.name}</strong> · {removeTarget?.domain}</div>
      <form data-testid="website-remove-form" className={dialogForm} onSubmit={(event) => { event.preventDefault(); void removeWebsite(); }}>
        <div className={field}><label htmlFor="website-remove-domain" className={fieldLabel}>Type the website domain</label><Input id="website-remove-domain" name="confirmation-domain" value={removeDomain} onChange={(event) => setRemoveDomain(event.target.value)} required maxLength={253} autoCapitalize="none" spellCheck={false} autoComplete="off" disabled={Boolean(busy) || removeNeedsRefresh} aria-describedby="website-remove-help" className={input} /><span id="website-remove-help" className={muted}>Enter {removeTarget?.domain} exactly to confirm permanent removal.</span></div>
        {(removeNeedsRefresh || (removeTarget && selected?.revision !== removeTarget.revision)) && <div className={refreshBox} role="status"><div>Removal was not confirmed. Refresh this website's details and review its domain and revision before confirming again. An interrupted removal requires recovery; it cannot be retried here.</div><Button variant="outline" size="sm" className={touch} disabled={Boolean(busy)} onClick={() => void removeWebsite(true)}><RefreshCw aria-hidden="true" />Refresh removal details</Button></div>}
        <div className={dialogActions}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={() => { setRemoveTarget(undefined); setRemoveDomain(""); setRemoveNeedsRefresh(false); }}>Cancel removal</Button><Button type="submit" variant="destructive" className={cn("h-9", touch)} disabled={!removeReady}>{busy === "Removing website" && spinner}Confirm website removal</Button></div>
      </form>{error && <div role="alert" className={cn("mt-3", dialogError)}>{error}</div>}
      <div className="mt-4"><TechnicalDetails>Revision {removeTarget?.revision}</TechnicalDetails></div>
    </dialog>}
    {authenticated && <dialog ref={nameDialog} className={dialogClass} aria-labelledby="edit-name-title" aria-describedby="edit-name-description" onClose={closeName} onCancel={(event) => { if (busy) event.preventDefault(); else closeName(); }}>
      <h1 id="edit-name-title" className={dialogTitle}>Edit website name</h1><div id="edit-name-description" className={dialogText}>Choose the display name used in your website inventory.</div><div className="mt-3 text-sm text-foreground wrap-anywhere">Current name: <strong className="font-semibold">{nameTarget?.name}</strong></div>
      <form data-testid="website-name-form" className={dialogForm} onSubmit={(event) => { event.preventDefault(); void changeName(); }}><div className={field}><label htmlFor="website-next-name" className={fieldLabel}>Website name</label><Input id="website-next-name" name="website-name" autoComplete="off" value={nextName} onChange={(event) => setNextName(event.target.value)} required maxLength={80} disabled={Boolean(busy)} aria-describedby="website-next-name-help" aria-invalid={nextNameBytes > 80} className={input} /><span id="website-next-name-help" className={muted}>{nextNameBytes}/80 UTF-8 bytes</span></div>
        {(nameNeedsRefresh || (nameTarget && selected?.revision !== nameTarget.revision)) && <div className={refreshBox} role="status"><div>The name change could not be confirmed or the website revision changed. Your requested name is kept. Refresh its current name and revision, review them, then save again.</div><Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || nameSettling} onClick={() => void changeName(true)}><RefreshCw aria-hidden="true" />Refresh name revision</Button></div>}
        <div className={dialogActions}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={closeName}>Cancel name change</Button><Button type="submit" className={cn("h-9", touch)} disabled={!nameReady}>{busy === "Saving website name" && spinner}Save website name</Button></div>
        {error && <div className={dialogError} role="alert">{error}</div>}
      </form>
      <div className="mt-4"><TechnicalDetails>Revision {nameTarget?.revision}</TechnicalDetails></div>
    </dialog>}
    {authenticated && <dialog ref={domainDialog} className={dialogClass} aria-labelledby="change-domain-title" aria-describedby="change-domain-description" onClose={() => { setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false); }} onCancel={(event) => { if (busy) event.preventDefault(); else { setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false); } }}>
      <h1 id="change-domain-title" className={dialogTitle}>Change website domain</h1><div id="change-domain-description" className={dialogText}>Change this static website's local HTTP routing only. DNS and TLS are not changed.</div><div className="mt-3 text-sm text-foreground wrap-anywhere">Current domain: <strong className="font-semibold">{domainTarget?.domain}</strong></div>
      <form data-testid="website-domain-form" className={dialogForm} onSubmit={(event) => { event.preventDefault(); void changeDomain(); }}><div className={field}><label htmlFor="website-next-domain" className={fieldLabel}>New domain</label><Input id="website-next-domain" name="website-domain" autoComplete="off" value={nextDomain} onChange={(event) => setNextDomain(event.target.value)} required maxLength={253} autoCapitalize="none" spellCheck={false} disabled={Boolean(busy)} aria-describedby="website-next-domain-help" aria-invalid={nextDomainBytes > 253} className={input} /><span id="website-next-domain-help" className={muted}>{nextDomainBytes}/253 UTF-8 bytes · no protocol or path</span></div>
        {(domainNeedsRefresh || (domainTarget && selected?.revision !== domainTarget.revision)) && <div className={refreshBox} role="status"><div>The domain is unavailable or the website revision changed. Your new domain is kept. Refresh its current domain and revision, review them, then submit again.</div><Button variant="outline" size="sm" className={touch} disabled={Boolean(busy)} onClick={() => void changeDomain(true)}><RefreshCw aria-hidden="true" />Refresh domain revision</Button></div>}
        <div className={dialogActions}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={() => { setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false); }}>Cancel domain change</Button><Button type="submit" className={cn("h-9", touch)} disabled={!domainReady}>{busy === "Changing website domain" && spinner}Confirm domain change</Button></div>
      </form>{error && <div role="alert" className={cn("mt-3", dialogError)}>{error}</div>}
      <div className="mt-4"><TechnicalDetails>Revision {domainTarget?.revision}</TechnicalDetails></div>
    </dialog>}
    {authenticated && <dialog ref={createDialog} className={dialogClass} aria-labelledby="create-website-title" aria-describedby="create-website-description" onClose={() => setCreateOpen(false)} onCancel={(event) => { if (busy) event.preventDefault(); else setCreateOpen(false); }}>
      <h1 id="create-website-title" className={dialogTitle}>Create website</h1><div id="create-website-description" className={dialogText}>Start a static website with its own files and native ZIP backups. The domain is a label; creating a website does not configure DNS or TLS.</div>
      <form onSubmit={create} data-testid="website-create-form" className={dialogForm}>
        <div className={field}><label htmlFor="website-name" className={fieldLabel}>Website name</label><Input id="website-name" name="website-name" autoComplete="off" value={name} onChange={(event) => setName(event.target.value)} required maxLength={80} autoFocus aria-invalid={nameBytes > 80} aria-describedby="website-name-help" disabled={Boolean(busy)} className={input} /><span id="website-name-help" className={cn(muted, nameBytes > 80 && "text-destructive")}>{nameBytes}/80 UTF-8 bytes</span></div>
        <div className={field}><label htmlFor="website-domain" className={fieldLabel}>Domain</label><Input id="website-domain" name="website-domain" autoComplete="off" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.test" required maxLength={253} autoCapitalize="none" spellCheck={false} aria-invalid={domainBytes > 253} aria-describedby="website-domain-help" disabled={Boolean(busy)} className={input} /><span id="website-domain-help" className={cn(muted, domainBytes > 253 && "text-destructive")}>{domainBytes}/253 UTF-8 bytes · no protocol or path</span></div>
        <div className={dialogActions}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={() => setCreateOpen(false)}>Cancel creation</Button><Button type="submit" className={cn("h-9", touch)} disabled={Boolean(busy) || dirty || sites.length >= 100 || nameBytes > 80 || domainBytes > 253 || !name.trim() || !domain.trim()}>{busy === "Creating website" && spinner}Create website</Button></div>
      </form>{error && <div role="alert" className={cn("mt-3", dialogError)}>{error}</div>}
    </dialog>}
    {authenticated && <dialog ref={importDialog} className={dialogClass} aria-labelledby="import-title" onClose={() => { setImportOpen(false); setDiscardDraftForImport(false); }} onCancel={(event) => { if (busy) event.preventDefault(); else closeImport(); }}><h1 id="import-title" className={dialogTitle}>Import native Sifruno ZIP</h1><div className={dialogText}>Import an app-owned static website archive into a new website. This accepts native Sifruno site ZIPs only; cPanel host backups are not compatible.</div>{preparedCopy && <div className="mt-4 flex flex-col gap-1.5 rounded-md border border-border p-3 text-sm text-foreground wrap-anywhere" data-testid="website-import-snapshot" data-source-site-id={preparedCopy.site.id} data-backup-id={preparedCopy.backup.id} data-sha256={preparedCopy.backup.sha256}><strong className="font-semibold">Verified saved snapshot · {preparedCopy.site.name}</strong><div className="text-muted-foreground">{dateLabel(preparedCopy.backup.created_at)} · {preparedCopy.backup.files} files · {bytes(preparedCopy.backup.bytes)}</div><div className="text-muted-foreground">Source: {preparedCopy.site.domain}. Choose a new website name and domain below. The source website stays unchanged.</div><TechnicalDetails>Backup {preparedCopy.backup.id}{"\n"}Revision {preparedCopy.backup.revision}{"\n"}SHA-256 {preparedCopy.backup.sha256}</TechnicalDetails></div>}<form onSubmit={submitImportArchive} className={dialogForm}>
      <div className={field}><label htmlFor="import-website-name" className={fieldLabel}>Website name</label><Input id="import-website-name" name="website-name" autoComplete="off" value={importName} onChange={(event) => setImportName(event.target.value)} required maxLength={80} aria-invalid={importNameBytes > 80} disabled={Boolean(busy)} className={input} /><span className={muted}>{importNameBytes}/80 UTF-8 bytes</span></div>
      <div className={field}><label htmlFor="import-website-domain" className={fieldLabel}>Domain</label><Input id="import-website-domain" name="website-domain" autoComplete="off" value={importDomain} onChange={(event) => setImportDomain(event.target.value)} required maxLength={253} autoCapitalize="none" spellCheck={false} disabled={Boolean(busy)} className={input} /><span className={muted}>{importDomainBytes}/253 UTF-8 bytes</span></div>
      <div className={field}>{preparedCopy ? <div className={fieldLabel}>Verified native site ZIP</div> : <><label htmlFor="import-website-archive" className={fieldLabel}>Native site ZIP</label><input ref={importInput} id="import-website-archive" type="file" accept=".zip,application/zip,application/octet-stream" required disabled={Boolean(busy)} onChange={(event) => setImportArchive(event.target.files?.[0])} className="w-full min-w-0 text-sm text-foreground file:me-3 file:rounded-md file:border file:border-input file:bg-card file:px-2.5 file:py-1.5 file:text-sm file:font-medium file:text-foreground disabled:opacity-65" /></>}<span className={muted}>Maximum 34 MiB · ZIP only</span>{importArchive && <span className={muted}>{importArchive.name} · {bytes(importArchive.size)}</span>}</div>
      {dirty && <label className="flex items-start gap-2 text-sm text-foreground"><input type="checkbox" className="mt-0.5 size-4 shrink-0 accent-primary" checked={discardDraftForImport} onChange={(event) => setDiscardDraftForImport(event.target.checked)} disabled={Boolean(busy)} />Discard the unsaved editor draft after the import succeeds.</label>}
      <div className={dialogActions}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={closeImport}>Cancel import</Button><Button type="submit" className={cn("h-9", touch)} disabled={Boolean(busy) || importPending.current || !active || !importName.trim() || importNameBytes > 80 || !importDomain.trim() || importDomainLength > 253 || importDomainBytes > 253 || !importArchive || importArchive.size === 0 || importArchive.size > maxTransferArchive || (dirty && !discardDraftForImport)}>{busy === "Importing native ZIP" && spinner}Import website</Button></div>
    </form>{error && <div role="alert" className={cn("mt-3", dialogError)}>{error}</div>}</dialog>}
  </section>;
}
