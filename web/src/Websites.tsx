import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Archive, ArrowDownToLine, ArrowUpRight, File, Folder, Globe, Info, LockKeyhole, LogOut, Plus, RefreshCw, Save, Search, Upload } from "lucide-react";
import { bytes } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import { downloadSiteBackup, importSiteArchive, previewURL, sitePreviewPort, SiteApiError, siteRequest, siteURL, validBackup, validBackupList, validFileContent, validFileList, validSession, validSite, validSiteList } from "@/lib/sites-api";
import type { OperatorSession, Site, SiteBackup, SiteFile, SiteFileContent } from "@/lib/sites-api";

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

export default function Websites({ revision, active, onStatus, onOpenSiteTool, importRequest, onImportRequestConsumed }: { revision: number; active: boolean; onStatus: (value: Resource<unknown>) => void; onOpenSiteTool: (destination: "files" | "backups", siteId: string, siteName: string) => void; importRequest?: number; onImportRequestConsumed: (requestId: number) => void }) {
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
  const [restore, setRestore] = useState<{ site: Site; backup: SiteBackup }>();
  const [restoreConfirmed, setRestoreConfirmed] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [section, setSection] = useState("files");
  const [importOpen, setImportOpen] = useState(false);
  const [domainTarget, setDomainTarget] = useState<Site>();
  const [nextDomain, setNextDomain] = useState("");
  const [domainNeedsRefresh, setDomainNeedsRefresh] = useState(false);
  const [importName, setImportName] = useState("");
  const [importDomain, setImportDomain] = useState("");
  const [importArchive, setImportArchive] = useState<File>();
  const [discardDraftForImport, setDiscardDraftForImport] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const createDialog = useRef<HTMLDialogElement>(null);
  const importDialog = useRef<HTMLDialogElement>(null);
  const domainDialog = useRef<HTMLDialogElement>(null);
  const domainGeneration = useRef(0), domainPending = useRef(false);
  const importGeneration = useRef(0), importPending = useRef(false), authEpoch = useRef(0);
  const requestedImport = useRef(importRequest), handledImport = useRef(0);
  if (importRequest !== undefined) requestedImport.current = importRequest;
  const importRequestId = requestedImport.current;
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
  const domainReady = Boolean(active && authenticated && domainTarget && selected?.id === domainTarget.id && selected.revision === domainTarget.revision && selected.state !== "recovery_required" && !dirty && !conflict && !busy && !domainNeedsRefresh && nextDomain.trim() && nextDomainBytes <= 253);

  const fail = useCallback((failure: unknown) => {
    setError(errorText(failure));
    if (failure instanceof SiteApiError && failure.status === 401) { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); setRestore(undefined); setNotice(undefined); }
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
    const request = requestedImport.current !== undefined && requestedImport.current !== handledImport.current ? requestedImport.current : undefined;
    if (!active) { if (request !== undefined) { handledImport.current = request; onImportRequestConsumed(request); } return; }
    let live = true, csrf: string | undefined, inventoryCount = 0;
    const authGeneration = authEpoch.current;
    if (request !== undefined) { handledImport.current = request; setDiscardDraftForImport(false); setNotice(undefined); setImportOpen(false); }
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
          inventoryCount = list.items.length; setSites(list.items);
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
          if (importPending.current || domainPending.current) throw new SiteApiError(409, "operation_pending", "The previous operation is still settling. Open Import native ZIP again after it completes.");
          if (inventoryCount >= 100) throw new SiteApiError(422, "capacity", "The website inventory is full. A ZIP import creates a new website.");
          setCreateOpen(false); setRestore(undefined); setDomainTarget(undefined); setImportOpen(true);
        }
      } catch (failure) { if (isLive()) fail(failure); }
      finally { if (live && activeRef.current) setBusy(undefined); if (request !== undefined) onImportRequestConsumed(request); }
    })();
    return () => { live = false; };
  }, [revision, active, fail, sessionAttempt, importRequestId, onImportRequestConsumed]);

  useEffect(() => { ++fileReadEpoch.current; if (!authenticated) clearAsset(); }, [active, authenticated, session?.authenticated ? session.csrf_token : undefined, clearAsset]);
  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => { if (!active) setAccessKey(""); }, [active]);
  useEffect(() => {
    if (active && authenticated) return;
    for (const ref of [createDialog, importDialog, dialog, domainDialog]) if (ref.current?.open) ref.current.close();
    setCreateOpen(false); setImportOpen(false); setRestore(undefined); setRestoreConfirmed(false);
    if (!authenticated) { setImportArchive(undefined); setDiscardDraftForImport(false); }
    dialogReturnFocus.current = null;
  }, [active, authenticated]);
  useEffect(() => {
    ++domainGeneration.current;
    if (!active || !authenticated || domainTarget?.id !== selected?.id) { setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false); }
  }, [active, authenticated, selected?.id, session?.authenticated ? session.csrf_token : undefined, revision]);
  useEffect(() => {
    if (active && authenticated && domainTarget && domainDialog.current && !domainDialog.current.open) domainDialog.current.showModal();
    else if (!domainTarget && domainDialog.current?.open) domainDialog.current.close();
  }, [domainTarget, active, authenticated]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); setRestore(undefined); setNotice(undefined); setError("Your operator session expired. Sign in again; your editor draft is kept."); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session]);
  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
  useEffect(() => {
    if (active && authenticated && restore && dialog.current && !dialog.current.open) dialog.current.showModal();
  }, [restore, active, authenticated]);
  useEffect(() => {
    ++importGeneration.current; setImportOpen(false); setDiscardDraftForImport(false);
    setBusy((current) => current === "Importing native ZIP" ? undefined : current);
  }, [active, authenticated, session?.authenticated ? session.csrf_token : undefined, revision, importRequestId]);
  useEffect(() => {
    if (active && authenticated && importOpen && importDialog.current && !importDialog.current.open) importDialog.current.showModal();
    else if (!importOpen && importDialog.current?.open) importDialog.current.close();
  }, [importOpen, active, authenticated]);
  useEffect(() => {
    if (active && authenticated && createOpen && createDialog.current && !createDialog.current.open) createDialog.current.showModal();
    else if (!createOpen && createDialog.current?.open) createDialog.current.close();
  }, [createOpen, active, authenticated]);
  useEffect(() => {
    if (active && authenticated && !busy && !createOpen && !importOpen && !restore && !domainTarget && dialogReturnFocus.current) {
      if (dialogReturnFocus.current.isConnected) dialogReturnFocus.current.focus();
      dialogReturnFocus.current = null;
    }
  }, [active, authenticated, busy, createOpen, importOpen, restore, domainTarget]);
  const rememberDialogTrigger = () => { dialogReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; };

  async function run(label: string, action: () => Promise<void>) {
    if (busy) return;
    setBusy(label); setError(undefined); setNotice(undefined);
    try { await action(); setLoadedAt(new Date()); } catch (failure) { fail(failure); }
    finally { setBusy(undefined); }
  }
  const requireClean = () => {
    if (!dirty) return true;
    setError("Save or discard your editor draft before switching websites, creating a website, changing its domain or state, restoring or signing out.");
    return false;
  };
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
      if (dirty) { setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); }
      updateSite(site);
      setImportOpen(false); setImportName(""); setImportDomain(""); setImportArchive(undefined); setDiscardDraftForImport(false);
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

  return <section data-testid="websites-view" className="websites-view website-workspace">
    {error && !domainTarget && !importOpen && <div className="website-message website-error" role="alert"><Info /><span>{error}</span></div>}
    {notice && <div className="website-message" role="status"><Info /><span>{notice}</span></div>}
    {!session ? <Card className="dashboard-card website-auth" padding={0}><p role="status">{busy || (error ? "Operator session could not be checked." : "Checking operator session…")}</p>{error && <Button label="Retry operator session" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={() => setSessionAttempt((attempt) => attempt + 1)} />}</Card> : !authenticated ? <Card className="dashboard-card website-auth" padding={0}>
      <div className="auth-heading"><LockKeyhole /><div><h2>Local operator sign-in</h2><p>Use the access key created by this server in its private state directory.</p></div></div>
      <form onSubmit={login} data-testid="operator-login" autoComplete="off">
        <label htmlFor="operator-access-key">Operator access key</label>
        <input id="operator-access-key" type="password" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} required autoComplete="off" spellCheck={false} disabled={Boolean(busy)} />
        <Button label="Sign in locally" type="submit" variant="primary" isLoading={busy === "Signing in"} isDisabled={Boolean(busy) || !accessKey.trim()} />
      </form>
      <p className="website-help">The key is cleared after submission. Overview stays available without sign-in. This operator session is local; production roles and remote authentication are not qualified yet.</p>
    </Card> : <>
      <div className="website-session"><span><LockKeyhole />Signed in locally · expires {dateLabel(session.expires_at)}</span><Button label="Sign out locally" icon={<LogOut />} variant="ghost" size="sm" isDisabled={Boolean(busy)} onClick={() => { if (!requireClean()) return; void run("Signing out", async () => {
        const next = await siteRequest("/api/v1/session/logout", validSession, { method: "POST", csrf: session.csrf_token, body: {} });
        if (next.authenticated) throw new SiteApiError(0, "invalid_response", "Sign-out was not confirmed.");
        setSession(next); setSites([]); setInventoryLoaded(false); setSelected(undefined); setFiles([]); setBackups([]); setEditor(undefined); clearAsset(); setConflict(undefined); setRestore(undefined);
      }); }} /></div>
      <Card className="dashboard-card website-inventory-toolbar" padding={0}>
        <div className="website-inventory-heading"><h2>Website inventory</h2><p>{inventoryLoaded ? <><strong>{sites.length}</strong> {sites.length === 1 ? "website" : "websites"}<span> · {stateCounts("active")} active · {stateCounts("suspended")} suspended{stateCounts("recovery_required") > 0 && <> · {stateCounts("recovery_required")} need recovery</>}</span></> : busy ? "Loading inventory…" : "Inventory could not be loaded. Refresh to try again."}</p></div>
        <div className="website-inventory-actions">
          <Button label="Refresh websites" icon={<RefreshCw />} variant="ghost" size="sm" isDisabled={Boolean(busy)} onClick={() => setSessionAttempt((attempt) => attempt + 1)} />
          <Button label="Import native ZIP" icon={<Upload />} variant="secondary" size="sm" isDisabled={Boolean(busy) || sites.length >= 100} onClick={() => { rememberDialogTrigger(); setDiscardDraftForImport(false); setError(undefined); setImportOpen(true); }} />
          <Button label="Create website" icon={<Plus />} variant="primary" size="sm" isDisabled={Boolean(busy) || dirty || sites.length >= 100} onClick={() => { if (!requireClean()) return; rememberDialogTrigger(); setError(undefined); setCreateOpen(true); }} />
        </div>
      </Card>
      <div className="hosting-notice website-scope-notice"><Info aria-hidden="true" /><span>Static websites and native site ZIPs · local HTTP preview. DNS, TLS, PHP, mail and databases are unavailable.</span></div>
      {dirty && <p className="website-draft-notice" role="status"><Save aria-hidden="true" />Unsaved file draft kept. You can switch between Files and ZIP backups; save or discard before changing websites or their state.</p>}
      {sites.length >= 100 && <p className="website-help">This local inventory has reached its 100-website limit.</p>}
      <div className="website-layout">
        <Card className="dashboard-card website-list" padding={0}><div className="card-heading"><h2>Websites</h2>{inventoryLoaded && <span>{filtered.length}{query.trim() && <> of {sites.length}</>}</span>}</div><label className="compact-search"><Search aria-hidden="true" /><input type="search" aria-label="Search websites" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Name or domain…" /></label>
          <div className="website-list-items">{filtered.map((site) => <button key={site.id} type="button" className="website-list-item" aria-label={`Open website ${site.name}`} aria-current={selected?.id === site.id ? "true" : undefined} disabled={Boolean(busy)} onClick={() => { if (site.id === selected?.id || !requireClean()) return; void run("Loading website", () => loadSite(site.id)); }}><Globe aria-hidden="true" /><span className="website-list-identity"><strong>{site.name}</strong><small>{site.domain}</small></span><span className={`website-state website-state-${site.state}`}>{site.state.replaceAll("_", " ")}</span></button>)}{!filtered.length && <div className="website-empty">{!inventoryLoaded ? <p>{busy ? "Loading website records…" : "Website inventory is unavailable. Use Refresh websites to retry."}</p> : sites.length ? <><p>No matching websites.</p><button className="website-text-action" type="button" onClick={() => setQuery("")}>Clear search</button></> : <p>No websites yet. Create a website or import a native site ZIP to get started.</p>}</div>}</div>
        </Card>
        {selected ? <div className="website-detail-stack">
          <Card className="dashboard-card website-details" padding={0} data-testid="website-details" data-site-id={selected.id} data-revision={selected.revision}><div className="card-heading"><div className="website-selected-identity"><span className="website-selected-label">Selected website</span><h2>{selected.name}</h2><p>{selected.domain}</p></div><span className={`website-state website-state-${selected.state}`}>{selected.state.replaceAll("_", " ")}</span></div>
            <dl><div><dt>Revision</dt><dd>{selected.revision}</dd></div><div><dt>Created</dt><dd>{dateLabel(selected.created_at)}</dd></div><div><dt>Updated</dt><dd>{dateLabel(selected.updated_at)}</dd></div></dl>
            <div className="website-actions"><Button label="Local HTTP preview" icon={<ArrowUpRight />} href={previewURL(selected)} target="_blank" rel="noopener noreferrer" isDisabled={selected.state !== "active" || !previewPort} variant="secondary" size="sm" /><Button label="Change domain" icon={<Globe />} variant="secondary" size="sm" isDisabled={Boolean(busy) || dirty || Boolean(conflict) || !editable} onClick={() => { if (!requireClean()) return; rememberDialogTrigger(); setError(undefined); setDomainTarget(selected); setNextDomain(selected.domain); setDomainNeedsRefresh(false); }} /><Button label={selected.state === "suspended" ? "Resume website" : "Suspend website"} variant="secondary" size="sm" isDisabled={Boolean(busy) || dirty || !editable} onClick={() => { if (!session.authenticated || !requireClean()) return; void run("Changing website state", async () => { const site = await siteRequest(siteURL(selected.id, "/state"), validSite, { method: "POST", csrf: session.csrf_token, body: { state: selected.state === "suspended" ? "active" : "suspended", expected_revision: selected.revision } }); updateSite(site); await loadSite(site.id); setNotice(`Website is ${site.state}.`); }); }} /></div>
            <p className="website-help">{previewPort ? <>Preview serves the site's actual files at {selected.preview_host}:{previewPort} using local HTTP.</> : "Preview serving is disabled in this local runtime."}</p>
            <div className="website-actions"><Button label="Open File Manager" icon={<Folder />} variant="secondary" size="sm" isDisabled={Boolean(busy) || !active || !authenticated} onClick={() => onOpenSiteTool("files", selected.id, selected.name)} /><Button label="Open Backups" icon={<Archive />} variant="secondary" size="sm" isDisabled={Boolean(busy) || !active || !authenticated} onClick={() => onOpenSiteTool("backups", selected.id, selected.name)} /></div>
            {selected.state === "recovery_required" && <p className="website-message" role="alert">This website requires scoped recovery. Serving and managed changes are disabled until its recovery is resolved.</p>}
          </Card>
          <div className="website-section-toolbar"><SegmentedControl label="Website section" value={section} onChange={setSection} size="sm" className="website-section-selector"><SegmentedControlItem value="files" label="Files" icon={<Folder />} /><SegmentedControlItem value="backups" label="ZIP backups" icon={<Archive />} /></SegmentedControl><span className="website-section-count">{section === "files" ? `${files.length} files` : `${backups.length} ZIP backups`}</span></div>
          <div className="website-section-pane" hidden={section !== "files"}>
          <Card className="dashboard-card website-files" padding={0}><div className="card-heading"><h2><Folder aria-hidden="true" />Files</h2><Button label="Add text file" variant="ghost" size="sm" isDisabled={Boolean(busy) || dirty || !editable || files.length >= 64} onClick={() => { if (!requireClean()) return; clearAsset(); setEditor({ path: "", draft: "", savedContent: "", sha256: "", revision: selected.revision, isNew: true }); setConflict(undefined); setError(undefined); }} /></div>
            <div className="website-file-list">{files.map((file) => <button key={file.path} aria-label={`View file ${file.path}`} aria-pressed={(editor?.path === file.path && !editor.isNew) || (asset?.siteId === selected.id && asset.file.path === file.path)} disabled={Boolean(busy)} onClick={() => { if ((editor?.path === file.path && !editor.isNew) || (asset?.siteId === selected.id && asset.file.path === file.path)) return; if (!requireClean()) return; void run("Reading file", () => openFile(selected, file)); }}><File /><span>{file.path}</span><small>{bytes(file.bytes)}</small></button>)}{!files.length && <p className="website-empty">No files returned for this website.</p>}</div>
            {asset && asset.siteId === selected.id && <section className="website-asset-details" data-testid="website-asset-details" data-site-id={asset.siteId} data-file-path={asset.file.path} data-revision={asset.revision} aria-label="Saved asset details"><h3>Saved asset</h3><p>This file is not readable as UTF-8 text. Its saved bytes remain available for preview and File Manager.</p><dl><div><dt>Relative path</dt><dd>{asset.file.path}</dd></div><div><dt>Saved bytes</dt><dd>{bytes(asset.file.bytes)}</dd></div><div><dt>Inventory revision</dt><dd>{asset.revision}</dd></div><div><dt>SHA-256</dt><dd><code>{asset.file.sha256}</code></dd></div></dl><p className="website-help">Use Open File Manager above to replace or delete this asset.</p></section>}
            {editor && <form className="website-editor" onSubmit={save} data-testid="website-editor">
              {editor.isNew ? <div className="new-file-path"><label htmlFor="new-file-path">Relative file path</label><input id="new-file-path" value={editor.path} onChange={(e) => { setEditor({ ...editor, path: e.target.value }); setConflict(undefined); }} placeholder="assets/style.css" required disabled={Boolean(busy)} /><p className="website-help">New UTF-8 text file. Use a relative static-file path; PHP, private and source files are rejected.</p></div> : <div className="editor-heading"><label htmlFor="site-file-content">{editor.path}</label><span>Revision {editor.revision}</span></div>}
              <textarea id="site-file-content" aria-label="File content" value={editor.draft} onChange={(e) => setEditor({ ...editor, draft: e.target.value })} spellCheck={false} disabled={Boolean(busy) || !editable} />
              <div className="editor-actions"><span>{bytes(new TextEncoder().encode(editor.draft).length)} / 2 MiB · {dirty ? "Unsaved draft" : "Saved version"}</span><div><Button label="Discard draft" variant="ghost" size="sm" isDisabled={Boolean(busy) || !dirty} onClick={() => { if (editor.isNew) { setEditor(undefined); setConflict(undefined); setError(undefined); } else void run("Reading saved version", async () => { const site = await siteRequest(siteURL(selected.id), validSite); updateSite(site); setEditor(fromFile(await readFile(site, editor.path))); setConflict(undefined); }); }} /><Button label="Save file" icon={<Save />} type="submit" size="sm" variant="primary" isLoading={busy === "Saving file"} isDisabled={Boolean(busy) || !dirty || !editor.path || !editable || new TextEncoder().encode(editor.draft).length > 2 * 1024 * 1024} /></div></div>
              {conflict && <div className="file-conflict" role="status"><h3>Draft kept · server revision {conflict.revision}</h3><p>{conflict.file ? "Compare the server content below." : "No file exists at this path in the latest inventory."} Updating the revision keeps your draft; Save remains an explicit action.</p>{conflict.file && <details><summary>Compare latest server content</summary><pre>{conflict.file.content}</pre><p className="website-help">SHA-256: {conflict.file.sha256}</p></details>}<Button label="Keep draft and use latest revision" variant="secondary" size="sm" isDisabled={Boolean(busy)} onClick={() => { setEditor({ ...editor, savedContent: conflict.file?.content ?? "", sha256: conflict.file?.sha256 ?? "", revision: conflict.revision, isNew: !conflict.file }); setConflict(undefined); setError(undefined); }} /></div>}
            </form>}
          </Card>
          </div>
          <div className="website-section-pane" hidden={section !== "backups"}>
          <Card className="dashboard-card website-backups" padding={0}><div className="card-heading"><div><h2><Archive />ZIP backups</h2><p>App-owned site files only · {backups.length} recorded</p></div><Button label="Create ZIP backup" icon={<Archive />} size="sm" variant="secondary" isLoading={busy === "Creating backup"} isDisabled={Boolean(busy) || !editable || dirty} onClick={() => { if (!session.authenticated) return; void run("Creating backup", async () => { const backup = await siteRequest(siteURL(selected.id, "/backups"), validBackup, { method: "POST", csrf: session.csrf_token, body: { expected_revision: selected.revision } }); await loadSite(selected.id); setNotice(`Created ZIP backup with ${backup.files} files.`); }); }} /></div>
            {!backups.length ? <p className="website-empty">No ZIP backups recorded. Create a backup of this site's current files.</p> : <div className="website-backup-list">{backups.map((backup) => <article key={backup.id}><div><strong>{dateLabel(backup.created_at)}</strong><p>{backup.files} files · {bytes(backup.bytes)} · revision {backup.revision}</p><details><summary>Backup hash</summary><code>{backup.sha256}</code></details></div><div className="website-backup-actions"><Button label={`Download ZIP backup ${backup.id}`} icon={<ArrowDownToLine />} size="sm" variant="ghost" isDisabled={Boolean(busy) || !authenticated} isLoading={busy === "Downloading ZIP backup"} onClick={() => { if (authenticated) void exportBackup(selected, backup); }}>Download ZIP</Button><Button label={`Restore backup ${backup.id}`} size="sm" variant="secondary" isDisabled={Boolean(busy) || dirty || !editable} onClick={() => { if (!requireClean()) return; rememberDialogTrigger(); setRestore({ site: selected, backup }); setRestoreConfirmed(false); }}>Restore</Button></div></article>)}</div>}
          </Card>
          </div>
        </div> : <Card className="dashboard-card website-no-selection" padding={0}><Globe aria-hidden="true" /><h2>{busy ? "Loading website records" : !inventoryLoaded ? "Website records unavailable" : sites.length ? "Select a website" : "Your website workspace"}</h2><p>{!inventoryLoaded ? "Check the operator session and inventory before working with website files." : sites.length ? "Choose a website to manage its files, state and native ZIP backups." : "Create a static website or import a native site ZIP. Its files and backups will appear here."}</p></Card>}
      </div>
    </>}
    {busy && session && <p className="website-busy" role="status">{busy}…</p>}
    {authenticated && <dialog ref={domainDialog} className="website-transfer-dialog website-domain-dialog" aria-labelledby="change-domain-title" aria-describedby="change-domain-description" onClose={() => { setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false); }} onCancel={(event) => { if (busy) event.preventDefault(); else { setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false); } }}>
      <h2 id="change-domain-title">Change website domain</h2><p id="change-domain-description">Change this static website's local HTTP routing only. DNS and TLS are not changed.</p><p className="website-domain-current">Current domain: <strong>{domainTarget?.domain}</strong> · revision {domainTarget?.revision}</p>
      <form data-testid="website-domain-form" onSubmit={(event) => { event.preventDefault(); void changeDomain(); }}><div><label htmlFor="website-next-domain">New domain</label><input id="website-next-domain" value={nextDomain} onChange={(event) => setNextDomain(event.target.value)} required maxLength={253} autoCapitalize="none" spellCheck={false} disabled={Boolean(busy)} aria-describedby="website-next-domain-help" aria-invalid={nextDomainBytes > 253} /><span id="website-next-domain-help" className="website-help">{nextDomainBytes}/253 UTF-8 bytes · no protocol or path</span></div>
        {(domainNeedsRefresh || (domainTarget && selected?.revision !== domainTarget.revision)) && <div className="website-domain-conflict" role="status"><p>The domain is unavailable or the website revision changed. Your new domain is kept. Refresh its current domain and revision, review them, then submit again.</p><Button label="Refresh domain revision" variant="secondary" size="sm" isDisabled={Boolean(busy)} onClick={() => void changeDomain(true)} /></div>}
        <div className="website-transfer-actions"><Button label="Cancel domain change" variant="ghost" isDisabled={Boolean(busy)} onClick={() => { setDomainTarget(undefined); setNextDomain(""); setDomainNeedsRefresh(false); }} /><Button label="Confirm domain change" type="submit" variant="primary" isDisabled={!domainReady} isLoading={busy === "Changing website domain"} /></div>
      </form>{error && <p role="alert" className="website-error">{error}</p>}
    </dialog>}
    {authenticated && <dialog ref={createDialog} className="website-transfer-dialog website-create-dialog" aria-labelledby="create-website-title" aria-describedby="create-website-description" onClose={() => setCreateOpen(false)} onCancel={(event) => { if (busy) event.preventDefault(); else setCreateOpen(false); }}>
      <h2 id="create-website-title">Create website</h2><p id="create-website-description">Start a static website with its own files and native ZIP backups. The domain is a label; creating a website does not configure DNS or TLS.</p>
      <form onSubmit={create} data-testid="website-create-form">
        <div><label htmlFor="website-name">Website name</label><input id="website-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={80} autoFocus aria-invalid={nameBytes > 80} aria-describedby="website-name-help" disabled={Boolean(busy)} /><span id="website-name-help" className={`website-help${nameBytes > 80 ? " website-error" : ""}`}>{nameBytes}/80 UTF-8 bytes</span></div>
        <div><label htmlFor="website-domain">Domain</label><input id="website-domain" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.test" required maxLength={253} autoCapitalize="none" spellCheck={false} aria-invalid={domainBytes > 253} aria-describedby="website-domain-help" disabled={Boolean(busy)} /><span id="website-domain-help" className={`website-help${domainBytes > 253 ? " website-error" : ""}`}>{domainBytes}/253 UTF-8 bytes · no protocol or path</span></div>
        <div className="website-transfer-actions"><Button label="Cancel creation" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setCreateOpen(false)} /><Button label="Create website" type="submit" variant="primary" isLoading={busy === "Creating website"} isDisabled={Boolean(busy) || dirty || sites.length >= 100 || nameBytes > 80 || domainBytes > 253 || !name.trim() || !domain.trim()} /></div>
      </form>{error && <p role="alert" className="website-error">{error}</p>}
    </dialog>}
    {authenticated && <dialog ref={importDialog} className="website-transfer-dialog" aria-labelledby="import-title" onClose={() => { setImportOpen(false); setDiscardDraftForImport(false); }} onCancel={(event) => { if (busy) event.preventDefault(); else { setImportOpen(false); setDiscardDraftForImport(false); } }}><h2 id="import-title">Import native Sifruno ZIP</h2><p>Import an app-owned static website archive into a new website. This accepts native Sifruno site ZIPs only; cPanel host backups are not compatible.</p><form onSubmit={submitImportArchive}>
      <div><label htmlFor="import-website-name">Website name</label><input id="import-website-name" value={importName} onChange={(event) => setImportName(event.target.value)} required maxLength={80} aria-invalid={importNameBytes > 80} disabled={Boolean(busy)} /><span className="website-help">{importNameBytes}/80 UTF-8 bytes</span></div>
      <div><label htmlFor="import-website-domain">Domain</label><input id="import-website-domain" value={importDomain} onChange={(event) => setImportDomain(event.target.value)} required maxLength={253} autoCapitalize="none" spellCheck={false} disabled={Boolean(busy)} /><span className="website-help">{importDomainBytes}/253 UTF-8 bytes</span></div>
      <div><label htmlFor="import-website-archive">Native site ZIP</label><input id="import-website-archive" type="file" accept=".zip,application/zip,application/octet-stream" required disabled={Boolean(busy)} onChange={(event) => setImportArchive(event.target.files?.[0])} /><span className="website-help">Maximum 34 MiB · ZIP only</span>{importArchive && <span className="website-help">{importArchive.name} · {bytes(importArchive.size)}</span>}</div>
      {dirty && <label className="website-discard-draft"><input type="checkbox" checked={discardDraftForImport} onChange={(event) => setDiscardDraftForImport(event.target.checked)} disabled={Boolean(busy)} />Discard the unsaved editor draft after the import succeeds.</label>}
      <div className="website-transfer-actions"><Button label="Cancel import" variant="ghost" isDisabled={Boolean(busy)} onClick={() => { setImportOpen(false); setDiscardDraftForImport(false); }} /><Button label="Import website" type="submit" variant="primary" isLoading={busy === "Importing native ZIP"} isDisabled={Boolean(busy) || importPending.current || !active || !importName.trim() || importNameBytes > 80 || !importDomain.trim() || importDomainLength > 253 || importDomainBytes > 253 || !importArchive || importArchive.size === 0 || importArchive.size > maxTransferArchive || (dirty && !discardDraftForImport)} /></div>
    </form>{error && <p role="alert" className="website-error">{error}</p>}</dialog>}
    {restore && <dialog ref={dialog} className="website-restore-dialog" aria-labelledby="restore-title" onCancel={(event) => { if (busy) event.preventDefault(); else setRestore(undefined); }}><h2 id="restore-title">Restore ZIP backup?</h2><p>Replace the app-owned files of <strong>{restore.site.name}</strong> with the backup from {dateLabel(restore.backup.created_at)}.</p><dl><div><dt>Backup</dt><dd>{restore.backup.files} files · {bytes(restore.backup.bytes)} · revision {restore.backup.revision}</dd></div><div><dt>Expected current revision</dt><dd>{restore.site.revision}</dd></div></dl><p>This restores site files through scoped recovery. It does not restore a server, database or mail system.</p><label><input type="checkbox" checked={restoreConfirmed} onChange={(e) => setRestoreConfirmed(e.target.checked)} disabled={Boolean(busy)} />I understand that the current site files will be replaced.</label><div><Button label="Cancel restore" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setRestore(undefined)} /><Button label="Confirm restore" variant="primary" isDisabled={!restoreConfirmed || Boolean(busy)} isLoading={busy === "Restoring backup"} onClick={() => { if (!session?.authenticated || !restoreConfirmed || !requireClean()) return; void run("Restoring backup", async () => { const site = await siteRequest(siteURL(restore.site.id, "/restore"), validSite, { method: "POST", csrf: session.csrf_token, body: { backup_id: restore.backup.id, expected_revision: restore.site.revision } }); updateSite(site); setEditor(undefined); latestEditor.current = undefined; await loadSite(site.id); setRestore(undefined); setNotice(`Restored ${site.name} from its ZIP backup.`); }); }} /></div>{error && <p role="alert" className="website-error">{error}</p>}</dialog>}
  </section>;
}
