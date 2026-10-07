import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { File, FilePlus, Folder, Info, LockKeyhole, LogOut, RefreshCw, Save, Search, Trash2 } from "lucide-react";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { bytes } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import { SiteApiError, siteRequest, siteURL, validFileContent, validFileList, validSession, validSite, validSiteList } from "@/lib/sites-api";
import type { OperatorSession, Site, SiteFile, SiteFileContent } from "@/lib/sites-api";
import "./file-manager.css";

interface Editor { siteId: string; path: string; draft: string; savedContent: string; sha256: string; revision: number; isNew: boolean }
interface Conflict { path: string; revision?: number; file?: SiteFileContent; compared: boolean }
interface DeleteTarget { siteId: string; path: string; sha256: string; revision: number }
const maxFileBytes = 2 * 1024 * 1024, maxSiteBytes = 32 * 1024 * 1024, maxFiles = 64;
const utf8Bytes = (value: string) => new TextEncoder().encode(value).length;
const dirtyEditor = (editor?: Editor) => Boolean(editor && (editor.isNew || editor.draft !== editor.savedContent));
const textExtensions = new Set(["html", "htm", "css", "js", "mjs", "txt", "svg"]);
const staticExtensions = new Set([...textExtensions, "png", "jpg", "jpeg", "gif", "webp", "ico", "woff", "woff2", "ttf", "pdf"]);
function validPath(value: string, newText = false): boolean {
  const parts = value.split("/"), extension = value.split(".").at(-1)!.toLowerCase();
  return utf8Bytes(value) <= 200 && parts.length <= 8 && (newText ? textExtensions : staticExtensions).has(extension) && parts.every((part) => {
    const base = part.split(".", 1)[0].toLowerCase();
    return /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$/.test(part) && !part.endsWith(".") && !/^(con|prn|aux|nul|com[0-9]|lpt[0-9]|credentials|password|secrets|kubeconfig|key)$/.test(base) && !base.startsWith("id_rsa") && !base.startsWith("id_ed25519");
  });
}
function validUtf16(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) { const next = value.charCodeAt(++index); if (!(next >= 0xdc00 && next <= 0xdfff)) return false; }
    else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}
const fromFile = (siteId: string, file: SiteFileContent): Editor => ({ siteId, path: file.path, draft: file.content, savedContent: file.content, sha256: file.sha256, revision: file.revision, isNew: false });
const fileError = (failure: unknown) => failure instanceof SiteApiError ? failure.message : "The file operation could not be confirmed. Your draft is kept. Refresh records before trying again.";

export default function FileManager({ revision, active, onStatus }: { revision: number; active: boolean; onStatus: (value: Resource<unknown>) => void }) {
  const [session, setSession] = useState<OperatorSession>();
  const [accessKey, setAccessKey] = useState("");
  const [sites, setSites] = useState<Site[]>([]);
  const [selected, setSelected] = useState<Site>();
  const [files, setFiles] = useState<SiteFile[]>([]);
  const [folder, setFolder] = useState("");
  const [query, setQuery] = useState("");
  const [editor, setEditor] = useState<Editor>();
  const [viewedPath, setViewedPath] = useState<string>();
  const [conflict, setConflict] = useState<Conflict>();
  const [fresh, setFresh] = useState(false);
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget>();
  const deleteDialog = useRef<HTMLDialogElement>(null), deleteReturnFocus = useRef<HTMLElement | null>(null);
  const latestEditor = useRef(editor); latestEditor.current = editor;
  const selectedId = useRef<string | undefined>(undefined);
  const epoch = useRef(0), actionPending = useRef(false), activeRef = useRef(active); activeRef.current = active;
  const dirty = dirtyEditor(editor), authenticated = session?.authenticated === true;
  const viewedFile = files.find((file) => file.path === viewedPath);
  const totalBytes = files.reduce((sum, file) => sum + file.bytes, 0), draftBytes = utf8Bytes(editor?.draft ?? "");
  const currentFile = files.find((file) => file.path === editor?.path);
  const pathCollision = Boolean(editor?.isNew && files.some((file) => file.path.toLowerCase() === editor.path.toLowerCase())) || Boolean(editor && files.some((file) => file.path !== editor.path && (file.path.toLowerCase().startsWith(editor.path.toLowerCase() + "/") || editor.path.toLowerCase().startsWith(file.path.toLowerCase() + "/"))));
  const projectedBytes = totalBytes - (currentFile?.bytes ?? 0) + draftBytes;
  const validDraft = Boolean(editor && validPath(editor.path, editor.isNew) && validUtf16(editor.draft) && draftBytes <= maxFileBytes && projectedBytes <= maxSiteBytes && !pathCollision && (!editor.isNew || files.length < maxFiles));
  const matchingBase = Boolean(editor && selected?.id === editor.siteId && editor.revision === selected.revision && (editor.isNew ? !currentFile : currentFile?.sha256 === editor.sha256));
  const canSave = Boolean(active && authenticated && fresh && !busy && dirty && validDraft && matchingBase && !conflict && selected?.state !== "recovery_required");
  const canDelete = Boolean(active && authenticated && fresh && !busy && !dirty && !conflict && selected && viewedFile && selected.state !== "recovery_required" && (!editor || (!editor.isNew && matchingBase && editor.path === viewedFile.path)));
  const matchingDelete = Boolean(canDelete && deleteTarget && selected?.id === deleteTarget.siteId && selected.revision === deleteTarget.revision && viewedFile?.path === deleteTarget.path && viewedFile.sha256 === deleteTarget.sha256);
  const clearPrivate = useCallback(() => { setSites([]); setSelected(undefined); setFiles([]); setFresh(false); }, []);
  const fail = useCallback((failure: unknown) => {
    setError(fileError(failure)); setFresh(false);
    if (failure instanceof SiteApiError && failure.status === 401) { setSession({ authenticated: false }); clearPrivate(); setNotice(undefined); }
  }, [clearPrivate]);

  const loadInventory = useCallback(async (preferredId?: string, isLive: () => boolean = () => true) => {
    const list = await siteRequest("/api/v1/sites", validSiteList);
    if (!isLive()) return;
    const draft = latestEditor.current, wanted = preferredId ?? selectedId.current;
    if (dirtyEditor(draft) && wanted === draft?.siteId && !list.items.some((site) => site.id === wanted)) { clearPrivate(); setSites(list.items); throw new SiteApiError(404, "not_found", "The draft's website is no longer in the inventory. Your text is kept; saving is disabled."); }
    const chosen = list.items.find((site) => site.id === wanted) ?? list.items[0];
    if (!chosen) { setSites(list.items); setSelected(undefined); setFiles([]); setFresh(true); setLoadedAt(new Date()); return; }
    const [site, catalog] = await Promise.all([siteRequest(siteURL(chosen.id), validSite), siteRequest(siteURL(chosen.id, "/files"), validFileList)]);
    if (!isLive()) return;
    if (site.id !== chosen.id || catalog.items.length > maxFiles || new Set(catalog.items.map((file) => file.path.toLowerCase())).size !== catalog.items.length || catalog.items.some((file) => !validPath(file.path) || file.bytes > maxFileBytes) || catalog.items.reduce((sum, file) => sum + file.bytes, 0) > maxSiteBytes) throw new SiteApiError(0, "invalid_response", "The file inventory did not match the static-site limits or selected website.");
    selectedId.current = site.id; setSites(list.items.map((item) => item.id === site.id ? site : item)); setSelected(site); setFiles(catalog.items); setFresh(true); setLoadedAt(new Date());
    const previous = latestEditor.current, actual = catalog.items.find((file) => file.path === previous?.path);
    if (previous?.siteId === site.id && (previous.revision !== site.revision || (previous.isNew ? Boolean(actual) : actual?.sha256 !== previous.sha256))) setConflict({ path: previous.path, compared: false });
  }, [clearPrivate]);
  const readFile = async (siteId: string, path: string) => {
    const file = await siteRequest(siteURL(siteId, `/file?path=${encodeURIComponent(path)}`), validFileContent);
    if (file.path !== path || utf8Bytes(file.content) > maxFileBytes || !validUtf16(file.content)) throw new SiteApiError(0, "invalid_response", "The file response did not match the requested UTF-8 file.");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(file.content));
    const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (hash !== file.sha256) throw new SiteApiError(0, "invalid_response", "The read content did not match its SHA-256. Your draft is kept.");
    return file;
  };

  useEffect(() => {
    const generation = ++epoch.current;
    if (!active) { setAccessKey(""); return; }
    if (actionPending.current) return;
    const isLive = () => activeRef.current && generation === epoch.current;
    setBusy("Checking file records"); setFresh(false); setDeleteTarget(undefined); setError(undefined);
    void (async () => {
      try { const next = await siteRequest("/api/v1/session", validSession, { unauthenticatedSession: true }); if (!isLive()) return; setSession(next); if (next.authenticated) await loadInventory(undefined, isLive); else clearPrivate(); if (isLive()) setLoadedAt(new Date()); }
      catch (failure) { if (isLive()) fail(failure); }
      finally { if (isLive()) setBusy(undefined); }
    })();
    return () => { if (generation === epoch.current) ++epoch.current; };
  }, [active, revision, attempt, loadInventory, clearPrivate, fail]);
  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => { setSession({ authenticated: false }); clearPrivate(); setError("Your operator session expired. Sign in again; your File Manager draft is kept."); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session, clearPrivate]);
  useEffect(() => { if (!dirty) return; const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; }; window.addEventListener("beforeunload", warn); return () => window.removeEventListener("beforeunload", warn); }, [dirty]);
  useEffect(() => {
    if (!active || !authenticated) { deleteDialog.current?.close(); setDeleteTarget(undefined); deleteReturnFocus.current = null; return; }
    if (deleteTarget && deleteDialog.current && !deleteDialog.current.open) deleteDialog.current.showModal();
    else if (!deleteTarget && deleteDialog.current?.open) deleteDialog.current.close();
    if (!deleteTarget && !busy && deleteReturnFocus.current) { if (deleteReturnFocus.current.isConnected) deleteReturnFocus.current.focus(); deleteReturnFocus.current = null; }
  }, [active, authenticated, deleteTarget, busy]);
  async function run(label: string, action: (isLive: () => boolean) => Promise<void>) {
    if (!activeRef.current || actionPending.current || busy) return;
    actionPending.current = true; const generation = epoch.current, isLive = () => activeRef.current && generation === epoch.current;
    setBusy(label); setError(undefined); setNotice(undefined);
    try { await action(isLive); if (isLive()) setLoadedAt(new Date()); } catch (failure) { if (isLive()) fail(failure); }
    finally { actionPending.current = false; if (isLive()) setBusy(undefined); else if (activeRef.current) setAttempt((value) => value + 1); }
  }
  const requireClean = () => { if (!dirtyEditor(latestEditor.current)) return true; setError("Save or discard your draft before deleting a file, opening another file, switching websites or signing out. Panel navigation keeps your draft."); return false; };
  async function login(event: React.FormEvent) {
    event.preventDefault(); if (!accessKey.trim()) return; const key = accessKey; setAccessKey("");
    await run("Signing in", async (isLive) => { const next = await siteRequest("/api/v1/session/login", validSession, { method: "POST", body: { access_key: key } }); if (!isLive()) return; if (!next.authenticated) throw new SiteApiError(401, "unauthorized", "The operator access key was not accepted."); setSession(next); await loadInventory(undefined, isLive); });
  }
  async function openFile(path: string) {
    if (!selected || !requireClean()) return;
    const target = selected; setViewedPath(path);
    await run("Reading file", async (isLive) => {
      try { const file = await readFile(target.id, path); if (!isLive()) return; const next = fromFile(target.id, file); setEditor(next); latestEditor.current = next; setConflict(file.revision === target.revision && files.find((item) => item.path === path)?.sha256 === file.sha256 ? undefined : { path, compared: false }); }
      catch (failure) { if (isLive() && failure instanceof SiteApiError && failure.status === 422) { setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setError("This asset is not readable as UTF-8 text. Its inventory metadata remains available."); return; } throw failure; }
    });
  }
  async function compareLatest() {
    const draft = latestEditor.current; if (!draft || !validPath(draft.path, draft.isNew) || !authenticated) return;
    await run("Reading latest server version", async (isLive) => {
      const [site, catalog] = await Promise.all([siteRequest(siteURL(draft.siteId), validSite), siteRequest(siteURL(draft.siteId, "/files"), validFileList)]);
      const existing = catalog.items.find((file) => file.path === draft.path);
      const file = existing ? await readFile(draft.siteId, draft.path) : undefined;
      if (!isLive()) return;
      if (site.id !== draft.siteId || (file && (file.revision !== site.revision || file.sha256 !== existing?.sha256))) throw new SiteApiError(409, "conflict", "The server changed while its latest file was read. Your draft is kept; read the latest version again.");
      selectedId.current = site.id; setSelected(site); setFiles(catalog.items); setSites((old) => old.map((item) => item.id === site.id ? site : item)); setFresh(true); setConflict({ path: draft.path, revision: site.revision, file, compared: true });
    });
  }
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!canSave || !session?.authenticated || !editor) return;
    const draft = editor;
    await run("Saving file", async (isLive) => {
      try {
        const site = await siteRequest(siteURL(draft.siteId, "/file"), validSite, { method: "PUT", csrf: session.csrf_token, body: { path: draft.path, content: draft.draft, expected_sha256: draft.sha256, expected_revision: draft.revision } });
        if (!isLive()) return;
        if (site.id !== draft.siteId || site.revision <= draft.revision) throw new SiteApiError(0, "invalid_response", "The save did not confirm an updated website revision. Your draft is kept.");
        setFresh(false); await loadInventory(site.id, isLive);
        const actual = await readFile(site.id, draft.path);
        if (!isLive()) return;
        if (actual.content !== draft.draft || actual.revision !== site.revision) throw new SiteApiError(409, "conflict", "The file changed before the saved content could be checked. Your draft is kept; compare the latest server version.");
        const next = fromFile(site.id, actual); setEditor(next); latestEditor.current = next; setConflict(undefined); setViewedPath(actual.path); setNotice(`Saved ${actual.path} · revision ${actual.revision}.`);
      } catch (failure) { if (isLive() && failure instanceof SiteApiError && failure.status === 409) setConflict({ path: draft.path, compared: false }); throw failure; }
    });
  }
  async function deleteFile() {
    if (!matchingDelete || !deleteTarget || !session?.authenticated || !requireClean()) return;
    const target = deleteTarget;
    await run("Deleting file", async (isLive) => {
      try {
        const site = await siteRequest(siteURL(target.siteId, "/file"), validSite, { method: "DELETE", csrf: session.csrf_token, body: { path: target.path, expected_sha256: target.sha256, expected_revision: target.revision } });
        if (!isLive()) return;
        if (site.id !== target.siteId || site.revision !== target.revision + 1) throw new SiteApiError(0, "invalid_response", "Deletion did not confirm the expected website revision. Refresh records before trying again.");
        setDeleteTarget(undefined); setFresh(false); setSelected(site); setSites((old) => old.map((item) => item.id === site.id ? site : item)); setFiles((old) => old.filter((file) => file.path !== target.path));
        setEditor(undefined); latestEditor.current = undefined; setViewedPath(undefined); setConflict(undefined); setNotice(`Deleted ${target.path} · revision ${site.revision}.`);
        await loadInventory(site.id, isLive);
      } catch (failure) {
        if (isLive()) { setDeleteTarget(undefined); if (failure instanceof SiteApiError && failure.status === 409 && latestEditor.current?.path === target.path) setConflict({ path: target.path, compared: false }); }
        throw failure;
      }
    });
  }

  const prefix = folder ? `${folder}/` : "", term = query.trim().toLowerCase();
  const visibleFiles = files.filter((file) => term ? file.path.toLowerCase().includes(term) : file.path.startsWith(prefix) && !file.path.slice(prefix.length).includes("/"));
  const folders = term ? [] : [...new Set(files.filter((file) => file.path.startsWith(prefix) && file.path.slice(prefix.length).includes("/")).map((file) => prefix + file.path.slice(prefix.length).split("/", 1)[0]))].sort();
  const folderParts = folder ? folder.split("/") : [];
  const draftProblem = !editor ? undefined : !validPath(editor.path, editor.isNew) ? "Use a relative static-file path up to 200 UTF-8 bytes and 8 segments. Each segment starts with a letter or number; private/reserved names are rejected. New text files use .html, .htm, .css, .js, .mjs, .txt or .svg." : pathCollision ? "A file already uses this path or conflicts with one of its parent folders. Open the existing file to edit it." : !validUtf16(editor.draft) ? "The draft contains an incomplete Unicode character." : draftBytes > maxFileBytes ? "The draft exceeds the 2 MiB UTF-8 file limit." : projectedBytes > maxSiteBytes ? "Saving would exceed the 32 MiB site limit." : editor.isNew && files.length >= maxFiles ? "This site has reached the 64-file limit." : undefined;

  return <section className="file-manager-page websites-view" data-testid="file-manager-page">
    <div className="hosting-notice"><Info aria-hidden="true" /><span>App-owned static site files only · explicit UTF-8 text edits. This is not a server filesystem, FTP client or PHP runtime.</span></div>
    {error && <div className="website-message website-error" role="alert"><Info /><span>{error}</span></div>}{notice && <div className="website-message" role="status"><Info /><span>{notice}</span></div>}
    {!session ? <Card className="dashboard-card website-auth" padding={0}><p role="status">{busy || "Operator session could not be checked."}</p>{error && <Button label="Retry operator session" isDisabled={Boolean(busy)} icon={<RefreshCw />} onClick={() => setAttempt((value) => value + 1)} />}</Card> : !authenticated ? <Card className="dashboard-card website-auth" padding={0}><div className="auth-heading"><LockKeyhole /><div><h2>Local operator sign-in</h2><p>Use the access key created by this server in its private state directory.</p></div></div><form onSubmit={login} data-testid="operator-login" autoComplete="off"><label htmlFor="file-manager-key">Operator access key</label><input id="file-manager-key" type="password" autoComplete="off" spellCheck={false} value={accessKey} onChange={(event) => setAccessKey(event.target.value)} required disabled={Boolean(busy)} /><Button label="Sign in locally" type="submit" variant="primary" isDisabled={Boolean(busy) || !accessKey.trim()} isLoading={busy === "Signing in"} /></form><p className="website-help">The key is cleared after submission. Your draft stays in this browser tab; credentials and drafts are not persisted by File Manager.</p></Card> : <>
      <div className="website-session"><span><LockKeyhole />Signed in locally · expires {dateLabel(session?.authenticated ? session.expires_at : "")}</span><Button label="Sign out locally" icon={<LogOut />} size="sm" variant="ghost" isDisabled={Boolean(busy) || dirty} onClick={() => { if (!requireClean()) return; void run("Signing out", async (isLive) => { if (!session?.authenticated) return; const next = await siteRequest("/api/v1/session/logout", validSession, { method: "POST", csrf: session.csrf_token, body: {} }); if (!isLive()) return; if (next.authenticated) throw new SiteApiError(0, "invalid_response", "Sign-out was not confirmed."); setSession(next); clearPrivate(); setEditor(undefined); latestEditor.current = undefined; setViewedPath(undefined); setConflict(undefined); }); }} /></div>
      <Card className="dashboard-card fm-picker" padding={0}><div><label htmlFor="file-manager-site-picker">Website</label><NativeSelect id="file-manager-site-picker" data-testid="file-manager-site-picker" aria-label="Website for files" value={selected?.id ?? ""} disabled={Boolean(busy) || dirty || !sites.length} onChange={(event) => { if (!requireClean()) return; const id = event.target.value; setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setViewedPath(undefined); setFolder(""); setQuery(""); setFresh(false); void run("Loading website files", (isLive) => loadInventory(id, isLive)); }}>{!sites.length && <NativeSelectOption value="">No websites available</NativeSelectOption>}{sites.map((site) => <NativeSelectOption key={site.id} value={site.id}>{site.name} · {site.domain}</NativeSelectOption>)}</NativeSelect></div><Button label="Refresh file records" variant="secondary" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)} /></Card>
      {selected && <div className="fm-context"><span>{selected.domain} · current revision {selected.revision}</span><span>{files.length} / 64 files · {bytes(totalBytes)} / 32 MiB</span></div>}
      {selected && fresh && files.length === 0 && <p className="fm-status" role="status">This website has no files. Active empty websites serve 404 responses. Add a text file or restore an existing ZIP backup in Websites. New ZIP backups require at least one file.</p>}
      {selected?.state === "recovery_required" && <p className="fm-status" role="alert">This website requires recovery. File changes are disabled until its recovery is resolved.</p>}
      {selected ? <div className="fm-layout">
        <Card className="dashboard-card fm-browser" padding={0} data-testid="file-manager-inventory" data-site-id={selected.id} data-revision={selected.revision} data-fresh={fresh}>
          <div className="card-heading"><h2>Site files</h2><Button label="New text file" icon={<FilePlus />} size="sm" variant="secondary" isDisabled={Boolean(busy) || !fresh || dirty || selected.state === "recovery_required" || files.length >= maxFiles} onClick={() => { if (!requireClean()) return; const next = { siteId: selected.id, path: prefix, draft: "", savedContent: "", sha256: "", revision: selected.revision, isNew: true }; setEditor(next); latestEditor.current = next; setViewedPath(undefined); setConflict(undefined); setError(undefined); }} /></div>
          <label className="compact-search"><Search aria-hidden="true" /><input type="search" aria-label="Search files" placeholder="Search all site paths…" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
          <nav className="fm-breadcrumb" aria-label="Site folders"><Button label="Root folder" variant="ghost" size="sm" onClick={() => { setFolder(""); setQuery(""); }}>Root</Button>{folderParts.map((part, index) => <Button key={index} label={`Open folder ${folderParts.slice(0, index + 1).join("/")}`} variant="ghost" size="sm" onClick={() => { setFolder(folderParts.slice(0, index + 1).join("/")); setQuery(""); }}>{part}</Button>)}</nav>
          <div className="fm-file-list">{folders.map((path) => <button key={path} type="button" data-testid="folder-row" data-folder-path={path} aria-label={`Open folder ${path}`} onClick={() => { setFolder(path); setQuery(""); }}><Folder aria-hidden="true" /><span>{path.slice(prefix.length)}</span><small>Folder</small></button>)}{visibleFiles.sort((a, b) => a.path.localeCompare(b.path)).map((file) => <button key={file.path} type="button" data-testid="file-row" data-file-path={file.path} aria-label={`View file ${file.path}`} aria-pressed={viewedPath === file.path} disabled={Boolean(busy) || dirty} onClick={() => void openFile(file.path)}><File aria-hidden="true" /><span>{term ? file.path : file.path.slice(prefix.length)}</span><small>{bytes(file.bytes)}</small></button>)}</div>
          {!visibleFiles.length && !folders.length && <div className="inventory-empty"><Folder /><h3>{term ? "No matching files" : "No reported files in this folder"}</h3><p>{term ? "Try another path or clear the search." : "Folders are derived from the actual file paths returned by the server."}</p></div>}
          <div className="table-footer"><span>{!fresh ? "Records need refreshing" : `${visibleFiles.length} files shown`}</span><span>{loadedAt ? `Checked ${loadedAt.toLocaleTimeString()}` : "Reading inventory"}</span></div>
        </Card>
        <Card className="dashboard-card fm-facts" padding={0} data-testid="file-manager-file-details"><div className="card-heading"><h2>File details</h2><Button label="Delete file" data-testid="file-manager-delete" icon={<Trash2 />} size="sm" variant="secondary" isDisabled={!canDelete} onClick={() => { if (!canDelete || !viewedFile || !requireClean()) return; deleteReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setDeleteTarget({ siteId: selected.id, path: viewedFile.path, sha256: viewedFile.sha256, revision: selected.revision }); }} /></div>{viewedFile ? <dl><div><dt>Relative path</dt><dd>{viewedFile.path}</dd></div><div><dt>Saved bytes</dt><dd>{bytes(viewedFile.bytes)}</dd></div><div><dt>Inventory revision</dt><dd>{selected.revision}</dd></div><div><dt>SHA-256</dt><dd><code>{viewedFile.sha256}</code></dd></div></dl> : <p>Select a reported file to inspect its saved size and hash.</p>}</Card>
      </div> : <Card className="dashboard-card" padding={0}><div className="inventory-empty"><Folder /><h2>{busy ? "Loading website files" : error ? "File records unavailable" : "No websites available"}</h2><p>{busy ? "Reading the actual app-owned site inventory." : error ? "Refresh records to check the current inventory. Retained drafts remain below." : "Create an app-owned static site in Websites to manage its files."}</p></div></Card>}
      {editor && <Card className="dashboard-card fm-editor" padding={0}><form onSubmit={save} data-testid="file-manager-editor" data-file-path={editor.path} data-read-revision={editor.revision} data-read-sha256={editor.sha256}>
        <div className="card-heading"><div><h2>{editor.isNew ? "New UTF-8 text file" : editor.path}</h2><p>Read revision {editor.revision} · {dirty ? "Unsaved draft" : "Saved version"}</p></div><Button label="Save file" type="submit" icon={<Save />} size="sm" variant="primary" isDisabled={!canSave} isLoading={busy === "Saving file"} /></div>
        <div className="fm-editor-body">{editor.isNew && <div className="fm-path-field"><label htmlFor="fm-new-path">Relative file path</label><input id="fm-new-path" value={editor.path} onChange={(event) => { const next = { ...editor, path: event.target.value }; setEditor(next); latestEditor.current = next; setConflict(undefined); }} placeholder="assets/style.css" required disabled={Boolean(busy)} aria-invalid={!validPath(editor.path, true)} /></div>}
          <label htmlFor="fm-content">File content</label><textarea id="fm-content" value={editor.draft} onChange={(event) => { const next = { ...editor, draft: event.target.value }; setEditor(next); latestEditor.current = next; }} spellCheck={false} disabled={Boolean(busy) || selected?.state === "recovery_required"} aria-describedby="fm-draft-limits" />
          <div className="fm-editor-footer"><p id="fm-draft-limits">{draftBytes.toLocaleString()} / {maxFileBytes.toLocaleString()} UTF-8 bytes · projected site {bytes(projectedBytes)}</p><Button label="Discard draft" size="sm" variant="ghost" isDisabled={Boolean(busy)} onClick={() => { setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setError(undefined); }} /></div>
          {draftProblem && <p className="website-error fm-status" role="status">{draftProblem}</p>}
          {(conflict || (!matchingBase && fresh)) && <div className="fm-conflict" data-testid="file-manager-conflict" role="status"><h3>Draft kept · server comparison required</h3><p>Read the current server version, compare it with your draft, then explicitly accept its revision before saving.</p><Button label="Read latest server version" icon={<RefreshCw />} variant="secondary" size="sm" isDisabled={Boolean(busy) || !validPath(editor.path, editor.isNew)} onClick={() => void compareLatest()} />{conflict?.compared && conflict.path === editor.path && <><p>Current revision {conflict.revision} · {conflict.file ? `SHA-256 ${conflict.file.sha256}` : "No file exists at this path in the latest inventory."}</p>{conflict.file && <details><summary>Compare latest server content</summary><pre>{conflict.file.content}</pre></details>}<Button label="Keep draft and use latest revision" variant="secondary" size="sm" isDisabled={Boolean(busy) || !fresh} onClick={() => { if (!conflict.compared || conflict.revision === undefined || conflict.path !== editor.path) return; const next = { ...editor, savedContent: conflict.file?.content ?? "", sha256: conflict.file?.sha256 ?? "", revision: conflict.revision, isNew: !conflict.file }; setEditor(next); latestEditor.current = next; setConflict(undefined); setError(undefined); }} /></>}</div>}
        </div>
      </form></Card>}
    </>}
    {authenticated && <dialog ref={deleteDialog} className="fm-delete-dialog" data-testid="file-manager-delete-dialog" aria-labelledby="fm-delete-title" aria-describedby="fm-delete-description" onClose={() => setDeleteTarget(undefined)} onCancel={(event) => { if (busy) event.preventDefault(); else setDeleteTarget(undefined); }}><h2 id="fm-delete-title">Delete this file?</h2><p id="fm-delete-description">Remove <strong>{deleteTarget?.path}</strong> from this website at revision {deleteTarget?.revision}. The file will stop being served. An existing ZIP backup can restore it.</p>{files.length === 1 && <p>This is the last file. An active empty website serves 404 responses; new ZIP backups require at least one file.</p>}<div><Button label="Cancel deletion" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setDeleteTarget(undefined)} /><Button label="Confirm file deletion" icon={<Trash2 />} variant="primary" isDisabled={!matchingDelete} isLoading={busy === "Deleting file"} onClick={() => void deleteFile()} /></div></dialog>}
    {busy && <p className="website-busy" role="status">{busy}…</p>}
  </section>;
}
