import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { ArrowUpRight, Download, File, FilePlus, Folder, Info, LockKeyhole, LogOut, RefreshCw, Save, Search, Trash2, Upload, Pencil } from "lucide-react";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { bytes } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import type { SiteHandoff } from "@/App";
import { SiteApiError, downloadSiteFile, uploadSiteFile, replaceSiteFile, renameSiteFile, savedFilePreviewURL, siteRequest, siteURL, validFileContent, validFileList, validSession, validSite, validSiteList } from "@/lib/sites-api";
import type { OperatorSession, Site, SiteFile, SiteFileContent } from "@/lib/sites-api";
import "./file-manager.css";

interface Editor { siteId: string; path: string; draft: string; savedContent: string; sha256: string; revision: number; isNew: boolean }
interface Conflict { path: string; revision?: number; file?: SiteFileContent; compared: boolean }
interface ReplaceTarget { siteId: string; domain: string; path: string; sha256: string; revision: number; bytes: number }
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

export default function FileManager({ revision, active, onStatus, siteHandoff, onHandoffConsumed }: { revision: number; active: boolean; onStatus: (value: Resource<unknown>) => void; siteHandoff?: SiteHandoff; onHandoffConsumed: (requestId: number) => void }) {
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
  const [uploadOpen, setUploadOpen] = useState(false);
  const [uploadFile, setUploadFile] = useState<globalThis.File>();
  const [uploadPath, setUploadPath] = useState("");
  const [replaceTarget, setReplaceTarget] = useState<ReplaceTarget>();
  const [replacementFile, setReplacementFile] = useState<globalThis.File>();
  const [renameTarget, setRenameTarget] = useState<ReplaceTarget>();
  const [renamePath, setRenamePath] = useState("");
  const renameDialog = useRef<HTMLDialogElement>(null), renameReturnFocus = useRef<HTMLElement | null>(null);
  const replacementPicker = useRef<HTMLInputElement>(null);
  const replacementDialog = useRef<HTMLDialogElement>(null), replacementReturnFocus = useRef<HTMLElement | null>(null);
  const uploadPicker = useRef<HTMLInputElement>(null);
  const uploadDialog = useRef<HTMLDialogElement>(null), uploadReturnFocus = useRef<HTMLElement | null>(null);
  const deleteDialog = useRef<HTMLDialogElement>(null), deleteReturnFocus = useRef<HTMLElement | null>(null);
  const latestEditor = useRef(editor); latestEditor.current = editor;
  const selectedId = useRef<string | undefined>(undefined);
  const handoff = useRef(siteHandoff), handledHandoff = useRef(0);
  if (siteHandoff) handoff.current = siteHandoff;
  const handoffRequestId = handoff.current?.requestId;
  const authEpoch = useRef(0);
  const sessionRef = useRef(session); sessionRef.current = session;
  const epoch = useRef(0), actionPending = useRef(false), activeRef = useRef(active); activeRef.current = active;
  const dirty = dirtyEditor(editor), authenticated = session?.authenticated === true;
  const viewedFile = files.find((file) => file.path === viewedPath);
  const downloadContext = useRef({ selected, viewedFile, fresh }); downloadContext.current = { selected, viewedFile, fresh };
  const canDownload = Boolean(active && authenticated && fresh && !busy && selected && viewedFile && selected.state !== "recovery_required");
  const savedFileHref = active && session?.authenticated && Date.parse(session.expires_at) > Date.now() && fresh && !busy && selected?.state === "active" && viewedFile ? savedFilePreviewURL(selected, viewedFile.path, validPath) : undefined;
  const totalBytes = files.reduce((sum, file) => sum + file.bytes, 0), draftBytes = utf8Bytes(editor?.draft ?? "");
  const currentFile = files.find((file) => file.path === editor?.path);
  const pathCollision = Boolean(editor?.isNew && files.some((file) => file.path.toLowerCase() === editor.path.toLowerCase())) || Boolean(editor && files.some((file) => file.path !== editor.path && (file.path.toLowerCase().startsWith(editor.path.toLowerCase() + "/") || editor.path.toLowerCase().startsWith(file.path.toLowerCase() + "/"))));
  const projectedBytes = totalBytes - (currentFile?.bytes ?? 0) + draftBytes;
  const validDraft = Boolean(editor && validPath(editor.path, editor.isNew) && validUtf16(editor.draft) && draftBytes <= maxFileBytes && projectedBytes <= maxSiteBytes && !pathCollision && (!editor.isNew || files.length < maxFiles));
  const matchingBase = Boolean(editor && selected?.id === editor.siteId && editor.revision === selected.revision && (editor.isNew ? !currentFile : currentFile?.sha256 === editor.sha256));
  const canSave = Boolean(active && authenticated && fresh && !busy && dirty && validDraft && matchingBase && !conflict && selected?.state !== "recovery_required");
  const canDelete = Boolean(active && authenticated && fresh && !busy && !dirty && !conflict && selected && viewedFile && selected.state !== "recovery_required" && (!editor || (!editor.isNew && matchingBase && editor.path === viewedFile.path)));
  const matchingDelete = Boolean(canDelete && deleteTarget && selected?.id === deleteTarget.siteId && selected.revision === deleteTarget.revision && viewedFile?.path === deleteTarget.path && viewedFile.sha256 === deleteTarget.sha256);
  const uploadCollision = files.some((file) => { const a = file.path.toLowerCase(), b = uploadPath.toLowerCase(); return a === b || a.startsWith(b + "/") || b.startsWith(a + "/"); });
  const uploadProblem = !uploadFile ? "Choose one local static file." : !validPath(uploadPath) ? "Use a relative static-file path up to 200 bytes and 8 segments, with a supported static extension." : uploadCollision ? "This destination already exists or conflicts with a file or folder. Choose a new path; upload never overwrites." : uploadFile.size > maxFileBytes ? "The file exceeds the 2 MiB limit." : files.length >= maxFiles ? "This site has reached the 64-file limit." : totalBytes + uploadFile.size > maxSiteBytes ? "Uploading would exceed the 32 MiB site limit." : undefined;
  const canUpload = Boolean(active && authenticated && fresh && !busy && !dirty && selected && selected.state !== "recovery_required");
  const currentReplacement = files.find((file) => file.path === replaceTarget?.path);
  const matchingReplacement = Boolean(replaceTarget && selected?.id === replaceTarget.siteId && selected.revision === replaceTarget.revision && currentReplacement?.sha256 === replaceTarget.sha256);
  const replacementProblem = !replacementFile ? "Choose one local replacement file." : replacementFile.size > maxFileBytes ? "The replacement exceeds the 2 MiB limit." : totalBytes - (currentReplacement?.bytes ?? 0) + replacementFile.size > maxSiteBytes ? "Replacing this file would exceed the 32 MiB site limit." : undefined;
  const canReplace = canDelete;
  const canConfirmReplacement = Boolean(canUpload && !conflict && matchingReplacement && !replacementProblem);
  const currentRename = files.find((file) => file.path === renameTarget?.path);
  const matchingRename = Boolean(renameTarget && selected?.id === renameTarget.siteId && selected.revision === renameTarget.revision && viewedFile?.path === renameTarget.path && currentRename?.sha256 === renameTarget.sha256 && currentRename.bytes === renameTarget.bytes);
  const renameCollision = files.some((file) => { const a = file.path.toLowerCase(), b = renamePath.toLowerCase(); return a === b || a.startsWith(b + "/") || b.startsWith(a + "/"); });
  const renameProblem = !validPath(renamePath) ? "Use a relative static-file path up to 200 bytes and 8 segments, with a supported static extension." : renamePath.toLowerCase() === renameTarget?.path.toLowerCase() ? "Choose a different path. Case-only changes are not supported." : renameCollision ? "This destination already exists or conflicts with a file or folder." : undefined;
  const canConfirmRename = Boolean(canUpload && !conflict && matchingRename && !renameProblem);
  const clearPrivate = useCallback(() => { setSites([]); setSelected(undefined); setFiles([]); setFresh(false); }, []);
  const fail = useCallback((failure: unknown) => {
    setError(fileError(failure)); setFresh(false);
    if (failure instanceof SiteApiError && failure.status === 401) { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); clearPrivate(); setNotice(undefined); }
  }, [clearPrivate]);

  const loadInventory = useCallback(async (preferredId?: string, isLive: () => boolean = () => true) => {
    if (!isLive()) return;
    const draft = latestEditor.current, wanted = preferredId ?? (dirtyEditor(draft) ? draft?.siteId : selectedId.current);
    if (wanted !== undefined && !/^[a-f0-9]{32}$/.test(wanted)) { selectedId.current = wanted; clearPrivate(); throw new SiteApiError(404, "not_found", "The requested website is unavailable. Choose a website explicitly; your draft is kept."); }
    const list = await siteRequest("/api/v1/sites", validSiteList);
    if (!isLive()) return;
    const chosen = wanted === undefined ? list.items[0] : list.items.find((site) => site.id === wanted);
    if (wanted !== undefined && !chosen) { selectedId.current = wanted; clearPrivate(); setSites(list.items); throw new SiteApiError(404, "not_found", "The requested website is no longer in the inventory. Choose a website explicitly; your draft is kept and saving is disabled."); }
    if (!chosen) { setSites(list.items); setSelected(undefined); setFiles([]); setFresh(true); setLoadedAt(new Date()); return; }
    const [site, catalog] = await Promise.all([siteRequest(siteURL(chosen.id), validSite), siteRequest(siteURL(chosen.id, "/files"), validFileList)]);
    if (!isLive()) return;
    if (site.id !== chosen.id || catalog.items.length > maxFiles || new Set(catalog.items.map((file) => file.path.toLowerCase())).size !== catalog.items.length || catalog.items.some((file) => !validPath(file.path) || file.bytes > maxFileBytes) || catalog.items.reduce((sum, file) => sum + file.bytes, 0) > maxSiteBytes) throw new SiteApiError(0, "invalid_response", "The file inventory did not match the static-site limits or selected website.");
    const previous = latestEditor.current;
    if (dirtyEditor(previous) && previous?.siteId !== site.id) throw new SiteApiError(409, "draft_kept", "Your File Manager draft is kept. Save or discard it, then open the requested website again from Websites.");
    if ((previous && previous.siteId !== site.id) || (!previous && selectedId.current !== site.id)) { setEditor(undefined); latestEditor.current = undefined; setViewedPath(undefined); setConflict(undefined); setFolder(""); setQuery(""); }
    selectedId.current = site.id; setSites(list.items.map((item) => item.id === site.id ? site : item)); setSelected(site); setFiles(catalog.items); setFresh(true); setLoadedAt(new Date());
    const actual = catalog.items.find((file) => file.path === previous?.path);
    if (previous?.siteId === site.id && (previous.revision !== site.revision || (previous.isNew ? Boolean(actual) : actual?.sha256 !== previous.sha256))) setConflict({ path: previous.path, compared: false });
    return { site, catalog };
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
    const request = handoff.current && handoff.current.requestId !== handledHandoff.current ? handoff.current : undefined;
    if (request) {
      handledHandoff.current = request.requestId;
      if (dirtyEditor(latestEditor.current)) { setBusy(undefined); setError(`Cannot open ${request.siteName}: your File Manager draft is kept. Save or discard it, then use Open File Manager in Websites again.`); onHandoffConsumed(request.requestId); return; }
      selectedId.current = request.siteId; setNotice(undefined); clearPrivate(); setEditor(undefined); latestEditor.current = undefined; setViewedPath(undefined); setConflict(undefined);
    }
    const authGeneration = authEpoch.current;
    let token: string | undefined;
    const isLive = () => activeRef.current && generation === epoch.current && authGeneration === authEpoch.current && (token === undefined || (sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now()));
    setBusy("Checking file records"); setFresh(false); setDeleteTarget(undefined); setError(undefined);
    void (async () => {
      try { const next = await siteRequest("/api/v1/session", validSession, { unauthenticatedSession: true }); if (!isLive()) return; sessionRef.current = next; setSession(next); if (next.authenticated) { token = next.csrf_token; await loadInventory(request?.siteId, isLive); } else clearPrivate(); if (isLive()) setLoadedAt(new Date()); }
      catch (failure) { if (isLive()) fail(failure); }
      finally { if (activeRef.current && generation === epoch.current) setBusy(undefined); if (request) onHandoffConsumed(request.requestId); }
    })();
    return () => { if (generation === epoch.current) ++epoch.current; };
  }, [active, revision, attempt, handoffRequestId, onHandoffConsumed, loadInventory, clearPrivate, fail]);
  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => { ++authEpoch.current; sessionRef.current = { authenticated: false }; setSession(sessionRef.current); clearPrivate(); setError("Your operator session expired. Sign in again; your File Manager draft is kept."); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session, clearPrivate]);
  useEffect(() => { if (!dirty) return; const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; }; window.addEventListener("beforeunload", warn); return () => window.removeEventListener("beforeunload", warn); }, [dirty]);
  useEffect(() => {
    if (!active || !authenticated) { deleteDialog.current?.close(); setDeleteTarget(undefined); deleteReturnFocus.current = null; return; }
    if (deleteTarget && deleteDialog.current && !deleteDialog.current.open) deleteDialog.current.showModal();
    else if (!deleteTarget && deleteDialog.current?.open) deleteDialog.current.close();
    if (!deleteTarget && !busy && deleteReturnFocus.current) { if (deleteReturnFocus.current.isConnected) deleteReturnFocus.current.focus(); deleteReturnFocus.current = null; }
  }, [active, authenticated, deleteTarget, busy]);
  useEffect(() => {
    if (!active || !authenticated) { uploadDialog.current?.close(); setUploadOpen(false); uploadReturnFocus.current = null; return; }
    if (uploadOpen && uploadDialog.current && !uploadDialog.current.open) uploadDialog.current.showModal();
    else if (!uploadOpen && uploadDialog.current?.open) uploadDialog.current.close();
    if (!uploadOpen && !busy && uploadReturnFocus.current) { if (uploadReturnFocus.current.isConnected) uploadReturnFocus.current.focus(); uploadReturnFocus.current = null; }
  }, [active, authenticated, uploadOpen, busy]);
  useEffect(() => {
    if (!active || !authenticated) { replacementDialog.current?.close(); setReplaceTarget(undefined); replacementReturnFocus.current = null; return; }
    if (replaceTarget && replacementDialog.current && !replacementDialog.current.open) replacementDialog.current.showModal();
    else if (!replaceTarget && replacementDialog.current?.open) replacementDialog.current.close();
    if (!replaceTarget && !busy && replacementReturnFocus.current) { if (replacementReturnFocus.current.isConnected) replacementReturnFocus.current.focus(); replacementReturnFocus.current = null; }
  }, [active, authenticated, replaceTarget, busy]);
  useEffect(() => { setReplaceTarget(undefined); setReplacementFile(undefined); if (replacementPicker.current) replacementPicker.current.value = ""; }, [session?.authenticated ? session.csrf_token : undefined]);
  useEffect(() => {
    if (!active || !authenticated) { renameDialog.current?.close(); setRenameTarget(undefined); setRenamePath(""); renameReturnFocus.current = null; return; }
    if (renameTarget && renameDialog.current && !renameDialog.current.open) renameDialog.current.showModal();
    else if (!renameTarget && renameDialog.current?.open) renameDialog.current.close();
    if (!renameTarget && !busy && renameReturnFocus.current) { if (renameReturnFocus.current.isConnected) renameReturnFocus.current.focus(); renameReturnFocus.current = null; }
  }, [active, authenticated, renameTarget, busy]);
  useEffect(() => { setRenameTarget(undefined); setRenamePath(""); }, [session?.authenticated ? session.csrf_token : undefined, selected?.id, viewedPath]);
  async function run(label: string, action: (isLive: () => boolean) => Promise<void>) {
    if (!activeRef.current || actionPending.current || busy) return;
    actionPending.current = true; const generation = epoch.current, isLive = () => activeRef.current && generation === epoch.current;
    setBusy(label); setError(undefined); setNotice(undefined);
    try { await action(isLive); if (isLive()) setLoadedAt(new Date()); } catch (failure) { if (isLive()) fail(failure); }
    finally { actionPending.current = false; if (isLive()) setBusy(undefined); else if (activeRef.current) setAttempt((value) => value + 1); }
  }
  const requireClean = () => { if (!dirtyEditor(latestEditor.current)) return true; setError("Save or discard your draft before uploading, replacing, renaming or deleting a file, opening another file, switching websites or signing out. Panel navigation keeps your draft."); return false; };
  async function login(event: React.FormEvent) {
    event.preventDefault(); if (!accessKey.trim()) return; const key = accessKey; setAccessKey("");
    await run("Signing in", async (isLive) => { const next = await siteRequest("/api/v1/session/login", validSession, { method: "POST", body: { access_key: key } }); if (!isLive()) return; if (!next.authenticated) throw new SiteApiError(401, "unauthorized", "The operator access key was not accepted."); sessionRef.current = next; setSession(next); await loadInventory(undefined, isLive); });
  }
  async function openFile(path: string) {
    if (!selected || !requireClean()) return;
    const target = selected; setViewedPath(path);
    await run("Reading file", async (isLive) => {
      try { const file = await readFile(target.id, path); if (!isLive()) return; const next = fromFile(target.id, file); setEditor(next); latestEditor.current = next; setConflict(file.revision === target.revision && files.find((item) => item.path === path)?.sha256 === file.sha256 ? undefined : { path, compared: false }); }
      catch (failure) { if (isLive() && failure instanceof SiteApiError && failure.status === 422) { setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setNotice("Binary asset selected. View its saved size and checksum in File details."); return; } throw failure; }
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
  async function downloadFile() {
    if (!canDownload || !selected || !viewedFile || !session?.authenticated) return;
    const target = selected, file = viewedFile, token = session.csrf_token, authGeneration = authEpoch.current;
    await run("Downloading saved file", async (isLive) => {
      const downloadLive = () => {
        const current = downloadContext.current;
        return isLive() && authGeneration === authEpoch.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now() && current.fresh && current.selected?.id === target.id && current.selected.revision === target.revision && current.viewedFile?.path === file.path && current.viewedFile.sha256 === file.sha256 && current.viewedFile.bytes === file.bytes;
      };
      try {
        const blob = await downloadSiteFile({ siteId: target.id, file, expectedRevision: target.revision, isLive: downloadLive });
        if (!downloadLive()) return;
        const url = URL.createObjectURL(blob), link = document.createElement("a");
        link.href = url; link.download = file.path.split("/").at(-1)!; link.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
        setNotice(`Downloaded saved ${file.path} - revision ${target.revision}. Your editor draft is kept.`);
      } catch (failure) { if (downloadLive()) fail(failure); }
    });
  }
  async function upload(event: React.FormEvent) {
    event.preventDefault();
    if (!canUpload || uploadProblem || !uploadFile || !selected || !session?.authenticated || !requireClean()) return;
    const target = selected, file = uploadFile, path = uploadPath, token = session.csrf_token, authGeneration = authEpoch.current;
    await run("Uploading file", async (isLive) => {
      const uploadLive = () => isLive() && authGeneration === authEpoch.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      try {
        const site = await uploadSiteFile({ siteId: target.id, path, file, expectedRevision: target.revision, csrf: token, isLive: uploadLive });
        if (!uploadLive()) return;
        // A clean editor belongs to the previous revision. Close it before refresh
        // so this unrelated create does not manufacture a stale editor conflict.
        setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setViewedPath(path);
        setUploadOpen(false); setUploadFile(undefined); setUploadPath(""); if (uploadPicker.current) uploadPicker.current.value = ""; setFresh(false);
        await loadInventory(site.id, uploadLive);
        if (uploadLive()) { setViewedPath(path); setNotice(`Uploaded ${path} - revision ${site.revision}.`); }
      } catch (failure) {
        if (uploadLive()) { fail(failure); }
      }
    });
  }
  async function replaceFile(event: React.FormEvent) {
    event.preventDefault();
    if (!canConfirmReplacement || !replaceTarget || !replacementFile || !session?.authenticated || !requireClean()) return;
    const target = replaceTarget, file = replacementFile, token = session.csrf_token, authGeneration = authEpoch.current;
    await run("Replacing file", async (isLive) => {
      const replacementLive = () => isLive() && authGeneration === authEpoch.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      try {
        const site = await replaceSiteFile({ siteId: target.siteId, path: target.path, file, expectedSHA256: target.sha256, expectedRevision: target.revision, csrf: token, isLive: replacementLive });
        if (!replacementLive()) return;
        setEditor(undefined); latestEditor.current = undefined; setConflict(undefined);
        setReplaceTarget(undefined); setReplacementFile(undefined); if (replacementPicker.current) replacementPicker.current.value = ""; setFresh(false);
        await loadInventory(site.id, replacementLive);
        if (replacementLive()) { setViewedPath(target.path); setNotice(`Replaced ${target.path} - revision ${site.revision}. Saved file bytes were updated.`); }
      } catch (failure) { if (replacementLive()) fail(failure); }
    });
  }
  async function refreshRenameTarget() {
    if (!renameTarget || !session?.authenticated || !requireClean() || selectedId.current !== renameTarget.siteId) return;
    const target = renameTarget, token = session.csrf_token, authGeneration = authEpoch.current;
    await run("Refreshing rename target", async (isLive) => {
      const renameLive = () => isLive() && selectedId.current === target.siteId && authGeneration === authEpoch.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      try {
        setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setFresh(false);
        const latest = await loadInventory(target.siteId, renameLive);
        if (!renameLive() || !latest) return;
        const file = latest.catalog.items.find((item) => item.path === target.path);
        if (!file) throw new SiteApiError(404, "not_found", "The saved source no longer exists. Your destination is kept; cancel rename and select another file.");
        setRenameTarget({ ...target, domain: latest.site.domain, revision: latest.site.revision, sha256: file.sha256, bytes: file.bytes });
        setNotice("Latest rename target loaded. Review its revision, bytes and checksum, then confirm explicitly.");
      } catch (failure) { if (renameLive()) fail(failure); }
    });
  }
  async function renameFile(event: React.FormEvent) {
    event.preventDefault();
    if (!canConfirmRename || !renameTarget || !session?.authenticated || !requireClean()) return;
    const target = renameTarget, destination = renamePath, token = session.csrf_token, authGeneration = authEpoch.current;
    await run("Renaming file", async (isLive) => {
      const renameLive = () => isLive() && selectedId.current === target.siteId && authGeneration === authEpoch.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now();
      const sourceLive = () => renameLive() && downloadContext.current.selected?.id === target.siteId && downloadContext.current.selected.revision === target.revision && downloadContext.current.viewedFile?.path === target.path && downloadContext.current.viewedFile.sha256 === target.sha256;
      try {
        const site = await renameSiteFile({ siteId: target.siteId, path: target.path, destination, expectedSHA256: target.sha256, expectedRevision: target.revision, csrf: token, isLive: sourceLive });
        if (!sourceLive()) return;
        setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setFresh(false);
        setSelected(site); setSites((old) => old.map((item) => item.id === site.id ? site : item)); setFiles((old) => old.map((file) => file.path === target.path ? { ...file, path: destination } : file));
        setViewedPath(destination); setFolder(destination.includes("/") ? destination.slice(0, destination.lastIndexOf("/")) : ""); setQuery(""); setRenameTarget(undefined); setRenamePath("");
        const latest = await loadInventory(site.id, renameLive);
        if (!renameLive() || !latest) return;
        const file = latest.catalog.items.find((item) => item.path === destination);
        if (latest.site.revision !== site.revision || latest.catalog.items.some((item) => item.path === target.path) || file?.sha256 !== target.sha256 || file.bytes !== target.bytes) throw new SiteApiError(409, "conflict", "Rename committed, but the website changed before verification. Refresh file records before continuing.");
        setViewedPath(destination); setFolder(destination.includes("/") ? destination.slice(0, destination.lastIndexOf("/")) : ""); setNotice(`Renamed ${target.path} to ${destination} - revision ${site.revision}. Saved bytes preserved.`);
      } catch (failure) { if (renameLive()) fail(failure); }
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
    <div className="hosting-notice"><Info aria-hidden="true" /><span>App-owned static site files - binary uploads and explicit UTF-8 text edits. This is not a server filesystem, FTP client or PHP runtime.</span></div>
    {error && <div className="website-message website-error" role="alert"><Info /><span>{error}</span></div>}{notice && <div className="website-message" role="status"><Info /><span>{notice}</span></div>}
    {!session ? <Card className="dashboard-card website-auth" padding={0}><p role="status">{busy || "Operator session could not be checked."}</p>{error && <Button label="Retry operator session" isDisabled={Boolean(busy)} icon={<RefreshCw />} onClick={() => setAttempt((value) => value + 1)} />}</Card> : !authenticated ? <Card className="dashboard-card website-auth" padding={0}><div className="auth-heading"><LockKeyhole /><div><h2>Local operator sign-in</h2><p>Use the access key created by this server in its private state directory.</p></div></div><form onSubmit={login} data-testid="operator-login" autoComplete="off"><label htmlFor="file-manager-key">Operator access key</label><input id="file-manager-key" type="password" autoComplete="off" spellCheck={false} value={accessKey} onChange={(event) => setAccessKey(event.target.value)} required disabled={Boolean(busy)} /><Button label="Sign in locally" type="submit" variant="primary" isDisabled={Boolean(busy) || !accessKey.trim()} isLoading={busy === "Signing in"} /></form><p className="website-help">The key is cleared after submission. Your draft stays in this browser tab; credentials and drafts are not persisted by File Manager.</p></Card> : <>
      <div className="website-session"><span><LockKeyhole />Signed in locally · expires {dateLabel(session?.authenticated ? session.expires_at : "")}</span><Button label="Sign out locally" icon={<LogOut />} size="sm" variant="ghost" isDisabled={Boolean(busy) || dirty} onClick={() => { if (!requireClean()) return; void run("Signing out", async (isLive) => { if (!session?.authenticated) return; const next = await siteRequest("/api/v1/session/logout", validSession, { method: "POST", csrf: session.csrf_token, body: {} }); if (!isLive()) return; if (next.authenticated) throw new SiteApiError(0, "invalid_response", "Sign-out was not confirmed."); setSession(next); clearPrivate(); setEditor(undefined); latestEditor.current = undefined; setViewedPath(undefined); setConflict(undefined); }); }} /></div>
      <Card className="dashboard-card fm-picker" padding={0}><div><label htmlFor="file-manager-site-picker">Website</label><NativeSelect id="file-manager-site-picker" data-testid="file-manager-site-picker" aria-label="Website for files" value={selected?.id ?? ""} disabled={Boolean(busy) || dirty || !sites.length} onChange={(event) => { if (!requireClean()) return; const id = event.target.value; if (!id) return; setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setViewedPath(undefined); setFolder(""); setQuery(""); setFresh(false); void run("Loading website files", async (isLive) => { await loadInventory(id, isLive); }); }}>{!selected && <NativeSelectOption value="">{sites.length ? "Choose a website" : "No websites available"}</NativeSelectOption>}{sites.map((site) => <NativeSelectOption key={site.id} value={site.id}>{site.name} · {site.domain}</NativeSelectOption>)}</NativeSelect></div><Button label="Refresh file records" variant="secondary" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)} /></Card>
      {selected && <div className="fm-context"><span>{selected.domain} · current revision {selected.revision}</span><span>{files.length} / 64 files · {bytes(totalBytes)} / 32 MiB</span></div>}
      {selected && fresh && files.length === 0 && <p className="fm-status" role="status">This website has no files. Active empty websites serve 404 responses. Upload a static file, add a text file or restore an existing ZIP backup in Websites. New ZIP backups require at least one file.</p>}
      {selected?.state === "recovery_required" && <p className="fm-status" role="alert">This website requires recovery. File changes are disabled until its recovery is resolved.</p>}
      {selected ? <div className="fm-layout">
        <Card className="dashboard-card fm-browser" padding={0} data-testid="file-manager-inventory" data-site-id={selected.id} data-revision={selected.revision} data-fresh={fresh}>
          <div className="card-heading"><h2>Site files</h2><div className="fm-file-actions"><Button label="Upload file" icon={<Upload />} size="sm" variant="secondary" isDisabled={!canUpload || files.length >= maxFiles} onClick={() => { if (!requireClean()) return; uploadReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setUploadOpen(true); }} /><Button label="New text file" icon={<FilePlus />} size="sm" variant="secondary" isDisabled={Boolean(busy) || !fresh || dirty || selected.state === "recovery_required" || files.length >= maxFiles} onClick={() => { if (!requireClean()) return; const next = { siteId: selected.id, path: prefix, draft: "", savedContent: "", sha256: "", revision: selected.revision, isNew: true }; setEditor(next); latestEditor.current = next; setViewedPath(undefined); setConflict(undefined); setError(undefined); }} /></div></div>
          <label className="compact-search"><Search aria-hidden="true" /><input type="search" aria-label="Search files" placeholder="Search all site paths…" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
          <nav className="fm-breadcrumb" aria-label="Site folders"><Button label="Root folder" variant="ghost" size="sm" onClick={() => { setFolder(""); setQuery(""); }}>Root</Button>{folderParts.map((part, index) => <Button key={index} label={`Open folder ${folderParts.slice(0, index + 1).join("/")}`} variant="ghost" size="sm" onClick={() => { setFolder(folderParts.slice(0, index + 1).join("/")); setQuery(""); }}>{part}</Button>)}</nav>
          <div className="fm-file-list">{folders.map((path) => <button key={path} type="button" data-testid="folder-row" data-folder-path={path} aria-label={`Open folder ${path}`} onClick={() => { setFolder(path); setQuery(""); }}><Folder aria-hidden="true" /><span>{path.slice(prefix.length)}</span><small>Folder</small></button>)}{visibleFiles.sort((a, b) => a.path.localeCompare(b.path)).map((file) => <button key={file.path} type="button" data-testid="file-row" data-file-path={file.path} aria-label={`View file ${file.path}`} aria-pressed={viewedPath === file.path} disabled={Boolean(busy) || dirty} onClick={() => void openFile(file.path)}><File aria-hidden="true" /><span>{term ? file.path : file.path.slice(prefix.length)}</span><small>{bytes(file.bytes)}</small></button>)}</div>
          {!visibleFiles.length && !folders.length && <div className="inventory-empty"><Folder /><h3>{term ? "No matching files" : "No reported files in this folder"}</h3><p>{term ? "Try another path or clear the search." : "Folders are derived from the actual file paths returned by the server."}</p></div>}
          <div className="table-footer"><span>{!fresh ? "Records need refreshing" : `${visibleFiles.length} files shown`}</span><span>{loadedAt ? `Checked ${loadedAt.toLocaleTimeString()}` : "Reading inventory"}</span></div>
        </Card>
        <Card className="dashboard-card fm-facts" padding={0} data-testid="file-manager-file-details"><div className="card-heading"><h2>File details</h2><div className="fm-file-actions"><Button label="Open saved file" data-testid="file-manager-open-saved-file" icon={<ArrowUpRight />} href={savedFileHref} target="_blank" rel="noopener noreferrer" size="sm" variant="secondary" isDisabled={!savedFileHref} onClick={(event) => { const current = downloadContext.current; if (!activeRef.current || !sessionRef.current?.authenticated || Date.parse(sessionRef.current.expires_at) <= Date.now() || !current.fresh || current.selected?.state !== "active" || !current.viewedFile || savedFilePreviewURL(current.selected, current.viewedFile.path, validPath) !== savedFileHref) event.preventDefault(); }} /><Button label="Download file" data-testid="file-manager-download" icon={<Download />} size="sm" variant="secondary" isDisabled={!canDownload} isLoading={busy === "Downloading saved file"} onClick={() => void downloadFile()} /><Button label="Replace file" data-testid="file-manager-replace" icon={<Upload />} size="sm" variant="secondary" isDisabled={!canReplace} onClick={() => { if (!canReplace || !viewedFile || !requireClean()) return; replacementReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setReplacementFile(undefined); if (replacementPicker.current) replacementPicker.current.value = ""; setReplaceTarget({ siteId: selected.id, domain: selected.domain, path: viewedFile.path, sha256: viewedFile.sha256, revision: selected.revision, bytes: viewedFile.bytes }); }} /><Button label="Rename / move file" data-testid="file-manager-rename" icon={<Pencil />} size="sm" variant="secondary" isDisabled={!canDelete} onClick={() => { if (!canDelete || !viewedFile || !requireClean()) return; renameReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setRenamePath(viewedFile.path); setRenameTarget({ siteId: selected.id, domain: selected.domain, path: viewedFile.path, sha256: viewedFile.sha256, revision: selected.revision, bytes: viewedFile.bytes }); }} /><Button label="Delete file" data-testid="file-manager-delete" icon={<Trash2 />} size="sm" variant="secondary" isDisabled={!canDelete} onClick={() => { if (!canDelete || !viewedFile || !requireClean()) return; deleteReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setDeleteTarget({ siteId: selected.id, path: viewedFile.path, sha256: viewedFile.sha256, revision: selected.revision }); }} /></div></div>{viewedFile ? <dl><div><dt>Relative path</dt><dd>{viewedFile.path}</dd></div><div><dt>Saved bytes</dt><dd>{bytes(viewedFile.bytes)}</dd></div><div><dt>Inventory revision</dt><dd>{selected.revision}</dd></div><div><dt>SHA-256</dt><dd><code>{viewedFile.sha256}</code></dd></div></dl> : <p>Select a reported file to inspect its saved size and hash.</p>}<p className="website-help">Open saved file uses local HTTP to show saved content. Your unsaved editor draft is kept and is not included in the preview.</p></Card>
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
    {authenticated && <dialog ref={uploadDialog} className="fm-delete-dialog fm-upload-dialog" data-testid="file-manager-upload-dialog" aria-labelledby="fm-upload-title" aria-describedby="fm-upload-description" onClose={(event) => { if (event.target === event.currentTarget && !event.currentTarget.open) setUploadOpen(false); }} onCancel={(event) => {
      // File inputs bubble cancel when the chooser is dismissed or the same file
      // is selected again. Only the dialog's own Escape event dismisses it.
      if (event.target !== event.currentTarget) return;
      if (busy) event.preventDefault(); else setUploadOpen(false);
    }}>
      <form onSubmit={upload}>
        <h2 id="fm-upload-title">Upload one static file</h2>
        <p id="fm-upload-description">Create a new file in <strong>{selected?.domain}</strong> at revision {selected?.revision}. Existing files are never overwritten. Maximum 2 MiB per file, 64 files and 32 MiB per site.</p>
        <label htmlFor="fm-upload-file">Local static file</label><input ref={uploadPicker} id="fm-upload-file" type="file" disabled={Boolean(busy)} onChange={(event) => { const file = event.target.files?.[0]; if (file) { setUploadFile(file); setUploadPath(prefix + file.name); } }} />
        {uploadFile && <p>Selected: {uploadFile.name} - {bytes(uploadFile.size)}</p>}
        <label htmlFor="fm-upload-path">Relative destination path</label><input id="fm-upload-path" value={uploadPath} placeholder="assets/image.png" disabled={Boolean(busy)} onChange={(event) => setUploadPath(event.target.value)} aria-invalid={Boolean(uploadFile && (!validPath(uploadPath) || uploadCollision))} />
        <p className="website-help">HTML, CSS, JavaScript, TXT, SVG, PNG, JPEG, GIF, WebP, ICO, WOFF, WOFF2, TTF and PDF. Parent folders are created from the destination path.</p>
        {uploadProblem && <p role="status">{uploadProblem}</p>}{error && <p className="website-error" role="alert">{error}</p>}
        {!fresh && <Button label="Refresh upload file records" size="sm" variant="secondary" isDisabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)} />}
        <div className="fm-upload-actions"><Button label="Cancel upload" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setUploadOpen(false)} /><Button label="Confirm upload" icon={<Upload />} type="submit" variant="primary" isDisabled={!canUpload || Boolean(uploadProblem)} isLoading={busy === "Uploading file"} /></div>
      </form>
    </dialog>}
    {authenticated && <dialog ref={replacementDialog} className="fm-delete-dialog fm-upload-dialog fm-replace-dialog" data-testid="file-manager-replace-dialog" aria-labelledby="fm-replace-title" aria-describedby="fm-replace-description" onClose={(event) => { if (event.target === event.currentTarget && !event.currentTarget.open) setReplaceTarget(undefined); }} onCancel={(event) => { if (event.target !== event.currentTarget) return; if (busy) event.preventDefault(); else setReplaceTarget(undefined); }}>
      <form onSubmit={replaceFile}>
        <h2 id="fm-replace-title">Replace this saved file?</h2>
        <p id="fm-replace-description">Replace the bytes at <strong>{replaceTarget?.path}</strong> in <strong>{replaceTarget?.domain}</strong>. The destination is fixed; this cannot create a missing file. An existing ZIP backup can restore the old bytes.</p>
        <dl><div><dt>Saved bytes</dt><dd>{bytes(replaceTarget?.bytes ?? 0)}</dd></div><div><dt>Expected website revision</dt><dd>{replaceTarget?.revision}</dd></div><div><dt>Expected SHA-256</dt><dd><code>{replaceTarget?.sha256}</code></dd></div></dl>
        <label htmlFor="fm-replace-file">Local replacement file</label><input ref={replacementPicker} id="fm-replace-file" type="file" disabled={Boolean(busy)} onChange={(event) => { const file = event.target.files?.[0]; if (file) setReplacementFile(file); }} />
        {replacementFile && <p>Selected: {replacementFile.name} - {bytes(replacementFile.size)}</p>}
        <p className="website-help">Maximum 2 MiB per file and 32 MiB per site. Replacing an existing file does not consume another file slot. Local bytes are preserved without text decoding.</p>
        {replacementProblem && <p role="status">{replacementProblem}</p>}{error && <p className="website-error" role="alert">{error}</p>}
        {(!fresh || !matchingReplacement) && <><p role="status">The captured target needs review. Refresh records, then explicitly review the latest target before confirming. Your selected replacement is kept.</p><Button label="Refresh replacement records" icon={<RefreshCw />} size="sm" variant="secondary" isDisabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)} /></>}
        {fresh && !matchingReplacement && (currentReplacement && selected && selected.id === replaceTarget?.siteId ? <><p>Latest revision {selected.revision} - saved bytes {bytes(currentReplacement.bytes)} - SHA-256 {currentReplacement.sha256}</p><Button label="Review latest replacement target" size="sm" variant="secondary" isDisabled={!canUpload || Boolean(conflict)} onClick={() => { if (!selected || !currentReplacement || !replaceTarget || !canUpload || conflict) return; setReplaceTarget({ ...replaceTarget, domain: selected.domain, bytes: currentReplacement.bytes, sha256: currentReplacement.sha256, revision: selected.revision }); setError(undefined); }} /></> : <p role="alert">The saved target no longer exists. Cancel replacement; a missing file cannot be created here.</p>)}
        {conflict && <p role="status">Compare or discard the retained editor version before replacing this file.</p>}
        <div className="fm-upload-actions"><Button label="Cancel replacement" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setReplaceTarget(undefined)} /><Button label="Confirm replacement" icon={<Upload />} type="submit" variant="primary" isDisabled={!canConfirmReplacement} isLoading={busy === "Replacing file"} /></div>
      </form>
    </dialog>}
    {authenticated && <dialog ref={renameDialog} className="fm-delete-dialog fm-upload-dialog fm-replace-dialog" data-testid="file-manager-rename-dialog" aria-labelledby="fm-rename-title" aria-describedby="fm-rename-description" onClose={(event) => { if (event.target === event.currentTarget && !event.currentTarget.open) setRenameTarget(undefined); }} onCancel={(event) => { if (event.target !== event.currentTarget) return; if (busy) event.preventDefault(); else setRenameTarget(undefined); }}>
      <form onSubmit={renameFile}>
        <h2 id="fm-rename-title">Rename or move this saved file?</h2>
        <p id="fm-rename-description">Move <strong>{renameTarget?.path}</strong> within <strong>{renameTarget?.domain}</strong>. Saved bytes stay unchanged. Existing files and folders cannot be overwritten.</p>
        <dl><div><dt>Saved bytes</dt><dd>{bytes(renameTarget?.bytes ?? 0)}</dd></div><div><dt>Expected website revision</dt><dd>{renameTarget?.revision}</dd></div><div><dt>Expected SHA-256</dt><dd><code>{renameTarget?.sha256}</code></dd></div></dl>
        <label htmlFor="fm-rename-path">Relative destination path</label><input id="fm-rename-path" data-testid="file-manager-rename-path" value={renamePath} placeholder="assets/image.png" disabled={Boolean(busy)} onChange={(event) => setRenamePath(event.target.value)} aria-invalid={Boolean(renameProblem)} />
        <p className="website-help">Parent folders are created from the relative path. Links and references inside HTML or CSS are not rewritten. Renaming index.html makes the website root return 404. Rename back to restore the old URL, or restore an existing ZIP backup.</p>
        {renameProblem && <p role="status">{renameProblem}</p>}{error && <p className="website-error" role="alert">{error}</p>}
        {(!fresh || !matchingRename) && <><p role="status">Refresh this rename target and review its latest revision and checksum before confirming. Your destination path is kept. A refresh never submits the rename.</p><Button label="Refresh rename target" data-testid="file-manager-rename-refresh" icon={<RefreshCw />} size="sm" variant="secondary" isDisabled={Boolean(busy) || dirty || selected?.id !== renameTarget?.siteId} onClick={() => void refreshRenameTarget()} /></>}
        <div className="fm-upload-actions"><Button label="Cancel rename" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setRenameTarget(undefined)} /><Button label="Rename / move" data-testid="file-manager-rename-confirm" icon={<Pencil />} type="submit" variant="primary" isDisabled={!canConfirmRename} isLoading={busy === "Renaming file"} /></div>
      </form>
    </dialog>}
    {authenticated && <dialog ref={deleteDialog} className="fm-delete-dialog" data-testid="file-manager-delete-dialog" aria-labelledby="fm-delete-title" aria-describedby="fm-delete-description" onClose={() => setDeleteTarget(undefined)} onCancel={(event) => { if (busy) event.preventDefault(); else setDeleteTarget(undefined); }}><h2 id="fm-delete-title">Delete this file?</h2><p id="fm-delete-description">Remove <strong>{deleteTarget?.path}</strong> from this website at revision {deleteTarget?.revision}. The file will stop being served. An existing ZIP backup can restore it.</p>{files.length === 1 && <p>This is the last file. An active empty website serves 404 responses; new ZIP backups require at least one file.</p>}<div><Button label="Cancel deletion" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setDeleteTarget(undefined)} /><Button label="Confirm file deletion" icon={<Trash2 />} variant="primary" isDisabled={!matchingDelete} isLoading={busy === "Deleting file"} onClick={() => void deleteFile()} /></div></dialog>}
    {busy && <p className="website-busy" role="status">{busy}…</p>}
  </section>;
}
