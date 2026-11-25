import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { cn } from "cn";
import { ArrowUpRight, Check, ChevronRight, CircleAlert, Download, File, FilePlus, Folder, Info, LoaderCircle, LockKeyhole, LogOut, Pencil, RefreshCw, Save, Search, Trash2, TriangleAlert, Upload } from "lucide-react";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { bytes, panel, TechnicalDetails } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import type { SiteHandoff } from "@/App";
import { SiteApiError, downloadSiteFile, uploadSiteFile, replaceSiteFile, renameSiteFile, savedFilePreviewURL, siteRequest, siteURL, validFileContent, validFileList, validSession, validSite, validSiteList } from "@/lib/sites-api";
import type { OperatorSession, Site, SiteFile, SiteFileContent } from "@/lib/sites-api";
import { reviewMultiUpload, uploadMultipleFiles } from "@/lib/multiUpload";
import type { UploadEntry, UploadOutcome } from "@/lib/multiUpload";

// The base styles colour <p>, clear the margins of headings, p and dl, and size
// inputs and buttons outside Tailwind's layers, so coloured text uses div or
// span and a few sizes and margins carry "!", as on the other rebuilt screens.
const muted = "text-xs text-muted-foreground wrap-anywhere";
const fieldLabel = "text-sm font-medium text-foreground";
const field = "flex min-w-0 flex-col gap-1.5";
const input = "h-9! text-base! md:text-sm! pointer-coarse:h-11!";
const touch = "pointer-coarse:h-11";
const fileInput = "w-full min-w-0 text-sm text-foreground file:me-3 file:rounded-md file:border file:border-input file:bg-card file:px-2.5 file:py-1.5 file:text-sm file:font-medium file:text-foreground disabled:opacity-65";
const dialogClass = "fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-[min(32.5rem,calc(100vw-1.75rem))] overflow-auto overscroll-contain rounded-xl border border-border bg-card p-5 text-foreground shadow-xl backdrop:overflow-hidden backdrop:overscroll-contain backdrop:bg-[rgb(8_14_22/58%)]";
const dialogTitle = "pb-1 text-lg! tracking-tight!";
const dialogText = "mt-2 text-sm text-muted-foreground wrap-anywhere";
const dialogForm = "mt-5 flex flex-col gap-3.5";
const dialogActions = "mt-2 flex flex-wrap justify-end gap-2";
const dialogStatus = "text-sm text-foreground wrap-anywhere";
const dialogError = "text-sm text-destructive wrap-anywhere";
// A refresh-and-review box inside a dialog, shown when its target changed.
const refreshBox = "flex flex-col items-start gap-2.5 rounded-md border border-input bg-muted p-3 text-sm text-foreground wrap-anywhere";
// A file or folder row. Rows sit in a scrolling list, so their focus outline is drawn inside them.
const row = "flex w-full items-center gap-3 rounded-sm px-2.5 py-2 text-start text-sm text-foreground focus-visible:-outline-offset-2! enabled:hover:bg-muted disabled:cursor-default disabled:opacity-65 aria-pressed:bg-secondary aria-pressed:text-primary";
const uploadList = "flex max-h-70 min-w-0 list-none flex-col gap-2.5 overflow-y-auto rounded-md border border-border p-3 text-sm";
const spinner = <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" />;

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return <div className="min-w-0"><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 text-sm text-foreground wrap-anywhere">{children}</dd></div>;
}

interface Editor { siteId: string; path: string; draft: string; savedContent: string; sha256: string; revision: number; isNew: boolean }
interface Conflict { path: string; revision?: number; file?: SiteFileContent; compared: boolean }
interface ReplaceTarget { siteId: string; domain: string; path: string; sha256: string; revision: number; bytes: number }
interface DeleteTarget { siteId: string; path: string; sha256: string; revision: number }
interface MultiUploadTarget { site: Site; folder: string; entries: UploadEntry[] }
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
  const [multiTarget, setMultiTarget] = useState<MultiUploadTarget>();
  const [multiOutcomes, setMultiOutcomes] = useState<UploadOutcome[]>();
  const [multiFinished, setMultiFinished] = useState(false);
  const [multiStopping, setMultiStopping] = useState(false);
  const multiDialog = useRef<HTMLDialogElement>(null), multiPicker = useRef<HTMLInputElement>(null), multiReturnFocus = useRef<HTMLElement | null>(null);
  const multiGeneration = useRef(0), multiStop = useRef(false);
  const currentFolder = useRef(folder); currentFolder.current = folder;
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
  const multiReview = multiTarget ? reviewMultiUpload(multiTarget.entries, files, validPath) : undefined;
  const matchingMulti = Boolean(multiTarget && selected?.id === multiTarget.site.id && selected.revision === multiTarget.site.revision && folder === multiTarget.folder);
  const canConfirmMulti = Boolean(canUpload && !conflict && matchingMulti && !multiFinished && !multiReview?.problem);
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
    if (!active || !authenticated) { multiDialog.current?.close(); closeMultiUpload(); multiReturnFocus.current = null; return; }
    if (multiTarget && multiDialog.current && !multiDialog.current.open) multiDialog.current.showModal();
    else if (!multiTarget && multiDialog.current?.open) multiDialog.current.close();
    if (!multiTarget && !busy && multiReturnFocus.current) { if (multiReturnFocus.current.isConnected) multiReturnFocus.current.focus(); multiReturnFocus.current = null; }
  }, [active, authenticated, multiTarget, busy]);
  useEffect(() => { closeMultiUpload(); }, [session?.authenticated ? session.csrf_token : undefined, selected?.id, folder, revision, handoffRequestId]);
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
  function closeMultiUpload() {
    ++multiGeneration.current; multiStop.current = true;
    setMultiTarget(undefined); setMultiOutcomes(undefined); setMultiFinished(false); setMultiStopping(false);
    if (multiPicker.current) multiPicker.current.value = "";
  }
  async function uploadMany(event: React.FormEvent) {
    event.preventDefault();
    if (!canConfirmMulti || !multiTarget || !session?.authenticated || !requireClean()) return;
    const target = multiTarget, token = session.csrf_token, authGeneration = authEpoch.current, generation = multiGeneration.current;
    multiStop.current = false; setMultiStopping(false);
    await run("Uploading selected files", async (isLive) => {
      const contextLive = () => isLive() && generation === multiGeneration.current && selectedId.current === target.site.id && currentFolder.current === target.folder && authGeneration === authEpoch.current && sessionRef.current?.authenticated === true && sessionRef.current.csrf_token === token && Date.parse(sessionRef.current.expires_at) > Date.now() && !dirtyEditor(latestEditor.current);
      const uploadLive = () => contextLive() && downloadContext.current.fresh && downloadContext.current.selected?.id === target.site.id && downloadContext.current.selected.revision === target.site.revision;
      const result = await uploadMultipleFiles({ site: target.site, entries: target.entries, catalog: files, validPath, csrf: token, isLive: uploadLive, shouldStop: () => multiStop.current, onProgress: (outcomes) => { if (uploadLive()) setMultiOutcomes(outcomes); } });
      if (!uploadLive()) return;
      setMultiOutcomes(result.outcomes); setMultiFinished(true);
      const saved = result.outcomes.filter((outcome) => outcome.status === "saved");
      if (saved.length || result.failure) setFresh(false);
      if (saved.length) { setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setViewedPath(saved.at(-1)!.path); }
      if (result.failure) { fail(result.failure); return; }
      if (saved.length) {
        try { await loadInventory(target.site.id, contextLive); }
        catch (failure) { if (contextLive()) fail(failure); }
      }
      if (contextLive()) setNotice(`Saved ${saved.length} of ${result.outcomes.length} selected files. ${result.outcomes.length - saved.length} not attempted. Each saved file is a separate change.`);
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

  return <section className="@container flex min-w-0 flex-col gap-3" data-testid="file-manager-page">
    <div className="flex items-start gap-2 text-xs text-muted-foreground"><Info className="mt-px size-4 shrink-0" aria-hidden="true" /><span className="wrap-anywhere">App-owned static site files - binary uploads and explicit UTF-8 text edits. This is not a server filesystem, FTP client or PHP runtime.</span></div>
    {error && <Alert variant="destructive" className="text-start"><CircleAlert aria-hidden="true" /><AlertTitle className="wrap-anywhere">{error}</AlertTitle></Alert>}{notice && <Alert role="status" className="text-start"><Check className="text-primary" aria-hidden="true" /><AlertTitle className="wrap-anywhere">{notice}</AlertTitle></Alert>}
    {!session ? <section className={cn(panel, "max-w-xl p-5")} aria-label="Operator session">
      <div role="status" className="text-sm text-foreground">{busy || "Operator session could not be checked."}</div>
      {error && <Button variant="outline" className={cn("mt-3 h-9", touch)} disabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)}><RefreshCw aria-hidden="true" />Retry operator session</Button>}
    </section> : !authenticated ? <section className={cn(panel, "max-w-xl p-5")} aria-labelledby="file-manager-sign-in-heading">
      <div className="flex items-start gap-3.5">
        <LockKeyhole className="size-6 shrink-0 text-primary" aria-hidden="true" />
        <div className="min-w-0"><h2 id="file-manager-sign-in-heading">Local operator sign-in</h2><div className="mt-1.5 text-sm text-muted-foreground wrap-anywhere">Use the access key created by this server in its private state directory.</div></div>
      </div>
      <form onSubmit={login} data-testid="operator-login" autoComplete="off" className="mt-6 flex flex-col items-start gap-2.5">
        <label htmlFor="file-manager-key" className={fieldLabel}>Operator access key</label>
        <Input id="file-manager-key" type="password" autoComplete="off" spellCheck={false} value={accessKey} onChange={(event) => setAccessKey(event.target.value)} required disabled={Boolean(busy)} className={cn("max-w-sm", input)} />
        <Button type="submit" className={cn("mt-1 h-9", touch)} disabled={Boolean(busy) || !accessKey.trim()}>{busy === "Signing in" && spinner}Sign in locally</Button>
      </form>
      <div className="mt-5 text-xs text-muted-foreground">The key is cleared after submission. Your draft stays in this browser tab; credentials and drafts are not persisted by File Manager.</div>
    </section> : <>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span className="flex min-w-0 flex-1 basis-56 items-center gap-2 wrap-anywhere"><LockKeyhole className="size-4 shrink-0" aria-hidden="true" />Signed in locally · expires {dateLabel(session?.authenticated ? session.expires_at : "")}</span>
        <Button variant="ghost" size="sm" className={touch} disabled={Boolean(busy) || dirty} onClick={() => { if (!requireClean()) return; void run("Signing out", async (isLive) => { if (!session?.authenticated) return; const next = await siteRequest("/api/v1/session/logout", validSession, { method: "POST", csrf: session.csrf_token, body: {} }); if (!isLive()) return; if (next.authenticated) throw new SiteApiError(0, "invalid_response", "Sign-out was not confirmed."); setSession(next); clearPrivate(); setEditor(undefined); latestEditor.current = undefined; setViewedPath(undefined); setConflict(undefined); }); }}><LogOut aria-hidden="true" />Sign out locally</Button>
      </div>
      <div className={cn(panel, "flex min-w-0 flex-wrap items-end gap-3 p-4")}>
        <div className="flex min-w-0 flex-1 basis-64 flex-col gap-1.5 @3xl:max-w-xl"><label htmlFor="file-manager-site-picker" className={fieldLabel}>Website</label><NativeSelect id="file-manager-site-picker" data-testid="file-manager-site-picker" aria-label="Website for files" className="w-full" value={selected?.id ?? ""} disabled={Boolean(busy) || dirty || !sites.length} onChange={(event) => { if (!requireClean()) return; const id = event.target.value; if (!id) return; setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setViewedPath(undefined); setFolder(""); setQuery(""); setFresh(false); void run("Loading website files", async (isLive) => { await loadInventory(id, isLive); }); }}>{!selected && <NativeSelectOption value="">{sites.length ? "Choose a website" : "No websites available"}</NativeSelectOption>}{sites.map((site) => <NativeSelectOption key={site.id} value={site.id}>{site.name} · {site.domain}</NativeSelectOption>)}</NativeSelect></div>
        <Button variant="outline" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)}><RefreshCw aria-hidden="true" />Refresh file records</Button>
      </div>
      {selected && <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-xs text-muted-foreground"><span className="wrap-anywhere">{selected.domain} · current revision {selected.revision}</span><span>{files.length} / 64 files · {bytes(totalBytes)} / 32 MiB</span></div>}
      {selected && fresh && files.length === 0 && <div className="text-sm text-foreground" role="status">This website has no files. Active empty websites serve 404 responses. Upload a static file, add a text file or restore an existing ZIP backup in Websites. New ZIP backups require at least one file.</div>}
      {selected?.state === "recovery_required" && <Alert variant="destructive" className="text-start"><TriangleAlert aria-hidden="true" /><AlertTitle className="wrap-anywhere">This website requires recovery. File changes are disabled until its recovery is resolved.</AlertTitle></Alert>}
      {selected ? <div className="grid min-w-0 grid-cols-1 items-start gap-3 @4xl:grid-cols-[minmax(0,1.6fr)_minmax(16.25rem,1fr)]">
        <section className={cn(panel, "min-w-0")} aria-labelledby="file-manager-files-heading" data-testid="file-manager-inventory" data-site-id={selected.id} data-revision={selected.revision} data-fresh={fresh}>
          <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3.5"><h2 id="file-manager-files-heading" className="text-sm!">Site files</h2><div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" className={touch} disabled={!canUpload || files.length >= maxFiles} onClick={() => { if (!requireClean()) return; uploadReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setUploadOpen(true); }}><Upload aria-hidden="true" />Upload file</Button>
            <Button variant="outline" size="sm" className={touch} data-testid="file-manager-multi-upload" disabled={!canUpload || Boolean(conflict) || files.length >= maxFiles} onClick={() => { if (!canUpload || conflict || !requireClean()) return; multiReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; ++multiGeneration.current; multiStop.current = false; setMultiOutcomes(undefined); setMultiFinished(false); setMultiStopping(false); setError(undefined); setMultiTarget({ site: selected, folder, entries: [] }); }}><Upload aria-hidden="true" />Upload multiple files</Button>
            <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || !fresh || dirty || selected.state === "recovery_required" || files.length >= maxFiles} onClick={() => { if (!requireClean()) return; const next = { siteId: selected.id, path: prefix, draft: "", savedContent: "", sha256: "", revision: selected.revision, isNew: true }; setEditor(next); latestEditor.current = next; setViewedPath(undefined); setConflict(undefined); setError(undefined); }}><FilePlus aria-hidden="true" />New text file</Button>
          </div></div>
          <div className="relative mx-4"><Search className="pointer-events-none absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" /><Input type="search" aria-label="Search files" placeholder="Search all site paths…" value={query} onChange={(event) => setQuery(event.target.value)} autoComplete="off" spellCheck={false} className="ps-8 pointer-coarse:h-11!" /></div>
          <nav className="flex flex-wrap items-center gap-0.5 px-2.5 py-2" aria-label="Site folders">
            <Button variant="ghost" size="sm" className={touch} aria-label="Root folder" onClick={() => { setFolder(""); setQuery(""); }}>Root</Button>
            {folderParts.map((part, index) => <span key={index} className="flex min-w-0 items-center gap-0.5"><ChevronRight className="size-3.5 shrink-0 text-muted-foreground rtl:-scale-x-100" aria-hidden="true" /><Button variant="ghost" size="sm" className={cn("h-auto min-h-7 whitespace-normal wrap-anywhere", touch)} aria-label={`Open folder ${folderParts.slice(0, index + 1).join("/")}`} onClick={() => { setFolder(folderParts.slice(0, index + 1).join("/")); setQuery(""); }}>{part}</Button></span>)}
          </nav>
          <div className="max-h-90 overflow-y-auto px-2 pb-2">{folders.map((path) => <button key={path} type="button" className={row} data-testid="folder-row" data-folder-path={path} aria-label={`Open folder ${path}`} onClick={() => { setFolder(path); setQuery(""); }}><Folder className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" /><span className="min-w-0 wrap-anywhere">{path.slice(prefix.length)}</span><span className="ms-auto shrink-0 text-xs text-muted-foreground">Folder</span></button>)}{visibleFiles.sort((a, b) => a.path.localeCompare(b.path)).map((file) => <button key={file.path} type="button" className={row} data-testid="file-row" data-file-path={file.path} aria-label={`View file ${file.path}`} aria-pressed={viewedPath === file.path} disabled={Boolean(busy) || dirty} onClick={() => void openFile(file.path)}><File className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" /><span className="min-w-0 wrap-anywhere">{term ? file.path : file.path.slice(prefix.length)}</span><span className="ms-auto shrink-0 text-xs text-muted-foreground tabular-nums">{bytes(file.bytes)}</span></button>)}</div>
          {!visibleFiles.length && !folders.length && <div className="flex flex-col items-center gap-2 px-4 pt-4 pb-8 text-center"><Folder className="size-5.5 text-muted-foreground" aria-hidden="true" /><h3>{term ? "No matching files" : "No reported files in this folder"}</h3><div className="text-sm text-muted-foreground">{term ? "Try another path or clear the search." : "Folders are derived from the actual file paths returned by the server."}</div></div>}
          <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-border px-4 py-2.5 text-xs text-muted-foreground"><span>{!fresh ? "Records need refreshing" : `${visibleFiles.length} files shown`}</span><span>{loadedAt ? `Checked ${loadedAt.toLocaleTimeString()}` : "Reading inventory"}</span></div>
        </section>
        <section className={cn(panel, "min-w-0")} aria-labelledby="file-manager-details-heading" data-testid="file-manager-file-details">
          <div className="flex flex-col gap-3 px-4 py-3.5"><h2 id="file-manager-details-heading" className="text-sm!">File details</h2><div className="flex flex-wrap gap-2">
            {/* A link only while the saved file can open; otherwise a disabled button. The
                link is sized by hand to match the buttons, whose font and height the base styles set. */}
            {savedFileHref ? <a href={savedFileHref} target="_blank" rel="noopener noreferrer" data-testid="file-manager-open-saved-file" className={buttonVariants({ variant: "outline", size: "sm", className: cn("min-h-7.5 text-sm! font-normal", touch) })} onClick={(event) => { const current = downloadContext.current; if (!activeRef.current || !sessionRef.current?.authenticated || Date.parse(sessionRef.current.expires_at) <= Date.now() || !current.fresh || current.selected?.state !== "active" || !current.viewedFile || savedFilePreviewURL(current.selected, current.viewedFile.path, validPath) !== savedFileHref) event.preventDefault(); }}><ArrowUpRight className="rtl:-scale-x-100" aria-hidden="true" />Open saved file</a> : <Button variant="outline" size="sm" className={touch} data-testid="file-manager-open-saved-file" disabled><ArrowUpRight className="rtl:-scale-x-100" aria-hidden="true" />Open saved file</Button>}
            <Button variant="outline" size="sm" className={touch} data-testid="file-manager-download" disabled={!canDownload} onClick={() => void downloadFile()}>{busy === "Downloading saved file" ? spinner : <Download aria-hidden="true" />}Download file</Button>
            <Button variant="outline" size="sm" className={touch} data-testid="file-manager-replace" disabled={!canReplace} onClick={() => { if (!canReplace || !viewedFile || !requireClean()) return; replacementReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setReplacementFile(undefined); if (replacementPicker.current) replacementPicker.current.value = ""; setReplaceTarget({ siteId: selected.id, domain: selected.domain, path: viewedFile.path, sha256: viewedFile.sha256, revision: selected.revision, bytes: viewedFile.bytes }); }}><Upload aria-hidden="true" />Replace file</Button>
            <Button variant="outline" size="sm" className={touch} data-testid="file-manager-rename" disabled={!canDelete} onClick={() => { if (!canDelete || !viewedFile || !requireClean()) return; renameReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setRenamePath(viewedFile.path); setRenameTarget({ siteId: selected.id, domain: selected.domain, path: viewedFile.path, sha256: viewedFile.sha256, revision: selected.revision, bytes: viewedFile.bytes }); }}><Pencil aria-hidden="true" />Rename / move file</Button>
            <Button variant="destructive" size="sm" className={touch} data-testid="file-manager-delete" disabled={!canDelete} onClick={() => { if (!canDelete || !viewedFile || !requireClean()) return; deleteReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setError(undefined); setDeleteTarget({ siteId: selected.id, path: viewedFile.path, sha256: viewedFile.sha256, revision: selected.revision }); }}><Trash2 aria-hidden="true" />Delete file</Button>
          </div></div>
          {viewedFile ? <div className="flex flex-col gap-3 px-4 pb-3"><dl className="grid grid-cols-1 gap-3 @xl:@max-4xl:grid-cols-2"><Fact label="Relative path">{viewedFile.path}</Fact><Fact label="Saved bytes">{bytes(viewedFile.bytes)}</Fact></dl><TechnicalDetails>Inventory revision {selected.revision}{"\n"}SHA-256 {viewedFile.sha256}</TechnicalDetails></div> : <div className="px-4 pb-3 text-sm text-muted-foreground">Select a reported file to inspect its saved size and hash.</div>}
          <div className="px-4 pb-4 text-xs text-muted-foreground">Open saved file uses local HTTP to show saved content. Your unsaved editor draft is kept and is not included in the preview.</div>
        </section>
      </div> : <section className={cn(panel, "flex flex-col items-center gap-2 px-4 py-8 text-center")} aria-labelledby="file-manager-none-heading"><Folder className="size-5.5 text-muted-foreground" aria-hidden="true" /><h2 id="file-manager-none-heading" className="text-base!">{busy ? "Loading website files" : error ? "File records unavailable" : "No websites available"}</h2><div className="max-w-[52ch] text-sm text-muted-foreground">{busy ? "Reading the actual app-owned site inventory." : error ? "Refresh records to check the current inventory. Retained drafts remain below." : "Create an app-owned static site in Websites to manage its files."}</div></section>}
      {editor && <section className={cn(panel, "min-w-0")} aria-labelledby="file-manager-editor-heading"><form onSubmit={save} data-testid="file-manager-editor" data-file-path={editor.path} data-read-revision={editor.revision} data-read-sha256={editor.sha256}>
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3.5"><div className="min-w-0"><h2 id="file-manager-editor-heading" className="text-sm! wrap-anywhere">{editor.isNew ? "New UTF-8 text file" : editor.path}</h2><div className="mt-1 text-xs text-muted-foreground">{dirty ? "Unsaved draft" : "Saved version"}</div></div><Button type="submit" size="sm" className={touch} disabled={!canSave}>{busy === "Saving file" ? spinner : <Save aria-hidden="true" />}Save file</Button></div>
        <div className="flex flex-col gap-3 p-4">{editor.isNew && <div className={field}><label htmlFor="fm-new-path" className={fieldLabel}>Relative file path</label><Input id="fm-new-path" value={editor.path} onChange={(event) => { const next = { ...editor, path: event.target.value }; setEditor(next); latestEditor.current = next; setConflict(undefined); }} placeholder="assets/style.css" required disabled={Boolean(busy)} aria-invalid={!validPath(editor.path, true)} autoComplete="off" spellCheck={false} className={input} /></div>}
          <div className={field}><label htmlFor="fm-content" className={fieldLabel}>File content</label><Textarea id="fm-content" dir="ltr" value={editor.draft} onChange={(event) => { const next = { ...editor, draft: event.target.value }; setEditor(next); latestEditor.current = next; }} spellCheck={false} disabled={Boolean(busy) || selected?.state === "recovery_required"} aria-describedby="fm-draft-limits" className="field-sizing-fixed h-75 min-h-60 resize-y bg-card text-start font-mono text-xs! leading-relaxed [tab-size:2] max-sm:h-60" /></div>
          <div className="flex flex-wrap items-center justify-between gap-3"><span id="fm-draft-limits" className={muted}>{draftBytes.toLocaleString()} / {maxFileBytes.toLocaleString()} UTF-8 bytes · projected site {bytes(projectedBytes)}</span><Button variant="ghost" size="sm" className={touch} disabled={Boolean(busy)} onClick={() => { setEditor(undefined); latestEditor.current = undefined; setConflict(undefined); setError(undefined); }}>Discard draft</Button></div>
          <TechnicalDetails>Read revision {editor.revision}</TechnicalDetails>
          {draftProblem && <div className="text-sm text-destructive wrap-anywhere" role="status">{draftProblem}</div>}
          {(conflict || (!matchingBase && fresh)) && <div className="flex flex-col items-start gap-2.5 rounded-lg border border-input bg-muted p-3.5" data-testid="file-manager-conflict" role="status"><h3>Draft kept · server comparison required</h3><div className="text-sm text-foreground wrap-anywhere">Read the current server version, compare it with your draft, then explicitly accept its revision before saving.</div><Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || !validPath(editor.path, editor.isNew)} onClick={() => void compareLatest()}><RefreshCw aria-hidden="true" />Read latest server version</Button>{conflict?.compared && conflict.path === editor.path && <><div className="text-sm text-foreground wrap-anywhere">Current revision {conflict.revision}{conflict.file ? "" : " · No file exists at this path in the latest inventory."}</div>{conflict.file && <><details className="w-full text-sm"><summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Compare latest server content</summary><pre dir="ltr" className="mt-2 max-h-60 overflow-auto rounded-md border border-border bg-card p-3 text-start font-mono text-xs whitespace-pre-wrap text-foreground wrap-anywhere">{conflict.file.content}</pre></details><div className="w-full"><TechnicalDetails>SHA-256 {conflict.file.sha256}</TechnicalDetails></div></>}<Button variant="outline" size="sm" className={touch} disabled={Boolean(busy) || !fresh} onClick={() => { if (!conflict.compared || conflict.revision === undefined || conflict.path !== editor.path) return; const next = { ...editor, savedContent: conflict.file?.content ?? "", sha256: conflict.file?.sha256 ?? "", revision: conflict.revision, isNew: !conflict.file }; setEditor(next); latestEditor.current = next; setConflict(undefined); setError(undefined); }}>Keep draft and use latest revision</Button></>}</div>}
        </div>
      </form></section>}
    </>}
    {authenticated && <dialog ref={multiDialog} className={cn(dialogClass, "w-[min(40rem,calc(100vw-1.75rem))]")} data-testid="file-manager-multi-upload-dialog" aria-labelledby="fm-multi-upload-title" aria-describedby="fm-multi-upload-description" onClose={(event) => { if (event.target === event.currentTarget && !event.currentTarget.open) closeMultiUpload(); }} onCancel={(event) => { if (event.target !== event.currentTarget) return; if (busy) event.preventDefault(); else closeMultiUpload(); }}>
      <h1 id="fm-multi-upload-title" className={dialogTitle}>Upload multiple static files</h1>
      <div id="fm-multi-upload-description" className={dialogText}>Review new files for <strong className="font-semibold text-foreground">{multiTarget?.site.domain}</strong>, folder <strong className="font-semibold text-foreground">{multiTarget?.folder || "Root"}</strong>, at revision {multiTarget?.site.revision}. Files are saved one at a time. A refusal stops the batch; files already saved remain saved. Existing files are never overwritten.</div>
      <form onSubmit={uploadMany} className={dialogForm}>
        <div className={field}><label htmlFor="fm-multi-upload-files" className={fieldLabel}>Local static files</label><input ref={multiPicker} id="fm-multi-upload-files" type="file" multiple className={fileInput} disabled={Boolean(busy) || multiFinished || !matchingMulti || !fresh} onChange={(event) => {
          const chosen = event.target.files;
          if (!chosen?.length || !multiTarget || !matchingMulti || !canUpload) return;
          const destinationPrefix = multiTarget.folder ? `${multiTarget.folder}/` : "";
          setMultiTarget({ ...multiTarget, entries: Array.from(chosen, (file) => ({ file, path: destinationPrefix + file.name })) }); setMultiOutcomes(undefined); setError(undefined);
        }} /><span className={muted}>Select filenames for this folder. Use Upload file to customize a single destination. Maximum 2 MiB per file, 64 files and 32 MiB per site. File bytes are validated by the server when each upload is attempted.</span></div>
        {!multiOutcomes && multiReview && <div className="flex min-w-0 flex-col gap-2.5" data-testid="file-manager-multi-upload-review"><div className={dialogStatus}>{multiTarget?.entries.length ?? 0} selected · {bytes(multiReview.addedBytes)} to add · site {bytes(totalBytes)} / 32 MiB</div>{multiReview.problem && <div className={dialogError} role="status">{multiReview.problem}</div>}
          {multiReview.entries.length > 0 && <ol className={uploadList}>{multiReview.entries.map((entry, index) => <li key={index} className="min-w-0 wrap-anywhere"><strong className="block font-medium text-foreground">{entry.path}</strong><span className="mt-1 block text-xs text-muted-foreground">{bytes(entry.file.size)}</span>{entry.problem && <span className="mt-1 block text-sm text-destructive">{entry.problem}</span>}</li>)}</ol>}
        </div>}
        {multiOutcomes && <div className="flex min-w-0 flex-col gap-2.5" data-testid="file-manager-multi-upload-results" role="status"><div className={dialogStatus}>{multiFinished ? "Upload attempt finished. Review each result before choosing new files." : "Uploading in selection order. Each saved file is a separate change."}</div><ol className={uploadList}>{multiOutcomes.map((outcome, index) => <li key={index} className="min-w-0 wrap-anywhere" data-upload-status={outcome.status}><strong className="block font-medium text-foreground">{outcome.path}</strong><span className="mt-1 block text-xs text-muted-foreground">{bytes(outcome.bytes)} · {({ uploading: "Uploading - result pending", saved: "Saved", failed_or_unconfirmed: "Failed or unconfirmed", not_attempted: "Not attempted" })[outcome.status]}{outcome.revision !== undefined && ` · revision ${outcome.revision}`}</span></li>)}</ol><div className={dialogStatus}>A failed or unconfirmed file may have been saved. Refresh file records before selecting files again; this attempt is never retried.</div></div>}
        {multiStopping && busy && <div className={dialogStatus} role="status">Stopping after the pending file settles. It may still be saved; the remaining files will not be attempted.</div>}
        {error && <div className={dialogError} role="alert">{error}</div>}
        {(!fresh || !matchingMulti) && <div className={refreshBox}><div role="status">Refresh file records, then choose a new selection and review its destinations before confirming.</div>
          {!fresh && <Button variant="outline" size="sm" className={touch} disabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)}><RefreshCw aria-hidden="true" />Refresh multiple upload records</Button>}</div>}
        {multiFinished && <Button variant="outline" size="sm" className={cn("self-start", touch)} disabled={!canUpload || Boolean(conflict)} onClick={() => { if (!canUpload || !selected || conflict) return; ++multiGeneration.current; multiStop.current = false; setMultiTarget({ site: selected, folder, entries: [] }); setMultiOutcomes(undefined); setMultiFinished(false); setMultiStopping(false); setError(undefined); if (multiPicker.current) multiPicker.current.value = ""; }}>Choose new files</Button>}
        <div className={dialogActions}>{busy === "Uploading selected files" ? <Button variant="outline" className={cn("h-9", touch)} disabled={multiStopping} onClick={() => { multiStop.current = true; setMultiStopping(true); }}>Stop after current file</Button> : <Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={closeMultiUpload}>{multiFinished ? "Close upload results" : "Cancel multiple upload"}</Button>}<Button type="submit" className={cn("h-9", touch)} data-testid="file-manager-multi-upload-confirm" disabled={!canConfirmMulti}>{busy === "Uploading selected files" ? spinner : <Upload aria-hidden="true" />}Confirm multiple uploads</Button></div>
      </form>
    </dialog>}
    {authenticated && <dialog ref={uploadDialog} className={dialogClass} data-testid="file-manager-upload-dialog" aria-labelledby="fm-upload-title" aria-describedby="fm-upload-description" onClose={(event) => { if (event.target === event.currentTarget && !event.currentTarget.open) setUploadOpen(false); }} onCancel={(event) => {
      // File inputs bubble cancel when the chooser is dismissed or the same file
      // is selected again. Only the dialog's own Escape event dismisses it.
      if (event.target !== event.currentTarget) return;
      if (busy) event.preventDefault(); else setUploadOpen(false);
    }}>
      <h1 id="fm-upload-title" className={dialogTitle}>Upload one static file</h1>
      <div id="fm-upload-description" className={dialogText}>Create a new file in <strong className="font-semibold text-foreground">{selected?.domain}</strong> at revision {selected?.revision}. Existing files are never overwritten. Maximum 2 MiB per file, 64 files and 32 MiB per site.</div>
      <form onSubmit={upload} className={dialogForm}>
        <div className={field}><label htmlFor="fm-upload-file" className={fieldLabel}>Local static file</label><input ref={uploadPicker} id="fm-upload-file" type="file" className={fileInput} disabled={Boolean(busy)} onChange={(event) => { const file = event.target.files?.[0]; if (file) { setUploadFile(file); setUploadPath(prefix + file.name); } }} />{uploadFile && <span className={muted}>Selected: {uploadFile.name} - {bytes(uploadFile.size)}</span>}</div>
        <div className={field}><label htmlFor="fm-upload-path" className={fieldLabel}>Relative destination path</label><Input id="fm-upload-path" value={uploadPath} placeholder="assets/image.png" disabled={Boolean(busy)} onChange={(event) => setUploadPath(event.target.value)} aria-invalid={Boolean(uploadFile && (!validPath(uploadPath) || uploadCollision))} autoComplete="off" spellCheck={false} className={input} /><span className={muted}>HTML, CSS, JavaScript, TXT, SVG, PNG, JPEG, GIF, WebP, ICO, WOFF, WOFF2, TTF and PDF. Parent folders are created from the destination path.</span></div>
        {uploadProblem && <div className={dialogStatus} role="status">{uploadProblem}</div>}{error && <div className={dialogError} role="alert">{error}</div>}
        {!fresh && <Button variant="outline" size="sm" className={cn("self-start", touch)} disabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)}><RefreshCw aria-hidden="true" />Refresh upload file records</Button>}
        <div className={dialogActions}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={() => setUploadOpen(false)}>Cancel upload</Button><Button type="submit" className={cn("h-9", touch)} disabled={!canUpload || Boolean(uploadProblem)}>{busy === "Uploading file" ? spinner : <Upload aria-hidden="true" />}Confirm upload</Button></div>
      </form>
    </dialog>}
    {authenticated && <dialog ref={replacementDialog} className={dialogClass} data-testid="file-manager-replace-dialog" aria-labelledby="fm-replace-title" aria-describedby="fm-replace-description" onClose={(event) => { if (event.target === event.currentTarget && !event.currentTarget.open) setReplaceTarget(undefined); }} onCancel={(event) => { if (event.target !== event.currentTarget) return; if (busy) event.preventDefault(); else setReplaceTarget(undefined); }}>
      <h1 id="fm-replace-title" className={dialogTitle}>Replace this saved file?</h1>
      <div id="fm-replace-description" className={dialogText}>Replace the bytes at <strong className="font-semibold text-foreground">{replaceTarget?.path}</strong> in <strong className="font-semibold text-foreground">{replaceTarget?.domain}</strong>. The destination is fixed; this cannot create a missing file. An existing ZIP backup can restore the old bytes.</div>
      <dl className="mt-3!"><Fact label="Saved bytes">{bytes(replaceTarget?.bytes ?? 0)}</Fact></dl>
      <form onSubmit={replaceFile} className={dialogForm}>
        <div className={field}><label htmlFor="fm-replace-file" className={fieldLabel}>Local replacement file</label><input ref={replacementPicker} id="fm-replace-file" type="file" className={fileInput} disabled={Boolean(busy)} onChange={(event) => { const file = event.target.files?.[0]; if (file) setReplacementFile(file); }} />{replacementFile && <span className={muted}>Selected: {replacementFile.name} - {bytes(replacementFile.size)}</span>}<span className={muted}>Maximum 2 MiB per file and 32 MiB per site. Replacing an existing file does not consume another file slot. Local bytes are preserved without text decoding.</span></div>
        {replacementProblem && <div className={dialogStatus} role="status">{replacementProblem}</div>}{error && <div className={dialogError} role="alert">{error}</div>}
        {(!fresh || !matchingReplacement) && <div className={refreshBox}><div role="status">The captured target needs review. Refresh records, then explicitly review the latest target before confirming. Your selected replacement is kept.</div><Button variant="outline" size="sm" className={touch} disabled={Boolean(busy)} onClick={() => setAttempt((value) => value + 1)}><RefreshCw aria-hidden="true" />Refresh replacement records</Button></div>}
        {fresh && !matchingReplacement && (currentReplacement && selected && selected.id === replaceTarget?.siteId ? <div className={refreshBox}><div>Latest revision {selected.revision} - saved bytes {bytes(currentReplacement.bytes)} - SHA-256 {currentReplacement.sha256}</div><Button variant="outline" size="sm" className={touch} disabled={!canUpload || Boolean(conflict)} onClick={() => { if (!selected || !currentReplacement || !replaceTarget || !canUpload || conflict) return; setReplaceTarget({ ...replaceTarget, domain: selected.domain, bytes: currentReplacement.bytes, sha256: currentReplacement.sha256, revision: selected.revision }); setError(undefined); }}>Review latest replacement target</Button></div> : <div className={dialogError} role="alert">The saved target no longer exists. Cancel replacement; a missing file cannot be created here.</div>)}
        {conflict && <div className={dialogStatus} role="status">Compare or discard the retained editor version before replacing this file.</div>}
        <div className={dialogActions}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={() => setReplaceTarget(undefined)}>Cancel replacement</Button><Button type="submit" className={cn("h-9", touch)} disabled={!canConfirmReplacement}>{busy === "Replacing file" ? spinner : <Upload aria-hidden="true" />}Confirm replacement</Button></div>
      </form>
      <div className="mt-4"><TechnicalDetails>Expected website revision {replaceTarget?.revision}{"\n"}Expected SHA-256 {replaceTarget?.sha256}</TechnicalDetails></div>
    </dialog>}
    {authenticated && <dialog ref={renameDialog} className={dialogClass} data-testid="file-manager-rename-dialog" aria-labelledby="fm-rename-title" aria-describedby="fm-rename-description" onClose={(event) => { if (event.target === event.currentTarget && !event.currentTarget.open) setRenameTarget(undefined); }} onCancel={(event) => { if (event.target !== event.currentTarget) return; if (busy) event.preventDefault(); else setRenameTarget(undefined); }}>
      <h1 id="fm-rename-title" className={dialogTitle}>Rename or move this saved file?</h1>
      <div id="fm-rename-description" className={dialogText}>Move <strong className="font-semibold text-foreground">{renameTarget?.path}</strong> within <strong className="font-semibold text-foreground">{renameTarget?.domain}</strong>. Saved bytes stay unchanged. Existing files and folders cannot be overwritten.</div>
      <dl className="mt-3!"><Fact label="Saved bytes">{bytes(renameTarget?.bytes ?? 0)}</Fact></dl>
      <form onSubmit={renameFile} className={dialogForm}>
        <div className={field}><label htmlFor="fm-rename-path" className={fieldLabel}>Relative destination path</label><Input id="fm-rename-path" data-testid="file-manager-rename-path" value={renamePath} placeholder="assets/image.png" disabled={Boolean(busy)} onChange={(event) => setRenamePath(event.target.value)} aria-invalid={Boolean(renameProblem)} autoComplete="off" spellCheck={false} className={input} /><span className={muted}>Parent folders are created from the relative path. Links and references inside HTML or CSS are not rewritten. Renaming index.html makes the website root return 404. Rename back to restore the old URL, or restore an existing ZIP backup.</span></div>
        {renameProblem && <div className={dialogStatus} role="status">{renameProblem}</div>}{error && <div className={dialogError} role="alert">{error}</div>}
        {(!fresh || !matchingRename) && <div className={refreshBox}><div role="status">Refresh this rename target and review its latest revision and checksum before confirming. Your destination path is kept. A refresh never submits the rename.</div><Button variant="outline" size="sm" className={touch} data-testid="file-manager-rename-refresh" disabled={Boolean(busy) || dirty || selected?.id !== renameTarget?.siteId} onClick={() => void refreshRenameTarget()}><RefreshCw aria-hidden="true" />Refresh rename target</Button></div>}
        <div className={dialogActions}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={() => setRenameTarget(undefined)}>Cancel rename</Button><Button type="submit" className={cn("h-9", touch)} data-testid="file-manager-rename-confirm" disabled={!canConfirmRename}>{busy === "Renaming file" ? spinner : <Pencil aria-hidden="true" />}Rename / move</Button></div>
      </form>
      <div className="mt-4"><TechnicalDetails>Expected website revision {renameTarget?.revision}{"\n"}Expected SHA-256 {renameTarget?.sha256}</TechnicalDetails></div>
    </dialog>}
    {authenticated && <dialog ref={deleteDialog} className={dialogClass} data-testid="file-manager-delete-dialog" aria-labelledby="fm-delete-title" aria-describedby="fm-delete-description" onClose={() => setDeleteTarget(undefined)} onCancel={(event) => { if (busy) event.preventDefault(); else setDeleteTarget(undefined); }}>
      <h1 id="fm-delete-title" className={dialogTitle}>Delete this file?</h1>
      <div id="fm-delete-description" className={dialogText}>Remove <strong className="font-semibold text-foreground">{deleteTarget?.path}</strong> from this website at revision {deleteTarget?.revision}. The file will stop being served. An existing ZIP backup can restore it.</div>
      {files.length === 1 && <div className={cn("mt-3", dialogStatus)}>This is the last file. An active empty website serves 404 responses; new ZIP backups require at least one file.</div>}
      <div className={cn("mt-5", dialogActions)}><Button variant="ghost" className={cn("h-9", touch)} disabled={Boolean(busy)} onClick={() => setDeleteTarget(undefined)}>Cancel deletion</Button><Button variant="destructive" className={cn("h-9", touch)} disabled={!matchingDelete} onClick={() => void deleteFile()}>{busy === "Deleting file" ? spinner : <Trash2 aria-hidden="true" />}Confirm file deletion</Button></div>
    </dialog>}
    {busy && <div className="text-xs text-muted-foreground" role="status">{busy}…</div>}
  </section>;
}
