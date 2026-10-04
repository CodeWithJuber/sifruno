import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Archive, ArrowUpRight, File, Folder, Globe, Info, LockKeyhole, LogOut, RefreshCw, Save, Search } from "lucide-react";
import { bytes } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import { previewURL, SiteApiError, siteRequest, siteURL, validBackup, validBackupList, validFileContent, validFileList, validSession, validSite, validSiteList } from "@/lib/sites-api";
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

export default function Websites({ revision, active, onStatus }: { revision: number; active: boolean; onStatus: (value: Resource<unknown>) => void }) {
  const [session, setSession] = useState<OperatorSession>();
  const [accessKey, setAccessKey] = useState("");
  const [sites, setSites] = useState<Site[]>([]);
  const [selected, setSelected] = useState<Site>();
  const [files, setFiles] = useState<SiteFile[]>([]);
  const [backups, setBackups] = useState<SiteBackup[]>([]);
  const [editor, setEditor] = useState<Editor>();
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
  const dialog = useRef<HTMLDialogElement>(null);
  const latestEditor = useRef(editor);
  const latestSelected = useRef(selected);
  latestEditor.current = editor;
  latestSelected.current = selected;
  const dirty = Boolean(editor && (editor.isNew || editor.draft !== editor.savedContent));
  const nameBytes = new TextEncoder().encode(name.trim()).length;
  const authenticated = session?.authenticated === true;
  const editable = authenticated && selected && selected.state !== "recovery_required";

  const fail = useCallback((failure: unknown) => {
    setError(errorText(failure));
    if (failure instanceof SiteApiError && failure.status === 401) { setSession({ authenticated: false }); setRestore(undefined); setNotice(undefined); }
  }, []);
  const updateSite = (site: Site) => {
    setSelected(site);
    setSites((old) => old.some((s) => s.id === site.id) ? old.map((s) => s.id === site.id ? site : s) : [...old, site]);
  };
  const readFile = (site: Site, path: string) => siteRequest(siteURL(site.id, `/file?path=${encodeURIComponent(path)}`), validFileContent);

  async function loadSite(siteId: string, preserveDraft = false) {
    const [site, fileList, backupList] = await Promise.all([
      siteRequest(siteURL(siteId), validSite),
      siteRequest(siteURL(siteId, "/files"), validFileList),
      siteRequest(siteURL(siteId, "/backups"), validBackupList),
    ]);
    updateSite(site);
    setFiles(fileList.items);
    setBackups(backupList.items);
    if (!preserveDraft) {
      const previous = latestEditor.current;
      const path = previous && !previous.isNew && fileList.items.some((f) => f.path === previous.path) ? previous.path : fileList.items[0]?.path;
      setEditor(path ? fromFile(await readFile(site, path)) : undefined);
      setConflict(undefined);
    }
    setLoadedAt(new Date());
  }

  useEffect(() => {
    if (!active) return;
    let live = true;
    setBusy("Loading websites");
    setError(undefined);
    (async () => {
      try {
        const nextSession = await siteRequest("/api/v1/session", validSession, { unauthenticatedSession: true });
        if (!live) return;
        setSession(nextSession);
        if (nextSession.authenticated) {
          const list = await siteRequest("/api/v1/sites", validSiteList);
          if (!live) return;
          setSites(list.items);
          const previous = latestSelected.current;
          const draft = latestEditor.current;
          if (previous && draft && (draft.isNew || draft.draft !== draft.savedContent) && !list.items.some((s) => s.id === previous.id)) throw new SiteApiError(404, "not_found", "The selected website is no longer in the inventory. Your draft is kept.");
          const chosen = list.items.find((s) => s.id === previous?.id) ?? list.items[0];
          if (chosen) await loadSite(chosen.id, Boolean(draft && (draft.isNew || draft.draft !== draft.savedContent)));
          else if (!draft || (!draft.isNew && draft.draft === draft.savedContent)) { setSelected(undefined); setFiles([]); setBackups([]); setEditor(undefined); }
        }
        setLoadedAt(new Date());
      } catch (failure) { if (live) fail(failure); }
      finally { if (live) setBusy(undefined); }
    })();
    return () => { live = false; };
  }, [revision, active, fail, sessionAttempt]);

  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => { if (!active) setAccessKey(""); }, [active]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => { setSession({ authenticated: false }); setRestore(undefined); setNotice(undefined); setError("Your operator session expired. Sign in again; your editor draft is kept."); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session]);
  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
  useEffect(() => {
    if (restore && dialog.current && !dialog.current.open) dialog.current.showModal();
  }, [restore]);

  async function run(label: string, action: () => Promise<void>) {
    if (busy) return;
    setBusy(label); setError(undefined); setNotice(undefined);
    try { await action(); setLoadedAt(new Date()); } catch (failure) { fail(failure); }
    finally { setBusy(undefined); }
  }
  const requireClean = () => {
    if (!dirty) return true;
    setError("Save or discard your editor draft before switching websites, changing state, restoring or signing out.");
    return false;
  };
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
      if (dirty && latestSelected.current && !list.items.some((s) => s.id === latestSelected.current?.id)) throw new SiteApiError(404, "not_found", "The selected website is no longer in the inventory. Your draft is kept.");
      const chosen = list.items.find((s) => s.id === latestSelected.current?.id) ?? list.items[0];
      if (chosen) await loadSite(chosen.id, dirty);
    });
  }
  async function create(event: React.FormEvent) {
    event.preventDefault();
    if (nameBytes > 80) { setError("The website name must fit within 80 UTF-8 bytes."); return; }
    if (!session?.authenticated || !requireClean()) return;
    await run("Creating website", async () => {
      const site = await siteRequest("/api/v1/sites", validSite, { method: "POST", csrf: session.csrf_token, body: { name: name.trim(), domain: domain.trim() } });
      updateSite(site); setName(""); setDomain(""); setEditor(undefined); latestEditor.current = undefined;
      await loadSite(site.id);
      setNotice(`Created ${site.name}.`);
    });
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

  return <section data-testid="websites-view" className="websites-view">
    {error && <div className="website-message website-error" role="alert"><Info /><span>{error}</span></div>}
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
        setSession(next); setSites([]); setSelected(undefined); setFiles([]); setBackups([]); setEditor(undefined); setConflict(undefined); setRestore(undefined);
      }); }} /></div>
      <div className="hosting-notice"><Info /><span>App-owned static websites · local HTTP preview. DNS, TLS, PHP, mail, databases and full server backups are not provided by this slice.</span></div>
      <Card className="dashboard-card website-create" padding={0}><div className="card-heading"><h2>Create website</h2><span>{sites.length} actual {sites.length === 1 ? "website" : "websites"}</span></div>
        <form onSubmit={create}><div><label htmlFor="website-name">Website name</label><input id="website-name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={80} aria-invalid={nameBytes > 80} aria-describedby={nameBytes > 80 ? "website-name-help" : undefined} disabled={Boolean(busy)} />{nameBytes > 80 && <p id="website-name-help" className="website-help website-error">Name is too long ({nameBytes}/80 UTF-8 bytes).</p>}</div><div><label htmlFor="website-domain">Domain</label><input id="website-domain" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.test" required maxLength={253} autoCapitalize="none" spellCheck={false} disabled={Boolean(busy)} /></div><Button label="Create website" type="submit" variant="primary" isLoading={busy === "Creating website"} isDisabled={Boolean(busy) || dirty || sites.length >= 100 || nameBytes > 80 || !name.trim() || !domain.trim()} /></form>
      </Card>
      <div className="website-layout">
        <Card className="dashboard-card website-list" padding={0}><div className="card-heading"><h2>Websites</h2><span>{filtered.length}</span></div><label className="compact-search"><Search /><input type="search" aria-label="Search websites" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Name or domain…" /></label>
          <div className="website-list-items">{filtered.map((site) => <button key={site.id} className="website-list-item" aria-label={`Open website ${site.name}`} aria-current={selected?.id === site.id ? "true" : undefined} disabled={Boolean(busy)} onClick={() => { if (site.id === selected?.id || !requireClean()) return; void run("Loading website", () => loadSite(site.id)); }}><Globe /><span>{site.name}<small>{site.domain}</small><small>{site.state.replaceAll("_", " ")}</small></span></button>)}{!filtered.length && <p className="website-empty">{sites.length ? "No matching websites." : "No websites yet. Create your first site above."}</p>}</div>
        </Card>
        {selected ? <div className="website-detail-stack">
          <Card className="dashboard-card website-details" padding={0} data-testid="website-details" data-site-id={selected.id} data-revision={selected.revision}><div className="card-heading"><div><h2>{selected.name}</h2><p>{selected.domain}</p></div><span className={`website-state website-state-${selected.state}`}>{selected.state.replaceAll("_", " ")}</span></div>
            <dl><div><dt>Revision</dt><dd>{selected.revision}</dd></div><div><dt>Created</dt><dd>{dateLabel(selected.created_at)}</dd></div><div><dt>Updated</dt><dd>{dateLabel(selected.updated_at)}</dd></div></dl>
            <div className="website-actions"><Button label="Local HTTP preview" icon={<ArrowUpRight />} href={previewURL(selected)} target="_blank" rel="noopener noreferrer" isDisabled={selected.state !== "active"} variant="secondary" size="sm" /><Button label={selected.state === "suspended" ? "Resume website" : "Suspend website"} variant="secondary" size="sm" isDisabled={Boolean(busy) || dirty || !editable} onClick={() => { if (!session.authenticated || !requireClean()) return; void run("Changing website state", async () => { const site = await siteRequest(siteURL(selected.id, "/state"), validSite, { method: "POST", csrf: session.csrf_token, body: { state: selected.state === "suspended" ? "active" : "suspended", expected_revision: selected.revision } }); updateSite(site); await loadSite(site.id); setNotice(`Website is ${site.state}.`); }); }} /></div>
            <p className="website-help">Preview serves the site's actual files at {selected.preview_host}:8082 using local HTTP.</p>
            {selected.state === "recovery_required" && <p className="website-message" role="alert">This website requires scoped recovery. Serving and managed changes are disabled until its recovery is resolved.</p>}
          </Card>
          <Card className="dashboard-card website-files" padding={0}><div className="card-heading"><h2><Folder />Files</h2><Button label="Add text file" variant="ghost" size="sm" isDisabled={Boolean(busy) || dirty || !editable || files.length >= 64} onClick={() => { if (!requireClean()) return; setEditor({ path: "", draft: "", savedContent: "", sha256: "", revision: selected.revision, isNew: true }); setConflict(undefined); setError(undefined); }} /></div>
            <div className="website-file-list">{files.map((file) => <button key={file.path} aria-label={`Edit ${file.path}`} aria-pressed={editor?.path === file.path && !editor.isNew} disabled={Boolean(busy)} onClick={() => { if (editor?.path === file.path && !editor.isNew) return; if (!requireClean()) return; void run("Reading file", async () => { setEditor(fromFile(await readFile(selected, file.path))); setConflict(undefined); }); }}><File /><span>{file.path}</span><small>{bytes(file.bytes)}</small></button>)}{!files.length && <p className="website-empty">No files returned for this website.</p>}</div>
            {editor && <form className="website-editor" onSubmit={save} data-testid="website-editor">
              {editor.isNew ? <div className="new-file-path"><label htmlFor="new-file-path">Relative file path</label><input id="new-file-path" value={editor.path} onChange={(e) => { setEditor({ ...editor, path: e.target.value }); setConflict(undefined); }} placeholder="assets/style.css" required disabled={Boolean(busy)} /><p className="website-help">New UTF-8 text file. Use a relative static-file path; PHP, private and source files are rejected.</p></div> : <div className="editor-heading"><label htmlFor="site-file-content">{editor.path}</label><span>Revision {editor.revision}</span></div>}
              <textarea id="site-file-content" aria-label="File content" value={editor.draft} onChange={(e) => setEditor({ ...editor, draft: e.target.value })} spellCheck={false} disabled={Boolean(busy) || !editable} />
              <div className="editor-actions"><span>{bytes(new TextEncoder().encode(editor.draft).length)} / 2 MiB · {dirty ? "Unsaved draft" : "Saved version"}</span><div><Button label="Discard draft" variant="ghost" size="sm" isDisabled={Boolean(busy) || !dirty} onClick={() => { if (editor.isNew) { setEditor(undefined); setConflict(undefined); setError(undefined); } else void run("Reading saved version", async () => { const site = await siteRequest(siteURL(selected.id), validSite); updateSite(site); setEditor(fromFile(await readFile(site, editor.path))); setConflict(undefined); }); }} /><Button label="Save file" icon={<Save />} type="submit" size="sm" variant="primary" isLoading={busy === "Saving file"} isDisabled={Boolean(busy) || !dirty || !editor.path || !editable || new TextEncoder().encode(editor.draft).length > 2 * 1024 * 1024} /></div></div>
              {conflict && <div className="file-conflict" role="status"><h3>Draft kept · server revision {conflict.revision}</h3><p>{conflict.file ? "Compare the server content below." : "No file exists at this path in the latest inventory."} Updating the revision keeps your draft; Save remains an explicit action.</p>{conflict.file && <details><summary>Compare latest server content</summary><pre>{conflict.file.content}</pre><p className="website-help">SHA-256: {conflict.file.sha256}</p></details>}<Button label="Keep draft and use latest revision" variant="secondary" size="sm" isDisabled={Boolean(busy)} onClick={() => { setEditor({ ...editor, savedContent: conflict.file?.content ?? "", sha256: conflict.file?.sha256 ?? "", revision: conflict.revision, isNew: !conflict.file }); setConflict(undefined); setError(undefined); }} /></div>}
            </form>}
          </Card>
          <Card className="dashboard-card website-backups" padding={0}><div className="card-heading"><div><h2><Archive />ZIP backups</h2><p>App-owned site files only · {backups.length} recorded</p></div><Button label="Create ZIP backup" icon={<Archive />} size="sm" variant="secondary" isLoading={busy === "Creating backup"} isDisabled={Boolean(busy) || !editable || dirty} onClick={() => { if (!session.authenticated) return; void run("Creating backup", async () => { const backup = await siteRequest(siteURL(selected.id, "/backups"), validBackup, { method: "POST", csrf: session.csrf_token, body: { expected_revision: selected.revision } }); await loadSite(selected.id); setNotice(`Created ZIP backup with ${backup.files} files.`); }); }} /></div>
            {!backups.length ? <p className="website-empty">No ZIP backups recorded. Create a backup of this site's current files.</p> : <div className="website-backup-list">{backups.map((backup) => <article key={backup.id}><div><strong>{dateLabel(backup.created_at)}</strong><p>{backup.files} files · {bytes(backup.bytes)} · revision {backup.revision}</p><details><summary>Backup hash</summary><code>{backup.sha256}</code></details></div><Button label={`Restore backup ${backup.id}`} size="sm" variant="secondary" isDisabled={Boolean(busy) || dirty || !editable} onClick={() => { if (!requireClean()) return; setRestore({ site: selected, backup }); setRestoreConfirmed(false); }}>Restore</Button></article>)}</div>}
          </Card>
        </div> : <Card className="dashboard-card website-no-selection" padding={0}><Globe /><h2>Select a website</h2><p>Its actual files, state and ZIP backups will appear here.</p></Card>}
      </div>
    </>}
    {busy && session && <p className="website-busy" role="status">{busy}…</p>}
    {restore && <dialog ref={dialog} className="website-restore-dialog" aria-labelledby="restore-title" onCancel={(event) => { if (busy) event.preventDefault(); else setRestore(undefined); }}><h2 id="restore-title">Restore ZIP backup?</h2><p>Replace the app-owned files of <strong>{restore.site.name}</strong> with the backup from {dateLabel(restore.backup.created_at)}.</p><dl><div><dt>Backup</dt><dd>{restore.backup.files} files · {bytes(restore.backup.bytes)} · revision {restore.backup.revision}</dd></div><div><dt>Expected current revision</dt><dd>{restore.site.revision}</dd></div></dl><p>This restores site files through scoped recovery. It does not restore a server, database or mail system.</p><label><input type="checkbox" checked={restoreConfirmed} onChange={(e) => setRestoreConfirmed(e.target.checked)} disabled={Boolean(busy)} />I understand that the current site files will be replaced.</label><div><Button label="Cancel restore" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setRestore(undefined)} /><Button label="Confirm restore" variant="primary" isDisabled={!restoreConfirmed || Boolean(busy)} isLoading={busy === "Restoring backup"} onClick={() => { if (!session?.authenticated || !restoreConfirmed || !requireClean()) return; void run("Restoring backup", async () => { const site = await siteRequest(siteURL(restore.site.id, "/restore"), validSite, { method: "POST", csrf: session.csrf_token, body: { backup_id: restore.backup.id, expected_revision: restore.site.revision } }); updateSite(site); setEditor(undefined); latestEditor.current = undefined; await loadSite(site.id); setRestore(undefined); setNotice(`Restored ${site.name} from its ZIP backup.`); }); }} /></div>{error && <p role="alert" className="website-error">{error}</p>}</dialog>}
  </section>;
}
