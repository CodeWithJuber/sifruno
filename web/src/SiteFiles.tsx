import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { FormEvent, KeyboardEvent, ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { cn } from "cn";
import { ArrowLeft, CircleAlert, CircleCheck, Download, File, FileText, Folder, FolderOpen, FolderPlus, Link2, LockKeyhole, Pencil, RefreshCw, Save, TextCursorInput, Trash2, Upload, X } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button, buttonVariants } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { actionsFor, checkName, checkText, deleteEntry, downloadURL, FilesApiError, joinPath, listFolder, makeFolder, maxTextBytes, modeLabel, modeOf, modifiedLabel, parentPath, pathTrail, permissionsOf, readText, renameEntry, saveText, setPermissions, siteFolder, sizeLabel, sortEntries, specialBits, typeLabel, uploadFile } from "@/lib/files-api";
import type { FileEntry, Folder as FolderList, Permissions, Triple } from "@/lib/files-api";
import { getWebsite, listWebsites, WebsitesApiError } from "@/lib/websites-api";
import type { Website } from "@/lib/websites-api";

// One website's Files page: the hosting account's real home folder. Every
// change runs on the server as the website's own user, so the account's
// permissions and disk quota apply, and a link is shown as a link and never
// followed. A suspended website's files can be looked at and downloaded,
// not changed. The base styles colour <p> and <a> outside Tailwind's
// layers, so coloured text uses div or span, as on the other Websites
// screens.

const panel = "rounded-lg border border-border bg-card";
const rowControl = "h-9 pointer-coarse:h-11";
const iconControl = "size-9 pointer-coarse:size-11";
const linkButton = (variant: "default" | "outline" | "ghost", className = "") =>
  cn(buttonVariants({ variant, className: `${rowControl} ${variant === "default" ? "text-primary-foreground!" : ""} ${className}` }));

interface Problem { what: string; why: string; next: string; technical: string; status: number }

function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof FilesApiError || error instanceof WebsitesApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
}

function TechnicalDetails({ children }: { children: ReactNode }) {
  return <details className="text-sm">
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
    <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{children}</div>
  </details>;
}

// What happened (the title), why and what to do, and the request under
// Technical details. role="alert": a failure is announced at once.
function ProblemAlert({ problem, children, testId }: { problem: Problem; children?: ReactNode; testId: string }) {
  return <Alert variant="destructive" className="text-start" data-testid={testId}>
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
      <div className="flex flex-col gap-1.5 text-sm">
        <div className="text-foreground">{problem.why}</div>
        {problem.next && <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {problem.next}</div>}
      </div>
      <TechnicalDetails>{problem.technical}</TechnicalDetails>
      {children && <div className="flex flex-wrap gap-2">{children}</div>}
    </AlertDescription>
  </Alert>;
}

// A file name keeps its extension in view when it is cut short: only the
// part before it truncates. The whole name stays in the text.
function FileName({ name }: { name: string }) {
  const dot = name.lastIndexOf(".");
  const split = dot > 0 && name.length - dot <= 8;
  return <span className="flex min-w-0 whitespace-nowrap" title={name}>
    <span className="min-w-0 overflow-hidden text-ellipsis">{split ? name.slice(0, dot) : name}</span>{split ? name.slice(dot) : ""}
  </span>;
}

function EntryIcon({ entry }: { entry: FileEntry }) {
  const Icon = entry.type === "folder" ? Folder : entry.type === "link" ? Link2 : entry.size <= maxTextBytes && entry.type === "file" ? FileText : File;
  return <Icon className={cn("size-4 shrink-0", entry.type === "folder" ? "text-primary" : "text-muted-foreground")} aria-hidden="true" />;
}

// One member per kind, so a check of kind narrows to exactly one.
type Dialogs =
  | { kind: "new-folder" }
  | { kind: "new-file" }
  | { kind: "rename"; entry: FileEntry }
  | { kind: "delete"; entry: FileEntry }
  | { kind: "mode"; entry: FileEntry };

interface Upload { id: number; file: File; sent: number; state: "waiting" | "sending" | "done" | "exists" | "failed"; problem?: Problem }

interface Editing { path: string; version: string; saved: string; draft: string; isNew: boolean }

export function SiteFiles({ accountId, path }: { accountId: string; path: string }) {
  const navigate = useNavigate();
  const [site, setSite] = useState<Website>();
  const [folder, setFolder] = useState<FolderList>();
  const [problem, setProblem] = useState<Problem>();
  const [actionProblem, setActionProblem] = useState<Problem>();
  const [loading, setLoading] = useState(true);
  const [round, setRound] = useState(0);
  const [notice, setNotice] = useState("");
  const [spoken, setSpoken] = useState("");
  const [dialog, setDialog] = useState<Dialogs>();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<Editing>();
  const [uploads, setUploads] = useState<Upload[]>([]);
  const uploadInput = useRef<HTMLInputElement>(null);
  const uploadSeq = useRef(0);
  const headingRef = useRef<HTMLHeadingElement>(null);

  const say = useCallback((message: string) => { setNotice(message); setSpoken(""); window.setTimeout(() => setSpoken(message), 150); }, []);
  const reload = useCallback(() => setRound((value) => value + 1), []);
  const goTo = useCallback((next: string) => {
    setNotice("");
    setActionProblem(undefined);
    void navigate({ to: "/websites/sites/$accountId/files", params: { accountId }, search: next ? { path: next } : {} });
  }, [accountId, navigate]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setProblem(undefined);
    (async () => {
      try {
        const [nextSite, nextFolder] = await Promise.all([site?.account_id === accountId ? Promise.resolve(site) : getWebsite(accountId, { signal: controller.signal }), listFolder(accountId, path, { signal: controller.signal })]);
        setSite(nextSite);
        setFolder(nextFolder);
      } catch (error) {
        if (!controller.signal.aborted) setProblem(problemFrom(error, "The folder could not be opened."));
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    })();
    return () => controller.abort();
    // The site is read once per page; the folder on every visit and reload.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accountId, path, round]);

  const writable = site?.state === "active";
  const entries = folder && folder.path === path ? sortEntries(folder.entries) : [];
  const names = new Set(entries.map((entry) => entry.name));

  const open = (next: Dialogs) => { setActionProblem(undefined); setDialog(next); setDialogOpen(true); };
  const finished = (message: string) => { setDialogOpen(false); say(message); reload(); };

  const openEditor = async (entry: FileEntry) => {
    const target = joinPath(path, entry.name);
    setActionProblem(undefined);
    try {
      const text = await readText(accountId, target);
      setEditing({ path: target, version: text.file.version ?? "", saved: text.content, draft: text.content, isNew: false });
      setNotice("");
    } catch (error) {
      setActionProblem(problemFrom(error, "The file could not be opened."));
    }
  };

  const startUploads = async (files: File[]) => {
    const added = files.map((file) => ({ id: ++uploadSeq.current, file, sent: 0, state: "waiting" as const }));
    setUploads((current) => [...current.filter((u) => u.state === "sending" || u.state === "waiting"), ...added]);
    for (const item of added) await sendUpload(item, false);
    reload();
  };
  const sendUpload = async (item: Upload, overwrite: boolean) => {
    const update = (change: Partial<Upload>) => setUploads((current) => current.map((u) => u.id === item.id ? { ...u, ...change } : u));
    update({ state: "sending", sent: 0, problem: undefined });
    try {
      await uploadFile(accountId, path, item.file, overwrite, (sent) => update({ sent }));
      update({ state: "done", sent: item.file.size });
      say(`Uploaded ${item.file.name}.`);
    } catch (error) {
      const failed = problemFrom(error, "The file was not uploaded.");
      update({ state: error instanceof FilesApiError && error.status === 409 && /already there/.test(error.why) ? "exists" : "failed", problem: failed });
    }
  };

  if (!site) return <div className="flex w-full max-w-5xl flex-col gap-4" data-testid="site-files">
    {problem
      ? <ProblemAlert problem={problem} testId="files-problem">{problem.status !== 404 && <Button variant="outline" size="sm" onClick={reload}><RefreshCw aria-hidden="true" />Try again</Button>}</ProblemAlert>
      : <div className={`${panel} flex flex-col gap-4 p-5`} aria-busy="true" data-testid="files-loading"><span className="sr-only">Loading the files</span><Skeleton className="h-8 w-1/2" /><Skeleton className="h-64 w-full" /></div>}
  </div>;

  if (editing) return <div className="flex w-full max-w-5xl flex-col gap-4" data-testid="site-files" data-account-id={site.account_id}>
    <Editor accountId={accountId} editing={editing} onChange={setEditing}
      onClose={() => { const where = parentPath(editing.path); setEditing(undefined); if (where !== path) goTo(where); else reload(); }} />
    <div aria-live="polite" className="sr-only" data-testid="files-announcer">{spoken}</div>
  </div>;

  const trail = pathTrail(path);
  return <div className="flex w-full max-w-5xl flex-col gap-4" data-testid="site-files" data-account-id={site.account_id}>
    <section className={`${panel} flex flex-col gap-3 p-5 md:p-6`}>
      <div className="flex flex-col gap-1">
        <h2 ref={headingRef} tabIndex={-1} className="wrap-anywhere outline-none" data-testid="files-heading">Files for {site.domain}</h2>
        <p className="text-sm">The hosting account's home folder. The website serves what is in <code>public_html</code>. Every change is made as the website's own user, so its permissions and disk quota apply.</p>
      </div>
      {!writable && <Alert className="text-start" data-testid="files-read-only">
        <LockKeyhole aria-hidden="true" />
        <AlertTitle>{site.state === "suspended" ? "This website is suspended, so its files are read-only." : "This website's files are read-only for now."}</AlertTitle>
        <AlertDescription className="text-start">
          <div>{site.state === "suspended" ? "You can open, read and download its files. To change them, resume the website in its Settings tab." : "The hosting account needs a check before its files can change. You can still open and download them."}</div>
        </AlertDescription>
      </Alert>}
      {notice && <Alert role={undefined} className="text-start" data-testid="files-notice">
        <CircleCheck className="text-primary" aria-hidden="true" />
        <AlertTitle>{notice}</AlertTitle>
      </Alert>}
    </section>

    {actionProblem && <ProblemAlert problem={actionProblem} testId="files-action-problem">
      <Button variant="outline" size="sm" onClick={() => setActionProblem(undefined)}>Dismiss</Button>
    </ProblemAlert>}

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="files-folder-heading">
      <div className="flex flex-col gap-3">
        <Breadcrumb aria-label="Folder">
          <BreadcrumbList>
            {trail.map((step, index) => <span key={step.path} className="contents">
              {index > 0 && <BreadcrumbSeparator />}
              <BreadcrumbItem>
                {index === trail.length - 1
                  ? <BreadcrumbPage className="font-medium wrap-anywhere" data-testid="files-current">{step.name}</BreadcrumbPage>
                  : <button type="button" className="rounded-sm wrap-anywhere text-primary underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={() => goTo(step.path)} data-testid="files-crumb">{step.name}</button>}
              </BreadcrumbItem>
            </span>)}
          </BreadcrumbList>
        </Breadcrumb>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 id="files-folder-heading" className="wrap-anywhere">{path ? `/${path}` : "Home folder"}</h3>
          <div className="flex flex-wrap gap-2">
            {path && <Button variant="ghost" className={rowControl} onClick={() => goTo(parentPath(path))} data-testid="files-up"><ArrowLeft className="rtl:rotate-180" aria-hidden="true" />Up one folder</Button>}
            <Button variant="outline" className={rowControl} onClick={reload} disabled={loading} data-testid="files-refresh"><RefreshCw aria-hidden="true" />Refresh</Button>
            {writable && <>
              <Button variant="outline" className={rowControl} onClick={() => open({ kind: "new-folder" })} data-testid="files-new-folder"><FolderPlus aria-hidden="true" />New folder</Button>
              <Button variant="outline" className={rowControl} onClick={() => open({ kind: "new-file" })} data-testid="files-new-file"><FileText aria-hidden="true" />New file</Button>
              <Button className={rowControl} onClick={() => uploadInput.current?.click()} data-testid="files-upload"><Upload aria-hidden="true" />Upload files</Button>
              <input ref={uploadInput} type="file" multiple className="sr-only" tabIndex={-1} aria-hidden="true" data-testid="files-upload-input"
                onChange={(event) => { const picked = Array.from(event.currentTarget.files ?? []); event.currentTarget.value = ""; if (picked.length) void startUploads(picked); }} />
            </>}
          </div>
        </div>
        {writable && <div className="text-sm text-muted-foreground">Uploads are up to 64 MB each. A file with the same name is not replaced unless you choose Replace.</div>}
      </div>

      {uploads.length > 0 && <UploadList uploads={uploads} onReplace={(item) => void sendUpload(item, true).then(reload)} onClear={() => setUploads((current) => current.filter((u) => u.state === "sending" || u.state === "waiting"))} />}

      {problem
        ? <ProblemAlert problem={problem} testId="files-problem">
          <Button variant="outline" size="sm" onClick={reload}><RefreshCw aria-hidden="true" />Try again</Button>
          {path && <Button variant="outline" size="sm" onClick={() => goTo("")}><FolderOpen aria-hidden="true" />Go to the home folder</Button>}
        </ProblemAlert>
        : loading && !folder ? <div aria-busy="true" className="flex flex-col gap-2"><span className="sr-only">Loading the folder</span><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-full" /></div>
        : entries.length === 0 && folder?.path === path
          ? <Empty className="border border-dashed border-border py-8" data-testid="files-empty">
            <EmptyHeader>
              <EmptyMedia variant="icon"><FolderOpen aria-hidden="true" /></EmptyMedia>
              <EmptyTitle>This folder is empty</EmptyTitle>
              <EmptyDescription>{writable ? "Upload files, or make a new folder or file here." : "There is nothing in this folder."}</EmptyDescription>
            </EmptyHeader>
          </Empty>
          : <FileTable entries={entries} path={path} writable={writable} accountId={accountId} busy={loading}
            onOpen={(entry) => goTo(joinPath(path, entry.name))} onEdit={(entry) => void openEditor(entry)} onDialog={open} />}
      {folder?.path === path && (folder.skipped > 0 || folder.truncated) && <div className="text-sm text-muted-foreground" data-testid="files-hidden-note">
        {folder.truncated && <div>This folder holds more than 5000 names; the first 5000 are shown. Use SFTP to work with the rest.</div>}
        {folder.skipped > 0 && <div>{folder.skipped === 1 ? "1 name is" : `${folder.skipped} names are`} not shown because the file manager cannot use {folder.skipped === 1 ? "it" : "them"} (not text, a control character, or longer than 255 bytes). Use SFTP for {folder.skipped === 1 ? "it" : "them"}.</div>}
      </div>}
    </section>

    <Dialog open={dialogOpen} onOpenChange={(next) => { if (!next) setDialogOpen(false); }}>
      <DialogContent className="sm:max-w-md" data-testid="files-dialog">
        {dialog && (dialog.kind === "new-folder" || dialog.kind === "new-file"
          ? <NameForm key={`${dialog.kind}-${round}`} title={dialog.kind === "new-folder" ? "New folder" : "New file"} label={dialog.kind === "new-folder" ? "Folder name" : "File name"}
            description={`It is made in ${path ? `/${path}` : "the home folder"}.`} initial="" taken={names} submit={dialog.kind === "new-folder" ? "Make folder" : "Open in the editor"}
            onCancel={() => setDialogOpen(false)}
            onSubmit={async (name) => {
              if (dialog.kind === "new-file") { setDialogOpen(false); setEditing({ path: joinPath(path, name), version: "", saved: "", draft: "", isNew: true }); return; }
              await makeFolder(accountId, joinPath(path, name));
              finished(`Made the folder ${name}.`);
            }} />
          : dialog.kind === "rename"
            ? <NameForm key={`rename-${dialog.entry.name}`} title={`Rename ${dialog.entry.name}`} label="New name" description={dialog.entry.type === "link" ? "The link itself is renamed; what it points to is not." : "Links to it by its old name, in pages or code, stop working."}
              initial={dialog.entry.name} taken={names} submit="Rename" onCancel={() => setDialogOpen(false)}
              onSubmit={async (name) => { await renameEntry(accountId, joinPath(path, dialog.entry.name), joinPath(path, name)); finished(`Renamed ${dialog.entry.name} to ${name}.`); }} />
            : dialog.kind === "delete"
              ? <DeleteForm entry={dialog.entry} onCancel={() => setDialogOpen(false)}
                onDelete={async () => { await deleteEntry(accountId, joinPath(path, dialog.entry.name)); finished(`Deleted ${dialog.entry.name}.`); }} />
              : <ModeForm key={`mode-${dialog.entry.name}`} entry={dialog.entry} onCancel={() => setDialogOpen(false)}
                onSave={async (mode) => { await setPermissions(accountId, joinPath(path, dialog.entry.name), mode); finished(`Changed the permissions of ${dialog.entry.name} to ${mode} (${modeLabel(mode)}).`); }} />)}
      </DialogContent>
    </Dialog>
    <div aria-live="polite" className="sr-only" data-testid="files-announcer">{spoken}</div>
  </div>;
}

// ---- The folder's table ---------------------------------------------------------------

function FileTable({ entries, path, writable, accountId, busy, onOpen, onEdit, onDialog }: { entries: FileEntry[]; path: string; writable: boolean; accountId: string; busy: boolean; onOpen: (entry: FileEntry) => void; onEdit: (entry: FileEntry) => void; onDialog: (dialog: Dialogs) => void }) {
  const caption = useId();
  // The wrapper scrolls on its own and is a container, so the table adapts
  // to its own width. Keyboard users reach it with Tab to scroll it.
  return <div role="region" aria-labelledby={caption} tabIndex={0} aria-busy={busy} className="@container rounded-md border border-border focus-visible:outline-2 focus-visible:outline-ring" data-testid="files-table">
    {/* Narrower than @xl, each row stacks: the name with its details, then
        its actions. The header row is then hidden, as its columns are. */}
    <Table className="table-fixed @max-xl:block">
      <TableCaption id={caption} className="sr-only">Files and folders in {path ? `/${path}` : "the home folder"}</TableCaption>
      <TableHeader className="@max-xl:hidden">
        <TableRow>
          <TableHead scope="col" className="ps-3 text-start">Name</TableHead>
          <TableHead scope="col" className="hidden w-24 text-end @xl:table-cell">Size</TableHead>
          <TableHead scope="col" className="hidden w-32 text-start @3xl:table-cell">Permissions</TableHead>
          <TableHead scope="col" className="hidden w-44 text-start @2xl:table-cell">Modified</TableHead>
          <TableHead scope="col" className="w-60 pe-3 text-end"><span className="sr-only">Actions</span></TableHead>
        </TableRow>
      </TableHeader>
      <TableBody className="@max-xl:block">
        {entries.map((entry) => {
          const can = actionsFor(entry, joinPath(path, entry.name), writable);
          return <TableRow key={entry.name} className="@max-xl:flex @max-xl:flex-col" data-testid="file-row" data-name={entry.name} data-type={entry.type}>
            <TableCell className="ps-3 @max-xl:block @max-xl:pe-3">
              <div className="flex min-w-0 items-center gap-2">
                <EntryIcon entry={entry} />
                {can.open
                  ? <button type="button" className="flex min-w-0 rounded-sm text-start font-medium text-primary underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-ring" onClick={() => onOpen(entry)} data-testid="open-folder"><FileName name={entry.name} /><span className="sr-only"> (folder)</span></button>
                  : <span className="flex min-w-0 text-foreground"><FileName name={entry.name} /></span>}
                {entry.type === "link" && <Badge variant="secondary" className="shrink-0">Link</Badge>}
                {entry.type === "other" && <Badge variant="secondary" className="shrink-0">Special</Badge>}
                {joinPath(path, entry.name) === siteFolder && <Badge variant="outline" className="shrink-0">Website folder</Badge>}
              </div>
              {/* On a narrow table the hidden columns' values move under the name. */}
              <div className="mt-0.5 ps-6 text-xs whitespace-normal text-muted-foreground @2xl:hidden">
                {typeLabel(entry)}{entry.type === "file" ? `, ${sizeLabel(entry.size)}` : ""} · {modifiedLabel(entry.modified)}
              </div>
            </TableCell>
            <TableCell className="hidden text-end text-muted-foreground tabular-nums @xl:table-cell">{entry.type === "file" ? sizeLabel(entry.size) : "—"}</TableCell>
            <TableCell className="hidden @3xl:table-cell"><code className="text-xs text-muted-foreground" title={`${entry.mode}`}>{modeLabel(entry.mode)}</code></TableCell>
            <TableCell className="hidden text-muted-foreground @2xl:table-cell">{modifiedLabel(entry.modified)}</TableCell>
            <TableCell className="pe-3 @max-xl:block @max-xl:ps-7 @max-xl:pt-0">
              <div className="flex flex-wrap justify-end gap-1 @max-xl:justify-start">
                {can.edit && <Button variant="ghost" size="icon" className={iconControl} onClick={() => onEdit(entry)} data-testid="edit-file"><Pencil aria-hidden="true" /><span className="sr-only">{writable ? "Edit" : "Read"} {entry.name}</span></Button>}
                {can.download && <a href={downloadURL(accountId, joinPath(path, entry.name))} download={entry.name} className={cn(buttonVariants({ variant: "ghost", size: "icon" }), iconControl)} data-testid="download-file"><Download aria-hidden="true" /><span className="sr-only">Download {entry.name}</span></a>}
                {can.rename && <Button variant="ghost" size="icon" className={iconControl} onClick={() => onDialog({ kind: "rename", entry })} data-testid="rename-entry"><TextCursorInput aria-hidden="true" /><span className="sr-only">Rename {entry.name}</span></Button>}
                {can.permissions && <Button variant="ghost" size="icon" className={iconControl} onClick={() => onDialog({ kind: "mode", entry })} data-testid="mode-entry"><LockKeyhole aria-hidden="true" /><span className="sr-only">Permissions of {entry.name}</span></Button>}
                {can.remove && <Button variant="ghost" size="icon" className={cn(iconControl, "text-destructive hover:text-destructive")} onClick={() => onDialog({ kind: "delete", entry })} data-testid="delete-entry"><Trash2 aria-hidden="true" /><span className="sr-only">Delete {entry.name}</span></Button>}
              </div>
            </TableCell>
          </TableRow>;
        })}
      </TableBody>
    </Table>
  </div>;
}

// ---- Uploads ------------------------------------------------------------------------------

function UploadList({ uploads, onReplace, onClear }: { uploads: Upload[]; onReplace: (item: Upload) => void; onClear: () => void }) {
  const finished = uploads.every((u) => u.state !== "sending" && u.state !== "waiting");
  return <section aria-label="Uploads" className="flex flex-col gap-2 rounded-md border border-border p-3" data-testid="files-uploads">
    <ul role="list" className="flex flex-col gap-2">
      {uploads.map((item) => <li key={item.id} className="flex flex-col gap-1.5" data-testid="upload-row" data-state={item.state}>
        <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
          <span className="flex min-w-0 items-center gap-2"><Upload className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" /><FileName name={item.file.name} /></span>
          <span className="text-muted-foreground">
            {item.state === "waiting" ? "Waiting" : item.state === "sending" ? `${sizeLabel(item.sent)} of ${sizeLabel(item.file.size)}` : item.state === "done" ? "Uploaded" : item.state === "exists" ? "Not replaced" : "Failed"}
          </span>
        </div>
        {(item.state === "sending" || item.state === "waiting") && <progress className="h-2 w-full accent-primary" max={item.file.size || 1} value={item.sent} aria-label={`Uploading ${item.file.name}`} />}
        {item.state === "exists" && <div className="flex flex-wrap items-center gap-2 text-sm">
          <span>A file named {item.file.name} is already here, so it was not replaced.</span>
          <Button variant="outline" size="sm" onClick={() => onReplace(item)} data-testid="upload-replace">Replace it</Button>
        </div>}
        {item.state === "failed" && item.problem && <ProblemAlert problem={item.problem} testId="upload-problem" />}
      </li>)}
    </ul>
    {finished && <Button variant="ghost" size="sm" className="w-fit" onClick={onClear} data-testid="uploads-clear"><X aria-hidden="true" />Clear this list</Button>}
  </section>;
}

// ---- Dialogs ------------------------------------------------------------------------------

// A name for a new folder or file, or a rename. The rules are the server's;
// a taken name is caught here and by the server, which never replaces one.
function NameForm({ title, label, description, initial, taken, submit, onSubmit, onCancel }: { title: string; label: string; description: string; initial: string; taken: Set<string>; submit: string; onSubmit: (name: string) => Promise<void>; onCancel: () => void }) {
  const id = useId();
  const [name, setName] = useState(initial);
  const [error, setError] = useState<string>();
  const [problem, setProblem] = useState<Problem>();
  const [busy, setBusy] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const check = (value: string) => checkName(value) ?? (value !== initial && taken.has(value) ? "A file or folder with that name is already here. Choose another name." : value === initial && initial ? "Enter a different name." : undefined);
  const send = async (event: FormEvent) => {
    event.preventDefault();
    const wrong = check(name);
    setError(wrong);
    if (wrong) { input.current?.focus(); return; }
    setBusy(true);
    setProblem(undefined);
    try { await onSubmit(name); } catch (failure) { setProblem(problemFrom(failure, "Nothing was changed.")); } finally { setBusy(false); }
  };
  return <form onSubmit={send} noValidate className="flex flex-col gap-4" aria-labelledby={`${id}-title`}>
    <DialogHeader>
      <DialogTitle id={`${id}-title`} className="wrap-anywhere">{title}</DialogTitle>
      <DialogDescription>{description}</DialogDescription>
    </DialogHeader>
    <Field data-invalid={error ? true : undefined}>
      <FieldLabel htmlFor={`${id}-name`}>{label}</FieldLabel>
      <Input ref={input} id={`${id}-name`} name="name" value={name} autoFocus autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck={false} className="h-10 pointer-coarse:h-12"
        aria-invalid={error ? true : undefined} aria-describedby={error ? `${id}-error` : `${id}-hint`}
        onChange={(event) => { setName(event.target.value); if (error && !check(event.target.value)) setError(undefined); }}
        onBlur={() => { if (name !== initial) setError(check(name)); }} data-testid="name-input" />
      {error ? <FieldError id={`${id}-error`}>{error}</FieldError> : <FieldDescription id={`${id}-hint`}>Up to 255 bytes; no slash (/) and no line breaks.</FieldDescription>}
    </Field>
    {problem && <ProblemAlert problem={problem} testId="dialog-problem" />}
    <DialogFooter>
      <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>Cancel</Button>
      <Button type="submit" disabled={busy} data-testid="name-submit">{busy ? "Working…" : submit}</Button>
    </DialogFooter>
  </form>;
}

function DeleteForm({ entry, onDelete, onCancel }: { entry: FileEntry; onDelete: () => Promise<void>; onCancel: () => void }) {
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const what = entry.type === "folder" ? `the folder ${entry.name} and everything in it` : entry.type === "link" ? `the link ${entry.name}` : `${entry.name}`;
  const send = async () => {
    setBusy(true);
    setProblem(undefined);
    try { await onDelete(); } catch (failure) { setProblem(problemFrom(failure, "Nothing was deleted.")); } finally { setBusy(false); }
  };
  return <div className="flex flex-col gap-4">
    <DialogHeader>
      <DialogTitle className="wrap-anywhere">Delete {what}?</DialogTitle>
      <DialogDescription>
        {entry.type === "folder" ? "Every file and folder inside it is deleted too. A link inside is removed as a link; what it points to is kept. " : entry.type === "link" ? "Only the link is removed; what it points to is kept. " : ""}
        This cannot be undone here; a backup can bring it back.
      </DialogDescription>
    </DialogHeader>
    {problem && <ProblemAlert problem={problem} testId="dialog-problem" />}
    <DialogFooter>
      <Button type="button" variant="outline" onClick={onCancel} disabled={busy} autoFocus>Cancel</Button>
      <Button type="button" variant="destructive" onClick={() => void send()} disabled={busy} data-testid="delete-confirm"><Trash2 aria-hidden="true" />{busy ? "Deleting…" : "Delete"}</Button>
    </DialogFooter>
  </div>;
}

// Read, write and run for the owner (the website's user), its group and
// everyone else. Special bits are never set here.
function ModeForm({ entry, onSave, onCancel }: { entry: FileEntry; onSave: (mode: string) => Promise<void>; onCancel: () => void }) {
  const id = useId();
  const [perms, setPerms] = useState<Permissions>(() => permissionsOf(entry.mode));
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const mode = modeOf(perms);
  const who: { key: keyof Permissions; label: string }[] = [{ key: "owner", label: "The website's user" }, { key: "group", label: "Its group" }, { key: "others", label: "Everyone else (including the web server)" }];
  const bits: { key: keyof Triple; label: string }[] = [{ key: "read", label: "Read" }, { key: "write", label: "Write" }, { key: "execute", label: entry.type === "folder" ? "Open" : "Run" }];
  const send = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try { await onSave(mode); } catch (failure) { setProblem(problemFrom(failure, "The permissions were not changed.")); } finally { setBusy(false); }
  };
  return <form onSubmit={send} className="flex flex-col gap-4">
    <DialogHeader>
      <DialogTitle className="wrap-anywhere">Permissions of {entry.name}</DialogTitle>
      <DialogDescription>Now {entry.mode} ({modeLabel(entry.mode)}). Files usually have 0644 and folders 0755. {entry.type === "folder" ? "A folder needs Open for the web server to serve what is inside it." : ""}</DialogDescription>
    </DialogHeader>
    <div className="flex flex-col gap-3">
      {who.map((w) => <fieldset key={w.key} className="flex flex-col gap-1.5">
        <legend className="mb-1 text-sm font-medium">{w.label}</legend>
        <div className="flex flex-wrap gap-4">
          {bits.map((b) => {
            const box = `${id}-${w.key}-${b.key}`;
            return <span key={b.key} className="flex items-center gap-2">
              <input id={box} type="checkbox" className="size-4 accent-primary" checked={perms[w.key][b.key]} data-testid={`mode-${w.key}-${b.key}`}
                onChange={(event) => { const checked = event.currentTarget.checked; setPerms((current) => ({ ...current, [w.key]: { ...current[w.key], [b.key]: checked } })); }} />
              <label htmlFor={box} className="text-sm">{b.label}</label>
            </span>;
          })}
        </div>
      </fieldset>)}
    </div>
    <div className="text-sm" data-testid="mode-result">New permissions: <code>{mode}</code> (<code>{modeLabel(mode)}</code>)</div>
    {specialBits(entry.mode) && <div className="text-sm text-muted-foreground">This {entry.type} also has a special bit (setuid, setgid or sticky). Saving here clears it.</div>}
    {problem && <ProblemAlert problem={problem} testId="dialog-problem" />}
    <DialogFooter>
      <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>Cancel</Button>
      <Button type="submit" disabled={busy || mode === `0${entry.mode.slice(1)}` && !specialBits(entry.mode)} data-testid="mode-save">{busy ? "Saving…" : "Save permissions"}</Button>
    </DialogFooter>
  </form>;
}

// ---- The editor ----------------------------------------------------------------------------

// A plain text editor for one file up to 1 MB. A save sends the version it
// opened, so a file changed meanwhile (by the site or another person) is
// never overwritten.
function Editor({ accountId, editing, onChange, onClose }: { accountId: string; editing: Editing; onChange: (next: Editing) => void; onClose: () => void }) {
  const id = useId();
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const [savedAt, setSavedAt] = useState("");
  const [confirmClose, setConfirmClose] = useState(false);
  const area = useRef<HTMLTextAreaElement>(null);
  const dirty = editing.isNew || editing.draft !== editing.saved;
  const name = editing.path.slice(editing.path.lastIndexOf("/") + 1);

  useEffect(() => { area.current?.focus(); }, []);
  // Leaving the page with unsaved changes asks first.
  useEffect(() => {
    if (!dirty) return;
    const stay = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    window.addEventListener("beforeunload", stay);
    return () => window.removeEventListener("beforeunload", stay);
  }, [dirty]);

  const save = async () => {
    const wrong = checkText(editing.draft);
    if (wrong) { setProblem({ what: "The file was not saved.", why: wrong, next: "", technical: "text outside the files contract; nothing was sent", status: 0 }); return; }
    setBusy(true);
    setProblem(undefined);
    try {
      const saved = await saveText(accountId, editing.path, editing.draft, editing.version);
      onChange({ ...editing, version: saved.version ?? "", saved: editing.draft, isNew: false });
      setSavedAt(`Saved ${name} at ${new Date().toLocaleTimeString()}.`);
    } catch (failure) {
      setProblem(problemFrom(failure, "The file was not saved."));
    } finally {
      setBusy(false);
    }
  };
  const keys = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.nativeEvent.isComposing) return;
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") { event.preventDefault(); if (!busy) void save(); }
  };

  return <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby={`${id}-title`} data-testid="files-editor">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 flex-col gap-1">
        <h2 id={`${id}-title`} className="wrap-anywhere">{editing.isNew ? `New file ${name}` : `Edit ${name}`}</h2>
        <div className="text-sm text-muted-foreground wrap-anywhere"><code>/{editing.path}</code>{editing.isNew ? " is made when you save." : ""}</div>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" className={rowControl} onClick={() => dirty ? setConfirmClose(true) : onClose()} data-testid="editor-close"><X aria-hidden="true" />Close</Button>
        <Button className={rowControl} onClick={() => void save()} disabled={busy || !dirty} data-testid="editor-save"><Save aria-hidden="true" />{busy ? "Saving…" : "Save"}</Button>
      </div>
    </div>
    {problem && <ProblemAlert problem={problem} testId="editor-problem" />}
    <label htmlFor={`${id}-text`} className="sr-only">Contents of {name}</label>
    <textarea ref={area} id={`${id}-text`} value={editing.draft} onChange={(event) => onChange({ ...editing, draft: event.target.value })} onKeyDown={keys}
      spellCheck={false} autoCapitalize="none" autoCorrect="off" autoComplete="off" wrap="off" rows={24}
      className="min-h-80 w-full resize-y rounded-md border border-input bg-background p-3 font-mono text-[max(1rem,0.875rem)] leading-relaxed text-foreground focus-visible:outline-2 focus-visible:outline-ring md:text-sm"
      aria-describedby={`${id}-help`} data-testid="editor-text" />
    <div id={`${id}-help`} className="flex flex-wrap justify-between gap-2 text-sm text-muted-foreground">
      <span>Plain text, up to 1 MB. Ctrl+S (or ⌘S) saves.</span>
      <span role="status" data-testid="editor-status">{dirty ? "Unsaved changes" : savedAt || "No changes"}</span>
    </div>
    <Dialog open={confirmClose} onOpenChange={setConfirmClose}>
      <DialogContent className="sm:max-w-md" data-testid="editor-discard-dialog">
        <DialogHeader>
          <DialogTitle>Close without saving?</DialogTitle>
          <DialogDescription>Your changes to {name} are not saved and will be lost.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => setConfirmClose(false)} autoFocus>Keep editing</Button>
          <Button variant="destructive" onClick={() => { setConfirmClose(false); onClose(); }} data-testid="editor-discard">Discard changes</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </section>;
}

// ---- The Files menu entry -------------------------------------------------------------------

// Websites → Files: every website, each opening its own Files page.
export function FilesSitePicker() {
  const [sites, setSites] = useState<Website[]>();
  const [problem, setProblem] = useState<Problem>();
  const [round, setRound] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setProblem(undefined);
    listWebsites({ signal: controller.signal }).then(setSites, (error: unknown) => { if (!controller.signal.aborted) setProblem(problemFrom(error, "Your websites could not be loaded.")); });
    return () => controller.abort();
  }, [round]);
  const usable = (sites ?? []).filter((site) => site.state !== "partly_deleted");
  return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="files-sites">
    {problem && <ProblemAlert problem={problem} testId="files-sites-problem"><Button variant="outline" size="sm" onClick={() => setRound((v) => v + 1)}><RefreshCw aria-hidden="true" />Try again</Button></ProblemAlert>}
    {!sites && !problem && <div aria-busy="true" className="flex flex-col gap-2"><span className="sr-only">Loading your websites</span><Skeleton className="h-14 w-full" /><Skeleton className="h-14 w-full" /></div>}
    {sites && <section className={`${panel} flex flex-col gap-3 p-5 md:p-6`} aria-labelledby="files-sites-heading">
      <h2 id="files-sites-heading">Choose a website</h2>
      <p className="text-sm">Each website has its own home folder. Open one to see, upload, edit and download its files.</p>
      {usable.length === 0
        ? <Empty className="border border-dashed border-border py-8"><EmptyHeader><EmptyMedia variant="icon"><Folder aria-hidden="true" /></EmptyMedia><EmptyTitle>No websites yet</EmptyTitle><EmptyDescription>Create a website first; its files then appear here.</EmptyDescription></EmptyHeader></Empty>
        : <ul role="list" className="flex flex-col gap-2">
          {usable.map((site) => <li key={site.account_id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-3" data-testid="files-site">
            <div className="flex min-w-0 flex-col">
              <span className="font-medium wrap-anywhere text-foreground">{site.domain}</span>
              <span className="text-sm text-muted-foreground">{site.state === "suspended" ? "Suspended: files are read-only" : site.kind === "php" ? "PHP site" : "WordPress"}</span>
            </div>
            <Link to="/websites/sites/$accountId/files" params={{ accountId: site.account_id }} className={linkButton("outline")} data-testid="files-site-open"><FolderOpen aria-hidden="true" />Open files<span className="sr-only"> of {site.domain}</span></Link>
          </li>)}
        </ul>}
      <div className="text-sm text-muted-foreground">Files of the older static sites open from <Link to="/websites/static" className="text-primary underline">Static sites (old)</Link>.</div>
    </section>}
  </div>;
}
