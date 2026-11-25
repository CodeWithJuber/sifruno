import { useState } from "react";
import type { ReactNode } from "react";
import { cn } from "cn";
import { Archive, ArrowRight, ChevronRight, Code2, File, Folder, Globe, Layers, LockKeyhole, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { panel, TechnicalDetails } from "@/Dashboard";
import type { Site, SiteBackup, SiteFile } from "@/lib/sites-api";

type Module = "files" | "backups" | "websites";
type PreviewFile = SiteFile & { content: string };
const files: PreviewFile[] = [
  { path: "index.html", bytes: 250, sha256: "ff8a7f4716deee65420e6055ec583c9a41c5d1ff0488f1e3584fdf34fabb9756", content: '<!doctype html>\n<html lang="en">\n  <head>\n    <title>Studio website</title>\n    <link rel="stylesheet" href="assets/styles.css">\n  </head>\n  <body>\n    <h1>A place for your next idea.</h1>\n    <p>Welcome to our sample workspace.</p>\n  </body>\n</html>' },
  { path: "assets/styles.css", bytes: 112, sha256: "5e130e7c435638be775fda9b7e1f691e513cb9160a764a84da5f5bd5dfab1810", content: ':root { color-scheme: light dark; }\nbody { font-family: system-ui, sans-serif; }\nh1 { letter-spacing: -0.03em; }' },
  { path: "assets/app.js", bytes: 78, sha256: "428628e1986470ff9180d9a649f7d49e09200accb32a5b4086238e8a5fe94223", content: '// Sample file preview\nconst title = "Studio website";\ndocument.title = title;' },
  { path: "notes/readme.txt", bytes: 121, sha256: "8ae1d7ee8ef1d36148f31d5f9a8cda14089068fa61ac810a8711a6019434baf1", content: "Sample workspace\n\nThese files illustrate the private File Manager design.\nNo customer files or server settings are shown." },
  { path: "docs/help.html", bytes: 95, sha256: "e35690f3e00639a7d3dfc12894792632a2b72f5590658237619c44ac81f4ff9c", content: "<article>\n  <h1>Help center</h1>\n  <p>A small static website, organized clearly.</p>\n</article>" },
];
const sites: Pick<Site, "id" | "name" | "domain" | "state" | "revision">[] = [
  { id: "00000000000000000000000000000000", name: "Studio website", domain: "studio.example.test", state: "active", revision: 4 },
  { id: "11111111111111111111111111111111", name: "Documentation", domain: "docs.example.test", state: "suspended", revision: 2 },
];
// Illustrative archive records; no ZIP is created or downloadable in this tour.
const backups: Pick<SiteBackup, "id" | "created_at" | "bytes" | "files" | "sha256" | "revision">[] = [
  { id: "studio-revision-4.zip", created_at: "2026-10-01T10:30:00Z", bytes: 1480, files: 5, sha256: "a4".repeat(32), revision: 4 },
  { id: "studio-revision-3.zip", created_at: "2026-09-30T16:45:00Z", bytes: 1216, files: 4, sha256: "b3".repeat(32), revision: 3 },
];
const modules = [
  { id: "files", name: "File Manager", icon: Folder, description: "A clear path from folders to file content." },
  { id: "backups", name: "Backups", icon: Archive, description: "Native static-site snapshots, with details at a glance." },
  { id: "websites", name: "Websites", icon: Globe, description: "Website state and configuration in one place." },
] as const;
const formatBytes = (value: number) => value < 1024 ? `${value} B` : `${(value / 1024).toFixed(1)} KiB`;
const formatDate = (value: string) => new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeZone: "UTC" }).format(new Date(value));

// The base styles colour <p> outside Tailwind's layers, so coloured text uses
// div or span, as on the other rebuilt screens.
const muted = "text-xs text-muted-foreground";
// Rows sit in a padded list, so the global focus outline has room to show.
const row = "flex w-full items-center gap-2.5 rounded-md border border-transparent px-2.5 py-3 text-start text-sm text-foreground hover:bg-muted aria-pressed:border-border aria-pressed:bg-secondary [&>svg]:shrink-0 [&>svg:first-child]:size-4.5 [&>svg:first-child]:text-muted-foreground aria-pressed:[&>svg:first-child]:text-primary";

function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn(panel, "min-w-0 overflow-hidden", className)}>{children}</div>;
}

function CardHeading({ title, note, children }: { title: ReactNode; note: string; children: ReactNode }) {
  return <div className="flex min-h-18 items-center justify-between gap-3 border-b border-border p-4">
    <div className="min-w-0"><h3 className="flex items-center gap-2 text-sm! wrap-anywhere">{title}</h3><div className={cn("mt-1", muted)}>{note}</div></div>
    {children}
  </div>;
}

function Count({ children }: { children: ReactNode }) {
  return <span className="shrink-0 rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">{children}</span>;
}

function Facts({ testId, children }: { testId?: string; children: ReactNode }) {
  return <dl className="grid grid-cols-2 gap-4 p-4" data-testid={testId}>{children}</dl>;
}

function Fact({ label, wide, children }: { label: string; wide?: boolean; children: ReactNode }) {
  return <div className={cn("min-w-0", wide && "col-span-full")}><dt className={muted}>{label}</dt><dd className="mt-1.5 text-sm text-foreground wrap-anywhere">{children}</dd></div>;
}

function ContextNote({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return <div className="flex items-start gap-2.5 border-t border-border bg-muted px-4 py-3.5 [&>svg]:mt-0.5 [&>svg]:size-4 [&>svg]:shrink-0 [&>svg]:text-muted-foreground">{icon}<div className="text-xs leading-relaxed text-muted-foreground">{children}</div></div>;
}

function Workspace({ children }: { children: ReactNode }) {
  return <div className="grid min-w-0 items-start gap-4 @3xl:grid-cols-[minmax(16rem,0.9fr)_minmax(0,1.25fr)]">{children}</div>;
}

function FileGallery() {
  const [folder, setFolder] = useState("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(files[0]);
  const search = query.trim().toLowerCase();
  const folders = Array.from(new Set(files.filter((file) => file.path.startsWith(folder ? folder + "/" : "")).map((file) => file.path.slice(folder ? folder.length + 1 : 0).split("/")).filter((parts) => parts.length > 1).map((parts) => folder ? folder + "/" + parts[0] : parts[0])));
  const visible = files.filter((file) => search ? file.path.toLowerCase().includes(search) : file.path.split("/").slice(0, -1).join("/") === folder);
  function openFolder(path: string) { setFolder(path); setQuery(""); }
  const crumb = "rounded-sm py-0.5 text-xs text-primary hover:underline";
  return <Workspace>
    <Card>
      <CardHeading title="Files" note="Studio website · sample inventory"><Count>5 files</Count></CardHeading>
      <div className="relative mx-4 mt-4">
        <Search className="pointer-events-none absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
        <Input type="search" name="sample-file-search" autoComplete="off" spellCheck={false} aria-label="Search sample files" placeholder="Search sample files…" value={query} onChange={(event) => setQuery(event.target.value)} data-testid="preview-file-search" className="ps-8 pointer-coarse:h-11!" />
      </div>
      <nav className="flex flex-wrap items-center gap-1 px-4 pt-3.5 pb-1.5" aria-label="Sample folder path">
        <button type="button" className={crumb} onClick={() => openFolder("")}>public_html</button>
        {folder.split("/").filter(Boolean).map((part, index, parts) => <span key={index} className="flex items-center gap-1"><ChevronRight className="size-3 text-muted-foreground rtl:-scale-x-100" aria-hidden="true" /><button type="button" className={crumb} onClick={() => openFolder(parts.slice(0, index + 1).join("/"))}>{part}</button></span>)}
      </nav>
      <div className="grid gap-1 p-3" role="group" aria-label="Sample files">
        {!search && folders.map((path) => <button type="button" key={path} className={row} onClick={() => openFolder(path)} data-testid="preview-folder" data-path={path}>
          <Folder aria-hidden="true" /><span className="min-w-0 flex-1 wrap-anywhere">{path.split("/").at(-1)}<small className={cn("mt-1 block", muted)}>Folder</small></span><ChevronRight className="size-3.5 text-muted-foreground rtl:-scale-x-100" aria-hidden="true" />
        </button>)}
        {visible.map((file) => <button type="button" key={file.path} className={row} aria-pressed={selected.path === file.path} onClick={() => setSelected(file)} data-testid="preview-file-row" data-path={file.path}>
          <File aria-hidden="true" /><span className="min-w-0 flex-1 wrap-anywhere">{search ? file.path : file.path.split("/").at(-1)}<small className={cn("mt-1 block", muted)}>UTF-8 text</small></span><small className={muted}>{formatBytes(file.bytes)}</small>
        </button>)}
        {!visible.length && (search || !folders.length) && <div className={cn("px-2.5 py-4", muted)} role="status">No sample files match this search.</div>}
      </div>
      <div className={cn("px-4 pt-1 pb-4", muted)}>Browse folders or select a file to inspect its content.</div>
    </Card>
    <Card>
      <CardHeading title={<><Code2 className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />{selected.path}</>} note="File content preview"><Badge variant="outline" className="text-muted-foreground"><LockKeyhole aria-hidden="true" />Read-only</Badge></CardHeading>
      {/* Code reads left to right in every language. */}
      <pre dir="ltr" className="m-0 max-h-110 min-h-60 overflow-y-auto bg-muted px-4 py-5 text-start font-mono text-xs leading-[1.9] whitespace-pre-wrap text-foreground wrap-anywhere" data-testid="preview-file-content" data-path={selected.path}><code>{selected.content}</code></pre>
      <div className="border-t border-border">
        <Facts><Fact label="Size">{formatBytes(selected.bytes)}</Fact><Fact label="Encoding">UTF-8</Fact></Facts>
        <div className="px-4 pb-4"><TechnicalDetails>SHA-256 of this sample text{"\n"}{selected.sha256}</TechnicalDetails></div>
      </div>
    </Card>
  </Workspace>;
}

function BackupGallery() {
  const [selected, setSelected] = useState(backups[0]);
  return <Workspace>
    <Card>
      <CardHeading title="Website snapshots" note="Studio website · sample archive records"><Count>2 snapshots</Count></CardHeading>
      <div className="grid gap-1 p-3" role="group" aria-label="Sample snapshots">{backups.map((backup) => <button type="button" key={backup.id} className={row} onClick={() => setSelected(backup)} aria-pressed={selected.id === backup.id} data-testid="preview-backup-row">
        <Archive aria-hidden="true" /><span className="min-w-0 flex-1 wrap-anywhere">{backup.id}<small className={cn("mt-1 block", muted)}>{formatDate(backup.created_at)} · {backup.files} files</small></span><small className={muted}>{formatBytes(backup.bytes)}</small>
      </button>)}</div>
      <div className={cn("px-4 pt-1 pb-4", muted)}>Select a snapshot to see its recorded metadata.</div>
    </Card>
    <Card>
      <CardHeading title="Snapshot details" note="Illustrative ZIP metadata"><Archive className="size-4 text-muted-foreground" aria-hidden="true" /></CardHeading>
      <Facts testId="preview-backup-details">
        <Fact label="Archive">{selected.id}</Fact>
        <Fact label="Created"><time dateTime={selected.created_at}>{formatDate(selected.created_at)}</time></Fact>
        <Fact label="Files">{selected.files} static files</Fact>
        <Fact label="Size">{formatBytes(selected.bytes)}</Fact>
      </Facts>
      <div className="px-4 pb-4"><TechnicalDetails>Revision {selected.revision}{"\n"}Illustrative SHA-256{"\n"}{selected.sha256}</TechnicalDetails></div>
      <ContextNote icon={<Layers aria-hidden="true" />}>Private Backups manages native Sifruno static-site ZIPs. This tour displays sample records only.</ContextNote>
    </Card>
  </Workspace>;
}

function WebsiteGallery() {
  const [selected, setSelected] = useState(sites[0]);
  const state = (site: typeof selected) => site.state === "active" ? "Active" : "Suspended";
  return <Workspace>
    <Card>
      <CardHeading title="Websites" note="Sample workspace inventory"><Count>2 websites</Count></CardHeading>
      <div className="grid gap-1 p-3" role="group" aria-label="Sample websites">{sites.map((site) => <button type="button" key={site.id} className={row} onClick={() => setSelected(site)} aria-pressed={selected.id === site.id} data-testid="preview-site-row">
        <Globe aria-hidden="true" /><span className="min-w-0 flex-1 wrap-anywhere">{site.name}<small className={cn("mt-1 block", muted)}>{site.domain}</small></span><Badge variant={site.state === "active" ? "secondary" : "outline"} className={site.state === "active" ? "text-primary" : "text-muted-foreground"}>{state(site)}</Badge>
      </button>)}</div>
      <div className={cn("px-4 pt-1 pb-4", muted)}>Domains and states shown here are sample metadata.</div>
    </Card>
    <Card>
      <CardHeading title={selected.name} note="Configuration preview"><Globe className="size-4 text-muted-foreground" aria-hidden="true" /></CardHeading>
      <Facts testId="preview-site-details">
        <Fact label="Sample domain" wide><code>{selected.domain}</code></Fact>
        <Fact label="Website state">{state(selected)}</Fact>
        <Fact label="Content type">Static files</Fact>
        <Fact label="Workspace">App-owned site</Fact>
      </Facts>
      <div className="px-4 pb-4"><TechnicalDetails>Revision {selected.revision}</TechnicalDetails></div>
      <ContextNote icon={<Folder aria-hidden="true" />}>The private Websites view connects site records, file content and native ZIP snapshots.</ContextNote>
    </Card>
  </Workspace>;
}

export interface PanelPreviewProps { className?: string }

/** Public-safe design tour: static samples and in-memory gallery interactions. */
export default function PanelPreview({ className = "" }: PanelPreviewProps) {
  const [module, setModule] = useState<Module>("files");
  const current = modules.find((item) => item.id === module)!;
  return <section className={cn("@container flex min-w-0 flex-col gap-5 text-foreground", className)} data-testid="panel-preview" aria-label="Sample panel workspace">
    <div className={cn(panel, "flex items-center gap-4 p-5 @max-md:items-start @max-md:gap-3 @max-md:p-4")}>
      <div className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-border bg-secondary text-primary @max-md:size-9"><Layers className="size-5.5" aria-hidden="true" /></div>
      <div className="min-w-0">
        <div className="text-xs font-semibold text-primary">Sample workspace / read-only preview</div>
        <h2 className="my-1.5 text-xl! @max-md:text-lg!">Your workspace, in focus.</h2>
        <div className="text-sm text-muted-foreground">Explore the private module designs using sample files, snapshots and websites.</div>
      </div>
      <Badge variant="outline" className="ms-auto hidden text-muted-foreground @3xl:inline-flex"><LockKeyhole aria-hidden="true" />Sample content</Badge>
    </div>
    <div className="flex flex-wrap gap-2" role="group" aria-label="Preview modules">{modules.map((item) => <Button key={item.id} variant={module === item.id ? "default" : "ghost"} className="h-9 @max-md:min-w-0 @max-md:flex-1 pointer-coarse:h-11" onClick={() => setModule(item.id)} aria-pressed={module === item.id} data-testid={`preview-module-${item.id}`}><item.icon aria-hidden="true" />{item.name}</Button>)}</div>
    <div className="flex items-center justify-between gap-3">
      <div className="min-w-0"><h2 className="text-base!">{current.name}</h2><div className={cn("mt-1", muted)}>{current.description}</div></div>
      <span className={cn("hidden shrink-0 items-center gap-1.5 @md:flex", muted)}><ArrowRight className="size-3.5 rtl:-scale-x-100" aria-hidden="true" />Select items to explore</span>
    </div>
    {module === "files" ? <FileGallery /> : module === "backups" ? <BackupGallery /> : <WebsiteGallery />}
    <div className={cn("flex items-start gap-2", muted)}><LockKeyhole className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" /><span>This public tour uses sample content. Private workflows require local operator sign-in.</span></div>
  </section>;
}
