import { useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Archive, ArrowRight, ChevronRight, Code2, File, Folder, Globe, Layers, LockKeyhole, Search } from "lucide-react";
import type { Site, SiteBackup, SiteFile } from "@/lib/sites-api";
import "./panel-preview.css";

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

function FileGallery() {
  const [folder, setFolder] = useState("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(files[0]);
  const search = query.trim().toLowerCase();
  const folders = Array.from(new Set(files.filter((file) => file.path.startsWith(folder ? folder + "/" : "")).map((file) => file.path.slice(folder ? folder.length + 1 : 0).split("/")).filter((parts) => parts.length > 1).map((parts) => folder ? folder + "/" + parts[0] : parts[0])));
  const visible = files.filter((file) => search ? file.path.toLowerCase().includes(search) : file.path.split("/").slice(0, -1).join("/") === folder);
  function openFolder(path: string) { setFolder(path); setQuery(""); }
  return <div className="pp-workspace">
    <Card className="pp-card pp-browser" padding={0}>
      <div className="pp-card-heading"><div><h3>Files</h3><p>Studio website · sample inventory</p></div><span className="pp-count">5 files</span></div>
      <div className="pp-search"><Search aria-hidden="true" /><input aria-label="Search sample files" placeholder="Search sample files…" value={query} onChange={(event) => setQuery(event.target.value)} data-testid="preview-file-search" /></div>
      <nav className="pp-breadcrumb" aria-label="Sample folder path"><button type="button" onClick={() => openFolder("")}>public_html</button>{folder.split("/").filter(Boolean).map((part, index, parts) => <span key={index}><ChevronRight aria-hidden="true" /><button type="button" onClick={() => openFolder(parts.slice(0, index + 1).join("/"))}>{part}</button></span>)}</nav>
      <div className="pp-list" aria-label="Sample files">
        {!search && folders.map((path) => <button type="button" key={path} onClick={() => openFolder(path)} data-testid="preview-folder" data-path={path}><Folder aria-hidden="true" /><span>{path.split("/").at(-1)}<small>Folder</small></span><ChevronRight aria-hidden="true" /></button>)}
        {visible.map((file) => <button type="button" key={file.path} aria-pressed={selected.path === file.path} onClick={() => setSelected(file)} data-testid="preview-file-row" data-path={file.path}><File aria-hidden="true" /><span>{search ? file.path : file.path.split("/").at(-1)}<small>UTF-8 text</small></span><small>{formatBytes(file.bytes)}</small></button>)}
        {!visible.length && (search || !folders.length) && <p className="pp-empty" role="status">No sample files match this search.</p>}
      </div>
      <p className="pp-card-footnote">Browse folders or select a file to inspect its content.</p>
    </Card>
    <Card className="pp-card pp-file-preview" padding={0}>
      <div className="pp-card-heading"><div><h3><Code2 aria-hidden="true" />{selected.path}</h3><p>File content preview</p></div><span className="pp-readonly"><LockKeyhole aria-hidden="true" />Read-only</span></div>
      <pre data-testid="preview-file-content" data-path={selected.path}><code>{selected.content}</code></pre>
      <dl className="pp-file-facts"><div><dt>Size</dt><dd>{formatBytes(selected.bytes)}</dd></div><div><dt>Encoding</dt><dd>UTF-8</dd></div><div className="pp-wide"><dt>SHA-256 of this sample text</dt><dd><code>{selected.sha256}</code></dd></div></dl>
    </Card>
  </div>;
}

function BackupGallery() {
  const [selected, setSelected] = useState(backups[0]);
  return <div className="pp-workspace">
    <Card className="pp-card" padding={0}><div className="pp-card-heading"><div><h3>Website snapshots</h3><p>Studio website · sample archive records</p></div><span className="pp-count">2 snapshots</span></div>
      <div className="pp-list">{backups.map((backup) => <button type="button" key={backup.id} onClick={() => setSelected(backup)} aria-pressed={selected.id === backup.id} data-testid="preview-backup-row"><Archive aria-hidden="true" /><span>{backup.id}<small>{formatDate(backup.created_at)} · revision {backup.revision}</small></span><small>{formatBytes(backup.bytes)}</small></button>)}</div>
      <p className="pp-card-footnote">Select a snapshot to see its recorded metadata.</p>
    </Card>
    <Card className="pp-card" padding={0}><div className="pp-card-heading"><div><h3>Snapshot details</h3><p>Illustrative ZIP metadata</p></div><Archive aria-hidden="true" /></div>
      <dl className="pp-details" data-testid="preview-backup-details"><div><dt>Archive</dt><dd>{selected.id}</dd></div><div><dt>Created</dt><dd><time dateTime={selected.created_at}>{formatDate(selected.created_at)}</time></dd></div><div><dt>Files</dt><dd>{selected.files} static files</dd></div><div><dt>Revision</dt><dd>{selected.revision}</dd></div><div className="pp-wide"><dt>Illustrative SHA-256</dt><dd><code>{selected.sha256}</code></dd></div></dl>
      <div className="pp-context-note"><Layers aria-hidden="true" /><p>Private Backups manages native Sifruno static-site ZIPs. This tour displays sample records only.</p></div>
    </Card>
  </div>;
}

function WebsiteGallery() {
  const [selected, setSelected] = useState(sites[0]);
  return <div className="pp-workspace">
    <Card className="pp-card" padding={0}><div className="pp-card-heading"><div><h3>Websites</h3><p>Sample workspace inventory</p></div><span className="pp-count">2 websites</span></div>
      <div className="pp-list">{sites.map((site) => <button type="button" key={site.id} onClick={() => setSelected(site)} aria-pressed={selected.id === site.id} data-testid="preview-site-row"><Globe aria-hidden="true" /><span>{site.name}<small>{site.domain}</small></span><span className={`pp-site-state ${site.state === "active" ? "pp-active" : ""}`}>{site.state === "active" ? "Active" : "Suspended"}</span></button>)}</div>
      <p className="pp-card-footnote">Domains and states shown here are sample metadata.</p>
    </Card>
    <Card className="pp-card" padding={0}><div className="pp-card-heading"><div><h3>{selected.name}</h3><p>Configuration preview</p></div><Globe aria-hidden="true" /></div>
      <dl className="pp-details" data-testid="preview-site-details"><div className="pp-wide"><dt>Sample domain</dt><dd><code>{selected.domain}</code></dd></div><div><dt>Website state</dt><dd>{selected.state === "active" ? "Active" : "Suspended"}</dd></div><div><dt>Revision</dt><dd>{selected.revision}</dd></div><div><dt>Content type</dt><dd>Static files</dd></div><div><dt>Workspace</dt><dd>App-owned site</dd></div></dl>
      <div className="pp-context-note"><Folder aria-hidden="true" /><p>The private Websites view connects site records, file content and native ZIP snapshots.</p></div>
    </Card>
  </div>;
}

export interface PanelPreviewProps { className?: string }

/** Public-safe design tour: static samples and in-memory gallery interactions. */
export default function PanelPreview({ className = "" }: PanelPreviewProps) {
  const [module, setModule] = useState<Module>("files");
  const current = modules.find((item) => item.id === module)!;
  return <section className={`panel-preview ${className}`} data-testid="panel-preview" aria-label="Sample panel workspace">
    <div className="pp-banner"><div className="pp-banner-icon"><Layers aria-hidden="true" /></div><div><span className="pp-eyebrow">Sample workspace / read-only preview</span><h2>Your workspace, in focus.</h2><p>Explore the private module designs using sample files, snapshots and websites.</p></div><span className="pp-banner-tag"><LockKeyhole aria-hidden="true" />Sample content</span></div>
    <div className="pp-module-bar" aria-label="Preview modules">{modules.map((item) => <Button key={item.id} label={item.name} icon={<item.icon />} variant={module === item.id ? "primary" : "ghost"} size="sm" onClick={() => setModule(item.id)} aria-pressed={module === item.id} data-testid={`preview-module-${item.id}`} />)}</div>
    <div className="pp-module-caption"><div><h2>{current.name}</h2><p>{current.description}</p></div><span><ArrowRight aria-hidden="true" />Select items to explore</span></div>
    {module === "files" ? <FileGallery /> : module === "backups" ? <BackupGallery /> : <WebsiteGallery />}
    <p className="pp-boundary"><LockKeyhole aria-hidden="true" />This public tour uses sample content. Private workflows require local operator sign-in.</p>
  </section>;
}
