import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { SideNav, SideNavItem, SideNavSection } from "@astryxdesign/core/SideNav";
import { Theme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral/built";
import { Archive, CircleDollarSign, Clock3, FileCheck2, Folder, Globe, HardDrive, Home, Info, Layers, LockKeyhole, Menu, Moon, Network, RefreshCw, Search, Server, Sun, Users, X } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { HostingWorkspace, Overview, ServiceInventory } from "@/Dashboard";
import { useResource, validBudget, validPlatform, validServer, validServices, validStatus, validTrail } from "@/lib/api";
import type { Resource } from "@/lib/api";
import type { RestoreHandoff } from "@/lib/restoreHandoff";

const Evidence = lazy(() => import("@/Tools").then((m) => ({ default: m.Evidence })));
const Trail = lazy(() => import("@/Tools").then((m) => ({ default: m.Trail })));
const Budget = lazy(() => import("@/Tools").then((m) => ({ default: m.Budget })));
const Platforms = lazy(() => import("@/Tools").then((m) => ({ default: m.Platforms })));
const Websites = lazy(() => import("@/Websites"));
const Accounts = lazy(() => import("@/Accounts"));
const Backups = lazy(() => import("@/Backups"));
const FileManager = lazy(() => import("@/FileManager"));
const Access = lazy(() => import("@/Access"));
const Storage = lazy(() => import("@/HostResources").then((m) => ({ default: m.Storage })));
const NetworkResources = lazy(() => import("@/HostResources").then((m) => ({ default: m.NetworkResources })));
const PanelPreview = lazy(() => import("@/PanelPreview"));

type View = "overview" | "services" | "storage" | "network" | "panel-preview" | "websites" | "accounts" | "backups" | "files" | "access" | "evidence" | "trail" | "budget" | "platform";
export interface SiteHandoff { requestId: number; siteId: string; siteName: string; restore?: RestoreHandoff }
const views = [
  { id: "overview", label: "Overview", title: "Hosting workspace", subtitle: "Manage your websites and server from one workspace.", icon: Home },
  { id: "services", label: "Services", title: "Services", subtitle: "Inspect the services installed on your server.", icon: Server },
  { id: "storage", label: "Storage", title: "Storage", subtitle: "Inspect real host volumes, capacity and available space.", icon: HardDrive },
  { id: "network", label: "Network", title: "Network", subtitle: "Follow measured traffic rates and host transfer counters.", icon: Network },
  { id: "panel-preview", label: "Panel preview", title: "Panel preview", subtitle: "Explore File Manager, Backups and Websites with sample content.", icon: Layers },
  { id: "websites", label: "Websites", title: "Websites", subtitle: "Manage your actual app-owned static sites locally.", icon: Globe },
  { id: "accounts", label: "Accounts", title: "Linux accounts", subtitle: "Manage local Linux identities and home directories.", icon: Users },
  { id: "backups", label: "Backups", title: "Website backups", subtitle: "Create, export and restore native static-site ZIP snapshots.", icon: Archive },
  { id: "files", label: "File Manager", title: "File Manager", subtitle: "Browse actual static-site paths and edit saved UTF-8 files.", icon: Folder },
  { id: "evidence", label: "Compatibility", title: "Compatibility evidence", subtitle: "Track the workflows that still need to be verified.", icon: FileCheck2 },
  { id: "access", label: "Access", title: "Access & sessions", subtitle: "Review local operator sessions and control access to this server.", icon: LockKeyhole },
  { id: "trail", label: "Change trail", title: "Change trail", subtitle: "Follow scoped file changes and their recovery history.", icon: Clock3 },
  { id: "budget", label: "AI budget", title: "AI spending controls", subtitle: "Keep paid AI work within a fixed monthly allowance.", icon: CircleDollarSign },
  { id: "platform", label: "Platforms", title: "Platform profiles", subtitle: "Review native targets and hosting runtime requirements.", icon: Layers },
] as const;

function initialTheme(): "light" | "dark" {
  try {
    if (localStorage.getItem("sifruno-theme") === "dark") return "dark";
  } catch { /* Persistence is optional. */ }
  return "light";
}

function DataState({ resource, retry, children }: { resource: Resource<unknown>; retry: () => void; children: React.ReactNode }) {
  if (resource.loading && !resource.data) return <div className="loading-state" role="status" aria-label="Loading server data"><Skeleton className="h-28 w-full" /><Skeleton className="h-64 w-full" /><span className="sr-only">Loading server data</span></div>;
  if (resource.error && !resource.data) return <Alert variant="destructive"><AlertTitle>Server data is unavailable</AlertTitle><AlertDescription><p>{resource.error}</p><Button label="Retry connection" variant="secondary" icon={<RefreshCw />} onClick={retry} /></AlertDescription></Alert>;
  return <>{resource.error && <div className="connection-notice" role="alert"><Info /><span>{resource.error} Showing the last successful reading.</span><Button label="Retry connection" variant="ghost" size="sm" onClick={retry} /></div>}{children}</>;
}

export function App() {
  const [view, setView] = useState<View>("overview");
  const [theme, setTheme] = useState(initialTheme);
  const [revision, setRevision] = useState(0);
  const [menuOpen, setMenuOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [serviceQuery, setServiceQuery] = useState("");
  const [range, setRange] = useState("60");
  const [websitesVisited, setWebsitesVisited] = useState(false);
  const [accountsVisited, setAccountsVisited] = useState(false);
  const [backupsVisited, setBackupsVisited] = useState(false);
  const [filesVisited, setFilesVisited] = useState(false);
  const [filesHandoff, setFilesHandoff] = useState<SiteHandoff>();
  const [backupsHandoff, setBackupsHandoff] = useState<SiteHandoff>();
  const [importRequest, setImportRequest] = useState<number>();
  const handoffSequence = useRef(0);
  const consumeImportRequest = useCallback((requestId: number) => setImportRequest((current) => current === requestId ? undefined : current), []);
  const consumeFilesHandoff = useCallback((requestId: number) => setFilesHandoff((current) => current?.requestId === requestId ? undefined : current), []);
  const consumeBackupsHandoff = useCallback((requestId: number) => setBackupsHandoff((current) => current?.requestId === requestId ? undefined : current), []);
  const [websitesResource, setWebsitesResource] = useState<Resource<unknown>>({ loading: false });
  const [accountsResource, setAccountsResource] = useState<Resource<unknown>>({ loading: false });
  const [backupsResource, setBackupsResource] = useState<Resource<unknown>>({ loading: false });
  const [filesResource, setFilesResource] = useState<Resource<unknown>>({ loading: false });
  const [accessResource, setAccessResource] = useState<Resource<unknown>>({ loading: false });
  const publicPreview = Boolean(document.querySelector('meta[name="sifruno-public-preview"]'));
  const status = useResource("/api/v1/status", validStatus, revision);
  const platform = useResource("/api/v1/platform", validPlatform, revision);
  const trail = useResource(!publicPreview && view === "trail" ? "/api/v1/trail" : null, validTrail, revision);
  const budget = useResource(!publicPreview && view === "budget" ? "/api/v1/budget" : null, validBudget, revision);
  const server = useResource(`/api/v1/server?range_seconds=${range}`, validServer, revision, 5000);
  const services = useResource("/api/v1/services", validServices, revision, 30000);
  const refresh = () => setRevision((v) => v + 1);
  const visibleViews = views.filter((v) => v.id === "panel-preview" ? publicPreview : !publicPreview || (v.id !== "websites" && v.id !== "accounts" && v.id !== "backups" && v.id !== "files" && v.id !== "access" && v.id !== "trail" && v.id !== "budget"));
  const active = views.find((v) => v.id === view)!;
  const activeResource = ["overview", "storage", "network"].includes(view) ? server : view === "services" ? services : view === "websites" ? websitesResource : view === "accounts" ? accountsResource : view === "backups" ? backupsResource : view === "files" ? filesResource : view === "access" ? accessResource : view === "evidence" ? status : view === "trail" ? trail : view === "budget" ? budget : platform;
  const connected = Boolean(server.data && !server.error);
  const partial = server.data?.collector.status === "partial";
  const unavailable = server.data?.collector.status === "unavailable";
  const navigate = (next: View) => { if ((!publicPreview && next === "panel-preview") || (publicPreview && ["websites", "accounts", "backups", "files", "access", "trail", "budget"].includes(next))) return; if (next !== "backups") setBackupsHandoff(current => current?.restore ? undefined : current); if (next === "websites") setWebsitesVisited(true); if (next === "accounts") setAccountsVisited(true); if (next === "backups") setBackupsVisited(true); if (next === "files") setFilesVisited(true); setView(next); setMenuOpen(false); setSearch(""); };
  const openSiteTool = (destination: "files" | "backups", siteId: string, siteName: string, restore?: RestoreHandoff) => {
    if (publicPreview) return;
    const request = { requestId: ++handoffSequence.current, siteId, siteName, ...(destination === "backups" && restore ? { restore } : {}) };
    if (destination === "files") setFilesHandoff(request); else setBackupsHandoff(request);
    navigate(destination);
  };
  const openZIPImport = () => { if (publicPreview) return; setImportRequest(++handoffSequence.current); navigate("websites"); };
  const results = useMemo(() => {
    const q = search.trim().toLowerCase();
    return q ? {
      sections: visibleViews.filter((v) => `${v.label} ${v.title}`.toLowerCase().includes(q)),
      services: (services.data?.items ?? []).filter((s) => `${s.name} ${s.display_name}`.toLowerCase().includes(q)).slice(0, 5),
    } : undefined;
  }, [search, services.data, publicPreview]);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    try { localStorage.setItem("sifruno-theme", theme); } catch { /* Optional. */ }
  }, [theme]);
  useEffect(() => {
    if (!menuOpen) return;
    const close = (e: KeyboardEvent) => { if (e.key === "Escape") setMenuOpen(false); };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [menuOpen]);

  const logo = <img src="/brand/logos/sifruno-logo-on-dark.svg" alt="Sifruno" width="164" height="46" />;
  const mobileLogo = <img src={`/brand/logos/sifruno-logo-${theme === "dark" ? "on-dark" : "primary"}.svg`} alt="Sifruno" width="164" height="46" />;
  const navItem = ({ id, label, icon: Icon }: (typeof views)[number]) => <SideNavItem key={id} label={label} icon={<Icon aria-hidden="true" />} isSelected={view === id} onClick={() => navigate(id)} className="panel-nav-item" size="sm" data-testid={`nav-${id}`} />;

  return <Theme theme={neutralTheme} mode={theme}>
    <a href="#panel-main" className="skip-link">Skip to panel content</a>
    <div className="panel-shell">
      <aside className="panel-sidebar" data-open={menuOpen}>
        <SideNav id="panel-navigation" className="panel-nav" aria-label="Panel sections"
          header={<button className="brand-link" aria-label="Sifruno server overview" onClick={() => navigate("overview")}>{logo}</button>}
          footer={<div className="sidebar-status"><i className={`status-dot ${!connected || unavailable ? "status-muted" : ""}`} /><div>Local server<small>{server.error ? "Connection lost" : connected ? partial ? "Partial monitoring" : unavailable ? "Measurements unavailable" : `Sampling every ${server.data!.collector.interval_seconds}s` : "Connecting…"}</small></div></div>}
          footerIcons={<div className="theme-switch"><Button label={`Switch to ${theme === "light" ? "dark" : "light"} theme`} variant="ghost" size="lg" icon={theme === "light" ? <Moon /> : <Sun />} onClick={() => setTheme(theme === "light" ? "dark" : "light")}>{theme === "light" ? "Dark theme" : "Light theme"}</Button></div>}>
          <SideNavSection title="Workspace" isHeaderHidden className="primary-nav">{visibleViews.filter((v) => ["overview", "panel-preview"].includes(v.id)).map(navItem)}</SideNavSection>
          {!publicPreview && <SideNavSection title="Hosting" className="hosting-nav">{["websites", "accounts", "backups", "files", "access"].map((id) => navItem(views.find((v) => v.id === id)!))}</SideNavSection>}
          <SideNavSection title="Monitoring" className="monitoring-nav">{visibleViews.filter((v) => ["services", "storage", "network"].includes(v.id)).map(navItem)}</SideNavSection>
          <SideNavSection title="System tools" className="tools-nav">{visibleViews.filter((v) => ["evidence", "trail", "budget", "platform"].includes(v.id)).map(navItem)}</SideNavSection>
          {publicPreview && <p className="sidebar-preview">Private tools are available in the local panel.</p>}
        </SideNav>
      </aside>
      <div className="panel-body">
        <header className="topbar">
          <div className="topbar-location"><div className="mobile-brand">{mobileLogo}</div><span className="breadcrumbs">Workspace <span>/</span> <strong>{active.label}</strong></span></div>
          <div className="topbar-actions">
            <div className="panel-search"><label className="compact-search"><Search aria-hidden="true" /><input type="search" aria-label="Search panel" placeholder="Search…" value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => { if (e.key === "Escape") setSearch(""); }} aria-controls={results ? "panel-search-results" : undefined} /></label>
              {results && <div id="panel-search-results" className="search-results" aria-label="Panel search results">
                {results.sections.map((v) => <Button key={v.id} label={v.label} variant="ghost" onClick={() => navigate(v.id)} />)}
                {results.services.map((s) => <Button key={s.id} label={s.display_name || s.name} variant="ghost" onClick={() => { setServiceQuery(s.name); navigate("services"); }} />)}
                {!results.sections.length && !results.services.length && <p>No matching section or service.</p>}
              </div>}
            </div>
            <Button label="Refresh server data" icon={<RefreshCw />} isIconOnly variant="secondary" size="lg" onClick={refresh} isDisabled={activeResource.loading} className="refresh-button" />
            <div className="monitoring-label"><i className={`status-dot ${!connected || unavailable ? "status-muted" : ""}`} /><div>{server.error ? "Connection lost" : connected ? partial ? "Partial monitoring" : unavailable ? "Monitoring unavailable" : "Live monitoring" : "Connecting…"}<small>{server.data ? `Sampling every ${server.data.collector.interval_seconds}s` : "Waiting for server data"}</small></div></div>
            <Button label={menuOpen ? "Close navigation" : "Open navigation"} icon={menuOpen ? <X /> : <Menu />} isIconOnly variant="ghost" size="lg" onClick={() => setMenuOpen(!menuOpen)} aria-expanded={menuOpen} aria-controls="panel-navigation" className="mobile-menu-button" />
          </div>
        </header>
        <main id="panel-main" tabIndex={-1}>
          <div className="page-heading"><h1>{active.title}</h1><p>{active.subtitle}</p></div>
          {publicPreview && view !== "overview" && <div className="hosting-notice public-preview-notice" role="status"><Info /><span>{view === "panel-preview" ? "Public panel tour · sample content. Private module actions stay in the local panel." : "Public preview · real host monitoring. Private websites, trail and spending records stay in the local panel."}</span></div>}
          {view === "services" && <div className="hosting-notice"><Info aria-hidden="true" /><span>Hosting engine in development. Compatibility is {status.data?.ready ? "reported ready by the service; review its evidence." : "not verified."}</span>{!publicPreview && <Button label="Review compatibility" variant="ghost" size="sm" onClick={() => navigate("evidence")}>Review</Button>}</div>}
          {view === "overview" && <div className="content-stack dashboard-stack">
            <HostingWorkspace publicPreview={publicPreview} platform={platform.data} onNavigate={navigate} onPreview={() => navigate("panel-preview")} />
            <section className="monitoring-workspace" aria-labelledby="monitoring-heading">
              <div className="workspace-section-heading"><div><h2 id="monitoring-heading">Server monitoring</h2><p>Measured resources and installed services.</p></div><span className="workspace-scope">Read-only</span></div>
              <DataState resource={server} retry={refresh}>{server.data && <Overview report={server.data} platform={platform.data} range={range} setRange={setRange} />}</DataState>
              <DataState resource={services} retry={refresh}>{services.data && <ServiceInventory report={services.data} compact query={serviceQuery} setQuery={setServiceQuery} viewAll={() => navigate("services")} />}</DataState>
            </section>
            <div className="hosting-notice"><Info aria-hidden="true" /><span>Hosting engine in development. Compatibility is {status.data?.ready ? "reported ready by the service; review its evidence." : "not verified."}</span>{!publicPreview && <Button label="Review compatibility" variant="ghost" size="sm" onClick={() => navigate("evidence")}>Review</Button>}</div>
          </div>}
          {view === "services" && <DataState resource={services} retry={refresh}>{services.data && <ServiceInventory report={services.data} query={serviceQuery} setQuery={setServiceQuery} />}</DataState>}
          <Suspense fallback={<div className="loading-state" role="status" aria-label="Loading panel tool"><Skeleton className="h-64 w-full" /></div>}>
          {view === "panel-preview" && publicPreview && <PanelPreview />}
          {view === "storage" && <DataState resource={server} retry={refresh}>{server.data && <Storage report={server.data} />}</DataState>}
          {view === "network" && <DataState resource={server} retry={refresh}>{server.data && <NetworkResources report={server.data} range={range} setRange={setRange} />}</DataState>}
          {websitesVisited && !publicPreview && <div hidden={view !== "websites"}><Websites revision={revision} active={view === "websites"} onStatus={setWebsitesResource} onOpenSiteTool={openSiteTool} importRequest={importRequest} onImportRequestConsumed={consumeImportRequest} /></div>}
          {accountsVisited && !publicPreview && <div hidden={view !== "accounts"}><Accounts revision={revision} active={view === "accounts"} onStatus={setAccountsResource} /></div>}
          {backupsVisited && !publicPreview && <div hidden={view !== "backups"}><Backups revision={revision} active={view === "backups"} onStatus={setBackupsResource} siteHandoff={backupsHandoff} onHandoffConsumed={consumeBackupsHandoff} onImportZIP={openZIPImport} /></div>}
          {filesVisited && !publicPreview && <div hidden={view !== "files"}><FileManager revision={revision} active={view === "files"} onStatus={setFilesResource} siteHandoff={filesHandoff} onHandoffConsumed={consumeFilesHandoff} /></div>}
          {view === "access" && !publicPreview && <Access revision={revision} onStatus={setAccessResource} />}
          {view === "evidence" && <DataState resource={status} retry={refresh}>{status.data && <Evidence report={status.data} />}</DataState>}
          {view === "trail" && !publicPreview && <DataState resource={trail} retry={refresh}>{trail.data && <Trail report={trail.data} />}</DataState>}
          {view === "budget" && !publicPreview && <DataState resource={budget} retry={refresh}>{budget.data && <Budget report={budget.data} />}</DataState>}
          {view === "platform" && <DataState resource={platform} retry={refresh}>{platform.data && <Platforms report={platform.data} />}</DataState>}
          </Suspense>
          <footer className="panel-footer"><span>{view === "panel-preview" ? "Sample workspace · read-only" : activeResource.loadedAt ? `Last checked ${activeResource.loadedAt.toLocaleTimeString()}` : "Waiting for server data"}</span><span>Sifruno</span></footer>
        </main>
      </div>
    </div>
  </Theme>;
}
