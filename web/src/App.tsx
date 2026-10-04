import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { SideNav, SideNavItem, SideNavSection } from "@astryxdesign/core/SideNav";
import { Theme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral/built";
import { CircleDollarSign, Clock3, FileCheck2, Globe, Home, Info, Layers, Menu, Moon, RefreshCw, Search, Server, Sun, X } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { Overview, ServiceInventory } from "@/Dashboard";
import { useResource, validBudget, validPlatform, validServer, validServices, validStatus, validTrail } from "@/lib/api";
import type { Resource } from "@/lib/api";

const Evidence = lazy(() => import("@/Tools").then((m) => ({ default: m.Evidence })));
const Trail = lazy(() => import("@/Tools").then((m) => ({ default: m.Trail })));
const Budget = lazy(() => import("@/Tools").then((m) => ({ default: m.Budget })));
const Platforms = lazy(() => import("@/Tools").then((m) => ({ default: m.Platforms })));
const Websites = lazy(() => import("@/Websites"));

type View = "overview" | "services" | "websites" | "evidence" | "trail" | "budget" | "platform";
const views = [
  { id: "overview", label: "Overview", title: "Server overview", subtitle: "A clear view of your server, in real time.", icon: Home },
  { id: "services", label: "Services", title: "Services", subtitle: "Inspect the services installed on your server.", icon: Server },
  { id: "websites", label: "Websites", title: "Websites", subtitle: "Manage your actual app-owned static sites locally.", icon: Globe },
  { id: "evidence", label: "Compatibility", title: "Compatibility evidence", subtitle: "Track the workflows that still need to be verified.", icon: FileCheck2 },
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
  const [websitesResource, setWebsitesResource] = useState<Resource<unknown>>({ loading: false });
  const publicPreview = Boolean(document.querySelector('meta[name="sifruno-public-preview"]'));
  const status = useResource("/api/v1/status", validStatus, revision);
  const platform = useResource("/api/v1/platform", validPlatform, revision);
  const trail = useResource(!publicPreview && view === "trail" ? "/api/v1/trail" : null, validTrail, revision);
  const budget = useResource(!publicPreview && view === "budget" ? "/api/v1/budget" : null, validBudget, revision);
  const server = useResource(`/api/v1/server?range_seconds=${range}`, validServer, revision, 5000);
  const services = useResource("/api/v1/services", validServices, revision, 30000);
  const refresh = () => setRevision((v) => v + 1);
  const visibleViews = views.filter((v) => !publicPreview || (v.id !== "websites" && v.id !== "trail" && v.id !== "budget"));
  const active = views.find((v) => v.id === view)!;
  const activeResource = view === "overview" ? server : view === "services" ? services : view === "websites" ? websitesResource : view === "evidence" ? status : view === "trail" ? trail : view === "budget" ? budget : platform;
  const connected = Boolean(server.data && !server.error);
  const partial = server.data?.collector.status === "partial";
  const unavailable = server.data?.collector.status === "unavailable";
  const navigate = (next: View) => { if (next === "websites" && !publicPreview) setWebsitesVisited(true); setView(next); setMenuOpen(false); setSearch(""); };
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

  const logo = <img src={`/brand/logos/sifruno-logo-${theme === "dark" ? "on-dark" : "primary"}.svg`} alt="Sifruno" width="164" height="46" />;
  const navItem = ({ id, label, icon: Icon }: (typeof views)[number]) => <SideNavItem key={id} label={label} icon={<Icon aria-hidden="true" />} isSelected={view === id} onClick={() => navigate(id)} className="panel-nav-item" size="lg" data-testid={`nav-${id}`} />;

  return <Theme theme={neutralTheme} mode={theme}>
    <a href="#panel-main" className="skip-link">Skip to panel content</a>
    <div className="panel-shell">
      <aside className="panel-sidebar" data-open={menuOpen}>
        <SideNav id="panel-navigation" className="panel-nav" aria-label="Panel sections"
          header={<button className="brand-link" aria-label="Sifruno server overview" onClick={() => navigate("overview")}>{logo}</button>}
          footer={<div className="sidebar-status"><i className={`status-dot ${!connected || unavailable ? "status-muted" : ""}`} /><div>Local server<small>{server.error ? "Connection lost" : connected ? partial ? "Partial monitoring" : unavailable ? "Measurements unavailable" : `Sampling every ${server.data!.collector.interval_seconds}s` : "Connecting…"}</small></div></div>}
          footerIcons={<div className="theme-switch"><Button label={`Switch to ${theme === "light" ? "dark" : "light"} theme`} variant="ghost" size="lg" icon={theme === "light" ? <Moon /> : <Sun />} onClick={() => setTheme(theme === "light" ? "dark" : "light")}>{theme === "light" ? "Dark theme" : "Light theme"}</Button></div>}>
          <SideNavSection title="Server" isHeaderHidden className="primary-nav">{visibleViews.filter((v) => ["overview", "services", "websites"].includes(v.id)).map(navItem)}</SideNavSection>
          <SideNavSection title="Tools" className="tools-nav">{visibleViews.filter((v) => !["overview", "services", "websites"].includes(v.id)).map(navItem)}</SideNavSection>
          {publicPreview && <p className="sidebar-preview">Private tools are available in the local panel.</p>}
        </SideNav>
      </aside>
      <div className="panel-body">
        <header className="topbar">
          <div className="topbar-location"><div className="mobile-brand">{logo}</div><span className="breadcrumbs">Server <span>/</span> <strong>{active.label}</strong></span></div>
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
          {publicPreview && <div className="hosting-notice public-preview-notice" role="status"><Info /><span>Public preview · real host monitoring. Private websites, trail and spending records stay in the local panel.</span></div>}
          {(view === "overview" || view === "services") && <div className="hosting-notice"><Info aria-hidden="true" /><span>Hosting engine in development. Compatibility is {status.data?.ready ? "reported ready by the service; review its evidence." : "not verified."}</span>{!publicPreview && <Button label="Review compatibility" variant="ghost" size="sm" onClick={() => navigate("evidence")}>Review</Button>}</div>}
          {view === "overview" && <div className="content-stack dashboard-stack"><DataState resource={server} retry={refresh}>{server.data && <Overview report={server.data} platform={platform.data} range={range} setRange={setRange} />}</DataState><DataState resource={services} retry={refresh}>{services.data && <ServiceInventory report={services.data} compact query={serviceQuery} setQuery={setServiceQuery} viewAll={() => navigate("services")} />}</DataState></div>}
          {view === "services" && <DataState resource={services} retry={refresh}>{services.data && <ServiceInventory report={services.data} query={serviceQuery} setQuery={setServiceQuery} />}</DataState>}
          <Suspense fallback={<div className="loading-state" role="status" aria-label="Loading panel tool"><Skeleton className="h-64 w-full" /></div>}>
          {websitesVisited && !publicPreview && <div hidden={view !== "websites"}><Websites revision={revision} active={view === "websites"} onStatus={setWebsitesResource} /></div>}
          {view === "evidence" && <DataState resource={status} retry={refresh}>{status.data && <Evidence report={status.data} />}</DataState>}
          {view === "trail" && !publicPreview && <DataState resource={trail} retry={refresh}>{trail.data && <Trail report={trail.data} />}</DataState>}
          {view === "budget" && !publicPreview && <DataState resource={budget} retry={refresh}>{budget.data && <Budget report={budget.data} />}</DataState>}
          {view === "platform" && <DataState resource={platform} retry={refresh}>{platform.data && <Platforms report={platform.data} />}</DataState>}
          </Suspense>
          <footer className="panel-footer"><span>{activeResource.loadedAt ? `Last checked ${activeResource.loadedAt.toLocaleTimeString()}` : "Waiting for server data"}</span><span>Sifruno</span></footer>
        </main>
      </div>
    </div>
  </Theme>;
}
