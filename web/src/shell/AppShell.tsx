import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { Theme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral/built";
import { Info, Menu, Moon, RefreshCw, Search, Sun } from "lucide-react";
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarMenuSub, SidebarMenuSubButton, SidebarMenuSubItem, SidebarProvider, useSidebar } from "@/components/ui/sidebar";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useResource, validPlatform, validServer, validServices } from "@/lib/api";
import type { Resource, ServerReport } from "@/lib/api";
import type { BackupCopySelection, ZIPImportRequest } from "@/lib/backupCopy";
import type { RestoreHandoff } from "@/lib/restoreHandoff";
import { CommandPalette } from "@/shell/CommandPalette";
import type { CommandGroup } from "@/shell/CommandPalette";
import { ShellContext } from "@/shell/context";
import type { ScreenTarget, Shell, SiteHandoff } from "@/shell/context";
import { pageById, pages, visiblePages } from "@/shell/pages";
import type { Page, PageId } from "@/shell/pages";
import { LoadingState } from "@/shell/views";

const Websites = lazy(() => import("@/Websites"));
const Accounts = lazy(() => import("@/Accounts"));
const Backups = lazy(() => import("@/Backups"));
const FileManager = lazy(() => import("@/FileManager"));

// These screens hold work in progress (uploads, unsaved edits), so once opened
// they stay mounted and are hidden instead of unmounted on navigation.
const keptAlive = ["websites", "files", "backups", "customers"] as const;
type KeptAlive = (typeof keptAlive)[number];

const screenPages: Record<ScreenTarget, PageId> = { websites: "websites", accounts: "customers", backups: "backups", files: "files", access: "security" };

export function isPublicPreview(): boolean {
  return Boolean(document.querySelector('meta[name="sifruno-public-preview"]'));
}

// Ctrl+K and Cmd+K both open search; show the one this keyboard has.
const shortcutLabel = /Mac|iPhone|iPad/.test(navigator.userAgent) ? "⌘K" : "Ctrl K";

function pageForPath(pathname: string): Page | undefined {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  return pages.find((p) => p.path === path);
}

function initialTheme(): "light" | "dark" {
  try {
    if (localStorage.getItem("sifruno-theme") === "dark") return "dark";
  } catch { /* Persistence is optional: private windows can refuse storage. */ }
  return "light";
}

function serverState(server: Resource<ServerReport>) {
  if (server.error) return { live: false, label: "Connection lost", detail: "Retrying automatically" };
  if (!server.data) return { live: false, label: "Connecting…", detail: "Waiting for server data" };
  const { status, interval_seconds } = server.data.collector;
  if (status === "unavailable") return { live: false, label: "Measurements unavailable", detail: "The collector is not reporting" };
  return { live: true, label: status === "partial" ? "Partial monitoring" : "Live monitoring", detail: `Sampling every ${interval_seconds}s` };
}

export function AppShell() {
  const publicPreview = isPublicPreview();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const page = pageForPath(pathname);
  const [theme, setTheme] = useState(initialTheme);
  const [revision, setRevision] = useState(0);
  const [range, setRange] = useState("60");
  const [serviceQuery, setServiceQuery] = useState("");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [visited, setVisited] = useState<ReadonlySet<PageId>>(() => new Set());
  const [filesHandoff, setFilesHandoff] = useState<SiteHandoff>();
  const [backupsHandoff, setBackupsHandoff] = useState<SiteHandoff>();
  const [importRequest, setImportRequest] = useState<ZIPImportRequest>();
  const [pageResources, setPageResources] = useState<Partial<Record<PageId, Resource<unknown>>>>({});
  const handoffSequence = useRef(0);
  const platform = useResource("/api/v1/platform", validPlatform, revision);
  const server = useResource(`/api/v1/server?range_seconds=${range}`, validServer, revision, 5000);
  const services = useResource("/api/v1/services", validServices, revision, 30000);
  const refresh = useCallback(() => setRevision((v) => v + 1), []);
  const setPageResource = useCallback((id: PageId, value: Resource<unknown>) => setPageResources((current) => current[id] === value ? current : { ...current, [id]: value }), []);
  const reporters = useMemo(() => Object.fromEntries(keptAlive.map((id) => [id, (value: Resource<unknown>) => setPageResource(id, value)])) as Record<KeptAlive, (value: Resource<unknown>) => void>, [setPageResource]);
  const consumeImportRequest = useCallback((requestId: number) => setImportRequest((current) => current?.requestId === requestId ? undefined : current), []);
  const consumeFilesHandoff = useCallback((requestId: number) => setFilesHandoff((current) => current?.requestId === requestId ? undefined : current), []);
  const consumeBackupsHandoff = useCallback((requestId: number) => setBackupsHandoff((current) => current?.requestId === requestId ? undefined : current), []);
  const open = useCallback((target: ScreenTarget) => { navigate({ to: pageById(screenPages[target]).path }); }, [navigate]);
  const openSiteTool = useCallback((destination: "files" | "backups", siteId: string, siteName: string, restore?: RestoreHandoff) => {
    const request = { requestId: ++handoffSequence.current, siteId, siteName, ...(destination === "backups" && restore ? { restore } : {}) };
    if (destination === "files") setFilesHandoff(request); else setBackupsHandoff(request);
    navigate({ to: pageById(destination).path });
  }, [navigate]);
  const openZIPImport = useCallback((snapshot?: BackupCopySelection) => {
    setImportRequest({ requestId: ++handoffSequence.current, snapshot });
    navigate({ to: "/websites" });
  }, [navigate]);

  const pageId = page?.id;
  useEffect(() => {
    if (!pageId) return;
    if ((keptAlive as readonly string[]).includes(pageId)) setVisited((current) => current.has(pageId) ? current : new Set(current).add(pageId));
    // A ZIP import or restore request belongs to the visit that asked for it.
    if (pageId !== "websites") setImportRequest(undefined);
    if (pageId !== "backups") setBackupsHandoff((current) => current?.restore ? undefined : current);
  }, [pageId]);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    try { localStorage.setItem("sifruno-theme", theme); } catch { /* Optional, see initialTheme. */ }
  }, [theme]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() === "k" && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        setPaletteOpen((value) => !value);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  useEffect(() => {
    document.title = page ? `${page.label} · Sifruno` : "Page not found · Sifruno";
  }, [page]);

  const active: Resource<unknown> | undefined = !page ? undefined
    : page.id === "home" || page.id === "storage" || page.id === "network" ? server
    : page.id === "server" ? services
    : pageResources[page.id];
  const toggleTheme = useCallback(() => setTheme((value) => value === "light" ? "dark" : "light"), []);
  const shell: Shell = { publicPreview, revision, refresh, server, services, platform, range, setRange, serviceQuery, setServiceQuery, setPageResource, open };

  const commandGroups = useMemo<CommandGroup[]>(() => {
    const pageCommands = visiblePages(publicPreview).map((p) => {
      const parent = p.parent ? pageById(p.parent) : undefined;
      const label = parent ? `${parent.label} › ${p.label === "Server" ? "Services" : p.label}` : p.label;
      return { id: `page-${p.id}`, label, hint: "Page", search: label, run: () => navigate({ to: p.path }) };
    });
    const actions = [
      { id: "theme", label: theme === "light" ? "Switch to dark theme" : "Switch to light theme", hint: "Action", search: "theme dark light appearance", run: toggleTheme },
      { id: "refresh", label: "Refresh data", hint: "Action", search: "refresh reload update data", run: refresh },
    ];
    const serviceCommands = (services.data?.items ?? []).map((s) => ({
      id: `service-${s.id}`, label: s.display_name || s.name, hint: "Service", search: `${s.name} ${s.display_name} service`,
      run: () => { setServiceQuery(s.name); navigate({ to: "/server" }); },
    }));
    return [{ value: "Pages", items: pageCommands }, { value: "Actions", items: actions }, ...(serviceCommands.length ? [{ value: "Services", items: serviceCommands }] : [])];
  }, [publicPreview, theme, services.data, navigate, toggleTheme, refresh]);

  const status = serverState(server);
  const heading = page ? page.title : "Page not found";
  const subtitle = page ? page.subtitle : "";
  const parent = page?.parent && page.parent !== "server" ? pageById(page.parent) : undefined;

  return <ShellContext.Provider value={shell}>
    <TooltipProvider>
      <SidebarProvider>
        <a href="#panel-main" className="skip-link">Skip to panel content</a>
        <PanelSidebar page={page} publicPreview={publicPreview} status={status} theme={theme} onToggleTheme={toggleTheme} />
        <div className="flex min-w-0 flex-1 flex-col bg-background">
          <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-border bg-card px-4 md:px-7">
            <MobileMenuButton />
            <img className="h-7 w-auto md:hidden" src={`/brand/logos/sifruno-logo-${theme === "dark" ? "on-dark" : "primary"}.svg`} alt="Sifruno" width="100" height="28" />
            <Breadcrumb className="hidden md:block">
              <BreadcrumbList>
                {parent && <><BreadcrumbItem><BreadcrumbLink render={<Link to={parent.path} activeOptions={{ exact: true }} />}>{parent.label}</BreadcrumbLink></BreadcrumbItem><BreadcrumbSeparator /></>}
                <BreadcrumbItem><BreadcrumbPage>{page ? (page.parent === "server" ? `Server › ${page.label}` : page.label) : "Page not found"}</BreadcrumbPage></BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
            <div className="ms-auto flex items-center gap-2">
              <Button variant="outline" className="h-9 gap-2 px-2.5 text-muted-foreground sm:w-56 sm:justify-start" onClick={() => setPaletteOpen(true)} aria-label="Search pages and actions" data-testid="open-search">
                <Search aria-hidden="true" /><span className="hidden sm:inline">Search…</span><Kbd className="ms-auto hidden sm:inline-flex">{shortcutLabel}</Kbd>
              </Button>
              <Button variant="outline" size="icon" className="size-9" onClick={refresh} disabled={active?.loading} aria-label="Refresh server data" title="Refresh server data">
                <RefreshCw aria-hidden="true" />
              </Button>
            </div>
          </header>
          <main id="panel-main" tabIndex={-1} className="mx-auto w-full max-w-[1600px] min-w-0 flex-1 px-4 py-5 outline-none md:px-7 md:py-6">
            <div className="mb-5"><h1>{heading}</h1>{subtitle && <p className="mt-1.5 text-sm">{subtitle}</p>}</div>
            {publicPreview && page && page.id !== "home" && <div className="mb-4 flex items-center gap-2 text-xs text-muted-foreground" role="status"><Info className="size-4" aria-hidden="true" /><span>{page.id === "tour" ? "Public panel tour with sample content. Changes stay in the local panel." : "Public preview of real server monitoring. Websites, files and backups stay in the local panel."}</span></div>}
            <Theme theme={neutralTheme} mode={theme}>
              <Suspense fallback={<LoadingState label="Loading page" />}>
                <Outlet />
                {!publicPreview && visited.has("websites") && <div hidden={pageId !== "websites"}><Websites revision={revision} active={pageId === "websites"} onStatus={reporters.websites} onOpenSiteTool={openSiteTool} importRequest={importRequest} onImportRequestConsumed={consumeImportRequest} /></div>}
                {!publicPreview && visited.has("customers") && <div hidden={pageId !== "customers"}><Accounts revision={revision} active={pageId === "customers"} onStatus={reporters.customers} /></div>}
                {!publicPreview && visited.has("backups") && <div hidden={pageId !== "backups"}><Backups revision={revision} active={pageId === "backups"} onStatus={reporters.backups} siteHandoff={backupsHandoff} onHandoffConsumed={consumeBackupsHandoff} onImportZIP={openZIPImport} /></div>}
                {!publicPreview && visited.has("files") && <div hidden={pageId !== "files"}><FileManager revision={revision} active={pageId === "files"} onStatus={reporters.files} siteHandoff={filesHandoff} onHandoffConsumed={consumeFilesHandoff} /></div>}
              </Suspense>
            </Theme>
            <footer className="flex justify-between gap-4 pt-5 text-xs text-muted-foreground">
              <span>{page?.id === "tour" ? "Sample content, read-only" : active?.loadedAt ? `Last checked ${active.loadedAt.toLocaleTimeString()}` : "Waiting for server data"}</span>
              <span>Sifruno</span>
            </footer>
          </main>
        </div>
        <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} groups={commandGroups} />
      </SidebarProvider>
    </TooltipProvider>
  </ShellContext.Provider>;
}

function MobileMenuButton() {
  const { openMobile, toggleSidebar } = useSidebar();
  return <Button variant="ghost" size="icon" className="size-9 md:hidden" onClick={toggleSidebar} aria-label={openMobile ? "Close navigation" : "Open navigation"} aria-expanded={openMobile}>
    <Menu aria-hidden="true" />
  </Button>;
}

function PanelSidebar({ page, publicPreview, status, theme, onToggleTheme }: { page?: Page; publicPreview: boolean; status: ReturnType<typeof serverState>; theme: "light" | "dark"; onToggleTheme: () => void }) {
  const { setOpenMobile } = useSidebar();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  useEffect(() => { setOpenMobile(false); }, [pathname, setOpenMobile]);
  // Tapping the page you are already on changes no URL, so close it here too.
  const closeMobile = () => setOpenMobile(false);
  const shown = visiblePages(publicPreview);
  const top = (group: Page["group"]) => shown.filter((p) => p.group === group && !p.parent);
  const children = (id: PageId) => shown.filter((p) => p.parent === id && id !== "server");
  const isActive = (p: Page) => page?.id === p.id || (p.id === "server" && page?.parent === "server");
  const item = (p: Page) => {
    const Icon = p.icon;
    const subs = children(p.id);
    return <SidebarMenuItem key={p.id}>
      <SidebarMenuButton isActive={isActive(p)} render={<Link to={p.path} activeOptions={{ exact: true }} />} onClick={closeMobile} data-testid={p.testId} className="h-9 text-sidebar-foreground/90 data-active:text-sidebar-accent-foreground [&_svg]:text-sidebar-muted-foreground data-active:[&_svg]:text-sidebar-primary">
        <Icon aria-hidden="true" /><span>{p.label}</span>
      </SidebarMenuButton>
      {subs.length > 0 && <SidebarMenuSub>
        {subs.map((s) => <SidebarMenuSubItem key={s.id}>
          <SidebarMenuSubButton isActive={page?.id === s.id} render={<Link to={s.path} activeOptions={{ exact: true }} />} onClick={closeMobile} data-testid={s.testId} className="text-sidebar-foreground/85">
            <span>{s.label}</span>
          </SidebarMenuSubButton>
        </SidebarMenuSubItem>)}
      </SidebarMenuSub>}
    </SidebarMenuItem>;
  };
  return <Sidebar>
    <SidebarHeader className="border-b border-sidebar-border px-4 py-4">
      <Link to="/" activeOptions={{ exact: true }} aria-label="Sifruno home" className="w-fit"><img src="/brand/logos/sifruno-logo-on-dark.svg" alt="Sifruno" width="148" height="42" className="block h-auto w-[148px]" /></Link>
    </SidebarHeader>
    <SidebarContent>
      <nav aria-label="Panel sections">
      <SidebarGroup>
        <SidebarGroupContent><SidebarMenu className="gap-0.5">{top("main").map(item)}</SidebarMenu></SidebarGroupContent>
      </SidebarGroup>
      <SidebarGroup>
        <SidebarGroupLabel className="text-sidebar-muted-foreground">Administration</SidebarGroupLabel>
        <SidebarGroupContent><SidebarMenu className="gap-0.5">{top("admin").map(item)}</SidebarMenu></SidebarGroupContent>
      </SidebarGroup>
      </nav>
    </SidebarContent>
    <SidebarFooter className="border-t border-sidebar-border px-3 py-3">
      <div className="flex items-center gap-2.5 px-1 text-xs" role="status">
        <span className={`size-2 shrink-0 rounded-full ${status.live ? "bg-sidebar-primary" : "bg-sidebar-muted-foreground"}`} aria-hidden="true" />
        <div><div>{status.label}</div><div className="text-sidebar-muted-foreground">{status.detail}</div></div>
      </div>
      <Button variant="ghost" className="justify-start gap-2 px-2 text-xs text-sidebar-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground" onClick={onToggleTheme} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} theme`}>
        {theme === "light" ? <Moon aria-hidden="true" /> : <Sun aria-hidden="true" />}{theme === "light" ? "Dark theme" : "Light theme"}
      </Button>
    </SidebarFooter>
  </Sidebar>;
}
