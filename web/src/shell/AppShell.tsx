import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { Theme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral/built";
import { ArrowLeft, Eye, Info, LogOut, Menu, Moon, RefreshCw, Search, ShieldAlert, Sun, UserRound } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarMenuSub, SidebarMenuSubButton, SidebarMenuSubItem, SidebarProvider, useSidebar } from "@/components/ui/sidebar";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useResource, validPlatform, validServer, validServices } from "@/lib/api";
import type { Resource, ServerReport } from "@/lib/api";
import type { BackupCopySelection, ZIPImportRequest } from "@/lib/backupCopy";
import type { RestoreHandoff } from "@/lib/restoreHandoff";
import { currentSession, endViewAs as endViewAsRequest, onThisServer, restricted, setupStatus, signOut, viewAsCustomer } from "@/lib/auth-api";
import type { AuthSession } from "@/lib/auth-api";
import { AuthGate } from "@/shell/AuthGate";
import { CommandPalette } from "@/shell/CommandPalette";
import type { CommandGroup } from "@/shell/CommandPalette";
import { ShellContext } from "@/shell/context";
import type { ScreenTarget, Shell, SiteHandoff } from "@/shell/context";
import { customerPage, pageById, pages, visiblePages } from "@/shell/pages";
import type { MenuRole, Page, PageId } from "@/shell/pages";
import { LoadingState } from "@/shell/views";

const Websites = lazy(() => import("@/Websites"));
const Accounts = lazy(() => import("@/Accounts"));
const Backups = lazy(() => import("@/Backups"));
const FileManager = lazy(() => import("@/FileManager"));

// These screens hold work in progress (uploads, unsaved edits), so once opened
// they stay mounted and are hidden instead of unmounted on navigation.
// "static-sites" is the old Websites screen for static-file sites, and
// "static-files" its file screen; Files in the menu is each website's
// own home folder now (SiteFiles).
const keptAlive = ["static-sites", "static-files", "backups", "hosting-accounts"] as const;
type KeptAlive = (typeof keptAlive)[number];

const screenPages: Record<ScreenTarget, PageId> = { websites: "websites", accounts: "hosting-accounts", backups: "backups", files: "files", access: "security" };

export function isPublicPreview(): boolean {
  return Boolean(document.querySelector('meta[name="sifruno-public-preview"]'));
}

// Ctrl+K and Cmd+K both open search; show the one this keyboard has.
const shortcutLabel = /Mac|iPhone|iPad/.test(navigator.userAgent) ? "⌘K" : "Ctrl K";

function pageForPath(pathname: string): Page | undefined {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  return pages.find((p) => p.path === path || p.pattern?.test(path));
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
  // Who is signed in. Private pages wait for this; monitoring pages do not.
  const [auth, setAuth] = useState<{ checked: boolean; session: AuthSession | null; adminRequired: boolean; error: string }>({ checked: false, session: null, adminRequired: false, error: "" });
  // Bumped on sign-out so the kept-alive screens drop what they had loaded.
  const [authEpoch, setAuthEpoch] = useState(0);
  const handoffSequence = useRef(0);
  // Over the network every reading needs a session, so nothing is fetched
  // until an admin is signed in there. A customer's session never reads the
  // server, on the server itself either.
  const remote = !publicPreview && !onThisServer();
  const limited = restricted(auth.session);
  // Someone opening a setup link is about to be a customer: it sees that menu.
  const menuRole: MenuRole = limited || (!auth.session && page?.id === "setup") ? "customer" : "admin";
  const readingsAllowed = !limited && (!remote || Boolean(auth.session && !auth.adminRequired));
  const platform = useResource(readingsAllowed ? "/api/v1/platform" : null, validPlatform, revision);
  const server = useResource(readingsAllowed ? `/api/v1/server?range_seconds=${range}` : null, validServer, revision, 5000);
  const services = useResource(readingsAllowed ? "/api/v1/services" : null, validServices, revision, 30000);
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
    navigate({ to: pageById(destination === "files" ? "static-files" : destination).path });
  }, [navigate]);
  const openZIPImport = useCallback((snapshot?: BackupCopySelection) => {
    setImportRequest({ requestId: ++handoffSequence.current, snapshot });
    navigate({ to: "/websites/static" });
  }, [navigate]);

  const refreshAuth = useCallback(async () => {
    try {
      const [status, session] = await Promise.all([setupStatus(), currentSession()]);
      setAuth({ checked: true, session, adminRequired: status.admin_required, error: "" });
    } catch (error) {
      setAuth((current) => ({ ...current, checked: true, error: error instanceof Error ? error.message : "The panel could not check your sign-in." }));
    }
  }, []);
  const signedIn = Boolean(auth.session && !auth.adminRequired);
  useEffect(() => { if (!publicPreview) void refreshAuth(); }, [publicPreview, refreshAuth]);
  // Sessions end after 15 minutes; notice it on return to the tab or within a minute.
  useEffect(() => {
    if (publicPreview || !auth.session) return;
    const onFocus = () => { void refreshAuth(); };
    window.addEventListener("focus", onFocus);
    const timer = window.setInterval(onFocus, 60000);
    return () => { window.removeEventListener("focus", onFocus); window.clearInterval(timer); };
  }, [publicPreview, auth.session, refreshAuth]);
  const onSession = useCallback((session: AuthSession, adminCreated: boolean) => {
    setAuth((current) => ({ checked: true, session, adminRequired: adminCreated ? false : current.adminRequired, error: "" }));
    // Screens that were open before the session ended pick up the new one.
    refresh();
  }, [refresh]);
  const endSession = useCallback(async () => {
    const csrf = auth.session?.csrf_token;
    try { if (csrf) await signOut(csrf); } catch { /* Already ended on the server; clear it here either way. */ }
    setAuth((current) => ({ ...current, session: null }));
    setVisited(new Set());
    setAuthEpoch((value) => value + 1);
  }, [auth.session]);
  // Viewing as a customer changes what the session may see, so the screens
  // kept open drop what they loaded, as at a sign-out.
  const switchView = useCallback((session: AuthSession, to: string) => {
    setAuth((current) => ({ ...current, session }));
    setVisited(new Set());
    setAuthEpoch((value) => value + 1);
    refresh();
    navigate({ to });
  }, [navigate, refresh]);
  const viewAs = useCallback(async (username: string) => {
    if (!auth.session) return;
    switchView(await viewAsCustomer(auth.session.csrf_token, username), "/websites");
  }, [auth.session, switchView]);
  const endViewAs = useCallback(async () => {
    if (!auth.session) return;
    switchView(await endViewAsRequest(auth.session.csrf_token), "/customers");
  }, [auth.session, switchView]);

  const pageId = page?.id;
  // A customer's setup link opens before anyone is signed in.
  const gated = !publicPreview && pageId !== "setup" && (page?.audience === "private" || remote) && !signedIn;
  // A page a customer has no use for; the server refuses its data anyway.
  const adminPage = Boolean(signedIn && limited && page && !customerPage(page));
  useEffect(() => {
    if (!pageId) return;
    if (signedIn && (keptAlive as readonly string[]).includes(pageId)) setVisited((current) => current.has(pageId) ? current : new Set(current).add(pageId));
    // A ZIP import or restore request belongs to the visit that asked for it.
    if (pageId !== "static-sites") setImportRequest(undefined);
    if (pageId !== "backups") setBackupsHandoff((current) => current?.restore ? undefined : current);
  }, [pageId, signedIn]);
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
  const signOutNow = useCallback(() => { void endSession(); }, [endSession]);
  const shell: Shell = { publicPreview, revision, refresh, server, services, platform, range, setRange, serviceQuery, setServiceQuery, setPageResource, open,
    viewer: { session: signedIn ? auth.session : null, restricted: limited }, viewAs, endViewAs, signOut: signOutNow, setSession: (session: AuthSession) => onSession(session, false) };

  const commandGroups = useMemo<CommandGroup[]>(() => {
    const pageCommands = visiblePages(publicPreview, menuRole).map((p) => {
      const parent = p.parent ? pageById(p.parent) : undefined;
      const label = parent ? `${parent.label} › ${p.label === "Server" ? "Services" : p.label}` : p.label;
      return { id: `page-${p.id}`, label, hint: "Page", search: label, run: () => navigate({ to: p.path }) };
    });
    const actions = [
      { id: "theme", label: theme === "light" ? "Switch to dark theme" : "Switch to light theme", hint: "Action", search: "theme dark light appearance", run: toggleTheme },
      { id: "refresh", label: "Refresh data", hint: "Action", search: "refresh reload update data", run: refresh },
    ];
    const serviceCommands = (limited ? [] : services.data?.items ?? []).map((s) => ({
      id: `service-${s.id}`, label: s.display_name || s.name, hint: "Service", search: `${s.name} ${s.display_name} service`,
      run: () => { setServiceQuery(s.name); navigate({ to: "/server" }); },
    }));
    return [{ value: "Pages", items: pageCommands }, { value: "Actions", items: actions }, ...(serviceCommands.length ? [{ value: "Services", items: serviceCommands }] : [])];
  }, [publicPreview, menuRole, limited, theme, services.data, navigate, toggleTheme, refresh]);

  const status = serverState(server);
  const heading = page ? page.title : "Page not found";
  const subtitle = page ? page.subtitle : "";
  const parent = page?.parent && page.parent !== "server" ? pageById(page.parent) : undefined;

  return <ShellContext.Provider value={shell}>
    <TooltipProvider>
      <SidebarProvider>
        <a href="#panel-main" className="skip-link">Skip to panel content</a>
        <PanelSidebar page={page} publicPreview={publicPreview} role={menuRole} status={status} theme={theme} onToggleTheme={toggleTheme} session={signedIn ? auth.session : null} onSignOut={() => void endSession()} />
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
          {signedIn && auth.session?.view_as && <ViewAsBanner customer={auth.session.view_as} admin={auth.session.username} onBack={endViewAs} />}
          <main id="panel-main" tabIndex={-1} className="mx-auto w-full max-w-[1600px] min-w-0 flex-1 px-4 py-5 outline-none md:px-7 md:py-6">
            {heading && <div className="mb-5"><h1>{heading}</h1>{subtitle && <p className="mt-1.5 text-sm">{subtitle}</p>}</div>}
            {publicPreview && page && page.id !== "home" && <div className="mb-4 flex items-center gap-2 text-xs text-muted-foreground" role="status"><Info className="size-4" aria-hidden="true" /><span>{page.id === "tour" ? "Public panel tour with sample content. Changes stay in the local panel." : "Public preview of real server monitoring. Websites, files and backups stay in the local panel."}</span></div>}
            <Theme theme={neutralTheme} mode={theme}>
              <Suspense fallback={<LoadingState label="Loading page" />}>
                {gated && (auth.checked
                  ? <>{auth.error && <p className="mb-4 text-sm text-destructive" role="alert">{auth.error}</p>}<AuthGate adminRequired={auth.adminRequired} keySession={auth.session} onSession={onSession} /></>
                  : <LoadingState label="Checking your sign-in" />)}
                {!gated && adminPage && <AdminPageNotice />}
                {!gated && !adminPage && <Outlet />}
                <div hidden={gated || adminPage} key={authEpoch}>
                {!publicPreview && visited.has("static-sites") && <div hidden={pageId !== "static-sites"}><Websites revision={revision} active={pageId === "static-sites"} onStatus={reporters["static-sites"]} onOpenSiteTool={openSiteTool} importRequest={importRequest} onImportRequestConsumed={consumeImportRequest} /></div>}
                {!publicPreview && visited.has("hosting-accounts") && <div hidden={pageId !== "hosting-accounts"}><Accounts revision={revision} active={pageId === "hosting-accounts"} onStatus={reporters["hosting-accounts"]} /></div>}
                {!publicPreview && visited.has("backups") && <div hidden={pageId !== "backups"}><Backups revision={revision} active={pageId === "backups"} onStatus={reporters.backups} siteHandoff={backupsHandoff} onHandoffConsumed={consumeBackupsHandoff} onImportZIP={openZIPImport} /></div>}
                {!publicPreview && visited.has("static-files") && <div hidden={pageId !== "static-files"}><FileManager revision={revision} active={pageId === "static-files"} onStatus={reporters["static-files"]} siteHandoff={filesHandoff} onHandoffConsumed={consumeFilesHandoff} /></div>}
                </div>
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

// While an admin views the panel as a customer: whose account this is, that
// changes are recorded as the admin's, and the way back. It sits above the
// page so it shows on every screen.
function ViewAsBanner({ customer, admin, onBack }: { customer: string; admin?: string; onBack: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const back = async () => {
    setBusy(true); setError("");
    try { await onBack(); }
    catch (e) { setError(e instanceof Error ? e.message : "The panel could not go back to your admin view."); }
    finally { setBusy(false); }
  };
  return <section aria-label="Viewing as a customer" className="sticky top-14 z-10 border-b border-primary/40 bg-primary/10 px-4 py-2.5 md:px-7" data-testid="view-as-banner">
    <div className="mx-auto flex w-full max-w-[1600px] flex-wrap items-center gap-x-4 gap-y-2">
      <Eye className="size-4 shrink-0 text-primary" aria-hidden="true" />
      <div className="min-w-[16rem] flex-1 text-sm text-foreground">
        You are viewing the panel as <strong className="font-semibold wrap-anywhere">{customer}</strong>. You see and can change only this customer's websites. Changes are recorded as yours{admin ? <> ({admin})</> : null}.
      </div>
      <Button size="sm" variant="outline" className="h-9 bg-card pointer-coarse:h-11" onClick={() => void back()} disabled={busy} data-testid="end-view-as"><ArrowLeft aria-hidden="true" className="rtl:rotate-180" />{busy ? "Going back…" : "Back to admin view"}</Button>
      {error && <div className="basis-full text-sm text-destructive" role="alert">{error} Reload the page and try again.</div>}
    </div>
  </section>;
}

function AdminPageNotice() {
  return <Alert data-testid="admin-page-notice">
    <ShieldAlert aria-hidden="true" />
    <AlertTitle>This page is for the server's admin</AlertTitle>
    <AlertDescription><span>Your login manages your own websites, so this page has nothing for it.</span><Link to="/websites" className="mt-2 inline-block text-primary underline">Go to your websites</Link></AlertDescription>
  </Alert>;
}

function MobileMenuButton() {
  const { openMobile, toggleSidebar } = useSidebar();
  return <Button variant="ghost" size="icon" className="size-9 md:hidden" onClick={toggleSidebar} aria-label={openMobile ? "Close navigation" : "Open navigation"} aria-expanded={openMobile}>
    <Menu aria-hidden="true" />
  </Button>;
}

function PanelSidebar({ page, publicPreview, role, status, theme, onToggleTheme, session, onSignOut }: { page?: Page; publicPreview: boolean; role: MenuRole; status: ReturnType<typeof serverState>; theme: "light" | "dark"; onToggleTheme: () => void; session: AuthSession | null; onSignOut: () => void }) {
  const { setOpenMobile } = useSidebar();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  useEffect(() => { setOpenMobile(false); }, [pathname, setOpenMobile]);
  // Tapping the page you are already on changes no URL, so close it here too.
  const closeMobile = () => setOpenMobile(false);
  const shown = visiblePages(publicPreview, role);
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
      {top("admin").length > 0 && <SidebarGroup>
        <SidebarGroupLabel className="text-sidebar-muted-foreground">Administration</SidebarGroupLabel>
        <SidebarGroupContent><SidebarMenu className="gap-0.5">{top("admin").map(item)}</SidebarMenu></SidebarGroupContent>
      </SidebarGroup>}
      </nav>
    </SidebarContent>
    <SidebarFooter className="border-t border-sidebar-border px-3 py-3">
      {session && <div className="flex items-center gap-2 border-b border-sidebar-border px-1 pb-2.5 text-xs" data-testid="signed-in-as">
        <UserRound className="size-4 shrink-0 text-sidebar-muted-foreground" aria-hidden="true" />
        <span className="min-w-0 flex-1 truncate">{session.view_as ? <>Viewing as <strong className="font-medium">{session.view_as}</strong></> : session.username ? <>Signed in as <strong className="font-medium">{session.username}</strong></> : "Signed in with the access key"}</span>
        <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs text-sidebar-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground" onClick={onSignOut}><LogOut aria-hidden="true" />Sign out</Button>
      </div>}
      {role === "admin" && <div className="flex items-center gap-2.5 px-1 text-xs" role="status">
        <span className={`size-2 shrink-0 rounded-full ${status.live ? "bg-sidebar-primary" : "bg-sidebar-muted-foreground"}`} aria-hidden="true" />
        <div><div>{status.label}</div><div className="text-sidebar-muted-foreground">{status.detail}</div></div>
      </div>}
      <Button variant="ghost" className="justify-start gap-2 px-2 text-xs text-sidebar-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground" onClick={onToggleTheme} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} theme`}>
        {theme === "light" ? <Moon aria-hidden="true" /> : <Sun aria-hidden="true" />}{theme === "light" ? "Dark theme" : "Light theme"}
      </Button>
    </SidebarFooter>
  </Sidebar>;
}
