import { createContext, Suspense, useCallback, useContext, useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { ArrowLeft, CircleAlert, CircleCheck, CircleQuestionMark, CircleX, LoaderCircle, TriangleAlert } from "lucide-react";
import { DnsHelp } from "@/components/dns-help";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { dateLabel } from "@/lib/api";
import { formatWhen, getSiteBackups } from "@/lib/site-backups-api";
import type { SiteBackups } from "@/lib/site-backups-api";
import { healthChecklist, readViewMode, recentActivity, saveViewMode, siteTab, tabFromPath, tabRoute, tabsFor, viewShows } from "@/lib/site-page";
import type { HealthLine, HealthState, Reading, SiteTab, SiteTabId, ViewMode } from "@/lib/site-page";
import { deletedSummary, getWebsite, limitsSummary } from "@/lib/websites-api";
import type { WebsiteDeleted, WebsiteDetail, WebsiteUsage } from "@/lib/websites-api";
import { useShell } from "@/shell/context";
import { LoadingState } from "@/shell/views";
import type { PageId } from "@/shell/pages";
import { SiteCronSection, SiteLogsSection, SiteUsageSection } from "./SiteTools";
import { control, HttpsBadge, linkButton, panel, ProblemAlert, SiteActions, SiteLink, StatusBadge, useRead } from "./WebsitesPage";
import "./website-tabs.css";

// One website's page: a header with the site's name, state and quick
// actions, and a tab bar whose tabs are addresses of their own, so back,
// reload and shared links keep the tab. The tabs are links in a nav with
// aria-current, not an ARIA tablist: each one is a page. Domains, Files,
// Databases and Backups are their own screens inside the tab; Overview,
// Settings, Cron jobs and Logs are here and use the site this layout read.

interface Website {
  site: WebsiteDetail;
  mode: ViewMode;
  // True once the person has moved between tabs: a tab then moves focus to
  // its first heading, as the other tabs' screens do. On arrival the site's
  // name has focus instead.
  navigated: boolean;
  replace: (site: WebsiteDetail) => void;
  reload: () => void;
  announce: (text: string) => void;
  onDeleted: (done: WebsiteDeleted) => void;
}

const WebsiteContext = createContext<Website | null>(null);

function useWebsite(): Website {
  const website = useContext(WebsiteContext);
  if (!website) throw new Error("useWebsite must be used inside a website's page");
  return website;
}

// The shell's page for each tab. The tabs this layout reads for report the
// site's read to the shell (its refresh button and footer); the other tabs'
// screens report their own, unless the tab is gone (see Gone).
const tabPages: Record<SiteTabId, PageId> = { overview: "website", domains: "site-domains", files: "site-files", databases: "site-databases", backups: "site-backups", cron: "site-cron", logs: "site-logs", settings: "site-settings" };
const ownTabs: readonly SiteTabId[] = ["overview", "settings", "cron", "logs"];

const browserStorage = () => window.localStorage;

// Whether the viewer may change the site's PHP, folder or state, or delete
// it: the Settings tab's own actions. A customer's login may not.
const siteActionsFor = (can: (route: string) => boolean) => can("POST /api/v1/websites/sites/{account_id}/php") || can("POST /api/v1/websites/sites/{account_id}/folder")
  || can("POST /api/v1/websites/sites/{account_id}/state") || can("POST /api/v1/websites/sites/{account_id}/delete");

export function WebsiteLayout({ accountId }: { accountId: string }) {
  const { viewer } = useShell();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const tab = tabFromPath(pathname) ?? "overview";
  const { data: site, problem, loading, retry, replace } = useRead<WebsiteDetail>(ownTabs.includes(tab) ? tabPages[tab] : undefined, (signal) => getWebsite(accountId, { signal }), "This website could not be loaded.");
  const [mode, setMode] = useState<ViewMode>(() => readViewMode(browserStorage));
  const [unsaved, setUnsaved] = useState(false);
  const [dnsOpen, setDnsOpen] = useState(false);
  const [deleted, setDeleted] = useState<WebsiteDeleted>();
  // One polite live region for the page: the outcome of each action.
  const [announcement, setAnnouncement] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);
  const deletedRef = useRef<HTMLHeadingElement>(null);
  const firstTab = useRef(tab);
  const movedOn = useRef(false);
  const navigated = movedOn.current || tab !== firstTab.current;
  useEffect(() => { if (tab !== firstTab.current) movedOn.current = true; }, [tab]);

  const domain = site?.domain;
  // Arriving from the list: start at the site's name.
  useEffect(() => { if (domain) headingRef.current?.focus(); }, [domain]);
  // Name the browser tab after the site and the tab. The shell names it
  // after the page in its own effect, which runs after this one, so this
  // waits for the effects to finish.
  useEffect(() => {
    if (!domain || deleted) return;
    const title = `${siteTab(tab).label} · ${domain} · Sifruno`;
    queueMicrotask(() => { document.title = title; });
  }, [tab, domain, deleted]);
  // After a delete the dialog is gone and the page is reachable again: say
  // what happened, and put focus on it instead of leaving it nowhere.
  useEffect(() => {
    if (!deleted) return;
    deletedRef.current?.focus();
    document.title = `${deleted.domain} deleted · Websites · Sifruno`;
    // Focus reads the heading; the region adds what went.
    setAnnouncement(deletedSummary(deleted) || `${deleted.domain} was deleted.`);
  }, [deleted]);

  const changeMode = (next: ViewMode) => {
    setMode(next);
    setUnsaved(!saveViewMode(next, browserStorage));
    setAnnouncement(next === "advanced" ? "Advanced view. Cron jobs and Logs are tabs of their own." : "Simple view. Cron jobs and logs are in Settings.");
  };
  const onDeleted = useCallback((done: WebsiteDeleted) => setDeleted(done), []);

  const back = <Link to="/websites" className={linkButton("ghost", "w-fit px-2")} data-testid="back-to-websites"><ArrowLeft className="rtl:rotate-180" aria-hidden="true" />All websites</Link>;
  // Keyed, so the same region stays in the page from one view to the next.
  const announcer = <div key="announcer" aria-live="polite" className="sr-only" data-testid="website-announcer">{announcement}</div>;

  if (deleted) return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="website-deleted">
    {back}
    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`}>
      <div className="flex flex-col gap-2">
        <h1 ref={deletedRef} tabIndex={-1} className="wrap-anywhere outline-none">{deleted.domain} was deleted</h1>
        <div className="text-sm text-foreground" data-testid="website-deleted-summary">{deletedSummary(deleted)}</div>
      </div>
      <Link to="/websites" className={linkButton("default", "w-fit")}>Back to all websites</Link>
    </section>
    {announcer}
  </div>;

  if (!site) return <div className="flex w-full max-w-3xl flex-col gap-4">
    {back}
    {problem
      ? <><h1 className="sr-only">Website</h1><ProblemAlert problem={problem} onRetry={problem.status === 404 ? undefined : retry} /></>
      : loading && <div className={`${panel} flex flex-col gap-4 p-5`} aria-busy="true"><h1 className="sr-only">Loading the website</h1><Skeleton className="h-8 w-1/2" /><Skeleton className="h-40 w-full" /></div>}
    {announcer}
  </div>;

  const partly = site.state === "partly_deleted";
  const tabs = tabsFor(mode, site.state, tab, siteActionsFor(viewer.can));
  const shown = tabs.some((t) => t.id === tab);
  const website: Website = { site, mode, navigated, replace, reload: retry, announce: setAnnouncement, onDeleted };

  return <WebsiteContext.Provider value={website}>
    <div className="flex w-full max-w-5xl min-w-0 flex-col gap-4" data-testid="website-page" data-account-id={site.account_id} data-tab={tab} data-view={mode}>
      {back}
      {problem && <ProblemAlert problem={{ ...problem, next: `${problem.next} The details below are from the last successful read.` }} onRetry={retry} />}
      <header className="flex flex-col gap-3">
        <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
          <div className="flex min-w-0 flex-col gap-2">
            <h1 ref={headingRef} tabIndex={-1} className="wrap-anywhere outline-none" data-testid="website-domain">{site.domain}</h1>
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge state={site.state} />
              {!partly && <HttpsBadge site={site} />}
              {!partly && site.php_version && <Badge variant="outline" data-testid="site-header-php">PHP {site.php_version}</Badge>}
            </div>
          </div>
          <ViewSwitch mode={mode} onChange={changeMode} unsaved={unsaved} />
        </div>
        {/* A partly deleted site no longer serves, so it has nothing to open. */}
        {!partly && <>
          <div className="flex flex-wrap gap-2">
            <SiteLink href={site.url} label="Open site" domain={site.domain} variant="default" testId="open-site" />
            {site.kind === "wordpress" && <SiteLink href={site.admin_url} label="WordPress admin" domain={site.domain} variant="outline" testId="open-admin" />}
            <Button variant="outline" className={control} aria-expanded={dnsOpen} aria-controls="dns-help" onClick={() => setDnsOpen((value) => !value)} data-testid="set-up-dns">Set up DNS</Button>
          </div>
          <DnsHelp id="dns-help" domain={site.domain} hidden={!dnsOpen} />
        </>}
      </header>
      <SiteTabsNav accountId={site.account_id} tabs={tabs} current={shown ? tab : undefined} />
      <Suspense fallback={<LoadingState label="Loading this tab" />}>
        {shown ? <Outlet /> : <Gone tab={tab} />}
      </Suspense>
      {announcer}
    </div>
  </WebsiteContext.Provider>;
}

// Simple or Advanced, kept in this browser. Native radio buttons: arrow
// keys move between the two, and the group is named by its visible label.
function ViewSwitch({ mode, onChange, unsaved }: { mode: ViewMode; onChange: (mode: ViewMode) => void; unsaved: boolean }) {
  const id = useId();
  const views: { value: ViewMode; label: string }[] = [{ value: "simple", label: "Simple" }, { value: "advanced", label: "Advanced" }];
  return <div className="flex flex-col items-start gap-1">
    <div role="radiogroup" aria-labelledby={`${id}-label`} aria-describedby={unsaved ? `${id}-unsaved` : undefined} className="flex items-center gap-2" data-testid="site-view-switch">
      <span id={`${id}-label`} className="text-xs text-muted-foreground">View</span>
      <div className="inline-flex rounded-md border border-input bg-background p-0.5">
        {views.map((view) => <label key={view.value} className="inline-flex h-8 cursor-pointer items-center rounded-[5px] px-3 text-sm text-muted-foreground select-none hover:text-foreground has-[:checked]:bg-primary has-[:checked]:text-primary-foreground has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-primary pointer-coarse:h-10">
          <input type="radio" className="sr-only" name={`${id}-view`} value={view.value} checked={mode === view.value} onChange={() => onChange(view.value)} data-testid={`site-view-${view.value}`} />
          {view.label}
        </label>)}
      </div>
    </div>
    {unsaved && <div id={`${id}-unsaved`} className="text-xs text-muted-foreground">This browser did not keep the choice; the next visit opens in Simple view.</div>}
  </div>;
}

// The tab bar: one row that scrolls sideways when the tabs do not fit, with
// the current tab scrolled into view. The current tab is underlined as well
// as coloured, and nothing about it changes its size.
function SiteTabsNav({ accountId, tabs, current }: { accountId: string; tabs: SiteTab[]; current?: SiteTabId }) {
  const listRef = useRef<HTMLUListElement>(null);
  useEffect(() => {
    const link = listRef.current?.querySelector<HTMLElement>('[aria-current="page"]');
    // container: "nearest" scrolls the tab bar only, not the page.
    link?.scrollIntoView({ block: "nearest", inline: "nearest", container: "nearest" } as ScrollIntoViewOptions);
  }, [current, tabs.length]);
  return <nav aria-label="Website sections" className="min-w-0 border-b border-border" data-testid="site-tabs">
    <ul ref={listRef} className="site-tabs m-0 flex list-none gap-1 p-0">
      {tabs.map((t) => <li key={t.id} className="flex-none">
        <Link to={tabRoute(t.id)} params={{ accountId }} activeOptions={{ exact: true, includeSearch: false }} aria-current={t.id === current ? "page" : undefined} data-testid={`site-tab-${t.id}`}
          className="relative inline-flex h-10 items-center px-3 text-sm whitespace-nowrap text-muted-foreground! after:pointer-events-none after:absolute after:start-0 after:end-0 after:bottom-0 after:border-b-2 after:border-transparent hover:text-foreground! focus-visible:outline-offset-[-4px]! aria-[current=page]:text-foreground! aria-[current=page]:after:border-primary pointer-coarse:h-11">
          {t.label}
        </Link>
      </li>)}
    </ul>
  </nav>;
}

// A tab's address for a site that no longer has that part: only a partly
// deleted site gets here, where the hosting account is gone. The tab's own
// screen does not run, so this reports the site's read for the footer.
function Gone({ tab }: { tab: SiteTabId }) {
  const { site } = useWebsite();
  const { setPageResource, viewer } = useShell();
  const canDelete = viewer.can("POST /api/v1/websites/sites/{account_id}/delete");
  useEffect(() => { setPageResource(tabPages[tab], { data: site, loading: false, loadedAt: new Date() }); }, [tab, site, setPageResource]);
  return <Alert className="text-start" data-testid="site-tab-gone">
    <CircleAlert aria-hidden="true" />
    <AlertTitle>This part of the website is gone</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start">
      <div className="text-foreground">The hosting account was deleted, so its files, domains, scheduled jobs and logs are gone too. The site's database is still on this server.</div>
      {canDelete
        ? <Link to={tabRoute("settings")} params={{ accountId: site.account_id }} className={linkButton("outline", "w-fit")}>Open Settings to delete the rest</Link>
        : <div className="text-foreground">Whoever runs this server can delete the rest.</div>}
    </AlertDescription>
  </Alert>;
}

// A tab's content. After a move between tabs it puts focus on its first
// heading, as the other tabs' screens do once they have read their data.
function TabBody({ testId, children }: { testId: string; children: ReactNode }) {
  const { navigated } = useWebsite();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { if (navigated) ref.current?.querySelector<HTMLElement>("h2[tabindex]")?.focus(); }, [navigated]);
  return <div ref={ref} className="flex w-full max-w-3xl flex-col gap-4" data-testid={testId}>{children}</div>;
}

// ---- Overview -----------------------------------------------------------------

export function WebsiteOverviewTab() {
  const { site } = useWebsite();
  const [usage, setUsage] = useState<Reading<WebsiteUsage>>({ failed: false });
  const onUsage = useCallback((data: WebsiteUsage | undefined, failed: boolean) => setUsage({ data, failed }), []);
  // A partly deleted site has no hosting account to read usage or backups for.
  if (site.state === "partly_deleted") return <TabBody testId="website-overview">
    <HealthSection lines={healthChecklist(site, usage, { failed: false })} />
    <ActivitySection backups={undefined} reading={false} />
    <DetailsSection />
  </TabBody>;
  return <TabBody testId="website-overview">
    <LiveOverview usage={usage} onUsage={onUsage} />
  </TabBody>;
}

function LiveOverview({ usage, onUsage }: { usage: Reading<WebsiteUsage>; onUsage: (data: WebsiteUsage | undefined, failed: boolean) => void }) {
  const { site } = useWebsite();
  const backups = useRead<SiteBackups>(undefined, (signal) => getSiteBackups(site.account_id, { signal }), "The backups could not be loaded.");
  const backupReading = { data: backups.data, failed: Boolean(backups.problem) && !backups.data };
  return <>
    <HealthSection lines={healthChecklist(site, usage, backupReading)} />
    <SiteUsageSection site={site} onRead={onUsage} />
    <ActivitySection backups={backups.data} reading={backups.loading && !backups.data} />
    <DetailsSection />
  </>;
}

const stateWords: Record<HealthState, string> = { ok: "Passed", attention: "Needs attention", problem: "Problem", checking: "Checking", unknown: "Not known" };
const stateIcons: Record<HealthState, { icon: typeof CircleCheck; className: string }> = {
  ok: { icon: CircleCheck, className: "text-primary" },
  attention: { icon: TriangleAlert, className: "text-foreground" },
  problem: { icon: CircleX, className: "text-destructive" },
  checking: { icon: LoaderCircle, className: "text-muted-foreground motion-safe:animate-spin" },
  unknown: { icon: CircleQuestionMark, className: "text-muted-foreground" },
};

// Each line says its state in words as well as by its icon, and a line that
// is not ok links to the tab where it can be dealt with.
function HealthSection({ lines }: { lines: HealthLine[] }) {
  const { site } = useWebsite();
  const ids = useId();
  const open = lines.filter((l) => l.state === "attention" || l.state === "problem").length;
  return <section className={`${panel} flex flex-col gap-3 p-5 md:p-6`} aria-labelledby={`${ids}-heading`} data-testid="site-health">
    <div className="flex flex-col gap-1">
      <h2 id={`${ids}-heading`} tabIndex={-1} className="outline-none">Health</h2>
      <div className="text-sm text-muted-foreground" data-testid="site-health-summary">
        {open === 0 ? "Checked from what the panel knows about this site." : `${open === 1 ? "1 thing needs" : `${open} things need`} a look. Checked from what the panel knows about this site.`}
      </div>
    </div>
    <ul className="m-0 flex list-none flex-col divide-y divide-border p-0">
      {lines.map((line) => {
        const { icon: Icon, className } = stateIcons[line.state];
        return <li key={line.id} className="flex items-start gap-3 py-3 first:pt-1 last:pb-0" data-testid="health-line" data-check={line.id} data-state={line.state}>
          <Icon className={`mt-0.5 size-4 shrink-0 ${className}`} aria-hidden="true" />
          <div className="flex min-w-0 flex-1 flex-wrap items-start justify-between gap-x-4 gap-y-2">
            <div className="flex min-w-0 grow basis-56 flex-col gap-0.5">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-medium text-foreground">
                {line.label}
                {line.state === "ok" || line.state === "checking"
                  ? <span className="sr-only">: {stateWords[line.state]}</span>
                  : <Badge variant={line.state === "problem" ? "destructive" : "outline"}><span className="sr-only">: </span>{stateWords[line.state]}</Badge>}
              </div>
              <div className="text-sm text-muted-foreground" data-testid="health-detail">{line.detail}</div>
            </div>
            {line.fix && <Link to={tabRoute(line.fix)} params={{ accountId: site.account_id }} className={linkButton("outline", "shrink-0")} data-testid="health-fix">
              Open {siteTab(line.fix).label}<span className="sr-only"> for {line.label}</span>
            </Link>}
          </div>
        </li>;
      })}
    </ul>
  </section>;
}

// What the API records for this site. It is not a full change log, and says so.
function ActivitySection({ backups, reading }: { backups?: SiteBackups; reading: boolean }) {
  const { site } = useWebsite();
  const ids = useId();
  const items = recentActivity(site, backups);
  return <section className={`${panel} flex flex-col gap-3 p-5 md:p-6`} aria-labelledby={`${ids}-heading`} data-testid="site-activity">
    <div className="flex flex-col gap-1">
      <h2 id={`${ids}-heading`}>Recent activity</h2>
      <div className="text-sm text-muted-foreground">The site's last backup, restore and restore drill, and when it was made.</div>
    </div>
    <ol className="m-0 flex list-none flex-col gap-3 p-0">
      {items.map((item) => <li key={item.id} className="flex items-start gap-3" data-testid="activity-item" data-kind={item.id} data-ok={String(item.ok)}>
        {item.ok ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" /> : <CircleX className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden="true" />}
        <div className="flex min-w-0 flex-col gap-0.5 text-sm">
          <span className="font-medium text-foreground">{item.title}</span>
          <span className="text-muted-foreground">{formatWhen(item.at, backups?.timezone ?? "")}{item.detail ? `. ${item.detail}` : ""}</span>
        </div>
      </li>)}
    </ol>
    {reading && <div className="text-sm text-muted-foreground" aria-busy="true" data-testid="activity-reading">Reading the backup history…</div>}
  </section>;
}

// The site's facts. Resource limits and the creation date are technical
// details, shown in Advanced view.
function DetailsSection() {
  const { site, mode } = useWebsite();
  const ids = useId();
  const technical = viewShows(mode).technical;
  return <section className={`${panel} flex flex-col gap-3 p-5 md:p-6`} aria-labelledby={`${ids}-heading`}>
    <h2 id={`${ids}-heading`}>Details</h2>
    <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 text-sm" data-testid="website-facts">
      <dt className="text-muted-foreground">Type</dt><dd className="text-foreground" data-testid="website-type">{site.kind === "php" ? "PHP site" : "WordPress"}</dd>
      {site.kind === "wordpress" && <><dt className="text-muted-foreground">WordPress version</dt><dd className="text-foreground" data-testid="website-wordpress">{site.wordpress_version}</dd></>}
      <dt className="text-muted-foreground">PHP version</dt><dd className="text-foreground" data-testid="website-php">{site.php_version || "Not reported for this site"}</dd>
      <dt className="text-muted-foreground">Other domains</dt>
      <dd className="wrap-anywhere text-foreground" data-testid="website-aliases">
        {site.aliases.length === 0 ? "None" : site.aliases.map((alias) => `${alias.name}${alias.https === "on" ? "" : " (http only for now)"}`).join(", ")}
      </dd>
      <dt className="text-muted-foreground">Redirects</dt>
      <dd className="text-foreground" data-testid="website-redirects">{site.redirect_count === 0 ? "None" : site.redirect_count === 1 ? "1 redirect" : `${site.redirect_count} redirects`}</dd>
      <dt className="text-muted-foreground">Hosting account</dt><dd className="text-foreground" data-testid="website-username"><code>{site.username}</code></dd>
      {site.kind === "php" && <><dt className="text-muted-foreground">Files</dt><dd className="text-foreground" data-testid="website-files">Upload with SFTP as <code>{site.username}</code>, into <code>public_html</code>. SFTP signs in with an SSH key.</dd></>}
      {technical && <>
        <dt className="text-muted-foreground">Resource limits</dt>
        <dd className="text-foreground" data-testid="website-limits">
          {site.limits
            ? `${limitsSummary(site.limits)}, shared by everything the site runs: its PHP, SFTP sessions and scheduled jobs. The hosting plan sets them.`
            : "Not reported for this site"}
        </dd>
        <dt className="text-muted-foreground">Created</dt><dd className="text-foreground" data-testid="website-created">{dateLabel(site.created_at)}</dd>
      </>}
    </dl>
  </section>;
}

// ---- Settings, Cron jobs and Logs ---------------------------------------------

export function WebsiteSettingsTab() {
  const { site, mode, replace, reload, announce, onDeleted } = useWebsite();
  const { viewer } = useShell();
  const shows = viewShows(mode);
  const partly = site.state === "partly_deleted";
  const onRevision = (revision: number) => replace({ ...site, revision });
  const between = partly ? undefined : <>
    {shows.cronInSettings && <SiteCronSection site={site} onRevision={onRevision} />}
    {shows.logsInSettings && <SiteLogsSection site={site} />}
  </>;
  // Reached by its address with nothing here for this login: say where things are.
  if (!siteActionsFor(viewer.can) && (partly || !shows.cronInSettings)) return <TabBody testId="site-settings">
    <div className="text-sm text-foreground" data-testid="site-settings-none">{partly
      ? "Whoever runs this server can delete what is left of this website."
      : "Cron jobs and Logs are tabs of their own in Advanced view. Changing PHP, suspending and deleting the website are for whoever runs this server."}</div>
  </TabBody>;
  return <TabBody testId="site-settings">
    <SiteActions site={site} repair={shows.repair} between={between} onChanged={replace} onDeleted={onDeleted} onReload={reload} announce={announce} />
  </TabBody>;
}

export function WebsiteCronTab() {
  const { site, replace } = useWebsite();
  return <TabBody testId="site-cron-tab"><SiteCronSection site={site} onRevision={(revision) => replace({ ...site, revision })} /></TabBody>;
}

export function WebsiteLogsTab() {
  const { site } = useWebsite();
  return <TabBody testId="site-logs-tab"><SiteLogsSection site={site} /></TabBody>;
}
