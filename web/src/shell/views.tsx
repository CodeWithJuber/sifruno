import { lazy, useCallback, useEffect } from "react";
import type { ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { Info, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { HostingWorkspace, Overview, ServiceInventory } from "@/Dashboard";
import { useResource, validBudget, validTrail } from "@/lib/api";
import type { Resource } from "@/lib/api";
import { useShell } from "@/shell/context";
import { pageById, serverTabs } from "@/shell/pages";
import type { PageId } from "@/shell/pages";

const Trail = lazy(() => import("@/Tools").then((m) => ({ default: m.Trail })));
const Budget = lazy(() => import("@/Tools").then((m) => ({ default: m.Budget })));
const Access = lazy(() => import("@/Access"));
const ApiTokens = lazy(() => import("@/ApiTokens").then((m) => ({ default: m.ApiTokens })));
const Storage = lazy(() => import("@/HostResources").then((m) => ({ default: m.Storage })));
const NetworkResources = lazy(() => import("@/HostResources").then((m) => ({ default: m.NetworkResources })));
const PanelPreview = lazy(() => import("@/PanelPreview"));
const NewWebsite = lazy(() => import("@/NewWebsite").then((m) => ({ default: m.NewWebsite })));
const WebsiteJob = lazy(() => import("@/NewWebsite").then((m) => ({ default: m.WebsiteJob })));
const WebsitesList = lazy(() => import("@/WebsitesPage").then((m) => ({ default: m.WebsitesList })));
const WebsiteLayout = lazy(() => import("@/WebsiteLayout").then((m) => ({ default: m.WebsiteLayout })));
const BackupStorage = lazy(() => import("@/BackupStorage").then((m) => ({ default: m.BackupStorage })));
const FilesSitePicker = lazy(() => import("@/SiteFiles").then((m) => ({ default: m.FilesSitePicker })));

export function LoadingState({ label }: { label: string }) {
  return <div className="flex flex-col gap-4" role="status" aria-label={label}><Skeleton className="h-28 w-full" /><Skeleton className="h-64 w-full" /><span className="sr-only">{label}</span></div>;
}

export function DataState({ resource, retry, children }: { resource: Resource<unknown>; retry: () => void; children: ReactNode }) {
  if (resource.loading && !resource.data) return <LoadingState label="Loading server data" />;
  if (resource.error && !resource.data) return <Alert variant="destructive">
    <AlertTitle>Server data is unavailable</AlertTitle>
    <AlertDescription><p>{resource.error}</p><p>Check that the Sifruno service is running, then try again.</p><Button variant="secondary" size="sm" className="mt-3" onClick={retry}><RefreshCw aria-hidden="true" />Try again</Button></AlertDescription>
  </Alert>;
  return <>
    {resource.error && <div className="mb-3 flex items-center gap-2 border border-input bg-card px-3 py-2 text-xs text-muted-foreground" role="alert">
      <Info className="size-4" aria-hidden="true" /><span>{resource.error} Showing the last successful reading.</span>
      <Button variant="ghost" size="sm" className="ms-auto" onClick={retry}>Try again</Button>
    </div>}
    {children}
  </>;
}

function useReport(id: PageId, resource: Resource<unknown>) {
  const { setPageResource } = useShell();
  useEffect(() => { setPageResource(id, resource); }, [id, resource, setPageResource]);
}

export function HomeView() {
  const shell = useShell();
  const navigate = useNavigate();
  return <div className="content-stack dashboard-stack">
    <HostingWorkspace publicPreview={shell.publicPreview} platform={shell.platform.data} onNavigate={shell.open} onPreview={() => navigate({ to: "/tour" })} />
    <section className="monitoring-workspace" aria-labelledby="monitoring-heading">
      <div className="workspace-section-heading"><div><h2 id="monitoring-heading">Server monitoring</h2><p>Measured resources and installed services.</p></div><span className="workspace-scope">Read-only</span></div>
      <DataState resource={shell.server} retry={shell.refresh}>{shell.server.data && <Overview report={shell.server.data} platform={shell.platform.data} range={shell.range} setRange={shell.setRange} />}</DataState>
      <DataState resource={shell.services} retry={shell.refresh}>{shell.services.data && <ServiceInventory report={shell.services.data} compact query={shell.serviceQuery} setQuery={shell.setServiceQuery} viewAll={() => navigate({ to: "/server" })} />}</DataState>
    </section>
  </div>;
}

export function ServerTabs({ active }: { active: PageId }) {
  const { publicPreview } = useShell();
  // The public demo has no backup storage; it shows only its own tabs.
  const tabs = serverTabs.filter((id) => !publicPreview || pageById(id).audience !== "private");
  return <nav aria-label="Server sections" className="mb-5 flex flex-wrap gap-1 border-b border-border">
    {tabs.map((id) => {
      const page = pageById(id);
      const current = id === active;
      return <Link key={id} to={page.path} activeOptions={{ exact: true }} data-testid={id === "server" ? "tab-services" : page.testId} aria-current={current ? "page" : undefined}
        className={`-mb-px border-b-2 px-3 py-2 text-sm ${current ? "border-primary font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}>
        {id === "server" ? "Services" : page.label}
      </Link>;
    })}
  </nav>;
}

export function ServicesView() {
  const shell = useShell();
  return <><ServerTabs active="server" /><DataState resource={shell.services} retry={shell.refresh}>{shell.services.data && <ServiceInventory report={shell.services.data} query={shell.serviceQuery} setQuery={shell.setServiceQuery} />}</DataState></>;
}

export function StorageView() {
  const shell = useShell();
  return <><ServerTabs active="storage" /><DataState resource={shell.server} retry={shell.refresh}>{shell.server.data && <Storage report={shell.server.data} />}</DataState></>;
}

export function NetworkView() {
  const shell = useShell();
  return <><ServerTabs active="network" /><DataState resource={shell.server} retry={shell.refresh}>{shell.server.data && <NetworkResources report={shell.server.data} range={shell.range} setRange={shell.setRange} />}</DataState></>;
}

export function BackupStorageView() {
  return <><ServerTabs active="backup-storage" /><BackupStorage /></>;
}

export function ActivityView() {
  const shell = useShell();
  const trail = useResource("/api/v1/trail", validTrail, shell.revision);
  useReport("activity", trail);
  return <DataState resource={trail} retry={shell.refresh}>{trail.data && <Trail report={trail.data} />}</DataState>;
}

export function SettingsView() {
  const shell = useShell();
  const budget = useResource("/api/v1/budget", validBudget, shell.revision);
  useReport("settings", budget);
  return <section aria-labelledby="ai-spending-heading" className="flex flex-col gap-3">
    <div><h2 id="ai-spending-heading">AI spending</h2><p className="mt-1 text-sm">Paid AI work stops when this month's limit is reached.</p></div>
    <DataState resource={budget} retry={shell.refresh}>{budget.data && <Budget report={budget.data} />}</DataState>
  </section>;
}

export function SecurityView() {
  const { revision, setPageResource } = useShell();
  const onStatus = useCallback((value: Resource<unknown>) => setPageResource("security", value), [setPageResource]);
  return <Access revision={revision} onStatus={onStatus} />;
}

export function ApiTokensView() {
  return <ApiTokens />;
}

export function TourView() {
  return <PanelPreview />;
}

export function NewWebsiteView() {
  return <NewWebsite />;
}

// Keyed by the id, so moving from one setup job to another starts fresh.
export function WebsiteJobView({ jobId }: { jobId: string }) {
  return <WebsiteJob key={jobId} jobId={jobId} />;
}

export function WebsitesView() {
  return <WebsitesList />;
}

// One website's page with its tabs. Keyed by the id, so moving from one
// website to another starts fresh.
export function WebsiteView({ accountId }: { accountId: string }) {
  return <WebsiteLayout key={accountId} accountId={accountId} />;
}

// Websites → Files: choose a website, then its Files page opens.
export function FilesView() {
  return <FilesSitePicker />;
}

// Kept-alive screens (Static sites and their files, Backups, Customers) are rendered by the
// shell itself so their unsaved state survives navigation; their routes only
// claim the URL.
export function ShellRendered() {
  return null;
}

export function NotFoundView() {
  return <Alert>
    <AlertTitle>This page does not exist</AlertTitle>
    <AlertDescription><p>The address may be old or mistyped. Pages moved when the menu was rebuilt.</p><Link to="/" activeOptions={{ exact: true }} className="mt-2 inline-block text-primary underline">Go to Home</Link></AlertDescription>
  </Alert>;
}
