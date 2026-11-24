import { lazy } from "react";
import type { ReactNode } from "react";
import { createRootRoute, createRoute, createRouter, redirect } from "@tanstack/react-router";
import { AppShell, isPublicPreview } from "@/shell/AppShell";
import { ActivityView, ApiTokensView, BackupStorageView, FilesView, HomeView, NetworkView, NewWebsiteView, NotFoundView, SecurityView, ServicesView, SettingsView, ShellRendered, StorageView, TourView, WebsiteJobView, WebsitesView, WebsiteView } from "@/shell/views";

// Every page has its own URL, so back, reload and shared links work. The Go
// server already answers unknown extension-less paths with index.html.

const rootRoute = createRootRoute({ component: AppShell, notFoundComponent: NotFoundView });

// The public demo never shows private pages, and the local panel has no tour.
const privateOnly = () => { if (isPublicPreview()) throw redirect({ to: "/" }); };
const previewOnly = () => { if (!isPublicPreview()) throw redirect({ to: "/" }); };

const route = (path: string, component: () => ReactNode, beforeLoad?: () => void) =>
  createRoute({ getParentRoute: () => rootRoute, path, component, beforeLoad });

// One setup job's progress. The id is in the address, so a reload keeps it.
const websiteJobRoute = createRoute({ getParentRoute: () => rootRoute, path: "/websites/jobs/$jobId", component: WebsiteJobRoute, beforeLoad: privateOnly });
function WebsiteJobRoute() {
  const { jobId } = websiteJobRoute.useParams();
  return <WebsiteJobView jobId={jobId} />;
}

// One website's Overview, by its hosting account's id.
const websiteRoute = createRoute({ getParentRoute: () => rootRoute, path: "/websites/sites/$accountId", component: WebsiteRoute, beforeLoad: privateOnly });
function WebsiteRoute() {
  const { accountId } = websiteRoute.useParams();
  return <WebsiteView accountId={accountId} />;
}

// One website's Databases page. Keyed by the id, so moving from one website
// to another starts fresh.
const SiteDatabases = lazy(() => import("@/SiteDatabases").then((m) => ({ default: m.SiteDatabases })));
const siteDatabasesRoute = createRoute({ getParentRoute: () => rootRoute, path: "/websites/sites/$accountId/databases", component: SiteDatabasesRoute, beforeLoad: privateOnly });
function SiteDatabasesRoute() {
  const { accountId } = siteDatabasesRoute.useParams();
  return <SiteDatabases key={accountId} accountId={accountId} />;
}

// One website's Backups page, keyed by the id like Databases.
const SiteBackups = lazy(() => import("@/SiteBackups").then((m) => ({ default: m.SiteBackups })));
const siteBackupsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/websites/sites/$accountId/backups", component: SiteBackupsRoute, beforeLoad: privateOnly });
function SiteBackupsRoute() {
  const { accountId } = siteBackupsRoute.useParams();
  return <SiteBackups key={accountId} accountId={accountId} />;
}

// One website's Domains page: its other domains and its redirects.
const SiteDomains = lazy(() => import("@/SiteDomains").then((m) => ({ default: m.SiteDomains })));
const siteDomainsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/websites/sites/$accountId/domains", component: SiteDomainsRoute, beforeLoad: privateOnly });
function SiteDomainsRoute() {
  const { accountId } = siteDomainsRoute.useParams();
  return <SiteDomains key={accountId} accountId={accountId} />;
}
// One website's Files page. The folder is in the address (?path=), so back,
// reload and shared links open the same folder.
const SiteFiles = lazy(() => import("@/SiteFiles").then((m) => ({ default: m.SiteFiles })));
const siteFilesRoute = createRoute({
  getParentRoute: () => rootRoute, path: "/websites/sites/$accountId/files", component: SiteFilesRoute, beforeLoad: privateOnly,
  validateSearch: (search: Record<string, unknown>): { path?: string } => typeof search.path === "string" && search.path ? { path: search.path } : {},
});
function SiteFilesRoute() {
  const { accountId } = siteFilesRoute.useParams();
  const { path } = siteFilesRoute.useSearch();
  return <SiteFiles key={accountId} accountId={accountId} path={path ?? ""} />;
}

const routeTree = rootRoute.addChildren([
  route("/", HomeView),
  route("/tour", TourView, previewOnly),
  route("/websites", WebsitesView, privateOnly),
  route("/websites/new", NewWebsiteView, privateOnly),
  websiteJobRoute,
  websiteRoute,
  siteDatabasesRoute,
  siteBackupsRoute,
  siteDomainsRoute,
  siteFilesRoute,
  route("/websites/static", ShellRendered, privateOnly),
  route("/websites/static/files", ShellRendered, privateOnly),
  route("/websites/files", FilesView, privateOnly),
  route("/websites/backups", ShellRendered, privateOnly),
  route("/activity", ActivityView, privateOnly),
  route("/customers", ShellRendered, privateOnly),
  route("/server", ServicesView),
  route("/server/storage", StorageView),
  route("/server/network", NetworkView),
  route("/server/backups", BackupStorageView, privateOnly),
  route("/security", SecurityView, privateOnly),
  route("/security/api-tokens", ApiTokensView, privateOnly),
  route("/settings", SettingsView, privateOnly),
]);

export const router = createRouter({ routeTree });
