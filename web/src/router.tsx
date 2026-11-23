import type { ReactNode } from "react";
import { createRootRoute, createRoute, createRouter, redirect } from "@tanstack/react-router";
import { AppShell, isPublicPreview } from "@/shell/AppShell";
import { ActivityView, HomeView, NetworkView, NewWebsiteView, NotFoundView, SecurityView, ServicesView, SettingsView, ShellRendered, StorageView, TourView, WebsiteJobView, WebsitesView, WebsiteView } from "@/shell/views";

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

const routeTree = rootRoute.addChildren([
  route("/", HomeView),
  route("/tour", TourView, previewOnly),
  route("/websites", WebsitesView, privateOnly),
  route("/websites/new", NewWebsiteView, privateOnly),
  websiteJobRoute,
  websiteRoute,
  route("/websites/static", ShellRendered, privateOnly),
  route("/websites/files", ShellRendered, privateOnly),
  route("/websites/backups", ShellRendered, privateOnly),
  route("/activity", ActivityView, privateOnly),
  route("/customers", ShellRendered, privateOnly),
  route("/server", ServicesView),
  route("/server/storage", StorageView),
  route("/server/network", NetworkView),
  route("/security", SecurityView, privateOnly),
  route("/settings", SettingsView, privateOnly),
]);

export const router = createRouter({ routeTree });
