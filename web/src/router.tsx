import type { ReactNode } from "react";
import { createRootRoute, createRoute, createRouter, redirect } from "@tanstack/react-router";
import { AppShell, isPublicPreview } from "@/shell/AppShell";
import { ActivityView, HomeView, NetworkView, NotFoundView, SecurityView, ServicesView, SettingsView, ShellRendered, StorageView, TourView } from "@/shell/views";

// Every page has its own URL, so back, reload and shared links work. The Go
// server already answers unknown extension-less paths with index.html.

const rootRoute = createRootRoute({ component: AppShell, notFoundComponent: NotFoundView });

// The public demo never shows private pages, and the local panel has no tour.
const privateOnly = () => { if (isPublicPreview()) throw redirect({ to: "/" }); };
const previewOnly = () => { if (!isPublicPreview()) throw redirect({ to: "/" }); };

const route = (path: string, component: () => ReactNode, beforeLoad?: () => void) =>
  createRoute({ getParentRoute: () => rootRoute, path, component, beforeLoad });

const routeTree = rootRoute.addChildren([
  route("/", HomeView),
  route("/tour", TourView, previewOnly),
  route("/websites", ShellRendered, privateOnly),
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
