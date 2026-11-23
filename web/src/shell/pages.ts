import { Archive, Folder, Globe, History, Home, Layers, Network, Server, Settings, ShieldCheck, HardDrive, Users } from "lucide-react";
import type { LucideIcon } from "lucide-react";

// One list drives the sidebar, the command palette, the breadcrumb and the
// page heading, so a page cannot appear in one place and be missing elsewhere.
// Menus name the job (plan, "Panel ka dhancha"): the old Accounts, Access,
// Change trail and AI budget screens live under Customers, Security,
// Activity and Settings. testId keeps the ids the browser QA scripts click.

export type PageId = "home" | "websites" | "files" | "backups" | "activity" | "customers" | "server" | "storage" | "network" | "security" | "settings" | "tour";

export interface Page {
  id: PageId;
  path: string;
  label: string;
  title: string;
  subtitle: string;
  icon: LucideIcon;
  testId: string;
  // private: local panel only. preview: the public demo only. Both: everywhere.
  audience: "private" | "preview" | "both";
  group: "main" | "admin";
  // A child appears under its parent in the sidebar, or as a tab (Server).
  parent?: PageId;
}

export const pages: readonly Page[] = [
  { id: "home", path: "/", label: "Home", title: "Home", subtitle: "Your websites and this server at a glance.", icon: Home, testId: "nav-overview", audience: "both", group: "main" },
  { id: "tour", path: "/tour", label: "Panel tour", title: "Panel tour", subtitle: "Explore Websites, Files and Backups with sample content.", icon: Layers, testId: "nav-panel-preview", audience: "preview", group: "main" },
  { id: "websites", path: "/websites", label: "Websites", title: "Websites", subtitle: "Your websites.", icon: Globe, testId: "nav-websites", audience: "private", group: "main" },
  { id: "files", path: "/websites/files", label: "Files", title: "Files", subtitle: "View and edit your website's files.", icon: Folder, testId: "nav-files", audience: "private", group: "main", parent: "websites" },
  { id: "backups", path: "/websites/backups", label: "Backups", title: "Backups", subtitle: "Create, download and restore website backups.", icon: Archive, testId: "nav-backups", audience: "private", group: "main", parent: "websites" },
  { id: "activity", path: "/activity", label: "Activity", title: "Activity", subtitle: "Recent changes to website files, and how to recover them.", icon: History, testId: "nav-trail", audience: "private", group: "main" },
  { id: "customers", path: "/customers", label: "Customers", title: "Customers", subtitle: "Customer accounts on this server and their home folders.", icon: Users, testId: "nav-accounts", audience: "private", group: "admin" },
  { id: "server", path: "/server", label: "Server", title: "Server", subtitle: "Services, storage and network on this server.", icon: Server, testId: "nav-services", audience: "both", group: "admin" },
  { id: "storage", path: "/server/storage", label: "Storage", title: "Server", subtitle: "Services, storage and network on this server.", icon: HardDrive, testId: "nav-storage", audience: "both", group: "admin", parent: "server" },
  { id: "network", path: "/server/network", label: "Network", title: "Server", subtitle: "Services, storage and network on this server.", icon: Network, testId: "nav-network", audience: "both", group: "admin", parent: "server" },
  { id: "security", path: "/security", label: "Security", title: "Security", subtitle: "Sessions signed in to this panel.", icon: ShieldCheck, testId: "nav-access", audience: "private", group: "admin" },
  { id: "settings", path: "/settings", label: "Settings", title: "Settings", subtitle: "Panel settings, including the monthly limit for paid AI work.", icon: Settings, testId: "nav-budget", audience: "private", group: "admin" },
];

export const serverTabs: readonly PageId[] = ["server", "storage", "network"];

export function pageById(id: PageId): Page {
  const page = pages.find((p) => p.id === id);
  if (!page) throw new Error(`Unknown page ${id}`);
  return page;
}

export function visiblePages(publicPreview: boolean): Page[] {
  return pages.filter((p) => p.audience === "both" || (publicPreview ? p.audience === "preview" : p.audience === "private"));
}
