import { Archive, ArchiveRestore, Database, DatabaseBackup, Folder, Globe, History, Home, KeyRound, Layers, ListChecks, Network, Plus, Server, Settings, ShieldCheck, HardDrive, Users } from "lucide-react";
import type { LucideIcon } from "lucide-react";

// One list drives the sidebar, the command palette, the breadcrumb and the
// page heading, so a page cannot appear in one place and be missing elsewhere.
// Menus name the job (plan, "Panel ka dhancha"): the old Accounts, Access,
// Change trail and AI budget screens live under Customers, Security,
// Activity and Settings. testId keeps the ids the browser QA scripts click.

export type PageId = "home" | "websites" | "new-website" | "website-job" | "website" | "site-databases" | "site-backups" | "site-domains" | "site-files" | "static-sites" | "static-files" | "files" | "backups" | "activity" | "customers" | "server" | "storage" | "network" | "backup-storage" | "security" | "api-tokens" | "settings" | "tour";

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
  // A page whose address holds an id (one setup job) is matched by this
  // pattern and is never listed in the sidebar or the palette.
  pattern?: RegExp;
}

export const pages: readonly Page[] = [
  { id: "home", path: "/", label: "Home", title: "Home", subtitle: "Your websites and this server at a glance.", icon: Home, testId: "nav-overview", audience: "both", group: "main" },
  { id: "tour", path: "/tour", label: "Panel tour", title: "Panel tour", subtitle: "Explore Websites, Files and Backups with sample content.", icon: Layers, testId: "nav-panel-preview", audience: "preview", group: "main" },
  { id: "websites", path: "/websites", label: "Websites", title: "Websites", subtitle: "The WordPress and PHP websites on this server.", icon: Globe, testId: "nav-websites", audience: "private", group: "main" },
  { id: "new-website", path: "/websites/new", label: "New website", title: "New website", subtitle: "Create a WordPress website on this server.", icon: Plus, testId: "nav-new-website", audience: "private", group: "main", parent: "websites" },
  { id: "website-job", path: "/websites/jobs/$jobId", label: "Website setup", title: "Website setup", subtitle: "Follow each step while the panel creates the website.", icon: ListChecks, testId: "nav-website-job", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/jobs\/[^/]+$/ },
  { id: "website", path: "/websites/sites/$accountId", label: "Overview", title: "Website overview", subtitle: "One website: its status, versions and links.", icon: Globe, testId: "nav-website", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+$/ },
  { id: "site-databases", path: "/websites/sites/$accountId/databases", label: "Databases", title: "Databases", subtitle: "One website's databases and database users.", icon: Database, testId: "nav-site-databases", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/databases$/ },
  { id: "site-backups", path: "/websites/sites/$accountId/backups", label: "Backups", title: "Backups", subtitle: "One website's backups: back up now, restore, and the last restore drill.", icon: ArchiveRestore, testId: "nav-site-backups", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/backups$/ },
  { id: "site-domains", path: "/websites/sites/$accountId/domains", label: "Domains", title: "Domains", subtitle: "One website's other domains and its redirects.", icon: Globe, testId: "nav-site-domains", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/domains$/ },
  { id: "site-files", path: "/websites/sites/$accountId/files", label: "Files", title: "Files", subtitle: "One website's home folder: browse, upload, edit and download its files.", icon: Folder, testId: "nav-site-files", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/files$/ },
  { id: "static-sites", path: "/websites/static", label: "Static sites (old)", title: "Static sites (old)", subtitle: "Websites made with the old static-file model.", icon: Globe, testId: "nav-static-sites", audience: "private", group: "main", parent: "websites" },
  { id: "files", path: "/websites/files", label: "Files", title: "Files", subtitle: "View and edit your website's files.", icon: Folder, testId: "nav-files", audience: "private", group: "main", parent: "websites" },
  // The old static sites' file screen, opened from Static sites (old) only.
  { id: "static-files", path: "/websites/static/files", label: "Static site files (old)", title: "Static site files (old)", subtitle: "Files of the websites made with the old static-file model.", icon: Folder, testId: "nav-static-files", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/static\/files$/ },
  { id: "backups", path: "/websites/backups", label: "Backups", title: "Backups", subtitle: "Create, download and restore website backups.", icon: Archive, testId: "nav-backups", audience: "private", group: "main", parent: "websites" },
  { id: "activity", path: "/activity", label: "Activity", title: "Activity", subtitle: "Recent changes to website files, and how to recover them.", icon: History, testId: "nav-trail", audience: "private", group: "main" },
  { id: "customers", path: "/customers", label: "Customers", title: "Customers", subtitle: "Customer accounts on this server and their home folders.", icon: Users, testId: "nav-accounts", audience: "private", group: "admin" },
  { id: "server", path: "/server", label: "Server", title: "Server", subtitle: "Services, storage and network on this server.", icon: Server, testId: "nav-services", audience: "both", group: "admin" },
  { id: "storage", path: "/server/storage", label: "Storage", title: "Server", subtitle: "Services, storage and network on this server.", icon: HardDrive, testId: "nav-storage", audience: "both", group: "admin", parent: "server" },
  { id: "network", path: "/server/network", label: "Network", title: "Server", subtitle: "Services, storage and network on this server.", icon: Network, testId: "nav-network", audience: "both", group: "admin", parent: "server" },
  { id: "backup-storage", path: "/server/backups", label: "Backup storage", title: "Server", subtitle: "Services, storage and network on this server.", icon: DatabaseBackup, testId: "nav-backup-storage", audience: "private", group: "admin", parent: "server" },
  { id: "security", path: "/security", label: "Security", title: "Security", subtitle: "Sessions signed in to this panel.", icon: ShieldCheck, testId: "nav-access", audience: "private", group: "admin" },
  { id: "api-tokens", path: "/security/api-tokens", label: "API tokens", title: "API tokens", subtitle: "Let a program, such as your billing system, use the panel API.", icon: KeyRound, testId: "nav-api-tokens", audience: "private", group: "admin", parent: "security" },
  { id: "settings", path: "/settings", label: "Settings", title: "Settings", subtitle: "Panel settings, including the monthly limit for paid AI work.", icon: Settings, testId: "nav-budget", audience: "private", group: "admin" },
];

export const serverTabs: readonly PageId[] = ["server", "storage", "network", "backup-storage"];

export function pageById(id: PageId): Page {
  const page = pages.find((p) => p.id === id);
  if (!page) throw new Error(`Unknown page ${id}`);
  return page;
}

export function visiblePages(publicPreview: boolean): Page[] {
  return pages.filter((p) => !p.pattern && (p.audience === "both" || (publicPreview ? p.audience === "preview" : p.audience === "private")));
}
