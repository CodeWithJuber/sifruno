import { Archive, ArchiveRestore, Clock, Database, DatabaseBackup, Folder, Globe, History, Home, KeyRound, Layers, ListChecks, Network, Plus, ScrollText, Server, Settings, ShieldCheck, HardDrive, UserRound, Users, ArrowRightLeft } from "lucide-react";
import type { LucideIcon } from "lucide-react";

// One list drives the sidebar, the command palette, the breadcrumb and the
// page heading, so a page cannot appear in one place and be missing elsewhere.
// Menus name the job (plan, "Panel ka dhancha"): the old Accounts, Access,
// Change trail and AI budget screens live under Customers, Security,
// Activity and Settings. testId keeps the ids the browser QA scripts click.

export type PageId = "home" | "websites" | "new-website" | "website-job" | "move-website" | "move-job" | "website" | "site-databases" | "site-backups" | "site-domains" | "site-files" | "site-settings" | "site-cron" | "site-logs" | "static-sites" | "static-files" | "files" | "backups" | "activity" | "customers" | "hosting-accounts" | "account" | "setup" | "server" | "storage" | "network" | "backup-storage" | "security" | "api-tokens" | "settings" | "tour";

export interface Page {
  id: PageId;
  path: string;
  label: string;
  // The page's heading. Empty for a website's tabs: the website layout shows
  // the site's own name as the heading instead.
  title: string;
  subtitle: string;
  icon: LucideIcon;
  testId: string;
  // private: local panel only. preview: the public demo only. Both: everywhere.
  audience: "private" | "preview" | "both";
  // advanced: the old static-site screens and tools for whoever runs the
  // server's Linux side, in their own group at the foot of the menu, so they
  // do not compete with the jobs above.
  group: "main" | "admin" | "advanced";
  // A child appears under its parent in the sidebar, or as a tab (Server).
  parent?: PageId;
  // A page whose address holds an id (one setup job) is matched by this
  // pattern and is never listed in the sidebar or the palette.
  pattern?: RegExp;
  // For a page in the customer's menu: the API routes it reads to show
  // itself, as the server's customer table names them. Each must be open to
  // customers (customer-routes.test.mjs checks it against the table). A
  // website's tabs name theirs in lib/site-page.ts.
  needs?: readonly string[];
}

const websitesRead = ["GET /api/v1/websites/sites"] as const;

export const pages: readonly Page[] = [
  { id: "home", path: "/", label: "Home", title: "Home", subtitle: "Your websites and this server at a glance.", icon: Home, testId: "nav-overview", audience: "both", group: "main", needs: websitesRead },
  { id: "tour", path: "/tour", label: "Panel tour", title: "Panel tour", subtitle: "Explore Websites, Files and Backups with sample content.", icon: Layers, testId: "nav-panel-preview", audience: "preview", group: "main" },
  { id: "websites", path: "/websites", label: "Websites", title: "Websites", subtitle: "The WordPress and PHP websites on this server.", icon: Globe, testId: "nav-websites", audience: "private", group: "main", needs: websitesRead },
  { id: "new-website", path: "/websites/new", label: "New website", title: "New website", subtitle: "Create a WordPress website on this server.", icon: Plus, testId: "nav-new-website", audience: "private", group: "main", parent: "websites" },
  { id: "website-job", path: "/websites/jobs/$jobId", label: "Website setup", title: "Website setup", subtitle: "Follow each step while the panel creates the website.", icon: ListChecks, testId: "nav-website-job", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/jobs\/[^/]+$/ },
  { id: "move-website", path: "/websites/move", label: "Move a website here", title: "Move a website here", subtitle: "Copy a website from a cPanel server or a cPanel backup file, compare it, then point DNS here.", icon: ArrowRightLeft, testId: "nav-move-website", audience: "private", group: "main", parent: "websites" },
  { id: "move-job", path: "/websites/move/$jobId", label: "Website move", title: "Website move", subtitle: "Follow the copy, compare it with the old site, then cut over.", icon: ArrowRightLeft, testId: "nav-move-job", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/move\/[^/]+$/ },
  // One website's page: one entry for each of its tabs.
  { id: "website", path: "/websites/sites/$accountId", label: "Overview", title: "", subtitle: "", icon: Globe, testId: "nav-website", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+$/ },
  { id: "site-databases", path: "/websites/sites/$accountId/databases", label: "Databases", title: "", subtitle: "", icon: Database, testId: "nav-site-databases", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/databases$/ },
  { id: "site-backups", path: "/websites/sites/$accountId/backups", label: "Backups", title: "", subtitle: "", icon: ArchiveRestore, testId: "nav-site-backups", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/backups$/ },
  { id: "site-domains", path: "/websites/sites/$accountId/domains", label: "Domains and SSL", title: "", subtitle: "", icon: Globe, testId: "nav-site-domains", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/domains$/ },
  { id: "site-files", path: "/websites/sites/$accountId/files", label: "Files", title: "", subtitle: "", icon: Folder, testId: "nav-site-files", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/files$/ },
  { id: "site-cron", path: "/websites/sites/$accountId/cron", label: "Cron jobs", title: "", subtitle: "", icon: Clock, testId: "nav-site-cron", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/cron$/ },
  { id: "site-logs", path: "/websites/sites/$accountId/logs", label: "Logs", title: "", subtitle: "", icon: ScrollText, testId: "nav-site-logs", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/logs$/ },
  { id: "site-settings", path: "/websites/sites/$accountId/settings", label: "Settings", title: "", subtitle: "", icon: Settings, testId: "nav-site-settings", audience: "private", group: "main", parent: "websites", pattern: /^\/websites\/sites\/[^/]+\/settings$/ },
  { id: "static-sites", path: "/websites/static", label: "Static sites (old)", title: "Static sites (old)", subtitle: "Websites made with the old static-file model.", icon: Globe, testId: "nav-static-sites", audience: "private", group: "advanced" },
  { id: "files", path: "/websites/files", label: "Files", title: "Files", subtitle: "View and edit your website's files.", icon: Folder, testId: "nav-files", audience: "private", group: "main", parent: "websites", needs: websitesRead },
  // The old static sites' file screen, opened from Static sites (old) only.
  { id: "static-files", path: "/websites/static/files", label: "Static site files (old)", title: "Static site files (old)", subtitle: "Files of the websites made with the old static-file model.", icon: Folder, testId: "nav-static-files", audience: "private", group: "advanced", parent: "static-sites", pattern: /^\/websites\/static\/files$/ },
  // The old static sites' ZIP backups; each website's own backups are its Backups tab.
  { id: "backups", path: "/websites/backups", label: "Static site backups (old)", title: "Static site backups (old)", subtitle: "ZIP backups of the websites made with the old static-file model.", icon: Archive, testId: "nav-backups", audience: "private", group: "advanced" },
  { id: "activity", path: "/activity", label: "Activity", title: "Activity", subtitle: "Recent changes to website files, and how to recover them.", icon: History, testId: "nav-trail", audience: "private", group: "advanced" },
  // The signed-in person's own login: its password and authenticator app,
  // and for a customer the websites it manages. Admins and customers both.
  { id: "account", path: "/account", label: "Account", title: "Account", subtitle: "Your login, its password and its authenticator app.", icon: UserRound, testId: "nav-account", audience: "private", group: "main", needs: ["GET /api/v1/session", ...websitesRead] },
  // Where a customer lands from its setup link. It needs no session.
  { id: "setup", path: "/setup", label: "Set up your login", title: "Set up your login", subtitle: "Choose a password and connect an authenticator app.", icon: ShieldCheck, testId: "nav-setup", audience: "private", group: "main", pattern: /^\/setup$/ },
  { id: "customers", path: "/customers", label: "Customers", title: "Customers", subtitle: "Who can sign in to manage which websites.", icon: Users, testId: "nav-customers", audience: "private", group: "admin" },
  // The older hosting-accounts screen; it keeps the nav id the QA scripts click.
  { id: "hosting-accounts", path: "/customers/accounts", label: "Hosting accounts", title: "Hosting accounts", subtitle: "Linux accounts on this server and their home folders.", icon: Users, testId: "nav-accounts", audience: "private", group: "advanced" },
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

// A customer (a site owner) sees Home, Websites with each website's tabs, and
// Account (plan, "Panel ka dhancha"); so does an admin viewing the panel as
// a customer. The server decides what a customer may do; this only shapes
// the menu and keeps admin pages out of the way. Admins see Account too.
export type MenuRole = "admin" | "customer";

export function customerPage(p: Page): boolean {
  return p.id === "home" || p.id === "websites" || p.id === "files" || p.id === "account" || p.id === "setup" || p.path.startsWith("/websites/sites/");
}

export function visiblePages(publicPreview: boolean, role: MenuRole = "admin"): Page[] {
  return pages.filter((p) => !p.pattern && (p.audience === "both" || (publicPreview ? p.audience === "preview" : p.audience === "private"))
    && (role !== "customer" || customerPage(p)));
}
