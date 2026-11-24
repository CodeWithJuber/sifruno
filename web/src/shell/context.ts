import { createContext, useContext } from "react";
import type { PlatformReport, Resource, ServerReport, ServicesReport } from "@/lib/api";
import type { AuthSession } from "@/lib/auth-api";
import type { RestoreHandoff } from "@/lib/restoreHandoff";
import type { PageId } from "@/shell/pages";

export interface SiteHandoff { requestId: number; siteId: string; siteName: string; restore?: RestoreHandoff }

// The old screens still navigate by their original ids.
export type ScreenTarget = "websites" | "accounts" | "backups" | "files" | "access";

export interface Shell {
  publicPreview: boolean;
  revision: number;
  refresh: () => void;
  server: Resource<ServerReport>;
  services: Resource<ServicesReport>;
  platform: Resource<PlatformReport>;
  range: string;
  setRange: (value: string) => void;
  serviceQuery: string;
  setServiceQuery: (value: string) => void;
  // Pages with their own data report it here for the refresh button and footer.
  setPageResource: (id: PageId, value: Resource<unknown>) => void;
  open: (target: ScreenTarget) => void;
  // Who is signed in. restricted: a customer's session, or an admin's while
  // it views the panel as a customer (viewAs).
  viewer: { session: AuthSession | null; restricted: boolean };
  viewAs: (username: string) => Promise<void>;
  endViewAs: () => Promise<void>;
  signOut: () => void;
  // A sign-in made on a page (a customer's setup) hands its session here.
  setSession: (session: AuthSession) => void;
}

export const ShellContext = createContext<Shell | null>(null);

export function useShell(): Shell {
  const shell = useContext(ShellContext);
  if (!shell) throw new Error("useShell must be used inside the panel shell");
  return shell;
}
