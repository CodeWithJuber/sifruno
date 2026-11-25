import { useEffect, useId, useRef, useState } from "react";
import type { ComponentProps, FormEvent, ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { cn } from "cn";
import { CircleAlert, CircleCheck, CirclePause, ExternalLink, Globe, Lock, LockOpen, Plus, RefreshCw, TriangleAlert } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { adoptCurrentFolder, changePhpVersion, dayLabel, deleteWebsite, folderNotice, httpsState, listWebsites, phpChange, setWebsiteState, siteStatus, WebsitesApiError } from "@/lib/websites-api";
import type { Website, WebsiteDeleted, WebsiteDetail } from "@/lib/websites-api";
import { useShell } from "@/shell/context";
import type { PageId } from "@/shell/pages";
import { DiskMeter, trafficText } from "./SiteTools";
// The busy ring a working button shows, as on the wizard's screens.
import "./new-website.css";

// Websites: the WordPress and PHP sites the New website wizard made, and the
// parts one site's page (WebsiteLayout) shares with the list: badges, links,
// reads, problems and the site's actions. The base styles colour <p> and <a>
// outside Tailwind's layers, so coloured text uses div or span and links
// drawn as buttons mark their text colour important, as on the wizard's
// screens.

export const panel = "rounded-lg border border-border bg-card";
export const control = "h-9 pointer-coarse:h-11";
export const linkButton = (variant: "default" | "outline" | "ghost", className = "") =>
  cn(buttonVariants({ variant, className: `${control} ${variant === "default" ? "text-primary-foreground!" : ""} ${className}` }));

export interface Problem { what: string; why: string; next: string; technical: string; status: number }

export function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof WebsitesApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
}

// One read of the server, again on the header's refresh and on Try again.
// It reports to the shell, which drives the refresh button and the footer;
// without a page id it does not report (another read on the page does).
export function useRead<T>(pageId: PageId | undefined, load: (signal: AbortSignal) => Promise<T>, what: string) {
  const { revision, setPageResource } = useShell();
  const [data, setData] = useState<T>();
  const [problem, setProblem] = useState<Problem>();
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const loader = useRef(load);
  loader.current = load;
  useEffect(() => {
    let live = true;
    const controller = new AbortController();
    setLoading(true);
    loader.current(controller.signal).then(
      (value) => { if (live) { setData(value); setProblem(undefined); setLoadedAt(new Date()); setLoading(false); } },
      (error) => { if (live) { setProblem(problemFrom(error, what)); setLoading(false); } },
    );
    return () => { live = false; controller.abort(); };
  }, [revision, attempt, what]);
  useEffect(() => {
    if (pageId) setPageResource(pageId, { data, loading, error: problem?.what, loadedAt });
  }, [pageId, data, loading, problem, loadedAt, setPageResource]);
  // replace takes the server's answer to a change as the newest read.
  const replace = (value: T) => { setData(value); setProblem(undefined); setLoadedAt(new Date()); };
  return { data, problem, loading, retry: () => setAttempt((value) => value + 1), replace };
}

// ---- Shared parts -------------------------------------------------------------

function TechnicalDetails({ children }: { children: ReactNode }) {
  return <details className="text-sm">
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
    <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{children}</div>
  </details>;
}

// What happened (the title), why, what to do next, and the request under
// Technical details. role="alert": a failed read or change is announced at once.
export function ProblemAlert({ problem, onRetry, retryLabel = "Try again", testId = "websites-problem" }: { problem: Problem; onRetry?: () => void; retryLabel?: string; testId?: string }) {
  return <Alert variant="destructive" className="text-start" data-testid={testId}>
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
      <div className="flex flex-col gap-1.5 text-sm">
        <div className="text-foreground">{problem.why}</div>
        <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {problem.next}</div>
      </div>
      <TechnicalDetails>{problem.technical}</TechnicalDetails>
      {onRetry && <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}><RefreshCw aria-hidden="true" />{retryLabel}</Button>}
    </AlertDescription>
  </Alert>;
}

// The state in words, with an icon that only repeats it.
export function StatusBadge({ state }: { state: string }) {
  const { label, tone } = siteStatus(state);
  const Icon = tone === "live" ? CircleCheck : tone === "suspended" ? CirclePause : TriangleAlert;
  return <Badge variant={tone === "live" ? "secondary" : tone === "suspended" ? "outline" : "destructive"} data-testid="website-status" data-state={state}>
    <Icon className={tone === "live" ? "text-primary" : ""} aria-hidden="true" />{label}
  </Badge>;
}

export function HttpsBadge({ site }: { site: Website }) {
  const https = httpsState(site.https);
  if (https.kind === "off") return <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
    <Badge variant="outline" data-testid="website-https" data-https="off"><LockOpen aria-hidden="true" />http</Badge>
    <span className="text-xs text-muted-foreground">No certificate yet</span>
  </span>;
  if (https.kind === "expired") return <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
    <Badge variant="destructive" data-testid="website-https" data-https="expired"><TriangleAlert aria-hidden="true" />https expired</Badge>
    <span className="text-xs text-muted-foreground">on {dayLabel(https.since)}</span>
  </span>;
  return <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
    <Badge variant="secondary" data-testid="website-https" data-https="on"><Lock className="text-primary" aria-hidden="true" />https</Badge>
    {https.until && <span className="text-xs text-muted-foreground" data-testid="website-https-until">until {dayLabel(https.until)}</span>}
  </span>;
}

// The site's other domains and redirects under its name in the list, when it
// has any. An alias without https says so.
function OtherDomains({ site }: { site: Website }) {
  if (site.aliases.length === 0 && site.redirect_count === 0) return null;
  const httpOnly = site.aliases.filter((alias) => alias.https !== "on").length;
  return <span className="mt-0.5 block text-xs font-normal text-muted-foreground" data-testid="website-other-domains">
    {site.aliases.length > 0 && <span className="wrap-anywhere">Also {site.aliases.map((alias) => alias.name).join(", ")}</span>}
    {httpOnly > 0 && <span> · {httpOnly === 1 ? "1 on http only" : `${httpOnly} on http only`}</span>}
    {site.redirect_count > 0 && <span>{site.aliases.length > 0 ? " · " : ""}{site.redirect_count === 1 ? "1 redirect" : `${site.redirect_count} redirects`}</span>}
  </span>;
}

// External links name the site, so each is distinct for a screen reader, and
// say that they open a new tab.
export function SiteLink({ href, label, domain, variant, testId }: { href: string; label: string; domain: string; variant: "default" | "outline" | "ghost"; testId: string }) {
  return <a href={href} target="_blank" rel="noopener noreferrer" className={linkButton(variant)} data-testid={testId}>
    {label}<span className="sr-only"> {domain} (opens in a new tab)</span><ExternalLink aria-hidden="true" />
  </a>;
}

// ---- Websites list ------------------------------------------------------------

export function WebsitesList() {
  const { viewer } = useShell();
  const { data: sites, problem, loading, retry } = useRead("websites", (signal) => listWebsites({ signal }), "Your websites could not be loaded.");
  // A customer's login cannot make websites or reach the old static sites,
  // so it is not offered either.
  const canCreate = viewer.can("POST /api/v1/websites/wordpress");
  const canStatic = viewer.can("GET /api/v1/sites");
  return <div className="flex w-full flex-col gap-4" data-testid="websites-page">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="text-sm text-muted-foreground" data-testid="websites-count">
        {sites?.length ? (sites.length === 1 ? "1 website" : `${sites.length} websites`) : ""}
      </div>
      {(canStatic || canCreate) && <div className="flex flex-wrap items-center gap-2">
        {canStatic && <Link to="/websites/static" className={linkButton("ghost")} data-testid="static-sites-link">Static sites (old)</Link>}
        {canCreate && <Link to="/websites/new" className={linkButton("default")} data-testid="new-website-link"><Plus aria-hidden="true" />New website</Link>}
      </div>}
    </div>
    {problem && (sites
      ? <ProblemAlert problem={{ ...problem, next: `${problem.next} The list below is from the last successful read.` }} onRetry={retry} />
      : <ProblemAlert problem={problem} onRetry={retry} />)}
    {!sites && loading && <ListLoading />}
    {sites && sites.length === 0 && <NoWebsites canCreate={canCreate} />}
    {sites && sites.length > 0 && <SiteTable sites={sites} />}
  </div>;
}

// A placeholder in the list's shape. Not a live region: "loading" is not
// worth announcing; the busy region and its hidden text say it.
function ListLoading() {
  return <div className={`${panel} flex flex-col gap-3 p-4`} aria-busy="true" data-testid="websites-loading">
    <span className="sr-only">Loading websites</span>
    {[0, 1, 2].map((row) => <Skeleton key={row} className="h-10 w-full" />)}
  </div>;
}

function NoWebsites({ canCreate }: { canCreate: boolean }) {
  return <Empty className={`${panel} border-dashed py-12`} data-testid="websites-empty">
    <EmptyHeader>
      <EmptyMedia variant="icon"><Globe aria-hidden="true" /></EmptyMedia>
      <EmptyTitle><h2 className="text-sm font-medium">No websites yet</h2></EmptyTitle>
      <EmptyDescription>{canCreate
        ? "Create a WordPress website or a PHP site. The panel sets up the hosting account and the site, and the site is listed here."
        : "Your login has no websites at the moment. Ask whoever gave you the login to add yours; they then show here."}</EmptyDescription>
    </EmptyHeader>
    {canCreate && <EmptyContent>
      <Link to="/websites/new" className={linkButton("default")} data-testid="empty-new-website"><Plus aria-hidden="true" />New website</Link>
    </EmptyContent>}
  </Empty>;
}

// A table while there is room for its columns. In a narrower container each
// row becomes a card: the header row is hidden and each cell shows its column
// name from data-label.
const stacked = "@max-[62rem]:block";
const stackedCell = `${stacked} @max-[62rem]:grid @max-[62rem]:grid-cols-[7rem_minmax(0,1fr)] @max-[62rem]:items-center @max-[62rem]:gap-x-3 @max-[62rem]:px-0 @max-[62rem]:py-1 @max-[62rem]:before:content-[attr(data-label)] @max-[62rem]:before:text-muted-foreground`;

function SiteTable({ sites }: { sites: Website[] }) {
  return <div className={`${panel} @container`}>
    <div className="flex items-baseline justify-between gap-3 px-4 pt-4 pb-3">
      <h2 id="websites-heading">Your websites</h2>
    </div>
    {/* Focusable so a keyboard can scroll it if the table is ever wider than the panel. */}
    <div className="overflow-x-auto px-2 pb-2 @max-[62rem]:px-4 @max-[62rem]:pb-4" role="region" aria-labelledby="websites-heading" tabIndex={0}>
      <table className={`w-full caption-bottom text-sm ${stacked}`} data-testid="websites-table">
        <caption className="sr-only">Your websites, newest first</caption>
        <TableHeader className="@max-[62rem]:hidden">
          <TableRow className="hover:bg-transparent">
            <TableHead scope="col" className="text-start text-muted-foreground">Website</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">Status</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">HTTPS</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">PHP</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">Type</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">Usage</TableHead>
            <TableHead scope="col" className="text-end text-muted-foreground"><span className="sr-only">Actions</span></TableHead>
          </TableRow>
        </TableHeader>
        <tbody className={`${stacked} @max-[62rem]:flex @max-[62rem]:flex-col @max-[62rem]:gap-3`}>
          {sites.map((site) => <TableRow key={site.account_id} data-testid="website-row" data-domain={site.domain} data-account-id={site.account_id}
            className={`${stacked} @max-[62rem]:rounded-lg @max-[62rem]:border @max-[62rem]:border-border @max-[62rem]:p-3 @max-[62rem]:hover:bg-transparent`}>
            <th scope="row" className={`p-2 text-start align-middle font-medium text-foreground ${stacked} @max-[62rem]:px-0 @max-[62rem]:pt-0 @max-[62rem]:pb-2`}>
              <span className="wrap-anywhere">{site.domain}</span>
              <OtherDomains site={site} />
            </th>
            <TableCell data-label="Status" className={stackedCell}><StatusBadge state={site.state} /></TableCell>
            <TableCell data-label="HTTPS" className={`${stackedCell} whitespace-normal`}><HttpsBadge site={site} /></TableCell>
            <TableCell data-label="PHP" className={stackedCell} data-testid="website-php">{site.php_version || <span className="text-muted-foreground">Not reported</span>}</TableCell>
            <TableCell data-label="Type" className={stackedCell} data-testid="website-type">{site.kind === "php" ? "PHP site"
              : <span>WordPress <span className="text-muted-foreground" data-testid="website-wordpress">{site.wordpress_version}</span></span>}</TableCell>
            <TableCell data-label="Usage" className={`${stackedCell} whitespace-normal`} data-testid="website-usage">{site.usage
              ? <span className="flex flex-col gap-1"><DiskMeter usage={site.usage} /><span className="text-xs text-muted-foreground">Traffic: {trafficText(site.usage)}</span></span>
              : <span className="text-muted-foreground">Not reported</span>}</TableCell>
            <TableCell className={`text-end ${stacked} @max-[62rem]:px-0 @max-[62rem]:pt-3 @max-[62rem]:text-start`}>
              <div className="inline-flex flex-nowrap gap-2 @max-[62rem]:flex @max-[62rem]:flex-wrap">
                {site.state !== "partly_deleted" && <>
                  <SiteLink href={site.url} label="Open site" domain={site.domain} variant="outline" testId="open-site" />
                  {site.kind === "wordpress" && <SiteLink href={site.admin_url} label="WordPress admin" domain={site.domain} variant="outline" testId="open-admin" />}
                </>}
                <Link to="/websites/sites/$accountId" params={{ accountId: site.account_id }} className={linkButton("ghost")} data-testid="website-details-link">
                  Details<span className="sr-only"> for {site.domain}</span>
                </Link>
              </div>
            </TableCell>
          </TableRow>)}
        </tbody>
      </table>
    </div>
  </div>;
}


// ---- The site's actions -------------------------------------------------------

type ActionName = "folder" | "php" | "state" | "resuspend" | "delete";

// A button that says it is working and cannot be pressed twice. It stays
// focusable while busy, so focus is not lost.
function ActionButton({ busy, busyLabel, children, className = "", disabled, ...props }: ComponentProps<typeof Button> & { busy: boolean; busyLabel: string }) {
  return <Button {...props} className={`${control} aria-disabled:opacity-70 ${className}`} disabled={busy || disabled} focusableWhenDisabled={busy}>
    {busy && <progress className="wizard-spinner" aria-hidden="true" />}
    {busy ? busyLabel : children}
  </Button>;
}

// The changes, one at a time: each sends the revision the page has, and the
// server's answer becomes the page's newest read. The outcome is said in the
// page's polite live region; a failure is an alert where the person is.
// Two sections on the site's Settings tab, PHP version first and Suspend or
// delete last, with between (cron jobs and logs in Simple view) in the
// middle. repair shows "Apply suspension again", which Advanced view adds.
export function SiteActions({ site, repair, between, onChanged, onDeleted, onReload, announce }: {
  site: WebsiteDetail; repair: boolean; between?: ReactNode; onChanged: (site: WebsiteDetail) => void; onDeleted: (done: WebsiteDeleted) => void; onReload: () => void; announce: (text: string) => void;
}) {
  // Each part shows only when the viewer may use its route: a customer's
  // login keeps the site's cron jobs and logs (between) and nothing here.
  const { viewer } = useShell();
  const canFolder = viewer.can("POST /api/v1/websites/sites/{account_id}/folder");
  const canPhp = viewer.can("POST /api/v1/websites/sites/{account_id}/php");
  const canState = viewer.can("POST /api/v1/websites/sites/{account_id}/state");
  const canDelete = viewer.can("POST /api/v1/websites/sites/{account_id}/delete");
  const [busy, setBusy] = useState<ActionName>();
  const [failure, setFailure] = useState<{ action: ActionName; problem: Problem }>();
  const [outcome, setOutcome] = useState<{ action: ActionName; text: string }>();
  const [version, setVersion] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState("");
  const confirmRef = useRef<HTMLInputElement>(null);
  const ids = useId();
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  const php = phpChange(site);
  const folder = folderNotice(site);
  const folderRef = useRef<HTMLDivElement>(null);
  // The button that was pressed is gone once the folder is used.
  useEffect(() => { if (outcome?.action === "folder" && !folder) folderRef.current?.focus(); }, [outcome, folder]);
  const chosen = php.kind === "ready" ? (php.versions.includes(version) ? version : php.versions[0]) : "";
  const suspended = site.state === "suspended";
  const canChangeState = site.state === "active" || suspended;
  // A delete removed the hosting account but not yet the database.
  const partly = site.state === "partly_deleted";
  const matches = typed === site.domain;

  // run does one change: done takes the server's answer and gives the
  // sentence that says what happened.
  async function run<T>(action: ActionName, what: string, work: () => Promise<T>, done: (value: T) => string) {
    if (busy) return;
    setBusy(action); setFailure(undefined); setOutcome(undefined); announce("");
    try {
      const value = await work();
      if (!mounted.current) return;
      const text = done(value);
      setOutcome({ action, text }); announce(text);
    } catch (error) {
      if (mounted.current) setFailure({ action, problem: problemFrom(error, what) });
    } finally {
      if (mounted.current) setBusy(undefined);
    }
  }

  const changePhp = () => run("php", "The PHP version was not changed.", () => changePhpVersion(site, chosen),
    (next) => { onChanged(next); return `${next.domain} now runs PHP ${next.php_version}.`; });
  const changeState = () => run("state", suspended ? "The website was not resumed." : "The website was not suspended.", () => setWebsiteState(site, suspended ? "active" : "suspended"),
    (next) => { onChanged(next); return next.state === "suspended" ? `${next.domain} is suspended. Visitors now get an error page.` : `${next.domain} is live again.`; });
  const reapplySuspension = () => run("resuspend", "The suspension was not applied again.", () => setWebsiteState(site, "suspended"),
    (next) => { onChanged(next); return `${next.domain} stays suspended. Its suspended web server settings were applied again.`; });
  const adoptFolder = () => run("folder", "The current public_html was not used.", () => adoptCurrentFolder(site),
    (next) => { onChanged(next); return `${next.domain} now uses the public_html that is in its hosting account.`; });
  const removeSite = (event: FormEvent) => {
    event.preventDefault();
    if (!matches) return;
    // The deleted view announces the outcome once the dialog is gone.
    void run("delete", "The website was not deleted.", () => deleteWebsite(site, typed), (done) => { onDeleted(done); return ""; });
  };
  // Closing the dialog after a failed delete reads the site again: part of
  // it may be gone. A delete in progress keeps the dialog open.
  const setDialog = (open: boolean) => {
    if (busy === "delete") return;
    setConfirming(open);
    if (open) { setTyped(""); setFailure(undefined); setOutcome(undefined); return; }
    if (failure?.action === "delete") { setFailure(undefined); onReload(); }
  };
  const failed = (action: ActionName) => failure?.action === action
    ? <ProblemAlert problem={failure.problem} testId="site-action-problem" retryLabel="Reload this website" onRetry={() => { setFailure(undefined); onReload(); }} />
    : null;
  const succeeded = (action: ActionName) => outcome?.action === action
    ? <div className="flex items-center gap-2 text-sm text-foreground" data-testid="site-action-outcome"><CircleCheck className="size-4 text-primary" aria-hidden="true" />{outcome.text}</div>
    : null;

  const sectionClass = `${panel} flex flex-col gap-5 p-5 md:p-6`;
  return <>
    {/* Part of the page from the start, so a named region rather than an alert that interrupts.
        Once the folder is used the notice and its button go; the outcome stays and takes focus. */}
    {canFolder && (folder || outcome?.action === "folder") && <section className={sectionClass} data-busy={busy ?? ""}>
      <div ref={folderRef} tabIndex={-1} className="flex flex-col gap-3 outline-none" data-testid="site-action-folder" data-kind={folder?.kind ?? "done"}>
        {folder && <>
          <Alert role="region" aria-labelledby={`${ids}-folder-title`} className="text-start" data-testid="site-folder-notice">
            <TriangleAlert aria-hidden="true" />
            <AlertTitle id={`${ids}-folder-title`}>{folder.what}</AlertTitle>
            <AlertDescription className="flex flex-col gap-1.5 text-start text-sm">
              <div className="text-foreground">{folder.why}</div>
              <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {folder.next}</div>
            </AlertDescription>
          </Alert>
          <div className="flex flex-col gap-2">
            <ActionButton variant="outline" className="w-fit" busy={busy === "folder"} busyLabel="Using the folder…" disabled={Boolean(busy)} aria-describedby={`${ids}-folder-hint`} onClick={adoptFolder} data-testid="use-current-folder">
              Use current public_html
            </ActionButton>
            <div className="text-sm text-muted-foreground" id={`${ids}-folder-hint`}>Records the public_html that is in the hosting account now as this site's folder, sets its permissions back and lets the web server read it.</div>
          </div>
        </>}
        {succeeded("folder")}
        {failed("folder")}
      </div>
    </section>}

    {canPhp && <section className={sectionClass} aria-labelledby={`${ids}-php-heading`} data-testid="site-actions" data-busy={busy ?? ""}>
      <div className="flex flex-col gap-3" data-testid="site-action-php">
        <div className="flex flex-col gap-1">
          <h2 id={`${ids}-php-heading`} tabIndex={-1} className="outline-none">PHP version</h2>
          <div className="text-sm text-muted-foreground" id={`${ids}-php-hint`}>
            {php.kind === "ready"
              ? `${site.php_version ? `The site runs PHP ${site.php_version}. ` : ""}Changing it restarts PHP for this site; its files, database and disk quota stay as they are.`
              : php.why}
          </div>
        </div>
        {php.kind === "ready" && <div className="flex flex-wrap items-end gap-2">
          <div className="flex flex-col gap-1.5">
            <label htmlFor={`${ids}-php`} className="text-sm font-medium text-foreground">Change to</label>
            <NativeSelect id={`${ids}-php`} className={`min-w-32 [&>select]:h-9 pointer-coarse:[&>select]:h-11`} aria-describedby={`${ids}-php-hint`} value={chosen} disabled={Boolean(busy)}
              onChange={(event) => setVersion(event.target.value)} data-testid="php-version-select">
              {php.versions.map((option) => <NativeSelectOption key={option} value={option}>PHP {option}</NativeSelectOption>)}
            </NativeSelect>
          </div>
          <ActionButton variant="outline" busy={busy === "php"} busyLabel="Changing PHP…" disabled={Boolean(busy)} onClick={changePhp} data-testid="change-php">Change PHP version</ActionButton>
        </div>}
        {succeeded("php")}
        {failed("php")}
      </div>
    </section>}

    {between}

    {(canState || canDelete) && <section className={sectionClass} aria-labelledby={`${ids}-manage-heading`} data-testid="site-manage" data-busy={busy ?? ""}>
      <h2 id={`${ids}-manage-heading`}>{canState && canDelete ? "Suspend or delete" : canState ? "Suspend" : "Delete"}</h2>
      {canState && <div className="flex flex-col gap-3" data-testid="site-action-state">
        <div className="flex flex-col gap-1">
          <h3 className="m-0 text-sm font-medium text-foreground">{suspended ? "Resume website" : "Suspend website"}</h3>
          <div className="text-sm text-muted-foreground">
            {suspended ? "The site serves visitors again, and the hosting account can sign in again."
              : canChangeState ? "Visitors get an error page (403) instead of the site, and the hosting account cannot sign in. Nothing is deleted, and you can resume it at any time."
              : partly ? "The hosting account is already deleted, so the website cannot be suspended or resumed."
              : "The hosting account needs a check by whoever runs this server before it can be suspended or resumed."}
          </div>
        </div>
        {canChangeState && <div className="flex flex-wrap gap-2">
          <ActionButton variant="outline" className="w-fit" busy={busy === "state"} busyLabel={suspended ? "Resuming…" : "Suspending…"} disabled={Boolean(busy)} onClick={changeState} data-testid="change-state">
            {suspended ? "Resume website" : "Suspend website"}
          </ActionButton>
          {suspended && repair && <ActionButton variant="ghost" className="w-fit" busy={busy === "resuspend"} busyLabel="Applying…" disabled={Boolean(busy)} aria-describedby={`${ids}-resuspend-hint`} onClick={reapplySuspension} data-testid="reapply-suspension">
            Apply suspension again
          </ActionButton>}
        </div>}
        {suspended && repair && <div className="text-sm text-muted-foreground" id={`${ids}-resuspend-hint`}>Apply suspension again writes the suspended site's web server settings again, for a site that still answers visitors. It stays suspended.</div>}
        {succeeded("state")}
        {failed("state")}
        {succeeded("resuspend")}
        {failed("resuspend")}
      </div>}

      {canState && canDelete && <Separator />}

      {canDelete && <div className="flex flex-col gap-3" data-testid="site-action-delete">
        <div className="flex flex-col gap-1">
          <h3 className="m-0 text-sm font-medium text-foreground">Delete website</h3>
          <div className="text-sm text-muted-foreground" data-testid="delete-website-hint">
            {partly ? "The hosting account and the site's files are already deleted, but the site's database is still on this server. Delete the website again to remove it. This cannot be undone."
              : "Removes the site's files, its database and its hosting account from this server. This cannot be undone."}
          </div>
        </div>
        <Button variant="destructive" className={`${control} w-fit`} disabled={Boolean(busy)} onClick={() => setDialog(true)} data-testid="delete-website">Delete website…</Button>
      </div>}

      <Dialog open={confirming} onOpenChange={setDialog}>
        <DialogContent className="sm:max-w-md" showCloseButton={false} initialFocus={confirmRef} data-testid="delete-website-dialog">
          <form className="contents" onSubmit={removeSite} noValidate>
            <DialogHeader>
              <DialogTitle className="wrap-anywhere leading-snug">Delete {site.domain}?</DialogTitle>
              <DialogDescription className="text-start">
                {partly ? "This removes what is left of the website: its database. It cannot be undone."
                  : <>This removes the website's files, its database and the hosting account <code>{site.username}</code> from this server. It cannot be undone.</>}
              </DialogDescription>
            </DialogHeader>
            <Field>
              <FieldLabel htmlFor={`${ids}-confirm`} className="flex-wrap gap-x-1">Type <span className="font-mono wrap-anywhere">{site.domain}</span> to confirm</FieldLabel>
              <Input id={`${ids}-confirm`} ref={confirmRef} className={control} type="text" inputMode="url" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={253}
                aria-describedby={`${ids}-confirm-hint`} value={typed} readOnly={busy === "delete"} onChange={(event) => setTyped(event.target.value.trim().toLowerCase())} data-testid="confirm-domain" />
              <FieldDescription id={`${ids}-confirm-hint`} className="text-start">The Delete website button works once the domain matches.</FieldDescription>
            </Field>
            {failure?.action === "delete" && <ProblemAlert problem={failure.problem} testId="site-action-problem" />}
            <DialogFooter>
              <DialogClose render={<Button type="button" variant="outline" className={control} />} disabled={busy === "delete"} data-testid="cancel-delete">Cancel</DialogClose>
              <ActionButton type="submit" variant="destructive" busy={busy === "delete"} busyLabel="Deleting…" disabled={!matches} data-testid="confirm-delete">Delete website</ActionButton>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </section>}
  </>;
}
