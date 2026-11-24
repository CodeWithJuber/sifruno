import { useEffect, useId, useRef, useState } from "react";
import type { ComponentProps, FormEvent, ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { cn } from "cn";
import { ArrowLeft, CircleAlert, CircleCheck, CirclePause, ExternalLink, Globe, Lock, LockOpen, Plus, RefreshCw, TriangleAlert } from "lucide-react";
import { DnsHelp } from "@/components/dns-help";
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
import { dateLabel } from "@/lib/api";
import { changePhpVersion, dayLabel, deletedSummary, deleteWebsite, getWebsite, httpsState, listWebsites, phpChange, setWebsiteState, siteStatus, WebsitesApiError } from "@/lib/websites-api";
import type { Website, WebsiteDeleted, WebsiteDetail } from "@/lib/websites-api";
import { useShell } from "@/shell/context";
import type { PageId } from "@/shell/pages";
// The busy ring a working button shows, as on the wizard's screens.
import "./new-website.css";

// Websites: the WordPress sites the New website wizard made, and one site's
// Overview with its actions. The base styles colour <p> and <a> outside
// Tailwind's layers, so coloured text uses div or span and links drawn as
// buttons mark their text colour important, as on the wizard's screens.

const panel = "rounded-lg border border-border bg-card";
const control = "h-9 pointer-coarse:h-11";
const linkButton = (variant: "default" | "outline" | "ghost", className = "") =>
  cn(buttonVariants({ variant, className: `${control} ${variant === "default" ? "text-primary-foreground!" : ""} ${className}` }));

interface Problem { what: string; why: string; next: string; technical: string; status: number }

function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof WebsitesApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
}

// One read of the server, again on the header's refresh and on Try again.
// It reports to the shell, which drives the refresh button and the footer.
function useRead<T>(pageId: PageId, load: (signal: AbortSignal) => Promise<T>, what: string) {
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
    setPageResource(pageId, { data, loading, error: problem?.what, loadedAt });
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
function ProblemAlert({ problem, onRetry, retryLabel = "Try again", testId = "websites-problem" }: { problem: Problem; onRetry?: () => void; retryLabel?: string; testId?: string }) {
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
function StatusBadge({ state }: { state: string }) {
  const { label, tone } = siteStatus(state);
  const Icon = tone === "live" ? CircleCheck : tone === "suspended" ? CirclePause : TriangleAlert;
  return <Badge variant={tone === "live" ? "secondary" : tone === "suspended" ? "outline" : "destructive"} data-testid="website-status" data-state={state}>
    <Icon className={tone === "live" ? "text-primary" : ""} aria-hidden="true" />{label}
  </Badge>;
}

function HttpsBadge({ site }: { site: Website }) {
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

// External links name the site, so each is distinct for a screen reader, and
// say that they open a new tab.
function SiteLink({ href, label, domain, variant, testId }: { href: string; label: string; domain: string; variant: "default" | "outline" | "ghost"; testId: string }) {
  return <a href={href} target="_blank" rel="noopener noreferrer" className={linkButton(variant)} data-testid={testId}>
    {label}<span className="sr-only"> {domain} (opens in a new tab)</span><ExternalLink aria-hidden="true" />
  </a>;
}

// ---- Websites list ------------------------------------------------------------

export function WebsitesList() {
  const { data: sites, problem, loading, retry } = useRead("websites", (signal) => listWebsites({ signal }), "Your websites could not be loaded.");
  return <div className="flex w-full flex-col gap-4" data-testid="websites-page">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="text-sm text-muted-foreground" data-testid="websites-count">
        {sites?.length ? (sites.length === 1 ? "1 website" : `${sites.length} websites`) : ""}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Link to="/websites/static" className={linkButton("ghost")} data-testid="static-sites-link">Static sites (old)</Link>
        <Link to="/websites/new" className={linkButton("default")} data-testid="new-website-link"><Plus aria-hidden="true" />New website</Link>
      </div>
    </div>
    {problem && (sites
      ? <ProblemAlert problem={{ ...problem, next: `${problem.next} The list below is from the last successful read.` }} onRetry={retry} />
      : <ProblemAlert problem={problem} onRetry={retry} />)}
    {!sites && loading && <ListLoading />}
    {sites && sites.length === 0 && <NoWebsites />}
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

function NoWebsites() {
  return <Empty className={`${panel} border-dashed py-12`} data-testid="websites-empty">
    <EmptyHeader>
      <EmptyMedia variant="icon"><Globe aria-hidden="true" /></EmptyMedia>
      <EmptyTitle><h2 className="text-sm font-medium">No websites yet</h2></EmptyTitle>
      <EmptyDescription>Create a WordPress website. The panel sets up the hosting account, the database and WordPress, and the site is listed here.</EmptyDescription>
    </EmptyHeader>
    <EmptyContent>
      <Link to="/websites/new" className={linkButton("default")} data-testid="empty-new-website"><Plus aria-hidden="true" />New website</Link>
    </EmptyContent>
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
      <h2 id="websites-heading">WordPress websites</h2>
    </div>
    {/* Focusable so a keyboard can scroll it if the table is ever wider than the panel. */}
    <div className="overflow-x-auto px-2 pb-2 @max-[62rem]:px-4 @max-[62rem]:pb-4" role="region" aria-labelledby="websites-heading" tabIndex={0}>
      <table className={`w-full caption-bottom text-sm ${stacked}`} data-testid="websites-table">
        <caption className="sr-only">Your WordPress websites, newest first</caption>
        <TableHeader className="@max-[62rem]:hidden">
          <TableRow className="hover:bg-transparent">
            <TableHead scope="col" className="text-start text-muted-foreground">Website</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">Status</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">HTTPS</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">PHP</TableHead>
            <TableHead scope="col" className="text-start text-muted-foreground">WordPress</TableHead>
            <TableHead scope="col" className="text-end text-muted-foreground"><span className="sr-only">Actions</span></TableHead>
          </TableRow>
        </TableHeader>
        <tbody className={`${stacked} @max-[62rem]:flex @max-[62rem]:flex-col @max-[62rem]:gap-3`}>
          {sites.map((site) => <TableRow key={site.account_id} data-testid="website-row" data-domain={site.domain} data-account-id={site.account_id}
            className={`${stacked} @max-[62rem]:rounded-lg @max-[62rem]:border @max-[62rem]:border-border @max-[62rem]:p-3 @max-[62rem]:hover:bg-transparent`}>
            <th scope="row" className={`p-2 text-start align-middle font-medium text-foreground ${stacked} @max-[62rem]:px-0 @max-[62rem]:pt-0 @max-[62rem]:pb-2`}>
              <span className="wrap-anywhere">{site.domain}</span>
            </th>
            <TableCell data-label="Status" className={stackedCell}><StatusBadge state={site.state} /></TableCell>
            <TableCell data-label="HTTPS" className={`${stackedCell} whitespace-normal`}><HttpsBadge site={site} /></TableCell>
            <TableCell data-label="PHP" className={stackedCell} data-testid="website-php">{site.php_version || <span className="text-muted-foreground">Not reported</span>}</TableCell>
            <TableCell data-label="WordPress" className={stackedCell} data-testid="website-wordpress">{site.wordpress_version}</TableCell>
            <TableCell className={`text-end ${stacked} @max-[62rem]:px-0 @max-[62rem]:pt-3 @max-[62rem]:text-start`}>
              <div className="inline-flex flex-nowrap gap-2 @max-[62rem]:flex @max-[62rem]:flex-wrap">
                {site.state !== "partly_deleted" && <>
                  <SiteLink href={site.url} label="Open site" domain={site.domain} variant="outline" testId="open-site" />
                  <SiteLink href={site.admin_url} label="WordPress admin" domain={site.domain} variant="outline" testId="open-admin" />
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


// ---- One website's Overview ---------------------------------------------------

export function WebsiteOverview({ accountId }: { accountId: string }) {
  const { data: site, problem, loading, retry, replace } = useRead<WebsiteDetail>("website", (signal) => getWebsite(accountId, { signal }), "This website could not be loaded.");
  const [dnsOpen, setDnsOpen] = useState(false);
  const [deleted, setDeleted] = useState<WebsiteDeleted>();
  // One polite live region for the page: the outcome of each action.
  const [announcement, setAnnouncement] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);
  const deletedRef = useRef<HTMLHeadingElement>(null);
  const domain = site?.domain;
  // Arriving from the list: start at the site's name, and name the tab after it.
  useEffect(() => {
    if (!domain) return;
    headingRef.current?.focus();
    document.title = `${domain} · Websites · Sifruno`;
  }, [domain]);
  // After a delete the dialog is gone and the page is reachable again: say
  // what happened, and put focus on it instead of leaving it nowhere.
  useEffect(() => {
    if (!deleted) return;
    deletedRef.current?.focus();
    document.title = `${deleted.domain} deleted · Websites · Sifruno`;
    // Focus reads the heading; the region adds what went.
    setAnnouncement(deletedSummary(deleted) || `${deleted.domain} was deleted.`);
  }, [deleted]);

  const back = <Link to="/websites" className={linkButton("ghost", "w-fit px-2")} data-testid="back-to-websites"><ArrowLeft className="rtl:rotate-180" aria-hidden="true" />All websites</Link>;
  // Keyed, so the same region stays in the page from one view to the next.
  const announcer = <div key="announcer" aria-live="polite" className="sr-only" data-testid="website-announcer">{announcement}</div>;

  if (deleted) return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="website-deleted">
    {back}
    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`}>
      <div className="flex flex-col gap-2">
        <h2 ref={deletedRef} tabIndex={-1} className="wrap-anywhere outline-none">{deleted.domain} was deleted</h2>
        <div className="text-sm text-foreground" data-testid="website-deleted-summary">{deletedSummary(deleted)}</div>
      </div>
      <Link to="/websites" className={linkButton("default", "w-fit")}>Back to all websites</Link>
    </section>
    {announcer}
  </div>;

  if (!site) return <div className="flex w-full max-w-3xl flex-col gap-4">
    {back}
    {problem
      ? <ProblemAlert problem={problem} onRetry={problem.status === 404 ? undefined : retry} />
      : loading && <div className={`${panel} flex flex-col gap-4 p-5`} aria-busy="true"><span className="sr-only">Loading the website</span><Skeleton className="h-8 w-1/2" /><Skeleton className="h-40 w-full" /></div>}
    {announcer}
  </div>;

  const https = httpsState(site.https);
  return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="website-overview" data-account-id={site.account_id}>
    {back}
    {problem && <ProblemAlert problem={{ ...problem, next: `${problem.next} The details below are from the last successful read.` }} onRetry={retry} />}
    <section className={`${panel} flex flex-col gap-5 p-5 md:p-6`}>
      <div className="flex flex-col gap-2">
        <h2 id="website-heading" ref={headingRef} tabIndex={-1} className="wrap-anywhere outline-none" data-testid="website-domain">{site.domain}</h2>
        <div className="flex flex-wrap items-center gap-2"><StatusBadge state={site.state} /><HttpsBadge site={site} /></div>
      </div>
      <Separator />
      <div className="flex flex-col gap-3">
        <h3>Overview</h3>
        <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 text-sm" data-testid="website-facts">
          <dt className="text-muted-foreground">Domain</dt><dd className="wrap-anywhere text-foreground">{site.domain}</dd>
          <dt className="text-muted-foreground">Status</dt><dd className="text-foreground" data-testid="website-status-fact">{siteStatus(site.state).label}</dd>
          <dt className="text-muted-foreground">HTTPS</dt>
          <dd className="text-foreground" data-testid="website-https-fact">
            {https.kind === "off" ? "Off: the site uses http. It has no certificate yet."
              : https.kind === "expired" ? `The certificate expired on ${dayLabel(https.since)}. Visitors see a security warning.`
              : https.until ? `On. The certificate is valid until ${dateLabel(site.https.not_after)}.` : "On."}
          </dd>
          <dt className="text-muted-foreground">PHP version</dt><dd className="text-foreground" data-testid="website-php">{site.php_version || "Not reported for this site"}</dd>
          <dt className="text-muted-foreground">WordPress version</dt><dd className="text-foreground" data-testid="website-wordpress">{site.wordpress_version}</dd>
          <dt className="text-muted-foreground">Hosting account</dt><dd className="text-foreground" data-testid="website-username"><code>{site.username}</code></dd>
          <dt className="text-muted-foreground">Created</dt><dd className="text-foreground">{dateLabel(site.created_at)}</dd>
        </dl>
      </div>
      {/* A partly deleted site no longer serves and has no account for its databases page. */}
      {site.state !== "partly_deleted" && <>
        <div className="flex flex-wrap gap-2">
          <SiteLink href={site.url} label="Open site" domain={site.domain} variant="default" testId="open-site" />
          <SiteLink href={site.admin_url} label="WordPress admin" domain={site.domain} variant="outline" testId="open-admin" />
          <Button variant="outline" className={control} aria-expanded={dnsOpen} aria-controls="dns-help" onClick={() => setDnsOpen((value) => !value)} data-testid="set-up-dns">Set up DNS</Button>
          <Link to="/websites/sites/$accountId/databases" params={{ accountId: site.account_id }} className={linkButton("outline")} data-testid="website-databases-link">Databases</Link>
        </div>
        <DnsHelp id="dns-help" domain={site.domain} hidden={!dnsOpen} />
      </>}
    </section>
    <SiteActions site={site} onChanged={replace} onDeleted={setDeleted} onReload={retry} announce={setAnnouncement} />
    {announcer}
  </div>;
}

// ---- The site's actions -------------------------------------------------------

type ActionName = "php" | "state" | "delete";

// A button that says it is working and cannot be pressed twice. It stays
// focusable while busy, so focus is not lost.
function ActionButton({ busy, busyLabel, children, className = "", disabled, ...props }: ComponentProps<typeof Button> & { busy: boolean; busyLabel: string }) {
  return <Button {...props} className={`${control} aria-disabled:opacity-70 ${className}`} disabled={busy || disabled} focusableWhenDisabled={busy}>
    {busy && <progress className="wizard-spinner" aria-hidden="true" />}
    {busy ? busyLabel : children}
  </Button>;
}

// Three changes, one at a time: each sends the revision the page has, and the
// server's answer becomes the page's newest read. The outcome is said in the
// page's polite live region; a failure is an alert where the person is.
function SiteActions({ site, onChanged, onDeleted, onReload, announce }: {
  site: WebsiteDetail; onChanged: (site: WebsiteDetail) => void; onDeleted: (done: WebsiteDeleted) => void; onReload: () => void; announce: (text: string) => void;
}) {
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

  return <section className={`${panel} flex flex-col gap-5 p-5 md:p-6`} data-testid="site-actions" data-busy={busy ?? ""}>
    <h3>Actions</h3>

    <div className="flex flex-col gap-3" data-testid="site-action-php">
      <div className="flex flex-col gap-1">
        <h4 className="m-0 text-sm font-medium text-foreground">PHP version</h4>
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

    <Separator />

    <div className="flex flex-col gap-3" data-testid="site-action-state">
      <div className="flex flex-col gap-1">
        <h4 className="m-0 text-sm font-medium text-foreground">{suspended ? "Resume website" : "Suspend website"}</h4>
        <div className="text-sm text-muted-foreground">
          {suspended ? "The site serves visitors again, and the hosting account can sign in again."
            : canChangeState ? "Visitors get an error page (403) instead of the site, and the hosting account cannot sign in. Nothing is deleted, and you can resume it at any time."
            : partly ? "The hosting account is already deleted, so the website cannot be suspended or resumed."
            : "The hosting account needs a check by whoever runs this server before it can be suspended or resumed."}
        </div>
      </div>
      {canChangeState && <ActionButton variant="outline" className="w-fit" busy={busy === "state"} busyLabel={suspended ? "Resuming…" : "Suspending…"} disabled={Boolean(busy)} onClick={changeState} data-testid="change-state">
        {suspended ? "Resume website" : "Suspend website"}
      </ActionButton>}
      {succeeded("state")}
      {failed("state")}
    </div>

    <Separator />

    <div className="flex flex-col gap-3" data-testid="site-action-delete">
      <div className="flex flex-col gap-1">
        <h4 className="m-0 text-sm font-medium text-foreground">Delete website</h4>
        <div className="text-sm text-muted-foreground" data-testid="delete-website-hint">
          {partly ? "The hosting account and the site's files are already deleted, but the site's database is still on this server. Delete the website again to remove it. This cannot be undone."
            : "Removes the site's files, its database and its hosting account from this server. This cannot be undone."}
        </div>
      </div>
      <Button variant="destructive" className={`${control} w-fit`} disabled={Boolean(busy)} onClick={() => setDialog(true)} data-testid="delete-website">Delete website…</Button>
    </div>

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
  </section>;
}
