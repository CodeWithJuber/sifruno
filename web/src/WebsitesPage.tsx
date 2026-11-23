import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { cn } from "cn";
import { ArrowLeft, CircleAlert, CircleCheck, CirclePause, ExternalLink, Globe, Lock, LockOpen, Plus, RefreshCw, TriangleAlert } from "lucide-react";
import { DnsHelp } from "@/components/dns-help";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { dateLabel } from "@/lib/api";
import { dayLabel, getWebsite, httpsState, listWebsites, siteStatus, WebsitesApiError } from "@/lib/websites-api";
import type { Website } from "@/lib/websites-api";
import { useShell } from "@/shell/context";
import type { PageId } from "@/shell/pages";

// Websites: the WordPress sites the New website wizard made, and one site's
// Overview. The base styles colour <p> and <a> outside Tailwind's layers, so
// coloured text uses div or span and links drawn as buttons mark their text
// colour important, as on the wizard's screens.

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
  return { data, problem, loading, retry: () => setAttempt((value) => value + 1) };
}

// ---- Shared parts -------------------------------------------------------------

function TechnicalDetails({ children }: { children: ReactNode }) {
  return <details className="text-sm">
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
    <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{children}</div>
  </details>;
}

// What happened (the title), why, what to do next, and the request under
// Technical details. role="alert": a failed read is announced at once.
function ProblemAlert({ problem, onRetry }: { problem: Problem; onRetry?: () => void }) {
  return <Alert variant="destructive" className="text-start" data-testid="websites-problem">
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
      <div className="flex flex-col gap-1.5 text-sm">
        <div className="text-foreground">{problem.why}</div>
        <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {problem.next}</div>
      </div>
      <TechnicalDetails>{problem.technical}</TechnicalDetails>
      {onRetry && <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}><RefreshCw aria-hidden="true" />Try again</Button>}
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
            <TableCell data-label="PHP" className={stackedCell} data-testid="website-php">{site.php_version || <span className="text-muted-foreground">Not recorded</span>}</TableCell>
            <TableCell data-label="WordPress" className={stackedCell} data-testid="website-wordpress">{site.wordpress_version}</TableCell>
            <TableCell className={`text-end ${stacked} @max-[62rem]:px-0 @max-[62rem]:pt-3 @max-[62rem]:text-start`}>
              <div className="inline-flex flex-nowrap gap-2 @max-[62rem]:flex @max-[62rem]:flex-wrap">
                <SiteLink href={site.url} label="Open site" domain={site.domain} variant="outline" testId="open-site" />
                <SiteLink href={site.admin_url} label="WordPress admin" domain={site.domain} variant="outline" testId="open-admin" />
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
  const { data: site, problem, loading, retry } = useRead("website", (signal) => getWebsite(accountId, { signal }), "This website could not be loaded.");
  const [dnsOpen, setDnsOpen] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const domain = site?.domain;
  // Arriving from the list: start at the site's name, and name the tab after it.
  useEffect(() => {
    if (!domain) return;
    headingRef.current?.focus();
    document.title = `${domain} · Websites · Sifruno`;
  }, [domain]);

  const back = <Link to="/websites" className={linkButton("ghost", "w-fit px-2")} data-testid="back-to-websites"><ArrowLeft className="rtl:rotate-180" aria-hidden="true" />All websites</Link>;
  if (!site) return <div className="flex w-full max-w-3xl flex-col gap-4">
    {back}
    {problem
      ? <ProblemAlert problem={problem} onRetry={problem.status === 404 ? undefined : retry} />
      : loading && <div className={`${panel} flex flex-col gap-4 p-5`} aria-busy="true"><span className="sr-only">Loading the website</span><Skeleton className="h-8 w-1/2" /><Skeleton className="h-40 w-full" /></div>}
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
          <dt className="text-muted-foreground">Status</dt><dd className="text-foreground">{siteStatus(site.state).label}</dd>
          <dt className="text-muted-foreground">HTTPS</dt>
          <dd className="text-foreground" data-testid="website-https-fact">
            {https.kind === "off" ? "Off: the site uses http. It has no certificate yet."
              : https.kind === "expired" ? `The certificate expired on ${dayLabel(https.since)}. Visitors see a security warning.`
              : https.until ? `On. The certificate is valid until ${dateLabel(site.https.not_after)}.` : "On."}
          </dd>
          <dt className="text-muted-foreground">PHP version</dt><dd className="text-foreground" data-testid="website-php">{site.php_version || "Not recorded for this site"}</dd>
          <dt className="text-muted-foreground">WordPress version</dt><dd className="text-foreground" data-testid="website-wordpress">{site.wordpress_version}</dd>
          <dt className="text-muted-foreground">Hosting account</dt><dd className="text-foreground" data-testid="website-username"><code>{site.username}</code></dd>
          <dt className="text-muted-foreground">Created</dt><dd className="text-foreground">{dateLabel(site.created_at)}</dd>
        </dl>
      </div>
      <div className="flex flex-wrap gap-2">
        <SiteLink href={site.url} label="Open site" domain={site.domain} variant="default" testId="open-site" />
        <SiteLink href={site.admin_url} label="WordPress admin" domain={site.domain} variant="outline" testId="open-admin" />
        <Button variant="outline" className={control} aria-expanded={dnsOpen} aria-controls="dns-help" onClick={() => setDnsOpen((value) => !value)} data-testid="set-up-dns">Set up DNS</Button>
      </div>
      <DnsHelp id="dns-help" domain={site.domain} hidden={!dnsOpen} />
    </section>
  </div>;
}
