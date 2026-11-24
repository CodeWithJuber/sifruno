import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { cn } from "cn";
import { ArchiveRestore, ArrowLeft, CircleAlert, DatabaseBackup, HardDrive, LoaderCircle, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { checkConfirmDomain, formatBytes, formatWhen, getSiteBackups, pollIntervalMs, restoreEffect, runningLine, scheduleLine, shouldPoll, startBackup, startDrill, startRestore, whatLabel } from "@/lib/site-backups-api";
import type { RestoreWhat, SiteBackups as Backups, Snapshot } from "@/lib/site-backups-api";
import { control, DrillSummary, panel, ProblemAlert, problemFrom, ResultAlert, TechnicalDetails } from "@/BackupParts";
import type { Problem } from "@/BackupParts";
import { useShell } from "@/shell/context";

// One website's Backups page: back up now, the backups with their time and
// size, a restore of files, database or both behind a typed confirmation,
// and the last restore drill. A job runs on the server; the page asks again
// every 5 seconds while one runs. Backup ids appear only under Technical
// details.

const rowControl = "h-9 pointer-coarse:h-11";
const linkButton = (variant: "default" | "outline" | "ghost", className = "") =>
  cn(buttonVariants({ variant, className: `${rowControl} ${variant === "default" ? "text-primary-foreground!" : ""} ${className}` }));

const whats: RestoreWhat[] = ["files", "database", "both"];

function RestoreForm({ accountId, data, snapshot, onStarted, onCancel, onBusy }: { accountId: string; data: Backups; snapshot: Snapshot; onStarted: () => void; onCancel: () => void; onBusy: (busy: boolean) => void }) {
  const hasDatabase = snapshot.databases.length > 0;
  const [what, setWhat] = useState<RestoreWhat>(hasDatabase ? "both" : "files");
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusyState] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const setBusy = (value: boolean) => { setBusyState(value); onBusy(value); };
  const matches = typed === data.domain;

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    const mismatch = checkConfirmDomain(data.domain, typed);
    if (mismatch) { setError(mismatch); document.getElementById("restore-confirm")?.focus(); return; }
    setBusy(true);
    setProblem(undefined);
    try {
      await startRestore(accountId, data, snapshot, what, typed);
      onBusy(false);
      onStarted();
    } catch (failure) {
      setProblem(problemFrom(failure, "The restore did not start."));
      setBusy(false);
    }
  };

  return <form method="post" onSubmit={(event) => void submit(event)} className="grid gap-4" data-testid="restore-form">
    <DialogHeader>
      <DialogTitle render={<h1 />} className="leading-snug">Restore {data.domain}</DialogTitle>
      <DialogDescription className="text-start">From the backup of {formatWhen(snapshot.time, data.timezone)}, {formatBytes(snapshot.bytes)}.</DialogDescription>
    </DialogHeader>
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-1 text-sm font-medium">What to restore</legend>
      {whats.map((value) => {
        const disabled = value !== "files" && !hasDatabase;
        return <label key={value} className={`flex items-center gap-2 text-sm ${disabled ? "text-muted-foreground" : ""}`}>
          <input type="radio" name="restore-what" value={value} className="size-4 accent-primary" checked={what === value} disabled={disabled || busy} onChange={() => setWhat(value)} data-testid={`restore-what-${value}`} />
          <span>{whatLabel[value]}{disabled ? " (this backup holds no database)" : ""}</span>
        </label>;
      })}
    </fieldset>
    <Alert role={undefined} variant="destructive" className="text-start" data-testid="restore-effect">
      <CircleAlert aria-hidden="true" />
      <AlertTitle>This changes the live site</AlertTitle>
      <AlertDescription className="text-start text-foreground">{restoreEffect(what)}</AlertDescription>
    </Alert>
    <Field data-invalid={error ? true : undefined}>
      <FieldLabel htmlFor="restore-confirm">Type the site's domain to confirm</FieldLabel>
      <FieldDescription id="restore-confirm-hint" className="text-start">Type <code className="wrap-anywhere text-foreground">{data.domain}</code> exactly.</FieldDescription>
      <Input id="restore-confirm" name="confirm_domain" className={`${control} font-mono`} type="text" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} required
        aria-invalid={error ? true : undefined} aria-describedby={["restore-confirm-hint", error ? "restore-confirm-error" : ""].filter(Boolean).join(" ")}
        value={typed} onChange={(e) => { setTyped(e.target.value); if (error) setError(checkConfirmDomain(data.domain, e.target.value)); }}
        onBlur={() => { if (typed) setError(checkConfirmDomain(data.domain, typed)); }} data-testid="restore-confirm" />
      {error && <div id="restore-confirm-error" className="flex items-start gap-1.5 text-sm text-destructive"><CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" /><span><span className="sr-only">Error: </span>{error}</span></div>}
    </Field>
    {problem && <ProblemAlert problem={problem} testId="restore-problem" />}
    <TechnicalDetails>{`backup id: ${snapshot.id}\nfiles: ${snapshot.files}\ndatabases: ${snapshot.databases.join(", ") || "none"}`}</TechnicalDetails>
    <DialogFooter>
      <Button type="button" variant="outline" className={rowControl} disabled={busy} onClick={onCancel} autoFocus data-testid="cancel-restore">Cancel</Button>
      <Button type="submit" variant="destructive" className={`${rowControl} aria-disabled:opacity-60`} disabled={!matches || busy} focusableWhenDisabled aria-describedby="restore-confirm-hint" data-testid="confirm-restore">
        <ArchiveRestore aria-hidden="true" />{busy ? "Starting the restore…" : `Restore ${whatLabel[what].toLowerCase()}`}
      </Button>
    </DialogFooter>
  </form>;
}

function SnapshotTable({ data, onRestore, disabled }: { data: Backups; onRestore: (snapshot: Snapshot) => void; disabled: boolean }) {
  return <Table aria-labelledby="backups-list-heading" data-testid="snapshots-table">
    <TableHeader>
      <TableRow>
        <TableHead scope="col">When</TableHead>
        <TableHead scope="col" className="hidden sm:table-cell">Size</TableHead>
        <TableHead scope="col" className="hidden md:table-cell">Databases</TableHead>
        <TableHead scope="col"><span className="sr-only">Restore</span></TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      {data.snapshots.map((snapshot, index) => {
        const when = formatWhen(snapshot.time, data.timezone);
        const databases = snapshot.databases.length ? snapshot.databases.map((db, i) => <span key={db}>{i > 0 && ", "}<code className="wrap-anywhere">{db}</code></span>) : <span className="text-muted-foreground">No database</span>;
        // On a narrow screen the size and databases move under the time, so
        // the Restore button stays in view without scrolling sideways.
        return <TableRow key={snapshot.id} data-testid="snapshot-row">
          <TableCell className="whitespace-normal">
            <div>{when}{index === 0 && <span className="ms-2 text-xs text-muted-foreground">(newest)</span>}</div>
            <div className="mt-1 text-xs text-muted-foreground md:hidden"><span className="sm:hidden">{formatBytes(snapshot.bytes)} · </span>{databases}</div>
          </TableCell>
          <TableCell className="hidden sm:table-cell">{formatBytes(snapshot.bytes)}</TableCell>
          <TableCell className="hidden whitespace-normal md:table-cell">{databases}</TableCell>
          <TableCell className="text-end">
            <Button variant="outline" className={`${rowControl} aria-disabled:opacity-60`} disabled={disabled} focusableWhenDisabled onClick={() => onRestore(snapshot)} data-testid="restore-snapshot">
              <ArchiveRestore aria-hidden="true" />Restore<span className="sr-only"> from the backup of {when}</span>
            </Button>
          </TableCell>
        </TableRow>;
      })}
    </TableBody>
  </Table>;
}

export function SiteBackups({ accountId }: { accountId: string }) {
  const { revision, setPageResource } = useShell();
  const [data, setData] = useState<Backups>();
  const [problem, setProblem] = useState<Problem>();
  const [actionProblem, setActionProblem] = useState<Problem>();
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [starting, setStarting] = useState<"backup" | "drill">();
  const [restoreFrom, setRestoreFrom] = useState<Snapshot>();
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [restoreRound, setRestoreRound] = useState(0);
  const [spoken, setSpoken] = useState("");
  const restoring = useRef(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);
  const wasRunning = useRef(false);

  useEffect(() => {
    let live = true;
    const controller = new AbortController();
    setLoading(true);
    getSiteBackups(accountId, { signal: controller.signal }).then(
      (value) => { if (live) { setData(value); setProblem(undefined); setLoadedAt(new Date()); setLoading(false); } },
      (error: unknown) => { if (live) { setProblem(problemFrom(error, "The backups could not be loaded.")); setLoading(false); } },
    );
    return () => { live = false; controller.abort(); };
  }, [accountId, revision, attempt]);
  useEffect(() => {
    setPageResource("site-backups", { data, loading, error: problem?.what, loadedAt });
  }, [data, loading, problem, loadedAt, setPageResource]);
  const reload = () => setAttempt((value) => value + 1);

  // While a job runs, read again every 5 seconds; say when it has ended.
  useEffect(() => {
    if (!shouldPoll(data)) {
      if (wasRunning.current && data) setSpoken("The job has finished. Its result is shown below.");
      wasRunning.current = false;
      return;
    }
    wasRunning.current = true;
    const timer = window.setTimeout(reload, pollIntervalMs);
    return () => window.clearTimeout(timer);
  }, [data]);

  const domain = data?.domain;
  useEffect(() => {
    if (!domain) return;
    headingRef.current?.focus();
    document.title = `Backups · ${domain} · Sifruno`;
  }, [domain]);

  const back = <Link to="/websites/sites/$accountId" params={{ accountId }} className={linkButton("ghost", "w-fit px-2")} data-testid="back-to-website">
    <ArrowLeft className="rtl:rotate-180" aria-hidden="true" />{domain ? <>Back to {domain}</> : "Back to the website"}
  </Link>;

  if (!data) return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="site-backups">
    {back}
    {problem
      ? <ProblemAlert problem={problem} onRetry={problem.status === 404 ? undefined : reload} testId="backups-problem" />
      : loading && <div className={`${panel} flex flex-col gap-4 p-5`} aria-busy="true"><span className="sr-only">Loading the backups</span><Skeleton className="h-8 w-1/2" /><Skeleton className="h-40 w-full" /></div>}
  </div>;

  const running = data.running;
  const busy = Boolean(running) || Boolean(starting);
  const start = async (kind: "backup" | "drill") => {
    if (busy) return;
    setStarting(kind);
    setActionProblem(undefined);
    try {
      await (kind === "backup" ? startBackup : startDrill)(accountId);
      setSpoken(kind === "backup" ? "The backup has started." : "The restore drill has started.");
      reload();
      window.requestAnimationFrame(() => statusRef.current?.focus());
    } catch (error) {
      setActionProblem(problemFrom(error, kind === "backup" ? "The backup did not start." : "The restore drill did not start."));
    } finally {
      setStarting(undefined);
    }
  };

  return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="site-backups" data-account-id={accountId}>
    {back}
    {problem && <ProblemAlert problem={{ ...problem, next: `${problem.next} What is shown below is from the last successful read.` }} onRetry={reload} testId="backups-problem" />}
    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="backups-heading">
      <div className="flex flex-col gap-1">
        <h2 id="backups-heading" ref={headingRef} tabIndex={-1} className="wrap-anywhere outline-none">Backups for {data.domain}</h2>
        <p className="text-sm">The site's files and databases, kept on the backup storage server. {data.configured ? scheduleLine(data.nightly_at, data.timezone) : ""}</p>
      </div>
      {!data.configured
        ? <Empty className="border border-dashed border-border py-8" data-testid="backups-not-configured">
          <EmptyHeader>
            <EmptyMedia variant="icon"><HardDrive aria-hidden="true" /></EmptyMedia>
            <EmptyTitle>Backup storage is not set up</EmptyTitle>
            <EmptyDescription>No website on this server is backed up yet, because the panel does not know where to keep the backups. Set up the storage server first.</EmptyDescription>
          </EmptyHeader>
          <Link to="/server/backups" className={linkButton("default")} data-testid="go-backup-storage">Set up backup storage</Link>
        </Empty>
        : <>
          {!data.ready && <Alert variant="destructive" className="text-start">
            <CircleAlert aria-hidden="true" />
            <AlertTitle>Backups cannot run on this server right now</AlertTitle>
            <AlertDescription className="text-start text-foreground">restic is missing or is not the version the panel was built for. Run the installer again, then reload this page.</AlertDescription>
          </Alert>}
          <div className="flex flex-wrap gap-2">
            <Button className={`${control} aria-disabled:opacity-60`} disabled={busy} focusableWhenDisabled onClick={() => void start("backup")} data-testid="back-up-now">
              {starting === "backup" ? <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" /> : <DatabaseBackup aria-hidden="true" />}Back up now
            </Button>
            <Button variant="outline" className={`${control} aria-disabled:opacity-60`} disabled={busy || data.snapshots.length === 0} focusableWhenDisabled onClick={() => void start("drill")} data-testid="drill-now">
              {starting === "drill" ? <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" /> : <ShieldCheck aria-hidden="true" />}Run restore drill now
            </Button>
          </div>
          {actionProblem && <ProblemAlert problem={actionProblem} testId="backup-action-problem" />}
          <div ref={statusRef} tabIndex={-1} className="outline-none" data-testid="backup-status">
            {running && <Alert role={undefined} className="text-start" data-testid="backup-running" data-kind={running.kind}>
              <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" />
              <AlertTitle>{runningLine(running, data.timezone)}</AlertTitle>
              <AlertDescription className="text-start text-muted-foreground">This page checks again every 5 seconds. You can leave it; the job keeps running on the server.</AlertDescription>
            </Alert>}
          </div>
          {data.last_restore && <ResultAlert result={data.last_restore} timezone={data.timezone} testId="last-restore" />}
          {data.last_backup && <ResultAlert result={data.last_backup} timezone={data.timezone} testId="last-backup" />}
          <DrillSummary drill={data.last_drill} timezone={data.timezone} />
        </>}
    </section>

    {data.configured && <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="backups-list-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 id="backups-list-heading">Backups</h3>
        <span className="text-sm text-muted-foreground" data-testid="snapshots-count">{data.snapshots.length === 1 ? "1 backup" : `${data.snapshots.length} backups`}</span>
      </div>
      {data.snapshots_error
        ? <Alert variant="destructive" className="text-start" data-testid="snapshots-error">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>The backups could not be listed</AlertTitle>
          <AlertDescription className="text-start text-foreground">{data.snapshots_error}</AlertDescription>
        </Alert>
        : data.snapshots.length === 0
          ? <Empty className="border border-dashed border-border py-8" data-testid="snapshots-empty">
            <EmptyHeader>
              <EmptyMedia variant="icon"><DatabaseBackup aria-hidden="true" /></EmptyMedia>
              <EmptyTitle>No backups yet</EmptyTitle>
              <EmptyDescription>The first backup runs tonight at {data.nightly_at}. To make one now, choose Back up now.</EmptyDescription>
            </EmptyHeader>
          </Empty>
          : <SnapshotTable data={data} disabled={busy} onRestore={(snapshot) => { setRestoreFrom(snapshot); setRestoreRound((value) => value + 1); setRestoreOpen(true); }} />}
      <div className="text-sm text-muted-foreground">Kept: the last 7 daily and 4 weekly backups. Older ones are removed each week.</div>
    </section>}

    <Dialog open={restoreOpen} onOpenChange={(open) => { if (!open && !restoring.current) setRestoreOpen(false); }}>
      <DialogContent showCloseButton={false} className="sm:max-w-lg" data-testid="restore-dialog">
        {restoreFrom && <RestoreForm key={restoreRound} accountId={accountId} data={data} snapshot={restoreFrom} onBusy={(value) => { restoring.current = value; }}
          onCancel={() => setRestoreOpen(false)}
          onStarted={() => { setRestoreOpen(false); setSpoken("The restore has started."); reload(); window.requestAnimationFrame(() => statusRef.current?.focus()); }} />}
      </DialogContent>
    </Dialog>
    <div aria-live="polite" className="sr-only" data-testid="backups-announcer">{spoken}</div>
  </div>;
}
