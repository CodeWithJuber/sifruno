import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { CircleAlert, CircleCheck, Clock, Plus, RefreshCw, Trash2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Skeleton } from "@/components/ui/skeleton";
import { TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { bytesLabel, commandProblem, cronPresets, diskUse, getCron, getLog, getUsage, maxJobs, monthLabel, normalizeSchedule, saveCron, scheduleLabel, scheduleProblem, serverClock, serverZone, SiteToolsApiError } from "@/lib/site-tools-api";
import type { CronJob, LogKind, WebsiteCron, WebsiteLog } from "@/lib/site-tools-api";
import type { Website, WebsiteUsage } from "@/lib/websites-api";
import { useShell } from "@/shell/context";

// A website's Usage, Scheduled jobs and Logs, below its Overview. Each
// section reads on its own, so one that fails leaves the others usable. The
// base styles colour <p> outside Tailwind's layers, so coloured text uses
// div or span, as on the other Websites screens.

const panel = "rounded-lg border border-border bg-card";
const control = "h-9 pointer-coarse:h-11";

interface Problem { what: string; why: string; next: string; technical: string }

function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof SiteToolsApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error" };
}

function ProblemAlert({ problem, onRetry, testId }: { problem: Problem; onRetry?: () => void; testId: string }) {
  return <Alert variant="destructive" className="text-start" data-testid={testId}>
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
      <div className="flex flex-col gap-1.5 text-sm">
        <div className="text-foreground">{problem.why}</div>
        <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {problem.next}</div>
      </div>
      <details className="text-sm">
        <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
        <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{problem.technical}</div>
      </details>
      {onRetry && <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}><RefreshCw aria-hidden="true" />Try again</Button>}
    </AlertDescription>
  </Alert>;
}

// One read, again on the shell's refresh and on Try again.
function useSectionRead<T>(load: (signal: AbortSignal) => Promise<T>, what: string, enabled = true) {
  const { revision } = useShell();
  const [data, setData] = useState<T>();
  const [problem, setProblem] = useState<Problem>();
  const [loading, setLoading] = useState(enabled);
  const [attempt, setAttempt] = useState(0);
  const loader = useRef(load);
  loader.current = load;
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    const controller = new AbortController();
    setLoading(true);
    loader.current(controller.signal).then(
      (value) => { if (live) { setData(value); setProblem(undefined); setLoading(false); } },
      (error) => { if (live) { setProblem(problemFrom(error, what)); setLoading(false); } },
    );
    return () => { live = false; controller.abort(); };
  }, [revision, attempt, what, enabled]);
  return { data, problem, loading, retry: () => setAttempt((value) => value + 1), replace: (value: T) => { setData(value); setProblem(undefined); } };
}

function SectionHeading({ id, title, children }: { id: string; title: string; children?: ReactNode }) {
  return <div className="flex flex-wrap items-center justify-between gap-2">
    <h3 id={id}>{title}</h3>
    {children}
  </div>;
}

export function SiteTools({ site, onRevision }: { site: Website; onRevision: (revision: number) => void }) {
  return <>
    <SiteUsageSection site={site} />
    <SiteCronSection site={site} onRevision={onRevision} />
    <SiteLogsSection site={site} />
  </>;
}

// ---- Usage --------------------------------------------------------------------

// Disk against the quota as a gauge, with the same words beside it.
export function DiskMeter({ usage, labelledBy }: { usage: WebsiteUsage; labelledBy?: string }) {
  const disk = diskUse(usage);
  if (disk.percent === undefined) return <span>{disk.used} <span className="text-muted-foreground">(no quota set)</span></span>;
  return <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
    <meter className="h-2 w-32" min={0} max={usage.disk_limit_bytes} low={usage.disk_limit_bytes * 0.8} high={usage.disk_limit_bytes * 0.9} optimum={0} value={usage.disk_used_bytes} aria-labelledby={labelledBy} />
    <span>{disk.used} of {disk.limit} <span className="text-muted-foreground">({disk.percent}%)</span>{disk.full && <span className="text-destructive"> Full: new files cannot be written.</span>}</span>
  </span>;
}

export function trafficText(usage: WebsiteUsage): string {
  return `${bytesLabel(usage.traffic_bytes)} in ${monthLabel(usage.traffic_month)}${usage.traffic_complete ? "" : " so far (older log lines are still being counted)"}`;
}

function SiteUsageSection({ site }: { site: Website }) {
  const ids = useId();
  const { data, problem, loading, retry } = useSectionRead((signal) => getUsage(site.account_id, { signal }), "The usage could not be loaded.");
  return <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby={`${ids}-heading`} data-testid="site-usage">
    <SectionHeading id={`${ids}-heading`} title="Usage">
      <Button variant="ghost" size="sm" onClick={retry} disabled={loading} data-testid="usage-refresh"><RefreshCw aria-hidden="true" />Refresh<span className="sr-only"> usage</span></Button>
    </SectionHeading>
    {problem && <ProblemAlert problem={problem} onRetry={retry} testId="usage-problem" />}
    {!data && loading && <div aria-busy="true"><span className="sr-only">Loading usage</span><Skeleton className="h-12 w-full" /></div>}
    {data && <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-3 text-sm">
      <dt className="text-muted-foreground" id={`${ids}-disk`}>Disk</dt>
      <dd className="text-foreground" data-testid="usage-disk"><DiskMeter usage={data} labelledBy={`${ids}-disk`} /></dd>
      <dt className="text-muted-foreground">Traffic</dt>
      <dd className="flex flex-col gap-1 text-foreground" data-testid="usage-traffic">
        <span>{trafficText(data)}</span>
        <span className="text-xs text-muted-foreground">What the site sent to visitors, counted from its access log. Headers are not counted.</span>
      </dd>
    </dl>}
  </section>;
}

// ---- Scheduled jobs -----------------------------------------------------------

const customPreset = "custom";

type FieldName = "schedule" | "command";

function SiteCronSection({ site, onRevision }: { site: Website; onRevision: (revision: number) => void }) {
  const ids = useId();
  const { data, problem, loading, retry, replace } = useSectionRead((signal) => getCron(site.account_id, { signal }), "The scheduled jobs could not be loaded.");
  const [preset, setPreset] = useState(cronPresets[0].id);
  const [schedule, setSchedule] = useState(cronPresets[0].schedule);
  const [command, setCommand] = useState("");
  // Field errors show once a field was changed and left, or after a submit.
  const [shown, setShown] = useState<Record<FieldName, boolean>>({ schedule: false, command: false });
  const [busy, setBusy] = useState<string>();
  const [failure, setFailure] = useState<Problem>();
  const [outcome, setOutcome] = useState("");
  const [announcement, setAnnouncement] = useState("");
  const edited = useRef<Record<FieldName, boolean>>({ schedule: false, command: false });
  const scheduleRef = useRef<HTMLInputElement>(null);
  const commandRef = useRef<HTMLInputElement>(null);
  const mounted = useRef(true);
  const announceTimer = useRef<number | undefined>(undefined);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; window.clearTimeout(announceTimer.current); }; }, []);
  const announce = useCallback((text: string, delayMs = 0) => {
    window.clearTimeout(announceTimer.current);
    setAnnouncement("");
    announceTimer.current = window.setTimeout(() => setAnnouncement(text), delayMs);
  }, []);

  const problems: Record<FieldName, string | undefined> = { schedule: scheduleProblem(schedule), command: commandProblem(command) };
  const revision = Math.max(site.revision, data?.revision ?? 0);
  const full = (data?.jobs.length ?? 0) >= maxJobs;

  const leave = (name: FieldName) => {
    if (!edited.current[name] || shown[name]) return;
    setShown((value) => ({ ...value, [name]: true }));
    const problem = problems[name];
    // A moment later, so it does not talk over the next field.
    if (problem) announce(`${name === "schedule" ? "Schedule" : "Command"}: ${problem}`, 500);
  };

  async function save(jobs: CronJob[], done: string, action: string) {
    if (busy || !data) return;
    setBusy(action); setFailure(undefined); setOutcome(""); announce("");
    try {
      const next = await saveCron(site.account_id, revision, jobs);
      if (!mounted.current) return;
      replace(next);
      onRevision(next.revision);
      setOutcome(done); announce(done);
      if (action === "add") {
        setCommand(""); edited.current = { schedule: false, command: false }; setShown({ schedule: false, command: false });
      }
    } catch (error) {
      if (mounted.current) setFailure(problemFrom(error, "The scheduled jobs were not saved."));
    } finally {
      if (mounted.current) setBusy(undefined);
    }
  }

  const add = (event: FormEvent) => {
    event.preventDefault();
    if (!data) return;
    setShown({ schedule: true, command: true });
    if (problems.schedule || problems.command) {
      // Focus reads the first field's error.
      (problems.schedule ? scheduleRef : commandRef).current?.focus();
      return;
    }
    const job = { schedule: normalizeSchedule(schedule), command };
    void save([...data.jobs.map((j) => ({ schedule: j.schedule, command: j.command })), job], `Job added. It runs ${scheduleLabel(job.schedule)?.toLowerCase() ?? `on the schedule ${job.schedule}`}.`, "add");
  };
  const remove = (index: number) => {
    if (!data) return;
    const jobs = data.jobs.filter((_, i) => i !== index).map((j) => ({ schedule: j.schedule, command: j.command }));
    void save(jobs, `Job ${index + 1} removed.`, `remove-${index}`);
  };

  const fieldProps = (name: FieldName) => {
    const invalid = shown[name] && Boolean(problems[name]);
    return {
      "aria-invalid": invalid,
      "aria-describedby": [`${ids}-${name}-hint`, invalid ? `${ids}-${name}-error` : ""].filter(Boolean).join(" "),
      onBlur: () => leave(name),
    };
  };
  const fieldError = (name: FieldName) => shown[name] && problems[name]
    ? <div id={`${ids}-${name}-error`} className="flex items-start gap-1.5 text-sm text-destructive" data-testid={`cron-${name}-error`}>
      <CircleAlert className="mt-0.5 size-4 shrink-0" role="img" aria-label="Error" />{problems[name]}
    </div>
    : null;

  const zone = data ? serverZone(data.server_time) : "";
  return <section className={`${panel} @container flex flex-col gap-4 p-5 md:p-6`} aria-labelledby={`${ids}-heading`} data-testid="site-cron" data-busy={busy ?? ""}>
    <SectionHeading id={`${ids}-heading`} title="Scheduled jobs" />
    <div className="text-sm text-muted-foreground">
      Commands that run on a schedule as the site's own user, <code>{site.username}</code>, in its home folder, within its resource limits. Root never runs them. Their output is not kept: to keep it, add <code>&gt;&gt; ~/cron.log 2&gt;&amp;1</code> to the command.
    </div>
    {site.state === "suspended" && <div className="flex items-center gap-2 text-sm text-foreground" data-testid="cron-suspended"><Clock className="size-4 text-muted-foreground" aria-hidden="true" />The site is suspended, so its jobs do not run until it is resumed.</div>}
    {problem && <ProblemAlert problem={problem} onRetry={retry} testId="cron-problem" />}
    {!data && loading && <div aria-busy="true"><span className="sr-only">Loading scheduled jobs</span><Skeleton className="h-16 w-full" /></div>}
    {data && <>
      {data.jobs.length === 0
        ? <div className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground" data-testid="cron-empty">No scheduled jobs yet.</div>
        : <CronTable cron={data} headingId={`${ids}-heading`} busy={busy} onRemove={remove} />}
      {data.jobs.length > 0 && <div className="text-xs text-muted-foreground">Times are on the server's clock ({zone}), which is the clock cron uses.</div>}
      {outcome && <div className="flex items-center gap-2 text-sm text-foreground" data-testid="cron-outcome"><CircleCheck className="size-4 text-primary" aria-hidden="true" />{outcome}</div>}
      {failure && <ProblemAlert problem={failure} onRetry={() => { setFailure(undefined); retry(); }} testId="cron-save-problem" />}
      <form className="flex flex-col gap-3 border-t border-border pt-4" onSubmit={add} noValidate aria-labelledby={`${ids}-add`} data-testid="cron-add-form">
        <h4 id={`${ids}-add`} className="m-0 text-sm font-medium text-foreground">Add a job</h4>
        {full
          ? <div className="text-sm text-muted-foreground" data-testid="cron-full">This site has {maxJobs} jobs, the most it can have. Remove one to add another.</div>
          : <>
            <div className="flex flex-col gap-1.5">
              <label htmlFor={`${ids}-preset`} className="text-sm font-medium text-foreground">When</label>
              <NativeSelect id={`${ids}-preset`} className="w-full max-w-sm [&>select]:h-9 pointer-coarse:[&>select]:h-11" value={preset} disabled={Boolean(busy)} data-testid="cron-preset"
                onChange={(event) => {
                  setPreset(event.target.value);
                  const chosen = cronPresets.find((p) => p.id === event.target.value);
                  if (chosen) { setSchedule(chosen.schedule); setShown((value) => ({ ...value, schedule: false })); }
                  else scheduleRef.current?.focus();
                }}>
                {cronPresets.map((p) => <NativeSelectOption key={p.id} value={p.id}>{p.label}</NativeSelectOption>)}
                <NativeSelectOption value={customPreset}>Custom schedule</NativeSelectOption>
              </NativeSelect>
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor={`${ids}-schedule`} className="text-sm font-medium text-foreground">Schedule</label>
              <div id={`${ids}-schedule-hint`} className="text-xs text-muted-foreground">Five fields: minute, hour, day of month, month, day of week (0 or 7 is Sunday). For example <code>30 2 * * 1-5</code> is 02:30 on weekdays.</div>
              <Input ref={scheduleRef} id={`${ids}-schedule`} className={`${control} max-w-sm font-mono`} dir="ltr" autoComplete="off" spellCheck={false} maxLength={100} value={schedule} disabled={Boolean(busy)} data-testid="cron-schedule"
                onChange={(event) => { edited.current.schedule = true; setSchedule(event.target.value); setPreset(cronPresets.find((p) => p.schedule === normalizeSchedule(event.target.value))?.id ?? customPreset); }}
                {...fieldProps("schedule")} />
              {fieldError("schedule")}
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor={`${ids}-command`} className="text-sm font-medium text-foreground">Command</label>
              <div id={`${ids}-command-hint`} className="text-xs text-muted-foreground">One line, run with /bin/sh. Without %, which cron turns into a new line: put such a command in a script and run the script.</div>
              <Input ref={commandRef} id={`${ids}-command`} className={`${control} font-mono`} dir="ltr" autoComplete="off" spellCheck={false} value={command} disabled={Boolean(busy)} placeholder="php ~/public_html/wp-cron.php" data-testid="cron-command"
                onChange={(event) => { edited.current.command = true; setCommand(event.target.value); }}
                {...fieldProps("command")} />
              {fieldError("command")}
            </div>
            <Button type="submit" className={`${control} w-fit`} disabled={Boolean(busy)} data-testid="cron-add">
              <Plus aria-hidden="true" />{busy === "add" ? "Adding…" : "Add job"}
            </Button>
          </>}
      </form>
    </>}
    <div aria-live="polite" className="sr-only" data-testid="cron-announcer">{announcement}</div>
  </section>;
}

// A table while there is room; in a narrow container each row becomes a
// card, its header row hidden and each cell named from data-label.
const stacked = "@max-[40rem]:block";
const stackedCell = `${stacked} @max-[40rem]:grid @max-[40rem]:grid-cols-[6rem_minmax(0,1fr)] @max-[40rem]:items-start @max-[40rem]:gap-x-3 @max-[40rem]:px-0 @max-[40rem]:py-1 @max-[40rem]:before:content-[attr(data-label)] @max-[40rem]:before:text-muted-foreground`;

function CronTable({ cron, headingId, busy, onRemove }: { cron: WebsiteCron; headingId: string; busy?: string; onRemove: (index: number) => void }) {
  return <div className="overflow-x-auto" role="region" aria-labelledby={headingId} tabIndex={0}>
    <table className={`w-full caption-bottom text-sm ${stacked}`} data-testid="cron-table">
      <caption className="sr-only">Scheduled jobs, in the order they were added</caption>
      <TableHeader className="@max-[40rem]:hidden">
        <TableRow className="hover:bg-transparent">
          <TableHead scope="col" className="text-start text-muted-foreground">Schedule</TableHead>
          <TableHead scope="col" className="text-start text-muted-foreground">Command</TableHead>
          <TableHead scope="col" className="text-start text-muted-foreground">Next run</TableHead>
          <TableHead scope="col" className="text-end text-muted-foreground"><span className="sr-only">Actions</span></TableHead>
        </TableRow>
      </TableHeader>
      <tbody className={`${stacked} @max-[40rem]:flex @max-[40rem]:flex-col @max-[40rem]:gap-3`}>
        {cron.jobs.map((job, index) => {
          const label = scheduleLabel(job.schedule);
          return <TableRow key={`${index}-${job.schedule}-${job.command}`} data-testid="cron-row" className={`${stacked} @max-[40rem]:rounded-lg @max-[40rem]:border @max-[40rem]:border-border @max-[40rem]:p-3 @max-[40rem]:hover:bg-transparent`}>
            <th scope="row" className={`p-2 text-start align-top font-normal ${stacked} @max-[40rem]:px-0 @max-[40rem]:pt-0 @max-[40rem]:pb-2`}>
              <span className="flex flex-col gap-0.5">
                <code dir="ltr" className="w-fit text-foreground" data-testid="cron-row-schedule">{job.schedule}</code>
                {label && <span className="text-xs text-muted-foreground">{label}</span>}
              </span>
            </th>
            <TableCell data-label="Command" className={`${stackedCell} align-top whitespace-normal`}>
              <code dir="ltr" className="block text-start wrap-anywhere text-foreground" data-testid="cron-row-command">{job.command}</code>
            </TableCell>
            <TableCell data-label="Next run" className={`${stackedCell} align-top`} data-testid="cron-row-next">{serverClock(job.next_run)}</TableCell>
            <TableCell className={`text-end align-top ${stacked} @max-[40rem]:px-0 @max-[40rem]:pt-2 @max-[40rem]:text-start`}>
              <Button variant="ghost" size="sm" className={control} disabled={Boolean(busy)} onClick={() => onRemove(index)} data-testid="cron-remove">
                <Trash2 aria-hidden="true" />{busy === `remove-${index}` ? "Removing…" : "Remove"}<span className="sr-only"> job {index + 1}, {job.schedule} {job.command}</span>
              </Button>
            </TableCell>
          </TableRow>;
        })}
      </tbody>
    </table>
  </div>;
}

// ---- Logs ---------------------------------------------------------------------

const logNames: Record<LogKind, string> = { access: "Access log", error: "Error log" };

function SiteLogsSection({ site }: { site: Website }) {
  const ids = useId();
  const [kind, setKind] = useState<LogKind>("access");
  return <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby={`${ids}-heading`} data-testid="site-logs">
    <SectionHeading id={`${ids}-heading`} title="Logs" />
    <div className="text-sm text-muted-foreground">The end of the web server's logs for this site, newest line last. They hold what visitors sent, shown as plain text.</div>
    <Tabs value={kind} onValueChange={(value) => setKind(value as LogKind)}>
      <TabsList>
        <TabsTrigger value="access" data-testid="log-tab-access">{logNames.access}</TabsTrigger>
        <TabsTrigger value="error" data-testid="log-tab-error">{logNames.error}</TabsTrigger>
      </TabsList>
      <TabsContent value="access"><LogView site={site} kind="access" active={kind === "access"} /></TabsContent>
      <TabsContent value="error"><LogView site={site} kind="error" active={kind === "error"} /></TabsContent>
    </Tabs>
  </section>;
}

function LogView({ site, kind, active }: { site: Website; kind: LogKind; active: boolean }) {
  const ids = useId();
  const [opened, setOpened] = useState(active);
  useEffect(() => { if (active) setOpened(true); }, [active]);
  const { data, problem, loading, retry } = useSectionRead<WebsiteLog>((signal) => getLog(site.account_id, kind, { signal }), "The log could not be loaded.", opened);
  const name = logNames[kind];
  return <div className="flex flex-col gap-3 pt-2" data-testid={`log-${kind}`}>
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="text-sm text-muted-foreground" id={`${ids}-summary`} data-testid="log-summary">
        {data ? (data.missing ? `There is no ${name.toLowerCase()} yet: the site has not had one written.`
          : data.lines.length === 0 ? `The ${name.toLowerCase()} is empty.`
          : `The last ${data.lines.length} ${data.lines.length === 1 ? "line" : "lines"}${data.truncated ? ` of a ${bytesLabel(data.size_bytes)} log` : ""}.`) : ""}
      </div>
      <Button variant="ghost" size="sm" onClick={retry} disabled={loading} data-testid={`log-refresh-${kind}`}><RefreshCw aria-hidden="true" />Refresh<span className="sr-only"> {name.toLowerCase()}</span></Button>
    </div>
    {problem && <ProblemAlert problem={problem} onRetry={retry} testId="log-problem" />}
    {!data && loading && <div aria-busy="true"><span className="sr-only">Loading the {name.toLowerCase()}</span><Skeleton className="h-40 w-full" /></div>}
    {data && data.lines.length > 0 && <div className="max-h-96 overflow-auto rounded-md border border-border bg-muted" role="region" aria-label={`${name}, last ${data.lines.length} lines`} tabIndex={0} data-testid="log-lines">
      {/* Text only: React escapes it, and nothing in a line is a link or markup. */}
      <pre dir="ltr" className="m-0 p-3 text-start font-mono text-xs leading-relaxed whitespace-pre-wrap wrap-anywhere text-foreground">{data.lines.join("\n")}</pre>
    </div>}
  </div>;
}
