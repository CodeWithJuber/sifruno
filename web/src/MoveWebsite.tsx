import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { cn } from "cn";
import { ArrowRight, CircleAlert, CircleCheck, CircleX, Copy, RefreshCw, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { dateLabel } from "@/lib/api";
import { acceptMigration, cancelSource, checkAcceptReason, checkSourceHost, checkSourcePort, clearStaleKey, confirmFingerprint, getMigrationJob, listSourceAccounts, listStaleKeys, openSource, readyMigration, startMigration, verifyMigration } from "@/lib/migration-api";
import type { MigrationSource, SourceAccount, StaleKey } from "@/lib/migration-api";
import { hostsLine } from "@/lib/migration-record";
import type { MigrationRecord } from "@/lib/migration-record";
import { jobProgress, validJobId } from "@/lib/wordpress-api";
import type { WebsiteJob } from "@/lib/wordpress-api";
import { Explanation, problemFrom, StepList, TechnicalDetails } from "@/NewWebsite";
import type { Problem } from "@/NewWebsite";
import { useShell } from "@/shell/context";
import "./new-website.css";

// "Move a website here": connect to the old cPanel server with a key made
// for this move, confirm its fingerprint, pick the account, follow the copy,
// then compare and cut over. Nothing here holds a password of the old
// server: the admin adds the key line there themselves.

const panel = "rounded-lg border border-border bg-card p-5 md:p-6";
const control = "h-10 pointer-coarse:h-12";
const linkButton = (variant: "default" | "outline") =>
  cn(buttonVariants({ variant, className: variant === "default" ? `${control} text-primary-foreground!` : control }));

function ProblemBox({ problem, onRetry }: { problem: Problem; onRetry?: () => void }) {
  return <Alert className="text-start" data-testid="move-problem">
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="text-start text-foreground">
      <Explanation problem={problem} />
      <TechnicalDetails className="mt-3">{problem.technical}</TechnicalDetails>
      {onRetry && <Button variant="outline" size="sm" className="mt-3" onClick={onRetry}><RefreshCw aria-hidden="true" />Try again</Button>}
    </AlertDescription>
  </Alert>;
}

// A command or line to copy, with a button whose result is announced in a
// status bubble beside it (never inside the button, whose children are not
// announced). Copying again is allowed at any time.
function CopyBlock({ id, label, value }: { id: string; label: string; value: string }) {
  const [message, setMessage] = useState("");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    window.clearTimeout(timer.current);
    setMessage("");
    let ok = true;
    try { await navigator.clipboard.writeText(value); } catch { ok = false; }
    requestAnimationFrame(() => setMessage(ok ? "Copied" : "Copy failed: select the text and copy it yourself"));
    timer.current = window.setTimeout(() => setMessage(""), 2500);
  };
  return <div className="flex flex-col gap-2">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span id={`${id}-label`} className="text-sm font-medium">{label}</span>
      <span className="flex items-center gap-2">
        <span role="status" className="text-xs text-muted-foreground">{message}</span>
        <Button type="button" variant="outline" size="sm" onClick={() => void copy()} aria-describedby={`${id}-label`} data-testid={`${id}-copy`}><Copy aria-hidden="true" />Copy</Button>
      </span>
    </div>
    <pre id={id} tabIndex={0} aria-labelledby={`${id}-label`} className="overflow-x-auto rounded-md border border-border bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">{value}</pre>
  </div>;
}

// Key lines the panel could not prove removed from an old server: each
// says which line to remove and where, until the admin says it is done.
function StaleKeys() {
  const [keys, setKeys] = useState<StaleKey[]>([]);
  const [problem, setProblem] = useState<Problem>();
  const [busy, setBusy] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    listStaleKeys({ signal: controller.signal }).then(setKeys, (error: unknown) => {
      if (!controller.signal.aborted) setProblem(problemFrom(error, "The key lines left on old servers could not be listed."));
    });
    return () => controller.abort();
  }, []);
  const cleared = (id: string) => {
    setBusy(id); setProblem(undefined);
    clearStaleKey(id).then(() => setKeys((list) => list.filter((k) => k.id !== id)), (error: unknown) => setProblem(problemFrom(error, "The key line was not taken off the list."))).finally(() => setBusy(""));
  };
  if (!keys.length && !problem) return null;
  return <Alert className="text-start" data-testid="move-stale-keys">
    <CircleAlert aria-hidden="true" />
    <AlertTitle>Remove {keys.length === 1 ? "a migration key line" : `${keys.length} migration key lines`} from old servers</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
      <p>Sifruno could not confirm that these old servers removed the key it used. On each server, delete the line from <code>/root/.ssh/authorized_keys</code>, then mark it done here.</p>
      {problem && <Explanation problem={problem} />}
      <ul role="list" className="flex flex-col gap-2">{keys.map((k) => <li key={k.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-3" data-testid={`stale-${k.id}`}>
        <span className="min-w-0 break-all text-sm"><span className="font-medium">{k.host}</span> (SSH port {k.port}): the line ending in <code>{k.line}</code>
          <span className="block text-xs text-muted-foreground">Since {dateLabel(k.since)}. {k.detail}</span></span>
        <Button size="sm" variant="outline" disabled={busy === k.id} onClick={() => cleared(k.id)}>I removed it</Button>
      </li>)}</ul>
    </AlertDescription>
  </Alert>;
}

// ---- Connect, confirm, choose -------------------------------------------------

type Stage = "connect" | "confirm" | "choose";

export function MoveWebsite() {
  const navigate = useNavigate();
  const [stage, setStage] = useState<Stage>("connect");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [touched, setTouched] = useState(false);
  const [source, setSource] = useState<MigrationSource>();
  const [fingerprint, setFingerprint] = useState("");
  const [accounts, setAccounts] = useState<SourceAccount[]>();
  const [busy, setBusy] = useState("");
  const [problem, setProblem] = useState<Problem>();
  const [ended, setEnded] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => { headingRef.current?.focus(); }, [stage]);

  const hostProblem = checkSourceHost(host), portProblem = checkSourcePort(port);
  const run = async (what: string, work: () => Promise<void>) => {
    setBusy(what); setProblem(undefined);
    try { await work(); } catch (error) { setProblem(problemFrom(error, what)); } finally { setBusy(""); }
  };

  const connect = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (hostProblem || portProblem) return;
    void run("Sifruno could not connect to the old server.", async () => {
      const opened = await openSource(host, Number(port));
      setSource(opened); setFingerprint(""); setStage("confirm");
    });
  };
  const confirm = (event: FormEvent) => {
    event.preventDefault();
    if (!source || !fingerprint) return;
    void run("The fingerprint was not confirmed.", async () => {
      const pinned = await confirmFingerprint(source.id, fingerprint);
      setSource(pinned);
      setAccounts(await listSourceAccounts(pinned.id));
      setStage("choose");
    });
  };
  const reload = () => { if (source) void run("The old server's accounts could not be listed.", async () => setAccounts(await listSourceAccounts(source.id))); };
  const move = (user: string) => {
    if (!source) return;
    void run("The move was not started.", async () => {
      const job = await startMigration(source.id, user);
      void navigate({ to: "/websites/move/$jobId", params: { jobId: job.id } });
    });
  };
  const cancel = () => {
    if (!source) return;
    void run("The migration key was not removed.", async () => {
      const result = await cancelSource(source.id);
      setEnded(result.removed_from_source ? "Stopped. The old server no longer accepts the migration key, and this server deleted it." : `Stopped. This server deleted the migration key. ${result.detail}`);
      setSource(undefined); setAccounts(undefined); setStage("connect");
    });
  };

  const heading = (children: ReactNode) => <h2 ref={headingRef} tabIndex={-1} className="outline-none">{children}</h2>;

  return <div className="flex w-full max-w-3xl flex-col gap-5" data-testid="move-website" data-stage={stage}>
    <StaleKeys />
    {ended && <Alert role="status" className="text-start"><CircleCheck aria-hidden="true" /><AlertTitle>{ended}</AlertTitle></Alert>}
    {stage === "connect" && <section className={`${panel} flex flex-col gap-5`}>
      <div className="flex flex-col gap-1">
        {heading("Connect to the old server")}
        <p className="text-sm">Move one website account from a cPanel server you run as root. Its email and DNS stay where they are; the old site keeps running until you change DNS.</p>
      </div>
      <form noValidate onSubmit={connect} className="flex flex-col gap-4">
        <FieldGroup>
          <Field data-invalid={touched && Boolean(hostProblem)}>
            <FieldLabel htmlFor="move-host">Old server</FieldLabel>
            <Input id="move-host" className={control} value={host} onChange={(e) => setHost(e.target.value.trim())} autoComplete="off" spellCheck={false} inputMode="url" aria-invalid={touched && Boolean(hostProblem)} aria-describedby="move-host-help move-host-error" data-testid="move-host" />
            <FieldDescription id="move-host-help">Its host name or IPv4 address, such as server1.example.com.</FieldDescription>
            {touched && hostProblem && <FieldError id="move-host-error">{hostProblem}</FieldError>}
          </Field>
          <Field data-invalid={touched && Boolean(portProblem)} className="max-w-40">
            <FieldLabel htmlFor="move-port">SSH port</FieldLabel>
            <Input id="move-port" className={control} value={port} onChange={(e) => setPort(e.target.value.trim())} inputMode="numeric" autoComplete="off" aria-invalid={touched && Boolean(portProblem)} aria-describedby="move-port-error" data-testid="move-port" />
            {touched && portProblem && <FieldError id="move-port-error">{portProblem}</FieldError>}
          </Field>
        </FieldGroup>
        {problem && <ProblemBox problem={problem} />}
        <div><Button type="submit" className={control} disabled={Boolean(busy)} data-testid="move-connect">{busy ? "Connecting…" : "Connect"}</Button></div>
      </form>
    </section>}

    {stage === "confirm" && source && <section className={`${panel} flex flex-col gap-5`} data-testid="move-confirm">
      <div className="flex flex-col gap-1">
        {heading(<>Let Sifruno in to {source.host}</>)}
        <p className="text-sm">Sifruno made a key for this move only. It signs in as root to read and copy the account, and is removed from both servers when the move ends. It expires {dateLabel(source.expires_at)}.</p>
      </div>
      <CopyBlock id="move-install" label="1. Run this as root on the old server" value={source.install_command} />
      <form onSubmit={confirm} className="flex flex-col gap-4">
        <RadioGroup value={fingerprint} onValueChange={(value) => setFingerprint(String(value))} aria-labelledby="move-fp-legend" aria-describedby="move-fp-help">
          <div id="move-fp-legend" className="text-sm font-medium">2. Confirm the old server's fingerprint</div>
          <p id="move-fp-help" className="text-sm text-muted-foreground">On the old server, run <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> (or the file of the same type below). Choose the line whose fingerprint is exactly the same. If none matches, stop: something else answered at this address.</p>
          {source.host_keys.map((key) => <FieldLabel key={key.fingerprint} htmlFor={`fp-${key.type}`}>
            <Field orientation="horizontal">
              <RadioGroupItem value={key.fingerprint} id={`fp-${key.type}`} data-testid={`move-fp-${key.type}`} />
              <FieldContent>
                <FieldTitle>{key.type}</FieldTitle>
                <FieldDescription className="font-mono text-xs break-all text-start">{key.fingerprint}</FieldDescription>
              </FieldContent>
            </Field>
          </FieldLabel>)}
        </RadioGroup>
        {problem && <ProblemBox problem={problem} />}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" className={control} disabled={!fingerprint || Boolean(busy)} data-testid="move-confirm-fp"><ShieldCheck aria-hidden="true" />{busy ? "Checking…" : "The fingerprint matches"}</Button>
          <Button type="button" variant="outline" className={control} onClick={cancel} disabled={Boolean(busy)}>Stop and remove the key</Button>
        </div>
      </form>
    </section>}

    {stage === "choose" && source && <section className={`${panel} flex flex-col gap-5`} data-testid="move-choose">
      <div className="flex flex-col gap-1">
        {heading(<>Choose the website to move from {source.host}</>)}
        <p className="text-sm">The account keeps its name and its folder <code>/home/&lt;name&gt;/public_html</code>, and its databases keep their names, users and passwords.</p>
      </div>
      {problem && <ProblemBox problem={problem} onRetry={reload} />}
      {accounts && accounts.length === 0 && <p className="text-sm">The old server has no accounts.</p>}
      {accounts && accounts.length > 0 && <Table data-testid="move-accounts">
        <TableHeader><TableRow><TableHead>Account</TableHead><TableHead>Main domain</TableHead><TableHead className="text-end">Disk</TableHead><TableHead><span className="sr-only">Action</span></TableHead></TableRow></TableHeader>
        <TableBody>{accounts.map((a) => <TableRow key={a.user} data-user={a.user}>
          <TableCell><code>{a.user}</code></TableCell>
          <TableCell className="break-all">{a.domain}{a.problem && <div className="mt-1 text-xs whitespace-normal text-muted-foreground">{a.problem}</div>}</TableCell>
          <TableCell className="text-end">{a.disk_used_mib} MiB</TableCell>
          <TableCell className="text-end">{!a.problem && <Button size="sm" onClick={() => move(a.user)} disabled={Boolean(busy)} aria-label={`Move ${a.domain}`} data-testid={`move-start-${a.user}`}>Move</Button>}</TableCell>
        </TableRow>)}</TableBody>
      </Table>}
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" className={control} onClick={reload} disabled={Boolean(busy)}><RefreshCw aria-hidden="true" />List again</Button>
        <Button type="button" variant="outline" className={control} onClick={cancel} disabled={Boolean(busy)}>Stop and remove the key</Button>
      </div>
    </section>}
    <div role="status" className="sr-only">{busy}</div>
  </div>;
}

// ---- The move's progress, comparison and cutover --------------------------------

const gateText: Record<MigrationRecord["gate"], { title: string; tone: "default" | "secondary" | "destructive" | "outline" }> = {
  closed: { title: "Cutover locked", tone: "destructive" },
  open: { title: "Cutover allowed", tone: "default" },
  accepted: { title: "Cutover allowed with accepted red lines", tone: "secondary" },
  ready: { title: "Ready: point DNS here", tone: "default" },
};

function Comparison({ job, onChanged }: { job: WebsiteJob; onChanged: (job: WebsiteJob) => void }) {
  const m = job.migration!;
  const v = m.verify;
  const [reason, setReason] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState("");
  const [problem, setProblem] = useState<Problem>();
  const reasonProblem = checkAcceptReason(reason);
  const act = (what: string, work: () => Promise<WebsiteJob>) => {
    setBusy(what); setProblem(undefined);
    work().then(onChanged, (error: unknown) => setProblem(problemFrom(error, what))).finally(() => setBusy(""));
  };
  const accept = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (!reasonProblem) act("The red lines were not accepted.", () => acceptMigration(job.id, reason));
  };
  const gate = gateText[m.gate];
  return <section className="flex flex-col gap-4" aria-labelledby="move-compare" data-testid="move-comparison" data-gate={m.gate}>
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 id="move-compare">Compare with the old site</h3>
      <Badge variant={gate.tone} data-testid="move-gate">{gate.title}</Badge>
    </div>
    <p className="text-sm">The copy runs on this server under its own domain; visitors still reach the old server. To look at it yourself, add this line to your computer's hosts file, open the site, then remove the line.</p>
    <CopyBlock id="move-hosts" label="Hosts file line" value={hostsLine(m.address, job.domain)} />
    {v?.running && <p role="status" className="text-sm" data-testid="move-verify-running">Comparing the copy with the old site…</p>}
    {v && !v.running && <div className="flex flex-col gap-2" data-testid="move-verify">
      <div className="text-sm font-medium" data-testid="move-verdict">{v.verdict}</div>
      {v.ran && <div className="text-sm text-muted-foreground">Pages: {v.pages_compared} compared, {v.pages_pass} the same, {v.pages_warn} to check, {v.pages_fail} different. Closed URLs (passwords, deny rules, address lists): {v.probes_pass} as the old site, {v.probes_fail} not.</div>}
      {v.problems.length > 0 && <ul className="list-disc ps-5 text-sm" data-testid="move-verify-problems">{v.problems.map((problem) => <li key={problem}>{problem}</li>)}</ul>}
      {v.lines.length > 0 && <TechnicalDetails>{v.lines.join("\n")}</TechnicalDetails>}
    </div>}
    {m.notes.length > 0 && <div className="flex flex-col gap-1" data-testid="move-notes">
      <div className="text-sm font-medium">To check before cutover</div>
      <ul className="list-disc ps-5 text-sm">{m.notes.map((note) => <li key={note}>{note}</li>)}</ul>
    </div>}
    {m.tables.length > 0 && <TechnicalDetails>{m.tables.map((t) => `${t.database}.${t.table}: ${t.source} rows on the old server, ${t.copy} in the copy`).join("\n")}</TechnicalDetails>}
    {problem && <ProblemBox problem={problem} />}
    {m.gate !== "ready" && <div className="flex flex-wrap gap-2">
      <Button variant="outline" className={control} disabled={Boolean(busy) || v?.running} onClick={() => act("The comparison was not started.", () => verifyMigration(job.id))} data-testid="move-verify-again"><RefreshCw aria-hidden="true" />Compare again</Button>
      {(m.gate === "open" || m.gate === "accepted") && <Button className={control} disabled={Boolean(busy)} onClick={() => act("The website was not marked ready.", () => readyMigration(job.id))} data-testid="move-ready">Mark ready for cutover</Button>}
    </div>}
    {m.gate === "closed" && v?.ran && !v.running && <form onSubmit={accept} className="flex flex-col gap-3 rounded-md border border-border p-4" data-testid="move-accept">
      <Field data-invalid={touched && Boolean(reasonProblem)}>
        <FieldLabel htmlFor="move-reason">Accept the red lines on purpose</FieldLabel>
        <FieldDescription id="move-reason-help">If you checked each line and the copy is right anyway, say why. The reason and your name go into the activity log.</FieldDescription>
        <textarea id="move-reason" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} aria-invalid={touched && Boolean(reasonProblem)} aria-describedby="move-reason-help move-reason-error"
          className="w-full rounded-lg border border-input bg-transparent px-2.5 py-2 text-base outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 aria-invalid:border-destructive md:text-sm dark:bg-input/30" data-testid="move-reason" />
        {touched && reasonProblem && <FieldError id="move-reason-error">{reasonProblem}</FieldError>}
      </Field>
      <div><Button type="submit" variant="outline" className={control} disabled={Boolean(busy)} data-testid="move-accept-submit">Accept and open the gate</Button></div>
    </form>}
    {m.gate === "ready" && <div className="flex flex-col gap-2" data-testid="move-dns">
      <div className="text-sm font-medium">Change these DNS records where the domain's DNS is kept</div>
      <Table>
        <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Points to</TableHead></TableRow></TableHeader>
        <TableBody>{m.dns.map((r) => <TableRow key={r.name}><TableCell className="break-all">{r.name}</TableCell><TableCell>{r.type}</TableCell><TableCell><code>{r.value}</code></TableCell></TableRow>)}</TableBody>
      </Table>
      <p className="text-sm text-muted-foreground">Leave the MX and other mail records as they are: email stays on the old server. Keep the old server running for 14 days, so you can switch back.</p>
    </div>}
    <div role="status" className="sr-only">{busy}</div>
  </section>;
}

function Activity({ m }: { m: MigrationRecord }) {
  return <details className="text-sm" data-testid="move-activity">
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Activity log ({m.activity.length})</summary>
    <ol role="list" className="mt-2 flex flex-col gap-1.5">{m.activity.map((a, i) => <li key={`${a.at}-${i}`} className="flex flex-col">
      <span className="text-xs text-muted-foreground">{dateLabel(a.at)} · {a.actor}</span><span>{a.what}</span>
    </li>)}</ol>
  </details>;
}

export function MoveJob({ jobId }: { jobId: string }) {
  const { revision } = useShell();
  const badId = !validJobId(jobId);
  const [job, setJob] = useState<WebsiteJob>();
  const [problem, setProblem] = useState<Problem>();
  const [attempt, setAttempt] = useState(0);
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Poll while the copy or a comparison runs.
  useEffect(() => {
    if (badId) return;
    let live = true;
    let timer: number | undefined;
    const controller = new AbortController();
    const poll = async () => {
      try {
        const next = await getMigrationJob(jobId, { signal: controller.signal });
        if (!live) return;
        setJob(next); setProblem(undefined);
        if (next.state === "running" || next.migration?.verify?.running) timer = window.setTimeout(() => void poll(), 2000);
      } catch (error) {
        if (!live) return;
        const found = problemFrom(error, "The move's progress could not be loaded.");
        setProblem(found);
        if (found.status === 0 || found.status >= 500) timer = window.setTimeout(() => void poll(), 5000);
      }
    };
    void poll();
    return () => { live = false; window.clearTimeout(timer); controller.abort(); };
  }, [badId, jobId, revision, attempt]);
  const view = job ? job.state : "other";
  useEffect(() => { headingRef.current?.focus(); }, [view]);

  if (badId) return <ProblemBox problem={{ what: "This move was not found.", why: "The address does not point to a move.", next: "Start again from Move a website here.", technical: "job id is not 32 lowercase hex characters", status: 404 }} />;
  if (!job) return problem ? <ProblemBox problem={problem} onRetry={() => setAttempt((n) => n + 1)} /> : <div role="status" aria-label="Loading the move"><Skeleton className="h-52 w-full max-w-3xl" /></div>;

  const m = job.migration!;
  const { done, total } = jobProgress(job);
  const heading = (children: ReactNode) => <h2 ref={headingRef} tabIndex={-1} className="break-words outline-none">{children}</h2>;
  const name = job.domain || m.source_user;
  return <section className={`${panel} flex w-full max-w-3xl flex-col gap-5`} data-testid="move-job" data-state={job.state}>
    <div className="flex items-start gap-3">
      {job.state === "succeeded" ? <CircleCheck className="mt-0.5 size-6 shrink-0 text-primary" aria-hidden="true" /> : job.state === "failed" ? <CircleX className="mt-0.5 size-6 shrink-0 text-destructive" aria-hidden="true" /> : null}
      <div className="flex min-w-0 flex-col gap-1">
        {heading(job.state === "running" ? <>Moving {name} from {m.source_host}</> : job.state === "succeeded" ? <>{name} is copied to this server</> : job.error?.what || "The website was not moved.")}
        {job.state === "running" && <p className="text-sm">This can take a while for a large site. You can leave this page: the move keeps running on the server.</p>}
        {job.state === "failed" && job.error && <Explanation problem={job.error} />}
      </div>
    </div>
    {problem && <ProblemBox problem={problem} onRetry={() => setAttempt((n) => n + 1)} />}
    {job.state === "running" && <div>
      <div className="mb-1.5 flex items-baseline justify-between gap-3">
        <label htmlFor="move-progress" className="text-sm font-medium">Progress</label>
        <span id="move-progress-count" className="text-sm text-muted-foreground">{done} of {total} steps done</span>
      </div>
      <progress id="move-progress" className="wizard-progress" max={total} value={done} aria-describedby="move-progress-count" />
    </div>}
    {job.state === "succeeded" && <Comparison job={job} onChanged={setJob} />}
    <StepList steps={job.steps} ended={job.state !== "running"} />
    {job.state === "failed" && job.error && <TechnicalDetails>{[job.error.step && `Step: ${job.error.step}`, `Job: ${job.id}`, job.error.technical].filter(Boolean).join("\n")}</TechnicalDetails>}
    <Activity m={m} />
    <Separator />
    <div className="flex flex-wrap gap-2">
      {job.state === "succeeded" && job.result?.account_id && <Link to="/websites/sites/$accountId" params={{ accountId: job.result.account_id }} className={linkButton("outline")}>Open the website's page<ArrowRight className="rtl:rotate-180" aria-hidden="true" /></Link>}
      {job.state === "failed" && <Link to="/websites/move" className={linkButton("default")}>Move a website here</Link>}
    </div>
  </section>;
}
