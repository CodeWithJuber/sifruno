import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { cn } from "cn";
import { ArrowLeft, Circle, CircleAlert, CircleCheck, CircleMinus, CircleX, ExternalLink, Eye, EyeOff, Info, RefreshCw, Undo2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field, FieldDescription, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { dateLabel } from "@/lib/api";
import { createWordPressSite, defaultPhpVersion, fieldChecks, getWebsiteJob, httpReason, jobProgress, phpVersions, usesHttps, validJobId, WordPressApiError } from "@/lib/wordpress-api";
import type { JobStep, StepState, WebsiteJob, WordPressField, WordPressInput } from "@/lib/wordpress-api";
import { useShell } from "@/shell/context";
import "./new-website.css";

// The "New website" wizard: a form, then the setup progress at its own URL
// (so a reload keeps it), then the result. The admin password lives only in
// the form's state until the request is sent; it is never written to storage,
// the URL or router state.

const panel = "rounded-lg border border-border bg-card p-5 md:p-6";
const control = "h-10 pointer-coarse:h-12";
// Links drawn as buttons. cn() merges the variant's classes the way the Button
// component does (otherwise border-transparent can win over the outline
// border). The base styles give every link `color: inherit` outside
// Tailwind's layers, so a primary link marks its text colour important.
const linkButton = (variant: "default" | "outline" | "ghost") =>
  cn(buttonVariants({ variant, className: variant === "default" ? `${control} text-primary-foreground!` : control }));

interface Problem { what: string; why: string; next: string; technical: string; status: number }

function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof WordPressApiError) return { what: error.message, why: error.detail, next: error.next, technical: error.technical, status: error.status };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
}

// The app's base styles reset margins and colour on h1-h3, p, dl and dd
// outside Tailwind's layers, so spacing here comes from gaps on parents and
// coloured text uses div.

function TechnicalDetails({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <details className={`text-sm ${className}`}>
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
    <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{children}</div>
  </details>;
}

function Explanation({ problem }: { problem: Pick<Problem, "why" | "next"> }) {
  return <div className="flex flex-col gap-1.5 text-sm">
    {problem.why && <div className="text-foreground">{problem.why}</div>}
    {/* next can list things the setup could not remove, one per line. */}
    {problem.next && <div className="whitespace-pre-line text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {problem.next}</div>}
  </div>;
}

// ---- What the form keeps between the form and the job page -------------------

type Draft = Omit<WordPressInput, "admin_password">;
const draftKey = "sifruno-new-website-draft";
const emptyDraft: Draft = { domain: "", title: "", admin_user: "", admin_email: "", php_version: defaultPhpVersion };

// Set by "Back to the form" on a failed setup, read once by the form. Never
// holds the password.
let retryDraft: Draft | undefined;

function validDraft(value: unknown): value is Draft {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (["domain", "title", "admin_user", "admin_email", "php_version"] as const).every((key) => typeof record[key] === "string" && (record[key] as string).length <= 1000);
}

// The non-secret fields are kept for this tab only, so "Back to the form"
// still works after a reload of the progress page.
function saveDraft(jobId: string, draft: Draft) {
  const { domain, title, admin_user, admin_email, php_version } = draft;
  try { sessionStorage.setItem(draftKey, JSON.stringify({ jobId, domain, title, admin_user, admin_email, php_version })); }
  catch { /* Optional: private windows can refuse storage; the form then keeps only the domain. */ }
}
function loadDraft(jobId: string): Draft | undefined {
  try {
    const value: unknown = JSON.parse(sessionStorage.getItem(draftKey) ?? "null");
    if (!validDraft(value) || (value as { jobId?: unknown }).jobId !== jobId) return undefined;
    const { domain, title, admin_user, admin_email, php_version } = value;
    return { domain, title, admin_user, admin_email, php_version };
  } catch { return undefined; /* Unreadable or refused storage: start from the job's domain. */ }
}
function forgetDraft() {
  try { sessionStorage.removeItem(draftKey); }
  catch { /* Nothing was stored if storage is refused. */ }
}

// ---- Form -------------------------------------------------------------------

const labels: Record<WordPressField, string> = {
  domain: "Domain", title: "Site title", php_version: "PHP version",
  admin_user: "Username", admin_email: "Email address", admin_password: "Password",
};
const fieldId = (name: WordPressField) => `nw-${name.replace("_", "-")}`;
type Control = HTMLInputElement | HTMLSelectElement;

// Field feedback follows the browser's :user-invalid: nothing is marked until
// the person has changed a field and left it, or tried to submit. aria-invalid
// and the error link in aria-describedby follow the same state, and an error
// that appears on leaving a field is read once through one polite live region.
function useUserValidity(values: WordPressInput) {
  const controls = useRef<Partial<Record<WordPressField, Control | null>>>({});
  // Used where :user-invalid is missing, and after a submit attempt.
  const edited = useRef(new Set<WordPressField>());
  const interacted = useRef(new Set<WordPressField>());
  const announced = useRef(new Set<WordPressField>());
  const announcedField = useRef<WordPressField | undefined>(undefined);
  const timer = useRef<number | undefined>(undefined);
  const [errors, setErrors] = useState<Partial<Record<WordPressField, string>>>({});
  const [announcement, setAnnouncement] = useState("");

  const userInvalid = (name: WordPressField, el: Control) => {
    let native = false;
    try { native = el.matches(":user-invalid"); } catch { native = false; /* Older browser: rely on the interaction flags below. */ }
    return native || (interacted.current.has(name) && !el.validity.valid);
  };

  const sync = useCallback((name: WordPressField, mode: "quiet" | "leave" | "submit") => {
    const el = controls.current[name];
    if (!el) return;
    if (mode === "submit") interacted.current.add(name);
    const invalid = mode === "submit" || userInvalid(name, el);
    const message = invalid ? (el.validationMessage || fieldChecks[name](el.value) || "Check this value.") : "";
    setErrors((current) => (current[name] ?? "") === message ? current : { ...current, [name]: message || undefined });
    if (invalid) {
      // After a submit the browser moves focus to the first invalid field,
      // which reads its error, so those are not announced again.
      if (mode === "submit") announced.current.add(name);
      if (mode === "leave" && !announced.current.has(name)) {
        announced.current.add(name);
        window.clearTimeout(timer.current);
        setAnnouncement("");
        announcedField.current = name;
        // Wait until the next field has been read out.
        timer.current = window.setTimeout(() => setAnnouncement(`${labels[name]}: Error: ${message}`), 500);
      }
    } else {
      announced.current.delete(name);
      if (announcedField.current === name) { window.clearTimeout(timer.current); setAnnouncement(""); announcedField.current = undefined; }
    }
  }, []);

  // The contract's rules become the fields' custom validity, so the browser's
  // own validation (and :user-invalid) applies them.
  useLayoutEffect(() => {
    for (const name of Object.keys(fieldChecks) as WordPressField[]) {
      const el = controls.current[name];
      if (el) el.setCustomValidity(fieldChecks[name](values[name]) ?? "");
    }
    for (const name of Object.keys(fieldChecks) as WordPressField[]) sync(name, "quiet");
  }, [values, sync]);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const bind = (name: WordPressField) => ({
    id: fieldId(name),
    name,
    ref: (el: Control | null) => { controls.current[name] = el; },
    onBlur: () => { if (edited.current.has(name)) interacted.current.add(name); sync(name, "leave"); },
    onInvalid: () => sync(name, "submit"),
    "aria-invalid": errors[name] ? ("true" as const) : ("false" as const),
    "aria-describedby": [`${fieldId(name)}-hint`, errors[name] ? `${fieldId(name)}-error` : ""].filter(Boolean).join(" "),
  });
  const markEdited = (name: WordPressField) => edited.current.add(name);
  return { errors, announcement, bind, markEdited };
}

function FieldProblem({ name, message }: { name: WordPressField; message?: string }) {
  if (!message) return null;
  return <div id={`${fieldId(name)}-error`} className="flex items-start gap-1.5 text-sm text-destructive">
    <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
    <span><span className="sr-only">Error: </span>{message}</span>
  </div>;
}

function Hint({ name, children }: { name: WordPressField; children: ReactNode }) {
  return <FieldDescription id={`${fieldId(name)}-hint`} className="text-start">{children}</FieldDescription>;
}

export function NewWebsite() {
  const navigate = useNavigate();
  // Read without side effects here (StrictMode calls initialisers twice);
  // the handoff is cleared in the effect below.
  const [restored] = useState(() => Boolean(retryDraft));
  const [values, setValues] = useState<WordPressInput>(() => ({ ...emptyDraft, ...retryDraft, admin_password: "" }));
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const { errors, announcement, bind, markEdited } = useUserValidity(values);

  useEffect(() => { retryDraft = undefined; }, []);
  // The view changed (from the menu, or back from a failed setup): start at its heading.
  useEffect(() => { headingRef.current?.focus(); }, []);

  const change = (name: WordPressField, value: string) => {
    markEdited(name);
    setValues((current) => ({ ...current, [name]: value }));
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setProblem(undefined);
    const input = { ...values };
    try {
      const job = await createWordPressSite(input);
      // saveDraft copies the five non-secret fields only.
      saveDraft(job.id, input);
      setValues((current) => ({ ...current, admin_password: "" }));
      await navigate({ to: "/websites/jobs/$jobId", params: { jobId: job.id } });
    } catch (error) {
      setProblem(problemFrom(error, "The website was not created."));
      setBusy(false);
    }
  };

  return <div className="flex w-full max-w-2xl flex-col gap-4" data-testid="new-website">
    {restored && <Alert role={undefined} className="text-start">
      <Info aria-hidden="true" />
      <AlertTitle>Your entries are back, except the password</AlertTitle>
      <AlertDescription className="text-start">Enter the password again, fix what the setup reported, then press Create website.</AlertDescription>
    </Alert>}
    <section className={panel}>
      <div className="flex flex-col gap-1">
        <h2 id="nw-form-heading" ref={headingRef} tabIndex={-1} className="outline-none">Website details</h2>
        <p className="text-sm">The panel creates the hosting account, the database and WordPress for you. All fields are required.</p>
      </div>
      <form method="post" onSubmit={(event) => void submit(event)} className="mt-6" data-testid="new-website-form">
        <FieldGroup className="gap-6">
          <FieldSet>
            <FieldLegend>Website</FieldLegend>
            <dl className="flex flex-col gap-1.5">
              <dt className="text-sm font-medium">Website type</dt>
              <dd className="text-sm text-foreground" data-testid="website-type">WordPress</dd>
            </dl>
            <Field data-invalid={errors.domain ? true : undefined}>
              <FieldLabel htmlFor={fieldId("domain")}>{labels.domain}</FieldLabel>
              <Hint name="domain">For example example.com. Lowercase, without http:// or a slash.</Hint>
              <Input {...bind("domain")} className={`${control} user-invalid:border-destructive`} type="text" inputMode="url" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={253} required
                value={values.domain} onChange={(e) => change("domain", e.target.value.trim().toLowerCase())} />
              <FieldProblem name="domain" message={errors.domain} />
            </Field>
            <Field data-invalid={errors.title ? true : undefined}>
              <FieldLabel htmlFor={fieldId("title")}>{labels.title}</FieldLabel>
              <Hint name="title">Shown at the top of the site. Up to 200 bytes: a plain letter is 1, letters with accents or from other scripts are 2 to 4. You can change it later in WordPress.</Hint>
              <Input {...bind("title")} className={`${control} user-invalid:border-destructive`} type="text" autoComplete="off" required
                value={values.title} onChange={(e) => change("title", e.target.value)} />
              <FieldProblem name="title" message={errors.title} />
            </Field>
            <Field data-invalid={errors.php_version ? true : undefined}>
              <FieldLabel htmlFor={fieldId("php_version")}>{labels.php_version}</FieldLabel>
              <Hint name="php_version">8.3 suits most WordPress sites.</Hint>
              <NativeSelect {...bind("php_version")} className={`max-w-40 [&>select]:h-10 pointer-coarse:[&>select]:h-12`} autoComplete="off" required
                value={values.php_version} onChange={(e) => change("php_version", e.target.value)}>
                {phpVersions.map((version) => <NativeSelectOption key={version} value={version}>PHP {version}</NativeSelectOption>)}
              </NativeSelect>
              <FieldProblem name="php_version" message={errors.php_version} />
            </Field>
          </FieldSet>
          <Separator />
          <FieldSet>
            <FieldLegend>WordPress admin account</FieldLegend>
            <FieldDescription className="text-start">You sign in to WordPress with these.</FieldDescription>
            <Field data-invalid={errors.admin_user ? true : undefined}>
              <FieldLabel htmlFor={fieldId("admin_user")}>{labels.admin_user}</FieldLabel>
              <Hint name="admin_user">Up to 60 letters, digits and . _ @ -</Hint>
              <Input {...bind("admin_user")} className={`${control} user-invalid:border-destructive`} type="text" autoComplete="username" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={60} required
                value={values.admin_user} onChange={(e) => change("admin_user", e.target.value)} />
              <FieldProblem name="admin_user" message={errors.admin_user} />
            </Field>
            <Field data-invalid={errors.admin_email ? true : undefined}>
              <FieldLabel htmlFor={fieldId("admin_email")}>{labels.admin_email}</FieldLabel>
              <Hint name="admin_email">WordPress sends password resets and site notices here.</Hint>
              <Input {...bind("admin_email")} className={`${control} user-invalid:border-destructive`} type="email" autoComplete="email" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={100} required
                value={values.admin_email} onChange={(e) => change("admin_email", e.target.value)} />
              <FieldProblem name="admin_email" message={errors.admin_email} />
            </Field>
            <Field data-invalid={errors.admin_password ? true : undefined}>
              <FieldLabel htmlFor={fieldId("admin_password")}>{labels.admin_password}</FieldLabel>
              <Hint name="admin_password">12 to 128 bytes (a plain letter or digit is 1), with no space at the start or end. Your password manager can suggest one. The panel does not keep it.</Hint>
              <div className="flex gap-2">
                <Input {...bind("admin_password")} className={`${control} min-w-0 flex-1 user-invalid:border-destructive`} type={showPassword ? "text" : "password"} autoComplete="new-password" autoCapitalize="none" autoCorrect="off" spellCheck={false} required
                  value={values.admin_password} onChange={(e) => change("admin_password", e.target.value)} />
                <Button type="button" variant="outline" className={`${control} shrink-0 px-3`} aria-pressed={showPassword} aria-controls={fieldId("admin_password")} aria-describedby="nw-password-toggle-note" onClick={() => setShowPassword((value) => !value)}>
                  {showPassword ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}Show password
                </Button>
              </div>
              <span id="nw-password-toggle-note" className="sr-only">Shows the password on the screen.</span>
              <FieldProblem name="admin_password" message={errors.admin_password} />
            </Field>
          </FieldSet>
          {problem && <Alert variant="destructive" className="text-start" data-testid="new-website-problem">
            <CircleAlert aria-hidden="true" />
            <AlertTitle>{problem.what}</AlertTitle>
            <AlertDescription className="text-start text-foreground">
              <Explanation problem={problem} />
              <TechnicalDetails className="mt-3">{problem.technical}</TechnicalDetails>
            </AlertDescription>
          </Alert>}
          <div className="flex flex-wrap items-center gap-3">
            {/* Stays focusable while busy, so focus is not lost and a second press does nothing. */}
            <Button type="submit" className={`${control} px-4 aria-disabled:opacity-70`} disabled={busy} focusableWhenDisabled data-testid="create-website">
              {busy && <progress className="wizard-spinner" aria-hidden="true" />}
              {busy ? "Creating…" : "Create website"}
            </Button>
            <Link to="/websites" className={linkButton("ghost")}>Cancel</Link>
          </div>
        </FieldGroup>
      </form>
      <div aria-live="polite" className="sr-only" data-testid="field-announcer">{announcement}</div>
    </section>
  </div>;
}

// ---- Job progress and result --------------------------------------------------

// "stopped": a step still marked running on a job that has ended, for example
// one interrupted by a panel restart.
type ShownState = StepState | "stopped";
const stepLabels: Record<ShownState, string> = { pending: "Waiting", running: "In progress", done: "Done", failed: "Failed", undone: "Undone", skipped: "Skipped", stopped: "Stopped" };
const stepBadge: Record<ShownState, "default" | "secondary" | "destructive" | "outline"> = { pending: "outline", running: "default", done: "secondary", failed: "destructive", undone: "outline", skipped: "outline", stopped: "outline" };

function StepIcon({ state }: { state: ShownState }) {
  // The state is always written out next to the icon, so icons are decorative.
  if (state === "running") return <progress className="wizard-spinner mt-0.5 text-primary" aria-hidden="true" />;
  const Icon = { pending: Circle, done: CircleCheck, failed: CircleX, undone: Undo2, skipped: CircleMinus, stopped: CircleMinus }[state];
  const tone = state === "done" ? "text-primary" : state === "failed" ? "text-destructive" : "text-muted-foreground";
  return <Icon className={`mt-0.5 size-4 shrink-0 ${tone}`} aria-hidden="true" />;
}

function StepList({ steps, ended }: { steps: JobStep[]; ended: boolean }) {
  return <div className="flex flex-col gap-2">
    <h3 id="job-steps-heading">Steps</h3>
    {/* role="list" keeps list semantics in Safari once list markers are removed. */}
    <ol role="list" aria-labelledby="job-steps-heading" className="flex flex-col gap-2" data-testid="job-steps">
      {steps.map((step) => {
        const state: ShownState = ended && step.state === "running" ? "stopped" : step.state;
        return <li key={step.name} aria-current={state === "running" ? "step" : undefined} data-state={state}
        className={`flex items-start gap-3 rounded-md border px-3 py-2.5 ${state === "running" ? "border-primary/50 bg-secondary" : state === "failed" ? "border-destructive/40" : "border-border"}`}>
        <StepIcon state={state} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
            <span className="text-sm font-medium text-foreground">{step.title}</span>
            <Badge variant={stepBadge[state]}>{stepLabels[state]}</Badge>
          </div>
          {step.message && <div className="mt-1 text-xs break-words text-muted-foreground">{step.message}</div>}
        </div>
      </li>;
      })}
    </ol>
  </div>;
}

function JobFacts({ job, version }: { job: WebsiteJob; version?: string }) {
  return <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-1.5 text-sm" data-testid="job-facts">
    <dt className="text-muted-foreground">Domain</dt><dd className="break-words text-foreground">{job.domain}</dd>
    <dt className="text-muted-foreground">Hosting account</dt><dd className="text-foreground" data-testid="job-username">{job.username ? <code>{job.username}</code> : "Chosen in the first step"}</dd>
    {version ? <><dt className="text-muted-foreground">WordPress version</dt><dd className="text-foreground" data-testid="job-wordpress-version">{version}</dd></>
      : <><dt className="text-muted-foreground">Started</dt><dd className="text-foreground">{dateLabel(job.created_at)}</dd></>}
  </dl>;
}

const notFound: Problem = { what: "This website setup was not found.", why: "The address does not point to a website setup.", next: "Check the address, or start again from New website.", technical: "job id in the address is not 32 lowercase hex characters; nothing was requested", status: 404 };

export function WebsiteJob({ jobId }: { jobId: string }) {
  const { revision, setPageResource } = useShell();
  const navigate = useNavigate();
  const badId = !validJobId(jobId);
  const [job, setJob] = useState<WebsiteJob>();
  const [problem, setProblem] = useState<Problem>();
  const [loading, setLoading] = useState(!badId);
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [dnsOpen, setDnsOpen] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Poll every 2 s while the job runs and stop once it has ended. A failed
  // read is retried after 5 s unless it cannot succeed by waiting (signed out,
  // refused, not found).
  useEffect(() => {
    if (badId) return;
    let live = true;
    let timer: number | undefined;
    const controller = new AbortController();
    const poll = async () => {
      setLoading(true);
      try {
        const next = await getWebsiteJob(jobId, { signal: controller.signal });
        if (!live) return;
        setJob(next); setProblem(undefined); setLoadedAt(new Date()); setLoading(false);
        if (next.state === "running") timer = window.setTimeout(() => void poll(), 2000);
        else if (next.state === "succeeded") forgetDraft();
      } catch (error) {
        if (!live) return;
        const found = problemFrom(error, "The setup progress could not be loaded.");
        setProblem(found); setLoading(false);
        if (found.status === 0 || found.status === 429 || found.status >= 500) timer = window.setTimeout(() => void poll(), 5000);
      }
    };
    void poll();
    return () => { live = false; window.clearTimeout(timer); controller.abort(); };
  }, [badId, jobId, revision, attempt]);

  useEffect(() => {
    setPageResource("website-job", { data: job, loading: loading && !job, error: problem?.what, loadedAt });
  }, [job, loading, problem, loadedAt, setPageResource]);

  const view = badId ? "missing" : job ? job.state : problem ? "problem" : "loading";
  // Each change of view (progress, result, failure) starts at its heading.
  useEffect(() => { if (view !== "loading") headingRef.current?.focus(); }, [view]);

  const backToForm = () => {
    if (!job) return;
    retryDraft = loadDraft(job.id) ?? { ...emptyDraft, domain: job.domain };
    void navigate({ to: "/websites/new" });
  };
  const retry = () => setAttempt((value) => value + 1);
  const heading = (children: ReactNode) => <h2 id="job-heading" ref={headingRef} tabIndex={-1} className="break-words outline-none">{children}</h2>;

  if (view === "loading") return <div className="flex w-full max-w-2xl flex-col gap-4" role="status" aria-label="Loading the setup progress">
    <Skeleton className="h-36 w-full" /><Skeleton className="h-52 w-full" /><span className="sr-only">Loading the setup progress</span>
  </div>;

  if (!job) {
    const shown = badId ? notFound : problem ?? notFound;
    return <section className={`${panel} flex w-full max-w-2xl flex-col gap-6`} data-testid="job-problem">
      <div className="flex items-start gap-3">
        <CircleAlert className="mt-0.5 size-5 shrink-0 text-destructive" aria-hidden="true" />
        <div className="flex min-w-0 flex-col gap-2">
          {heading(shown.what)}
          <Explanation problem={shown} />
          <TechnicalDetails>{shown.technical}</TechnicalDetails>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        {!badId && <Button variant="outline" className={control} onClick={retry}><RefreshCw aria-hidden="true" />Try again</Button>}
        <Link to="/websites/new" className={linkButton("default")}>New website</Link>
      </div>
    </section>;
  }

  const { done, total } = jobProgress(job);
  const running = job.steps.findIndex((step) => step.state === "running");
  const readProblem = problem && <Alert className="text-start" role="status" data-testid="job-read-problem">
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="text-start text-foreground">
      <Explanation problem={problem} />
      <TechnicalDetails className="mt-3">{problem.technical}</TechnicalDetails>
      <Button variant="outline" size="sm" className="mt-3" onClick={retry}><RefreshCw aria-hidden="true" />Try again now</Button>
    </AlertDescription>
  </Alert>;

  if (job.state === "running") return <section className={`${panel} flex w-full max-w-2xl flex-col gap-5`} data-testid="job-running">
    <div className="flex flex-col gap-1">
      {heading(<>Creating {job.domain}</>)}
      <p className="text-sm">This can take a few minutes. You can leave this page: the setup keeps running on the server, and this address shows its progress.</p>
    </div>
    <div>
      <div className="mb-1.5 flex items-baseline justify-between gap-3">
        <label htmlFor="job-progress" className="text-sm font-medium">Progress</label>
        <span id="job-progress-count" className="text-sm text-muted-foreground">{done} of {total} steps done</span>
      </div>
      <progress id="job-progress" className="wizard-progress" max={total} value={done} aria-describedby="job-progress-count" data-testid="job-progress" />
    </div>
    {readProblem}
    <StepList steps={job.steps} ended={false} />
    <JobFacts job={job} />
    {/* Announces each new step once; the visible list carries the same text. */}
    <div role="status" className="sr-only">{running >= 0 ? `Step ${running + 1} of ${total}: ${job.steps[running].title}.` : ""}</div>
  </section>;

  if (job.state === "succeeded" && job.result) {
    const result = job.result;
    const secure = usesHttps(result);
    // Why the site has no certificate yet, as the "ssl" step said it.
    const reason = secure ? "" : httpReason(job);
    return <section className={`${panel} flex w-full max-w-2xl flex-col gap-5`} data-testid="job-succeeded">
      <div className="flex items-start gap-3">
        <CircleCheck className="mt-0.5 size-6 shrink-0 text-primary" aria-hidden="true" />
        <div className="flex min-w-0 flex-col gap-1">
          {heading(<>{job.domain} is ready</>)}
          <p className="text-sm" data-testid="site-protocol">{secure ? "WordPress is installed. The site uses https with its own certificate." : "WordPress is installed. The site uses http for now."}</p>
          {reason && <p className="text-sm text-muted-foreground" data-testid="http-reason">{reason}</p>}
        </div>
      </div>
      <JobFacts job={job} version={result.wordpress_version} />
      <div className="flex flex-wrap gap-2">
        <a href={result.url} target="_blank" rel="noopener noreferrer" className={linkButton("default")} data-testid="open-site">
          Open site<ExternalLink aria-hidden="true" /><span className="sr-only"> (opens in a new tab)</span>
        </a>
        <a href={result.admin_url} target="_blank" rel="noopener noreferrer" className={linkButton("outline")} data-testid="open-admin">
          Open WordPress admin<ExternalLink aria-hidden="true" /><span className="sr-only"> (opens in a new tab)</span>
        </a>
        <Button variant="outline" className={control} aria-expanded={dnsOpen} aria-controls="dns-help" onClick={() => setDnsOpen((value) => !value)} data-testid="set-up-dns">Set up DNS</Button>
      </div>
      <div id="dns-help" hidden={!dnsOpen} className="rounded-md border border-border bg-muted p-4" data-testid="dns-help">
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <h3>Point {job.domain} at this server</h3>
            <p className="text-sm">Where you manage the domain's DNS, add this record:</p>
          </div>
          <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Type</dt><dd className="font-medium text-foreground">A</dd>
            <dt className="text-muted-foreground">Name</dt><dd className="break-words text-foreground">{job.domain}</dd>
            <dt className="text-muted-foreground">Points to</dt><dd className="text-foreground">This server's public IP address</dd>
          </dl>
          <p className="text-sm">Open site works once the record is live. DNS changes can take a few hours to reach everyone.</p>
        </div>
      </div>
    </section>;
  }

  // Failed (or ended without a usable result).
  const error = job.error ?? { step: "", what: "The website was not created.", why: "A setup step failed and the job stopped.", next: "Go back to the form and try again. If it fails again, check the Sifruno service log.", technical: "" };
  const undone = job.steps.some((step) => step.state === "undone");
  return <section className={`${panel} flex w-full max-w-2xl flex-col gap-5 border-destructive/40`} data-testid="job-failed">
    <div className="flex items-start gap-3">
      <CircleX className="mt-0.5 size-6 shrink-0 text-destructive" aria-hidden="true" />
      <div className="flex min-w-0 flex-col gap-2">
        {heading(error.what || "The website was not created.")}
        <Explanation problem={error} />
      </div>
    </div>
    {undone && <p className="text-sm">Steps marked Undone were removed again.</p>}
    {readProblem}
    <StepList steps={job.steps} ended />
    <JobFacts job={job} />
    <TechnicalDetails>
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1">
        {error.step && <><dt>Step</dt><dd>{error.step}</dd></>}
        <dt>Job</dt><dd>{job.id}</dd>
        {error.technical && <><dt>Detail</dt><dd className="whitespace-pre-wrap">{error.technical}</dd></>}
      </dl>
    </TechnicalDetails>
    <div className="flex flex-wrap items-center gap-3">
      <Button className={control} onClick={backToForm} data-testid="back-to-form"><ArrowLeft className="rtl:rotate-180" aria-hidden="true" />Back to the form</Button>
      <p className="text-sm">Your entries are kept, except the password.</p>
    </div>
  </section>;
}
