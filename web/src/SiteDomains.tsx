import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { ComponentProps, FocusEvent, FormEvent, ReactNode } from "react";
import { ArrowRight, CircleAlert, CircleCheck, Globe, Info, Lock, LockOpen, Plus, RefreshCw, Trash2, TriangleAlert } from "lucide-react";
import { DnsHelp } from "@/components/dns-help";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { addDomain, addRedirect, aliasHttps, alwaysHttps, alwaysHttpsOutcome, checkDomain, checkRedirectFrom, checkRedirectTo, getSiteDomains, maxAliases, maxPathLength, maxRedirects, maxTargetLength, normalizeDomain, redirectKind, removeDomain, removeRedirect, setAlwaysHttps, SiteDomainsApiError, statusLabel } from "@/lib/site-domains-api";
import type { AliasHttps, SiteDomains as Domains, WebsiteRedirect } from "@/lib/site-domains-api";
import { useShell } from "@/shell/context";
// The busy ring a working button shows, as on the wizard's screens.
import "./new-website.css";

// One website's Domains page: the website's other domains (aliases, which
// serve the same site) with what each one's HTTPS is, its "Always use HTTPS"
// switch, and its redirects, with forms to add each and a remove for each.
// The base styles colour <p> and <a> outside Tailwind's layers, so coloured
// text uses div or span, as on the other Websites screens.

const panel = "rounded-lg border border-border bg-card";
const control = "h-10 pointer-coarse:h-12";
const rowControl = "h-9 pointer-coarse:h-11";

interface Problem { what: string; why: string; next: string; technical: string; status: number }

function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof SiteDomainsApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
}

function TechnicalDetails({ children }: { children: ReactNode }) {
  return <details className="text-sm">
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
    <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{children}</div>
  </details>;
}

// What happened (the title), why, what to do next, and the request under
// Technical details. role="alert": a failure is announced at once.
function ProblemAlert({ problem, onRetry, testId }: { problem: Problem; onRetry?: () => void; testId: string }) {
  return <Alert variant="destructive" className="text-start" data-testid={testId}>
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

// ---- One polite live region ---------------------------------------------------

// One region speaks for the page: a field's error a moment after the person
// leaves it, and the result of a change. Each message has an owner, so a
// field that was fixed takes back only its own announcement.
interface Announcer { say: (owner: string, message: string, delayMs: number) => void; clear: (owner: string) => void }

function useAnnouncer(): { text: string; announcer: Announcer } {
  const [text, setText] = useState("");
  const timer = useRef<number | undefined>(undefined);
  const current = useRef<string | undefined>(undefined);
  const say = useCallback((owner: string, message: string, delayMs: number) => {
    window.clearTimeout(timer.current);
    setText("");
    current.current = owner;
    timer.current = window.setTimeout(() => setText(message), delayMs);
  }, []);
  const clear = useCallback((owner: string) => {
    if (current.current !== owner) return;
    window.clearTimeout(timer.current);
    setText("");
    current.current = undefined;
  }, []);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return { text, announcer: useMemo(() => ({ say, clear }), [say, clear]) };
}

// ---- Field feedback -----------------------------------------------------------

type Check = (value: string) => string | undefined;

// Field feedback follows the browser's :user-invalid: nothing is marked until
// the person has changed a field and left it, or tried to submit. The rule
// is the field's custom validity, so the browser's own validation applies it
// and moves focus to the first invalid field on submit; aria-invalid and the
// error's place in aria-describedby follow the same state, and an error that
// appears on leaving a field is read once through the live region.
function useField(id: string, label: string, check: Check, value: string, announcer: Announcer) {
  const el = useRef<HTMLInputElement | null>(null);
  const edited = useRef(false);
  const interacted = useRef(false);
  const announced = useRef(false);
  const rule = useRef(check);
  rule.current = check;
  const [error, setError] = useState("");

  const sync = useCallback((mode: "quiet" | "leave" | "submit") => {
    const input = el.current;
    if (!input) return;
    if (mode === "submit") interacted.current = true;
    let native = false;
    try { native = input.matches(":user-invalid"); } catch { native = false; /* Older browser: the interaction flags below decide. */ }
    const invalid = mode === "submit" || native || (interacted.current && !input.validity.valid);
    const message = invalid ? (rule.current(input.value) || input.validationMessage || "Check this value.") : "";
    setError((current) => current === message ? current : message);
    if (!invalid) {
      announced.current = false;
      announcer.clear(id);
    } else if (mode === "submit") {
      // Focus goes to the first invalid field, which reads its error.
      // Browsers move it themselves, but not every one when the page itself
      // does not have focus.
      announced.current = true;
      if (input.form?.querySelector("input:invalid") === input && document.activeElement !== input) input.focus();
    } else if (mode === "leave" && !announced.current) {
      announced.current = true;
      announcer.say(id, `${label}: Error: ${message}`, 500);
    }
  }, [announcer, id, label]);

  useLayoutEffect(() => {
    el.current?.setCustomValidity(rule.current(value) ?? "");
    sync("quiet");
  });

  const props = {
    id,
    ref: (node: HTMLInputElement | null) => { el.current = node; },
    onBlur: (event: FocusEvent<HTMLInputElement>) => {
      if (edited.current) interacted.current = true;
      // Leaving for the form's own submit button: the submit checks the
      // field, and an error shown now would move the button away from the
      // pointer between press and release, so the press would do nothing.
      const next = event.relatedTarget;
      if (next instanceof HTMLButtonElement && next.type === "submit" && next.form === event.currentTarget.form) return;
      sync("leave");
    },
    onInvalid: () => sync("submit"),
    "aria-invalid": error ? ("true" as const) : ("false" as const),
    "aria-describedby": [`${id}-hint`, error ? `${id}-error` : ""].filter(Boolean).join(" "),
  };
  return { props, error, markEdited: () => { edited.current = true; } };
}

function FieldProblem({ id, message }: { id: string; message: string }) {
  if (!message) return null;
  return <div id={`${id}-error`} className="flex items-start gap-1.5 text-sm text-destructive" data-testid={`${id}-error`}>
    <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
    <span><span className="sr-only">Error: </span>{message}</span>
  </div>;
}

// A button that says it is working and cannot be pressed twice. It stays
// focusable while busy, so focus is not lost.
function BusyButton({ busy, busyLabel, children, className = "", ...props }: ComponentProps<typeof Button> & { busy: boolean; busyLabel: string }) {
  return <Button {...props} className={`aria-disabled:opacity-70 ${className}`} disabled={busy || props.disabled} focusableWhenDisabled={busy}>
    {busy && <progress className="wizard-spinner" aria-hidden="true" />}
    {busy ? busyLabel : children}
  </Button>;
}

// ---- What each domain's HTTPS is --------------------------------------------------

function HttpsBadge({ https, testId }: { https: AliasHttps | "main-on" | "main-off"; testId: string }) {
  if (https === "main-on") return <Badge variant="secondary" data-testid={testId} data-https="on"><Lock className="text-primary" aria-hidden="true" />https</Badge>;
  if (https === "main-off") return <Badge variant="outline" data-testid={testId} data-https="off"><LockOpen aria-hidden="true" />http</Badge>;
  const said = aliasHttps(https);
  return <Badge variant={said.tone === "on" ? "secondary" : "outline"} data-testid={testId} data-https={https}>
    {said.tone === "on" ? <Lock className="text-primary" aria-hidden="true" /> : <LockOpen aria-hidden="true" />}{said.label}
  </Badge>;
}

// ---- Forms --------------------------------------------------------------------

function AddDomainForm({ site, busy, announcer, onSubmit }: { site: Domains; busy: boolean; announcer: Announcer; onSubmit: (domain: string) => void }) {
  const [domain, setDomain] = useState("");
  const field = useField("add-domain-name", "Domain", (value) => checkDomain(value, site), domain, announcer);
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || checkDomain(domain, site)) return;
    onSubmit(normalizeDomain(domain));
  };
  return <form method="post" onSubmit={submit} aria-labelledby="add-domain-heading" data-testid="add-domain-form">
    <FieldGroup className="gap-4">
      <h4 id="add-domain-heading" className="m-0 text-sm font-medium text-foreground">Add a domain</h4>
      <Field data-invalid={field.error ? true : undefined}>
        <FieldLabel htmlFor="add-domain-name">Domain</FieldLabel>
        <FieldDescription id="add-domain-name-hint" className="text-start">
          Another domain for this website, such as www.{site.domain} or a domain you also registered. It shows the same site. Point its DNS at this server too.
        </FieldDescription>
        <Input {...field.props} name="domain" className={`${control} user-invalid:border-destructive`} type="text" inputMode="url" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={253} required
          value={domain} onChange={(event) => { field.markEdited(); setDomain(event.target.value); }} data-testid="add-domain-input" />
        <FieldProblem id="add-domain-name" message={field.error} />
      </Field>
      <div>
        <BusyButton type="submit" className={`${control} px-4`} busy={busy} busyLabel="Adding…" data-testid="add-domain">
          <Plus aria-hidden="true" />Add domain
        </BusyButton>
      </div>
    </FieldGroup>
  </form>;
}

function AddRedirectForm({ site, busy, announcer, onSubmit }: { site: Domains; busy: boolean; announcer: Announcer; onSubmit: (from: string, to: string, status: 301 | 302) => void }) {
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [status, setStatus] = useState<"301" | "302">("301");
  const fromField = useField("add-redirect-from", "Redirect from", (value) => checkRedirectFrom(value, site), from, announcer);
  const toField = useField("add-redirect-to", "Send visitors to", (value) => checkRedirectTo(value, from, site), to, announcer);
  const whole = from.trim() !== "" && redirectKind(from) === "domain";
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || checkRedirectFrom(from, site) || checkRedirectTo(to, from, site)) return;
    onSubmit(from, to, status === "302" ? 302 : 301);
  };
  return <form method="post" onSubmit={submit} aria-labelledby="add-redirect-heading" data-testid="add-redirect-form">
    <FieldGroup className="gap-4">
      <h4 id="add-redirect-heading" className="m-0 text-sm font-medium text-foreground">Add a redirect</h4>
      <Field data-invalid={fromField.error ? true : undefined}>
        <FieldLabel htmlFor="add-redirect-from">Redirect from</FieldLabel>
        <FieldDescription id="add-redirect-from-hint" className="text-start">
          A path on this website, such as /old-page, or one of its domains to send the whole domain, such as www.{site.domain}. Up to {maxPathLength} characters for a path.
        </FieldDescription>
        <Input {...fromField.props} name="from" className={`${control} font-mono user-invalid:border-destructive`} type="text" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={253} required
          value={from} onChange={(event) => { fromField.markEdited(); setFrom(event.target.value); }} data-testid="add-redirect-from" />
        <FieldProblem id="add-redirect-from" message={fromField.error} />
      </Field>
      <Field data-invalid={toField.error ? true : undefined}>
        <FieldLabel htmlFor="add-redirect-to">Send visitors to</FieldLabel>
        <FieldDescription id="add-redirect-to-hint" className="text-start">
          {whole
            ? "The address of the other domain, such as https://" + site.domain + ". Each visitor's path and query are kept."
            : `A full address that starts with http:// or https://, such as https://${site.domain}/new-page. Up to ${maxTargetLength} characters.`}
        </FieldDescription>
        <Input {...toField.props} name="to" className={`${control} font-mono user-invalid:border-destructive`} type="text" inputMode="url" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={maxTargetLength} required
          value={to} onChange={(event) => { toField.markEdited(); setTo(event.target.value); }} data-testid="add-redirect-to" />
        <FieldProblem id="add-redirect-to" message={toField.error} />
      </Field>
      <FieldSet className="gap-2">
        <FieldLegend variant="label">Kind of redirect</FieldLegend>
        <RadioGroup name="status" value={status} onValueChange={(value) => setStatus(value === "302" ? "302" : "301")} className="gap-2" data-testid="add-redirect-status">
          <div className="flex items-start gap-2">
            <RadioGroupItem value="301" id="add-redirect-301" className="mt-0.5" aria-describedby="add-redirect-301-hint" />
            <div className="flex flex-col gap-0.5">
              <Label htmlFor="add-redirect-301">Moved for good (301)</Label>
              <span id="add-redirect-301-hint" className="text-sm text-muted-foreground">Browsers and search engines remember the new address.</span>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <RadioGroupItem value="302" id="add-redirect-302" className="mt-0.5" aria-describedby="add-redirect-302-hint" />
            <div className="flex flex-col gap-0.5">
              <Label htmlFor="add-redirect-302">Moved for now (302)</Label>
              <span id="add-redirect-302-hint" className="text-sm text-muted-foreground">Use it while you try something; nothing remembers it.</span>
            </div>
          </div>
        </RadioGroup>
      </FieldSet>
      <div>
        <BusyButton type="submit" className={`${control} px-4`} busy={busy} busyLabel="Adding…" data-testid="add-redirect">
          <Plus aria-hidden="true" />Add redirect
        </BusyButton>
      </div>
    </FieldGroup>
  </form>;
}

// ---- Always use HTTPS -------------------------------------------------------------

// The switch shows the stored setting. It changes only while the site is live
// with a valid certificate; otherwise it cannot be pressed, and the section
// says why and what to do next. While a change is saved, it shows the new
// position and cannot be pressed again.
function AlwaysHttpsSection({ site, locked, saving, status, failure, onChange }: { site: Domains; locked: boolean; saving?: boolean; status: string; failure?: Problem; onChange: (on: boolean) => void }) {
  const [dnsOpen, setDnsOpen] = useState(false);
  const state = alwaysHttps(site);
  const blocked = state.kind !== "ready";
  const checked = saving ?? site.always_https;
  const describedBy = ["always-https-hint", blocked ? "always-https-blocked" : "", status && saving === undefined ? "always-https-status" : ""].filter(Boolean).join(" ");
  return <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="always-https-heading" data-testid="always-https-section" data-state={state.kind} data-on={String(site.always_https)}>
    <h3 id="always-https-heading">HTTPS</h3>
    <Field orientation="horizontal" data-disabled={blocked ? true : undefined} className="gap-4">
      <FieldContent>
        <FieldLabel htmlFor="always-https">Always use HTTPS</FieldLabel>
        <FieldDescription id="always-https-hint" className="text-start">Send visitors from http:// to https:// once a valid certificate is in force.</FieldDescription>
      </FieldContent>
      <Switch id="always-https" checked={checked} disabled={blocked} readOnly={locked} aria-busy={saving !== undefined}
        aria-describedby={describedBy} onCheckedChange={(on) => { if (!locked) onChange(on); }} data-testid="always-https-switch" />
    </Field>
    {saving !== undefined && <div className="flex items-center gap-2 text-sm text-muted-foreground" data-testid="always-https-saving">
      <progress className="wizard-spinner" aria-hidden="true" />{saving ? "Turning Always use HTTPS on…" : "Turning Always use HTTPS off…"}
    </div>}
    {status && saving === undefined && <div id="always-https-status" className="flex items-start gap-1.5 text-sm text-foreground" data-testid="always-https-status">
      <CircleCheck className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" /><span>{status}</span>
    </div>}
    {blocked && <div id="always-https-blocked" className="flex flex-col gap-2 text-sm" data-testid="always-https-blocked">
      <span className="text-foreground">{state.why}</span>
      <span className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {state.next}</span>
      {(state.kind === "no-certificate" || state.kind === "expired") && <>
        <Button type="button" variant="outline" size="sm" className="w-fit" aria-expanded={dnsOpen} aria-controls="dns-main-domain" onClick={() => setDnsOpen((open) => !open)} data-testid="always-https-show-dns">
          Set up DNS<span className="sr-only"> for {site.domain}</span>
        </Button>
        <DnsHelp id="dns-main-domain" domain={site.domain} hidden={!dnsOpen} />
      </>}
    </div>}
    {failure && <ProblemAlert problem={failure} testId="always-https-problem" />}
  </section>;
}

// ---- The page -----------------------------------------------------------------

type Busy = "add-domain" | "add-redirect" | `remove-domain:${string}` | `remove-redirect:${string}` | "always-https";
// Where a failed change is told: by its list, its switch, or in the remove
// dialog.
type Where = "domains" | "redirects" | "remove-domain" | "always-https";

export function SiteDomains({ accountId }: { accountId: string }) {
  const { revision, setPageResource, viewer } = useShell();
  // A login that may not change the switch does not see it.
  const canHttps = viewer.can("POST /api/v1/websites/sites/{account_id}/always-https");
  const [site, setSite] = useState<Domains>();
  const [problem, setProblem] = useState<Problem>();
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState<Busy>();
  const [failure, setFailure] = useState<{ where: Where; problem: Problem }>();
  const [notice, setNotice] = useState("");
  // The switch's position while its change is saved, and what the last
  // change did; said beside the switch, not at the top of the page.
  const [httpsTarget, setHttpsTarget] = useState<boolean>();
  const [httpsStatus, setHttpsStatus] = useState("");
  const [dnsFor, setDnsFor] = useState<string>();
  const [removing, setRemoving] = useState<string>();
  // Bumped after an add, so its form starts again untouched.
  const [round, setRound] = useState(0);
  const { text: spoken, announcer } = useAnnouncer();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const domainsHeading = useRef<HTMLHeadingElement>(null);
  const redirectsHeading = useRef<HTMLHeadingElement>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  useEffect(() => {
    let live = true;
    const controller = new AbortController();
    setLoading(true);
    getSiteDomains(accountId, { signal: controller.signal }).then(
      (value) => { if (live) { setSite(value); setProblem(undefined); setLoadedAt(new Date()); setLoading(false); } },
      (error: unknown) => { if (live) { setProblem(problemFrom(error, "This website's domains could not be loaded.")); setLoading(false); } },
    );
    return () => { live = false; controller.abort(); };
  }, [accountId, revision, attempt]);
  useEffect(() => {
    setPageResource("site-domains", { data: site, loading, error: problem?.what, loadedAt });
  }, [site, loading, problem, loadedAt, setPageResource]);
  const reload = () => setAttempt((value) => value + 1);

  const domain = site?.domain;
  useEffect(() => {
    if (!domain) return;
    headingRef.current?.focus();
    document.title = `Domains · ${domain} · Sifruno`;
  }, [domain]);

  const region = <div aria-live="polite" className="sr-only" data-testid="domains-announcer">{spoken}</div>;

  if (!site) return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="site-domains">
    {problem
      ? <ProblemAlert problem={problem} onRetry={problem.status === 404 ? undefined : reload} testId="domains-problem" />
      : loading && <div className={`${panel} flex flex-col gap-4 p-5`} aria-busy="true"><span className="sr-only">Loading the domains</span><Skeleton className="h-8 w-1/2" /><Skeleton className="h-28 w-full" /><Skeleton className="h-28 w-full" /></div>}
    {region}
  </div>;

  const live = site.state === "active";
  // One change at a time: the server's answer becomes the page's read, the
  // outcome is said, and focus goes to the list the change was in. The
  // switch keeps focus, and its outcome is shown beside it.
  async function run(what: Busy, where: Where, failed: string, work: () => Promise<Domains>, done: (next: Domains) => string) {
    if (busy) return;
    setBusy(what); setFailure(undefined); setNotice(""); setHttpsStatus("");
    try {
      const next = await work();
      if (!mounted.current) return;
      const message = done(next);
      setSite(next); setLoadedAt(new Date()); setRemoving(undefined);
      if (where === "always-https") setHttpsStatus(message);
      else setNotice(message);
      if (what.startsWith("add")) setRound((value) => value + 1);
      announcer.say("status", message, 500);
      if (where !== "always-https") (where === "redirects" ? redirectsHeading : domainsHeading).current?.focus();
    } catch (error) {
      if (!mounted.current) return;
      setFailure({ where, problem: problemFrom(error, failed) });
      // The website changed meanwhile: read it again, so the switch shows it
      // as it is now.
      if (where === "always-https" && error instanceof SiteDomainsApiError && error.status === 409) reload();
    } finally {
      if (mounted.current) setBusy(undefined);
    }
  }
  const httpsNote = (d: string, next: Domains) => {
    const alias = next.aliases.find((a) => a.name === d);
    return alias && alias.https === "off" ? " Certificates are not set up on this server, so it uses http." : " HTTPS for it follows in a few minutes, once its DNS points here.";
  };
  const addAlias = (d: string) => void run("add-domain", "domains", "The domain was not added.", () => addDomain(site, d),
    (next) => `Added ${d}. It shows the same site as ${next.domain}.${httpsNote(d, next)}`);
  const removeAlias = (d: string) => void run(`remove-domain:${d}`, "remove-domain", "The domain was not removed.", () => removeDomain(site, d),
    () => `Removed ${d}. It no longer shows this website.`);
  const addRoute = (from: string, to: string, status: 301 | 302) => void run("add-redirect", "redirects", "The redirect was not added.", () => addRedirect(site, from, to, status),
    () => `Added the redirect from ${from.trim()}.`);
  const removeRoute = (r: WebsiteRedirect) => void run(`remove-redirect:${r.from}`, "redirects", "The redirect was not removed.", () => removeRedirect(site, r.from),
    () => `Removed the redirect from ${r.from}.`);
  const switchHttps = (on: boolean) => {
    if (busy) return;
    setHttpsTarget(on);
    void run("always-https", "always-https", "Always use HTTPS did not change.", () => setAlwaysHttps(site, on), (next) => alwaysHttpsOutcome(next));
  };
  const unread = site.redirect_count - site.redirects.length;
  const removingRedirects = removing ? site.redirects.filter((r) => r.from === removing) : [];

  return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="site-domains" data-account-id={site.account_id}>
    {problem && <ProblemAlert problem={{ ...problem, next: `${problem.next} The lists below are from the last successful read.` }} onRetry={reload} testId="domains-problem" />}
    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`}>
      <div className="flex flex-col gap-1">
        <h2 ref={headingRef} tabIndex={-1} className="wrap-anywhere outline-none" data-testid="domains-heading">Domains and redirects for {site.domain}</h2>
        <div className="text-sm text-muted-foreground">Other domains show the same website. A redirect sends visitors from a path or a whole domain to another address.</div>
      </div>
      {notice && <Alert className="text-start" data-testid="domains-notice">
        <CircleCheck className="text-primary" aria-hidden="true" />
        <AlertTitle className="wrap-anywhere">{notice}</AlertTitle>
      </Alert>}
      {!live && <Alert className="text-start" data-testid="domains-not-live">
        <Info aria-hidden="true" />
        <AlertTitle>{site.state === "suspended" ? "This website is suspended." : "This website cannot change now."}</AlertTitle>
        <AlertDescription className="text-start text-sm">
          {site.state === "suspended"
            ? "Its domains answer every visitor with an error page and its redirects are off. Resume the website in its Settings tab to change them."
            : "The hosting account needs a check by whoever runs this server before its domains or redirects can change."}
        </AlertDescription>
      </Alert>}
    </section>

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="domains-list-heading" data-testid="domains-section">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 id="domains-list-heading" ref={domainsHeading} tabIndex={-1} className="outline-none">Domains</h3>
        <span className="text-sm text-muted-foreground" data-testid="domains-count">{site.aliases.length + 1} of {maxAliases + 1}</span>
      </div>
      <ul role="list" className="flex flex-col divide-y divide-border rounded-md border border-border" data-testid="domains-list">
        <li className="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2.5" data-testid="domain-row" data-domain={site.domain}>
          <span className="min-w-0 flex-1 font-medium wrap-anywhere text-foreground">{site.domain}</span>
          <Badge variant="outline">Main domain</Badge>
          <HttpsBadge https={site.https.on ? "main-on" : "main-off"} testId="domain-https" />
        </li>
        {site.aliases.map((alias) => {
          const said = aliasHttps(alias.https);
          const dnsId = `dns-${alias.name.replace(/[^a-z0-9-]/g, "-")}`;
          return <li key={alias.name} className="flex flex-col gap-2 px-3 py-2.5" data-testid="domain-row" data-domain={alias.name} data-https={alias.https}>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
              <span className="min-w-0 flex-1 wrap-anywhere text-foreground">{alias.name}</span>
              <HttpsBadge https={alias.https} testId="domain-https" />
              {live && <Button type="button" variant="ghost" className={`${rowControl} px-2`} disabled={Boolean(busy)} onClick={() => { setFailure(undefined); setRemoving(alias.name); }} data-testid="remove-domain">
                <Trash2 aria-hidden="true" />Remove<span className="sr-only"> {alias.name}</span>
              </Button>}
            </div>
            {alias.https !== "on" && <div className="flex flex-col gap-2 text-sm text-muted-foreground" data-testid="domain-https-note">
              <span>{said.detail}</span>
              {alias.https === "waiting_for_dns" && <>
                <Button type="button" variant="outline" size="sm" className="w-fit" aria-expanded={dnsFor === alias.name} aria-controls={dnsId} onClick={() => setDnsFor((current) => current === alias.name ? undefined : alias.name)} data-testid="show-dns">
                  Set up DNS<span className="sr-only"> for {alias.name}</span>
                </Button>
                <DnsHelp id={dnsId} domain={alias.name} hidden={dnsFor !== alias.name} />
              </>}
            </div>}
          </li>;
        })}
      </ul>
      {site.aliases.length === 0 && <div className="text-sm text-muted-foreground" data-testid="domains-none">This website has no other domains yet.</div>}
      {failure?.where === "domains" && <ProblemAlert problem={failure.problem} testId="domains-change-problem" />}
      {live && <>
        <Separator />
        <AddDomainForm key={`domain-${round}`} site={site} busy={busy === "add-domain"} announcer={announcer} onSubmit={addAlias} />
      </>}
    </section>

    {canHttps && <AlwaysHttpsSection site={site} locked={Boolean(busy)} saving={busy === "always-https" ? httpsTarget : undefined} status={httpsStatus}
      failure={failure?.where === "always-https" ? failure.problem : undefined} onChange={switchHttps} />}

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="redirects-list-heading" data-testid="redirects-section">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 id="redirects-list-heading" ref={redirectsHeading} tabIndex={-1} className="outline-none">Redirects</h3>
        <span className="text-sm text-muted-foreground" data-testid="redirects-count">{site.redirect_count} of {maxRedirects}</span>
      </div>
      {unread > 0 && <Alert className="text-start" data-testid="redirects-unread">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>{unread === 1 ? "1 redirect could not be read." : `${unread} redirects could not be read.`}</AlertTitle>
        <AlertDescription className="text-start text-sm">The account service did not answer for them, so they are not listed. They still work. Reload the page to read them again.</AlertDescription>
      </Alert>}
      {site.redirect_count === 0
        ? <Empty className="border border-dashed border-border py-8" data-testid="redirects-empty">
          <EmptyHeader>
            <EmptyMedia variant="icon"><Globe aria-hidden="true" /></EmptyMedia>
            <EmptyTitle>No redirects yet</EmptyTitle>
            <EmptyDescription>Send an old page to its new address, or a whole domain, such as www.{site.domain}, to another.</EmptyDescription>
          </EmptyHeader>
        </Empty>
        : site.redirects.length > 0 && <ul role="list" className="flex flex-col divide-y divide-border rounded-md border border-border" data-testid="redirects-list">
          {site.redirects.map((r) => <li key={r.from} className="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2.5" data-testid="redirect-row" data-from={r.from}>
            <div className="flex min-w-0 flex-1 flex-col gap-1">
              <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 font-mono text-sm text-foreground">
                <span className="wrap-anywhere">{r.from}</span>
                <ArrowRight className="size-4 shrink-0 text-muted-foreground rtl:rotate-180" aria-hidden="true" /><span className="sr-only">to</span>
                <span className="wrap-anywhere">{r.to}</span>
              </div>
              <span className="text-xs text-muted-foreground">{redirectKind(r.from) === "domain" ? "Whole domain, path kept" : "One path"} · {statusLabel(r.status)}</span>
            </div>
            {live && <BusyButton type="button" variant="ghost" className={`${rowControl} px-2`} busy={busy === `remove-redirect:${r.from}`} busyLabel="Removing…" disabled={Boolean(busy)} onClick={() => removeRoute(r)} data-testid="remove-redirect">
              <Trash2 aria-hidden="true" />Remove<span className="sr-only"> the redirect from {r.from}</span>
            </BusyButton>}
          </li>)}
        </ul>}
      {failure?.where === "redirects" && <ProblemAlert problem={failure.problem} testId="redirects-change-problem" />}
      {live && <>
        <Separator />
        <AddRedirectForm key={`redirect-${round}`} site={site} busy={busy === "add-redirect"} announcer={announcer} onSubmit={addRoute} />
      </>}
    </section>

    <Dialog open={removing !== undefined} onOpenChange={(open) => { if (!open && !busy) setRemoving(undefined); }}>
      <DialogContent className="sm:max-w-md" showCloseButton={false} data-testid="remove-domain-dialog">
        <DialogHeader>
          <DialogTitle className="wrap-anywhere leading-snug">Remove {removing}?</DialogTitle>
          <DialogDescription className="text-start">
            {removing} will no longer show this website. Its files stay as they are, and you can add the domain again.
            {site.redirects.some((r) => r.from === removing) && <> Its redirect, to {removingRedirects[0]?.to}, is removed with it.</>}
          </DialogDescription>
        </DialogHeader>
        {failure?.where === "remove-domain" && <ProblemAlert problem={failure.problem} testId="remove-domain-problem" />}
        <DialogFooter>
          <DialogClose render={<Button type="button" variant="outline" className={control} />} disabled={Boolean(busy)} data-testid="cancel-remove-domain">Cancel</DialogClose>
          <BusyButton type="button" variant="destructive" className={control} busy={busy === `remove-domain:${removing}`} busyLabel="Removing…" onClick={() => { if (removing) removeAlias(removing); }} data-testid="confirm-remove-domain">Remove domain</BusyButton>
        </DialogFooter>
      </DialogContent>
    </Dialog>
    {region}
  </div>;
}
