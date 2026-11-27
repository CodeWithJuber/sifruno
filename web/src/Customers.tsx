import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { Check, CircleCheck, Copy, Eye, Globe, KeyRound, Link2, Plus, Power, Trash2, UserRound, Users } from "lucide-react";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { PanelTrustNote } from "@/components/panel-trust-note";
import { ProblemAlert } from "@/components/problem-alert";
import type { Problem } from "@/components/problem-alert";
import { dateLabel } from "@/lib/api";
import { checkUsername, checkWebsites, createCustomer, CustomersApiError, listCustomers, loginState, newSetupLink, removeCustomer, setCustomerDisabled, setCustomerWebsites, setupLinkURL } from "@/lib/customers-api";
import type { CustomerList, CustomerLogin, CustomerSetupLink } from "@/lib/customers-api";
import { listWebsites, WebsitesApiError } from "@/lib/websites-api";
import type { Website } from "@/lib/websites-api";
import { useShell } from "@/shell/context";

// Customers: an admin gives a site owner a login for some of the server's
// websites and sends it the one-time setup link; changes the websites; turns
// the login off or on; makes a new link (which also resets the password and
// authenticator); removes it; or opens the panel as that customer. The link
// lives only in this page's state until the admin hides it.
// Coloured text uses div or span, as on the other new screens.

const panel = "rounded-lg border border-border bg-card";
const control = "h-10 pointer-coarse:h-12";
const rowControl = "h-9 pointer-coarse:h-11";

function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof CustomersApiError || error instanceof WebsitesApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status };
  if (error instanceof Error && error.message) return { what, why: error.message, next: "Reload the page and try again.", technical: error.name, status: 0 };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: "unknown error", status: 0 };
}

// The websites a login may reach, as checkboxes.
function WebsitePicker({ sites, selected, onChange, error, describedBy }: { sites: readonly Website[]; selected: readonly string[]; onChange: (next: string[]) => void; error?: string; describedBy?: string }) {
  const id = useId();
  if (sites.length === 0) return <div className="text-sm text-foreground">This server has no websites yet. Make one under Websites first.</div>;
  return <fieldset className="flex flex-col gap-2" aria-describedby={[describedBy, error ? `${id}-error` : ""].filter(Boolean).join(" ") || undefined} aria-invalid={error ? true : undefined}>
    <legend className="mb-1 text-sm font-medium text-foreground">Websites</legend>
    <div className="grid max-h-64 gap-1 overflow-y-auto rounded-md border border-border p-2 sm:grid-cols-2">
      {sites.map((site) => <label key={site.account_id} className="flex min-h-9 cursor-pointer items-center gap-2 rounded px-2 py-1 text-sm text-foreground hover:bg-muted pointer-coarse:min-h-11">
        <input type="checkbox" className="size-4 accent-primary" checked={selected.includes(site.account_id)} data-testid="pick-website" data-domain={site.domain}
          onChange={(event) => onChange(event.target.checked ? [...selected, site.account_id] : selected.filter((value) => value !== site.account_id))} />
        <span className="wrap-anywhere">{site.domain}</span>
      </label>)}
    </div>
    {error && <div id={`${id}-error`} className="text-sm text-destructive">{error}</div>}
  </fieldset>;
}

// The link, shown once. The copy result goes to one role="status" region
// beside the button, and the button stays enabled so a failed copy can be
// retried; if the browser refuses the clipboard, the link is selected.
function SetupLinkPanel({ link, onDone }: { link: CustomerSetupLink; onDone: () => void }) {
  const url = setupLinkURL(link.setup_link, window.location.origin);
  const [message, setMessage] = useState("");
  const [failed, setFailed] = useState(false);
  const field = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const last = useRef("");
  useEffect(() => { heading.current?.focus(); }, []);
  const copy = async () => {
    let next: string;
    try { await navigator.clipboard.writeText(url); next = "Copied"; setFailed(false); }
    catch { field.current?.focus(); field.current?.select(); next = "Copy failed. The link is selected: press Ctrl+C or ⌘C to copy it."; setFailed(true); }
    if (next === last.current) next += " ";
    last.current = next;
    setMessage("");
    requestAnimationFrame(() => setMessage(next));
  };
  return <section className="flex flex-col gap-4 rounded-lg border-2 border-primary bg-card p-5 md:p-6" aria-labelledby="setup-link-heading" data-testid="setup-link-panel">
    <div className="flex flex-col gap-1">
      <h2 id="setup-link-heading" ref={heading} tabIndex={-1} className="outline-none">Send this setup link to {link.username}</h2>
      <div className="text-sm text-foreground">The customer opens it to choose a password and connect an authenticator app. It works once, until <time dateTime={link.setup_expires_at ?? undefined}>{link.setup_expires_at ? dateLabel(link.setup_expires_at) : "tomorrow"}</time>. This is the only time the panel shows it: send it in a private message, not a public channel.</div>
    </div>
    <Field>
      <FieldLabel htmlFor="setup-link-value">Setup link</FieldLabel>
      <div className="flex flex-col gap-2 sm:flex-row">
        <Input id="setup-link-value" ref={field} readOnly value={url} className={`${control} min-w-0 flex-1 font-mono text-sm`} spellCheck={false} autoComplete="off" onFocus={(event) => event.currentTarget.select()} data-testid="setup-link-value" />
        <Button type="button" variant="outline" className={`${control} min-w-24`} onClick={() => void copy()} data-testid="copy-setup-link">{message.startsWith("Copied") ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}Copy link</Button>
      </div>
      <span role="status" className={`min-h-5 text-sm ${failed ? "text-destructive" : "text-muted-foreground"}`}>{message}</span>
    </Field>
    <PanelTrustNote place="setup-link" admin testId="setup-link-trust" />
    <Button type="button" className={`${rowControl} w-fit`} onClick={onDone} data-testid="hide-setup-link"><Check aria-hidden="true" />I have sent it</Button>
  </section>;
}

function CreateLoginForm({ sites, taken, onCreated }: { sites: readonly Website[]; taken: readonly string[]; onCreated: (link: CustomerSetupLink) => void }) {
  const [username, setUsername] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [nameError, setNameError] = useState<string>();
  const [sitesError, setSitesError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const nameField = useRef<HTMLInputElement>(null);
  const checkName = (value: string) => checkUsername(value) ?? (taken.includes(value) ? "Another login already has this username. Choose another one." : undefined);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    const nameProblem = checkName(username);
    const sitesProblem = checkWebsites(picked);
    setNameError(nameProblem); setSitesError(sitesProblem);
    if (nameProblem) { nameField.current?.focus(); return; }
    if (sitesProblem) return;
    setBusy(true); setProblem(undefined);
    try {
      onCreated(await createCustomer(username, picked));
    } catch (failure) {
      const next = problemFrom(failure, "The login was not made.");
      if (next.status === 409) setNameError(next.why);
      else if (next.status === 422 && next.technical.startsWith("not sent")) setSitesError(next.why);
      else setProblem(next);
      setBusy(false);
    }
  };
  return <form method="post" noValidate onSubmit={(event) => void submit(event)} className="flex flex-col gap-4" aria-labelledby="new-login-heading" data-testid="create-login">
    <h2 id="new-login-heading">Give a customer a login</h2>
    <Field data-invalid={nameError ? true : undefined} className="md:max-w-sm">
      <FieldLabel htmlFor="login-username">Username</FieldLabel>
      <Input id="login-username" ref={nameField} className={control} value={username} required autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={32}
        aria-invalid={nameError ? true : undefined} aria-describedby={nameError ? "login-username-hint login-username-error" : "login-username-hint"}
        onChange={(event) => { const value = event.target.value.toLowerCase(); setUsername(value); if (nameError) setNameError(checkName(value)); }} data-testid="login-username" />
      <FieldDescription id="login-username-hint" className="text-start">What the customer signs in with: 3 to 32 lowercase letters, digits, dots, dashes or underscores, starting with a letter.</FieldDescription>
      {nameError && <div id="login-username-error" className="text-sm text-destructive" data-testid="login-username-error">{nameError}</div>}
    </Field>
    <WebsitePicker sites={sites} selected={picked} onChange={(next) => { setPicked(next); if (sitesError) setSitesError(checkWebsites(next)); }} error={sitesError} />
    <div className="text-sm text-foreground">The customer can manage these websites' domains, databases, files, cron jobs and logs, and see their backups. It cannot create, suspend or delete websites, or see the server.</div>
    {problem && <ProblemAlert problem={problem} testId="create-login-problem" />}
    <Button type="submit" className={`${rowControl} w-fit`} disabled={busy || sites.length === 0} data-testid="create-login-submit"><Plus aria-hidden="true" />{busy ? "Making the login…" : "Make login and setup link"}</Button>
  </form>;
}

type Pending = { kind: "websites" | "link" | "remove"; login: CustomerLogin };

function ChangeDialog({ pending, sites, onDone, onCancel }: { pending: Pending; sites: readonly Website[]; onDone: (result: CustomerLogin | CustomerSetupLink, message: string) => void; onCancel: () => void }) {
  const { kind, login } = pending;
  const [picked, setPicked] = useState<string[]>(login.websites);
  const [sitesError, setSitesError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    if (kind === "websites") { const error = checkWebsites(picked); setSitesError(error); if (error) return; }
    setBusy(true); setProblem(undefined);
    try {
      if (kind === "websites") onDone(await setCustomerWebsites(login.username, picked), `${login.username} now has ${picked.length === 1 ? "1 website" : `${picked.length} websites`}.`);
      else if (kind === "link") onDone(await newSetupLink(login.username), "");
      else onDone(await removeCustomer(login.username), `Removed the login ${login.username}. Its websites are still on the server.`);
    } catch (failure) {
      setProblem(problemFrom(failure, kind === "websites" ? "The websites were not changed." : kind === "link" ? "No new setup link was made." : "The login was not removed."));
      setBusy(false);
    }
  };
  const title = kind === "websites" ? `Websites for ${login.username}` : kind === "link" ? `New setup link for ${login.username}?` : `Remove the login ${login.username}?`;
  const description = kind === "websites" ? "The change applies to the customer's next click."
    : kind === "link" ? (login.setup === "done" ? "This resets the login: the customer's password and authenticator app stop working and its sessions end. It chooses new ones from the link, which works for a day." : "The old link stops working. The new one works for a day.")
      : "The customer is signed out at once and cannot sign in again. Its websites stay on the server.";
  return <form method="post" noValidate onSubmit={(event) => void submit(event)} className="grid gap-4" data-testid={`${kind}-form`}>
    <DialogHeader>
      <DialogTitle className="leading-snug wrap-anywhere">{title}</DialogTitle>
      <DialogDescription className="text-start">{description}</DialogDescription>
    </DialogHeader>
    {kind === "websites" && <WebsitePicker sites={sites} selected={picked} onChange={(next) => { setPicked(next); if (sitesError) setSitesError(checkWebsites(next)); }} error={sitesError} />}
    {problem && <ProblemAlert problem={problem} testId={`${kind}-problem`} />}
    <DialogFooter>
      <Button type="button" variant="outline" className={rowControl} disabled={busy} onClick={onCancel}>Cancel</Button>
      <Button type="submit" variant={kind === "remove" ? "destructive" : "default"} className={rowControl} disabled={busy} data-testid={`confirm-${kind}`}>
        {kind === "remove" ? <Trash2 aria-hidden="true" /> : kind === "link" ? <Link2 aria-hidden="true" /> : <Check aria-hidden="true" />}
        {busy ? "Saving…" : kind === "websites" ? "Save websites" : kind === "link" ? "Make new link" : "Remove login"}
      </Button>
    </DialogFooter>
  </form>;
}

const tones: Record<ReturnType<typeof loginState>["tone"], "default" | "secondary" | "destructive" | "outline"> = { ready: "default", waiting: "secondary", attention: "destructive", off: "outline" };

function LoginRows({ list, sites, busy, onViewAs, onToggle, onChange }: {
  list: CustomerList; sites: readonly Website[]; busy: string;
  onViewAs: (login: CustomerLogin) => void; onToggle: (login: CustomerLogin) => void; onChange: (pending: Pending) => void;
}) {
  const domain = (id: string) => sites.find((site) => site.account_id === id)?.domain;
  return <ul role="list" aria-labelledby="logins-heading" className="flex flex-col gap-3" data-testid="logins-list">
    {list.items.map((login) => {
      const state = loginState(login);
      return <li key={login.username} className="flex flex-col gap-3 rounded-md border border-border p-3" data-testid="login-row" data-username={login.username}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <UserRound className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <span className="font-medium wrap-anywhere text-foreground">{login.username}</span>
            <Badge variant={tones[state.tone]} data-testid="login-state">{state.label}</Badge>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" className={rowControl} disabled={Boolean(busy)} onClick={() => onViewAs(login)} data-testid="view-as"><Eye aria-hidden="true" />View as customer<span className="sr-only"> {login.username}</span></Button>
            <Button variant="outline" className={rowControl} disabled={Boolean(busy)} onClick={() => onChange({ kind: "websites", login })}><Globe aria-hidden="true" />Websites<span className="sr-only"> of {login.username}</span></Button>
            <Button variant="outline" className={rowControl} disabled={Boolean(busy)} onClick={() => onChange({ kind: "link", login })} data-testid="new-link"><KeyRound aria-hidden="true" />New setup link</Button>
            <Button variant="outline" className={rowControl} disabled={Boolean(busy)} onClick={() => onToggle(login)} data-testid="toggle-login"><Power aria-hidden="true" />{busy === login.username ? "Saving…" : login.disabled ? "Turn on" : "Turn off"}</Button>
            <Button variant="destructive" className={rowControl} disabled={Boolean(busy)} onClick={() => onChange({ kind: "remove", login })}><Trash2 aria-hidden="true" />Remove<span className="sr-only"> the login {login.username}</span></Button>
          </div>
        </div>
        <dl className="grid gap-x-6 gap-y-2 text-sm md:grid-cols-[2fr_1fr]">
          <div className="flex min-w-0 flex-col gap-0.5"><dt className="text-muted-foreground">Websites</dt>
            <dd className="text-foreground">{login.websites.length === 0 ? "None" : login.websites.map((id, index) => <span key={id}>{index > 0 && ", "}{domain(id)
              ? <Link to="/websites/sites/$accountId" params={{ accountId: id }} className="wrap-anywhere text-primary underline-offset-4 hover:underline">{domain(id)}</Link>
              : <span className="text-muted-foreground">a removed website</span>}</span>)}</dd></div>
          <div className="flex min-w-0 flex-col gap-0.5"><dt className="text-muted-foreground">{login.setup === "done" ? "Made" : login.setup === "pending" ? "Setup link works until" : "Setup link expired"}</dt>
            <dd className="text-foreground">{login.setup === "done" || !login.setup_expires_at ? <time dateTime={login.created_at}>{dateLabel(login.created_at)}</time> : <time dateTime={login.setup_expires_at}>{dateLabel(login.setup_expires_at)}</time>}</dd></div>
        </dl>
      </li>;
    })}
  </ul>;
}

export function Customers() {
  const shell = useShell();
  const { revision, setPageResource } = shell;
  const [list, setList] = useState<CustomerList>();
  const [sites, setSites] = useState<Website[]>([]);
  const [problem, setProblem] = useState<Problem>();
  const [sitesProblem, setSitesProblem] = useState<Problem>();
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [link, setLink] = useState<CustomerSetupLink>();
  const [formRound, setFormRound] = useState(0);
  const [notice, setNotice] = useState("");
  const [pending, setPending] = useState<Pending>();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogRound, setDialogRound] = useState(0);
  const [busy, setBusy] = useState("");
  const listHeading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    let live = true;
    const controller = new AbortController();
    setLoading(true);
    listCustomers({ signal: controller.signal }).then(
      (next) => { if (live) { setList(next); setProblem(undefined); setLoadedAt(new Date()); setLoading(false); } },
      (error: unknown) => { if (live) { setProblem(problemFrom(error, "The customer logins could not be loaded.")); setLoading(false); } },
    );
    listWebsites({ signal: controller.signal }).then(
      (next) => { if (live) { setSites(next); setSitesProblem(undefined); } },
      (error: unknown) => { if (live) setSitesProblem(problemFrom(error, "The websites could not be loaded.")); },
    );
    return () => { live = false; controller.abort(); };
  }, [revision, attempt]);
  useEffect(() => {
    setPageResource("customers", { data: list, loading, error: problem?.what, loadedAt });
  }, [list, loading, problem, loadedAt, setPageResource]);
  const reload = () => setAttempt((value) => value + 1);

  const viewAs = async (login: CustomerLogin) => {
    setBusy(login.username); setProblem(undefined);
    try { await shell.viewAs(login.username); }
    catch (error) { setProblem(problemFrom(error, `The panel could not open ${login.username}'s view.`)); setBusy(""); }
  };
  const toggle = async (login: CustomerLogin) => {
    setBusy(login.username); setProblem(undefined); setNotice("");
    try {
      const changed = await setCustomerDisabled(login.username, !login.disabled);
      setNotice(changed.disabled ? `Turned off the login ${login.username}. It was signed out and cannot sign in until you turn it on.` : `Turned on the login ${login.username}.`);
      reload();
    } catch (error) { setProblem(problemFrom(error, "The login was not changed.")); }
    finally { setBusy(""); }
  };
  const openChange = (next: Pending) => { setPending(next); setDialogRound((value) => value + 1); setDialogOpen(true); };
  const changed = (result: CustomerLogin | CustomerSetupLink, message: string) => {
    setDialogOpen(false);
    if ("setup_link" in result) { setLink(result); setNotice(""); } else setNotice(message);
    reload();
  };

  const full = list ? list.items.length >= list.capacity : false;
  return <div className="flex w-full max-w-5xl flex-col gap-4" data-testid="customers">
    {link && <SetupLinkPanel key={link.setup_link} link={link} onDone={() => { setLink(undefined); listHeading.current?.focus(); }} />}
    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`}>
      {sitesProblem && <ProblemAlert problem={sitesProblem} onRetry={reload} testId="customer-sites-problem" />}
      {full
        ? <Alert className="text-start"><Users aria-hidden="true" /><AlertTitle>This panel has {list?.capacity} customer logins, the most it keeps. Remove one that is no longer used to make another.</AlertTitle></Alert>
        : <CreateLoginForm key={formRound} sites={sites} taken={list?.items.map((item) => item.username) ?? []}
          onCreated={(created) => { setLink(created); setNotice(""); setFormRound((value) => value + 1); reload(); }} />}
    </section>
    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="logins-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="logins-heading" ref={listHeading} tabIndex={-1} className="outline-none">Customer logins</h2>
        {list && <span className="text-sm text-muted-foreground">{list.items.length} of {list.capacity}</span>}
      </div>
      {notice && <Alert role="status" className="text-start" data-testid="customers-notice"><CircleCheck className="text-primary" aria-hidden="true" /><AlertTitle className="wrap-anywhere">{notice}</AlertTitle></Alert>}
      {problem && <ProblemAlert problem={list ? { ...problem, next: `${problem.next} The list below is from the last successful read.` } : problem} onRetry={reload} testId="customers-problem" />}
      {!list
        ? loading && <div className="flex flex-col gap-3" aria-busy="true"><span className="sr-only">Loading the customer logins</span><Skeleton className="h-16 w-full" /><Skeleton className="h-16 w-full" /></div>
        : list.items.length === 0
          ? <Empty className="border border-dashed border-border py-8" data-testid="customers-empty">
            <EmptyHeader>
              <EmptyMedia variant="icon"><Users aria-hidden="true" /></EmptyMedia>
              <EmptyTitle>No customer logins yet</EmptyTitle>
              <EmptyDescription>Give a customer a login above. It signs in with its own password and authenticator app and sees only its websites.</EmptyDescription>
            </EmptyHeader>
          </Empty>
          : <LoginRows list={list} sites={sites} busy={busy} onViewAs={(login) => void viewAs(login)} onToggle={(login) => void toggle(login)} onChange={openChange} />}
    </section>
    <Dialog open={dialogOpen} onOpenChange={(open) => { if (!open) setDialogOpen(false); }}>
      <DialogContent showCloseButton={false} className="sm:max-w-lg" data-testid="customer-dialog">
        {pending && <ChangeDialog key={dialogRound} pending={pending} sites={sites} onDone={changed} onCancel={() => setDialogOpen(false)} />}
      </DialogContent>
    </Dialog>
  </div>;
}
