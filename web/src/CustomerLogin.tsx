import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { Check, Copy, ExternalLink, Eye, EyeOff, Globe, KeyRound, LogOut, ShieldCheck, UserRound } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ProblemAlert } from "@/components/problem-alert";
import type { Problem } from "@/components/problem-alert";
import { AuthError, beginAuthenticatorChange, beginCustomerSetup, changeOwnPassword, finishAuthenticatorChange, finishCustomerSetup, groupedSecret } from "@/lib/auth-api";
import type { CustomerSetupSecret, SetupSecret } from "@/lib/auth-api";
import { linkSecret } from "@/lib/customers-api";
import { listWebsites, WebsitesApiError } from "@/lib/websites-api";
import type { Website } from "@/lib/websites-api";
import { useShell } from "@/shell/context";

// A customer's setup, which its link opens, and Account, the signed-in
// person's own login page for admins and customers alike. The link's
// secret is read from the address's # once and then taken out of the
// address bar; it stays in memory only, like the password and the key.
// Coloured text uses div or span: the base styles colour <p> outside
// Tailwind's layers, as on the other new screens.

const panel = "mx-auto flex w-full max-w-lg flex-col gap-5 rounded-lg border border-border bg-card p-5 md:p-6";
const control = "h-10 pointer-coarse:h-12";

function setupProblem(error: unknown): Problem {
  if (!(error instanceof AuthError)) return { what: "Setup stopped", why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
  const technical = `HTTP ${error.status || "none"}${error.code ? ` (${error.code})` : ""}`;
  switch (error.code) {
    case "setup_link_invalid": return { what: "This setup link does not work", why: error.message, next: "Ask whoever sent it for a new link, then open the new one.", technical, status: error.status };
    case "rate_limited": return { what: "Too many tries", why: error.message, next: "Wait a minute, then open the link again.", technical, status: error.status };
    case "origin_not_allowed": return { what: "Setup was refused", why: error.message, next: "Open the link exactly as you got it, in the browser's address bar.", technical, status: error.status };
    case "connection_failed": return { what: "Setup stopped", why: error.message, next: "Check that this computer is online, then try again.", technical, status: 0 };
    default: return { what: "Setup stopped", why: error.message, next: "Try again in a minute. If it keeps failing, tell whoever sent you the link.", technical, status: error.status };
  }
}

export function CustomerSetup() {
  const shell = useShell();
  const navigate = useNavigate();
  const [token] = useState(() => linkSecret(window.location.hash));
  const [secret, setSecret] = useState<CustomerSetupSecret>();
  const [problem, setProblem] = useState<Problem>();
  const [round, setRound] = useState(0);
  const [password, setPassword] = useState("");
  const [shown, setShown] = useState(false);
  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<{ field: "password" | "code"; text: string }>();
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);

  // The secret has been read: take it out of the address bar and history.
  useEffect(() => {
    if (window.location.hash) window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
  }, []);
  useEffect(() => {
    if (!token) return;
    let live = true;
    setProblem(undefined);
    beginCustomerSetup(token).then(
      (next) => { if (live) { setSecret(next); setCode(""); heading.current?.focus(); } },
      (error: unknown) => { if (live) setProblem(setupProblem(error)); },
    );
    return () => { live = false; };
  }, [token, round]);

  if (!token) return <section className={panel} aria-labelledby="setup-missing" data-testid="customer-setup-missing">
    <Alert variant="destructive" className="text-start">
      <ShieldCheck aria-hidden="true" />
      <AlertTitle id="setup-missing">This page needs the whole setup link</AlertTitle>
      <AlertDescription className="text-start text-foreground">
        <span>The address has no setup code after the # sign. It may have been cut short when it was copied.</span>
        <span><span className="font-medium">Next step:</span> open the link again from the message you got, or ask whoever sent it for a new one.</span>
      </AlertDescription>
    </Alert>
  </section>;

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || !secret) return;
    if ([...password].length < 12) { setFieldError({ field: "password", text: "Use a password of at least 12 characters. A few unrelated words work well." }); return; }
    if (!/^[0-9]{6}$/.test(code)) { setFieldError({ field: "code", text: "Enter the 6-digit code your app shows now." }); return; }
    setBusy(true); setFieldError(undefined); setProblem(undefined);
    try {
      const session = await finishCustomerSetup(token, password, code);
      setPassword(""); setCode("");
      shell.setSession(session);
      navigate({ to: "/websites" });
    } catch (error) {
      if (error instanceof AuthError && error.code === "invalid_password") setFieldError({ field: "password", text: error.message });
      else if (error instanceof AuthError && error.code === "invalid_code") setFieldError({ field: "code", text: error.message });
      else if (error instanceof AuthError && error.code === "setup_expired") { setProblem({ what: "The setup step expired", why: error.message, next: "Add the new key below to your app, then enter its code.", technical: "HTTP 409 (setup_expired)", status: 409 }); setRound((value) => value + 1); }
      else setProblem(setupProblem(error));
    } finally { setBusy(false); }
  };
  const copyKey = async () => {
    if (!secret) return;
    try { await navigator.clipboard.writeText(secret.secret); setCopied("Copied"); }
    catch { setCopied("Copy failed. Select the key and copy it with the keyboard."); }
  };

  return <section className={panel} aria-labelledby="customer-setup-heading" data-testid="customer-setup">
    <div className="flex gap-3">
      <ShieldCheck className="mt-0.5 size-5 shrink-0 text-primary" aria-hidden="true" />
      <div className="flex flex-col gap-1">
        <h2 id="customer-setup-heading" ref={heading} tabIndex={-1} className="outline-none">{secret ? `Set up the login ${secret.username}` : "Opening your setup link…"}</h2>
        <div className="text-sm text-foreground">You will sign in with this username, a password you choose now, and a 6-digit code from an authenticator app on your phone.</div>
      </div>
    </div>
    {shell.viewer.session && <Alert className="text-start" data-testid="setup-replaces-session">
      <UserRound aria-hidden="true" />
      <AlertTitle>Someone is signed in to this browser</AlertTitle>
      <AlertDescription className="text-start text-foreground">Finishing the setup signs this browser in as the new login and signs {shell.viewer.session.username ?? "the current session"} out.</AlertDescription>
    </Alert>}
    {problem && <ProblemAlert problem={problem} onRetry={problem.status === 409 ? undefined : () => setRound((value) => value + 1)} testId="customer-setup-problem" />}
    {!secret && !problem && <div className="flex flex-col gap-3" aria-busy="true"><span className="sr-only">Checking the setup link</span><Skeleton className="h-24 w-full" /><Skeleton className="h-10 w-full" /></div>}
    {secret && <>
      <div className="flex flex-col gap-2 rounded-md border border-border bg-muted p-3">
        <div className="text-sm font-medium text-foreground">1. Add this key to your authenticator app</div>
        <div className="text-xs text-muted-foreground">Google Authenticator, Microsoft Authenticator and 1Password all work. Key for {secret.username}:</div>
        <code className="block font-mono text-base tracking-wider break-all text-foreground" data-testid="customer-setup-secret">{groupedSecret(secret.secret)}</code>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => void copyKey()}>{copied === "Copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}Copy key</Button>
          <a className={buttonVariants({ variant: "outline", size: "sm" })} href={secret.otpauth_uri}><ExternalLink aria-hidden="true" />Open in authenticator app</a>
          <span role="status" className="text-xs text-muted-foreground">{copied}</span>
        </div>
        <div className="text-xs text-foreground">The key is shown only during setup. Anyone with it can make codes, so do not share it or save it in a note.</div>
      </div>
      <form method="post" noValidate onSubmit={(event) => void submit(event)} aria-label="Choose your password">
        <FieldGroup className="gap-4">
          <div className="text-sm font-medium text-foreground">2. Choose a password and enter the app's code</div>
          {/* Password managers save the password with this username. */}
          <input type="text" name="username" autoComplete="username" value={secret.username} readOnly hidden />
          <Field data-invalid={fieldError?.field === "password" ? true : undefined}>
            <FieldLabel htmlFor="customer-password">Password</FieldLabel>
            <div className="flex gap-2">
              <Input id="customer-password" name="new-password" type={shown ? "text" : "password"} autoComplete="new-password" enterKeyHint="next" required minLength={12} className={`${control} min-w-0 flex-1`}
                value={password} onChange={(event) => setPassword(event.target.value)} aria-invalid={fieldError?.field === "password" ? true : undefined}
                aria-describedby={fieldError?.field === "password" ? "customer-password-hint customer-password-error" : "customer-password-hint"} />
              <Button type="button" variant="outline" className={control} onClick={() => setShown((value) => !value)} aria-pressed={shown}>
                {shown ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}{shown ? "Hide" : "Show"}<span className="sr-only"> password</span>
              </Button>
            </div>
            <FieldDescription id="customer-password-hint" className="text-start">At least 12 characters. A few unrelated words work well, or let your browser suggest one.</FieldDescription>
            {fieldError?.field === "password" && <div id="customer-password-error" className="text-sm text-destructive">{fieldError.text}</div>}
          </Field>
          <Field data-invalid={fieldError?.field === "code" ? true : undefined}>
            <FieldLabel htmlFor="customer-code">6-digit code from the app</FieldLabel>
            <Input id="customer-code" name="one-time-code" inputMode="numeric" autoComplete="one-time-code" enterKeyHint="done" pattern="[0-9]{6}" maxLength={6} required className={control}
              value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} aria-invalid={fieldError?.field === "code" ? true : undefined}
              aria-describedby={fieldError?.field === "code" ? "customer-code-error" : undefined} />
            {fieldError?.field === "code" && <div id="customer-code-error" className="text-sm text-destructive">{fieldError.text}</div>}
          </Field>
          <Button type="submit" className={`${control} w-fit`} disabled={busy} data-testid="customer-setup-submit"><ShieldCheck aria-hidden="true" />{busy ? "Creating…" : "Create my login"}</Button>
        </FieldGroup>
      </form>
    </>}
  </section>;
}

// Account: who is signed in, the login's password and authenticator app, and
// for a customer the websites it manages. Admins and customers use the same
// page and the same routes. An admin viewing as a customer sees the
// customer's websites but not its login, which is the customer's own; a
// session opened with the server's access key has no password to change.
export function CustomerAccount() {
  const shell = useShell();
  const session = shell.viewer.session;
  const listed = shell.viewer.restricted;
  const [sites, setSites] = useState<Website[]>();
  const [problem, setProblem] = useState<Problem>();
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!listed) return;
    const controller = new AbortController();
    let live = true;
    listWebsites({ signal: controller.signal }).then(
      (next) => { if (live) { setSites(next); setProblem(undefined); } },
      (error: unknown) => {
        if (!live) return;
        setProblem(error instanceof WebsitesApiError ? { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status } : { what: "Your websites could not be loaded.", why: "Something unexpected went wrong in the panel.", next: "Reload the page.", technical: "", status: 0 });
      },
    );
    return () => { live = false; controller.abort(); };
  }, [shell.revision, attempt, listed]);
  if (!session) return null;
  const name = session.view_as ?? session.username ?? "";
  const customer = session.role === "customer";
  const own = Boolean(session.username) && !session.view_as;
  return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="customer-account">
    <section className={section} aria-labelledby="account-login">
      <h2 id="account-login">Your login</h2>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
        <dt className="text-muted-foreground">Username</dt><dd className="font-medium text-foreground wrap-anywhere" data-testid="account-username">{name || "None: signed in with the server's access key"}</dd>
        <dt className="text-muted-foreground">Sign-in</dt><dd className="text-foreground">{name ? "Password and a 6-digit code from your authenticator app" : "The access key, on this server only"}</dd>
      </dl>
      {customer && <div className="text-sm text-foreground">Lost your phone, or forgot your password? Ask whoever gave you this login for a new setup link. It replaces your password and your authenticator app, and signs out your other sessions.</div>}
      {session.view_as && <div className="text-sm text-foreground" data-testid="account-view-as-note">The password and authenticator app of {session.view_as} are its own, so they cannot be changed here. Go back to your admin view to change yours.</div>}
      {!session.username && <div className="text-sm text-foreground" data-testid="account-key-note">The access key has no password or authenticator app. Sign in with your admin username to change those.</div>}
      {!session.view_as && <Button variant="outline" className={`${control} w-fit`} onClick={shell.signOut}><LogOut aria-hidden="true" />Sign out</Button>}
    </section>
    {own && session.username && <>
      <PasswordChange username={session.username} csrf={session.csrf_token} />
      <AuthenticatorChange username={session.username} csrf={session.csrf_token} />
    </>}
    {listed && <section className={section} aria-labelledby="account-websites">
      <h2 id="account-websites">Websites this login manages</h2>
      {problem && <ProblemAlert problem={problem} onRetry={() => setAttempt((value) => value + 1)} testId="account-websites-problem" />}
      {!sites && !problem && <Skeleton className="h-16 w-full" />}
      {sites && (sites.length === 0
        ? <div className="text-sm text-foreground">This login has no websites at the moment. Ask whoever gave you the login to add yours.</div>
        : <ul role="list" className="flex flex-col gap-2" data-testid="account-websites-list">
          {sites.map((site) => <li key={site.account_id}>
            <Link to="/websites/sites/$accountId" params={{ accountId: site.account_id }} className="inline-flex items-center gap-2 text-sm font-medium text-primary underline-offset-4 hover:underline">
              <Globe className="size-4" aria-hidden="true" /><span className="wrap-anywhere">{site.domain}</span>
            </Link>
          </li>)}
        </ul>)}
    </section>}
  </div>;
}

const section = "flex flex-col gap-3 rounded-lg border border-border bg-card p-5 md:p-6";

// What went wrong with a change to the login, in the panel's three parts.
function changeProblem(error: unknown, what: string): Problem {
  if (!(error instanceof AuthError)) return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
  const technical = `HTTP ${error.status || "none"}${error.code ? ` (${error.code})` : ""}`;
  switch (error.code) {
    case "invalid_credentials": return { what, why: error.message, next: "Enter your current password and the newest code from your app, then try again.", technical, status: error.status };
    case "rate_limited": return { what, why: error.message, next: "Wait a minute, then try again.", technical, status: error.status };
    case "unauthorized": case "login_disabled": return { what, why: error.message, next: "Reload the page and sign in again.", technical, status: error.status };
    case "connection_failed": return { what, why: error.message, next: "Check that this computer is online, then try again.", technical, status: 0 };
    default: return { what, why: error.message, next: "Reload the page and try again. If it keeps failing, tell whoever runs this server.", technical, status: error.status };
  }
}

// One input for the current code, with its hint above it so the keyboard
// and autofill do not cover it.
function CodeField({ id, label, hint, value, onChange, error, testId }: { id: string; label: string; hint: string; value: string; onChange: (value: string) => void; error?: string; testId: string }) {
  return <Field data-invalid={error ? true : undefined}>
    <FieldLabel htmlFor={id}>{label}</FieldLabel>
    <FieldDescription id={`${id}-hint`} className="text-start">{hint}</FieldDescription>
    <Input id={id} name="one-time-code" type="text" inputMode="numeric" autoComplete="one-time-code" enterKeyHint="done" pattern="[0-9]{6}" maxLength={6} required className={`${control} w-40 font-mono tracking-widest`}
      value={value} onChange={(event) => onChange(event.target.value.replace(/\D/g, ""))} aria-invalid={error ? true : undefined}
      aria-describedby={error ? `${id}-hint ${id}-error` : `${id}-hint`} data-testid={testId} />
    {error && <div id={`${id}-error`} className="text-sm text-destructive">{error}</div>}
  </Field>;
}

// The password the person signs in with now.
function CurrentField({ id, value, onChange, error, testId }: { id: string; value: string; onChange: (value: string) => void; error?: string; testId: string }) {
  return <Field data-invalid={error ? true : undefined}>
    <FieldLabel htmlFor={id}>Current password</FieldLabel>
    <Input id={id} name="current-password" type="password" autoComplete="current-password" enterKeyHint="next" required className={control}
      value={value} onChange={(event) => onChange(event.target.value)} aria-invalid={error ? true : undefined} aria-describedby={error ? `${id}-error` : undefined} data-testid={testId} />
    {error && <div id={`${id}-error`} className="text-sm text-destructive">{error}</div>}
  </Field>;
}

// A new password: the current one and a current code first, then the new
// one. Other sessions of this login are signed out; this one stays.
function PasswordChange({ username, csrf }: { username: string; csrf: string }) {
  const [current, setCurrent] = useState("");
  const [chosen, setChosen] = useState("");
  const [shown, setShown] = useState(false);
  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<{ field: "current" | "new" | "code"; text: string }>();
  const [problem, setProblem] = useState<Problem>();
  const [done, setDone] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setDone("");
    if (!current) { setFieldError({ field: "current", text: "Enter the password you sign in with now." }); return; }
    if ([...chosen].length < 12) { setFieldError({ field: "new", text: "Use a new password of at least 12 characters. A few unrelated words work well." }); return; }
    if (chosen === current) { setFieldError({ field: "new", text: "The new password is the same as the current one. Choose a different one." }); return; }
    if (!/^[0-9]{6}$/.test(code)) { setFieldError({ field: "code", text: "Enter the 6-digit code your app shows now." }); return; }
    setBusy(true); setFieldError(undefined); setProblem(undefined);
    try {
      const result = await changeOwnPassword(csrf, current, code, chosen);
      setCurrent(""); setChosen(""); setCode(""); setShown(false);
      const ended = result.other_sessions_ended;
      setDone(`Your password was changed.${ended === 0 ? "" : ended === 1 ? " 1 other session of this login was signed out." : ` ${ended} other sessions of this login were signed out.`}`);
    } catch (error) {
      if (error instanceof AuthError && error.code === "invalid_password") setFieldError({ field: "new", text: error.message });
      else setProblem(changeProblem(error, "Your password was not changed"));
      setCode("");
    } finally { setBusy(false); }
  };
  return <section className={section} aria-labelledby="account-password">
    <div className="flex flex-col gap-1">
      <h2 id="account-password">Password</h2>
      <div className="text-sm text-muted-foreground">Changing it signs out your other sessions of this login. This one stays signed in.</div>
    </div>
    <form method="post" noValidate onSubmit={(event) => void submit(event)} aria-labelledby="account-password" data-testid="account-password-form">
      <FieldGroup className="gap-4">
        {/* Password managers update the saved password for this username. */}
        <input type="text" name="username" autoComplete="username" value={username} readOnly hidden />
        <CurrentField id="password-current" value={current} onChange={setCurrent} error={fieldError?.field === "current" ? fieldError.text : undefined} testId="current-password" />
        <Field data-invalid={fieldError?.field === "new" ? true : undefined}>
          <FieldLabel htmlFor="password-new">New password</FieldLabel>
          <div className="flex gap-2">
            <Input id="password-new" name="new-password" type={shown ? "text" : "password"} autoComplete="new-password" enterKeyHint="next" required minLength={12} className={`${control} min-w-0 flex-1`}
              value={chosen} onChange={(event) => setChosen(event.target.value)} aria-invalid={fieldError?.field === "new" ? true : undefined}
              aria-describedby={fieldError?.field === "new" ? "password-new-hint password-new-error" : "password-new-hint"} data-testid="new-password" />
            <Button type="button" variant="outline" className={control} onClick={() => setShown((value) => !value)} aria-pressed={shown}>
              {shown ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}{shown ? "Hide" : "Show"}<span className="sr-only"> new password</span>
            </Button>
          </div>
          <FieldDescription id="password-new-hint" className="text-start">At least 12 characters, not your username. A few unrelated words work well, or let your browser suggest one.</FieldDescription>
          {fieldError?.field === "new" && <div id="password-new-error" className="text-sm text-destructive">{fieldError.text}</div>}
        </Field>
        <CodeField id="password-code" label="6-digit code from your app" hint="The code your authenticator app shows now. Each code works once." value={code} onChange={setCode}
          error={fieldError?.field === "code" ? fieldError.text : undefined} testId="password-code" />
        {problem && <ProblemAlert problem={problem} testId="password-problem" />}
        <Button type="submit" className={`${control} w-fit`} disabled={busy} data-testid="change-password-submit"><KeyRound aria-hidden="true" />{busy ? "Changing…" : "Change password"}</Button>
        <div role="status" className="text-sm text-foreground empty:hidden" data-testid="password-changed">{done && <span className="inline-flex items-center gap-2"><Check className="size-4 text-primary" aria-hidden="true" />{done}</span>}</div>
      </FieldGroup>
    </form>
  </section>;
}

// A new authenticator app: the current password and a code from the app in
// use, then the new key, then a code from the new app. The old app works
// until the last step; other sessions stay signed in.
function AuthenticatorChange({ username, csrf }: { username: string; csrf: string }) {
  const [current, setCurrent] = useState("");
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState<SetupSecret>();
  const [newCode, setNewCode] = useState("");
  const [fieldError, setFieldError] = useState<{ field: "current" | "code" | "new"; text: string }>();
  const [problem, setProblem] = useState<Problem>();
  const [done, setDone] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState("");
  const keyHeading = useRef<HTMLHeadingElement>(null);
  const restart = () => { setSecret(undefined); setNewCode(""); setCopied(""); setFieldError(undefined); };
  const begin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setDone("");
    if (!current) { setFieldError({ field: "current", text: "Enter the password you sign in with now." }); return; }
    if (!/^[0-9]{6}$/.test(code)) { setFieldError({ field: "code", text: "Enter the 6-digit code your app shows now." }); return; }
    setBusy(true); setFieldError(undefined); setProblem(undefined);
    try {
      const next = await beginAuthenticatorChange(csrf, current, code);
      setCurrent(""); setCode(""); setSecret(next);
      window.requestAnimationFrame(() => keyHeading.current?.focus());
    } catch (error) {
      setProblem(changeProblem(error, "No new key was made"));
      setCode("");
    } finally { setBusy(false); }
  };
  const finish = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || !secret) return;
    if (!/^[0-9]{6}$/.test(newCode)) { setFieldError({ field: "new", text: "Enter the 6-digit code the new entry in your app shows now." }); return; }
    setBusy(true); setFieldError(undefined); setProblem(undefined);
    try {
      await finishAuthenticatorChange(csrf, newCode);
      restart();
      setDone("Your codes now come from the new app. The old entry no longer works, so you can delete it from the old app.");
    } catch (error) {
      if (error instanceof AuthError && error.code === "invalid_code") setFieldError({ field: "new", text: error.message });
      else if (error instanceof AuthError && error.code === "authenticator_change_expired") { restart(); setProblem({ what: "The new key expired", why: error.message, next: "Enter your password and a code from the app you use now to get a new key.", technical: `HTTP ${error.status} (${error.code})`, status: error.status }); }
      else setProblem(changeProblem(error, "The new app was not saved"));
      setNewCode("");
    } finally { setBusy(false); }
  };
  const copyKey = async () => {
    if (!secret) return;
    try { await navigator.clipboard.writeText(secret.secret); setCopied("Copied"); }
    catch { setCopied("Copy failed. Select the key and copy it with the keyboard."); }
  };
  return <section className={section} aria-labelledby="account-authenticator" data-testid="account-authenticator">
    <div className="flex flex-col gap-1">
      <h2 id="account-authenticator">Authenticator app</h2>
      <div className="text-sm text-muted-foreground">Move your sign-in codes to a new phone or app. The app you use now keeps working until the new one is set up.</div>
    </div>
    {problem && <ProblemAlert problem={problem} testId="authenticator-problem" />}
    {!secret && <form method="post" noValidate onSubmit={(event) => void begin(event)} aria-label="Confirm it is you" data-testid="authenticator-begin-form">
      <FieldGroup className="gap-4">
        <input type="text" name="username" autoComplete="username" value={username} readOnly hidden />
        <CurrentField id="authenticator-current" value={current} onChange={setCurrent} error={fieldError?.field === "current" ? fieldError.text : undefined} testId="authenticator-password" />
        <CodeField id="authenticator-code" label="6-digit code from the app you use now" hint="Proves the change is yours. Each code works once." value={code} onChange={setCode}
          error={fieldError?.field === "code" ? fieldError.text : undefined} testId="authenticator-code" />
        <Button type="submit" variant="outline" className={`${control} w-fit`} disabled={busy} data-testid="authenticator-begin"><ShieldCheck aria-hidden="true" />{busy ? "Checking…" : "Set up a new app"}</Button>
      </FieldGroup>
    </form>}
    {secret && <>
      <div className="flex flex-col gap-2 rounded-md border border-border bg-muted p-3">
        <h3 ref={keyHeading} tabIndex={-1} className="m-0 text-sm font-medium text-foreground outline-none">1. Add this key to the new app</h3>
        <div className="text-xs text-muted-foreground">Google Authenticator, Microsoft Authenticator and 1Password all work. Key for {username}:</div>
        <code className="block font-mono text-base tracking-wider break-all text-foreground" data-testid="authenticator-secret">{groupedSecret(secret.secret)}</code>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => void copyKey()}>{copied === "Copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}Copy key</Button>
          <a className={buttonVariants({ variant: "outline", size: "sm" })} href={secret.otpauth_uri}><ExternalLink aria-hidden="true" />Open in authenticator app</a>
          <span role="status" className="text-xs text-muted-foreground">{copied}</span>
        </div>
        <div className="text-xs text-foreground">The key is shown only now and works for 10 minutes until it is confirmed. Anyone with it can make codes, so do not share it or save it in a note.</div>
      </div>
      <form method="post" noValidate onSubmit={(event) => void finish(event)} aria-label="Confirm the new app" data-testid="authenticator-finish-form">
        <FieldGroup className="gap-4">
          <div className="text-sm font-medium text-foreground">2. Enter the code the new app shows</div>
          <CodeField id="authenticator-new-code" label="6-digit code from the new app" hint="From the entry you just added, not the old one." value={newCode} onChange={setNewCode}
            error={fieldError?.field === "new" ? fieldError.text : undefined} testId="authenticator-new-code" />
          <div className="flex flex-wrap gap-2">
            <Button type="submit" className={`${control} w-fit`} disabled={busy} data-testid="authenticator-finish"><ShieldCheck aria-hidden="true" />{busy ? "Saving…" : "Use the new app"}</Button>
            <Button type="button" variant="ghost" className={control} disabled={busy} onClick={restart} data-testid="authenticator-cancel">Keep the app I use now</Button>
          </div>
        </FieldGroup>
      </form>
    </>}
    <div role="status" className="text-sm text-foreground empty:hidden" data-testid="authenticator-changed">{done && <span className="inline-flex items-center gap-2"><Check className="size-4 text-primary" aria-hidden="true" />{done}</span>}</div>
  </section>;
}
