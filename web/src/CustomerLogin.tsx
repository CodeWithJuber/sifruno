import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { Check, Copy, ExternalLink, Eye, EyeOff, Globe, LogOut, ShieldCheck, UserRound } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ProblemAlert } from "@/components/problem-alert";
import type { Problem } from "@/components/problem-alert";
import { AuthError, beginCustomerSetup, finishCustomerSetup, groupedSecret } from "@/lib/auth-api";
import type { CustomerSetupSecret } from "@/lib/auth-api";
import { linkSecret } from "@/lib/customers-api";
import { listWebsites, WebsitesApiError } from "@/lib/websites-api";
import type { Website } from "@/lib/websites-api";
import { useShell } from "@/shell/context";

// A customer's own pages: the setup its link opens, and Account. The link's
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

// Account: who is signed in and the websites the login manages. An admin
// viewing as a customer sees the customer's.
export function CustomerAccount() {
  const shell = useShell();
  const session = shell.viewer.session;
  const [sites, setSites] = useState<Website[]>();
  const [problem, setProblem] = useState<Problem>();
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
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
  }, [shell.revision, attempt]);
  if (!session) return null;
  const name = session.view_as ?? session.username ?? "";
  return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="customer-account">
    <section className="flex flex-col gap-3 rounded-lg border border-border bg-card p-5 md:p-6" aria-labelledby="account-login">
      <h2 id="account-login">Your login</h2>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
        <dt className="text-muted-foreground">Username</dt><dd className="font-medium text-foreground wrap-anywhere" data-testid="account-username">{name}</dd>
        <dt className="text-muted-foreground">Sign-in</dt><dd className="text-foreground">Password and a 6-digit code from your authenticator app</dd>
      </dl>
      <div className="text-sm text-foreground">Lost your phone or forgot your password? Ask whoever gave you this login for a new setup link. It replaces your password and your authenticator app, and signs out your other sessions.</div>
      {!session.view_as && <Button variant="outline" className={`${control} w-fit`} onClick={shell.signOut}><LogOut aria-hidden="true" />Sign out</Button>}
    </section>
    <section className="flex flex-col gap-3 rounded-lg border border-border bg-card p-5 md:p-6" aria-labelledby="account-websites">
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
    </section>
  </div>;
}
