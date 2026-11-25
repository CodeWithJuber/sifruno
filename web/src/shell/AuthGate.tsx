import { useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { Check, Copy, ExternalLink, KeyRound, LogIn, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { AuthError, beginSetup, finishSetup, groupedSecret, onThisServer, signInAdmin, signInWithKey } from "@/lib/auth-api";
import type { AuthSession, SetupSecret } from "@/lib/auth-api";

// Shown in place of a private page until someone is signed in. With no admin
// yet it walks through first-run setup: the server's access key proves the
// person controls this server, then they choose a username and password and
// connect an authenticator app.

type Props = {
  adminRequired: boolean;
  keySession: AuthSession | null;
  onSession: (session: AuthSession, adminCreated: boolean) => void;
};

const panel = "mx-auto w-full max-w-md rounded-lg border border-border bg-card p-6";

function Problem({ error }: { error: string }) {
  return error ? <Alert variant="destructive" className="mt-4" role="alert"><AlertTitle>That did not work</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null;
}

function useSubmit() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const run = async (work: () => Promise<void>) => {
    setBusy(true); setError("");
    try { await work(); }
    catch (e) { setError(e instanceof AuthError ? e.message : "Something went wrong. Try again."); }
    finally { setBusy(false); }
  };
  return { busy, error, run };
}

function Heading({ id, icon, title, children }: { id: string; icon: ReactNode; title: string; children: ReactNode }) {
  return <div className="mb-5 flex gap-3">
    <span className="mt-0.5 text-primary [&_svg]:size-5" aria-hidden="true">{icon}</span>
    <div><h2 id={id}>{title}</h2><p className="mt-1 text-sm">{children}</p></div>
  </div>;
}

function KeyForm({ intro, onSession }: { intro: ReactNode; onSession: (s: AuthSession) => void }) {
  const [key, setKey] = useState("");
  const { busy, error, run } = useSubmit();
  const submit = (e: FormEvent) => { e.preventDefault(); void run(async () => { const s = await signInWithKey(key.trim()); setKey(""); onSession(s); }); };
  return <form onSubmit={submit} data-testid="key-sign-in">
    {intro}
    <FieldGroup>
      <Field><FieldLabel htmlFor="access-key">Access key</FieldLabel>
        <Input id="access-key" type="password" autoComplete="off" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} required />
        <FieldDescription>It is in <code>operator/access.key</code> inside the panel's state folder on this server.</FieldDescription>
      </Field>
      <Button type="submit" disabled={busy || key.trim().length !== 43}><KeyRound aria-hidden="true" />{busy ? "Checking…" : "Continue"}</Button>
    </FieldGroup>
    <Problem error={error} />
  </form>;
}

export function AuthGate({ adminRequired, keySession, onSession }: Props) {
  if (adminRequired && !onThisServer()) return <section className={panel} aria-labelledby="setup-remote-title" data-testid="setup-on-server">
    <Heading id="setup-remote-title" icon={<ShieldCheck />} title="Create the admin account on the server first">This panel has no admin account yet. First-run setup needs the server's access key, so it works only when you open the panel on the server itself. Then sign in here.</Heading>
  </section>;
  return adminRequired ? <Setup keySession={keySession} onSession={onSession} /> : <SignIn onSession={onSession} />;
}

function SignIn({ onSession }: { onSession: Props["onSession"] }) {
  const [useKey, setUseKey] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const { busy, error, run } = useSubmit();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => { const s = await signInAdmin(username.trim(), password, code); setPassword(""); setCode(""); onSession(s, false); });
  };
  if (useKey) return <section className={panel} aria-labelledby="sign-in-title">
    <KeyForm onSession={(s) => onSession(s, false)} intro={<Heading id="sign-in-title" icon={<KeyRound />} title="Sign in with the access key">For someone working on this server itself, for example when the authenticator app is lost.</Heading>} />
    <Button variant="link" className="mt-3 px-0" onClick={() => setUseKey(false)}>Back to username and password</Button>
  </section>;
  return <section className={panel} aria-labelledby="sign-in-title" data-testid="admin-sign-in">
    <Heading id="sign-in-title" icon={<LogIn />} title="Sign in">Use your username, password and the 6-digit code from your authenticator app.</Heading>
    <form onSubmit={submit}>
      <FieldGroup>
        <Field><FieldLabel htmlFor="sign-in-username">Username</FieldLabel>
          <Input id="sign-in-username" autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} required /></Field>
        <Field><FieldLabel htmlFor="sign-in-password">Password</FieldLabel>
          <Input id="sign-in-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></Field>
        <Field><FieldLabel htmlFor="sign-in-code">6-digit code</FieldLabel>
          <Input id="sign-in-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} required /></Field>
        <Button type="submit" disabled={busy || !username.trim() || !password || code.length !== 6}><LogIn aria-hidden="true" />{busy ? "Signing in…" : "Sign in"}</Button>
      </FieldGroup>
    </form>
    <Problem error={error} />
    {onThisServer() && <Button variant="link" className="mt-3 px-0" onClick={() => setUseKey(true)}>Sign in with the server's access key instead</Button>}
  </section>;
}

function Setup({ keySession, onSession }: { keySession: AuthSession | null; onSession: Props["onSession"] }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [secret, setSecret] = useState<SetupSecret>();
  const [code, setCode] = useState("");
  const [copied, setCopied] = useState(false);
  const { busy, error, run } = useSubmit();

  if (!keySession) return <section className={panel} aria-labelledby="setup-title" data-testid="setup-key">
    <KeyForm onSession={(s) => onSession(s, false)} intro={<Heading id="setup-title" icon={<ShieldCheck />} title="Set up the admin account">This panel has no admin yet. First, prove you control this server with its access key. Step 1 of 3.</Heading>} />
  </section>;

  const mismatch = confirm.length > 0 && confirm !== password;
  const chooseAccount = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => { setSecret(await beginSetup(keySession.csrf_token, username.trim())); });
  };
  const create = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const s = await finishSetup(keySession.csrf_token, username.trim(), password, code);
      setPassword(""); setConfirm(""); setCode(""); setSecret(undefined);
      onSession(s, true);
    });
  };
  const copy = async () => {
    if (!secret) return;
    try { await navigator.clipboard.writeText(secret.secret); setCopied(true); } catch { setCopied(false); }
  };

  if (!secret) return <section className={panel} aria-labelledby="setup-title" data-testid="setup-account">
    <Heading id="setup-title" icon={<ShieldCheck />} title="Choose your admin login">You will sign in with these from now on. Step 2 of 3.</Heading>
    <form onSubmit={chooseAccount}>
      <FieldGroup>
        <Field><FieldLabel htmlFor="setup-username">Username</FieldLabel>
          <Input id="setup-username" autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())} required maxLength={32} />
          <FieldDescription>3 to 32 lowercase letters, digits, dots, dashes or underscores, starting with a letter.</FieldDescription></Field>
        <Field><FieldLabel htmlFor="setup-password">Password</FieldLabel>
          <Input id="setup-password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} />
          <FieldDescription>At least 12 characters. A few unrelated words work well.</FieldDescription></Field>
        <Field data-invalid={mismatch || undefined}><FieldLabel htmlFor="setup-confirm">Password again</FieldLabel>
          <Input id="setup-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required aria-invalid={mismatch} aria-describedby={mismatch ? "setup-confirm-problem" : undefined} />
          {mismatch && <FieldDescription id="setup-confirm-problem" className="text-destructive">The two passwords are different.</FieldDescription>}</Field>
        <Button type="submit" disabled={busy || !username.trim() || [...password].length < 12 || confirm !== password}>{busy ? "Preparing…" : "Continue"}</Button>
      </FieldGroup>
    </form>
    <Problem error={error} />
  </section>;

  return <section className={panel} aria-labelledby="setup-title" data-testid="setup-code">
    <Heading id="setup-title" icon={<ShieldCheck />} title="Connect your authenticator app">Add this key to an app such as Google Authenticator, Microsoft Authenticator or 1Password, then enter the code it shows. Step 3 of 3.</Heading>
    <div className="mb-4 rounded-md border border-border bg-muted p-3">
      <div className="text-xs text-muted-foreground">Key for {username.trim()}</div>
      <code className="mt-1 block font-mono text-base tracking-wider break-all" data-testid="setup-secret">{groupedSecret(secret.secret)}</code>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button type="button" variant="outline" size="sm" onClick={() => void copy()}>{copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}{copied ? "Copied" : "Copy key"}</Button>
        <a className={buttonVariants({ variant: "outline", size: "sm" })} href={secret.otpauth_uri}><ExternalLink aria-hidden="true" />Open in authenticator app</a>
      </div>
      <p className="mt-3 text-xs">The key is shown only now. Anyone with it can make codes, so do not share it or save it in a note.</p>
    </div>
    <form onSubmit={create}>
      <FieldGroup>
        <Field><FieldLabel htmlFor="setup-code">6-digit code from the app</FieldLabel>
          <Input id="setup-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} required /></Field>
        <Button type="submit" disabled={busy || code.length !== 6}><ShieldCheck aria-hidden="true" />{busy ? "Creating…" : "Create admin account"}</Button>
      </FieldGroup>
    </form>
    <Problem error={error} />
    <Button variant="link" className="mt-3 px-0" onClick={() => { setSecret(undefined); setCode(""); }}>Back</Button>
  </section>;
}
