import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { Check, CircleAlert, CircleCheck, Copy, KeyRound, Plus, RefreshCw, Trash2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Skeleton } from "@/components/ui/skeleton";
import { dateLabel } from "@/lib/api";
import { checkTokenName, createApiToken, defaultExpiryDays, expiresOn, expiryChoices, listApiTokens, revokeApiToken, TokensApiError } from "@/lib/tokens-api";
import type { ApiToken, CreatedToken, TokenList } from "@/lib/tokens-api";
import { useShell } from "@/shell/context";

// Security › API tokens. An admin makes a token for a program such as the
// WHMCS module, copies it once, sees when each token was last used, and
// revokes it. The new token lives only in this component's state until the
// person hides it or leaves the page; the server cannot show it again.
// The base styles colour <p> outside Tailwind's layers, so coloured text uses
// div or span, as on the other new screens.

const panel = "rounded-lg border border-border bg-card";
const control = "h-10 pointer-coarse:h-12";
const rowControl = "h-9 pointer-coarse:h-11";

interface Problem { what: string; why: string; next: string; technical: string; status: number }

function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof TokensApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
}

// What happened (the title), why, what to do next, and the request under
// Technical details.
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

// ---- The token, shown once ------------------------------------------------------

// The copy result goes to one role="status" region beside the button (not
// inside it), and the button stays enabled so a failed copy can be retried.
// If the browser refuses the clipboard, the token is selected instead so the
// person can copy it with the keyboard.
function NewToken({ token, onDone }: { token: CreatedToken; onDone: () => void }) {
  const [copy, setCopy] = useState<"copied" | "failed">();
  const [message, setMessage] = useState("");
  const field = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const timer = useRef<number | undefined>(undefined);
  const lastMessage = useRef("");

  useEffect(() => { heading.current?.focus(); }, []);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const report = (ok: boolean) => {
    window.clearTimeout(timer.current);
    let next = ok ? "Copied" : "Copy failed. The token is selected: press Ctrl+C or ⌘C to copy it.";
    // VoiceOver skips a message identical to the last one.
    if (next === lastMessage.current) next += " ";
    lastMessage.current = next;
    setCopy(ok ? "copied" : "failed");
    setMessage("");
    requestAnimationFrame(() => setMessage(next));
    if (ok) timer.current = window.setTimeout(() => { setCopy(undefined); setMessage(""); }, 3000);
  };
  const copyToken = async () => {
    try {
      await navigator.clipboard.writeText(token.token);
      report(true);
    } catch {
      field.current?.focus();
      field.current?.select();
      report(false);
    }
  };

  return <section className="flex flex-col gap-4 rounded-lg border-2 border-primary bg-card p-5 md:p-6" aria-labelledby="new-token-heading" data-testid="new-token">
    <div className="flex flex-col gap-1">
      <h2 id="new-token-heading" ref={heading} tabIndex={-1} className="outline-none">Copy your new token now</h2>
      <div className="text-sm text-foreground">This is the only time the panel shows the token <strong className="wrap-anywhere">{token.name}</strong>. Put it in the program that will use it, such as the WHMCS module. If you lose it, revoke it and create a new one.</div>
    </div>
    <Field>
      <FieldLabel htmlFor="new-token-value">Token</FieldLabel>
      <div className="flex flex-col gap-2 sm:flex-row">
        <Input id="new-token-value" ref={field} readOnly value={token.token} className={`${control} min-w-0 flex-1 font-mono text-sm`} spellCheck={false} autoComplete="off" autoCapitalize="none" autoCorrect="off"
          aria-describedby="new-token-hint" onFocus={(event) => event.currentTarget.select()} data-testid="new-token-value" />
        <Button type="button" variant="outline" className={`${control} min-w-24`} onClick={() => void copyToken()} data-testid="copy-token">
          {copy === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}Copy token
        </Button>
      </div>
      <span role="status" className={`min-h-5 text-sm ${copy === "failed" ? "text-destructive" : "text-muted-foreground"}`} data-testid="copy-status">{message}</span>
      <FieldDescription id="new-token-hint" className="text-start">
        Send it in each request as <code className="wrap-anywhere text-foreground">Authorization: Bearer {token.prefix}…</code> It works until <time dateTime={token.expires_at}>{dateLabel(token.expires_at)}</time>.
      </FieldDescription>
    </Field>
    <Button type="button" className={`${rowControl} w-fit`} onClick={onDone} data-testid="hide-token"><Check aria-hidden="true" />I have copied it</Button>
  </section>;
}

// ---- Create -------------------------------------------------------------------

function CreateTokenForm({ names, onCreated }: { names: readonly string[]; onCreated: (token: CreatedToken) => void }) {
  const [name, setName] = useState("");
  const [days, setDays] = useState(defaultExpiryDays);
  const [nameError, setNameError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const nameField = useRef<HTMLInputElement>(null);

  const check = (value: string) => checkTokenName(value)
    ?? (names.some((taken) => taken.toLowerCase() === value.toLowerCase()) ? "Another token already has this name. Choose a different name." : undefined);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    const error = check(name);
    setNameError(error);
    if (error) { nameField.current?.focus(); return; }
    setBusy(true);
    setProblem(undefined);
    try {
      onCreated(await createApiToken(name, days));
    } catch (failure) {
      const next = problemFrom(failure, "The token was not created.");
      if (next.status === 422 || next.status === 409) setNameError(next.why);
      setProblem(next);
      setBusy(false);
    }
  };

  return <form method="post" noValidate onSubmit={(event) => void submit(event)} className="flex flex-col gap-4" aria-labelledby="create-token-heading" data-testid="create-token">
    <h2 id="create-token-heading">New token</h2>
    <FieldGroup className="gap-4 md:flex-row md:items-start">
      <Field data-invalid={nameError ? true : undefined} className="md:flex-1">
        <FieldLabel htmlFor="token-name">Name</FieldLabel>
        <Input id="token-name" ref={nameField} className={control} value={name} required autoComplete="off" spellCheck={false}
          aria-invalid={nameError ? true : undefined} aria-describedby={nameError ? "token-name-hint token-name-error" : "token-name-hint"}
          onChange={(event) => { setName(event.target.value); if (nameError) setNameError(check(event.target.value)); }} data-testid="token-name" />
        <FieldDescription id="token-name-hint" className="text-start">Where the token is used, such as WHMCS.</FieldDescription>
        {nameError && <div id="token-name-error" className="flex items-start gap-1.5 text-sm text-destructive" data-testid="token-name-error">
          <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" /><span><span className="sr-only">Error: </span>{nameError}</span>
        </div>}
      </Field>
      <Field className="md:w-56">
        <FieldLabel htmlFor="token-expiry">Expires after</FieldLabel>
        <NativeSelect id="token-expiry" className={`${control} w-full`} value={String(days)} onChange={(event) => setDays(Number(event.target.value))} aria-describedby="token-expiry-hint" data-testid="token-expiry">
          {expiryChoices.map((choice) => <NativeSelectOption key={choice} value={String(choice)}>{choice === 365 ? "1 year" : `${choice} days`}</NativeSelectOption>)}
        </NativeSelect>
        <FieldDescription id="token-expiry-hint" className="text-start">Until about {new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(expiresOn(days))}. A token cannot last longer than a year.</FieldDescription>
      </Field>
    </FieldGroup>
    {problem && problem.status !== 422 && problem.status !== 409 && <ProblemAlert problem={problem} testId="create-problem" />}
    <Button type="submit" className={`${rowControl} w-fit aria-disabled:opacity-70`} disabled={busy} focusableWhenDisabled data-testid="create-token-submit">
      <Plus aria-hidden="true" />{busy ? "Creating…" : "Create token"}
    </Button>
  </form>;
}

// ---- Revoke -------------------------------------------------------------------

function RevokeForm({ token, onBusy, onRevoked, onCancel, cancelRef }: { token: ApiToken; onBusy: (busy: boolean) => void; onRevoked: (token: ApiToken) => void; onCancel: () => void; cancelRef: React.RefObject<HTMLButtonElement | null> }) {
  const [busy, setBusyState] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const setBusy = (value: boolean) => { setBusyState(value); onBusy(value); };
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setProblem(undefined);
    try {
      const revoked = await revokeApiToken(token.id);
      onBusy(false);
      onRevoked(revoked);
    } catch (failure) {
      setProblem(problemFrom(failure, "The token was not revoked."));
      setBusy(false);
    }
  };
  return <form method="post" onSubmit={(event) => void submit(event)} className="grid gap-4" data-testid="revoke-form">
    <DialogHeader>
      <DialogTitle className="leading-snug wrap-anywhere">Revoke the token {token.name}?</DialogTitle>
      <DialogDescription className="text-start">Programs that use it stop working at once. This cannot be undone: to connect them again, create a new token and put it in their settings.</DialogDescription>
    </DialogHeader>
    <div className="text-sm text-muted-foreground">Token starting <code className="text-foreground">{token.prefix}</code>, last used {token.last_used_at ? dateLabel(token.last_used_at) : "never"}.</div>
    {problem && <ProblemAlert problem={problem} testId="revoke-problem" />}
    <DialogFooter>
      <Button ref={cancelRef} type="button" variant="outline" className={rowControl} disabled={busy} onClick={onCancel} data-testid="cancel-revoke">Cancel</Button>
      <Button type="submit" variant="destructive" className={`${rowControl} aria-disabled:opacity-70`} disabled={busy} focusableWhenDisabled data-testid="confirm-revoke">
        <Trash2 aria-hidden="true" />{busy ? "Revoking…" : "Revoke token"}
      </Button>
    </DialogFooter>
  </form>;
}

// ---- The page -------------------------------------------------------------------

// One row per token: its name and Revoke on top, the details below, wrapping
// to two columns on a phone so nothing hides off the side.
function TokenRows({ list, onRevoke }: { list: TokenList; onRevoke: (token: ApiToken) => void }) {
  const detail = (term: string, value: ReactNode) => <div className="flex min-w-0 flex-col gap-0.5">
    <dt className="text-muted-foreground">{term}</dt><dd className="text-foreground">{value}</dd>
  </div>;
  // role="list" keeps list semantics in Safari once list markers are removed.
  return <ul role="list" aria-labelledby="tokens-heading" className="flex flex-col gap-3" data-testid="tokens-list">
    {list.items.map((token) => <li key={token.id} className="flex flex-col gap-3 rounded-md border border-border p-3" data-testid="token-row" data-name={token.name}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <KeyRound className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <span className="font-medium wrap-anywhere text-foreground">{token.name}</span>
          {token.expired && <Badge variant="destructive">Expired</Badge>}
        </div>
        <Button variant="destructive" className={rowControl} onClick={() => onRevoke(token)} data-testid="revoke-token">
          <Trash2 aria-hidden="true" />Revoke<span className="sr-only"> the token {token.name}</span>
        </Button>
      </div>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm md:grid-cols-4">
        {detail("Starts with", <code>{token.prefix}</code>)}
        {detail("Created", <time dateTime={token.created_at}>{dateLabel(token.created_at)}</time>)}
        {detail(token.expired ? "Expired" : "Expires", <time dateTime={token.expires_at}>{dateLabel(token.expires_at)}</time>)}
        {detail("Last used", token.last_used_at ? <time dateTime={token.last_used_at}>{dateLabel(token.last_used_at)}</time> : "Never")}
      </dl>
    </li>)}
  </ul>;
}

export function ApiTokens() {
  const { revision, setPageResource } = useShell();
  const [list, setList] = useState<TokenList>();
  const [problem, setProblem] = useState<Problem>();
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [created, setCreated] = useState<CreatedToken>();
  const [formRound, setFormRound] = useState(0);
  const [notice, setNotice] = useState("");
  const [target, setTarget] = useState<ApiToken>();
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revokeRound, setRevokeRound] = useState(0);
  const revoking = useRef(false);
  const listHeading = useRef<HTMLHeadingElement>(null);
  const cancelRevoke = useRef<HTMLButtonElement>(null);
  // Set once a revoke worked: its row is gone, so focus goes to the list's
  // heading. Otherwise the dialog gives focus back to the Revoke button.
  const afterRevoke = useRef<HTMLElement | null>(null);

  useEffect(() => {
    let live = true;
    const controller = new AbortController();
    setLoading(true);
    listApiTokens({ signal: controller.signal }).then(
      (next) => { if (live) { setList(next); setProblem(undefined); setLoadedAt(new Date()); setLoading(false); } },
      (error: unknown) => { if (live) { setProblem(problemFrom(error, "The API tokens could not be loaded.")); setLoading(false); } },
    );
    return () => { live = false; controller.abort(); };
  }, [revision, attempt]);
  useEffect(() => {
    setPageResource("api-tokens", { data: list, loading, error: problem?.what, loadedAt });
  }, [list, loading, problem, loadedAt, setPageResource]);
  const reload = () => setAttempt((value) => value + 1);

  const openRevoke = (token: ApiToken) => {
    afterRevoke.current = null;
    setTarget(token);
    setRevokeRound((value) => value + 1);
    setRevokeOpen(true);
  };
  const revoked = (token: ApiToken) => {
    afterRevoke.current = listHeading.current;
    setRevokeOpen(false);
    setNotice(`Revoked the token ${token.name}. Programs that used it can no longer reach the panel.`);
    if (created?.id === token.id) setCreated(undefined);
    reload();
  };

  const full = list ? list.items.length >= list.capacity : false;

  return <div className="flex w-full max-w-5xl flex-col gap-4" data-testid="api-tokens">
    {created && <NewToken key={created.id} token={created} onDone={() => { setCreated(undefined); listHeading.current?.focus(); }} />}

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`}>
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2"><KeyRound className="size-5 text-primary" aria-hidden="true" /><span className="text-sm font-medium text-foreground">What a token can do</span></div>
        <div className="text-sm text-foreground">A token lets a program, such as your billing system, use the panel's API with an admin's access: create, suspend and remove websites. It cannot sign in to the panel, see sessions or manage tokens. Send it only over HTTPS or on this server.</div>
      </div>
      {full
        ? <Alert className="text-start" data-testid="tokens-full"><CircleAlert aria-hidden="true" /><AlertTitle>The panel has {list?.capacity} tokens, the most it keeps</AlertTitle><AlertDescription className="text-start text-foreground">Revoke a token you no longer use to make a new one.</AlertDescription></Alert>
        : <CreateTokenForm key={formRound} names={list?.items.map((item) => item.name) ?? []}
          onCreated={(token) => { setCreated(token); setNotice(""); setFormRound((value) => value + 1); reload(); }} />}
    </section>

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="tokens-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="tokens-heading" ref={listHeading} tabIndex={-1} className="outline-none">Your tokens</h2>
        {list && <span className="text-sm text-muted-foreground" data-testid="tokens-count">{list.items.length} of {list.capacity}</span>}
      </div>
      {notice && <Alert role="status" className="text-start" data-testid="tokens-notice">
        <CircleCheck className="text-primary" aria-hidden="true" />
        <AlertTitle className="wrap-anywhere">{notice}</AlertTitle>
      </Alert>}
      {problem && <ProblemAlert problem={list ? { ...problem, next: `${problem.next} The list below is from the last successful read.` } : problem} onRetry={reload} testId="tokens-problem" />}
      {!list
        ? loading && <div className="flex flex-col gap-3" aria-busy="true" data-testid="tokens-loading"><span className="sr-only">Loading the tokens</span><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-full" /></div>
        : list.items.length === 0
          ? <Empty className="border border-dashed border-border py-8" data-testid="tokens-empty">
            <EmptyHeader>
              <EmptyMedia variant="icon"><KeyRound aria-hidden="true" /></EmptyMedia>
              <EmptyTitle>No API tokens yet</EmptyTitle>
              <EmptyDescription>Create one above for each program that needs the panel API, so you can revoke one without stopping the others.</EmptyDescription>
            </EmptyHeader>
          </Empty>
          : <TokenRows list={list} onRevoke={openRevoke} />}
    </section>

    {/* A closed dialog keeps its last target, so its text does not vanish while it fades out. */}
    <Dialog open={revokeOpen} onOpenChange={(open) => { if (!open && !revoking.current) setRevokeOpen(false); }}>
      <DialogContent showCloseButton={false} className="sm:max-w-md" data-testid="revoke-dialog"
        initialFocus={cancelRevoke} finalFocus={() => afterRevoke.current ?? true}>
        {target && <RevokeForm key={revokeRound} token={target} cancelRef={cancelRevoke} onBusy={(busy) => { revoking.current = busy; }} onRevoked={revoked} onCancel={() => setRevokeOpen(false)} />}
      </DialogContent>
    </Dialog>
  </div>;
}
