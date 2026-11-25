import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CircleCheck, Info, LoaderCircle, LockKeyhole, LogOut, Plus, RefreshCw, Search, UserRound, Users } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ProblemAlert } from "@/components/problem-alert";
import type { Problem } from "@/components/problem-alert";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import {
  ACCOUNT_RECOVERY_REQUIRED, AccountsApiError, createAccount, getAccounts, getAccountsCapability, getAccountsSession,
  loginAccountsSession, logoutAccountsSession, setAccountState, validAccountDomain, validAccountReason, getAccountsWebPreview,
} from "@/lib/accounts-api";
import type { Account, AccountsCapability, AccountsSession } from "@/lib/accounts-api";
import { AccountsWebPreviewError, PreviewRequestGate } from "@/lib/accounts-web-preview";
import type { AccountsWebPreview } from "@/lib/accounts-web-preview";

interface PendingStateChange { accountId: string; state: "active" | "suspended"; reason: string }
const accountError = (error: unknown) => error instanceof AccountsApiError ? error.message : "The local account operation could not be confirmed. Your form values are kept.";
const stateLabel = (state: Account["state"]) => state.replaceAll("_", " ");
const utf8Bytes = (value: string) => new TextEncoder().encode(value.trim()).length;
function capabilityCopy(capability: AccountsCapability, fresh: boolean): string {
  if (!fresh) return "Broker availability is being rechecked. Account changes stay paused until its status and the account list are refreshed.";
  if (capability.available) return "The local Linux account broker is available.";
  if (capability.reason === ACCOUNT_RECOVERY_REQUIRED) return "An account requires recovery. Its listing remains available; account changes are disabled until reviewed.";
  if (capability.reason === "linux_broker_not_configured") return "Linux account creation requires a local Linux broker. This host currently has no configured broker.";
  if (capability.reason === "linux_broker_unavailable") return "The local Linux account broker is unreachable. No account change can be confirmed. Refresh before retrying.";
  return "The Linux account broker's availability could not be confirmed. Check again before trying account changes.";
}

// An error as the panel shows it: what happened (the action that failed),
// why (the message the page already had), what to do next, and the error's
// code and status under "Technical details". The API client's messages stay
// as they are; the next step follows from the status.
function nextStep(status: number, code: string): string {
  if (status === 401) return "Sign in again with the operator access key.";
  if (status === 403) return "Reload the page, sign in again, then try again.";
  if (status === 404) return "Use Refresh accounts and choose the account again.";
  if (status === 409) return "Use Refresh accounts, review the account, then try again.";
  if (status === 422) return "Check the username, domain and reason, then try again.";
  if (status === 429) return "Wait a minute before signing in again.";
  if (status === 503) return "Check that the Linux account broker is running, then use Refresh accounts.";
  if (status === 0 && code === "invalid_response") return "Reload the page. If it happens again, the panel and the server may be different versions.";
  if (status === 0) return "Check that Sifruno is running and this computer is online, then refresh.";
  return "Use Refresh accounts and try again.";
}
function accountProblem(message: string, what: string, failure?: unknown, next?: string): Problem {
  if (failure instanceof AccountsApiError || failure instanceof AccountsWebPreviewError) {
    return { what, why: message, next: next ?? nextStep(failure.status, failure.code), technical: `${failure.code}${failure.status ? ` · status ${failure.status}` : ""}`, status: failure.status };
  }
  return { what, why: message, next: next ?? "Use Refresh accounts and try again.", technical: failure === undefined ? "Checked in this browser; nothing was sent to the server." : "The page could not read the failure.", status: 0 };
}

const panel = "rounded-lg border border-border bg-card";
const control = "h-10! text-sm! pointer-coarse:h-12!";
const rowControl = "h-9 pointer-coarse:h-11";
const dialogClass = "fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-[min(32rem,calc(100vw-1.75rem))] overflow-auto overscroll-contain rounded-xl border border-border bg-card p-5 text-foreground shadow-xl backdrop:overflow-hidden backdrop:overscroll-contain backdrop:bg-[rgb(8_14_22/58%)]";
const stateTone: Record<Account["state"], "secondary" | "outline" | "destructive"> = { active: "secondary", suspended: "outline", recovery_required: "destructive" };
const Busy = ({ when }: { when: boolean }) => when ? <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" /> : null;

export default function Accounts({ revision, active, onStatus }: { revision: number; active: boolean; onStatus: (value: Resource<unknown>) => void }) {
  const [session, setSession] = useState<AccountsSession>();
  const [capability, setCapability] = useState<AccountsCapability>();
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [hasFreshList, setHasFreshList] = useState(false);
  const [hasFreshCapability, setHasFreshCapability] = useState(false);
  const [selectedId, setSelectedId] = useState<string>();
  const [accessKey, setAccessKey] = useState("");
  const [username, setUsername] = useState("");
  const [domain, setDomain] = useState("");
  const [createReason, setCreateReason] = useState("");
  const [query, setQuery] = useState("");
  const [pending, setPending] = useState<PendingStateChange>();
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [sessionAttempt, setSessionAttempt] = useState(0);
  const [refreshAttempt, setRefreshAttempt] = useState(0);
  const stateDialog = useRef<HTMLDialogElement>(null);
  const createDialog = useRef<HTMLDialogElement>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const dialogReturnFocus = useRef<HTMLElement | null>(null);
  // Each error message the page shows, with what failed and the codes behind
  // it; say() files one and hands the message back for setError.
  const problems = useRef(new Map<string, Problem>());
  const say = useCallback((message: string, what: string, failure?: unknown, next?: string) => { problems.current.set(message, accountProblem(message, what, failure, next)); return message; }, []);
  const problemFor = (message: string): Problem => problems.current.get(message) ?? { what: "The account action did not finish.", why: message, next: "Use Refresh accounts and try again.", technical: "", status: 0 };

  const [webPreview, setWebPreview] = useState<AccountsWebPreview>();
  const [previewError, setPreviewError] = useState<string>();
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const previewGate = useRef(new PreviewRequestGate());
  const previewBusyRef = useRef(false);
  const previewTriggerRef = useRef<HTMLSpanElement>(null);
  const previewDismissFocus = useRef(false);
  // Update the comparison identity during render so late callbacks cannot win
  // the interval between a changed prop/state commit and effect cleanup.
  const previewContext = JSON.stringify([active, revision, session, refreshAttempt, sessionAttempt, busy, hasFreshList, hasFreshCapability, capability, accounts]);
  const previewContextRef = useRef(previewContext);
  previewContextRef.current = previewContext;
  const invalidatePreview = useCallback(() => {
    previewGate.current.invalidate(); previewBusyRef.current = false;
    setWebPreview(undefined); setPreviewError(undefined); setPreviewLoading(false); setPreviewOpen(false);
  }, []);
  useEffect(() => { invalidatePreview(); return () => previewGate.current.invalidate(); }, [previewContext, invalidatePreview]);

  const selected = accounts.find((account) => account.id === selectedId);
  const authenticated = session?.authenticated === true;
  useEffect(() => {
    if (!previewDismissFocus.current || previewOpen || previewLoading) return;
    previewDismissFocus.current = false;
    if (active && authenticated && !busy) previewTriggerRef.current?.querySelector("button")?.focus();
  }, [previewOpen, previewLoading, active, authenticated, busy]);
  const recoveryBlocked = capability?.reason === ACCOUNT_RECOVERY_REQUIRED || accounts.some((account) => account.state === "recovery_required");
  const mutationContextValid = Boolean(active && authenticated && capability?.available && hasFreshCapability && hasFreshList && !recoveryBlocked);
  const canMutate = mutationContextValid && !busy;
  const usernameValid = /^[a-z][a-z0-9_]{2,31}$/.test(username.trim());
  const stateCount = (state: Account["state"]) => accounts.filter((account) => account.state === state).length;
  const createReasonBytes = utf8Bytes(createReason);
  const createReasonValid = validAccountReason(createReason);
  const domainValid = validAccountDomain(domain);
  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return accounts;
    return accounts.filter((account) => [account.username, account.domain, account.home, account.public_html, String(account.uid), String(account.gid), account.state].some((value) => value.toLowerCase().includes(term)));
  }, [accounts, query]);

  const fail = useCallback((failure: unknown, what: string) => {
    setError(say(accountError(failure), what, failure));
    setHasFreshList(false);
    if (failure instanceof AccountsApiError && failure.status === 401) {
      setSession({ authenticated: false });
      setCapability(undefined);
      setHasFreshCapability(false);
    }
  }, [say]);

  const reload = useCallback(async (live?: () => boolean) => {
    const isLive = () => live?.() !== false;
    invalidatePreview();
    setBusy("Checking local operator session");
    setError(undefined);
    setHasFreshList(false);
    setHasFreshCapability(false);
    try {
      const nextSession = await getAccountsSession();
      if (!isLive()) return;
      setSession(nextSession);
      if (!nextSession.authenticated) {
        setCapability(undefined);
        setHasFreshCapability(false);
        setAccounts([]);
        setSelectedId(undefined);
        return;
      }
      const nextCapability = await getAccountsCapability();
      if (!isLive()) return;
      setCapability(nextCapability);
      setHasFreshCapability(true);
      if (!nextCapability.available && nextCapability.reason !== ACCOUNT_RECOVERY_REQUIRED) {
        setAccounts([]);
        setSelectedId(undefined);
        return;
      }
      const result = await getAccounts();
      if (!isLive()) return;
      setAccounts(result.items);
      setSelectedId((current) => result.items.some((account) => account.id === current) ? current : result.items[0]?.id);
      setHasFreshList(true);
      setLoadedAt(new Date());
    } catch (failure) {
      if (isLive()) fail(failure, "The account list could not be loaded.");
    } finally {
      if (isLive()) setBusy(undefined);
    }
  }, [fail, invalidatePreview]);

  useEffect(() => {
    if (!active) { setAccessKey(""); return; }
    let live = true;
    void reload(() => live);
    return () => { live = false; };
  }, [active, revision, sessionAttempt, refreshAttempt, reload]);

  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => {
      setSession({ authenticated: false });
      setError(say("Your local operator session expired. Sign in again; your creation draft is kept. Any state confirmation and its reason were cleared; refresh, review and enter a new reason.", "Your sign-in ended.", undefined, "Sign in again with the operator access key."));
    }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session, say]);
  useEffect(() => {
    if (mutationContextValid) return;
    for (const ref of [createDialog, stateDialog]) if (ref.current?.open) ref.current.close();
    setCreateOpen(false); setPending(undefined);
    dialogReturnFocus.current = null;
  }, [mutationContextValid]);
  useEffect(() => {
    if (pending && pending.accountId !== selectedId) setPending(undefined);
  }, [pending, selectedId]);
  useEffect(() => {
    if (mutationContextValid && pending && stateDialog.current && !stateDialog.current.open) stateDialog.current.showModal();
    else if (!pending && stateDialog.current?.open) stateDialog.current.close();
  }, [mutationContextValid, pending]);
  useEffect(() => {
    if (mutationContextValid && createOpen && createDialog.current && !createDialog.current.open) createDialog.current.showModal();
    else if (!createOpen && createDialog.current?.open) createDialog.current.close();
  }, [mutationContextValid, createOpen]);
  useEffect(() => {
    if (active && authenticated && !busy && !createOpen && !pending && dialogReturnFocus.current) {
      if (dialogReturnFocus.current.isConnected) dialogReturnFocus.current.focus();
      dialogReturnFocus.current = null;
    }
  }, [active, authenticated, busy, createOpen, pending]);
  const rememberDialogTrigger = () => { dialogReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; };

  async function login(event: React.FormEvent) {
    event.preventDefault();
    if (busy || !accessKey.trim()) return;
    const key = accessKey;
    setAccessKey("");
    invalidatePreview();
    setBusy("Signing in locally"); setError(undefined); setNotice(undefined);
    try {
      const nextSession = await loginAccountsSession(key);
      if (!nextSession.authenticated) throw new AccountsApiError(401, "unauthorized", "The local operator access key was not accepted.");
      setSession(nextSession);
      setCapability(undefined);
      setHasFreshCapability(false);
      setHasFreshList(false);
      const nextCapability = await getAccountsCapability();
      setCapability(nextCapability);
      setHasFreshCapability(true);
      if (nextCapability.available || nextCapability.reason === ACCOUNT_RECOVERY_REQUIRED) {
        const result = await getAccounts();
        setAccounts(result.items);
        setSelectedId((current) => result.items.some((account) => account.id === current) ? current : result.items[0]?.id);
        setHasFreshList(true);
      } else {
        setAccounts([]); setSelectedId(undefined);
      }
      setLoadedAt(new Date());
    } catch (failure) { fail(failure, "You were not signed in."); }
    finally { setBusy(undefined); }
  }

  async function create(event: React.FormEvent) {
    event.preventDefault();
    if (busy || !canMutate) return;
    const cleanUsername = username.trim();
    const cleanDomain = domain.trim();
    const cleanReason = createReason.trim();
    if (!/^[a-z][a-z0-9_]{2,31}$/.test(cleanUsername)) { setError(say("Username must be 3–32 characters: a lowercase letter followed by lowercase letters, numbers or underscores.", "The Linux account was not created.", undefined, "Correct the username, then create the account.")); return; }
    if (!validAccountDomain(cleanDomain)) { setError(say("Enter a lowercase DNS domain with at least two valid labels, no trailing dot, and no IP address.", "The Linux account was not created.", undefined, "Correct the domain, then create the account.")); return; }
    if (!validAccountReason(cleanReason)) { setError(say("Reason must be 1–500 UTF-8 bytes after trimming, with no control characters.", "The Linux account was not created.", undefined, "Shorten or correct the reason, then create the account.")); return; }
    if (!cleanDomain || !cleanReason || !session?.authenticated || !capability?.available || recoveryBlocked) return;
    invalidatePreview();
    setBusy("Creating Linux account"); setError(undefined); setNotice(undefined);
    try {
      const account = await createAccount({ username: cleanUsername, domain: cleanDomain, reason: cleanReason }, session.csrf_token);
      setAccounts((items) => [...items.filter((item) => item.id !== account.id), account]);
      setSelectedId(account.id); setUsername(""); setDomain(""); setCreateReason(""); setCreateOpen(false);
      setNotice(`Created Linux account ${account.username}.`); setLoadedAt(new Date());
    } catch (failure) { fail(failure, "The Linux account was not created."); }
    finally { setBusy(undefined); }
  }

  async function confirmStateChange(event: React.FormEvent) {
    event.preventDefault();
    if (!pending || !session?.authenticated || !canMutate || !pending.reason.trim() || busy) return;
    if (!validAccountReason(pending.reason)) { setError(say("Reason must be 1–500 UTF-8 bytes after trimming, with no control characters.", "The account state was not changed.", undefined, "Shorten or correct the reason, then confirm again.")); return; }
    if (recoveryBlocked) { setError(say("Account changes are disabled while an account requires recovery.", "The account state was not changed.", undefined, "Resolve the account's recovery, then use Refresh accounts.")); return; }
    const current = accounts.find((account) => account.id === pending.accountId);
    if (!current) { setError(say("This account is no longer in the current list. Refresh and review before trying again.", "The account state was not changed.", undefined, "Use Refresh accounts and choose the account again.")); return; }
    invalidatePreview();
    setBusy("Updating account state"); setError(undefined); setNotice(undefined);
    try {
      const account = await setAccountState(current, pending.state, pending.reason.trim(), session.csrf_token);
      setAccounts((items) => items.map((item) => item.id === account.id ? account : item));
      setPending(undefined); setNotice(`${account.username} is ${stateLabel(account.state)}.`); setLoadedAt(new Date());
    } catch (failure) {
      fail(failure, "The account state was not changed.");
      const detail = accountError(failure).replaceAll("Your form values are kept", "Your creation draft is kept").replaceAll("your form values are kept", "your creation draft is kept");
      setError(say(`${detail} The state change could not be confirmed. The previous confirmation and its reason were cleared. Refresh and reconcile the account, then begin a new confirmation with a new reason.`, "The account state was not changed.", failure));
    }
    finally { setBusy(undefined); }
  }

  async function signOut() {
    if (!session?.authenticated || busy) return;
    invalidatePreview();
    setBusy("Signing out locally"); setError(undefined); setNotice(undefined);
    try {
      const signedOut = await logoutAccountsSession(session.csrf_token);
      if (signedOut.authenticated) throw new AccountsApiError(0, "invalid_response", "Local sign-out could not be confirmed.");
      setSession(signedOut); setCapability(undefined); setHasFreshCapability(false); setHasFreshList(false); setAccounts([]); setSelectedId(undefined);
    } catch (failure) { fail(failure, "You were not signed out."); }
    finally { setBusy(undefined); }
  }

  async function requestWebPreview() {
    if (!active || !authenticated || busy || previewBusyRef.current) return;
    previewBusyRef.current = true;
    const identity = previewContextRef.current;
    const request = previewGate.current.begin();
    const current = () => request.current() && previewContextRef.current === identity;
    setWebPreview(undefined); setPreviewError(undefined); setPreviewOpen(true); setPreviewLoading(true);
    try {
      const result = await getAccountsWebPreview(request.signal);
      if (current()) setWebPreview(result);
    } catch (failure) {
      if (!current()) return;
      const detail = say(failure instanceof AccountsWebPreviewError ? failure.message : "The preview could not be read. Retry after checking the local connection.", "The web configuration preview could not be read.", failure);
      setPreviewError(detail);
      if (failure instanceof AccountsWebPreviewError && failure.status === 401) {
        setSession({ authenticated: false }); setCapability(undefined); setHasFreshCapability(false); setHasFreshList(false);
        setError(detail);
      } else if (failure instanceof AccountsWebPreviewError && failure.status === 409) {
        setHasFreshList(false); setError(detail);
      }
    } finally { if (current()) { previewBusyRef.current = false; setPreviewLoading(false); } }
  }

  return <div className="@container flex w-full max-w-[90rem] min-w-0 flex-col gap-4" data-testid="accounts-view">
    {error && !pending && !createOpen && <ProblemAlert problem={problemFor(error)} testId="accounts-problem" />}
    {notice && <Alert role="status" className="text-start"><CircleCheck className="text-primary" aria-hidden="true" /><AlertTitle className="wrap-anywhere">{notice}</AlertTitle></Alert>}
    {!session ? <section className={`${panel} max-w-xl p-5`} aria-label="Operator session">
      <div role="status" className="text-sm text-foreground">{busy || (error ? "Operator session could not be checked." : "Checking operator session…")}</div>
      {error && <Button variant="outline" className={`mt-3 ${rowControl}`} disabled={Boolean(busy)} onClick={() => setSessionAttempt((attempt) => attempt + 1)}><RefreshCw aria-hidden="true" />Retry operator session</Button>}
    </section> : !authenticated ? <section className={`${panel} max-w-xl p-5`} aria-labelledby="accounts-sign-in-heading">
      <div className="flex items-start gap-3.5">
        <LockKeyhole className="size-6 shrink-0 text-primary" aria-hidden="true" />
        <div className="min-w-0"><h2 id="accounts-sign-in-heading">Local operator sign-in</h2><div className="mt-1.5 text-sm text-muted-foreground wrap-anywhere">Use the access key created by this server in its private state directory.</div></div>
      </div>
      <form onSubmit={login} data-testid="operator-login" autoComplete="off" className="mt-6 flex flex-col items-start gap-2.5">
        <label htmlFor="accounts-access-key" className="text-sm font-medium text-foreground">Operator access key</label>
        <Input id="accounts-access-key" type="password" value={accessKey} onChange={(event) => setAccessKey(event.target.value)} required autoComplete="off" spellCheck={false} disabled={Boolean(busy)} className={`${control} max-w-sm`} />
        <Button type="submit" className={rowControl} disabled={Boolean(busy) || !accessKey.trim()}><Busy when={busy === "Signing in locally"} />Sign in locally</Button>
      </form>
      <div className="mt-5 text-xs text-muted-foreground">The key is cleared after submission and is not saved in this browser. This is a local operator session.</div>
    </section> : <>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 text-sm text-muted-foreground">
        <span className="flex min-w-0 items-center gap-2 wrap-anywhere"><LockKeyhole className="size-4 shrink-0" aria-hidden="true" />Signed in locally · expires {session.authenticated ? dateLabel(session.expires_at) : ""}</span>
        <Button variant="ghost" size="sm" className="pointer-coarse:h-11" disabled={Boolean(busy)} onClick={() => void signOut()}><LogOut aria-hidden="true" />Sign out locally</Button>
      </div>
      <Alert role={capability?.available ? "status" : "alert"} className="text-start" data-testid="accounts-capability">
        <Info aria-hidden="true" />
        <AlertTitle className="text-sm! text-foreground">Linux account identities and home directories. <span className="font-normal text-muted-foreground">Web, DNS and mail setup is still in development.</span></AlertTitle>
        <AlertDescription className="flex flex-col items-start gap-2 text-start">
          {capability && <div className="text-sm text-foreground wrap-anywhere">{capabilityCopy(capability, hasFreshCapability)}</div>}
          {capability && !capability.available && capability.reason !== ACCOUNT_RECOVERY_REQUIRED && <Button variant="outline" size="sm" className="pointer-coarse:h-11" disabled={Boolean(busy)} onClick={() => { invalidatePreview(); setRefreshAttempt((value) => value + 1); }}><RefreshCw aria-hidden="true" />Check broker again</Button>}
        </AlertDescription>
      </Alert>
      <section className={`${panel} min-w-0 p-4`} aria-labelledby="accounts-preview-heading" data-testid="accounts-web-preview">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1 basis-64"><h2 id="accounts-preview-heading" className="text-base!">Inventory web configuration preview</h2><div className="mt-1 text-sm text-muted-foreground">Broker snapshot for the full managed inventory, independent of selection or search.</div></div>
          <span className="shrink-0" ref={previewTriggerRef}><Button variant="outline" size="sm" className="pointer-coarse:h-11" disabled={!active || !authenticated || Boolean(busy) || previewLoading} onClick={() => void requestWebPreview()}><Busy when={previewLoading} />{previewLoading ? "Reading web preview…" : "Preview web configuration"}</Button></span>
        </div>
        <div className="mt-3 text-xs text-muted-foreground">Configuration preview only; no files applied or serving status checked. Existing broker verification may record recovery when native identity drift is detected.</div>
        {previewOpen && <div className="mt-3 flex flex-col items-start gap-3 border-t border-border pt-3 text-sm" aria-live="polite" aria-busy={previewLoading}>
          {previewLoading && <div role="status" className="text-foreground">Reading a verified broker snapshot…</div>}
          {previewError && <ProblemAlert problem={problemFor(previewError)} testId="accounts-preview-problem" />}
          {webPreview && <>
            <div role="status" className="text-foreground">Preview received. It is a point-in-time broker snapshot, not a guarantee that the inventory remains unchanged.</div>
            <dl className="grid w-full gap-3 @xl:grid-cols-2">
              <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Profile</dt><dd className="wrap-anywhere text-foreground">{webPreview.profile}</dd></div>
              <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Snapshot accounts</dt><dd className="text-foreground">{webPreview.accounts} total · {webPreview.active_accounts} active · {webPreview.suspended_accounts} suspended</dd></div>
            </dl>
            <details className="w-full">
              <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Snapshot fingerprints</summary>
              <dl className="mt-2 grid gap-3">
                <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Profile SHA-256</dt><dd><code className="font-mono text-xs break-all text-foreground">{webPreview.profile_sha256}</code></dd></div>
                <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Snapshot SHA-256</dt><dd><code className="font-mono text-xs break-all text-foreground">{webPreview.snapshot_sha256}</code></dd></div>
                <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Bundle SHA-256</dt><dd><code className="font-mono text-xs break-all text-foreground">{webPreview.bundle_sha256}</code></dd></div>
              </dl>
            </details>
            <details className="w-full">
              <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Generated artifact metadata ({webPreview.files.length})</summary>
              <ul className="m-0 mt-2 list-none p-0">{webPreview.files.map((file) => <li key={file.path} className="flex min-w-0 flex-col gap-1 border-t border-border py-2.5">
                <strong className="font-medium wrap-anywhere text-foreground">{file.path}</strong>
                <span className="text-xs text-muted-foreground">{file.bytes.toLocaleString()} bytes · mode {file.mode.toString(8).padStart(4, "0")}</span>
                <code className="font-mono text-xs break-all text-muted-foreground">{file.sha256}</code>
              </li>)}</ul>
            </details>
          </>}
          <Button variant="ghost" size="sm" className="pointer-coarse:h-11" onClick={() => { previewDismissFocus.current = true; invalidatePreview(); }}>Dismiss web preview</Button>
        </div>}
      </section>
      {(capability?.available || capability?.reason === ACCOUNT_RECOVERY_REQUIRED) && <>
        {recoveryBlocked && <Alert variant="destructive" className="text-start" data-testid="accounts-recovery"><Info aria-hidden="true" /><AlertTitle className="wrap-anywhere">An account requires recovery. All account changes are disabled until recovery is resolved.</AlertTitle></Alert>}
        {capability.available && !hasFreshList && <Alert role="status" className="text-start"><Info aria-hidden="true" /><AlertTitle className="wrap-anywhere">The account list is not current. Refresh and review it before changing accounts.</AlertTitle></Alert>}
        <section className={`${panel} flex flex-wrap items-center justify-between gap-x-5 gap-y-3 p-4`} aria-labelledby="accounts-inventory-heading">
          <div className="min-w-0">
            <h2 id="accounts-inventory-heading" className="text-base!">Account inventory</h2>
            <div className="mt-1 text-sm text-muted-foreground wrap-anywhere">{hasFreshList ? <><strong className="font-semibold text-foreground">{accounts.length}</strong> {accounts.length === 1 ? "account" : "accounts"} · {stateCount("active")} active · {stateCount("suspended")} suspended{stateCount("recovery_required") > 0 && <> · {stateCount("recovery_required")} need recovery</>}</> : busy ? "Refreshing account inventory…" : accounts.length ? `${accounts.length} previously loaded accounts · refresh required` : "Account inventory unavailable · refresh required"}</div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" className={rowControl} disabled={Boolean(busy)} onClick={() => { invalidatePreview(); setError(undefined); setRefreshAttempt((value) => value + 1); }}><RefreshCw aria-hidden="true" />Refresh accounts</Button>
            <Button className={rowControl} disabled={!canMutate} onClick={() => { if (!canMutate) return; rememberDialogTrigger(); setError(undefined); setCreateOpen(true); }}><Plus aria-hidden="true" />Create Linux account</Button>
          </div>
        </section>
        <div className="grid min-w-0 items-start gap-4 @4xl:grid-cols-[minmax(16rem,20rem)_minmax(0,1fr)]">
          <section className={`${panel} min-w-0`} aria-labelledby="accounts-list-heading">
            <div className="flex items-baseline justify-between gap-3 p-4 pb-3"><h2 id="accounts-list-heading" className="text-sm!">Accounts</h2>{hasFreshList && <span className="text-sm text-muted-foreground">{filtered.length}{query.trim() && <> of {accounts.length}</>}</span>}</div>
            <div className="relative mx-3 mb-3">
              <Search className="pointer-events-none absolute top-1/2 inset-s-3 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
              <Input type="search" aria-label="Search accounts" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="User, domain, UID or home…" autoComplete="off" spellCheck={false} className={`${control} ps-9!`} />
            </div>
            <ul className="m-0 flex max-h-[30rem] list-none flex-col gap-0.5 overflow-y-auto overscroll-contain px-2 pb-2" aria-label="Linux accounts">
              {filtered.map((account) => <li key={account.id}>
                <button type="button" className="flex w-full min-w-0 items-start gap-2.5 rounded-md px-2.5 py-2.5 text-start text-sm text-foreground hover:bg-muted disabled:cursor-default disabled:hover:bg-transparent aria-[current=true]:bg-secondary aria-[current=true]:shadow-[inset_2px_0_var(--primary)] rtl:aria-[current=true]:shadow-[inset_-2px_0_var(--primary)] pointer-coarse:min-h-12" aria-label={`Open Linux account ${account.username}`} aria-current={selectedId === account.id ? "true" : undefined} disabled={Boolean(busy)} onClick={() => setSelectedId(account.id)}>
                  <UserRound className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <span className="flex min-w-0 flex-1 flex-col gap-0.5"><span className="font-medium wrap-anywhere">{account.username}</span><span className="text-xs text-muted-foreground wrap-anywhere">{account.domain}</span><span className="text-xs text-muted-foreground">UID {account.uid} · GID {account.gid}</span></span>
                  <Badge variant={stateTone[account.state]} className="shrink-0 capitalize">{stateLabel(account.state)}</Badge>
                </button>
              </li>)}
            </ul>
            {!filtered.length && <div className="flex flex-col items-start gap-2 px-4 pb-4 text-sm text-muted-foreground" data-testid="accounts-empty">{!hasFreshList ? <span>{busy ? "Loading account records…" : "Current account records are unavailable. Refresh to review."}</span> : accounts.length ? <><span>No matching accounts.</span><Button variant="link" className="h-auto p-0" onClick={() => setQuery("")}>Clear search</Button></> : <span>No Linux accounts returned. Create an account after reviewing the broker prerequisites.</span>}</div>}
          </section>
          {selected ? <section className={`${panel} min-w-0`} aria-labelledby="account-detail-heading" data-testid="account-details" data-account-id={selected.id} data-revision={selected.revision}>
            <div className="flex flex-wrap items-start justify-between gap-3 p-4">
              <div className="min-w-0">
                <span className="text-xs text-muted-foreground">Selected Linux account{!hasFreshList && " · refresh required"}</span>
                <h2 id="account-detail-heading" className="mt-0.5 wrap-anywhere">{selected.username}</h2>
                <div className="mt-1 text-sm text-muted-foreground wrap-anywhere">{selected.domain}</div>
              </div>
              <Badge variant={stateTone[selected.state]} className="capitalize">{stateLabel(selected.state)}</Badge>
            </div>
            <dl className="grid gap-4 px-4 pb-4 grid-cols-2 @2xl:grid-cols-3">
              {([["UID", selected.uid], ["GID", selected.gid], ["Revision", selected.revision], ["Home", selected.home], ["Public HTML", selected.public_html], ["Updated", dateLabel(selected.updated_at)]] as const).map(([term, value]) => <div key={term} className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">{term}</dt><dd className="text-sm wrap-anywhere text-foreground">{value}</dd></div>)}
            </dl>
            {selected.state !== "recovery_required" && <div className="border-t border-border p-4"><Button variant="outline" className={rowControl} disabled={!canMutate} onClick={() => { if (!canMutate) return; rememberDialogTrigger(); setError(undefined); setPending({ accountId: selected.id, state: selected.state === "active" ? "suspended" : "active", reason: "" }); }}>{selected.state === "active" ? "Suspend account" : "Activate account"}</Button></div>}
            {selected.state === "recovery_required" && <div className="border-t border-border p-4 text-sm text-foreground" role="status">This account requires recovery. State changes are unavailable until recovery is resolved.</div>}
          </section> : <Empty className={`${panel} items-start p-6 text-start`} data-testid="account-details-empty">
            <EmptyHeader className="items-start text-start">
              <EmptyMedia variant="icon"><Users aria-hidden="true" /></EmptyMedia>
              <EmptyTitle>{!hasFreshList ? "Account records unavailable" : accounts.length ? "Select an account" : "Your account workspace"}</EmptyTitle>
              <EmptyDescription className="text-start">{!hasFreshList ? "Refresh the broker status and inventory before changing accounts." : "Review actual Linux identities and home directories here. Domain values are metadata; no DNS or web setup is provided."}</EmptyDescription>
            </EmptyHeader>
          </Empty>}
        </div>
      </>}
    </>}
    {busy && <div className="text-xs text-muted-foreground" role="status">{busy}…</div>}
    <dialog ref={createDialog} className={dialogClass} aria-labelledby="account-create-title" aria-describedby="account-create-description" onClose={() => setCreateOpen(false)} onCancel={(event) => { if (busy) event.preventDefault(); else setCreateOpen(false); }}>
      <h1 id="account-create-title" className="pb-2 text-lg! tracking-tight!">Create Linux account</h1>
      <div id="account-create-description" className="mb-4 text-sm text-muted-foreground wrap-anywhere">Creates an OS identity and home directory through the available local broker. Domain is reserved metadata; this does not set up a website, DNS or mail.</div>
      <form onSubmit={create} data-testid="account-create-form" className="flex flex-col gap-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="flex min-w-0 flex-col gap-1.5">
            <label htmlFor="account-username" className="text-sm font-medium text-foreground">Username</label>
            <Input id="account-username" value={username} onChange={(event) => setUsername(event.target.value)} required autoFocus aria-invalid={Boolean(username.trim()) && !usernameValid} maxLength={32} minLength={3} pattern="[a-z][a-z0-9_]{2,31}" autoCapitalize="none" autoComplete="off" spellCheck={false} disabled={Boolean(busy)} aria-describedby="account-username-help" className={control} />
            <div id="account-username-help" className="text-xs text-muted-foreground">3–32 lowercase letters, numbers or underscores; starts with a letter.</div>
          </div>
          <div className="flex min-w-0 flex-col gap-1.5">
            <label htmlFor="account-domain" className="text-sm font-medium text-foreground">Domain</label>
            <Input id="account-domain" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.test" required maxLength={253} autoCapitalize="none" autoComplete="off" spellCheck={false} disabled={Boolean(busy)} aria-invalid={Boolean(domain.trim()) && !domainValid} aria-describedby="account-domain-help" className={control} />
            <div id="account-domain-help" className={`text-xs ${Boolean(domain.trim()) && !domainValid ? "text-destructive" : "text-muted-foreground"}`}>{Boolean(domain.trim()) && !domainValid ? "Use lowercase DNS labels (2 or more), without a trailing dot or IP address." : "Reserved account metadata; this does not configure DNS or a website."}</div>
          </div>
        </div>
        <div className="flex min-w-0 flex-col gap-1.5">
          <label htmlFor="account-create-reason" className="text-sm font-medium text-foreground">Reason</label>
          <Textarea id="account-create-reason" value={createReason} onChange={(event) => setCreateReason(event.target.value)} required maxLength={500} rows={2} disabled={Boolean(busy)} aria-invalid={Boolean(createReason.trim()) && !createReasonValid} aria-describedby="account-create-reason-help" className="text-sm!" />
          <div id="account-create-reason-help" className={`text-xs ${Boolean(createReason.trim()) && !createReasonValid ? "text-destructive" : "text-muted-foreground"}`}>{createReasonBytes}/500 UTF-8 bytes · trimmed, without control characters.</div>
        </div>
        {error && <ProblemAlert problem={problemFor(error)} testId="account-create-problem" />}
        <div className="flex flex-wrap justify-end gap-2"><Button type="button" variant="ghost" className={rowControl} disabled={Boolean(busy)} onClick={() => setCreateOpen(false)}>Cancel creation</Button><Button type="submit" className={rowControl} disabled={!canMutate || !usernameValid || !domainValid || !createReasonValid}><Busy when={busy === "Creating Linux account"} />Create Linux account</Button></div>
      </form>
    </dialog>
    <dialog ref={stateDialog} className={dialogClass} aria-labelledby="account-state-title" onClose={() => setPending(undefined)} onCancel={(event) => { if (busy) event.preventDefault(); else setPending(undefined); }}>
      {pending && (() => {
        const account = accounts.find((item) => item.id === pending.accountId);
        return <form onSubmit={confirmStateChange} className="flex flex-col gap-3">
          <h1 id="account-state-title" className="text-lg! tracking-tight!">{pending.state === "suspended" ? "Suspend this Linux account?" : "Activate this Linux account?"}</h1>
          <div className="text-sm text-foreground wrap-anywhere">{account ? <><strong className="font-semibold">{account.username}</strong> · {account.domain} · current revision {account.revision}</> : "The selected account is no longer in the current list."}</div>
          <div className="text-sm text-muted-foreground wrap-anywhere">{pending.state === "suspended" ? "This restricts new account access through PAM-aware login paths. Existing processes, websites, mail and databases are unaffected; this is not a full hosting suspension." : "This clears the PAM account expiration. The password remains locked and the shell remains nologin; this does not configure web, DNS or mail."}</div>
          {error && <ProblemAlert problem={problemFor(error)} testId="account-state-problem" />}
          <div className="flex min-w-0 flex-col gap-1.5">
            <label htmlFor="account-state-reason" className="text-sm font-medium text-foreground">Reason</label>
            <Textarea id="account-state-reason" value={pending.reason} onChange={(event) => setPending({ ...pending, reason: event.target.value })} required maxLength={500} rows={3} disabled={!canMutate} aria-invalid={Boolean(pending.reason.trim()) && !validAccountReason(pending.reason)} aria-describedby="account-state-reason-help" className="text-sm!" />
            <div id="account-state-reason-help" className={`text-xs ${Boolean(pending.reason.trim()) && !validAccountReason(pending.reason) ? "text-destructive" : "text-muted-foreground"}`}>{utf8Bytes(pending.reason)}/500 UTF-8 bytes · trimmed, without control characters.</div>
          </div>
          <div className="mt-2 flex flex-wrap justify-end gap-2">{error && <Button type="button" variant="ghost" className={rowControl} disabled={Boolean(busy)} onClick={() => { invalidatePreview(); setError(undefined); setRefreshAttempt((value) => value + 1); }}><RefreshCw aria-hidden="true" />Refresh accounts</Button>}<Button type="button" variant="ghost" className={rowControl} disabled={Boolean(busy)} onClick={() => setPending(undefined)}>Cancel</Button><Button type="submit" className={rowControl} disabled={!canMutate || !validAccountReason(pending.reason) || !account}><Busy when={busy === "Updating account state"} />{`Confirm ${pending.state === "suspended" ? "suspension" : "activation"}`}</Button></div>
        </form>;
      })()}
    </dialog>
  </div>;
}
