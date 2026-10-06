import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Info, LockKeyhole, LogOut, Plus, RefreshCw, Search, UserRound, Users } from "lucide-react";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import {
  ACCOUNT_RECOVERY_REQUIRED, AccountsApiError, createAccount, getAccounts, getAccountsCapability, getAccountsSession,
  loginAccountsSession, logoutAccountsSession, setAccountState, validAccountDomain, validAccountReason,
} from "@/lib/accounts-api";
import type { Account, AccountsCapability, AccountsSession } from "@/lib/accounts-api";
import "@/accounts.css";

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

  const selected = accounts.find((account) => account.id === selectedId);
  const authenticated = session?.authenticated === true;
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

  const fail = useCallback((failure: unknown) => {
    setError(accountError(failure));
    setHasFreshList(false);
    if (failure instanceof AccountsApiError && failure.status === 401) {
      setSession({ authenticated: false });
      setCapability(undefined);
      setHasFreshCapability(false);
    }
  }, []);

  const reload = useCallback(async (live?: () => boolean) => {
    const isLive = () => live?.() !== false;
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
      if (isLive()) fail(failure);
    } finally {
      if (isLive()) setBusy(undefined);
    }
  }, [fail]);

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
      setError("Your local operator session expired. Sign in again; your creation draft is kept. Any state confirmation and its reason were cleared; refresh, review and enter a new reason.");
    }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session]);
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
    } catch (failure) { fail(failure); }
    finally { setBusy(undefined); }
  }

  async function create(event: React.FormEvent) {
    event.preventDefault();
    if (busy || !canMutate) return;
    const cleanUsername = username.trim();
    const cleanDomain = domain.trim();
    const cleanReason = createReason.trim();
    if (!/^[a-z][a-z0-9_]{2,31}$/.test(cleanUsername)) { setError("Username must be 3–32 characters: a lowercase letter followed by lowercase letters, numbers or underscores."); return; }
    if (!validAccountDomain(cleanDomain)) { setError("Enter a lowercase DNS domain with at least two valid labels, no trailing dot, and no IP address."); return; }
    if (!validAccountReason(cleanReason)) { setError("Reason must be 1–500 UTF-8 bytes after trimming, with no control characters."); return; }
    if (!cleanDomain || !cleanReason || !session?.authenticated || !capability?.available || recoveryBlocked) return;
    setBusy("Creating Linux account"); setError(undefined); setNotice(undefined);
    try {
      const account = await createAccount({ username: cleanUsername, domain: cleanDomain, reason: cleanReason }, session.csrf_token);
      setAccounts((items) => [...items.filter((item) => item.id !== account.id), account]);
      setSelectedId(account.id); setUsername(""); setDomain(""); setCreateReason(""); setCreateOpen(false);
      setNotice(`Created Linux account ${account.username}.`); setLoadedAt(new Date());
    } catch (failure) { fail(failure); }
    finally { setBusy(undefined); }
  }

  async function confirmStateChange(event: React.FormEvent) {
    event.preventDefault();
    if (!pending || !session?.authenticated || !canMutate || !pending.reason.trim() || busy) return;
    if (!validAccountReason(pending.reason)) { setError("Reason must be 1–500 UTF-8 bytes after trimming, with no control characters."); return; }
    if (recoveryBlocked) { setError("Account changes are disabled while an account requires recovery."); return; }
    const current = accounts.find((account) => account.id === pending.accountId);
    if (!current) { setError("This account is no longer in the current list. Refresh and review before trying again."); return; }
    setBusy("Updating account state"); setError(undefined); setNotice(undefined);
    try {
      const account = await setAccountState(current, pending.state, pending.reason.trim(), session.csrf_token);
      setAccounts((items) => items.map((item) => item.id === account.id ? account : item));
      setPending(undefined); setNotice(`${account.username} is ${stateLabel(account.state)}.`); setLoadedAt(new Date());
    } catch (failure) {
      fail(failure);
      const detail = accountError(failure).replaceAll("Your form values are kept", "Your creation draft is kept").replaceAll("your form values are kept", "your creation draft is kept");
      setError(`${detail} The state change could not be confirmed. The previous confirmation and its reason were cleared. Refresh and reconcile the account, then begin a new confirmation with a new reason.`);
    }
    finally { setBusy(undefined); }
  }

  async function signOut() {
    if (!session?.authenticated || busy) return;
    setBusy("Signing out locally"); setError(undefined); setNotice(undefined);
    try {
      const signedOut = await logoutAccountsSession(session.csrf_token);
      if (signedOut.authenticated) throw new AccountsApiError(0, "invalid_response", "Local sign-out could not be confirmed.");
      setSession(signedOut); setCapability(undefined); setHasFreshCapability(false); setHasFreshList(false); setAccounts([]); setSelectedId(undefined);
    } catch (failure) { fail(failure); }
    finally { setBusy(undefined); }
  }

  return <section className="accounts-view accounts-workspace" data-testid="accounts-view">
    {error && !pending && !createOpen && <div className="account-message account-error" role="alert"><Info /><span>{error}</span></div>}
    {notice && <div className="account-message" role="status"><Info /><span>{notice}</span></div>}
    {!session ? <Card className="dashboard-card account-auth" padding={0}>
      <p role="status">{busy || (error ? "Operator session could not be checked." : "Checking operator session…")}</p>
      {error && <Button label="Retry operator session" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={() => setSessionAttempt((attempt) => attempt + 1)} />}
    </Card> : !authenticated ? <Card className="dashboard-card account-auth" padding={0}>
      <div className="account-auth-heading"><LockKeyhole /><div><h2>Local operator sign-in</h2><p>Use the access key created by this server in its private state directory.</p></div></div>
      <form onSubmit={login} data-testid="operator-login" autoComplete="off">
        <label htmlFor="accounts-access-key">Operator access key</label>
        <input id="accounts-access-key" type="password" value={accessKey} onChange={(event) => setAccessKey(event.target.value)} required autoComplete="off" spellCheck={false} disabled={Boolean(busy)} />
        <Button label="Sign in locally" type="submit" variant="primary" isLoading={busy === "Signing in locally"} isDisabled={Boolean(busy) || !accessKey.trim()} />
      </form>
      <p className="account-help">The key is cleared after submission and is not saved in this browser. This is a local operator session.</p>
    </Card> : <>
      <div className="account-session"><span><LockKeyhole />Signed in locally · expires {session.authenticated ? dateLabel(session.expires_at) : ""}</span><Button label="Sign out locally" icon={<LogOut />} variant="ghost" size="sm" isDisabled={Boolean(busy)} onClick={() => void signOut()} /></div>
      <div className="account-capability" role={capability?.available ? "status" : "alert"}>
        <Info aria-hidden="true" />
        <div><strong>Linux account identities and home directories.</strong><span> Web, DNS and mail setup is still in development.</span>
          {capability && <p>{capabilityCopy(capability, hasFreshCapability)}</p>}
        </div>
        {capability && !capability.available && capability.reason !== ACCOUNT_RECOVERY_REQUIRED && <Button label="Check broker again" variant="ghost" size="sm" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={() => setRefreshAttempt((value) => value + 1)} />}
      </div>
      {(capability?.available || capability?.reason === ACCOUNT_RECOVERY_REQUIRED) && <>
        {recoveryBlocked && <div className="account-message account-recovery-notice" role="alert"><Info /><span>An account requires recovery. All account changes are disabled until recovery is resolved.</span></div>}
        {capability.available && !hasFreshList && <div className="account-message account-refresh-notice" role="status"><Info /><span>The account list is not current. Refresh and review it before changing accounts.</span></div>}
        <Card className="dashboard-card account-inventory-toolbar" padding={0}>
          <div className="account-inventory-heading"><h2>Account inventory</h2><p>{hasFreshList ? <><strong>{accounts.length}</strong> {accounts.length === 1 ? "account" : "accounts"} · {stateCount("active")} active · {stateCount("suspended")} suspended{stateCount("recovery_required") > 0 && <> · {stateCount("recovery_required")} need recovery</>}</> : busy ? "Refreshing account inventory…" : accounts.length ? `${accounts.length} previously loaded accounts · refresh required` : "Account inventory unavailable · refresh required"}</p></div>
          <div className="account-inventory-actions"><Button label="Refresh accounts" icon={<RefreshCw />} variant="ghost" size="sm" isDisabled={Boolean(busy)} onClick={() => { setError(undefined); setRefreshAttempt((value) => value + 1); }} /><Button label="Create Linux account" icon={<Plus />} variant="primary" size="sm" isDisabled={!canMutate} onClick={() => { if (!canMutate) return; rememberDialogTrigger(); setError(undefined); setCreateOpen(true); }} /></div>
        </Card>
        <div className="account-layout">
          <Card className="dashboard-card account-list" padding={0}>
            <div className="card-heading"><h2>Accounts</h2>{hasFreshList && <span>{filtered.length}{query.trim() && <> of {accounts.length}</>}</span>}</div>
            <label className="compact-search"><Search aria-hidden="true" /><input type="search" aria-label="Search accounts" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="User, domain, UID or home…" /></label>
            <div className="account-list-items">{filtered.map((account) => <button key={account.id} type="button" className="account-list-item" aria-label={`Open Linux account ${account.username}`} aria-current={selectedId === account.id ? "true" : undefined} disabled={Boolean(busy)} onClick={() => setSelectedId(account.id)}><UserRound aria-hidden="true" /><span><strong>{account.username}</strong><small>{account.domain}</small><small>UID {account.uid} · GID {account.gid}</small></span><span className={`account-state account-state-${account.state}`}>{stateLabel(account.state)}</span></button>)}{!filtered.length && <div className="account-empty">{!hasFreshList ? <p>{busy ? "Loading account records…" : "Current account records are unavailable. Refresh to review."}</p> : accounts.length ? <><p>No matching accounts.</p><button type="button" className="account-text-action" onClick={() => setQuery("")}>Clear search</button></> : <p>No Linux accounts returned. Create an account after reviewing the broker prerequisites.</p>}</div>}</div>
          </Card>
          {selected ? <Card className="dashboard-card account-detail" padding={0} data-testid="account-details" data-account-id={selected.id} data-revision={selected.revision}>
            <div className="card-heading"><div><span className="account-selected-label">Selected Linux account{!hasFreshList && " · refresh required"}</span><h2>{selected.username}</h2><p>{selected.domain}</p></div><span className={`account-state account-state-${selected.state}`}>{stateLabel(selected.state)}</span></div>
            <dl><div><dt>UID</dt><dd>{selected.uid}</dd></div><div><dt>GID</dt><dd>{selected.gid}</dd></div><div><dt>Revision</dt><dd>{selected.revision}</dd></div><div><dt>Home</dt><dd>{selected.home}</dd></div><div><dt>Public HTML</dt><dd>{selected.public_html}</dd></div><div><dt>Updated</dt><dd>{dateLabel(selected.updated_at)}</dd></div></dl>
            <div className="account-actions">{selected.state !== "recovery_required" && <Button label={selected.state === "active" ? "Suspend account" : "Activate account"} variant="secondary" size="sm" isDisabled={!canMutate} onClick={() => { if (!canMutate) return; rememberDialogTrigger(); setError(undefined); setPending({ accountId: selected.id, state: selected.state === "active" ? "suspended" : "active", reason: "" }); }} />}</div>
            {selected.state === "recovery_required" && <p className="account-message" role="status">This account requires recovery. State changes are unavailable until recovery is resolved.</p>}
          </Card> : <Card className="dashboard-card account-detail account-no-selection" padding={0}><Users aria-hidden="true" /><div><h2>{!hasFreshList ? "Account records unavailable" : accounts.length ? "Select an account" : "Your account workspace"}</h2><p>{!hasFreshList ? "Refresh the broker status and inventory before changing accounts." : "Review actual Linux identities and home directories here. Domain values are metadata; no DNS or web setup is provided."}</p></div></Card>}
        </div>
      </>}
    </>}
    {busy && <p className="account-busy" role="status">{busy}…</p>}
    <dialog ref={createDialog} className="account-create account-create-dialog" aria-labelledby="account-create-title" aria-describedby="account-create-description" onClose={() => setCreateOpen(false)} onCancel={(event) => { if (busy) event.preventDefault(); else setCreateOpen(false); }}>
      <h2 id="account-create-title">Create Linux account</h2><p id="account-create-description">Creates an OS identity and home directory through the available local broker. Domain is reserved metadata; this does not set up a website, DNS or mail.</p>
          <form onSubmit={create} data-testid="account-create-form">
            <div className="account-create-fields">
              <div><label htmlFor="account-username">Username</label><input id="account-username" value={username} onChange={(event) => setUsername(event.target.value)} required autoFocus aria-invalid={Boolean(username.trim()) && !usernameValid} maxLength={32} minLength={3} pattern="[a-z][a-z0-9_]{2,31}" autoCapitalize="none" autoComplete="off" spellCheck={false} disabled={Boolean(busy)} aria-describedby="account-username-help" /><p id="account-username-help" className="account-help">3–32 lowercase letters, numbers or underscores; starts with a letter.</p></div>
              <div><label htmlFor="account-domain">Domain</label><input id="account-domain" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.test" required maxLength={253} autoCapitalize="none" autoComplete="off" spellCheck={false} disabled={Boolean(busy)} aria-invalid={Boolean(domain.trim()) && !domainValid} aria-describedby="account-domain-help" /><p id="account-domain-help" className={`account-help ${Boolean(domain.trim()) && !domainValid ? "account-error" : ""}`}>{Boolean(domain.trim()) && !domainValid ? "Use lowercase DNS labels (2 or more), without a trailing dot or IP address." : "Reserved account metadata; this does not configure DNS or a website."}</p></div>
            </div>
            <div className="account-reason-field"><label htmlFor="account-create-reason">Reason</label><textarea id="account-create-reason" value={createReason} onChange={(event) => setCreateReason(event.target.value)} required maxLength={500} rows={2} disabled={Boolean(busy)} aria-invalid={Boolean(createReason.trim()) && !createReasonValid} aria-describedby="account-create-reason-help" /><p id="account-create-reason-help" className={`account-help ${Boolean(createReason.trim()) && !createReasonValid ? "account-error" : ""}`}>{createReasonBytes}/500 UTF-8 bytes · trimmed, without control characters.</p></div>
            {error && <div className="account-message account-error" role="alert"><Info /><span>{error}</span></div>}
            <div className="account-dialog-actions"><Button label="Cancel creation" variant="ghost" type="button" isDisabled={Boolean(busy)} onClick={() => setCreateOpen(false)} /><Button label="Create Linux account" type="submit" variant="primary" isLoading={busy === "Creating Linux account"} isDisabled={!canMutate || !usernameValid || !domainValid || !createReasonValid} /></div>
          </form>
    </dialog>
    <dialog ref={stateDialog} className="account-state-dialog" aria-labelledby="account-state-title" onClose={() => setPending(undefined)} onCancel={(event) => { if (busy) event.preventDefault(); else setPending(undefined); }}>
      {pending && (() => {
        const account = accounts.find((item) => item.id === pending.accountId);
        return <form onSubmit={confirmStateChange}>
          <h2 id="account-state-title">{pending.state === "suspended" ? "Suspend this Linux account?" : "Activate this Linux account?"}</h2>
          <p>{account ? <><strong>{account.username}</strong> · {account.domain} · current revision {account.revision}</> : "The selected account is no longer in the current list."}</p>
          <p>{pending.state === "suspended" ? "This restricts new account access through PAM-aware login paths. Existing processes, websites, mail and databases are unaffected; this is not a full hosting suspension." : "This clears the PAM account expiration. The password remains locked and the shell remains nologin; this does not configure web, DNS or mail."}</p>
          {error && <div className="account-message account-error" role="alert"><Info /><span>{error}</span></div>}
          <label htmlFor="account-state-reason">Reason</label>
          <textarea id="account-state-reason" value={pending.reason} onChange={(event) => setPending({ ...pending, reason: event.target.value })} required maxLength={500} rows={3} disabled={!canMutate} aria-invalid={Boolean(pending.reason.trim()) && !validAccountReason(pending.reason)} aria-describedby="account-state-reason-help" />
          <p id="account-state-reason-help" className={`account-help ${Boolean(pending.reason.trim()) && !validAccountReason(pending.reason) ? "account-error" : ""}`}>{utf8Bytes(pending.reason)}/500 UTF-8 bytes · trimmed, without control characters.</p>
          <div className="account-dialog-actions">{error && <Button label="Refresh accounts" type="button" variant="ghost" icon={<RefreshCw />} isDisabled={Boolean(busy)} onClick={() => { setError(undefined); setRefreshAttempt((value) => value + 1); }} />}<Button label="Cancel" type="button" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setPending(undefined)} /><Button label={`Confirm ${pending.state === "suspended" ? "suspension" : "activation"}`} type="submit" variant="primary" isLoading={busy === "Updating account state"} isDisabled={!canMutate || !validAccountReason(pending.reason) || !account} /></div>
        </form>;
      })()}
    </dialog>
  </section>;
}
