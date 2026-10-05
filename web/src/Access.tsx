import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Check, Info, LockKeyhole, LogOut, RefreshCw, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import { SiteApiError } from "@/lib/sites-api";
import type { OperatorSession } from "@/lib/sites-api";
import { accessError, getAccessInventory, getAccessSession, loginAccessSession, logoutAccessSession, revokeAccessSession, revokeOtherAccessSessions } from "@/lib/access-api";
import type { AccessInventory, AccessSession } from "@/lib/access-api";
import "@/access.css";

type Pending = { kind: "one"; session: AccessSession } | { kind: "others"; count: number };

export default function Access({ revision, onStatus }: { revision: number; onStatus: (value: Resource<unknown>) => void }) {
  const [session, setSession] = useState<OperatorSession>();
  const [inventory, setInventory] = useState<AccessInventory>();
  const [fresh, setFresh] = useState(false);
  const [accessKey, setAccessKey] = useState("");
  const [pending, setPending] = useState<Pending>();
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const epoch = useRef(0);
  const actionPending = useRef(false);
  const mounted = useRef(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const authenticated = session?.authenticated === true;
  const others = inventory?.items.filter((item) => !item.current) ?? [];
  const canChange = authenticated && fresh && !busy;

  const clearPrivate = useCallback(() => { setInventory(undefined); setFresh(false); setPending(undefined); setAccessKey(""); }, []);
  const fail = useCallback((failure: unknown) => {
    setError(accessError(failure)); setFresh(false); setPending(undefined);
    if (failure instanceof SiteApiError && failure.status === 401) { setSession({ authenticated: false }); clearPrivate(); setNotice(undefined); }
  }, [clearPrivate]);
  const loadInventory = useCallback(async (isLive: () => boolean) => {
    const next = await getAccessInventory();
    if (!isLive()) return;
    setInventory(next); setFresh(true); setLoadedAt(new Date());
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; ++epoch.current; };
  }, []);
  useEffect(() => {
    if (actionPending.current) return;
    const generation = ++epoch.current;
    const isLive = () => mounted.current && generation === epoch.current;
    setBusy("Checking local sessions"); setFresh(false); setError(undefined); setPending(undefined);
    void (async () => {
      try {
        const next = await getAccessSession();
        if (!isLive()) return;
        setSession(next);
        if (next.authenticated) await loadInventory(isLive);
        else clearPrivate();
        if (isLive()) setLoadedAt(new Date());
      } catch (failure) { if (isLive()) fail(failure); }
      finally { if (isLive()) setBusy(undefined); }
    })();
    return () => { if (generation === epoch.current) ++epoch.current; };
  }, [revision, attempt, loadInventory, clearPrivate, fail]);
  useEffect(() => { onStatus({ data: session, loading: Boolean(busy), error, loadedAt }); }, [session, busy, error, loadedAt, onStatus]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const timer = setTimeout(() => {
      ++epoch.current; setSession({ authenticated: false }); clearPrivate(); setBusy(undefined); setNotice(undefined);
      setError("Your local operator session expired. Sign in again to manage access.");
    }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session, clearPrivate]);
  useEffect(() => {
    if (pending && authenticated && dialog.current && !dialog.current.open) dialog.current.showModal();
    else if ((!pending || !authenticated) && dialog.current?.open) dialog.current.close();
  }, [pending, authenticated]);

  async function run(label: string, action: (isLive: () => boolean) => Promise<void>) {
    if (!mounted.current || actionPending.current || busy) return;
    actionPending.current = true;
    const generation = epoch.current;
    const isLive = () => mounted.current && generation === epoch.current;
    setBusy(label); setError(undefined); setNotice(undefined);
    try { await action(isLive); }
    catch (failure) { if (isLive()) fail(failure); }
    finally {
      actionPending.current = false;
      if (isLive()) setBusy(undefined);
      else if (mounted.current) setAttempt((value) => value + 1);
    }
  }
  const refresh = () => { if (busy || actionPending.current) return; setPending(undefined); setNotice(undefined); setAttempt((value) => value + 1); };
  async function login(event: React.FormEvent) {
    event.preventDefault();
    if (busy || actionPending.current || !accessKey.trim()) return;
    const key = accessKey; setAccessKey("");
    await run("Signing in", async (isLive) => {
      const next = await loginAccessSession(key);
      if (!isLive()) return;
      if (!next.authenticated) throw new SiteApiError(401, "unauthorized", "Sign-in was not accepted.");
      setSession(next); await loadInventory(isLive);
    });
  }
  async function signOut() {
    if (!session?.authenticated) return;
    const csrf = session.csrf_token;
    await run("Signing out", async (isLive) => {
      const next = await logoutAccessSession(csrf);
      if (!isLive()) return;
      if (next.authenticated) throw new SiteApiError(0, "invalid_response", "Sign-out was not confirmed.");
      ++epoch.current; setSession(next); clearPrivate(); setBusy(undefined); setLoadedAt(new Date()); setNotice("Signed out locally.");
    });
  }
  async function confirmRevocation() {
    if (!pending || !session?.authenticated || !canChange) return;
    const target = pending, csrf = session.csrf_token;
    if (target.kind === "one" && (!inventory?.items.some((item) => item.id === target.session.id && !item.current) || target.session.current)) { setPending(undefined); return; }
    await run("Revoking sessions", async (isLive) => {
      const result = target.kind === "one" ? await revokeAccessSession(target.session.id, csrf) : await revokeOtherAccessSessions(csrf);
      if (!isLive()) return;
      setPending(undefined); setInventory(undefined); setFresh(false);
      setNotice(result.revoked_count === 0 ? "No other sessions remained to revoke." : `${result.revoked_count} ${result.revoked_count === 1 ? "other session revoked" : "other sessions revoked"}. Your current session remains signed in.`);
      await loadInventory(isLive);
    });
  }

  return <div className="access-view" data-testid="access-page" aria-busy={Boolean(busy)}>
    <p className="access-scope"><ShieldCheck aria-hidden="true" />Local operator access to this Sifruno server.</p>
    {error && <div className="access-message access-error" role="alert"><Info aria-hidden="true" /><span>{error}</span><Button label="Refresh access" variant="ghost" size="sm" isDisabled={Boolean(busy)} onClick={refresh} /></div>}
    {notice && <div className="access-message" role="status"><Check aria-hidden="true" /><span>{notice}</span></div>}
    {!session ? <Card className="dashboard-card access-auth" padding={0}>
      <p role="status">{busy ? "Checking local operator session…" : "Your operator session could not be checked."}</p>
      {!busy && <Button label="Retry operator session" icon={<RefreshCw />} variant="secondary" onClick={refresh} />}
    </Card> : !authenticated ? <Card className="dashboard-card access-auth" padding={0}>
      <div className="access-auth-heading"><LockKeyhole aria-hidden="true" /><div><h2>Local operator sign-in</h2><p>Use the access key created by this server in its private state directory.</p></div></div>
      <form onSubmit={login} autoComplete="off" data-testid="access-login">
        <label htmlFor="access-key">Operator access key</label>
        <Input id="access-key" type="password" autoComplete="off" spellCheck={false} value={accessKey} onChange={(event) => setAccessKey(event.target.value)} disabled={Boolean(busy)} required />
        <Button label="Sign in locally" type="submit" variant="primary" isLoading={busy === "Signing in"} isDisabled={Boolean(busy) || !accessKey.trim()} />
      </form>
      <p className="access-help">The key is cleared when you submit. It is never saved in browser storage.</p>
    </Card> : <>
      <Card className="dashboard-card access-current" padding={0}>
        <div className="access-current-heading"><div className="access-current-icon"><LockKeyhole aria-hidden="true" /></div><div><h2>Signed in locally <Badge variant="secondary">Current session</Badge></h2><p>Expires <time dateTime={session.authenticated ? session.expires_at : undefined}>{session.authenticated ? dateLabel(session.expires_at) : ""}</time></p></div><Button label="Sign out locally" icon={<LogOut />} variant="secondary" size="sm" isDisabled={Boolean(busy)} onClick={() => void signOut()} data-testid="access-signout" /></div>
        <p className="access-help">Sign out ends this session. Revoking other sessions keeps this one active.</p>
      </Card>
      <Card className="dashboard-card access-inventory" padding={0}>
        <div className="card-heading"><div><h2>Operator sessions</h2><p>{inventory ? `${inventory.items.length} of ${inventory.capacity} sessions · ${inventory.lifetime_seconds / 60}-minute lifetime` : "Check the sessions currently signed in to this server."}</p></div><Button label="Refresh sessions" icon={<RefreshCw />} variant="ghost" size="sm" isDisabled={Boolean(busy)} onClick={refresh} data-testid="access-refresh" /></div>
        {!fresh && <p className="access-stale" role="status">{busy ? "Refreshing session inventory…" : "Refresh required before revoking sessions."}</p>}
        {inventory && <ul className="access-session-list" aria-label="Local operator sessions">{inventory.items.map((item, index) => <li key={item.id} className="access-session-row" data-testid={item.current ? "access-current-row" : "access-other-row"}>
          <div className="access-session-name"><LockKeyhole aria-hidden="true" /><strong>{item.current ? "This session" : `Other session ${inventory.items.slice(0, index + 1).filter((entry) => !entry.current).length}`}</strong>{item.current && <Badge variant="secondary">Current</Badge>}</div>
          <dl><div><dt>Created</dt><dd><time dateTime={item.created_at}>{dateLabel(item.created_at)}</time></dd></div><div><dt>Expires</dt><dd><time dateTime={item.expires_at}>{dateLabel(item.expires_at)}</time></dd></div></dl>
          {!item.current && <Button label={`Revoke session created ${dateLabel(item.created_at)}`} variant="secondary" size="sm" isDisabled={!canChange} onClick={() => setPending({ kind: "one", session: item })}>Revoke</Button>}
        </li>)}</ul>}
        {fresh && inventory && others.length === 0 && <Empty className="access-empty"><EmptyHeader><EmptyMedia variant="icon"><ShieldCheck aria-hidden="true" /></EmptyMedia><EmptyTitle>No other sessions are signed in.</EmptyTitle><EmptyDescription>Only your current operator session is active on this server.</EmptyDescription></EmptyHeader></Empty>}
        <div className="access-inventory-footer"><p className="access-help">Sessions belong to the single local operator. Device and location details are not collected.</p><Button label="Revoke all other sessions" variant="secondary" size="sm" isDisabled={!canChange || others.length === 0} onClick={() => setPending({ kind: "others", count: others.length })} data-testid="access-revoke-others" /></div>
      </Card>
    </>}
    {busy && session && <p className="access-busy" role="status">{busy}…</p>}
    <dialog ref={dialog} className="access-dialog" aria-labelledby="access-confirm-title" aria-describedby="access-confirm-description" onCancel={(event) => { if (busy) event.preventDefault(); else setPending(undefined); }}>{pending && <>
      <h2 id="access-confirm-title">{pending.kind === "one" ? "Revoke this other session?" : "Revoke all other sessions?"}</h2>
      <p id="access-confirm-description">{pending.kind === "one" ? <>End the operator session created <strong>{dateLabel(pending.session.created_at)}</strong>. It will need to sign in again.</> : <>End all other operator sessions on this server. The latest reading contains <strong>{pending.count}</strong> {pending.count === 1 ? "other session" : "other sessions"}.</>}</p>
      <p>Your current session stays signed in.</p>
      <div className="access-dialog-actions"><Button label="Cancel revocation" variant="ghost" isDisabled={Boolean(busy)} onClick={() => setPending(undefined)} /><Button label={pending.kind === "one" ? "Confirm revocation" : "Confirm revoke all others"} variant="primary" isDisabled={!canChange} isLoading={busy === "Revoking sessions"} onClick={() => void confirmRevocation()} data-testid="access-confirm-revoke" /></div>
    </>}</dialog>
  </div>;
}
