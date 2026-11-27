import { useCallback, useEffect, useRef, useState } from "react";
import { Check, Info, LoaderCircle, LockKeyhole, LogOut, RefreshCw, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { dateLabel } from "@/lib/api";
import type { Resource } from "@/lib/api";
import { SiteApiError } from "@/lib/sites-api";
import type { OperatorSession } from "@/lib/sites-api";
import { accessError, getAccessInventory, getAccessSession, loginAccessSession, logoutAccessSession, revokeAccessSession, revokeOtherAccessSessions } from "@/lib/access-api";
import type { AccessInventory, AccessSession } from "@/lib/access-api";

// The base styles colour <p> outside Tailwind's layers, so coloured text
// uses div or span, as on the other new screens.
const panel = "rounded-lg border border-border bg-card";

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

  return <div className="@container flex w-full max-w-[70rem] min-w-0 flex-col gap-4" data-testid="access-page" aria-busy={Boolean(busy)}>
    <div className="flex items-center gap-2 text-sm text-muted-foreground"><ShieldCheck className="size-4 shrink-0 text-primary" aria-hidden="true" />Local operator access to this Sifruno server.</div>
    {error && <Alert variant="destructive" className="text-start">
      <Info aria-hidden="true" />
      <AlertTitle className="wrap-anywhere">{error}</AlertTitle>
      <AlertDescription className="text-start"><Button variant="outline" size="sm" className="mt-2 w-fit pointer-coarse:h-11" disabled={Boolean(busy)} onClick={refresh}><RefreshCw aria-hidden="true" />Refresh access</Button></AlertDescription>
    </Alert>}
    {notice && <Alert role="status" className="text-start"><Check className="text-primary" aria-hidden="true" /><AlertTitle className="wrap-anywhere">{notice}</AlertTitle></Alert>}
    {!session ? <section className={`${panel} max-w-xl p-5`} aria-label="Operator session">
      <div role="status" className="text-sm text-foreground">{busy ? "Checking local operator session…" : "Your operator session could not be checked."}</div>
      {!busy && <Button variant="outline" className="mt-3 h-9 pointer-coarse:h-11" onClick={refresh}><RefreshCw aria-hidden="true" />Retry operator session</Button>}
    </section> : !authenticated ? <section className={`${panel} max-w-xl p-5`} aria-labelledby="access-sign-in-heading">
      <div className="flex items-start gap-3.5">
        <LockKeyhole className="size-6 shrink-0 text-primary" aria-hidden="true" />
        <div className="min-w-0"><h2 id="access-sign-in-heading">Local operator sign-in</h2><div className="mt-1.5 text-sm text-muted-foreground wrap-anywhere">Use the access key created by this server in its private state directory.</div></div>
      </div>
      <form onSubmit={login} autoComplete="off" data-testid="access-login" className="mt-6 flex flex-col items-start gap-2.5">
        <label htmlFor="access-key" className="text-sm font-medium text-foreground">Operator access key</label>
        <Input id="access-key" type="password" autoComplete="off" spellCheck={false} value={accessKey} onChange={(event) => setAccessKey(event.target.value)} disabled={Boolean(busy)} required className="h-10! max-w-sm text-sm! pointer-coarse:h-12!" />
        <Button type="submit" className="h-9 pointer-coarse:h-11" disabled={Boolean(busy) || !accessKey.trim()}>{busy === "Signing in" && <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" />}Sign in locally</Button>
      </form>
      <div className="mt-5 text-xs text-muted-foreground">The key is cleared when you submit. It is never saved in browser storage.</div>
    </section> : <>
      <section className={`${panel} p-5`} aria-labelledby="access-current-heading">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-secondary text-primary"><LockKeyhole className="size-5" aria-hidden="true" /></div>
          <div className="min-w-0 flex-1 basis-48">
            <h2 id="access-current-heading" className="flex flex-wrap items-center gap-2.5">Signed in locally <Badge variant="secondary">Current session</Badge></h2>
            <div className="mt-1.5 text-sm text-muted-foreground wrap-anywhere">Expires <time dateTime={session.authenticated ? session.expires_at : undefined}>{session.authenticated ? dateLabel(session.expires_at) : ""}</time></div>
          </div>
          <Button variant="outline" size="sm" className="pointer-coarse:h-11" disabled={Boolean(busy)} onClick={() => void signOut()} data-testid="access-signout"><LogOut aria-hidden="true" />Sign out locally</Button>
        </div>
        <div className="mt-3.5 text-xs text-muted-foreground">Sign out ends this session. Revoking other sessions keeps this one active.</div>
      </section>
      <section className={`${panel} min-w-0`} aria-labelledby="access-sessions-heading">
        <div className="flex flex-wrap items-start justify-between gap-3 p-4">
          <div className="min-w-0"><h2 id="access-sessions-heading">Operator sessions</h2><div className="mt-1 text-sm text-muted-foreground">{inventory ? `${inventory.items.length} of ${inventory.capacity} sessions · each ends after ${inventory.idle_seconds / 60} minutes unused, or ${inventory.kept_idle_seconds / 3600} hours if kept signed in` : "Check the sessions currently signed in to this server."}</div></div>
          <Button variant="ghost" size="sm" className="pointer-coarse:h-11" disabled={Boolean(busy)} onClick={refresh} data-testid="access-refresh"><RefreshCw aria-hidden="true" />Refresh sessions</Button>
        </div>
        {!fresh && <div className="px-4 pb-3 text-sm text-muted-foreground" role="status">{busy ? "Refreshing session inventory…" : "Refresh required before revoking sessions."}</div>}
        {inventory && <ul className="m-0 list-none p-0" aria-label="Local operator sessions">{inventory.items.map((item, index) => <li key={item.id} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-t border-border p-4 @3xl:grid-cols-[minmax(11rem,1fr)_minmax(0,1.7fr)_6rem] @3xl:gap-4" data-testid={item.current ? "access-current-row" : "access-other-row"}>
          <div className="flex min-w-0 flex-wrap items-center gap-2 text-sm"><LockKeyhole className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" /><strong className="font-medium text-foreground">{item.current ? "This session" : `Other session ${inventory.items.slice(0, index + 1).filter((entry) => !entry.current).length}`}</strong>{item.current && <Badge variant="secondary">Current</Badge>}{item.kept_signed_in && <Badge variant="outline">Kept signed in</Badge>}</div>
          <dl className="col-span-2 row-start-2 grid min-w-0 grid-cols-2 gap-3 @3xl:col-span-1 @3xl:row-start-auto">
            <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Created</dt><dd className="text-sm wrap-anywhere text-foreground"><time dateTime={item.created_at}>{dateLabel(item.created_at)}</time></dd></div>
            <div className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">Expires</dt><dd className="text-sm wrap-anywhere text-foreground"><time dateTime={item.expires_at}>{dateLabel(item.expires_at)}</time></dd></div>
          </dl>
          {!item.current && <Button variant="outline" size="sm" className="justify-self-end pointer-coarse:h-11" disabled={!canChange} onClick={() => setPending({ kind: "one", session: item })}>Revoke<span className="sr-only"> session created {dateLabel(item.created_at)}</span></Button>}
        </li>)}</ul>}
        {fresh && inventory && others.length === 0 && <Empty className="px-4 py-6"><EmptyHeader><EmptyMedia variant="icon"><ShieldCheck aria-hidden="true" /></EmptyMedia><EmptyTitle>No other sessions are signed in.</EmptyTitle><EmptyDescription>Only your current operator session is active on this server.</EmptyDescription></EmptyHeader></Empty>}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border p-4">
          <div className="max-w-md text-xs text-muted-foreground">Sessions belong to the single local operator. Device and location details are not collected.</div>
          <Button variant="outline" size="sm" className="pointer-coarse:h-11" disabled={!canChange || others.length === 0} onClick={() => setPending({ kind: "others", count: others.length })} data-testid="access-revoke-others">Revoke all other sessions</Button>
        </div>
      </section>
    </>}
    {busy && session && <div className="text-xs text-muted-foreground" role="status">{busy}…</div>}
    <dialog ref={dialog} className="fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-[min(28.75rem,calc(100vw-1.75rem))] overflow-auto overscroll-contain rounded-xl border border-border bg-card p-5 text-foreground shadow-xl backdrop:overflow-hidden backdrop:overscroll-contain backdrop:bg-[rgb(8_14_22/58%)]" aria-labelledby="access-confirm-title" aria-describedby="access-confirm-description" onCancel={(event) => { if (busy) event.preventDefault(); else setPending(undefined); }}>{pending && <>
      <h1 id="access-confirm-title" className="pb-3 text-lg! tracking-tight!">{pending.kind === "one" ? "Revoke this other session?" : "Revoke all other sessions?"}</h1>
      <div id="access-confirm-description" className="mb-3 text-sm text-foreground">{pending.kind === "one" ? <>End the operator session created <strong>{dateLabel(pending.session.created_at)}</strong>. It will need to sign in again.</> : <>End all other operator sessions on this server. The latest reading contains <strong>{pending.count}</strong> {pending.count === 1 ? "other session" : "other sessions"}.</>}</div>
      <div className="text-sm text-muted-foreground">Your current session stays signed in.</div>
      <div className="mt-5 flex flex-wrap justify-end gap-2"><Button variant="ghost" className="h-9 pointer-coarse:h-11" disabled={Boolean(busy)} onClick={() => setPending(undefined)}>Cancel revocation</Button><Button className="h-9 pointer-coarse:h-11" disabled={!canChange} onClick={() => void confirmRevocation()} data-testid="access-confirm-revoke">{busy === "Revoking sessions" && <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" />}{pending.kind === "one" ? "Confirm revocation" : "Confirm revoke all others"}</Button></div>
    </>}</dialog>
  </div>;
}
