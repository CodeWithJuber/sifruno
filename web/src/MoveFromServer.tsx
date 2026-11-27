import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { useNavigate } from "@tanstack/react-router";
import { cn } from "cn";
import { CircleCheck, Eye, EyeOff, FileWarning, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Textarea } from "@/components/ui/textarea";
import { dateLabel } from "@/lib/api";
import { cancelSource, checkSourceHost, checkSourcePort, confirmFingerprint, installKey, listSites, openSource, startMigration } from "@/lib/migration-api";
import type { MigrationSource, RootLogin } from "@/lib/migration-api";
import { checkAccountName, checkPrivateKey, checkRootPassword, serverName } from "@/lib/migration-server";
import type { ServerSite, SiteItem } from "@/lib/migration-server";
import { CopyBlock, ProblemBox } from "@/MoveParts";
import { problemFrom, TechnicalDetails } from "@/NewWebsite";
import type { Problem } from "@/NewWebsite";

// "Move a website here" from another Linux server: one whose websites
// Apache or nginx serves with PHP-FPM. The admin connects over SSH and
// confirms the server's fingerprint; then Sifruno's key for this move gets
// onto the server, by a command the admin runs there as root, or with
// root's password or a private key, which this form keeps until it is sent
// and then clears (the panel uses it once and keeps nothing). Sifruno then
// reads the websites the web server serves and shows, for the one picked,
// what moves and what will not, before anything is made here.

const panel = "rounded-lg border border-border bg-card p-5 md:p-6";
const control = "h-10 pointer-coarse:h-12";

type Stage = "connect" | "confirm" | "letin" | "choose";
type Way = "command" | "password" | "key";

const serverSteps = [
  { title: "Connect over SSH", what: "Sifruno reads the old server's SSH key. Nothing is sent to it yet." },
  { title: "Confirm the SSH key", what: "You compare the old server's fingerprint and confirm it once; every later step checks it." },
  { title: "Let Sifruno in", what: "A key for this move goes into root's SSH keys there: you run one command, or Sifruno adds it with root's password or a key, used once and not kept." },
  { title: "Choose the website", what: "Sifruno reads what Apache or nginx serves and shows what moves and what will not. Nothing is made here yet." },
  { title: "Copy and compare", what: "Files, database and jobs are copied into a new account, then compared with the old site." },
  { title: "Remove the key", what: "The key is removed from the old server and deleted here." },
];

const ways: { value: Way; title: string; what: string }[] = [
  { value: "command", title: "I run a command as root there", what: "Copy one line to the old server's root shell. Nothing secret leaves your hands." },
  { value: "password", title: "Root's password", what: "Sifruno signs in once as root to add the key, then forgets the password." },
  { value: "key", title: "A private key root accepts", what: "Sifruno signs in once with it to add the key, then forgets it." },
];

function Steps({ current }: { current: number }) {
  return <ol aria-label="Steps of the move" className="flex flex-col gap-3" data-testid="move-steps">
    {serverSteps.map((step, i) => <li key={step.title} aria-current={i === current ? "step" : undefined} className="flex items-start gap-3">
      <span aria-hidden="true" className={cn("flex size-6 shrink-0 items-center justify-center rounded-full border text-xs font-medium",
        i < current ? "border-primary bg-primary text-primary-foreground" : i === current ? "border-primary text-primary" : "border-border text-muted-foreground")}>
        {i < current ? <CircleCheck className="size-4" /> : i + 1}
      </span>
      <span className="flex min-w-0 flex-col">
        <span className={cn("text-sm", i === current ? "font-medium text-foreground" : "text-muted-foreground")}>{step.title}{i < current && <span className="sr-only"> (done)</span>}</span>
        <span className="text-xs text-muted-foreground"><span className="font-medium">What happens:</span> {step.what}</span>
      </span>
    </li>)}
  </ol>;
}

// One thing that does not move, or stops the move: plain words, and the
// file and line it came from under Technical details.
function ItemList({ items, icon, testid }: { items: SiteItem[]; icon: ReactNode; testid: string }) {
  return <ul role="list" className="flex flex-col gap-2 text-sm" data-testid={testid}>
    {items.map((item, i) => <li key={i} className="flex gap-2">
      <span aria-hidden="true" className="mt-0.5 shrink-0 text-muted-foreground">{icon}</span>
      <span className="flex min-w-0 flex-col gap-1">
        <span>{item.text}</span>
        {item.where && <TechnicalDetails className="text-xs">{item.where}</TechnicalDetails>}
      </span>
    </li>)}
  </ul>;
}

export function MoveFromServer({ onBack }: { onBack: () => void }) {
  const navigate = useNavigate();
  const [stage, setStage] = useState<Stage>("connect");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [touched, setTouched] = useState(false);
  const [source, setSource] = useState<MigrationSource>();
  const [fingerprint, setFingerprint] = useState("");
  const [way, setWay] = useState<Way>("command");
  // Root's password or key lives only in this state until it is sent; it
  // is cleared once it was used, and never stored.
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const [sites, setSites] = useState<ServerSite[]>();
  const [picked, setPicked] = useState("");
  const [account, setAccount] = useState("");
  const [busy, setBusy] = useState("");
  const [problem, setProblem] = useState<Problem>();
  const [retry, setRetry] = useState<() => void>();
  const [ended, setEnded] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => { headingRef.current?.focus(); }, [stage]);

  const hostProblem = checkSourceHost(host), portProblem = checkSourcePort(port);
  const secretProblem = way === "password" ? checkRootPassword(password) : way === "key" ? checkPrivateKey(privateKey) : undefined;
  const site = sites?.find((s) => s.domain === picked);
  const accountProblem = checkAccountName(account);
  const run = async (what: string, work: () => Promise<void>) => {
    setBusy(what); setProblem(undefined); setRetry(undefined);
    try { await work(); } catch (error) { setProblem(problemFrom(error, what)); setRetry(() => () => void run(what, work)); } finally { setBusy(""); }
  };
  const forgetSecret = () => { setPassword(""); setPrivateKey(""); setPassphrase(""); setShowSecret(false); };
  const pick = (domain: string, list = sites) => {
    setPicked(domain); setTouched(false);
    setAccount(list?.find((s) => s.domain === domain)?.account ?? "");
  };
  const readSites = async (id: string) => {
    const list = await listSites(id);
    setSites(list);
    pick(list.find((s) => s.movable)?.domain ?? list[0]?.domain ?? "", list);
    setStage("choose");
  };

  const connect = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (hostProblem || portProblem) return;
    void run("Sifruno could not connect to the old server.", async () => {
      const opened = await openSource(host, Number(port), { via: "server" });
      setSource(opened); setFingerprint(""); setTouched(false); setStage("confirm");
    });
  };
  const confirm = (event: FormEvent) => {
    event.preventDefault();
    if (!source || !fingerprint) return;
    void run("The fingerprint was not confirmed.", async () => {
      setSource(await confirmFingerprint(source.id, fingerprint));
      setStage("letin");
    });
  };
  const letIn = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (!source || secretProblem) return;
    if (way === "command") {
      void run("The old server's websites could not be listed.", () => readSites(source.id));
      return;
    }
    const login: RootLogin = way === "password" ? { password } : { private_key: privateKey.trim(), passphrase };
    void run("Sifruno could not add its key on the old server.", async () => {
      try {
        await installKey(source.id, login);
      } finally {
        // Used once, right or wrong: the form asks again rather than keep it.
        forgetSecret();
      }
      await readSites(source.id);
    });
  };
  const move = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (!source || !site || !site.movable || accountProblem) return;
    void run("The move was not started.", async () => {
      const job = await startMigration(source.id, account, { site: site.domain });
      void navigate({ to: "/websites/move/$jobId", params: { jobId: job.id } });
    });
  };
  const cancel = () => {
    if (!source) return;
    void run("The migration key was not removed.", async () => {
      const result = await cancelSource(source.id);
      setEnded(result.removed_from_source ? `Stopped. ${result.detail || "The old server no longer accepts the migration key."} This server deleted its own copy of the key.` : `Stopped. This server deleted the migration key. ${result.detail}`);
      setSource(undefined); setSites(undefined); forgetSecret(); setStage("connect");
    });
  };

  const heading = (children: ReactNode) => <h2 ref={headingRef} tabIndex={-1} className="outline-none">{children}</h2>;
  const current = { connect: 0, confirm: 1, letin: 2, choose: 3 }[stage];
  const stop = <Button type="button" variant="outline" className={control} onClick={cancel} disabled={Boolean(busy)} data-testid="move-stop">Stop and remove the key</Button>;
  const secretId = way === "password" ? "move-root-password" : "move-root-key";

  return <div className="flex flex-col gap-5" data-testid="move-server" data-stage={stage}>
    {ended && <Alert role="status" className="text-start"><CircleCheck aria-hidden="true" /><AlertTitle>{ended}</AlertTitle></Alert>}
    <div className={`${panel} flex flex-col gap-5`}><Steps current={current} /></div>

    {stage === "connect" && <section className={`${panel} flex flex-col gap-5`} data-testid="move-server-connect">
      <div className="flex flex-col gap-1">
        {heading("Connect to the old server over SSH")}
        <p className="text-sm">Sifruno reads the websites Apache or nginx serves there. Their email and DNS stay where they are, and the old sites keep running until you change DNS.</p>
      </div>
      <form noValidate onSubmit={connect} className="flex flex-col gap-4">
        <FieldGroup>
          <Field data-invalid={touched && Boolean(hostProblem)}>
            <FieldLabel htmlFor="move-server-host">Old server</FieldLabel>
            <FieldDescription id="move-server-host-help">Its host name or IPv4 address, such as server1.example.com.</FieldDescription>
            <Input id="move-server-host" name="host" className={control} value={host} onChange={(e) => setHost(e.target.value.trim())} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} inputMode="url" enterKeyHint="next"
              aria-invalid={touched && Boolean(hostProblem)} aria-describedby={touched && hostProblem ? "move-server-host-help move-server-host-error" : "move-server-host-help"} data-testid="move-host" />
            {touched && hostProblem && <FieldError id="move-server-host-error">{hostProblem}</FieldError>}
          </Field>
          <Field data-invalid={touched && Boolean(portProblem)} className="max-w-40">
            <FieldLabel htmlFor="move-server-port">SSH port</FieldLabel>
            <Input id="move-server-port" name="port" className={control} value={port} onChange={(e) => setPort(e.target.value.trim())} inputMode="numeric" autoComplete="off" enterKeyHint="go"
              aria-invalid={touched && Boolean(portProblem)} aria-describedby={touched && portProblem ? "move-server-port-error" : undefined} data-testid="move-port" />
            {touched && portProblem && <FieldError id="move-server-port-error">{portProblem}</FieldError>}
          </Field>
        </FieldGroup>
        {problem && <ProblemBox problem={problem} onRetry={retry} />}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" className={control} disabled={Boolean(busy)} data-testid="move-connect">{busy ? "Connecting…" : "Connect"}</Button>
          <Button type="button" variant="outline" className={control} onClick={onBack} data-testid="move-back">Back</Button>
        </div>
      </form>
    </section>}

    {stage === "confirm" && source && <section className={`${panel} flex flex-col gap-5`} data-testid="move-confirm">
      <div className="flex flex-col gap-1">
        {heading(<>Confirm the SSH key of {source.host}</>)}
        <p className="text-sm">Sifruno made a key for this move only, which expires {dateLabel(source.expires_at)}. Before it signs in, or sends a password, confirm that this is the right server.</p>
      </div>
      <form onSubmit={confirm} className="flex flex-col gap-4">
        <RadioGroup value={fingerprint} onValueChange={(value) => setFingerprint(String(value))} aria-labelledby="move-fp-legend" aria-describedby="move-fp-help">
          <div id="move-fp-legend" className="text-sm font-medium">The old server's fingerprint</div>
          <p id="move-fp-help" className="text-sm text-muted-foreground">On the old server, run <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> (or the file of the same type below). Choose the line whose fingerprint is exactly the same. If none matches, stop: something else answered at this address.</p>
          {source.host_keys.map((key) => <FieldLabel key={key.fingerprint} htmlFor={`fp-${key.type}`}>
            <Field orientation="horizontal">
              <RadioGroupItem value={key.fingerprint} id={`fp-${key.type}`} data-testid={`move-fp-${key.type}`} />
              <FieldContent>
                <FieldTitle>{key.type}</FieldTitle>
                <FieldDescription className="font-mono text-xs break-all text-start">{key.fingerprint}</FieldDescription>
              </FieldContent>
            </Field>
          </FieldLabel>)}
        </RadioGroup>
        {problem && <ProblemBox problem={problem} onRetry={retry} />}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" className={control} disabled={!fingerprint || Boolean(busy)} data-testid="move-confirm-fp"><ShieldCheck aria-hidden="true" />{busy ? "Checking…" : "The fingerprint matches"}</Button>
          {stop}
        </div>
      </form>
    </section>}

    {stage === "letin" && source && <section className={`${panel} flex flex-col gap-5`} data-testid="move-letin">
      <div className="flex flex-col gap-1">
        {heading(<>Let Sifruno in to {source.host}</>)}
        <p className="text-sm">Sifruno signs in as root with a key made for this move, to read and copy the website. The key is removed from both servers when the move ends.</p>
      </div>
      <form noValidate onSubmit={letIn} className="flex flex-col gap-4" autoComplete="off">
        <FieldSet>
          <FieldLegend variant="label">How the key gets there</FieldLegend>
          <RadioGroup value={way} onValueChange={(value) => { setWay(value === "password" || value === "key" ? value : "command"); setTouched(false); forgetSecret(); }}>
            {ways.map((w) => <FieldLabel key={w.value} htmlFor={`move-way-${w.value}`}>
              <Field orientation="horizontal">
                <RadioGroupItem value={w.value} id={`move-way-${w.value}`} data-testid={`move-way-${w.value}`} />
                <FieldContent>
                  <FieldTitle>{w.title}</FieldTitle>
                  <FieldDescription className="text-start">{w.what}</FieldDescription>
                </FieldContent>
              </Field>
            </FieldLabel>)}
          </RadioGroup>
        </FieldSet>
        {way === "command" && <CopyBlock id="move-install" label="Run this as root on the old server, then press I ran it" value={source.install_command} />}
        {way === "password" && <Field data-invalid={touched && Boolean(secretProblem)}>
          <FieldLabel htmlFor={secretId}>Root's password on the old server</FieldLabel>
          <FieldDescription id="move-secret-help">Sent once to {source.host}, which showed the fingerprint you confirmed, to add the key. Never stored, logged or shown again.</FieldDescription>
          <div className="flex gap-2">
            {/* autocomplete off: this is another server's login, not one for this panel to save. */}
            <Input id={secretId} name="root-password" type={showSecret ? "text" : "password"} className={`${control} min-w-0 flex-1`} value={password} onChange={(e) => setPassword(e.target.value)}
              autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} enterKeyHint="go"
              aria-invalid={touched && Boolean(secretProblem)} aria-describedby={touched && secretProblem ? "move-secret-help move-secret-error" : "move-secret-help"} data-testid="move-root-password" />
            <Button type="button" variant="outline" className={`${control} shrink-0 px-3`} aria-pressed={showSecret} aria-controls={secretId} onClick={() => setShowSecret((v) => !v)}>
              {showSecret ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}Show
            </Button>
          </div>
          {touched && secretProblem && <FieldError id="move-secret-error">{secretProblem}</FieldError>}
        </Field>}
        {way === "key" && <>
          <Field data-invalid={touched && Boolean(secretProblem)}>
            <FieldLabel htmlFor={secretId}>Private key</FieldLabel>
            <FieldDescription id="move-secret-help">The whole key root accepts there, from its -----BEGIN line to its -----END line. Sent once to {source.host} to add the move's key. Never stored, logged or shown again.</FieldDescription>
            <Textarea id={secretId} name="root-private-key" rows={6} className="font-mono text-xs" value={privateKey} onChange={(e) => setPrivateKey(e.target.value)}
              autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false}
              aria-invalid={touched && Boolean(secretProblem)} aria-describedby={touched && secretProblem ? "move-secret-help move-secret-error" : "move-secret-help"} data-testid="move-root-key" />
            {touched && secretProblem && <FieldError id="move-secret-error">{secretProblem}</FieldError>}
          </Field>
          <Field>
            <FieldLabel htmlFor="move-root-passphrase">Its passphrase, if it has one</FieldLabel>
            <Input id="move-root-passphrase" name="root-key-passphrase" type="password" className={control} value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="off" data-testid="move-root-passphrase" />
          </Field>
        </>}
        {problem && <ProblemBox problem={problem} onRetry={way === "command" ? retry : undefined} />}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" className={control} disabled={Boolean(busy)} data-testid="move-letin-go">{busy ? "Working…" : way === "command" ? "I ran it" : "Add the key"}</Button>
          {stop}
        </div>
      </form>
    </section>}

    {stage === "choose" && source && sites && <section className={`${panel} flex flex-col gap-5`} data-testid="move-choose">
      <div className="flex flex-col gap-1">
        {heading(<>Choose the website on {source.host}</>)}
        <p className="text-sm">These are the websites the old server's web server names. Nothing is created here until you press Move this website.</p>
      </div>
      <form noValidate onSubmit={move} className="flex flex-col gap-5">
        <RadioGroup value={picked} onValueChange={(value) => pick(String(value))} aria-label="Websites on the old server">
          {sites.map((s) => <FieldLabel key={s.domain} htmlFor={`move-site-${s.domain}`}>
            <Field orientation="horizontal">
              <RadioGroupItem value={s.domain} id={`move-site-${s.domain}`} data-testid={`move-site-${s.domain}`} />
              <FieldContent>
                <FieldTitle className="break-all">{s.domain}{!s.movable && <Badge variant="outline">Cannot move as it is</Badge>}</FieldTitle>
                <FieldDescription className="text-start break-words">{serverName(s)}{s.doc_root ? `, files in ${s.doc_root}` : ""}{s.wordpress ? ", WordPress" : ""}</FieldDescription>
              </FieldContent>
            </Field>
          </FieldLabel>)}
        </RadioGroup>

        {site && <div className="flex flex-col gap-4 border-t border-border pt-4" data-testid="move-site-summary">
          <h3 className="text-base font-medium break-all">{site.domain}</h3>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-muted-foreground">Web server</dt><dd>{serverName(site)}</dd>
            {site.doc_root && <><dt className="text-muted-foreground">Files</dt><dd className="break-words"><code>{site.doc_root}</code>{site.owner && <> owned by <code>{site.owner}</code>; they go into the account's <code>public_html</code></>}</dd></>}
            {site.www && <><dt className="text-muted-foreground">Also answers</dt><dd className="break-words">www.{site.domain}</dd></>}
            <dt className="text-muted-foreground">PHP</dt><dd>{site.php}{site.php_source ? ` (the old server runs ${site.php_source})` : " (the old server does not name its version)"}</dd>
            <dt className="text-muted-foreground">Database</dt><dd className="break-words">{site.database ? <><code>{site.database}</code>, named in wp-config.php: it moves with its user and password, under the account's name</> : "None found"}</dd>
            <dt className="text-muted-foreground">Certificate</dt><dd>{site.certificate ? "Copied when a trusted authority issued it and it is valid for 7 days more" : "None named; the site uses http here until its domain points here"}</dd>
          </dl>
          {site.refused.length > 0 && <Alert className="text-start" data-testid="move-site-refused">
            <FileWarning aria-hidden="true" />
            <AlertTitle>This website cannot move as it is</AlertTitle>
            <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
              <p>Its web server configuration has lines this server does not convert, so the copy would behave differently. Nothing is made for it here.</p>
              <ItemList items={site.refused} icon={<FileWarning className="size-4" />} testid="move-site-refused-list" />
              <p className="text-sm text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> Leave this website on the old server for now, or change those lines there (Technical details names the file and line), then press Stop and connect again.</p>
            </AlertDescription>
          </Alert>}
          {site.not_carried.length > 0 && <div className="flex flex-col gap-2" data-testid="move-site-not-carried">
            <h3 className="text-sm font-medium">What will not move, or moves differently</h3>
            <ItemList items={site.not_carried} icon={<FileWarning className="size-4" />} testid="move-site-not-carried-list" />
          </div>}
          {site.movable && <Field data-invalid={touched && Boolean(accountProblem)} className="max-w-sm">
            <FieldLabel htmlFor="move-account">Account name here</FieldLabel>
            <FieldDescription id="move-account-help">The hosting account the website gets on this server: 3 to 32 lowercase letters, digits or _. Its database names start with it.</FieldDescription>
            <Input id="move-account" name="account" className={control} value={account} onChange={(e) => setAccount(e.target.value.trim())} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} enterKeyHint="go"
              aria-invalid={touched && Boolean(accountProblem)} aria-describedby={touched && accountProblem ? "move-account-help move-account-error" : "move-account-help"} data-testid="move-account" />
            {touched && accountProblem && <FieldError id="move-account-error">{accountProblem}</FieldError>}
          </Field>}
        </div>}
        {problem && <ProblemBox problem={problem} onRetry={retry} />}
        <div className="flex flex-wrap gap-2">
          {site?.movable && <Button type="submit" className={control} disabled={Boolean(busy)} data-testid="move-site-start">{busy === "The move was not started." ? "Starting…" : "Move this website"}</Button>}
          <Button type="button" variant="outline" className={control} disabled={Boolean(busy)} onClick={() => void run("The old server's websites could not be listed.", () => readSites(source.id))}>Read the websites again</Button>
          {stop}
        </div>
      </form>
    </section>}
    <div role="status" className="sr-only">{busy}</div>
  </div>;
}
