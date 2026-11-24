import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { CircleAlert, CircleCheck, HardDrive, KeyRound, LoaderCircle, ShieldCheck, TriangleAlert } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { canClosePassword, formFromTarget, getBackupStorage, passwordFrom, saveBackupStorage, scheduleLine, targetChecks } from "@/lib/site-backups-api";
import type { BackupStorage as Storage, TargetField, TargetForm } from "@/lib/site-backups-api";
import { control, CopyButton, DrillSummary, panel, ProblemAlert, problemFrom, PruneSummary } from "@/BackupParts";
import type { Problem } from "@/BackupParts";
import { useShell } from "@/shell/context";

// The Backup storage page: where every website's backups go (an SFTP
// server outside this one), the key this server signs in there with, and
// the last restore drill. The repository password arrives once, in the
// answer to the first save, and is shown in a dialog that stays until the
// person says it is saved; it is kept nowhere else.

const fieldLabels: Record<TargetField, string> = { host: "Storage server", port: "SSH port", user: "User", path: "Folder", known_hosts: "Host key" };
const order: TargetField[] = ["host", "port", "user", "path", "known_hosts"];

function FieldProblem({ id, message }: { id: string; message?: string }) {
  if (!message) return null;
  return <div id={id} className="flex items-start gap-1.5 text-sm text-destructive">
    <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
    <span><span className="sr-only">Error: </span>{message}</span>
  </div>;
}

function TargetFormView({ storage, onSaved }: { storage: Storage; onSaved: (saved: { initialized: boolean; path: string; password?: string; storage: Storage }) => void }) {
  const [values, setValues] = useState<TargetForm>(() => formFromTarget(storage.target));
  const [errors, setErrors] = useState<Partial<Record<TargetField, string>>>({});
  const touched = useRef(new Set<TargetField>());
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const fields = useRef<Partial<Record<TargetField, HTMLInputElement | HTMLTextAreaElement | null>>>({});

  const check = (field: TargetField, value: string) => targetChecks[field](field === "known_hosts" ? value : value.trim());
  const set = (field: TargetField, value: string) => {
    touched.current.add(field);
    setValues((current) => ({ ...current, [field]: value }));
    // An error already shown clears as soon as it is fixed, never earlier.
    if (errors[field]) setErrors((current) => ({ ...current, [field]: check(field, value) }));
  };
  const leave = (field: TargetField) => {
    if (touched.current.has(field)) setErrors((current) => ({ ...current, [field]: check(field, values[field]) }));
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    const found: Partial<Record<TargetField, string>> = {};
    for (const field of order) found[field] = check(field, values[field]);
    setErrors(found);
    const first = order.find((field) => found[field]);
    if (first) { fields.current[first]?.focus(); return; }
    setBusy(true);
    setProblem(undefined);
    try {
      const saved = await saveBackupStorage(values);
      onSaved({ initialized: saved.initialized, path: saved.target?.path ?? values.path.trim(), password: passwordFrom(saved), storage: saved });
    } catch (error) {
      setProblem(problemFrom(error, "The backup storage was not saved."));
    } finally {
      setBusy(false);
    }
  };

  const bind = (field: TargetField) => {
    const id = `backup-target-${field}`;
    const describedBy = [`${id}-hint`, errors[field] ? `${id}-error` : ""].filter(Boolean).join(" ");
    return {
      id, name: field, required: true, "aria-invalid": errors[field] ? true : undefined, "aria-describedby": describedBy,
      onBlur: () => leave(field),
      ref: (el: HTMLInputElement | HTMLTextAreaElement | null) => { fields.current[field] = el; },
    };
  };
  const identifier = { autoComplete: "off", autoCapitalize: "none", autoCorrect: "off", spellCheck: false } as const;

  return <form method="post" noValidate aria-labelledby="backup-target-heading" onSubmit={(event) => void submit(event)} className="flex flex-col gap-4" data-testid="backup-target-form">
    <div className="flex flex-col gap-1">
      <h3 id="backup-target-heading">{storage.configured ? "Change the storage server" : "Set the storage server"}</h3>
      <p className="text-sm">An SFTP server outside this one. Make a user there for the backups and install this server's backup key for it first.</p>
    </div>
    <FieldGroup className="gap-4">
      <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_8rem]">
        <Field data-invalid={errors.host ? true : undefined}>
          <FieldLabel htmlFor="backup-target-host">{fieldLabels.host}</FieldLabel>
          <Input {...bind("host")} {...identifier} className={control} type="text" inputMode="url" enterKeyHint="next" placeholder="backup.example.com" value={values.host} onChange={(e) => set("host", e.target.value)} />
          <FieldDescription id="backup-target-host-hint" className="text-start">A DNS name or IP address.</FieldDescription>
          <FieldProblem id="backup-target-host-error" message={errors.host} />
        </Field>
        <Field data-invalid={errors.port ? true : undefined}>
          <FieldLabel htmlFor="backup-target-port">{fieldLabels.port}</FieldLabel>
          <Input {...bind("port")} {...identifier} className={control} type="text" inputMode="numeric" enterKeyHint="next" value={values.port} onChange={(e) => set("port", e.target.value)} />
          <FieldDescription id="backup-target-port-hint" className="text-start">Usually 22.</FieldDescription>
          <FieldProblem id="backup-target-port-error" message={errors.port} />
        </Field>
      </div>
      <Field data-invalid={errors.user ? true : undefined}>
        <FieldLabel htmlFor="backup-target-user">{fieldLabels.user}</FieldLabel>
        <Input {...bind("user")} {...identifier} className={control} type="text" enterKeyHint="next" value={values.user} onChange={(e) => set("user", e.target.value)} />
        <FieldDescription id="backup-target-user-hint" className="text-start">The SFTP user the backups sign in as.</FieldDescription>
        <FieldProblem id="backup-target-user-error" message={errors.user} />
      </Field>
      <Field data-invalid={errors.path ? true : undefined}>
        <FieldLabel htmlFor="backup-target-path">{fieldLabels.path}</FieldLabel>
        <Input {...bind("path")} {...identifier} className={`${control} font-mono`} type="text" enterKeyHint="next" placeholder="/srv/backups/this-server" value={values.path} onChange={(e) => set("path", e.target.value)} />
        <FieldDescription id="backup-target-path-hint" className="text-start">An absolute folder on the storage server. Use an empty folder, or the one this server's backups are already in.</FieldDescription>
        <FieldProblem id="backup-target-path-error" message={errors.path} />
      </Field>
      <Field data-invalid={errors.known_hosts ? true : undefined}>
        <FieldLabel htmlFor="backup-target-known_hosts">{fieldLabels.known_hosts}</FieldLabel>
        <textarea {...bind("known_hosts")} {...identifier} rows={4} maxLength={3500}
          className="min-h-24 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-2 font-mono text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:bg-input/30"
          value={values.known_hosts} onChange={(e) => set("known_hosts", e.target.value)} />
        <FieldDescription id="backup-target-known_hosts-hint" className="text-start">
          Run <code className="text-foreground">ssh-keyscan -p {values.port.trim() || "22"} {values.host.trim() || "HOST"}</code> on a trusted machine and paste the output. Backups trust only these keys.
        </FieldDescription>
        <FieldProblem id="backup-target-known_hosts-error" message={errors.known_hosts} />
      </Field>
    </FieldGroup>
    {problem && <ProblemAlert problem={problem} testId="backup-target-problem" />}
    <div className="flex flex-wrap items-center gap-3">
      <Button type="submit" className={`${control} aria-disabled:opacity-70`} disabled={busy} focusableWhenDisabled data-testid="save-backup-target">
        {busy && <LoaderCircle className="motion-safe:animate-spin" aria-hidden="true" />}{busy ? "Checking the storage server…" : "Save and check"}
      </Button>
      <span className="text-sm text-muted-foreground" role="status">{busy ? "The panel signs in with this server's key and opens or makes the backup folder. This can take up to 3 minutes." : ""}</span>
    </div>
  </form>;
}

// Shown once. It closes only after the person says the password is saved:
// not by a click outside, and not by Esc before that.
function PasswordDialog({ password, onClosed, afterClose }: { password: string; onClosed: () => void; afterClose: () => HTMLElement | null }) {
  const [saved, setSaved] = useState(false);
  const [open, setOpen] = useState(true);
  // The password leaves the page once the dialog has finished closing.
  return <Dialog open={open} disablePointerDismissal onOpenChange={(next) => { if (!next && canClosePassword(saved)) setOpen(false); }} onOpenChangeComplete={(next) => { if (!next) onClosed(); }}>
    <DialogContent showCloseButton={false} className="sm:max-w-lg" data-testid="password-dialog" initialFocus={() => document.getElementById("backup-password-value") ?? true} finalFocus={() => afterClose() ?? true}>
      <DialogHeader>
        <DialogTitle render={<h1 />} className="leading-snug">Save the backup password</DialogTitle>
        <DialogDescription className="text-start text-foreground">Save this password now. Without it the backups cannot be restored on another server. It will not be shown again.</DialogDescription>
      </DialogHeader>
      <div className="flex flex-col gap-2">
        <label htmlFor="backup-password-value" className="text-sm font-medium">Backup password</label>
        <input id="backup-password-value" readOnly value={password} className="h-10 w-full min-w-0 rounded-lg border border-input bg-muted px-2.5 font-mono text-sm text-foreground" onFocus={(e) => e.currentTarget.select()} data-testid="backup-password" {...{ autoComplete: "off", spellCheck: false }} />
        <CopyButton text={password} label="Copy password" testId="copy-password" />
      </div>
      <Alert role={undefined} className="text-start">
        <TriangleAlert aria-hidden="true" />
        <AlertDescription className="text-start text-foreground">Keep it in a password manager, away from this server. Anyone with it and the storage folder can read the backups.</AlertDescription>
      </Alert>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-0.5 size-4 accent-primary" checked={saved} onChange={(e) => setSaved(e.target.checked)} data-testid="password-saved" />
        <span>I saved the password somewhere safe.</span>
      </label>
      <DialogFooter>
        <Button type="button" className={`${control} aria-disabled:opacity-60`} disabled={!saved} focusableWhenDisabled aria-describedby="backup-password-close-note" onClick={() => setOpen(false)} data-testid="close-password">Close</Button>
        <span id="backup-password-close-note" className="sr-only">Available once the box above is ticked.</span>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}

export function BackupStorage() {
  const { revision, setPageResource } = useShell();
  const [storage, setStorage] = useState<Storage>();
  const [problem, setProblem] = useState<Problem>();
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [notice, setNotice] = useState("");
  const [password, setPassword] = useState<string>();
  const [formRound, setFormRound] = useState(0);
  const noticeRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let live = true;
    const controller = new AbortController();
    setLoading(true);
    getBackupStorage({ signal: controller.signal }).then(
      (value) => { if (live) { setStorage(value); setProblem(undefined); setLoadedAt(new Date()); setLoading(false); } },
      (error: unknown) => { if (live) { setProblem(problemFrom(error, "The backup storage settings could not be loaded.")); setLoading(false); } },
    );
    return () => { live = false; controller.abort(); };
  }, [revision, attempt]);
  useEffect(() => {
    setPageResource("backup-storage", { data: storage, loading, error: problem?.what, loadedAt });
  }, [storage, loading, problem, loadedAt, setPageResource]);

  if (!storage) return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="backup-storage">
    {problem
      ? <ProblemAlert problem={problem} onRetry={() => setAttempt((value) => value + 1)} testId="backup-storage-problem" />
      : loading && <div className={`${panel} flex flex-col gap-4 p-5`} aria-busy="true"><span className="sr-only">Loading the backup storage settings</span><Skeleton className="h-8 w-1/2" /><Skeleton className="h-40 w-full" /></div>}
  </div>;

  const target = storage.target;
  return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="backup-storage" data-configured={String(storage.configured)}>
    {problem && <ProblemAlert problem={{ ...problem, next: `${problem.next} The settings below are from the last successful read.` }} onRetry={() => setAttempt((value) => value + 1)} testId="backup-storage-problem" />}
    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="backup-storage-heading">
      <div className="flex flex-col gap-1">
        <h2 id="backup-storage-heading">Backup storage</h2>
        <p className="text-sm">Every website on this server is backed up to a storage server outside it. restic encrypts the backups with a password only this server holds.</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {storage.ready ? <Badge variant="secondary" data-testid="restic-ready"><ShieldCheck aria-hidden="true" />restic is ready</Badge> : <Badge variant="destructive" data-testid="restic-ready">restic is not ready</Badge>}
        {storage.configured ? <Badge variant="secondary"><HardDrive aria-hidden="true" />Storage set</Badge> : <Badge variant="outline">No storage set yet</Badge>}
      </div>
      {!storage.ready && <Alert variant="destructive" className="text-start" data-testid="restic-not-ready">
        <CircleAlert aria-hidden="true" />
        <AlertTitle>No backup can run on this server yet</AlertTitle>
        <AlertDescription className="flex flex-col gap-1 text-start text-foreground">
          <div>The account service did not find restic, or found a different version than the panel was built for.</div>
          <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> Run the installer again; it installs restic 0.20.0. Then reload this page.</div>
        </AlertDescription>
      </Alert>}
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 text-sm" data-testid="backup-facts">
        <dt className="text-muted-foreground">Schedule</dt><dd className="text-foreground" data-testid="backup-schedule">{scheduleLine(storage.nightly_at, storage.timezone)}</dd>
        <dt className="text-muted-foreground">Goes to</dt>
        <dd className="wrap-anywhere text-foreground" data-testid="backup-target">{target ? <><code>{target.user}@{target.host}:{target.port}</code>, folder <code>{target.path}</code></> : "Nowhere yet. Set the storage server below."}</dd>
      </dl>
      {notice && <Alert role={undefined} className="text-start" data-testid="backup-storage-notice" ref={noticeRef} tabIndex={-1}>
        <CircleCheck className="text-primary" aria-hidden="true" />
        <AlertTitle>{notice}</AlertTitle>
      </Alert>}
    </section>

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="backup-key-heading">
      <div className="flex flex-col gap-1">
        <h3 id="backup-key-heading" className="flex items-center gap-2"><KeyRound className="size-4" aria-hidden="true" />This server's backup key</h3>
        <p className="text-sm">Install this public key for the backup user on the storage server: in <code>/etc/sifruno/ssh/authorized_keys/USER</code> on a Sifruno server, or in that user's <code>~/.ssh/authorized_keys</code> elsewhere.</p>
      </div>
      <pre className="max-w-full overflow-x-auto rounded-md border border-border bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all text-foreground" data-testid="backup-public-key"><code id="backup-public-key">{storage.public_key}</code></pre>
      <CopyButton text={storage.public_key} label="Copy key" testId="copy-public-key" />
      <Separator />
      <TargetFormView key={formRound} storage={storage} onSaved={(saved) => {
        setStorage(saved.storage);
        setNotice(saved.initialized ? `Saved. A new backup repository was made in ${saved.path}.` : `Saved. The backup repository in ${saved.path} opens with this server's password.`);
        setFormRound((value) => value + 1);
        if (saved.password) setPassword(saved.password); else window.requestAnimationFrame(() => noticeRef.current?.focus());
      }} />
    </section>

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="backup-checks-heading">
      <div className="flex flex-col gap-1">
        <h3 id="backup-checks-heading">Checks</h3>
        <p className="text-sm">Each week one website's latest backup is restored to a private folder and compared with its file list, and old backups beyond {"7 daily and 4 weekly"} are removed.</p>
      </div>
      <DrillSummary drill={storage.last_drill} timezone={storage.timezone} />
      <PruneSummary prune={storage.last_prune} timezone={storage.timezone} />
    </section>

    {password && <PasswordDialog password={password} onClosed={() => setPassword(undefined)} afterClose={() => noticeRef.current} />}
  </div>;
}
