import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "@tanstack/react-router";
import { CircleAlert, CircleCheck, FileArchive, Upload } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { dateLabel } from "@/lib/api";
import { cancelSource, startMigration, uploadArchive } from "@/lib/migration-api";
import { checkArchiveFile, sizeText } from "@/lib/migration-archive";
import type { ArchiveSource } from "@/lib/migration-archive";
import { Explanation, problemFrom, TechnicalDetails } from "@/NewWebsite";
import type { Problem } from "@/NewWebsite";

// "Move a website here" from a cPanel backup file: the person uploads the
// file the old host's cPanel made (Backup, Download a Full Account Backup,
// or WHM's Transfer Tool and pkgacct), sees what it holds and what will not
// move, and starts the same move a cPanel server's account gets. The file
// stays on this server, root's only, until the move ends or 24 hours pass.

const panel = "rounded-lg border border-border bg-card p-5 md:p-6";
const control = "h-10 pointer-coarse:h-12";

const backupSteps = [
  { title: "Upload the backup file", what: "The file goes to this server, where only the system can read it." },
  { title: "Check what it holds", what: "You see the website, its databases, and what will not move." },
  { title: "Copy and compare", what: "Files and databases are copied into a new account, then compared with the old site if it still runs." },
  { title: "Delete the file", what: "The uploaded file is deleted when the move ends." },
];

function BackupSteps({ current }: { current: number }) {
  return <ol aria-label="Steps of the move" className="flex flex-col gap-3" data-testid="move-steps">
    {backupSteps.map((step, i) => <li key={step.title} aria-current={i === current ? "step" : undefined} className="flex items-start gap-3">
      <span aria-hidden="true" className={`flex size-6 shrink-0 items-center justify-center rounded-full border text-xs font-medium ${i < current ? "border-primary bg-primary text-primary-foreground" : i === current ? "border-primary text-primary" : "border-border text-muted-foreground"}`}>
        {i < current ? <CircleCheck className="size-4" /> : i + 1}
      </span>
      <span className="flex min-w-0 flex-col">
        <span className={`text-sm ${i === current ? "font-medium text-foreground" : "text-muted-foreground"}`}>{step.title}{i < current && <span className="sr-only"> (done)</span>}</span>
        <span className="text-xs text-muted-foreground"><span className="font-medium">What happens:</span> {step.what}</span>
      </span>
    </li>)}
  </ol>;
}

function ProblemBox({ problem }: { problem: Problem }) {
  return <Alert className="text-start" data-testid="move-problem">
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="text-start text-foreground">
      <Explanation problem={problem} />
      <TechnicalDetails className="mt-3">{problem.technical}</TechnicalDetails>
    </AlertDescription>
  </Alert>;
}

export function MoveFromBackup({ onBack }: { onBack: () => void }) {
  const navigate = useNavigate();
  const [file, setFile] = useState<File>();
  const [touched, setTouched] = useState(false);
  const [progress, setProgress] = useState<{ sent: number; total: number }>();
  const [source, setSource] = useState<ArchiveSource>();
  const [busy, setBusy] = useState("");
  const [problem, setProblem] = useState<Problem>();
  const [ended, setEnded] = useState("");
  const controller = useRef<AbortController | undefined>(undefined);
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => { headingRef.current?.focus(); }, [source]);
  useEffect(() => () => controller.current?.abort(), []);

  const fileProblem = checkArchiveFile(file);
  const upload = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (fileProblem || !file) return;
    controller.current = new AbortController();
    setBusy("Uploading the backup file…"); setProblem(undefined); setEnded(""); setProgress({ sent: 0, total: file.size });
    uploadArchive(file, (sent, total) => setProgress({ sent, total }), { signal: controller.current.signal })
      .then((s) => { setSource(s); setFile(undefined); setTouched(false); },
        (error: unknown) => setProblem(problemFrom(error, "The backup file was not taken.")))
      .finally(() => { setBusy(""); setProgress(undefined); });
  };
  const stopUpload = () => controller.current?.abort();
  const move = () => {
    if (!source) return;
    setBusy("Starting the move…"); setProblem(undefined);
    startMigration(source.id, source.archive.user).then(
      (job) => void navigate({ to: "/websites/move/$jobId", params: { jobId: job.id } }),
      (error: unknown) => { setProblem(problemFrom(error, "The move was not started.")); setBusy(""); });
  };
  const discard = () => {
    if (!source) return;
    setBusy("Deleting the file…"); setProblem(undefined);
    cancelSource(source.id).then(
      () => { setSource(undefined); setEnded("Stopped. The uploaded backup file was deleted from this server."); },
      (error: unknown) => setProblem(problemFrom(error, "The uploaded file was not deleted."))).finally(() => setBusy(""));
  };

  const percent = progress && progress.total > 0 ? Math.min(100, Math.round((progress.sent / progress.total) * 100)) : 0;
  const a = source?.archive;
  return <div className="flex flex-col gap-5" data-testid="move-backup" data-stage={source ? "check" : "upload"}>
    {ended && <Alert role="status" className="text-start"><CircleCheck aria-hidden="true" /><AlertTitle>{ended}</AlertTitle></Alert>}
    <div className={`${panel} flex flex-col gap-5`}><BackupSteps current={source ? 1 : 0} /></div>

    {!source && <section className={`${panel} flex flex-col gap-5`} data-testid="move-backup-upload">
      <div className="flex flex-col gap-1">
        <h2 ref={headingRef} tabIndex={-1} className="outline-none">Upload the cPanel backup file</h2>
        <p className="text-sm">Use the full account backup the old host's cPanel made, such as <code>cpmove-name.tar.gz</code> or <code>backup-…_name.tar.gz</code> (in cPanel: Backup, Download a Full Account Backup). One account per file, up to 32 GiB. Email and DNS stay where they are.</p>
      </div>
      <form noValidate onSubmit={upload} className="flex flex-col gap-4">
        <Field data-invalid={touched && Boolean(fileProblem)}>
          <FieldLabel htmlFor="move-backup-file">Backup file</FieldLabel>
          <FieldDescription id="move-backup-file-help">Only this server's system can read the file once it is here. It is deleted when the move ends, or after 24 hours.</FieldDescription>
          <Input id="move-backup-file" type="file" accept=".tar.gz,.tgz,.tar,application/gzip,application/x-tar" className={control} disabled={Boolean(busy)}
            onChange={(e) => { setFile(e.target.files?.[0]); setProblem(undefined); }}
            aria-invalid={touched && Boolean(fileProblem)} aria-describedby={touched && fileProblem ? "move-backup-file-help move-backup-file-error" : "move-backup-file-help"} data-testid="move-backup-file" />
          {touched && fileProblem && <FieldError id="move-backup-file-error">{fileProblem}</FieldError>}
        </Field>
        {progress && <div className="flex flex-col gap-1.5" data-testid="move-backup-progress">
          <Progress value={percent} aria-label="Upload progress" />
          <span className="text-sm text-muted-foreground">{sizeText(progress.sent)} of {sizeText(progress.total)} sent ({percent}%). When it is all here, the server reads the file; that takes a moment more.</span>
        </div>}
        {problem && <ProblemBox problem={problem} />}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" className={control} disabled={Boolean(busy)} data-testid="move-backup-send"><Upload aria-hidden="true" />{busy ? "Uploading…" : "Upload"}</Button>
          {busy && <Button type="button" variant="outline" className={control} onClick={stopUpload}>Stop the upload</Button>}
          {!busy && <Button type="button" variant="outline" className={control} onClick={onBack}>Back</Button>}
        </div>
      </form>
    </section>}

    {source && a && <section className={`${panel} flex flex-col gap-5`} data-testid="move-backup-check">
      <div className="flex flex-col gap-1">
        <h2 ref={headingRef} tabIndex={-1} className="outline-none">Check what the backup file holds</h2>
        <p className="text-sm">Sifruno read the file. Nothing is created on this server until you press Move this website. The file is kept until {dateLabel(source.expires_at)}.</p>
      </div>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
        <dt className="text-muted-foreground">Website</dt><dd className="break-all font-medium" data-testid="move-backup-domain">{a.domain}</dd>
        <dt className="text-muted-foreground">Account name here</dt><dd><code>{a.user}</code></dd>
        <dt className="text-muted-foreground">Files</dt><dd>{sizeText(a.home_bytes)} in the home folder, with public_html</dd>
        <dt className="text-muted-foreground">Databases</dt><dd className="break-all">{a.databases.length ? a.databases.join(", ") : "None"}</dd>
      </dl>
      {a.not_carried.length > 0 && <div className="flex flex-col gap-2" data-testid="move-backup-not-carried">
        <h3 className="text-sm font-medium">What will not move</h3>
        <ul role="list" className="flex flex-col gap-1.5 text-sm">
          {a.not_carried.map((item, i) => <li key={i} className="flex gap-2"><FileArchive aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" /><span>{item.text}{item.where && <span className="block text-xs text-muted-foreground break-all">{item.where}</span>}</span></li>)}
        </ul>
      </div>}
      {problem && <ProblemBox problem={problem} />}
      <div className="flex flex-wrap gap-2">
        <Button type="button" className={control} onClick={move} disabled={Boolean(busy)} data-testid="move-backup-start">{busy === "Starting the move…" ? "Starting…" : "Move this website"}</Button>
        <Button type="button" variant="outline" className={control} onClick={discard} disabled={Boolean(busy)} data-testid="move-backup-discard">Stop and delete the file</Button>
      </div>
    </section>}
    <div role="status" className="sr-only">{busy}</div>
  </div>;
}
