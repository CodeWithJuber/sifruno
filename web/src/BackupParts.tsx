import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Check, CircleAlert, CircleCheck, Copy, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { BackupsApiError, drillLine, resultTechnical } from "@/lib/site-backups-api";
import type { DrillRecord, JobResult, PruneRecord } from "@/lib/site-backups-api";
import { formatWhen, kindLabel, whatLabel } from "@/lib/site-backups-api";

// Pieces the Backup storage page and a website's Backups page share. The
// base styles colour <p> and <a> outside Tailwind's layers, so coloured text
// uses div or span, as on the other Websites screens.

export const panel = "rounded-lg border border-border bg-card";
export const control = "h-10 pointer-coarse:h-12";

export interface Problem { what: string; why: string; next: string; technical: string; status: number }

export function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof BackupsApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
}

export function TechnicalDetails({ children }: { children: ReactNode }) {
  return <details className="text-sm">
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
    <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{children}</div>
  </details>;
}

// What happened (the title), why, what to do next, and the request under
// Technical details. role="alert": a failure is announced at once.
export function ProblemAlert({ problem, onRetry, testId }: { problem: Problem; onRetry?: () => void; testId: string }) {
  return <Alert variant="destructive" className="text-start" data-testid={testId}>
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
      <div className="flex flex-col gap-1.5 text-sm">
        <div className="text-foreground">{problem.why}</div>
        <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {problem.next}</div>
      </div>
      <TechnicalDetails>{problem.technical}</TechnicalDetails>
      {onRetry && <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}><RefreshCw aria-hidden="true" />Try again</Button>}
    </AlertDescription>
  </Alert>;
}

// A finished backup or restore: its message, and the step, the broker's
// words and the backup's id under Technical details.
export function ResultAlert({ result, timezone, testId }: { result: JobResult; timezone: string; testId: string }) {
  const failed = result.status === "failed";
  const what = result.kind === "restore" && result.what ? ` (${whatLabel[result.what].toLowerCase()})` : "";
  const technical = resultTechnical(result);
  return <Alert role={undefined} variant={failed ? "destructive" : "default"} className="text-start" data-testid={testId} data-status={result.status}>
    {failed ? <CircleAlert aria-hidden="true" /> : <CircleCheck className="text-primary" aria-hidden="true" />}
    <AlertTitle>{kindLabel[result.kind]}{what} {failed ? "failed" : "finished"} {formatWhen(result.finished_at, timezone)}</AlertTitle>
    <AlertDescription className="flex flex-col gap-2 text-start text-foreground">
      <div className="text-sm text-foreground">{result.message}</div>
      <div className="text-xs text-muted-foreground">Started by {result.actor === "scheduler" ? "the nightly schedule" : result.actor}.</div>
      {technical && <TechnicalDetails>{technical}</TechnicalDetails>}
    </AlertDescription>
  </Alert>;
}

// "Last restore drill: passed or failed, when, which site".
export function DrillSummary({ drill, timezone }: { drill: DrillRecord | null; timezone: string }) {
  const technical = drill ? resultTechnical(drill) : "";
  return <div className="flex flex-col gap-2" data-testid="last-drill" data-passed={drill ? String(drill.passed) : undefined}>
    <div className="flex items-start gap-2 text-sm">
      {drill && (drill.passed ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" /> : <CircleAlert className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden="true" />)}
      <span><span className="font-medium text-foreground">Last restore drill:</span> <span className="text-foreground">{drillLine(drill, timezone)}</span></span>
    </div>
    {drill && <div className="text-sm text-muted-foreground">{drill.message}</div>}
    {technical && <TechnicalDetails>{technical}{drill?.files ? `\nfiles compared: ${drill.files}` : ""}</TechnicalDetails>}
  </div>;
}

// Copies text with the Async Clipboard API. The status next to the button
// (not inside it) is both the visible feedback and the live region, and the
// button stays enabled so a failed copy can be tried again.
export function CopyButton({ text, label, testId }: { text: string; label: string; testId: string }) {
  const [state, setState] = useState<"" | "Copied" | "Copy failed">("");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    window.clearTimeout(timer.current);
    setState("");
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch { ok = false; /* Clipboard access can be denied; say so. */ }
    setState(ok ? "Copied" : "Copy failed");
    timer.current = window.setTimeout(() => setState(""), 2500);
  };
  return <span className="inline-flex items-center gap-2">
    <Button type="button" variant="outline" className={control} onClick={() => void copy()} data-testid={testId}>
      {state === "Copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}{label}
    </Button>
    <span role="status" className={`text-sm ${state === "Copy failed" ? "text-destructive" : "text-muted-foreground"}`}>{state}</span>
  </span>;
}

export function PruneSummary({ prune, timezone }: { prune: PruneRecord | null; timezone: string }) {
  if (!prune) return <div className="text-sm text-muted-foreground" data-testid="last-prune">Old backups have not been cleaned up yet. The first clean-up runs after the first nightly backup.</div>;
  return <div className="flex flex-col gap-2" data-testid="last-prune">
    <div className="text-sm"><span className="font-medium text-foreground">Last clean-up:</span> <span className="text-foreground">{prune.passed ? `${prune.removed === 1 ? "1 old backup" : `${prune.removed} old backups`} removed` : "failed"}, {formatWhen(prune.at, timezone)}.</span></div>
    {!prune.passed && <div className="text-sm text-muted-foreground">{prune.message}</div>}
    {(prune.step || prune.detail) && <TechnicalDetails>{resultTechnical(prune)}</TechnicalDetails>}
  </div>;
}
