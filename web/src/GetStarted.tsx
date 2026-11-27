import { useEffect, useId, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Circle, CircleCheck, CircleHelp, Clock3, ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress, ProgressLabel } from "@/components/ui/progress";
import { passkeyLoginStatus } from "@/lib/auth-api";
import type { PasskeyStatus } from "@/lib/auth-api";
import { listCustomers } from "@/lib/customers-api";
import type { CustomerList } from "@/lib/customers-api";
import { getStartedProgress, getStartedSteps, nextStep } from "@/lib/get-started";
import type { Reading, Step, StepState } from "@/lib/get-started";
import { getBackupStorage } from "@/lib/site-backups-api";
import type { BackupStorage } from "@/lib/site-backups-api";
import { listWebsites } from "@/lib/websites-api";
import type { Website } from "@/lib/websites-api";
import { listWebsiteJobs } from "@/lib/wordpress-api";
import type { WebsiteJob } from "@/lib/wordpress-api";
import { linkButton, panel } from "@/WebsitesPage";

// Home's "Get started" list for an admin: what makes a new server ready for
// customers, from the server's real state (lib/get-started.ts). It reads the
// five sources again when Home opens and on Refresh. Once every required
// step is done the admin can hide it; the choice is this browser's only, and
// the list comes back if a step stops being done.

const hiddenKey = "sifruno-get-started-hidden";
function readHidden(): boolean {
  try { return localStorage.getItem(hiddenKey) === "1"; } catch { return false; }
}
function writeHidden() {
  try { localStorage.setItem(hiddenKey, "1"); } catch { /* A private window may refuse storage; the list then hides until reload. */ }
}

const loading = { loading: true } as const;
const failed = (error: unknown): { error: string } => ({ error: error instanceof Error ? error.message : "The request failed." });

function useReading<T>(read: (signal: AbortSignal) => Promise<T>, revision: number): Reading<T> {
  const [reading, setReading] = useState<Reading<T>>(loading);
  useEffect(() => {
    const controller = new AbortController();
    read(controller.signal)
      .then((data) => { if (!controller.signal.aborted) setReading({ data }); })
      .catch((error: unknown) => { if (!controller.signal.aborted) setReading(failed(error)); });
    return () => controller.abort();
  }, [read, revision]);
  return reading;
}

// Module-level, so each reading's effect runs only when the revision changes.
const readAddress = (): Promise<PasskeyStatus> => passkeyLoginStatus();
const readWebsites = (signal: AbortSignal): Promise<Website[]> => listWebsites({ signal });
const readJobs = (signal: AbortSignal): Promise<WebsiteJob[]> => listWebsiteJobs({ signal });
const readBackups = (signal: AbortSignal): Promise<BackupStorage> => getBackupStorage({ signal });
const readCustomers = (signal: AbortSignal): Promise<CustomerList> => listCustomers({ signal });

const stateWords: Record<StepState, string> = { done: "Done", todo: "To do", waiting: "Waiting", unknown: "Not checked" };

function StateIcon({ state }: { state: StepState }) {
  const common = "mt-0.5 size-5 shrink-0";
  if (state === "done") return <CircleCheck className={`${common} text-primary`} aria-hidden="true" />;
  if (state === "waiting") return <Clock3 className={`${common} text-muted-foreground`} aria-hidden="true" />;
  if (state === "unknown") return <CircleHelp className={`${common} text-muted-foreground`} aria-hidden="true" />;
  return <Circle className={`${common} text-muted-foreground`} aria-hidden="true" />;
}

function StepAction({ step, primary, howId, howOpen, onHow }: { step: Step; primary: boolean; howId: string; howOpen: boolean; onHow: () => void }) {
  const action = step.action;
  if (!action) return null;
  // A done step keeps a quiet way to its screen; the next step is the one
  // primary button in the list.
  const variant = primary ? "default" : step.state === "done" ? "ghost" : "outline";
  const testId = `get-started-${step.id}-action`;
  if (action.kind === "page") return <Link to={action.to} className={linkButton(variant, "shrink-0")} data-testid={testId}>{action.label}</Link>;
  if (action.kind === "address") return <a href={action.href} target="_blank" rel="noopener noreferrer" className={linkButton(variant, "shrink-0")} data-testid={testId}>
    {action.label}<ExternalLink aria-hidden="true" /><span className="sr-only"> (opens in a new tab)</span>
  </a>;
  return <Button variant={variant} className="h-9 shrink-0 pointer-coarse:h-11" aria-expanded={howOpen} aria-controls={howId} onClick={onHow} data-testid={testId}>{howOpen ? "Hide the steps" : action.label}</Button>;
}

export function GetStarted({ revision, origin }: { revision: number; origin: string }) {
  const address = useReading(readAddress, revision);
  const websites = useReading(readWebsites, revision);
  const jobs = useReading(readJobs, revision);
  const backups = useReading(readBackups, revision);
  const customers = useReading(readCustomers, revision);
  const [hidden, setHidden] = useState(readHidden);
  const [openHow, setOpenHow] = useState<string>();
  const baseId = useId();
  const steps = getStartedSteps({ address, websites, jobs, backups, customers, origin });
  const { done, total, complete } = getStartedProgress(steps);
  const next = nextStep(steps);
  const checking = steps.some((s) => s.status === "Checking…");
  if (complete && hidden) return null;
  return <section className={`${panel} min-w-0 overflow-hidden`} aria-labelledby={`${baseId}-heading`} data-testid="get-started" data-complete={String(complete)} aria-busy={checking}>
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-4 md:px-5">
      <div className="min-w-0 flex-1 basis-64">
        <h2 id={`${baseId}-heading`}>{complete ? "Your server is ready for customers" : "Get started"}</h2>
        <div className="mt-1 text-sm text-muted-foreground">{complete
          ? "Every step below is done. The list stays here until you hide it, and comes back if a step stops being done."
          : "What makes this server ready for customers. Each step ticks itself when the panel sees it done."}</div>
      </div>
      {complete && <Button variant="ghost" className="h-9 pointer-coarse:h-11" onClick={() => { writeHidden(); setHidden(true); }} data-testid="get-started-hide">Hide this list</Button>}
    </div>
    <Progress value={done} max={total} getAriaValueText={() => `${done} of ${total} steps done`} className="items-baseline px-4 pt-4 md:px-5" data-testid="get-started-progress">
      <ProgressLabel className="text-sm font-medium">Ready for customers</ProgressLabel>
      <span className="ms-auto text-sm text-muted-foreground tabular-nums" aria-hidden="true">{done} of {total} steps done</span>
    </Progress>
    <ol className="mt-3 flex flex-col">
      {steps.map((step) => {
        const howId = `${baseId}-${step.id}-how`;
        const howOpen = openHow === step.id;
        return <li key={step.id} className="flex flex-wrap items-start gap-x-3 gap-y-3 border-t border-border px-4 py-4 md:px-5" data-testid={`get-started-${step.id}`} data-state={step.state}>
          <StateIcon state={step.state} />
          <div className="min-w-0 flex-1 basis-56">
            <h3 className="flex flex-wrap items-center gap-2 text-sm font-medium text-foreground">{step.title}{step.optional && <Badge variant="outline" className="text-muted-foreground">Optional</Badge>}</h3>
            <div className="mt-0.5 text-sm text-muted-foreground">{step.why}</div>
            <div className="mt-1.5 text-sm text-foreground wrap-anywhere" data-testid={`get-started-${step.id}-status`}><span className="sr-only">{stateWords[step.state]}: </span>{step.status}</div>
            {step.action?.kind === "how" && <ol id={howId} hidden={!howOpen} className="mt-2 flex list-decimal flex-col gap-1.5 ps-5 text-sm text-foreground marker:text-muted-foreground">
              {step.action.lines.map((line) => <li key={line} className="wrap-anywhere">{line}</li>)}
            </ol>}
          </div>
          <StepAction step={step} primary={step.id === next} howId={howId} howOpen={howOpen} onHow={() => setOpenHow((current) => current === step.id ? undefined : step.id)} />
        </li>;
      })}
    </ol>
  </section>;
}
