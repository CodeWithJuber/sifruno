import { useEffect, useRef, useState } from "react";
import { CircleAlert, Copy, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Explanation, TechnicalDetails } from "@/NewWebsite";
import type { Problem } from "@/NewWebsite";

// Parts the "Move a website here" pages share: a problem with its next
// step and Technical details, and a command or line to copy.

export function ProblemBox({ problem, onRetry }: { problem: Problem; onRetry?: () => void }) {
  return <Alert className="text-start" data-testid="move-problem">
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="text-start text-foreground">
      <Explanation problem={problem} />
      <TechnicalDetails className="mt-3">{problem.technical}</TechnicalDetails>
      {onRetry && <Button variant="outline" size="sm" className="mt-3" onClick={onRetry}><RefreshCw aria-hidden="true" />Try again</Button>}
    </AlertDescription>
  </Alert>;
}

// A command or line to copy, with a button whose result is announced in a
// status bubble beside it (never inside the button, whose children are not
// announced). Copying again is allowed at any time.
export function CopyBlock({ id, label, value }: { id: string; label: string; value: string }) {
  const [message, setMessage] = useState("");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    window.clearTimeout(timer.current);
    setMessage("");
    let ok = true;
    try { await navigator.clipboard.writeText(value); } catch { ok = false; }
    requestAnimationFrame(() => setMessage(ok ? "Copied" : "Copy failed: select the text and copy it yourself"));
    timer.current = window.setTimeout(() => setMessage(""), 2500);
  };
  return <div className="flex flex-col gap-2">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span id={`${id}-label`} className="text-sm font-medium">{label}</span>
      <span className="flex items-center gap-2">
        <span role="status" className="text-xs text-muted-foreground">{message}</span>
        <Button type="button" variant="outline" size="sm" onClick={() => void copy()} aria-describedby={`${id}-label`} data-testid={`${id}-copy`}><Copy aria-hidden="true" />Copy</Button>
      </span>
    </div>
    <pre id={id} tabIndex={0} aria-labelledby={`${id}-label`} className="overflow-x-auto rounded-md border border-border bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">{value}</pre>
  </div>;
}
