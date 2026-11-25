import { CircleAlert, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

// An error as the panel shows it: what happened (the title), why, what to do
// next, and the request under "Technical details".
export interface Problem { what: string; why: string; next: string; technical: string; status: number }

export function ProblemAlert({ problem, onRetry, testId }: { problem: Problem; onRetry?: () => void; testId: string }) {
  return <Alert variant="destructive" className="text-start" data-testid={testId}>
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
      <div className="flex flex-col gap-1.5 text-sm">
        <div className="text-foreground">{problem.why}</div>
        <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {problem.next}</div>
      </div>
      {problem.technical && <details className="text-sm">
        <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
        <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{problem.technical}</div>
      </details>}
      {onRetry && <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}><RefreshCw aria-hidden="true" />Try again</Button>}
    </AlertDescription>
  </Alert>;
}
