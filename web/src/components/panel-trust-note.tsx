import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ExternalLink, TriangleAlert } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { buttonVariants } from "@/components/ui/button";
import { passkeyLoginStatus } from "@/lib/auth-api";
import { panelTrustNote } from "@/lib/get-started";
import type { TrustNote, TrustPlace } from "@/lib/get-started";

// A short warning beside a link that opens at the panel's name (a
// customer's setup link, "Open phpMyAdmin") while browsers do not trust
// the panel's certificate there: what the person will see, why, and the
// next step. It reads what Get started's first step reads; if that cannot
// be read, it says nothing rather than guess.
export function PanelTrustNote({ place, admin, testId }: { place: TrustPlace; admin: boolean; testId: string }) {
  const [note, setNote] = useState<TrustNote>();
  useEffect(() => {
    let live = true;
    passkeyLoginStatus()
      .then((status) => { if (live) setNote(panelTrustNote(status, window.location.origin, place, admin)); })
      .catch(() => { if (live) setNote(undefined); });
    return () => { live = false; };
  }, [place, admin]);
  if (!note) return null;
  const control = buttonVariants({ variant: "outline", size: "sm" });
  return <Alert className="text-start" data-testid={testId} data-state={note.state}>
    <TriangleAlert aria-hidden="true" />
    <AlertTitle>{note.title}</AlertTitle>
    <AlertDescription className="flex flex-col gap-2 text-start text-foreground">
      <div>{note.what}</div>
      <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {note.next}</div>
      {admin && <div className="flex flex-wrap gap-2">
        {note.href && <a href={note.href} target="_blank" rel="noopener noreferrer" className={control}>
          Open {new URL(note.href).host}<ExternalLink className="rtl:-scale-x-100" aria-hidden="true" /><span className="sr-only"> (opens in a new tab)</span>
        </a>}
        <Link to="/" className={control} data-testid={`${testId}-get-started`}>Open Get started</Link>
      </div>}
    </AlertDescription>
  </Alert>;
}
