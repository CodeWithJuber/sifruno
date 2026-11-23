import { GitBranch, LockKeyhole } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { dateLabel, usd } from "@/lib/api";
import type { BudgetReport, TrailReport } from "@/lib/api";
export function Trail({ report }: { report: TrailReport }) {
  return (
    <div className="content-stack">
      <Alert>
        <GitBranch />
        <AlertTitle>Experimental scoped file recovery</AlertTitle>
        <AlertDescription>
          Encrypted before-images and signed change events cover explicitly
          selected local files. These records do not certify a server backup,
          database restore or cPanel migration.
        </AlertDescription>
      </Alert>
      <section className="surface">
        <div className="section-heading">
          <div>
            <h2>Recorded changes</h2>
            <p>Read from the local encrypted trail store.</p>
          </div>
          <Badge variant="outline">{report.items.length} changes</Badge>
        </div>
        {report.items.length ? (
          <div className="trail-list">
            {report.items.map((item) => (
              <article key={item.id}>
                <div className="section-heading">
                  <h3>{item.reason}</h3>
                  <Badge variant="outline">{item.state}</Badge>
                </div>
                <p>
                  {item.actor} · {dateLabel(item.created)} · {item.files}{" "}
                  {item.files === 1 ? "file" : "files"}
                </p>
                <dl>
                  <div>
                    <dt>Change</dt>
                    <dd>{item.id}</dd>
                  </div>
                  <div>
                    <dt>Parent</dt>
                    <dd>{item.parent || "First checkpoint"}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        ) : (
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <GitBranch />
              </EmptyMedia>
              <EmptyTitle>No changes recorded</EmptyTitle>
              <EmptyDescription>
                Create and apply a scoped checkpoint through the local CLI, then
                refresh this view. A zero count is an empty history.
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}
      </section>
      <section className="trail-principles">
        <div>
          <span>01</span>
          <h2>Explain the change</h2>
          <p>Each checkpoint carries its actor, reason and parent.</p>
        </div>
        <div>
          <span>02</span>
          <h2>Keep the evidence</h2>
          <p>Before-images stay encrypted; events have a signed hash chain.</p>
        </div>
        <div>
          <span>03</span>
          <h2>Respect new edits</h2>
          <p>Rollback checks current files and rejects content conflicts.</p>
        </div>
      </section>
    </div>
  );
}

export function Budget({ report }: { report: BudgetReport }) {
  const allocated = report.spent_usd_micros + report.reserved_usd_micros;
  const ratio =
    report.cap_usd_micros > 0
      ? Math.min(100, (allocated / report.cap_usd_micros) * 100)
      : 0;
  return (
    <div className="content-stack">
      {(report.over_cap || report.reconciliation_required) && <Alert variant="destructive"><AlertTitle>Spending needs attention</AlertTitle><AlertDescription>{report.over_cap ? "The ledger reports spending or reservations above the monthly cap." : "The ledger requires cost reconciliation before more paid work."}</AlertDescription></Alert>}
      <section className="surface budget-surface">
        <div className="section-heading">
          <div>
            <h2>Monthly allowance</h2>
            <p>{report.month} · USD ledger</p>
          </div>
          <Badge variant="outline">
            {report.approval_required
              ? "Operator approval required"
              : "Approval policy not enforced"}
          </Badge>
        </div>
        <div className="budget-total">
          <span>Available</span>
          <strong>{usd(report.remaining_usd_micros)}</strong>
          <span>of {usd(report.cap_usd_micros)} monthly cap</span>
        </div>
        <div
          className="budget-meter"
          role="meter"
          aria-label="Spent and reserved allowance"
          aria-valuemin={0}
          aria-valuemax={report.cap_usd_micros}
          aria-valuenow={Math.min(allocated, report.cap_usd_micros)}
          aria-valuetext={`${usd(allocated)} spent or reserved of ${usd(report.cap_usd_micros)}`}
        >
          <span style={{ width: `${ratio}%` }} />
        </div>
        <dl className="budget-breakdown">
          <div>
            <dt>Spent</dt>
            <dd>{usd(report.spent_usd_micros)}</dd>
          </div>
          <div>
            <dt>Reserved</dt>
            <dd>{usd(report.reserved_usd_micros)}</dd>
          </div>
          <div>
            <dt>Remaining</dt>
            <dd>{usd(report.remaining_usd_micros)}</dd>
          </div>
        </dl>
      </section>
      <Alert>
        <LockKeyhole />
        <AlertTitle>Read-only spending view</AlertTitle>
        <AlertDescription>
          This screen reads the local budget ledger. Provider billing
          reconciliation and paid model execution need a separately verified
          integration. No model request is issued from this interface.
        </AlertDescription>
      </Alert>
    </div>
  );
}
