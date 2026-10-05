import { Fragment, useMemo, useState } from "react";
import { ArrowUpRight, GitBranch, Laptop, LockKeyhole, Search, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { dateLabel, safeSource, usd } from "@/lib/api";
import type { BudgetReport, Obligation, PlatformReport, StatusReport, TrailReport } from "@/lib/api";
export function Evidence({ report }: { report: StatusReport }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [selectedId, setSelectedId] = useState<string>();
  const categories = useMemo(
    () => Array.from(new Set(report.entries.map((e) => e.category))).sort(),
    [report.entries],
  );
  const filtered = report.entries.filter(
    (e) =>
      (category === "all" || e.category === category) &&
      `${e.title} ${e.id} ${e.vendor ?? ""} ${e.category}`
        .toLowerCase()
        .includes(query.toLowerCase().trim()),
  );
  const selected = filtered.find((e) => e.id === selectedId);
  return (
    <div className="content-stack">
      <section
        className="evidence-summary"
        aria-label="Current evidence counts"
      >
        <div className="summary-intro">
          <ShieldCheck aria-hidden="true" />
          <div>
            <strong>
              {report.ready
                ? "Certification state reported"
                : "Compatibility is not certified"}
            </strong>
            <span>{report.stage}</span>
          </div>
        </div>
        <dl className="summary-counts">
          <div>
            <dt>Obligations</dt>
            <dd>{report.total}</dd>
          </div>
          <div>
            <dt>Passed</dt>
            <dd>{report.passed}</dd>
          </div>
          <div>
            <dt>Untested</dt>
            <dd>{report.untested}</dd>
          </div>
        </dl>
      </section>
      <div className="readiness-layout">
        <section className="surface gates">
          <div className="section-heading">
            <h2>Release gates</h2>
            <Badge variant="outline">{report.blockers.length} open</Badge>
          </div>
          <ol>
            {report.blockers.map((blocker, i) => (
              <li key={blocker}>
                <span aria-hidden="true">{String(i + 1).padStart(2, "0")}</span>
                <p>{blocker}</p>
              </li>
            ))}
          </ol>
        </section>
        <section className="surface reference">
          <h2>Reference baseline</h2>
          <dl>
            <div>
              <dt>Product</dt>
              <dd>{report.reference.family}</dd>
            </div>
            <div>
              <dt>Documentation</dt>
              <dd>Version {report.reference.documentation_version}</dd>
            </div>
            <div>
              <dt>Exact build</dt>
              <dd>{report.reference.exact_build || "Not frozen"}</dd>
            </div>
            <div>
              <dt>Reference OS</dt>
              <dd>{report.reference.os || "Not captured"}</dd>
            </div>
            <div>
              <dt>Licensed access</dt>
              <dd>
                {report.reference.licensed_reference_verified
                  ? "Verified"
                  : "Not verified"}
              </dd>
            </div>
            <div>
              <dt>Complete inventory</dt>
              <dd>{report.inventory_complete ? "Captured" : "Not captured"}</dd>
            </div>
          </dl>
          <Separator />
          <p>
            {report.pilot_accounts} accounts is the planned pilot size. No
            hosted accounts are reported here.
          </p>
        </section>
      </div>
      <section className="surface obligations">
        <div className="section-heading">
          <div>
            <h2>Compatibility obligations</h2>
            <p>
              Bootstrap inventory · {filtered.length} of {report.entries.length}{" "}
              shown
            </p>
          </div>
          <Badge variant="outline">
            {report.inventory_complete
              ? "Inventory complete"
              : "Inventory incomplete"}
          </Badge>
        </div>
        <FieldGroup className="filter-fields">
          <Field>
            <FieldLabel htmlFor="obligation-search">
              Search obligations
            </FieldLabel>
            <div className="search-field">
              <Search aria-hidden="true" />
              <Input
                id="obligation-search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="API, backup, vendor…"
              />
            </div>
          </Field>
          <Field>
            <FieldLabel htmlFor="obligation-category">Category</FieldLabel>
            <NativeSelect
              id="obligation-category"
              value={category}
              onChange={(event) => setCategory(event.target.value)}
              className="w-full"
            >
              <NativeSelectOption value="all">
                All categories
              </NativeSelectOption>
              {categories.map((c) => (
                <NativeSelectOption key={c} value={c}>
                  {c}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </Field>
        </FieldGroup>
        {filtered.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Obligation</TableHead>
                <TableHead className="category-cell">Category</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>
                  <span className="sr-only">Details</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((entry) => (
                <Fragment key={entry.id}>
                  <TableRow data-selected={selected?.id === entry.id}>
                    <TableCell>
                      <strong>{entry.title}</strong>
                      <span className="obligation-id">{entry.id}</span>
                    </TableCell>
                    <TableCell className="category-cell">
                      {entry.category}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{entry.status}</Badge>
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          setSelectedId(
                            selected?.id === entry.id ? undefined : entry.id,
                          )
                        }
                        aria-expanded={selected?.id === entry.id}
                        aria-controls={
                          selected?.id === entry.id
                            ? "obligation-detail"
                            : undefined
                        }
                        aria-label={`View details for ${entry.title}`}
                      >
                        Details
                        <ArrowUpRight data-icon="inline-end" />
                      </Button>
                    </TableCell>
                  </TableRow>
                  {selected?.id === entry.id && (
                    <TableRow>
                      <TableCell colSpan={4}>
                        <ObligationDetail
                          entry={entry}
                          close={() => setSelectedId(undefined)}
                        />
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Search />
              </EmptyMedia>
              <EmptyTitle>No matching obligations</EmptyTitle>
              <EmptyDescription>
                Try another keyword or choose all categories.
              </EmptyDescription>
            </EmptyHeader>
            <Button
              variant="outline"
              onClick={() => {
                setQuery("");
                setCategory("all");
              }}
            >
              Clear filters
            </Button>
          </Empty>
        )}
      </section>
    </div>
  );
}

function ObligationDetail({
  entry,
  close,
}: {
  entry: Obligation;
  close: () => void;
}) {
  const source = safeSource(entry.source);
  return (
    <aside
      id="obligation-detail"
      className="obligation-detail"
      aria-label={`Details for ${entry.title}`}
    >
      <div className="section-heading">
        <h3>{entry.title}</h3>
        <Button variant="ghost" size="sm" onClick={close}>
          Close details
        </Button>
      </div>
      <p>{entry.reason}</p>
      <dl>
        <div>
          <dt>Identifier</dt>
          <dd>{entry.id}</dd>
        </div>
        {entry.vendor && (
          <div>
            <dt>Vendor</dt>
            <dd>{entry.vendor}</dd>
          </div>
        )}
      </dl>
      {source && (
        <a
          className={cn(buttonVariants({ variant: "outline", size: "sm" }))}
          href={source}
          target="_blank"
          rel="noopener noreferrer"
        >
          Open source documentation
          <ArrowUpRight data-icon="inline-end" />
        </a>
      )}
    </aside>
  );
}

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

export function Platforms({ report }: { report: PlatformReport }) {
  return (
    <div className="content-stack">
      <section className="surface platform-current">
        <div className="section-heading">
          <div>
            <h2>Current control-plane runtime</h2>
            <p>Reported by the running workbench service.</p>
          </div>
          <Badge variant="outline">
            {report.os} / {report.arch}
          </Badge>
        </div>
        <dl>
          <div>
            <dt>Operating system</dt>
            <dd>{report.os_name}</dd>
          </div>
          <div>
            <dt>Runtime mode</dt>
            <dd>{report.mode.replaceAll("-", " ")}</dd>
          </div>
          <div>
            <dt>Compiled target support</dt>
            <dd>
              {report.control_plane_supported
                ? "Supported target"
                : "Not supported"}
            </dd>
          </div>
          <div>
            <dt>Required hosting runtime</dt>
            <dd>{report.hosting_runtime.replaceAll("-", " ")}</dd>
          </div>
          <div>
            <dt>cPanel compatibility</dt>
            <dd>
              {report.compatibility_verified
                ? "Verified by service"
                : "Not verified"}
            </dd>
          </div>
        </dl>
      </section>
      <Alert>
        <Laptop />
        <AlertTitle>
          Native and legacy support need separate evidence
        </AlertTitle>
        <AlertDescription>
          These profiles describe build targets and feasibility candidates. The
          original cPanel ecosystem requires a Linux hosting runtime, including
          a managed Linux guest on Windows or macOS. Old operating systems have
          no completed native compatibility certification here.
        </AlertDescription>
      </Alert>
      <section className="surface platform-profiles">
        <div className="section-heading">
          <h2>Support profiles</h2>
          <Badge variant="outline">{report.profiles.length} profiles</Badge>
        </div>
        {report.profiles.length ? (
          <div className="profile-list">
            {report.profiles.map((profile) => (
              <article key={profile.id}>
                <div className="section-heading">
                  <div>
                    <h3>{profile.label}</h3>
                    <p>{profile.os}</p>
                  </div>
                  <Badge variant="outline">
                    {profile.status.replaceAll("-", " ")}
                  </Badge>
                </div>
                <p>{profile.notes}</p>
              </article>
            ))}
          </div>
        ) : (
          <Empty>
            <EmptyHeader>
              <EmptyTitle>No support profiles returned</EmptyTitle>
              <EmptyDescription>
                The running service has no platform inventory to display.
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}
      </section>
    </div>
  );
}


