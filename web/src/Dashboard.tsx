import { Fragment, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Radio as RadioPrimitive } from "@base-ui/react/radio";
import { RadioGroup as RadioGroupPrimitive } from "@base-ui/react/radio-group";
import { Archive, ArrowDown, ArrowUp, ArrowUpRight, Clock3, Cpu, Database, Folder, Globe, Info, Layers, LockKeyhole, MemoryStick, Monitor, Network, Search, Server, Users } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { PlatformReport, ServerReport, ServerSample, ServiceItem, ServicesReport } from "@/lib/api";
import { dateLabel } from "@/lib/api";

// Home and Server › Services: the hosting modules, the server's measured
// resources and the read-only service inventory. Server › Storage and
// Network (HostResources.tsx) reuse the pieces exported here. The base
// styles colour <p> outside Tailwind's layers, so coloured text uses div or
// span, as on the other new screens.

export const panel = "rounded-lg border border-border bg-card";

export const percent = (value: number | null) => value === null ? "Unavailable" : `${value.toFixed(1)}%`;
export function bytes(value: number | null): string {
  if (value === null) return "Unavailable";
  if (value === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const power = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** power).toLocaleString(undefined, { maximumFractionDigits: power ? 1 : 0 })} ${units[power]}`;
}
export function uptime(value: number | null): string {
  if (value === null) return "Unavailable";
  const days = Math.floor(value / 86400);
  const hours = Math.floor(value % 86400 / 3600);
  const minutes = Math.floor(value % 3600 / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${Math.floor(value % 60)}s`;
  return `${Math.floor(value)}s`;
}
const time = (timestamp: string) => new Date(timestamp).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });

// A one-of-a-few choice drawn as joined segments. It stays a radio group, as
// the Astryx control was: one tab stop, arrow keys move the choice.
// data-value keeps the hook the older browser checks select segments by.
export interface Segment { value: string; label: string; short?: string }
export function Segments({ label, value, onChange, options, testId }: { label: string; value: string; onChange: (value: string) => void; options: readonly Segment[]; testId?: string }) {
  return <RadioGroupPrimitive aria-label={label} value={value} onValueChange={(next) => onChange(String(next))} data-testid={testId}
    className="inline-flex h-8 shrink-0 items-center gap-0.5 rounded-lg border border-input bg-card p-0.5 pointer-coarse:h-11">
    {options.map((option) => <RadioPrimitive.Root key={option.value} value={option.value} data-value={option.value} aria-label={option.short ? option.label : undefined}
      className="inline-flex h-full min-w-10 cursor-pointer items-center justify-center rounded-md px-2.5 text-xs font-medium whitespace-nowrap text-muted-foreground outline-none select-none hover:bg-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary focus-visible:outline-solid data-checked:bg-primary data-checked:text-primary-foreground data-checked:hover:bg-primary">
      {option.short ?? option.label}
    </RadioPrimitive.Root>)}
  </RadioGroupPrimitive>;
}

export const rangeSegments: readonly Segment[] = [
  { value: "60", label: "1 minute", short: "1m" },
  { value: "300", label: "5 minutes", short: "5m" },
  { value: "600", label: "10 minutes", short: "10m" },
];

// One reading in the row of tiles. The row draws the lines between tiles.
export function MetricTile({ label, icon, children }: { label: string; icon: ReactNode; children: ReactNode }) {
  return <div className="flex min-h-30 min-w-0 flex-col gap-2 bg-card p-4">
    <div className="flex items-center gap-2 text-xs text-muted-foreground [&_svg]:size-4">{icon}<span>{label}</span></div>
    {children}
  </div>;
}
export const metricRow = "grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border @3xl:grid-cols-4";
export const metricValue = "block text-2xl leading-tight font-semibold tracking-tight tabular-nums text-foreground wrap-anywhere @max-sm:text-xl";
export const metricNote = "text-xs text-muted-foreground wrap-anywhere";

// A reading that is partly or wholly missing. It is a state, not an error.
export function CollectorNotice({ children }: { children: ReactNode }) {
  return <div className="flex items-start gap-2 text-xs text-muted-foreground" role="status"><Info className="mt-px size-4 shrink-0" aria-hidden="true" /><span className="wrap-anywhere">{children}</span></div>;
}

export function TechnicalDetails({ children }: { children: ReactNode }) {
  return <details className="text-sm">
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
    <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{children}</div>
  </details>;
}

export function ChartLegend({ first, second }: { first: string; second: string }) {
  return <div className="flex items-center justify-center gap-6 text-xs text-muted-foreground">
    <span className="flex items-center gap-2"><i className="inline-block size-2 rounded-full bg-primary" />{first}</span>
    <span className="flex items-center gap-2"><i className="inline-block size-2 rounded-full bg-(--chart-memory)" />{second}</span>
  </div>;
}
export const chartGrid = "stroke-border";
export const chartText = "fill-muted-foreground text-[11px] max-[480px]:text-sm";

type HostingTarget = "websites" | "accounts" | "backups" | "files" | "access";
const hostingModules = [
  { id: "websites", label: "Websites", description: "Create and manage your websites.", detail: "WordPress sites", icon: Globe },
  { id: "accounts", label: "Customers", description: "Customer accounts and their home folders.", detail: "Linux broker required", icon: Users },
  { id: "backups", label: "Backups", description: "Create, download and restore website backups.", detail: "Native ZIP snapshots", icon: Archive },
  { id: "files", label: "Files", description: "View and edit your website's files.", detail: "Website files", icon: Folder },
  { id: "access", label: "Security", description: "Sessions signed in to this panel.", detail: "Operator sessions", icon: LockKeyhole },
] as const;

export function HostingWorkspace({ publicPreview, platform, onNavigate, onPreview }: { publicPreview: boolean; platform?: PlatformReport; onNavigate: (target: HostingTarget) => void; onPreview: () => void }) {
  return <section className={`${panel} min-w-0 overflow-hidden`} aria-labelledby="hosting-heading" data-testid="hosting-workspace">
    <div className="flex items-center justify-between gap-4 border-b border-border px-4 py-4 md:px-5">
      <div className="min-w-0">
        <h2 id="hosting-heading">{publicPreview ? "Public panel preview" : "Hosting"}</h2>
        <div className="mt-1 text-sm text-muted-foreground">{publicPreview ? "Host monitoring and a tour of the workspace." : "Open a module to work on this server."}</div>
      </div>
      <Badge variant="outline" className="text-muted-foreground">{publicPreview ? "Preview" : "Local panel"}</Badge>
    </div>
    {publicPreview ? <div className="flex flex-wrap items-center gap-4 px-4 py-5 md:px-5">
      <Layers className="size-7 text-primary" aria-hidden="true" />
      <div className="min-w-0 flex-1 basis-60">
        <h3>Explore the panel</h3>
        <div className="mt-1 max-w-2xl text-sm text-muted-foreground">The tour uses sample content. Private websites, accounts, backups, files and access controls stay in the local panel.</div>
      </div>
      <Button variant="outline" className="h-9 pointer-coarse:h-11" onClick={onPreview} data-testid="open-panel-preview">Explore panel</Button>
    </div> : <>
      <ul role="list" className="grid sm:grid-cols-2">{hostingModules.map(({ id, label, description, detail, icon: Icon }, index) => {
        const lead = id === "websites";
        return <li key={id} className={`min-w-0 border-b border-border ${lead ? "sm:col-span-2" : index % 2 === 1 ? "sm:border-e" : ""}`}>
          <button type="button" onClick={() => onNavigate(id)} aria-label={`Open ${label}`} data-testid={`workspace-${id}`}
            className={`group/module flex h-full min-h-18 w-full min-w-0 items-center gap-3.5 px-4 py-4 text-start text-foreground hover:bg-muted focus-visible:relative focus-visible:z-10 focus-visible:-outline-offset-3! md:px-5 ${lead ? "bg-secondary" : ""}`}>
            <Icon className="size-5 text-primary" aria-hidden="true" />
            <span className="min-w-0 flex-1">
              <span className={`block font-medium ${lead ? "text-base" : "text-sm"}`}>{label}</span>
              <span className="mt-0.5 block text-sm text-muted-foreground wrap-anywhere">{description}</span>
            </span>
            {lead && <span className="hidden text-xs text-muted-foreground md:inline">{detail}</span>}
            <ArrowUpRight className="size-4 text-muted-foreground group-hover/module:text-primary rtl:-scale-x-100" aria-hidden="true" />
          </button>
        </li>;
      })}</ul>
      <div className="flex items-start gap-2 px-4 py-2.5 text-xs text-muted-foreground md:px-5">
        <Info className="mt-px size-3.5 shrink-0" aria-hidden="true" />
        <span>{platform && platform.os !== "linux" ? "Native account actions require Linux. Static-site tools and monitoring remain separate modules." : "Account availability is checked after sign-in. A configured, admitted Linux broker is required for native account actions."}</span>
      </div>
    </>}
  </section>;
}

function paths(samples: ServerSample[], key: "cpu_usage_percent" | "memory_used_percent", x: (s: ServerSample) => number) {
  let open = false;
  return samples.map((sample) => {
    const value = sample[key];
    if (value === null) { open = false; return ""; }
    const command = open ? "L" : "M";
    open = true;
    return `${command}${x(sample).toFixed(2)},${(200 - value * 1.65).toFixed(2)}`;
  }).join(" ");
}

function Sparkline({ history }: { history: ServerSample[] }) {
  const values = history.slice(-30);
  if (!values.some((s) => s.cpu_usage_percent !== null)) return <div className={metricNote}>Collecting first CPU reading</div>;
  const start = Date.parse(values[0].sampled_at), end = Date.parse(values.at(-1)!.sampled_at);
  const x = (sample: ServerSample) => 8 + (end === start ? 0.5 : (Date.parse(sample.sampled_at) - start) / (end - start)) * 644;
  return <svg className="mt-auto block h-5 w-full text-primary" viewBox="0 30 660 180" preserveAspectRatio="none" role="img" aria-label="Recent CPU activity from recorded samples">
    <path d={paths(values, "cpu_usage_percent", x)} fill="none" stroke="currentColor" strokeWidth="2" vectorEffect="non-scaling-stroke" />
    {values.length === 1 && values[0].cpu_usage_percent !== null && <circle cx={330} cy={200 - values[0].cpu_usage_percent * 1.65} r="3" fill="currentColor" />}
  </svg>;
}

export function ResourceChart({ report, range, setRange }: { report: ServerReport; range: string; setRange: (v: string) => void }) {
  const [compact, setCompact] = useState(() => window.matchMedia("(max-width: 480px)").matches);
  useEffect(() => {
    const media = window.matchMedia("(max-width: 480px)");
    const update = () => setCompact(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  const history = report.history;
  const start = history.length ? Date.parse(history[0].sampled_at) : Date.parse(report.sampled_at);
  const end = history.length ? Date.parse(history.at(-1)!.sampled_at) : start;
  const width = compact ? 400 : 660;
  const left = 48, right = width - 18;
  const x = (sample: ServerSample) => left + (end === start ? 0.5 : (Date.parse(sample.sampled_at) - start) / (end - start)) * (right - left);
  const chartTime = (timestamp: string) => new Date(timestamp).toLocaleTimeString(undefined, {
    hour: "2-digit", minute: "2-digit", ...(end - start < 120000 ? { second: "2-digit" } : {}), hour12: false,
  });
  const hasValues = history.some((s) => s.cpu_usage_percent !== null || s.memory_used_percent !== null);
  return <section className={`${panel} min-w-0`} aria-labelledby="activity-heading">
    <div className="flex flex-wrap items-center justify-between gap-3 p-4">
      <h2 id="activity-heading">Resource activity</h2>
      <Segments label="Chart time range" value={range} onChange={setRange} options={rangeSegments} />
    </div>
    <div className="px-3 max-[480px]:px-2">
      {/* The chart's own coordinates are left-to-right; the page around it follows the reading direction. */}
      <svg className="block h-47 w-full [direction:ltr] max-[480px]:h-43.5" viewBox={`0 0 ${width} 246`} role="img" aria-labelledby="activity-title activity-description">
        <title id="activity-title">CPU and memory utilization</title>
        <desc id="activity-description">{history.length} actual samples at {report.collector.interval_seconds}-second intervals. {history.length ? `From ${chartTime(history[0].sampled_at)} to ${chartTime(history.at(-1)!.sampled_at)}.` : "History is collecting."} Gaps represent unavailable readings.</desc>
        {[0, 25, 50, 75, 100].map((value) => <g key={value}>
          <line className={chartGrid} x1={left} x2={right} y1={200 - value * 1.65} y2={200 - value * 1.65} />
          <text className={chartText} x={compact ? 39 : 34} y={204 - value * 1.65} textAnchor="end">{value}%</text>
        </g>)}
        {[0, 1, 2, 3, 4].map((index) => <g key={index}>
          <line className={chartGrid} x1={left + index * (right - left) / 4} x2={left + index * (right - left) / 4} y1="35" y2="200" />
          {history.length > 1 && (!compact || index % 2 === 0) && <text className={chartText} x={left + index * (right - left) / 4} y="226" textAnchor={index === 0 ? "start" : index === 4 ? "end" : "middle"}>{chartTime(new Date(start + (end - start) * index / 4).toISOString())}</text>}
        </g>)}
        <g data-testid="cpu-chart" className="text-primary">
          <path d={paths(history, "cpu_usage_percent", x)} fill="none" stroke="currentColor" strokeWidth="2" vectorEffect="non-scaling-stroke" />
          {history.map((s) => s.cpu_usage_percent === null ? null : <circle key={s.sampled_at} cx={x(s)} cy={200 - s.cpu_usage_percent * 1.65} r={history.length === 1 ? 3 : 2} fill="currentColor"><title>{chartTime(s.sampled_at)} · CPU {percent(s.cpu_usage_percent)}</title></circle>)}
        </g>
        <g data-testid="memory-chart" className="text-(--chart-memory)">
          <path d={paths(history, "memory_used_percent", x)} fill="none" stroke="currentColor" strokeWidth="2" vectorEffect="non-scaling-stroke" />
          {history.map((s) => s.memory_used_percent === null ? null : <circle key={s.sampled_at} cx={x(s)} cy={200 - s.memory_used_percent * 1.65} r={history.length === 1 ? 3 : 2} fill="currentColor"><title>{chartTime(s.sampled_at)} · Memory {percent(s.memory_used_percent)}</title></circle>)}
        </g>
        {!hasValues && <text x={(left + right) / 2} y="126" textAnchor="middle" className="fill-muted-foreground text-xs">Waiting for the first measurements</text>}
      </svg>
    </div>
    <ChartLegend first="CPU" second="Memory" />
    <div className="px-3 pt-2 pb-3 text-center text-xs text-muted-foreground">{history.length} actual {history.length === 1 ? "sample" : "samples"} · collected during this server session · no estimated history</div>
  </section>;
}

// Label and value in a details list: the label starts the row, the value ends it.
export function DetailRow({ label, icon, children }: { label: string; icon?: ReactNode; children: ReactNode }) {
  return <div className="flex items-start justify-between gap-3 border-t border-border py-2.5 text-sm">
    <dt className="flex items-center gap-2.5 text-muted-foreground [&_svg]:size-4 [&_svg]:text-foreground">{icon}{label}</dt>
    <dd className="max-w-[55%] text-end wrap-anywhere text-foreground">{children}</dd>
  </div>;
}

export function Overview({ report, platform, range, setRange }: { report: ServerReport; platform?: PlatformReport; range: string; setRange: (v: string) => void }) {
  const cpu = report.cpu.available ? report.cpu.usage_percent : null;
  const memory = report.memory.available ? report.memory.used_percent : null;
  const storage = report.storage.available ? report.storage.used_percent : null;
  const seconds = report.uptime.available ? report.uptime.seconds : null;
  const capacity = (used: number | null, total: number | null) => <>{bytes(used)} <small className="text-xs font-medium tracking-normal text-muted-foreground @max-sm:block">/ {bytes(total)}</small></>;
  return <div data-testid="server-overview" data-sampled-at={report.sampled_at} className="@container flex min-w-0 flex-col gap-3.5">
    <div className={metricRow}>
      <MetricTile label="CPU" icon={<Cpu aria-hidden="true" />}>
        <strong className={metricValue} data-testid="cpu-usage" data-metric-value={cpu ?? "null"}>{percent(cpu)}</strong>
        {cpu === null ? <div className={metricNote}>{report.cpu.reason || "First reading is collecting"}</div> : <Sparkline history={report.history} />}
      </MetricTile>
      <MetricTile label="Memory" icon={<MemoryStick aria-hidden="true" />}>
        <strong className={metricValue} data-testid="memory-usage" data-metric-value={memory ?? "null"}>{memory === null ? "Unavailable" : capacity(report.memory.used_bytes, report.memory.total_bytes)}</strong>
        {memory === null ? <div className={metricNote}>{report.memory.reason}</div> : <div className="mt-auto flex flex-col gap-1.5"><Progress value={memory} aria-label="Memory used" /><div className={metricNote}>{percent(memory)} used</div></div>}
      </MetricTile>
      <MetricTile label="Storage" icon={<Database aria-hidden="true" />}>
        <strong className={metricValue} data-testid="storage-usage" data-metric-value={storage ?? "null"}>{storage === null ? "Unavailable" : capacity(report.storage.used_bytes, report.storage.total_bytes)}</strong>
        {storage === null ? <div className={metricNote}>{report.storage.reason}</div> : <div className="mt-auto flex flex-col gap-1.5"><Progress value={storage} aria-label="Storage used" /><div className={metricNote}>{percent(storage)} used · {report.storage.disks.length} {report.storage.disks.length === 1 ? "volume" : "volumes"}</div></div>}
      </MetricTile>
      <MetricTile label="Uptime" icon={<Clock3 aria-hidden="true" />}>
        <strong className={metricValue} data-testid="server-uptime" data-metric-value={seconds ?? "null"}>{uptime(seconds)}</strong>
        <div className={`${metricNote} mt-auto`}>{seconds === null ? report.uptime.reason : <>Last sampled <time className="block" dateTime={report.sampled_at}>{dateLabel(report.sampled_at)}</time></>}</div>
      </MetricTile>
    </div>
    {report.collector.status !== "available" && <CollectorNotice>{report.collector.status === "partial" ? "Some measurements are unavailable." : "Server measurements are unavailable."} {report.collector.reasons.join(" ")}</CollectorNotice>}
    <div className="grid gap-3.5 @4xl:grid-cols-[minmax(0,1.8fr)_minmax(17.5rem,1fr)]">
      <ResourceChart report={report} range={range} setRange={setRange} />
      <section className={`${panel} min-w-0 px-4 pb-1`} aria-labelledby="server-details-heading">
        <h2 id="server-details-heading" className="py-4">Server details</h2>
        <dl className="grid @2xl:@max-4xl:grid-cols-2 @2xl:@max-4xl:gap-x-6">
          <DetailRow label="Operating system" icon={<Monitor aria-hidden="true" />}>{platform?.os_name || report.os}</DetailRow>
          <DetailRow label="Architecture" icon={<Cpu aria-hidden="true" />}>{report.arch}</DetailRow>
          <DetailRow label="Logical cores" icon={<Server aria-hidden="true" />}>{report.cpu.logical_cores ?? "Unavailable"}</DetailRow>
          <DetailRow label="Sampling interval" icon={<Clock3 aria-hidden="true" />}>{report.collector.interval_seconds}s</DetailRow>
        </dl>
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-t border-border py-3 text-xs text-muted-foreground [&_svg]:size-3.5">
          <span className="flex items-center gap-1.5"><Network aria-hidden="true" />Network</span>
          <span className="flex items-center gap-1"><ArrowDown aria-hidden="true" /><span className="sr-only">Receiving </span>{report.network.available && report.network.rx_bytes_per_second !== null ? `${bytes(report.network.rx_bytes_per_second)}/s` : "Unavailable"}</span>
          <span className="flex items-center gap-1"><ArrowUp aria-hidden="true" /><span className="sr-only">Sending </span>{report.network.available && report.network.tx_bytes_per_second !== null ? `${bytes(report.network.tx_bytes_per_second)}/s` : "Unavailable"}</span>
        </div>
      </section>
    </div>
  </div>;
}

const stateDot: Record<ServiceItem["status"], string> = { running: "bg-primary", stopped: "bg-destructive", paused: "bg-[#a97a28]", pending: "bg-[#a97a28]", unknown: "bg-muted-foreground" };
function State({ state }: { state: ServiceItem["status"] }) {
  return <span className="inline-flex items-center gap-2 whitespace-nowrap" data-state={state}><i className={`inline-block size-2 shrink-0 rounded-full ${stateDot[state]}`} aria-hidden="true" />{state[0].toUpperCase() + state.slice(1)}</span>;
}

const managerName = (manager: ServicesReport["manager"]) => manager === "windows-scm" ? "Windows service manager" : manager === "systemd" ? "systemd" : "service manager";

export function ServiceInventory({ report, compact = false, query, setQuery, viewAll }: { report: ServicesReport; compact?: boolean; query: string; setQuery: (q: string) => void; viewAll?: () => void }) {
  const [filter, setFilter] = useState("all");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string>();
  const filtered = report.items.filter((s) => (filter === "all" || s.status === filter) && `${s.name} ${s.display_name}`.toLowerCase().includes(query.toLowerCase().trim()));
  const pageSize = compact ? 5 : 25;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const visible = filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const heading = compact ? "Services" : "Service inventory";
  return <section className={`${panel} @container min-w-0`} aria-labelledby="services-heading" data-testid="service-inventory" data-sampled-at={report.sampled_at}>
    <div className="flex flex-wrap items-center justify-between gap-3 p-4">
      <div className="min-w-0">
        <h2 id="services-heading">{heading}</h2>
        {!compact && <div className="mt-1 text-sm text-muted-foreground">Native {managerName(report.manager)} · read-only inventory</div>}
      </div>
      <div className="flex w-full flex-wrap items-center gap-3 @2xl:w-auto">
        <div className="relative min-w-0 flex-1 basis-full @md:basis-auto @2xl:w-52 @2xl:flex-none">
          <Search className="pointer-events-none absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input type="search" name="service-search" autoComplete="off" spellCheck={false} aria-label="Search services" placeholder="Search services…" className="ps-8 pointer-coarse:h-11!" value={query} onChange={(e) => { setQuery(e.target.value); setPage(0); }} />
        </div>
        <Segments label="Service state" value={filter} onChange={(v) => { setFilter(v); setPage(0); }} options={[{ value: "all", label: "All" }, { value: "running", label: "Running" }, { value: "stopped", label: "Stopped" }]} />
      </div>
    </div>
    {!report.available ? <div className="px-4 pb-4"><Alert role="status" className="text-start">
      <Server aria-hidden="true" />
      <AlertTitle>The service list is not available</AlertTitle>
      <AlertDescription className="flex flex-col gap-2 text-start">
        <div className="text-foreground">The panel could not read the services from this server's {managerName(report.manager)}.</div>
        <div><span className="font-medium text-foreground">Next step:</span> Wait a moment. The panel asks again every 30 seconds, or use the refresh button at the top of the page.</div>
        {report.reason && <TechnicalDetails>{report.reason}</TechnicalDetails>}
      </AlertDescription>
    </Alert></div> : <>
      {report.truncated && <div className="px-4 pb-3 text-sm text-muted-foreground">The service manager returned a limited inventory of {report.items.length} entries.</div>}
      {!!visible.length && <div className="overflow-x-auto px-4" role="region" aria-labelledby="services-heading" tabIndex={0}>
        <table className="w-full text-sm">
          <TableHeader className="bg-muted">
            <TableRow className="border-border hover:bg-transparent">
              <TableHead scope="col" className="text-start font-normal text-muted-foreground">Service</TableHead>
              <TableHead scope="col" className="text-start font-normal text-muted-foreground">State</TableHead>
              <TableHead scope="col" className="text-start font-normal text-muted-foreground @max-xl:hidden">Start mode</TableHead>
              <TableHead scope="col" className="text-end"><span className="sr-only">Details</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>{visible.map((service) => {
            const name = service.display_name || service.name;
            const open = selected === service.id;
            return <Fragment key={service.id}>
              <TableRow className={`border-border ${open ? "border-b-0" : ""}`}>
                <th scope="row" className="p-2 text-start align-middle font-normal text-foreground">
                  <span className="flex items-center gap-3"><Server className="size-4 shrink-0 text-muted-foreground @max-xl:hidden" aria-hidden="true" /><span className="wrap-anywhere">{name}</span></span>
                </th>
                <TableCell><State state={service.status} /></TableCell>
                <TableCell className="@max-xl:hidden">{service.start_type[0].toUpperCase() + service.start_type.slice(1)}</TableCell>
                <TableCell className="text-end">
                  <Button size="sm" variant="outline" className="pointer-coarse:h-11" onClick={() => setSelected(open ? undefined : service.id)} aria-expanded={open} aria-controls={open ? "service-detail" : undefined}>Details<span className="sr-only"> for {name}</span></Button>
                </TableCell>
              </TableRow>
              {open && <TableRow className="border-border hover:bg-transparent"><td colSpan={4} className="p-2 pt-0">
                <div id="service-detail" className="flex flex-col gap-3.5 rounded-md bg-muted p-3.5 text-start" role="group" aria-label={`Service facts for ${name}`}>
                  <div className="flex items-center justify-between gap-4"><h3 className="wrap-anywhere">{name}</h3><Button size="sm" variant="ghost" className="pointer-coarse:h-11" onClick={() => setSelected(undefined)}>Close<span className="sr-only"> service details</span></Button></div>
                  <dl className="grid grid-cols-1 gap-3 @sm:grid-cols-2 @2xl:grid-cols-3">
                    {([["Service name", service.name], ["State", service.status], ["Start mode", service.start_type], ["Source", report.manager], ["Last collected", dateLabel(report.sampled_at)]] as const).map(([label, value]) => <div key={label} className="flex min-w-0 flex-col gap-0.5">
                      <dt className="text-xs text-muted-foreground">{label}</dt><dd className="text-sm wrap-anywhere text-foreground">{value}</dd>
                    </div>)}
                  </dl>
                  <div className="text-xs text-muted-foreground">This view reads the native service manager. Service changes are not available yet.</div>
                </div>
              </td></TableRow>}
            </Fragment>;
          })}</TableBody>
        </table>
      </div>}
      {!filtered.length && <Empty className="py-8">
        <EmptyHeader>
          <EmptyMedia variant="icon"><Search aria-hidden="true" /></EmptyMedia>
          <EmptyTitle><h3>{report.items.length ? "No matching services" : "No services returned"}</h3></EmptyTitle>
          <EmptyDescription>{report.items.length ? "Try another name or choose All states." : "The native service manager returned an empty inventory."}</EmptyDescription>
        </EmptyHeader>
        {report.items.length > 0 && <EmptyContent><Button variant="outline" className="h-9 pointer-coarse:h-11" onClick={() => { setQuery(""); setFilter("all"); setPage(0); }}>Clear service filters</Button></EmptyContent>}
      </Empty>}
      <div className="mt-2 flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-2.5 text-xs text-muted-foreground">
        <span>{filtered.length ? `${currentPage * pageSize + 1}–${Math.min((currentPage + 1) * pageSize, filtered.length)} of ${filtered.length}` : "0"} services · collected {time(report.sampled_at)}</span>
        {compact && viewAll ? <Button size="sm" variant="ghost" className="pointer-coarse:h-11" onClick={viewAll}>View all services</Button> : pageCount > 1 && <nav className="flex items-center gap-2" aria-label="Service pages">
          <Button size="sm" variant="ghost" className="pointer-coarse:h-11" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous<span className="sr-only"> services</span></Button>
          <span>{currentPage + 1} / {pageCount}</span>
          <Button size="sm" variant="ghost" className="pointer-coarse:h-11" disabled={currentPage + 1 === pageCount} onClick={() => setPage(currentPage + 1)}>Next<span className="sr-only"> services</span></Button>
        </nav>}
      </div>
    </>}
  </section>;
}
