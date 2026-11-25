import { Fragment, useState } from "react";
import { ArrowDown, ArrowUp, Database, HardDrive, Network, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Progress } from "@/components/ui/progress";
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { bytes, chartGrid, ChartLegend, chartText, CollectorNotice, DetailRow, metricNote, metricRow, MetricTile, metricValue, panel, percent, rangeSegments, Segments } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { ServerReport, ServerSample } from "@/lib/api";

// Server › Storage and Server › Network: read-only readings from the host's
// collector, in the same pieces as Home's monitoring.

type Disk = ServerReport["storage"]["disks"][number];
const reading = (available: boolean, value: number | null) => available ? value : null;
const rate = (value: number | null) => value === null ? "Unavailable" : value > 0 && value < 1 ? `${value.toLocaleString(undefined, { maximumSignificantDigits: 3 })} B/s` : `${bytes(value)}/s`;

function SampleStamp({ report }: { report: ServerReport }) {
  return <div className="flex flex-wrap justify-between gap-x-4 gap-y-2 text-xs text-muted-foreground"><span className="text-primary">Read-only monitoring</span><span>Sampled <time dateTime={report.sampled_at} data-testid="host-sampled-at">{dateLabel(report.sampled_at)}</time></span></div>;
}

function Metric({ label, value, note, icon, testId, raw }: { label: string; value: string; note: string; icon: React.ReactNode; testId: string; raw: number | null }) {
  return <MetricTile label={label} icon={icon}><strong className={metricValue} data-testid={testId} data-metric-value={raw ?? "null"}>{value}</strong><div className={`${metricNote} mt-auto`}>{note}</div></MetricTile>;
}

function DiskDetails({ disk, sampledAt }: { disk: Disk; sampledAt: string }) {
  const facts: [string, React.ReactNode][] = [
    ["Volume ID", disk.id], ["Collector label", disk.label || "Not reported"],
    ["Total capacity", bytes(reading(disk.available, disk.total_bytes))], ["Used space", bytes(reading(disk.available, disk.used_bytes))],
    ["Free space", bytes(reading(disk.available, disk.free_bytes))], ["Utilization", percent(reading(disk.available, disk.used_percent))],
    ["Mount path", "Not reported by collector"], ["Filesystem", "Not reported by collector"],
    ["Last sampled", <time dateTime={sampledAt}>{dateLabel(sampledAt)}</time>],
  ];
  return <div className="flex flex-col gap-4 rounded-md bg-muted p-4 text-start" data-testid="volume-details" role="group" aria-label={`Volume details for ${disk.label || disk.id}`}>
    <h3 className="wrap-anywhere">{disk.label || disk.id}</h3>
    <dl className="grid grid-cols-1 gap-4 @sm:grid-cols-2 @2xl:grid-cols-3">
      {facts.map(([label, value]) => <div key={label} className="flex min-w-0 flex-col gap-1"><dt className="text-xs text-muted-foreground">{label}</dt><dd className="text-sm wrap-anywhere text-foreground">{value}</dd></div>)}
    </dl>
    {disk.reason && <div className="text-sm text-muted-foreground">{disk.reason}</div>}
  </div>;
}

export function Storage({ report }: { report: ServerReport }) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState("label");
  const [selected, setSelected] = useState<string>();
  const storage = report.storage;
  const disks = storage.disks.filter((d) => `${d.label} ${d.id}`.toLowerCase().includes(query.trim().toLowerCase())).sort((a, b) => {
    if (sort === "label") return (a.label || a.id).localeCompare(b.label || b.id);
    const key = sort === "free" ? "free_bytes" : "used_percent";
    const av = reading(a.available, a[key]), bv = reading(b.available, b[key]);
    if (av === null) return bv === null ? a.id.localeCompare(b.id) : 1;
    if (bv === null) return -1;
    return (sort === "free" ? av - bv : bv - av) || a.id.localeCompare(b.id);
  });
  const total = reading(storage.available, storage.total_bytes), used = reading(storage.available, storage.used_bytes), free = reading(storage.available, storage.free_bytes), utilization = reading(storage.available, storage.used_percent);
  return <div className="@container flex min-w-0 flex-col gap-4" data-testid="storage-page" data-sampled-at={report.sampled_at}>
    <SampleStamp report={report} />
    <div className={metricRow}>
      <Metric label="Total capacity" value={bytes(total)} raw={total} note="Combined capacity reported by the host" icon={<HardDrive aria-hidden="true" />} testId="storage-total" />
      <Metric label="Used space" value={bytes(used)} raw={used} note={utilization === null ? "Utilization unavailable" : `${percent(utilization)} of reported capacity`} icon={<Database aria-hidden="true" />} testId="storage-used" />
      <Metric label="Free space" value={bytes(free)} raw={free} note="Available space reported by the host" icon={<HardDrive aria-hidden="true" />} testId="storage-free" />
      <Metric label="Volumes" value={String(storage.disks.length)} raw={storage.disks.length} note={`${storage.disks.filter((d) => d.available).length} with available measurements`} icon={<Database aria-hidden="true" />} testId="storage-volumes" />
    </div>
    {(!storage.available || storage.reason) && <CollectorNotice>{storage.reason || "Storage measurements are unavailable from this collector."}</CollectorNotice>}
    <section className={`${panel} min-w-0`} aria-labelledby="volumes-heading">
      <div className="flex flex-wrap items-center justify-between gap-3 p-4">
        <div className="min-w-0"><h2 id="volumes-heading">Volume inventory</h2><div className="mt-1 text-sm text-muted-foreground">Inspect capacity and usage for each reported volume.</div></div>
        <div className="flex w-full flex-wrap items-center gap-3 @2xl:w-auto">
          <div className="relative min-w-0 flex-1 basis-full @md:basis-auto @2xl:w-52 @2xl:flex-none">
            <Search className="pointer-events-none absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input type="search" name="volume-search" autoComplete="off" spellCheck={false} aria-label="Search volumes" placeholder="Search volumes…" data-testid="volume-search" className="ps-8 pointer-coarse:h-11!" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <NativeSelect aria-label="Sort volumes" data-testid="volume-sort" className="min-w-40 flex-1 @md:flex-none [&>select]:text-foreground pointer-coarse:[&>select]:h-11!" value={sort} onChange={(e) => setSort(e.target.value)}>
            <NativeSelectOption value="label">Volume name</NativeSelectOption><NativeSelectOption value="used">Most used first</NativeSelectOption><NativeSelectOption value="free">Least free first</NativeSelectOption>
          </NativeSelect>
        </div>
      </div>
      {!!disks.length && <div className="overflow-x-auto px-4" role="region" aria-labelledby="volumes-heading" tabIndex={0}>
        <table className="w-full text-sm">
          <TableHeader className="bg-muted">
            <TableRow className="border-border hover:bg-transparent">
              <TableHead scope="col" className="text-start font-normal text-muted-foreground">Volume</TableHead>
              <TableHead scope="col" className="text-start font-normal text-muted-foreground @max-xl:hidden">Capacity</TableHead>
              <TableHead scope="col" className="text-start font-normal text-muted-foreground @max-4xl:hidden">Used</TableHead>
              <TableHead scope="col" className="text-start font-normal text-muted-foreground">Free</TableHead>
              <TableHead scope="col" className="text-start font-normal text-muted-foreground @max-xl:hidden">Utilization</TableHead>
              <TableHead scope="col" className="text-end"><span className="sr-only">Details</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>{disks.map((disk, index) => {
            const name = disk.label || disk.id;
            const open = selected === disk.id;
            return <Fragment key={disk.id}>
              <TableRow className={`border-border ${open ? "border-b-0" : ""}`} data-testid="volume-row" data-volume-id={disk.id}>
                <th scope="row" className="p-2 text-start align-middle font-medium text-foreground">
                  <span className="flex items-start gap-2.5 wrap-anywhere"><HardDrive className="mt-0.5 size-4 shrink-0 text-muted-foreground @max-xl:hidden" aria-hidden="true" /><span>{name}
                    <small className="mt-1 block text-xs font-normal text-muted-foreground">{disk.id}</small>
                    {!disk.available && <small className="mt-1 block text-xs font-normal text-muted-foreground">Unavailable{disk.reason ? ` · ${disk.reason}` : ""}</small>}
                  </span></span>
                </th>
                <TableCell className="tabular-nums @max-xl:hidden">{bytes(reading(disk.available, disk.total_bytes))}</TableCell>
                <TableCell className="tabular-nums @max-4xl:hidden">{bytes(reading(disk.available, disk.used_bytes))}</TableCell>
                <TableCell className="tabular-nums">{bytes(reading(disk.available, disk.free_bytes))}</TableCell>
                <TableCell className="min-w-28 tabular-nums @max-xl:hidden">
                  <span>{percent(reading(disk.available, disk.used_percent))}</span>
                  {disk.available && disk.used_percent !== null && <Progress className="mt-1.5" value={disk.used_percent} aria-label={`${name} used`} />}
                </TableCell>
                <TableCell className="text-end">
                  <Button size="sm" variant="outline" className="pointer-coarse:h-11" aria-expanded={open} aria-controls={open ? `volume-detail-${index}` : undefined} onClick={() => setSelected(open ? undefined : disk.id)}>{open ? "Close" : "Details"}<span className="sr-only"> for {name}</span></Button>
                </TableCell>
              </TableRow>
              {open && <TableRow className="border-border hover:bg-transparent"><td colSpan={6} className="p-2 pt-0"><div id={`volume-detail-${index}`}><DiskDetails disk={disk} sampledAt={report.sampled_at} /></div></td></TableRow>}
            </Fragment>;
          })}</TableBody>
        </table>
      </div>}
      {!disks.length && <Empty className="py-8" role="status">
        <EmptyHeader>
          <EmptyMedia variant="icon">{query ? <Search aria-hidden="true" /> : <HardDrive aria-hidden="true" />}</EmptyMedia>
          <EmptyTitle><h3>{query ? "No matching volumes" : "No volumes reported"}</h3></EmptyTitle>
          <EmptyDescription>{query ? "Try a different volume name or ID." : storage.reason || "The collector returned an empty volume inventory."}</EmptyDescription>
        </EmptyHeader>
        {query && <EmptyContent><Button variant="outline" className="h-9 pointer-coarse:h-11" onClick={() => setQuery("")}>Clear volume search</Button></EmptyContent>}
      </Empty>}
      <div className="mt-2 flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-2.5 text-xs text-muted-foreground"><span>{disks.length} of {storage.disks.length} volumes</span><span>Reported measurements · no disk changes</span></div>
    </section>
  </div>;
}

type RateKey = "network_rx_bytes_per_second" | "network_tx_bytes_per_second";
function NetworkChart({ report, range, setRange }: { report: ServerReport; range: string; setRange: (v: string) => void }) {
  const samples = report.history;
  const start = samples.length ? Date.parse(samples[0].sampled_at) : Date.parse(report.sampled_at), end = samples.length ? Date.parse(samples.at(-1)!.sampled_at) : start;
  const values = samples.flatMap((s) => [s.network_rx_bytes_per_second, s.network_tx_bytes_per_second]).filter((v): v is number => v !== null);
  const maximum = Math.max(1, ...values);
  const x = (s: ServerSample) => 92 + (end === start ? 0.5 : (Date.parse(s.sampled_at) - start) / (end - start)) * 526;
  const y = (v: number) => 192 - v / maximum * 156;
  const path = (key: RateKey) => {
    let open = false;
    return samples.map((s) => { const value = s[key]; if (value === null) { open = false; return ""; } const command = open ? "L" : "M"; open = true; return `${command}${x(s).toFixed(2)},${y(value).toFixed(2)}`; }).join(" ");
  };
  const time = (v: number) => new Date(v).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  return <section className={`${panel} min-w-0`} aria-labelledby="network-activity-heading">
    <div className="flex flex-wrap items-center justify-between gap-3 p-4"><h2 id="network-activity-heading">Network activity</h2><Segments label="Network chart time range" testId="network-range" value={range} onChange={setRange} options={rangeSegments} /></div>
    <div className="px-3 max-[480px]:px-2">
      {/* The chart's own coordinates are left-to-right; the page around it follows the reading direction. */}
      <svg className="block h-47 w-full [direction:ltr] max-[480px]:h-43.5" viewBox="0 0 660 238" role="img" aria-labelledby="network-chart-title network-chart-description"><title id="network-chart-title">Received and sent network rates</title><desc id="network-chart-description">{samples.length} recorded samples. Gaps indicate unavailable rates. The vertical scale adapts to the observed rates.</desc>
        {[0, 0.5, 1].map((fraction) => <g key={fraction}><line className={chartGrid} x1="92" x2="618" y1={y(maximum * fraction)} y2={y(maximum * fraction)} /><text className={chartText} x="80" y={y(maximum * fraction) + 4} textAnchor="end">{rate(maximum * fraction)}</text></g>)}
        {samples.length > 1 && [0, 0.5, 1].map((fraction) => <text className={chartText} key={fraction} x={92 + fraction * 526} y="220" textAnchor={fraction === 0 ? "start" : fraction === 1 ? "end" : "middle"}>{time(start + (end - start) * fraction)}</text>)}
        {(["network_rx_bytes_per_second", "network_tx_bytes_per_second"] as const).map((key, index) => <g key={key} className={index ? "text-(--chart-memory)" : "text-primary"} data-testid={index ? "network-tx-chart" : "network-rx-chart"}><path d={path(key)} fill="none" stroke="currentColor" strokeWidth="2" vectorEffect="non-scaling-stroke" />{samples.map((s) => s[key] === null ? null : <circle key={s.sampled_at} cx={x(s)} cy={y(s[key])} r={samples.length === 1 ? 3 : 2} fill="currentColor"><title>{time(Date.parse(s.sampled_at))} · {index ? "Sent" : "Received"} {rate(s[key])}</title></circle>)}</g>)}
        {!values.length && <text className="fill-muted-foreground text-xs" x="355" y="120" textAnchor="middle">Waiting for measured rates</text>}
      </svg>
    </div>
    <ChartLegend first="Received" second="Sent" />
    <div className="px-3 pt-2 pb-3 text-center text-xs text-muted-foreground">{samples.length} actual samples · {values.length ? "null readings appear as gaps" : "no rate readings available yet"}</div>
  </section>;
}

export function NetworkResources({ report, range, setRange }: { report: ServerReport; range: string; setRange: (v: string) => void }) {
  const network = report.network;
  const rx = reading(network.available, network.rx_bytes_per_second), tx = reading(network.available, network.tx_bytes_per_second), received = reading(network.available, network.bytes_received), sent = reading(network.available, network.bytes_sent);
  return <div className="@container flex min-w-0 flex-col gap-4" data-testid="network-page" data-sampled-at={report.sampled_at}>
    <SampleStamp report={report} />
    <div className={metricRow}>
      <Metric label="Receiving" value={rate(rx)} raw={rx} note={rx === null ? "Waiting for a measured receive rate" : "Measured incoming traffic rate"} icon={<ArrowDown aria-hidden="true" />} testId="network-rx-rate" />
      <Metric label="Sending" value={rate(tx)} raw={tx} note={tx === null ? "Waiting for a measured send rate" : "Measured outgoing traffic rate"} icon={<ArrowUp aria-hidden="true" />} testId="network-tx-rate" />
      <Metric label="Total received" value={bytes(received)} raw={received} note="Cumulative counter reported by the host" icon={<ArrowDown aria-hidden="true" />} testId="network-received" />
      <Metric label="Total sent" value={bytes(sent)} raw={sent} note="Cumulative counter reported by the host" icon={<ArrowUp aria-hidden="true" />} testId="network-sent" />
    </div>
    {(!network.available || network.reason || rx === null || tx === null) && <CollectorNotice>{network.reason || (!network.available ? "Network measurements are unavailable from this collector." : "Rate measurements need consecutive host samples. Totals may be available while rates are collecting.")}</CollectorNotice>}
    <div className="grid gap-4 @4xl:grid-cols-[minmax(0,1.8fr)_minmax(16.25rem,1fr)]">
      <NetworkChart report={report} range={range} setRange={setRange} />
      <section className={`${panel} min-w-0 px-4`} aria-labelledby="measurement-heading">
        <h2 id="measurement-heading" className="py-4">Measurement details</h2>
        <dl>
          <DetailRow label="Scope" icon={<Network aria-hidden="true" />}>Host aggregate</DetailRow>
          <DetailRow label="Sampling interval">{report.collector.interval_seconds}s</DetailRow>
          <DetailRow label="Recorded samples">{report.history.length}</DetailRow>
          <DetailRow label="Collector">{report.collector.name} {report.collector.version}</DetailRow>
        </dl>
        <div className="border-t border-border py-4 text-sm text-muted-foreground">Traffic counters come from the host. They are not a billing-period transfer total. Per-interface addresses and configuration are not included in this report.</div>
      </section>
    </div>
  </div>;
}
