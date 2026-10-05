import { Fragment, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { ProgressBar } from "@astryxdesign/core/ProgressBar";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { ArrowDown, ArrowUp, Database, HardDrive, Info, Network, Search } from "lucide-react";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { bytes, percent } from "@/Dashboard";
import { dateLabel } from "@/lib/api";
import type { ServerReport, ServerSample } from "@/lib/api";
import "./host-resources.css";

type Disk = ServerReport["storage"]["disks"][number];
const reading = (available: boolean, value: number | null) => available ? value : null;
const rate = (value: number | null) => value === null ? "Unavailable" : value > 0 && value < 1 ? `${value.toLocaleString(undefined, { maximumSignificantDigits: 3 })} B/s` : `${bytes(value)}/s`;

function SampleStamp({ report }: { report: ServerReport }) {
  return <div className="host-sample"><span className="host-read-only">Read-only monitoring</span><span>Sampled <time dateTime={report.sampled_at} data-testid="host-sampled-at">{dateLabel(report.sampled_at)}</time></span></div>;
}

function Metric({ label, value, note, icon, testId, raw }: { label: string; value: string; note: string; icon: React.ReactNode; testId: string; raw: number | null }) {
  return <Card className="dashboard-card metric-card host-metric" padding={0}><div className="metric-label"><span className="metric-icon">{icon}</span><span>{label}</span></div><strong data-testid={testId} data-metric-value={raw ?? "null"}>{value}</strong><p className="metric-note">{note}</p></Card>;
}

function DiskDetails({ disk, sampledAt }: { disk: Disk; sampledAt: string }) {
  return <div className="host-volume-details" data-testid="volume-details" aria-label={`Volume details for ${disk.label || disk.id}`}>
    <h3>{disk.label || disk.id}</h3>
    <dl>
      <div><dt>Volume ID</dt><dd>{disk.id}</dd></div><div><dt>Collector label</dt><dd>{disk.label || "Not reported"}</dd></div>
      <div><dt>Total capacity</dt><dd>{bytes(reading(disk.available, disk.total_bytes))}</dd></div><div><dt>Used space</dt><dd>{bytes(reading(disk.available, disk.used_bytes))}</dd></div>
      <div><dt>Free space</dt><dd>{bytes(reading(disk.available, disk.free_bytes))}</dd></div><div><dt>Utilization</dt><dd>{percent(reading(disk.available, disk.used_percent))}</dd></div>
      <div><dt>Mount path</dt><dd>Not reported by collector</dd></div><div><dt>Filesystem</dt><dd>Not reported by collector</dd></div>
      <div><dt>Last sampled</dt><dd><time dateTime={sampledAt}>{dateLabel(sampledAt)}</time></dd></div>
    </dl>
    {disk.reason && <p>{disk.reason}</p>}
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
  return <div className="host-resources" data-testid="storage-page" data-sampled-at={report.sampled_at}>
    <SampleStamp report={report} />
    <div className="metric-grid">
      <Metric label="Total capacity" value={bytes(total)} raw={total} note="Combined capacity reported by the host" icon={<HardDrive />} testId="storage-total" />
      <Metric label="Used space" value={bytes(used)} raw={used} note={utilization === null ? "Utilization unavailable" : `${percent(utilization)} of reported capacity`} icon={<Database />} testId="storage-used" />
      <Metric label="Free space" value={bytes(free)} raw={free} note="Available space reported by the host" icon={<HardDrive />} testId="storage-free" />
      <Metric label="Volumes" value={String(storage.disks.length)} raw={storage.disks.length} note={`${storage.disks.filter((d) => d.available).length} with available measurements`} icon={<Database />} testId="storage-volumes" />
    </div>
    {(!storage.available || storage.reason) && <p className="collector-notice" role="status"><Info aria-hidden="true" />{storage.reason || "Storage measurements are unavailable from this collector."}</p>}
    <Card className="dashboard-card" padding={0}>
      <div className="card-heading host-inventory-heading"><div><h2>Volume inventory</h2><p>Inspect capacity and usage for each reported volume.</p></div><div className="host-inventory-controls">
        <label className="compact-search"><Search aria-hidden="true" /><input type="search" aria-label="Search volumes" placeholder="Search volumes…" data-testid="volume-search" value={query} onChange={(e) => setQuery(e.target.value)} /></label>
        <NativeSelect aria-label="Sort volumes" data-testid="volume-sort" value={sort} onChange={(e) => setSort(e.target.value)}><NativeSelectOption value="label">Volume name</NativeSelectOption><NativeSelectOption value="used">Most used first</NativeSelectOption><NativeSelectOption value="free">Least free first</NativeSelectOption></NativeSelect>
      </div></div>
      {!!disks.length && <div className="host-volume-table-wrap"><table className="host-volume-table"><thead><tr><th scope="col">Volume</th><th scope="col" className="volume-capacity">Capacity</th><th scope="col" className="volume-used">Used</th><th scope="col">Free</th><th scope="col" className="volume-utilization">Utilization</th><th scope="col"><span className="sr-only">Details</span></th></tr></thead><tbody>
        {disks.map((disk, index) => <Fragment key={disk.id}><tr data-testid="volume-row" data-volume-id={disk.id}>
          <th scope="row"><span className="volume-identity"><HardDrive aria-hidden="true" /><span>{disk.label || disk.id}<small>{disk.id}</small>{!disk.available && <small>Unavailable{disk.reason ? ` · ${disk.reason}` : ""}</small>}</span></span></th>
          <td className="volume-capacity">{bytes(reading(disk.available, disk.total_bytes))}</td><td className="volume-used">{bytes(reading(disk.available, disk.used_bytes))}</td><td>{bytes(reading(disk.available, disk.free_bytes))}</td>
          <td className="volume-utilization"><span>{percent(reading(disk.available, disk.used_percent))}</span>{disk.available && disk.used_percent !== null && <ProgressBar className="resource-meter" label={`${disk.label || disk.id} used`} isLabelHidden value={disk.used_percent} />}</td>
          <td><Button label={`Details for ${disk.label || disk.id}`} size="sm" variant="secondary" className="detail-button" aria-expanded={selected === disk.id} aria-controls={selected === disk.id ? `volume-detail-${index}` : undefined} onClick={() => setSelected(selected === disk.id ? undefined : disk.id)}>{selected === disk.id ? "Close" : "Details"}</Button></td>
        </tr>{selected === disk.id && <tr><td colSpan={6}><div id={`volume-detail-${index}`}><DiskDetails disk={disk} sampledAt={report.sampled_at} /></div></td></tr>}</Fragment>)}
      </tbody></table></div>}
      {!disks.length && <div className="inventory-empty" role="status">{query ? <Search /> : <HardDrive />}<h3>{query ? "No matching volumes" : "No volumes reported"}</h3><p>{query ? "Try a different volume name or ID." : storage.reason || "The collector returned an empty volume inventory."}</p>{query && <Button label="Clear volume search" variant="secondary" onClick={() => setQuery("")} />}</div>}
      <div className="table-footer"><span>{disks.length} of {storage.disks.length} volumes</span><span>Reported measurements · no disk changes</span></div>
    </Card>
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
  return <Card className="dashboard-card host-network-chart" padding={0}>
    <div className="card-heading"><h2>Network activity</h2><SegmentedControl label="Network chart time range" data-testid="network-range" value={range} onChange={setRange} size="sm" className="range-control"><SegmentedControlItem value="60" label="1 minute" isLabelHidden icon={<span>1m</span>} /><SegmentedControlItem value="300" label="5 minutes" isLabelHidden icon={<span>5m</span>} /><SegmentedControlItem value="600" label="10 minutes" isLabelHidden icon={<span>10m</span>} /></SegmentedControl></div>
    <div className="chart-wrap"><svg className="activity-chart" viewBox="0 0 660 238" role="img" aria-labelledby="network-chart-title network-chart-description"><title id="network-chart-title">Received and sent network rates</title><desc id="network-chart-description">{samples.length} recorded samples. Gaps indicate unavailable rates. The vertical scale adapts to the observed rates.</desc>
      {[0, 0.5, 1].map((fraction) => <g className="chart-grid" key={fraction}><line x1="92" x2="618" y1={y(maximum * fraction)} y2={y(maximum * fraction)} /><text x="80" y={y(maximum * fraction) + 4} textAnchor="end">{rate(maximum * fraction)}</text></g>)}
      {samples.length > 1 && [0, 0.5, 1].map((fraction) => <text className="host-chart-time" key={fraction} x={92 + fraction * 526} y="220" textAnchor={fraction === 0 ? "start" : fraction === 1 ? "end" : "middle"}>{time(start + (end - start) * fraction)}</text>)}
      {(["network_rx_bytes_per_second", "network_tx_bytes_per_second"] as const).map((key, index) => <g key={key} className={index ? "memory-series" : "cpu-series"} data-testid={index ? "network-tx-chart" : "network-rx-chart"}><path d={path(key)} fill="none" stroke="currentColor" strokeWidth="2" vectorEffect="non-scaling-stroke" />{samples.map((s) => s[key] === null ? null : <circle key={s.sampled_at} cx={x(s)} cy={y(s[key])} r={samples.length === 1 ? 3 : 2} fill="currentColor"><title>{time(Date.parse(s.sampled_at))} · {index ? "Sent" : "Received"} {rate(s[key])}</title></circle>)}</g>)}
      {!values.length && <text className="chart-placeholder" x="355" y="120" textAnchor="middle">Waiting for measured rates</text>}
    </svg></div>
    <div className="chart-legend"><span><i className="cpu-dot" />Received</span><span><i className="memory-dot" />Sent</span></div><p className="chart-caption">{samples.length} actual samples · {values.length ? "null readings appear as gaps" : "no rate readings available yet"}</p>
  </Card>;
}

export function NetworkResources({ report, range, setRange }: { report: ServerReport; range: string; setRange: (v: string) => void }) {
  const network = report.network;
  const rx = reading(network.available, network.rx_bytes_per_second), tx = reading(network.available, network.tx_bytes_per_second), received = reading(network.available, network.bytes_received), sent = reading(network.available, network.bytes_sent);
  return <div className="host-resources" data-testid="network-page" data-sampled-at={report.sampled_at}>
    <SampleStamp report={report} />
    <div className="metric-grid">
      <Metric label="Receiving" value={rate(rx)} raw={rx} note={rx === null ? "Waiting for a measured receive rate" : "Measured incoming traffic rate"} icon={<ArrowDown />} testId="network-rx-rate" />
      <Metric label="Sending" value={rate(tx)} raw={tx} note={tx === null ? "Waiting for a measured send rate" : "Measured outgoing traffic rate"} icon={<ArrowUp />} testId="network-tx-rate" />
      <Metric label="Total received" value={bytes(received)} raw={received} note="Cumulative counter reported by the host" icon={<ArrowDown />} testId="network-received" />
      <Metric label="Total sent" value={bytes(sent)} raw={sent} note="Cumulative counter reported by the host" icon={<ArrowUp />} testId="network-sent" />
    </div>
    {(!network.available || network.reason || rx === null || tx === null) && <p className="collector-notice" role="status"><Info aria-hidden="true" />{network.reason || (!network.available ? "Network measurements are unavailable from this collector." : "Rate measurements need consecutive host samples. Totals may be available while rates are collecting.")}</p>}
    <div className="host-network-layout"><NetworkChart report={report} range={range} setRange={setRange} /><Card className="dashboard-card server-details" padding={0}><div className="card-heading"><h2>Measurement details</h2></div><dl>
      <div><dt><Network />Scope</dt><dd>Host aggregate</dd></div><div><dt>Sampling interval</dt><dd>{report.collector.interval_seconds}s</dd></div><div><dt>Recorded samples</dt><dd>{report.history.length}</dd></div><div><dt>Collector</dt><dd>{report.collector.name} {report.collector.version}</dd></div>
    </dl><p className="host-network-note">Traffic counters come from the host. They are not a billing-period transfer total. Per-interface addresses and configuration are not included in this report.</p></Card></div>
  </div>;
}
