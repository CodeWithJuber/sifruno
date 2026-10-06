import { Fragment, useEffect, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { ProgressBar } from "@astryxdesign/core/ProgressBar";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Archive, ArrowDown, ArrowUp, ArrowUpRight, Clock3, Cpu, Database, Folder, Globe, Info, Layers, LockKeyhole, MemoryStick, Monitor, Network, Search, Server, Users } from "lucide-react";
import type { PlatformReport, ServerReport, ServerSample, ServiceItem, ServicesReport } from "@/lib/api";
import { dateLabel } from "@/lib/api";

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

type HostingTarget = "websites" | "accounts" | "backups" | "files" | "access";
const hostingModules = [
  { id: "websites", label: "Websites", description: "Manage local static sites and their files.", detail: "Static sites", icon: Globe },
  { id: "accounts", label: "Accounts", description: "Local Linux identities and home directories.", detail: "Linux broker required", icon: Users },
  { id: "backups", label: "Backups", description: "Create, export and restore website snapshots.", detail: "Native ZIP snapshots", icon: Archive },
  { id: "files", label: "File Manager", description: "Browse and edit saved website files.", detail: "Website files", icon: Folder },
  { id: "access", label: "Access", description: "Review operator sessions and server access.", detail: "Operator sessions", icon: LockKeyhole },
] as const;

export function HostingWorkspace({ publicPreview, platform, onNavigate, onPreview }: { publicPreview: boolean; platform?: PlatformReport; onNavigate: (target: HostingTarget) => void; onPreview: () => void }) {
  return <Card className="dashboard-card hosting-workspace" padding={0} data-testid="hosting-workspace">
    <div className="workspace-heading"><div><h2>{publicPreview ? "Public panel preview" : "Hosting"}</h2><p>{publicPreview ? "Host monitoring and a tour of the workspace." : "Open a module to work on this server."}</p></div><span className="workspace-scope">{publicPreview ? "Preview" : "Local panel"}</span></div>
    {publicPreview ? <div className="workspace-preview"><Layers aria-hidden="true" /><div><h3>Explore the panel</h3><p>The tour uses sample content. Private websites, accounts, backups, files and access controls stay in the local panel.</p></div><Button label="Explore panel" variant="secondary" size="sm" onClick={onPreview} data-testid="open-panel-preview" /></div> : <>
      <div className="workspace-modules">{hostingModules.map(({ id, label, description, detail, icon: Icon }) => <button key={id} type="button" className={`workspace-module module-${id}`} onClick={() => onNavigate(id)} aria-label={`Open ${label}`} data-testid={`workspace-${id}`}>
        <Icon className="workspace-module-icon" aria-hidden="true" /><span className="workspace-module-copy"><strong>{label}</strong><span>{description}</span></span><span className="workspace-module-kind">{detail}</span><ArrowUpRight className="workspace-module-arrow" aria-hidden="true" />
      </button>)}</div>
      <div className="workspace-context"><Info aria-hidden="true" /><p>{platform && platform.os !== "linux" ? "Native account actions require Linux. Static-site tools and monitoring remain separate modules." : "Account availability is checked after sign-in. A configured, admitted Linux broker is required for native account actions."}</p></div>
    </>}
  </Card>;
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
  if (!values.some((s) => s.cpu_usage_percent !== null)) return <p className="metric-note">Collecting first CPU reading</p>;
  const start = Date.parse(values[0].sampled_at), end = Date.parse(values.at(-1)!.sampled_at);
  const x = (sample: ServerSample) => 8 + (end === start ? 0.5 : (Date.parse(sample.sampled_at) - start) / (end - start)) * 644;
  return <svg className="sparkline" viewBox="0 30 660 180" preserveAspectRatio="none" role="img" aria-label="Recent CPU activity from recorded samples">
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
  return <Card className="dashboard-card activity-card" padding={0}>
    <div className="card-heading">
      <h2>Resource activity</h2>
      <SegmentedControl label="Chart time range" value={range} onChange={setRange} size="sm" className="range-control">
        <SegmentedControlItem value="60" label="1 minute" isLabelHidden icon={<span>1m</span>} />
        <SegmentedControlItem value="300" label="5 minutes" isLabelHidden icon={<span>5m</span>} />
        <SegmentedControlItem value="600" label="10 minutes" isLabelHidden icon={<span>10m</span>} />
      </SegmentedControl>
    </div>
    <div className="chart-wrap">
      <svg className="activity-chart" viewBox={`0 0 ${width} 246`} role="img" aria-labelledby="activity-title activity-description">
        <title id="activity-title">CPU and memory utilization</title>
        <desc id="activity-description">{history.length} actual samples at {report.collector.interval_seconds}-second intervals. {history.length ? `From ${chartTime(history[0].sampled_at)} to ${chartTime(history.at(-1)!.sampled_at)}.` : "History is collecting."} Gaps represent unavailable readings.</desc>
        {[0, 25, 50, 75, 100].map((value) => <g key={value} className="chart-grid">
          <line x1={left} x2={right} y1={200 - value * 1.65} y2={200 - value * 1.65} />
          <text x={compact ? 39 : 34} y={204 - value * 1.65} textAnchor="end">{value}%</text>
        </g>)}
        {[0, 1, 2, 3, 4].map((index) => <g key={index} className="chart-grid">
          <line x1={left + index * (right - left) / 4} x2={left + index * (right - left) / 4} y1="35" y2="200" />
          {history.length > 1 && (!compact || index % 2 === 0) && <text x={left + index * (right - left) / 4} y="226" textAnchor={index === 0 ? "start" : index === 4 ? "end" : "middle"}>{chartTime(new Date(start + (end - start) * index / 4).toISOString())}</text>}
        </g>)}
        <g data-testid="cpu-chart" className="cpu-series">
          <path d={paths(history, "cpu_usage_percent", x)} fill="none" stroke="currentColor" strokeWidth="2" vectorEffect="non-scaling-stroke" />
          {history.map((s) => s.cpu_usage_percent === null ? null : <circle key={s.sampled_at} cx={x(s)} cy={200 - s.cpu_usage_percent * 1.65} r={history.length === 1 ? 3 : 2} fill="currentColor"><title>{chartTime(s.sampled_at)} · CPU {percent(s.cpu_usage_percent)}</title></circle>)}
        </g>
        <g data-testid="memory-chart" className="memory-series">
          <path d={paths(history, "memory_used_percent", x)} fill="none" stroke="currentColor" strokeWidth="2" vectorEffect="non-scaling-stroke" />
          {history.map((s) => s.memory_used_percent === null ? null : <circle key={s.sampled_at} cx={x(s)} cy={200 - s.memory_used_percent * 1.65} r={history.length === 1 ? 3 : 2} fill="currentColor"><title>{chartTime(s.sampled_at)} · Memory {percent(s.memory_used_percent)}</title></circle>)}
        </g>
        {!hasValues && <text x={(left + right) / 2} y="126" textAnchor="middle" className="chart-placeholder">Waiting for the first measurements</text>}
      </svg>
    </div>
    <div className="chart-legend"><span><i className="cpu-dot" />CPU</span><span><i className="memory-dot" />Memory</span></div>
    <p className="chart-caption">{history.length} actual {history.length === 1 ? "sample" : "samples"} · collected during this server session · no estimated history</p>
  </Card>;
}

export function Overview({ report, platform, range, setRange }: { report: ServerReport; platform?: PlatformReport; range: string; setRange: (v: string) => void }) {
  const cpu = report.cpu.available ? report.cpu.usage_percent : null;
  const memory = report.memory.available ? report.memory.used_percent : null;
  const storage = report.storage.available ? report.storage.used_percent : null;
  const seconds = report.uptime.available ? report.uptime.seconds : null;
  return <div data-testid="server-overview" data-sampled-at={report.sampled_at} className="overview-content">
    <div className="metric-grid">
      <Card className="dashboard-card metric-card" padding={0}>
        <div className="metric-label"><span className="metric-icon"><Cpu /></span><span>CPU</span></div>
        <strong data-testid="cpu-usage" data-metric-value={cpu ?? "null"}>{percent(cpu)}</strong>
        {cpu === null ? <p className="metric-note">{report.cpu.reason || "First reading is collecting"}</p> : <Sparkline history={report.history} />}
      </Card>
      <Card className="dashboard-card metric-card" padding={0}>
        <div className="metric-label"><span className="metric-icon"><MemoryStick /></span><span>Memory</span></div>
        <strong className="capacity-value" data-testid="memory-usage" data-metric-value={memory ?? "null"}>{memory === null ? "Unavailable" : <>{bytes(report.memory.used_bytes)} <small>/ {bytes(report.memory.total_bytes)}</small></>}</strong>
        {memory === null ? <p className="metric-note">{report.memory.reason}</p> : <><ProgressBar className="resource-meter" label="Memory used" isLabelHidden value={memory} /><p className="meter-caption">{percent(memory)} used</p></>}
      </Card>
      <Card className="dashboard-card metric-card" padding={0}>
        <div className="metric-label"><span className="metric-icon"><Database /></span><span>Storage</span></div>
        <strong className="capacity-value" data-testid="storage-usage" data-metric-value={storage ?? "null"}>{storage === null ? "Unavailable" : <>{bytes(report.storage.used_bytes)} <small>/ {bytes(report.storage.total_bytes)}</small></>}</strong>
        {storage === null ? <p className="metric-note">{report.storage.reason}</p> : <><ProgressBar className="resource-meter" label="Storage used" isLabelHidden value={storage} /><p className="meter-caption">{percent(storage)} used · {report.storage.disks.length} {report.storage.disks.length === 1 ? "volume" : "volumes"}</p></>}
      </Card>
      <Card className="dashboard-card metric-card" padding={0}>
        <div className="metric-label"><span className="metric-icon"><Clock3 /></span><span>Uptime</span></div>
        <strong data-testid="server-uptime" data-metric-value={seconds ?? "null"}>{uptime(seconds)}</strong>
        <p className="metric-note">{seconds === null ? report.uptime.reason : <>Last sampled<br /><time dateTime={report.sampled_at}>{dateLabel(report.sampled_at)}</time></>}</p>
      </Card>
    </div>
    {report.collector.status !== "available" && <p className="collector-notice" role="status"><Info aria-hidden="true" />{report.collector.status === "partial" ? "Some measurements are unavailable." : "Server measurements are unavailable."} {report.collector.reasons.join(" ")}</p>}
    <div className="activity-layout">
      <ResourceChart report={report} range={range} setRange={setRange} />
      <Card className="dashboard-card server-details" padding={0}>
        <div className="card-heading"><h2>Server details</h2></div>
        <dl>
          <div><dt><Monitor />Operating system</dt><dd>{platform?.os_name || report.os}</dd></div>
          <div><dt><Cpu />Architecture</dt><dd>{report.arch}</dd></div>
          <div><dt><Server />Logical cores</dt><dd>{report.cpu.logical_cores ?? "Unavailable"}</dd></div>
          <div><dt><Clock3 />Sampling interval</dt><dd>{report.collector.interval_seconds}s</dd></div>
        </dl>
        <div className="network-summary"><span><Network />Network</span><span><ArrowDown />{report.network.available && report.network.rx_bytes_per_second !== null ? `${bytes(report.network.rx_bytes_per_second)}/s` : "Unavailable"}</span><span><ArrowUp />{report.network.available && report.network.tx_bytes_per_second !== null ? `${bytes(report.network.tx_bytes_per_second)}/s` : "Unavailable"}</span></div>
      </Card>
    </div>
  </div>;
}

function State({ state }: { state: ServiceItem["status"] }) {
  return <span className={`service-state state-${state}`}><i />{state[0].toUpperCase() + state.slice(1)}</span>;
}

export function ServiceInventory({ report, compact = false, query, setQuery, viewAll }: { report: ServicesReport; compact?: boolean; query: string; setQuery: (q: string) => void; viewAll?: () => void }) {
  const [filter, setFilter] = useState("all");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string>();
  const filtered = report.items.filter((s) => (filter === "all" || s.status === filter) && `${s.name} ${s.display_name}`.toLowerCase().includes(query.toLowerCase().trim()));
  const pageSize = compact ? 5 : 25;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const visible = filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  return <Card className="dashboard-card service-card" padding={0} data-testid="service-inventory" data-sampled-at={report.sampled_at}>
    <div className="card-heading service-heading">
      <div><h2>{compact ? "Services" : "Service inventory"}</h2>{!compact && <p>Native {report.manager === "windows-scm" ? "Windows service manager" : report.manager === "systemd" ? "systemd" : "service manager"} · read-only inventory</p>}</div>
      <div className="service-controls">
        <label className="compact-search"><Search aria-hidden="true" /><input aria-label="Search services" placeholder="Search services…" value={query} onChange={(e) => { setQuery(e.target.value); setPage(0); }} type="search" /></label>
        <SegmentedControl value={filter} onChange={(v) => { setFilter(v); setPage(0); }} label="Service state" size="sm">
          <SegmentedControlItem value="all" label="All" />
          <SegmentedControlItem value="running" label="Running" />
          <SegmentedControlItem value="stopped" label="Stopped" />
        </SegmentedControl>
      </div>
    </div>
    {!report.available ? <div className="inventory-empty" role="status"><Server /><h3>Service inventory unavailable</h3><p>{report.reason}</p></div> : <>
      {report.truncated && <p className="table-notice">The service manager returned a limited inventory of {report.items.length} entries.</p>}
      <div className="service-table-wrap"><table className="service-table">
        <thead><tr><th scope="col">Service</th><th scope="col">State</th><th scope="col" className="start-column">Start mode</th><th scope="col"><span className="sr-only">Details</span></th></tr></thead>
        <tbody>{visible.map((service) => <Fragment key={service.id}>
          <tr><th scope="row"><Server aria-hidden="true" /><span>{service.display_name || service.name}</span></th><td><State state={service.status} /></td><td className="start-column">{service.start_type[0].toUpperCase() + service.start_type.slice(1)}</td><td><Button label={`Details for ${service.display_name || service.name}`} size="sm" variant="secondary" className="detail-button" onClick={() => setSelected(selected === service.id ? undefined : service.id)} aria-expanded={selected === service.id} aria-controls={selected === service.id ? "service-detail" : undefined}>Details</Button></td></tr>
          {selected === service.id && <tr><td colSpan={4}><div id="service-detail" className="service-detail" aria-label={`Service facts for ${service.display_name || service.name}`}>
            <div><h3>{service.display_name || service.name}</h3><Button label="Close service details" variant="ghost" size="sm" onClick={() => setSelected(undefined)}>Close</Button></div>
            <dl><div><dt>Service name</dt><dd>{service.name}</dd></div><div><dt>State</dt><dd>{service.status}</dd></div><div><dt>Start mode</dt><dd>{service.start_type}</dd></div><div><dt>Source</dt><dd>{report.manager}</dd></div><div><dt>Last collected</dt><dd>{dateLabel(report.sampled_at)}</dd></div></dl>
            <p>This view reads the native service manager. Service changes are not available yet.</p>
          </div></td></tr>}
        </Fragment>)}</tbody>
      </table></div>
      {!filtered.length && <div className="inventory-empty"><Search /><h3>{report.items.length ? "No matching services" : "No services returned"}</h3><p>{report.items.length ? "Try another name or choose All states." : "The native service manager returned an empty inventory."}</p>{report.items.length > 0 && <Button label="Clear service filters" variant="secondary" onClick={() => { setQuery(""); setFilter("all"); setPage(0); }} />}</div>}
      <div className="table-footer"><span>{filtered.length ? `${currentPage * pageSize + 1}–${Math.min((currentPage + 1) * pageSize, filtered.length)} of ${filtered.length}` : "0"} services · collected {time(report.sampled_at)}</span>
        {compact && viewAll ? <Button label="View all services" variant="ghost" size="sm" onClick={viewAll} /> : pageCount > 1 && <div><Button label="Previous services" size="sm" variant="ghost" isDisabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</Button><span>{currentPage + 1} / {pageCount}</span><Button label="Next services" size="sm" variant="ghost" isDisabled={currentPage + 1 === pageCount} onClick={() => setPage(currentPage + 1)}>Next</Button></div>}
      </div>
    </>}
  </Card>;
}
