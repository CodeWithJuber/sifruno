// A migration job's record, as GET /api/v1/websites/jobs/{id} carries it
// under "migration" for a website moved from another server. It never holds
// a password, a hash or a crontab command. The server is the authority; this
// only checks the shape, so a broken answer is reported instead of shown.

export type Gate = "closed" | "open" | "accepted" | "ready";
export interface TableDifference { database: string; table: string; source: number; copy: number }
export interface VerifySummary {
  running: boolean; ran: boolean; cutover_allowed: boolean; verdict: string;
  pages_compared: number; pages_pass: number; pages_warn: number; pages_fail: number;
  probes_pass: number; probes_fail: number; problems: string[]; lines: string[]; finished_at: string;
  // Why the copy is not the same yet, or the comparison did not run, and what to do.
  why: string; next: string;
}
export interface Acceptance { actor: string; at: string; reason: string }
export interface DnsRecord { name: string; type: "A" | "AAAA"; value: string }
export interface ActivityLine { at: string; actor: string; what: string }
// Whether the old site's certificate was copied, until when and from which
// authority, or why not; null for a move from before that step.
export interface MigrationCertificate { copied: boolean; not_after: string; issuer: string; why: string }
export interface MigrationRecord {
  source: string;
  source_host: string;
  source_user: string;
  tier: string;
  php_source: string;
  wordpress: boolean;
  databases: string[];
  database_users: string[];
  tables: TableDifference[];
  notes: string[];
  verify: VerifySummary | null;
  gate: Gate;
  accepted: Acceptance | null;
  address: string;
  dns: DnsRecord[];
  key_removed: boolean;
  activity: ActivityLine[];
  certificate: MigrationCertificate | null;
}

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown, max = 1000): v is string => typeof v === "string" && v.length <= max;
const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= -1;
const bool = (v: unknown): v is boolean => typeof v === "boolean";
const date = (v: unknown) => text(v) && Number.isFinite(Date.parse(v));
const texts = (v: unknown, max: number): v is string[] => Array.isArray(v) && v.length <= max && v.every((item) => text(item));
const optionalTexts = (v: unknown, max: number) => v === undefined || v === null || texts(v, max);
const gates: readonly string[] = ["closed", "open", "accepted", "ready"];

function parseVerify(v: unknown): VerifySummary | null | undefined {
  if (v === undefined || v === null) return null;
  if (!object(v) || !bool(v.running) || !bool(v.ran) || !bool(v.cutover_allowed) || !text(v.verdict)) return undefined;
  const numbers = [v.pages_compared, v.pages_pass, v.pages_warn, v.pages_fail, v.probes_pass, v.probes_fail];
  if (!numbers.every(count) || !optionalTexts(v.problems, 60) || !optionalTexts(v.lines, 60) || !(v.finished_at === "" || v.finished_at === undefined || date(v.finished_at))) return undefined;
  if (!(v.why === undefined || text(v.why)) || !(v.next === undefined || text(v.next))) return undefined;
  return {
    running: v.running, ran: v.ran, cutover_allowed: v.cutover_allowed, verdict: v.verdict,
    pages_compared: v.pages_compared as number, pages_pass: v.pages_pass as number, pages_warn: v.pages_warn as number, pages_fail: v.pages_fail as number,
    probes_pass: v.probes_pass as number, probes_fail: v.probes_fail as number, problems: (v.problems as string[] | null | undefined) ?? [],
    lines: (v.lines as string[] | null | undefined) ?? [], finished_at: (v.finished_at as string | undefined) ?? "",
    why: (v.why as string | undefined) ?? "", next: (v.next as string | undefined) ?? "",
  };
}

function parseCertificate(v: unknown): MigrationCertificate | null | undefined {
  if (v === undefined || v === null) return null;
  if (!object(v) || !bool(v.copied) || !(v.issuer === undefined || text(v.issuer, 600)) || !(v.why === undefined || text(v.why))) return undefined;
  if (v.copied ? !date(v.not_after) : !(v.not_after === undefined || v.not_after === "")) return undefined;
  return { copied: v.copied, not_after: (v.not_after as string | undefined) ?? "", issuer: (v.issuer as string | undefined) ?? "", why: (v.why as string | undefined) ?? "" };
}

function parseList<T>(v: unknown, max: number, item: (x: unknown) => T | undefined): T[] | undefined {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.length > max) return undefined;
  const out = v.map(item);
  return out.some((x) => x === undefined) ? undefined : out as T[];
}

export function parseMigration(v: unknown): MigrationRecord | null | undefined {
  if (v === undefined || v === null) return null;
  if (!object(v) || !text(v.source) || !/^[a-f0-9]{32}$/.test(v.source) || !text(v.source_host, 253) || !text(v.source_user, 32)) return undefined;
  if (!(v.tier === undefined || text(v.tier, 20)) || !(v.php_source === undefined || text(v.php_source, 64)) || !bool(v.wordpress) || !gates.includes(String(v.gate))) return undefined;
  if (!optionalTexts(v.databases, 64) || !optionalTexts(v.database_users, 64) || !optionalTexts(v.notes, 40) || !text(v.address, 64) || !bool(v.key_removed)) return undefined;
  const tables = parseList(v.tables, 60, (t) => object(t) && text(t.database, 64) && text(t.table, 64) && count(t.source) && count(t.copy) ? { database: t.database, table: t.table, source: t.source, copy: t.copy } as TableDifference : undefined);
  const dns = parseList(v.dns, 4, (d) => object(d) && text(d.name, 253) && (d.type === "A" || d.type === "AAAA") && text(d.value, 64) ? { name: d.name, type: d.type, value: d.value } as DnsRecord : undefined);
  const activity = parseList(v.activity, 80, (a) => object(a) && date(a.at) && text(a.actor, 120) && text(a.what) ? { at: a.at as string, actor: a.actor, what: a.what } : undefined);
  const verify = parseVerify(v.verify);
  const certificate = parseCertificate(v.certificate);
  let accepted: Acceptance | null | undefined = null;
  if (v.accepted !== undefined && v.accepted !== null) {
    const a = v.accepted;
    accepted = object(a) && text(a.actor, 120) && date(a.at) && text(a.reason, 600) ? { actor: a.actor, at: a.at as string, reason: a.reason } : undefined;
  }
  if (!tables || !dns || !activity || verify === undefined || accepted === undefined || certificate === undefined) return undefined;
  return {
    source: v.source, source_host: v.source_host, source_user: v.source_user, tier: (v.tier as string | undefined) ?? "", php_source: (v.php_source as string | undefined) ?? "",
    wordpress: v.wordpress, databases: (v.databases as string[] | null | undefined) ?? [], database_users: (v.database_users as string[] | null | undefined) ?? [],
    tables, notes: (v.notes as string[] | null | undefined) ?? [], verify, gate: v.gate as Gate, accepted, address: v.address, dns, key_removed: v.key_removed, activity, certificate,
  };
}

// What the cutover step says about https once the DNS records point here:
// the copied certificate and its date, or why there is none yet.
export function certificateNote(m: Pick<MigrationRecord, "certificate">, locale?: string): string {
  const follows = "Once these records point here, the panel gets the website's certificate by itself, usually within the hour, when certificates are set up on this server. Until then the website uses http.";
  const c = m.certificate;
  if (c?.copied) {
    const date = new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeZone: "UTC" }).format(new Date(c.not_after));
    return `The website already answers https on this server, with the certificate copied from the old server, valid until ${date}. Once these records point here, the panel replaces it with a Let's Encrypt certificate before it runs out.`;
  }
  return c?.why ? `${c.why} ${follows}` : follows;
}

// The line a person adds to their computer's hosts file to see the copy
// before DNS changes.
export function hostsLine(address: string, domain: string): string {
  return `${address} ${domain} www.${domain}`;
}
