// A cPanel backup file for "Move a website here": the shape of what the
// server read from an uploaded file, and the checks on a chosen file before
// it is sent. No imports, so the tests load it alone.

// What an uploaded backup file holds, as the server read it, and what will
// not move, each with its reason.
export interface ArchiveItem { part: string; text: string; where: string }
export interface MigrationArchive { user: string; domain: string; databases: string[]; bytes: number; home_bytes: number; not_carried: ArchiveItem[] }
export interface ArchiveSource { id: string; archive: MigrationArchive; expires_at: string }

export const maxArchiveBytes = 32 * 1024 ** 3;

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown, max = 4096): v is string => typeof v === "string" && v.length <= max;
const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

export function parseArchiveSource(v: unknown): ArchiveSource | undefined {
  const s = object(v) ? v.source : undefined;
  if (!object(s) || !text(s.id) || !/^[a-f0-9]{32}$/.test(s.id) || s.via !== "archive" || !text(s.expires_at, 40)) return undefined;
  const a = s.archive;
  if (!object(a) || !text(a.user, 32) || !/^[a-z][a-z0-9_]{2,31}$/.test(a.user) || !text(a.domain, 253) || !count(a.bytes) || !count(a.home_bytes)) return undefined;
  if (!Array.isArray(a.databases) || a.databases.length > 64 || !a.databases.every((d) => text(d, 64))) return undefined;
  if (!Array.isArray(a.not_carried) || a.not_carried.length > 200) return undefined;
  const items: ArchiveItem[] = [];
  for (const i of a.not_carried) {
    if (!object(i) || !text(i.part, 32) || !text(i.text, 1100) || !(i.where === undefined || text(i.where, 1100))) return undefined;
    items.push({ part: i.part, text: i.text, where: (i.where as string | undefined) ?? "" });
  }
  return { id: s.id, expires_at: s.expires_at, archive: { user: a.user, domain: a.domain, databases: a.databases as string[], bytes: a.bytes, home_bytes: a.home_bytes, not_carried: items } };
}

// checkArchiveFile says why a chosen file cannot be a cPanel backup file
// this server takes, or undefined.
export function checkArchiveFile(file: { name: string; size: number } | undefined): string | undefined {
  if (!file) return "Choose the backup file first.";
  if (!/\.(tar\.gz|tgz|tar)$/i.test(file.name)) return "Choose the .tar.gz file cPanel's backup made, such as cpmove-name.tar.gz or backup-…_name.tar.gz.";
  if (file.size <= 0) return "This file is empty.";
  if (file.size > maxArchiveBytes) return "This file is larger than 32 GiB, the most one move takes. Move the website from its server instead.";
  return undefined;
}

// sizeText is a byte count in the units a person reads.
export function sizeText(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}
