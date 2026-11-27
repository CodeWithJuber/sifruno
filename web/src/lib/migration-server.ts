// Another Linux server for "Move a website here": the shape of the
// websites the server read from the old server's web server, and the checks
// on what the person types (the account name here, root's password or a
// private key) before it is sent. No imports, so the tests load it alone.

// One thing that does not move, or stops a website from moving: plain
// words, and the file and line it came from for Technical details.
export interface SiteItem { part: string; text: string; where: string }
export interface ServerSite {
  domain: string;
  aliases: string[];
  www: boolean;
  server: "apache" | "nginx";
  where: string;
  doc_root: string;
  owner: string;
  account: string;
  php_source: string;
  php: string;
  wordpress: boolean;
  database: string;
  certificate: boolean;
  movable: boolean;
  refused: SiteItem[];
  not_carried: SiteItem[];
}

type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown, max = 4096): v is string => typeof v === "string" && v.length <= max;
const list = (v: unknown, max: number): v is unknown[] => Array.isArray(v) && v.length <= max;

function items(v: unknown): SiteItem[] | undefined {
  if (!list(v, 200)) return undefined;
  const out: SiteItem[] = [];
  for (const i of v) {
    if (!object(i) || !text(i.part, 32) || !text(i.text, 1100) || !(i.where === undefined || text(i.where, 1100))) return undefined;
    out.push({ part: i.part, text: i.text, where: (i.where as string | undefined) ?? "" });
  }
  return out;
}

export function parseSites(v: unknown): ServerSite[] | undefined {
  if (!object(v) || !list(v.sites, 500)) return undefined;
  const out: ServerSite[] = [];
  for (const s of v.sites) {
    if (!object(s) || !text(s.domain, 253) || !list(s.aliases, 64) || !s.aliases.every((a) => text(a, 253)) || typeof s.www !== "boolean") return undefined;
    if ((s.server !== "apache" && s.server !== "nginx") || !text(s.where, 1100) || !text(s.doc_root, 4096) || !text(s.owner, 32) || !text(s.account, 32)) return undefined;
    if (!text(s.php_source, 32) || !text(s.php, 8) || typeof s.wordpress !== "boolean" || !text(s.database, 64) || typeof s.certificate !== "boolean" || typeof s.movable !== "boolean") return undefined;
    const refused = items(s.refused), notCarried = items(s.not_carried);
    if (!refused || !notCarried) return undefined;
    out.push({ domain: s.domain, aliases: s.aliases as string[], www: s.www, server: s.server, where: s.where, doc_root: s.doc_root, owner: s.owner, account: s.account,
      php_source: s.php_source, php: s.php, wordpress: s.wordpress, database: s.database, certificate: s.certificate, movable: s.movable, refused, not_carried: notCarried });
  }
  return out;
}

// The account name the website gets here, as the server takes it.
export function checkAccountName(value: string): string | undefined {
  if (!value) return "Enter the account name the website gets here.";
  if (value !== value.toLowerCase()) return "Use lowercase letters only.";
  if (!/^[a-z][a-z0-9_]{2,31}$/.test(value)) return "Use 3 to 32 lowercase letters, digits or _, starting with a letter.";
  return undefined;
}

// Root's password or a private key, as the server takes them: the server
// checks both again and keeps neither.
export function checkRootPassword(value: string): string | undefined {
  if (!value) return "Enter root's password on the old server.";
  if (/\p{Cc}/u.test(value)) return "Remove line breaks and tabs from the password.";
  if (new TextEncoder().encode(value).length > 1024) return "Use at most 1024 characters.";
  return undefined;
}
export function checkPrivateKey(value: string): string | undefined {
  const key = value.trim();
  if (!key) return "Paste the private key root accepts on the old server.";
  if (!/^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(key) || !/-----END [A-Z0-9 ]*PRIVATE KEY-----$/.test(key)) return "Paste the whole private key, from its -----BEGIN line to its -----END line. A public key (ssh-ed25519 AAAA…) does not sign in.";
  if (new TextEncoder().encode(key).length > 16384) return "This key is larger than 16 KiB, more than a private key is.";
  return undefined;
}

// A site's main facts for the summary: what the server is and where the
// site's files are, in words.
export function serverName(site: ServerSite): string {
  return site.server === "nginx" ? "nginx" : "Apache";
}
