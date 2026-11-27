import type { PasskeyStatus } from "./auth-api";
import type { CustomerList } from "./customers-api";
import type { BackupStorage } from "./site-backups-api";
import type { Website } from "./websites-api";
import type { WebsiteJob } from "./wordpress-api";

// Home's "Get started" list: what makes a new server ready for customers,
// read from the server's real state each time Home opens. Each step says why
// it matters, where it stands, and offers one way to the screen that does
// it. Nothing here is stored: a step ticks itself when the API says it is
// done, and unticks if that stops being true (a failed restore test).

export type StepId = "panel-address" | "first-website" | "move-website" | "backups" | "customer-login" | "always-https";
// done: nothing left to do. todo: the owner can act now. waiting: something
// outside the panel has to happen first (DNS, a certificate, a customer).
// unknown: the panel could not read it.
export type StepState = "done" | "todo" | "waiting" | "unknown";
// page: a screen in the panel. address: the panel at its own name, in a new
// tab. how: instructions for the server, shown in place.
export type StepAction =
  | { kind: "page"; label: string; to: string }
  | { kind: "address"; label: string; href: string }
  | { kind: "how"; label: string; lines: string[] };

export interface Step {
  id: StepId;
  title: string;
  why: string;
  state: StepState;
  status: string;
  action?: StepAction;
  optional?: true;
}

// One API read: its data, the problem it ended with, or still loading.
export type Reading<T> = { data: T } | { error: string } | { loading: true };

export interface ServerState {
  address: Reading<PasskeyStatus>;
  websites: Reading<Website[]>;
  jobs: Reading<WebsiteJob[]>;
  backups: Reading<BackupStorage>;
  customers: Reading<CustomerList>;
  // Where the panel is open now, such as https://panel.example.com:8443.
  origin: string;
  // A day in the reader's terms, for "passed on 27 Nov 2026".
  day?: (iso: string) => string;
}

const defaultDay = (iso: string) => {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "an unknown day" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
};

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
const sitePage = (site: Pick<Website, "account_id">, tab: "" | "domains" | "backups") => `/websites/sites/${site.account_id}${tab ? `/${tab}` : ""}`;

function unread(reading: Reading<unknown>): Pick<Step, "state" | "status"> | undefined {
  if ("loading" in reading) return { state: "unknown", status: "Checking…" };
  if ("error" in reading) return { state: "unknown", status: `The panel could not check this: ${reading.error}` };
  return undefined;
}

function hostOf(address: string): string {
  try { return new URL(address).host; } catch { return address; }
}

const nameHow = [
  "Choose a name for the panel, such as panel.example.com, and point it at this server's IP address at your DNS provider.",
  "On the server, as root, run the installer again with that name and your email address: ./install.sh --panel-host panel.example.com --acme-email you@example.com",
  "Open ports 80 and 8443 in the server's firewall. The panel then gets a free Let's Encrypt certificate for the name by itself.",
];

const certificateHow = [
  "Check that the name points at this server's IP address, and that port 80 is open to the internet: Let's Encrypt checks the name there.",
  "See what happened on the server: journalctl -u sifruno | grep 'Panel certificate:'",
  "The panel asks again by itself within 6 hours. To ask sooner, restart it on the server (systemctl restart sifruno); it waits an hour between tries.",
];

export function panelAddressStep(reading: Reading<PasskeyStatus>, origin: string): Step {
  const base = { id: "panel-address" as const, title: "Give the panel its own address", why: "You and your customers sign in at a name with a padlock, not at an IP address that browsers warn about." };
  const pending = unread(reading);
  if (pending) return { ...base, ...pending };
  const status = (reading as { data: PasskeyStatus }).data;
  if (status.available) {
    return { ...base, state: "done", status: `The panel answers at ${status.address ? hostOf(status.address) : "its name"} with a certificate browsers trust.` };
  }
  if (!status.address) {
    return { ...base, state: "todo", status: "The panel has no name yet, so it opens only through this server.", action: { kind: "how", label: "Show how", lines: nameHow } };
  }
  const host = hostOf(status.address);
  if (status.address.toLowerCase() === origin.toLowerCase()) {
    return { ...base, state: "waiting", status: `Browsers warn at ${host}: its certificate is not in place yet. Customers' setup links and phpMyAdmin open here too.`, action: { kind: "how", label: "Show what to check", lines: certificateHow } };
  }
  return { ...base, state: "todo", status: `The panel has a name, ${host}. Open it there: that is where you check its certificate and where your customers sign in.`, action: { kind: "address", label: `Open ${host}`, href: `${status.address}/` } };
}

export function firstWebsiteStep(reading: Reading<Website[]>): Step {
  const base = { id: "first-website" as const, title: "Create your first website", why: "A website is what your customers pay for. The wizard sets up the hosting account, the database and WordPress." };
  const pending = unread(reading);
  if (pending) return { ...base, ...pending };
  const sites = (reading as { data: Website[] }).data;
  if (sites.length === 0) return { ...base, state: "todo", status: "No websites yet.", action: { kind: "page", label: "Create a website", to: "/websites/new" } };
  return { ...base, state: "done", status: `${plural(sites.length, "website", "websites")} on this server.`, action: { kind: "page", label: "Open Websites", to: "/websites" } };
}

export function moveWebsiteStep(reading: Reading<WebsiteJob[]>): Step {
  const base = { id: "move-website" as const, title: "Move a website from another server", why: "Bring a site over from your cPanel server. It keeps running there until you change its DNS.", optional: true as const };
  const pending = unread(reading);
  if (pending) return { ...base, ...pending };
  // The list is newest first; the latest move says where things stand.
  const moves = (reading as { data: WebsiteJob[] }).data.filter((job) => job.kind === "migration" && job.migration);
  const moved = moves.find((job) => job.migration?.gate === "ready");
  if (moved) return { ...base, state: "done", status: `${moved.domain || "A website"} was moved and is ready for its DNS change.`, action: { kind: "page", label: "Open the move", to: `/websites/move/${moved.id}` } };
  const latest = moves[0];
  if (!latest) return { ...base, state: "todo", status: "Skip this if you have no other server.", action: { kind: "page", label: "Move a website", to: "/websites/move" } };
  const name = latest.domain || "the website";
  if (latest.state === "failed") return { ...base, state: "todo", status: `The move of ${name} stopped. Open it to see why and what to do.`, action: { kind: "page", label: "Open the move", to: `/websites/move/${latest.id}` } };
  return { ...base, state: "todo", status: `${name} is being moved. Open it to compare the copy and mark it ready.`, action: { kind: "page", label: "Open the move", to: `/websites/move/${latest.id}` } };
}

export function backupsStep(reading: Reading<BackupStorage>, websites: Reading<Website[]>, day: (iso: string) => string = defaultDay): Step {
  const base = { id: "backups" as const, title: "Set up backups and test a restore", why: "Nightly copies on another server save your customers' sites if this one fails. A backup counts once you have seen it restore." };
  const pending = unread(reading);
  if (pending) return { ...base, ...pending };
  const storage = (reading as { data: BackupStorage }).data;
  const storagePage = { kind: "page" as const, label: "Set up backup storage", to: "/server/backups" };
  if (!storage.configured) return { ...base, state: "todo", status: "No website is backed up: the panel does not know where to keep backups yet.", action: storagePage };
  if (!storage.password_saved) return { ...base, state: "todo", status: "Backups are set up, but the backup password is not marked as saved. Without it no backup can be restored on another server.", action: { ...storagePage, label: "Save the backup password" } };
  const sites = "data" in websites ? websites.data : [];
  const drill = storage.last_drill;
  if (drill && drill.passed) return { ...base, state: "done", status: `Every website is backed up each night, and a restore test passed on ${day(drill.checked_at)}.` };
  if (drill) {
    const site = sites.find((s) => s.account_id === drill.account_id);
    return { ...base, state: "todo", status: `The last restore test, on ${drill.domain || "a website"}, failed. Open its backups to see why.`, action: site ? { kind: "page", label: "Open its backups", to: sitePage(site, "backups") } : { ...storagePage, label: "Open backup storage" } };
  }
  if (sites.length === 0) return { ...base, state: "waiting", status: "Backups are set up. They start with your first website.", action: { ...storagePage, label: "Open backup storage" } };
  return { ...base, state: "todo", status: `Backups run every night at ${storage.nightly_at || "02:30"}. Test one restore now to be sure they work.`, action: { kind: "page", label: "Test a restore", to: sitePage(sites[0], "backups") } };
}

export function customerLoginStep(reading: Reading<CustomerList>): Step {
  const base = { id: "customer-login" as const, title: "Give a customer their own login", why: "Customers manage their own site's files, databases and domains, so small jobs stop coming to you." };
  const pending = unread(reading);
  if (pending) return { ...base, ...pending };
  const logins = (reading as { data: CustomerList }).data.items;
  const ready = logins.filter((c) => c.setup === "done" && !c.disabled);
  const page = { kind: "page" as const, label: "Open Customers", to: "/customers" };
  if (ready.length > 0) return { ...base, state: "done", status: `${plural(ready.length, "customer login is", "customer logins are")} set up.`, action: page };
  const waiting = logins.find((c) => c.setup === "pending" && !c.disabled);
  if (waiting) return { ...base, state: "waiting", status: `Waiting for ${waiting.username} to open the setup link and choose a password.`, action: page };
  const expired = logins.find((c) => c.setup === "expired" && !c.disabled);
  if (expired) return { ...base, state: "todo", status: `The setup link for ${expired.username} has expired. Make a new one and send it again.`, action: { ...page, label: "Make a new setup link" } };
  return { ...base, state: "todo", status: "Only you can sign in so far.", action: { ...page, label: "Give a customer a login" } };
}

export function alwaysHttpsStep(reading: Reading<Website[]>): Step {
  const base = { id: "always-https" as const, title: "Always use HTTPS", why: "Visitors always get the padlock, and browsers and search engines stop marking the sites as not secure." };
  const pending = unread(reading);
  if (pending) return { ...base, ...pending };
  const sites = (reading as { data: Website[] }).data.filter((s) => s.state === "active");
  if (sites.length === 0) return { ...base, state: "waiting", status: "This follows your first website.", action: { kind: "page", label: "Open Websites", to: "/websites" } };
  const secure = sites.filter((s) => s.https.on);
  if (secure.length === 0) {
    return { ...base, state: "waiting", status: `No website has a certificate yet. ${sites[0].domain} gets one by itself once its domain points at this server.`, action: { kind: "page", label: "Open Domains and SSL", to: sitePage(sites[0], "domains") } };
  }
  if (secure.some((s) => s.always_https === undefined)) return { ...base, state: "unknown", status: "This server does not report it. Check each website's Domains and SSL tab." };
  const plain = secure.find((s) => s.always_https === false);
  if (plain) return { ...base, state: "todo", status: `${plain.domain} still answers on plain http://.`, action: { kind: "page", label: "Turn it on", to: sitePage(plain, "domains") } };
  const waiting = sites.length - secure.length;
  return { ...base, state: "done", status: `${plural(secure.length, "website sends", "websites send")} visitors to https://.${waiting ? ` ${plural(waiting, "website follows", "websites follow")} once its certificate comes.` : ""}` };
}

export function getStartedSteps(state: ServerState): Step[] {
  return [
    panelAddressStep(state.address, state.origin),
    firstWebsiteStep(state.websites),
    moveWebsiteStep(state.jobs),
    backupsStep(state.backups, state.websites, state.day),
    customerLoginStep(state.customers),
    alwaysHttpsStep(state.websites),
  ];
}

// How far the owner is: the steps that are not optional count. The list is
// complete when each of them is done.
export function getStartedProgress(steps: readonly Step[]): { done: number; total: number; complete: boolean } {
  const counted = steps.filter((s) => !s.optional);
  const done = counted.filter((s) => s.state === "done").length;
  return { done, total: counted.length, complete: done === counted.length };
}

// The one step whose button is the primary action: the first the owner can
// act on now in the panel, required steps before the optional one. Steps
// done on the server itself ("how") never are: their button only shows text.
export function nextStep(steps: readonly Step[]): StepId | undefined {
  const actionable = (s: Step) => s.state === "todo" && s.action !== undefined && s.action.kind !== "how";
  return (steps.find((s) => !s.optional && actionable(s)) ?? steps.find(actionable))?.id;
}
