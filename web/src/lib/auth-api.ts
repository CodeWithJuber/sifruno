// Sign-in and first-run setup. Credentials stay in memory only: never in
// localStorage, the URL or logs. Server messages for these routes are written
// for people, so they are shown as they come.

// role is "customer" for a site owner's login, which reaches only its own
// websites; view_as names the customer an admin is viewing the panel as.
// routes comes with a restricted session: the API routes it may use, as the
// server's customer table names them ("POST /api/v1/websites/sites/{account_id}/php").
export interface AuthSession { authenticated: true; csrf_token: string; expires_at: string; username?: string; role?: "admin" | "customer"; view_as?: string; routes?: string[] }
export interface SetupSecret { secret: string; otpauth_uri: string; expires_at: string }
export interface CustomerSetupSecret extends SetupSecret { username: string }

export class AuthError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}

const object = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string";

const name = (v: unknown) => text(v) && /^[a-z][a-z0-9._-]{2,31}$/.test(v);

function validSession(v: unknown): v is AuthSession {
  return object(v) && v.authenticated === true && text(v.csrf_token) && v.csrf_token.length === 43 && text(v.expires_at)
    && !Number.isNaN(Date.parse(v.expires_at)) && (v.username === undefined || name(v.username))
    && (v.role === undefined || v.role === "admin" || v.role === "customer") && (v.view_as === undefined || (name(v.view_as) && v.role !== "customer"))
    && (v.role !== "customer" || name(v.username))
    && (v.routes === undefined || (Array.isArray(v.routes) && v.routes.length <= 512 && v.routes.every((r) => text(r) && r.length <= 200)));
}
function validSecret(v: unknown): v is SetupSecret {
  return object(v) && text(v.secret) && /^[A-Z2-7]{32}$/.test(v.secret) && text(v.otpauth_uri) && v.otpauth_uri.startsWith("otpauth://totp/") && text(v.expires_at);
}

async function request<T>(path: string, validate: (v: unknown) => v is T, options: { method?: "GET" | "POST"; body?: unknown; csrf?: string } = {}): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(path, {
      method: options.method ?? "GET",
      headers: { Accept: "application/json", ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}), ...(options.csrf ? { "X-CSRF-Token": options.csrf } : {}) },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      credentials: "same-origin", cache: "no-store", signal: controller.signal,
    });
    const raw = await response.text();
    let value: unknown;
    try { value = raw ? JSON.parse(raw) : undefined; } catch { value = undefined; }
    if (!response.ok) {
      const code = object(value) && text(value.error) && /^[a-z_]+$/.test(value.error) ? value.error : "request_failed";
      const detail = object(value) && text(value.detail) && value.detail.length < 300 ? value.detail : "The server did not accept the request. Try again.";
      throw new AuthError(response.status, code, detail);
    }
    if (!validate(value)) throw new AuthError(0, "invalid_response", "The server's answer was not what the panel expected. Reload the page and try again.");
    return value;
  } catch (error) {
    if (error instanceof AuthError) throw error;
    throw new AuthError(0, "connection_failed", "The panel could not reach its server. Check that Sifruno is running, then try again.");
  } finally { clearTimeout(timer); }
}

export const setupStatus = () => request("/api/v1/session/setup", (v): v is { admin_required: boolean } => object(v) && typeof v.admin_required === "boolean");

// Resolves to null when there is no session (HTTP 401), instead of throwing.
export async function currentSession(): Promise<AuthSession | null> {
  try { return await request("/api/v1/session", validSession); }
  catch (error) { if (error instanceof AuthError && error.status === 401) return null; throw error; }
}

export const signInAdmin = (username: string, password: string, totp_code: string) =>
  request("/api/v1/session/login", validSession, { method: "POST", body: { username, password, totp_code } });
export const signInWithKey = (access_key: string) =>
  request("/api/v1/session/login", validSession, { method: "POST", body: { access_key } });
export const signOut = (csrf: string) =>
  request("/api/v1/session/logout", (v): v is { authenticated: false } => object(v) && v.authenticated === false, { method: "POST", body: {}, csrf });
export const beginSetup = (csrf: string, username: string) =>
  request("/api/v1/session/setup/totp", validSecret, { method: "POST", body: { username }, csrf });
export const finishSetup = (csrf: string, username: string, password: string, totp_code: string) =>
  request("/api/v1/session/setup/admin", validSession, { method: "POST", body: { username, password, totp_code }, csrf });

// A customer's setup from the link an admin sent: the link's secret proves
// who it is, so these need no session.
export const beginCustomerSetup = (token: string) =>
  request("/api/v1/session/customer-setup/begin", (v): v is CustomerSetupSecret => validSecret(v) && object(v) && name(v.username), { method: "POST", body: { token } });
export const finishCustomerSetup = (token: string, password: string, totp_code: string) =>
  request("/api/v1/session/customer-setup/finish", validSession, { method: "POST", body: { token, password, totp_code } });

// View as customer: the admin's own session takes the customer's access
// until it goes back.
export const viewAsCustomer = (csrf: string, username: string) =>
  request("/api/v1/session/view-as", validSession, { method: "POST", body: { username }, csrf });
export const endViewAs = (csrf: string) =>
  request("/api/v1/session/view-as/end", validSession, { method: "POST", body: {}, csrf });

// Whether a session reaches only one customer's websites: a customer's own,
// or an admin's while it views as a customer.
export const restricted = (session: AuthSession | null) => Boolean(session && (session.role === "customer" || session.view_as));

// Whether the session may use an API route, named as the server's customer
// table names it. An admin may use all; a restricted session only the routes
// its session lists, and none when the list is missing. The panel hides what
// this refuses; the server still checks every request.
export const allows = (session: AuthSession | null, route: string) => !restricted(session) || Boolean(session?.routes?.includes(route));

// On the server itself the panel is reached through loopback; anywhere else it
// came through the HTTPS listener, where only password sign-in works.
export const onThisServer = () => ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);

// Groups of four are easier to type into an authenticator app.
export const groupedSecret = (secret: string) => secret.replace(/(.{4})(?=.)/g, "$1 ");
