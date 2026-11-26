// The browser's side of passkeys: what this browser can do, the server's
// options turned into what navigator.credentials wants, and its answer turned
// back into JSON. The server (go-webauthn) checks every answer; nothing here
// decides who signs in.
//
// parse*OptionsFromJSON() and toJSON() are used where the browser has them
// (Baseline 2025); the small fallbacks below do the same base64url work for
// older browsers, without adding a dependency.

type Json = Record<string, unknown>;

const object = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export function toBase64url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(value: string): ArrayBuffer {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) throw new TypeError("not base64url");
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

const descriptors = (list: unknown) => Array.isArray(list)
  ? list.filter(object).map((d) => ({ ...d, id: fromBase64url(String(d.id)) }))
  : undefined;

// The server's PublicKeyCredentialRequestOptions, ready for get().
export function requestOptions(options: Json): PublicKeyCredentialRequestOptions {
  const parse = (globalThis.PublicKeyCredential as unknown as { parseRequestOptionsFromJSON?: (o: Json) => PublicKeyCredentialRequestOptions } | undefined)?.parseRequestOptionsFromJSON;
  if (parse) return parse(options);
  const allow = descriptors(options.allowCredentials);
  return { ...options, challenge: fromBase64url(String(options.challenge)), ...(allow ? { allowCredentials: allow } : {}) } as unknown as PublicKeyCredentialRequestOptions;
}

// The server's PublicKeyCredentialCreationOptions, ready for create().
export function creationOptions(options: Json): PublicKeyCredentialCreationOptions {
  const parse = (globalThis.PublicKeyCredential as unknown as { parseCreationOptionsFromJSON?: (o: Json) => PublicKeyCredentialCreationOptions } | undefined)?.parseCreationOptionsFromJSON;
  if (parse) return parse(options);
  const user = object(options.user) ? { ...options.user, id: fromBase64url(String(options.user.id)) } : options.user;
  const exclude = descriptors(options.excludeCredentials);
  return { ...options, challenge: fromBase64url(String(options.challenge)), user, ...(exclude ? { excludeCredentials: exclude } : {}) } as unknown as PublicKeyCredentialCreationOptions;
}

type Answer = {
  id: string; rawId: ArrayBuffer; type: string; authenticatorAttachment?: string | null;
  toJSON?: () => Json; getClientExtensionResults?: () => Json;
  response: {
    clientDataJSON: ArrayBuffer; attestationObject?: ArrayBuffer; authenticatorData?: ArrayBuffer;
    signature?: ArrayBuffer; userHandle?: ArrayBuffer | null; getTransports?: () => string[];
  };
};

// The browser's answer as JSON, as PublicKeyCredential.toJSON() gives it.
export function credentialJSON(credential: unknown): Json {
  const c = credential as Answer;
  if (typeof c.toJSON === "function") return c.toJSON();
  const r = c.response;
  const response: Json = { clientDataJSON: toBase64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = toBase64url(r.attestationObject);
    response.transports = typeof r.getTransports === "function" ? r.getTransports() : [];
  } else {
    if (r.authenticatorData) response.authenticatorData = toBase64url(r.authenticatorData);
    if (r.signature) response.signature = toBase64url(r.signature);
    if (r.userHandle) response.userHandle = toBase64url(r.userHandle);
  }
  return {
    id: c.id, rawId: toBase64url(c.rawId), type: c.type, response,
    clientExtensionResults: typeof c.getClientExtensionResults === "function" ? c.getClientExtensionResults() : {},
    ...(c.authenticatorAttachment ? { authenticatorAttachment: c.authenticatorAttachment } : {}),
  };
}

export interface PasskeySupport {
  // The browser can use passkeys at all.
  supported: boolean;
  // It can offer passkeys in the username field's autofill.
  autofill: boolean;
}

// What this browser can do, from getClientCapabilities() where it exists.
// Making a passkey is not gated on its platform authenticator: a security
// key, a phone nearby, or a password manager's extension (which the
// capabilities do not show) can hold one, and the browser's own dialog says
// when nothing can.
export async function passkeySupport(): Promise<PasskeySupport> {
  const pkc = globalThis.PublicKeyCredential as unknown as {
    getClientCapabilities?: () => Promise<Record<string, boolean | undefined>>;
    isConditionalMediationAvailable?: () => Promise<boolean>;
  } | undefined;
  if (!pkc || !globalThis.isSecureContext || !navigator.credentials) return { supported: false, autofill: false };
  try {
    if (pkc.getClientCapabilities) return { supported: true, autofill: (await pkc.getClientCapabilities()).conditionalGet === true };
    return { supported: true, autofill: await (pkc.isConditionalMediationAvailable?.() ?? Promise.resolve(false)) };
  } catch {
    // A browser that cannot answer is treated as one without autofill: the
    // button, and the password and code, still work.
    return { supported: true, autofill: false };
  }
}

// The Signal API keeps the browser's passkey manager in step with the
// panel. It is a courtesy: where a browser lacks it or refuses, nothing
// else depends on it, so its failures are dropped on purpose.
type Signals = {
  signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
  signalAllAcceptedCredentials?: (o: { rpId: string; userId: string; allAcceptedCredentialIds: string[] }) => Promise<void>;
};
const base64urlID = (v: string) => /^[A-Za-z0-9_-]+$/.test(v) && v.length % 4 !== 1;

export async function signalUnknown(rpId: string, credentialId: string) {
  const pkc = globalThis.PublicKeyCredential as unknown as Signals | undefined;
  if (!pkc?.signalUnknownCredential || !rpId || !base64urlID(credentialId)) return;
  try { await pkc.signalUnknownCredential({ rpId, credentialId }); } catch { /* courtesy only, see above */ }
}

export async function signalAccepted(rpId: string | undefined, userId: string | undefined, ids: string[]) {
  const pkc = globalThis.PublicKeyCredential as unknown as Signals | undefined;
  if (!pkc?.signalAllAcceptedCredentials || !rpId || !userId || !base64urlID(userId) || !ids.every(base64urlID)) return;
  try { await pkc.signalAllAcceptedCredentials({ rpId, userId, allAcceptedCredentialIds: ids }); } catch { /* courtesy only, see above */ }
}

// A sentence for a person when the browser's passkey step stopped, or "" when
// they cancelled it themselves and nothing needs saying.
export function passkeyBrowserProblem(error: unknown, adding: boolean): string {
  const name = error instanceof DOMException || error instanceof Error ? error.name : "";
  switch (name) {
    case "NotAllowedError": case "AbortError": return adding ? "Adding the passkey was cancelled, or your device did not confirm it was you. Nothing was added." : "";
    case "InvalidStateError": return "This device or password manager already holds a passkey for your login. Use that one, or add one somewhere else.";
    case "SecurityError": return "The browser refused passkeys here. Open the panel at its name over HTTPS, with no certificate warning, and try again.";
    default: return adding ? "The browser could not make a passkey. Try again, or try another device or password manager." : "The browser could not use a passkey. Sign in with your password and code.";
  }
}
