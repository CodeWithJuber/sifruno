import { useMemo } from "react";
import { encodeQr, qrPath, QrTooLong } from "@/lib/qr";
import type { QrCode } from "@/lib/qr";

// The authenticator app's otpauth:// link as a QR code, drawn here from the
// link alone (lib/qr.ts). The link holds the secret, so nothing is fetched
// or stored for it. Black on white with a four-module quiet zone in both
// themes, as scanners expect. The key and the link stay beside it for an
// app or a person that cannot scan.
export function AuthenticatorQr({ uri, username, testId }: { uri: string; username: string; testId: string }) {
  const code = useMemo((): QrCode | undefined => {
    try { return encodeQr(uri); }
    catch (error) {
      // A link too long for any QR code: the key below still works.
      if (error instanceof QrTooLong) return undefined;
      throw error;
    }
  }, [uri]);
  if (!code) return null;
  const side = code.size + 8;
  return <figure className="m-0 flex shrink-0 flex-col items-center gap-1.5" data-testid={testId} data-version={code.version}>
    <svg role="img" aria-label={`QR code that adds ${username} to an authenticator app`} viewBox={`0 0 ${side} ${side}`} shapeRendering="crispEdges"
      className="size-44 rounded-md border border-border">
      <rect width={side} height={side} fill="#fff" />
      <path d={qrPath(code)} fill="#000" />
    </svg>
    <figcaption className="text-xs text-muted-foreground">Scan it with the app</figcaption>
  </figure>;
}
