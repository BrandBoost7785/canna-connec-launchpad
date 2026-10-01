// Security response headers. Pure functions so they are unit-tested without a server.

export interface SecurityHeaderOptions {
  /** Production adds HSTS and the enforcing CSP; development relaxes both for HMR. */
  production: boolean;
  /** Origin of the Supabase project (allowed in connect-src / img-src). Optional. */
  supabaseUrl?: string | undefined;
  /**
   * Who may embed this site in a frame. Default is 'none'. Set CSP_FRAME_ANCESTORS
   * (space-separated origins) only if embedding is intentionally required.
   */
  frameAncestors?: string | undefined;
}

const SAFE_SOURCE = /^(?:'self'|'none'|https?:\/\/[A-Za-z0-9*.-]+(?::\d{1,5})?)$/;

export function sanitizeFrameAncestors(raw: string | undefined): string {
  if (!raw) return "'none'";
  const parts = raw.split(/\s+/).filter(Boolean);
  if (parts.length === 0 || !parts.every((p) => SAFE_SOURCE.test(p))) return "'none'";
  return parts.join(" ");
}

function origin(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

export function buildCsp(opts: SecurityHeaderOptions): string {
  const supabase = origin(opts.supabaseUrl);
  const connect = ["'self'", ...(supabase ? [supabase, supabase.replace(/^http/, "ws")] : [])];
  const directives = [
    "default-src 'self'",
    // LIMITATION: TanStack Start injects inline bootstrap scripts, so 'unsafe-inline'
    // is required until nonce support is wired in. Documented in SECURITY_NOTES.md.
    "script-src 'self' 'unsafe-inline'",
    // The existing root layout loads Google Fonts (src/routes/__root.tsx); allow exactly those hosts.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    `img-src 'self' data: blob:${supabase ? ` ${supabase}` : ""}`,
    "font-src 'self' data: https://fonts.gstatic.com",
    `connect-src ${connect.join(" ")}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    `frame-ancestors ${sanitizeFrameAncestors(opts.frameAncestors)}`,
  ];
  return directives.join("; ");
}

export function buildSecurityHeaders(opts: SecurityHeaderOptions): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
  };
  if (opts.production) {
    headers["Content-Security-Policy"] = buildCsp(opts);
    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
  }
  return headers;
}

/** Returns a response with security headers applied (existing values are not overridden). */
export function withSecurityHeaders(
  response: Response,
  opts: SecurityHeaderOptions,
  noStore = false,
): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(buildSecurityHeaders(opts))) {
    if (!headers.has(k)) headers.set(k, v);
  }
  if (noStore && !headers.has("Cache-Control")) headers.set("Cache-Control", "no-store");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
