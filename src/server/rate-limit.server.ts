import { AppError } from "@/lib/errors";
import { adminRpc } from "./rpc.server";

// Database-backed fixed-window rate limiting (shared across all server instances).
// Keys are HMAC-SHA256(RATE_LIMIT_KEY_SECRET, scope:subject) so raw IPs, Client Codes
// and identifiers are never stored. FAILS CLOSED: if the limiter is misconfigured or
// unavailable the request is refused rather than allowed.

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retry_after_seconds: number;
}

const enc = new TextEncoder();

export async function rateLimitKey(
  scope: string,
  subject: string,
  secret: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(`${scope}:${subject}`)),
  );
  let hex = "";
  for (const b of sig) hex += b.toString(16).padStart(2, "0");
  return `${scope}:${hex}`;
}

export async function enforceRateLimit(
  scope: string,
  subject: string,
  policy: { limit: number; windowSeconds: number },
): Promise<void> {
  const secret = process.env["RATE_LIMIT_KEY_SECRET"];
  if (!secret || secret.length < 32) {
    console.error(
      "[rate-limit] RATE_LIMIT_KEY_SECRET is missing or shorter than 32 characters; refusing request",
    );
    throw new AppError("configuration_required");
  }
  let result: RateLimitResult;
  try {
    result = await adminRpc<RateLimitResult>("rate_limit_hit", {
      p_key: await rateLimitKey(scope, subject, secret),
      p_limit: policy.limit,
      p_window_seconds: policy.windowSeconds,
    });
  } catch (error) {
    console.error("[rate-limit] limiter unavailable; refusing request", error);
    throw new AppError("internal");
  }
  if (!result.allowed) throw new AppError("rate_limited", result.retry_after_seconds);
}
