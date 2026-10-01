import { z } from "zod";
import { AppError } from "@/lib/errors";
import { adminRpc } from "./rpc.server";

// The authentication throttling / lockout / secret-length policy is OWNER-CONFIGURED
// (business_settings, changed only with `security_settings.manage`) and required to
// complete first-run setup. The code contains no default values: if the database
// reports the policy as unconfigured, the dependent feature fails closed.

const positiveInt = z.number().int().positive();

export const securityPolicySchema = z.object({
  login_max_failed_attempts: positiveInt,
  login_lock_seconds: positiveInt,
  rate_limit_login_ip_attempts: positiveInt,
  rate_limit_login_ip_window_seconds: positiveInt,
  rate_limit_login_code_attempts: positiveInt,
  rate_limit_login_code_window_seconds: positiveInt,
  secret_code_min_length: positiveInt,
});
export type SecurityPolicy = z.infer<typeof securityPolicySchema>;

export async function getSecurityPolicy(): Promise<SecurityPolicy> {
  const raw = await adminRpc<unknown>("get_security_policy"); // P0001 -> configuration_required
  const parsed = securityPolicySchema.safeParse(raw);
  if (!parsed.success) {
    console.error("[security-policy] database returned an invalid policy", parsed.error.issues);
    throw new AppError("configuration_required");
  }
  return parsed.data;
}

/**
 * Deployment-level throttle for the one endpoint that exists BEFORE any owner
 * configuration can exist (first-run setup). Supplied by whoever deploys the
 * installation through the environment; setup is disabled until both are set.
 */
export function getSetupRateLimit(): { limit: number; windowSeconds: number } {
  const limit = Number(process.env["SETUP_RATE_LIMIT_ATTEMPTS"]);
  const windowSeconds = Number(process.env["SETUP_RATE_LIMIT_WINDOW_SECONDS"]);
  const ok = (n: number, max: number) => Number.isInteger(n) && n >= 1 && n <= max;
  if (!ok(limit, 100000) || !ok(windowSeconds, 86400)) {
    console.error(
      "[setup] SETUP_RATE_LIMIT_ATTEMPTS / SETUP_RATE_LIMIT_WINDOW_SECONDS are not configured; first-run setup is disabled",
    );
    throw new AppError("configuration_required");
  }
  return { limit, windowSeconds };
}
