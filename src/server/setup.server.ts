import { AppError } from "@/lib/errors";
import type { FirstRunSetupInput } from "@/lib/validation";
import { supabaseAdmin } from "@/integrations/supabase/client.server";
import { getSetupRateLimit } from "./security-policy.server";
import { getClientIp } from "./request-context.server";
import { enforceRateLimit } from "./rate-limit.server";
import { adminRpc } from "./rpc.server";

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

/** Constant-time comparison of two secrets (compares fixed-length digests). */
export async function secretsMatch(provided: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all([sha256(provided), sha256(expected)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export async function getSetupStatus(): Promise<{ setup_completed: boolean }> {
  return adminRpc<{ setup_completed: boolean }>("get_setup_status");
}

/**
 * First-run setup: creates the first administrator and stores the owner-supplied
 * configuration. Protected by (1) a deployment-held SETUP_TOKEN, (2) rate limiting,
 * (3) a database-level single-winner guard that permanently closes setup.
 * There is no default admin account and no built-in password.
 */
export async function completeFirstRunSetup(input: FirstRunSetupInput): Promise<void> {
  await enforceRateLimit("setup-ip", getClientIp(), getSetupRateLimit());

  const expected = process.env["SETUP_TOKEN"];
  if (!expected || expected.length < 32) {
    console.error(
      "[setup] SETUP_TOKEN is not configured (min 32 chars); first-run setup is disabled",
    );
    throw new AppError("configuration_required");
  }
  if (!(await secretsMatch(input.setupToken, expected))) throw new AppError("forbidden");

  // Cheap early exit; the database function is the real single-winner guard.
  if ((await getSetupStatus()).setup_completed) throw new AppError("state_conflict");

  const { data, error } = await supabaseAdmin.auth.admin.createUser({
    email: input.admin.email,
    password: input.admin.password,
    email_confirm: true,
  });
  if (error || !data.user) {
    console.error("[setup] createUser failed", error?.message);
    // Supabase Auth enforces the project's password policy and email uniqueness.
    const code = (error as { code?: string } | null)?.code;
    throw new AppError(
      code === "weak_password"
        ? "invalid_input"
        : code === "email_exists" || code === "user_already_exists"
          ? "conflict"
          : "internal",
    );
  }
  const adminId = data.user.id;

  try {
    await adminRpc("complete_first_run_setup", {
      p_admin_user_id: adminId,
      p_admin_display_name: input.admin.displayName,
      p_settings: input.settings,
      p_commission_rate_bps: input.commission.rateBps,
      p_commission_rounding: input.commission.rounding,
      p_notification_channels: input.notificationChannels,
    });
  } catch (e) {
    // Compensate: do not leave an orphaned auth user behind a failed/lost setup race.
    const { error: delError } = await supabaseAdmin.auth.admin.deleteUser(adminId);
    if (delError)
      console.error("[setup] failed to remove orphaned auth user", adminId, delError.message);
    throw e;
  }
}
