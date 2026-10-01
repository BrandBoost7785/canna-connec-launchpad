import { createClient } from "@supabase/supabase-js";
import { AppError } from "@/lib/errors";
import { dummyVerify, verifySecretCode } from "@/lib/security/secret-code";
import type { QuickLoginInput } from "@/lib/validation";
import { AUTH_POLICY } from "./auth-policy";
import { getClientIp } from "./request-context.server";
import { enforceRateLimit } from "./rate-limit.server";
import { adminRpc } from "./rpc.server";
import { supabaseAdmin } from "@/integrations/supabase/client.server";

interface Credential {
  user_id: string;
  secret_hash: string;
  status: "pending_approval" | "approved" | "rejected" | "suspended";
  locked_until: string | null;
}

export interface SessionTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

// Every failure for an existing, unknown, locked, unapproved or wrongly-guessed
// credential is the SAME AppError("unauthenticated"), so the endpoint does not reveal
// whether a Client Code exists or what state its account is in.
const fail = (): never => {
  throw new AppError("unauthenticated");
};

export async function quickLogin(input: QuickLoginInput): Promise<SessionTokens> {
  await enforceRateLimit("ql-ip", getClientIp(), AUTH_POLICY.perIpQuickLogin);
  await enforceRateLimit("ql-code", input.clientCode, AUTH_POLICY.perClientCodeQuickLogin);

  const rows = await adminRpc<Credential[]>("get_quick_login_credential", {
    p_client_code: input.clientCode,
  });
  const cred = rows[0];
  if (!cred) return dummyVerify(input.secretCode) || fail();

  const locked = cred.locked_until !== null && new Date(cred.locked_until).getTime() > Date.now();
  // Always run the hash verification (even when locked) so timing is uniform.
  const matches = verifySecretCode(input.secretCode, cred.secret_hash);
  if (locked) return fail();

  // DECISION PENDING (owner): only approved accounts may sign in.
  const ok = matches && cred.status === "approved";
  await adminRpc("record_quick_login_attempt", {
    p_user_id: cred.user_id,
    p_success: ok,
    p_max_failures: AUTH_POLICY.maxFailedAttempts,
    p_lock_seconds: AUTH_POLICY.lockSeconds,
  });
  if (!ok) return fail();

  return mintSession(cred.user_id);
}

// UNVERIFIED AGAINST A LIVE SUPABASE/GoTrue INSTANCE (none available in the build
// sandbox): issues a magic-link token for the verified user server-side and exchanges
// it for a normal Supabase session. Requires the auth user to have an email address.
// See docs/SECURITY_NOTES.md.
async function mintSession(userId: string): Promise<SessionTokens> {
  const url = process.env["SUPABASE_URL"];
  const anonKey = process.env["SUPABASE_PUBLISHABLE_KEY"];
  if (!url || !anonKey) throw new AppError("configuration_required");

  const { data: user, error: userError } = await supabaseAdmin.auth.admin.getUserById(userId);
  const email = user?.user?.email;
  if (userError || !email) {
    console.error("[quick-login] cannot mint session: user has no email or lookup failed");
    throw new AppError("unauthenticated");
  }
  const { data: link, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
    type: "magiclink",
    email,
  });
  const tokenHash = link?.properties?.hashed_token;
  if (linkError || !tokenHash) {
    console.error("[quick-login] generateLink failed", linkError?.message);
    throw new AppError("internal");
  }
  const anon = createClient(url, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: session, error: otpError } = await anon.auth.verifyOtp({
    type: "magiclink",
    token_hash: tokenHash,
  });
  if (otpError || !session.session) {
    console.error("[quick-login] verifyOtp failed", otpError?.message);
    throw new AppError("internal");
  }
  return {
    access_token: session.session.access_token,
    refresh_token: session.session.refresh_token,
    expires_in: session.session.expires_in,
  };
}
