import type pg from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createTestDb, TEST_SETTINGS, type TestDb } from "./harness";

// Values come from the configured (TEST FIXTURE) policy stored in the database.
const POLICY = {
  maxFailedAttempts: TEST_SETTINGS.login_max_failed_attempts,
  perIpLimit: TEST_SETTINGS.rate_limit_login_ip_attempts,
  perCodeLimit: TEST_SETTINGS.rate_limit_login_code_attempts,
};
import { hashSecretCode } from "../../src/lib/security/secret-code";

// End-to-end test of the server-side Client Code + Secret Access Code flow
// (src/server/quick-login.server.ts) against a REAL PostgreSQL database.
//
// Real: the Node flow, Argon2id hashing/verification, every database function,
// lockout counters, rate limiting, account status checks.
// Replaced by a minimal fake: ONLY the Supabase/GoTrue HTTP API (user lookup and
// magic-link -> session exchange), because no GoTrue server exists in this sandbox.
// Session minting is therefore UNVERIFIED by this suite.

const h = vi.hoisted(() => ({
  svc: null as unknown as pg.Client,
  su: null as unknown as pg.Client,
  ip: "198.51.100.7",
}));

vi.mock("@/server/rpc.server", () => ({
  adminRpc: async (fn: string, args: Record<string, unknown> = {}) => {
    const keys = Object.keys(args);
    const sql = `select * from public.${fn}(${keys.map((k, i) => `${k} => $${i + 1}`).join(", ")})`;
    const { toAppError } = await import("../../src/lib/errors");
    const r = await h.svc
      .query(
        sql,
        keys.map((k) => args[k]),
      )
      .catch((e) => {
        throw toAppError(e, `rpc ${fn}`);
      });
    return fn === "get_quick_login_credential" ? r.rows : r.rows[0]?.[fn];
  },
}));
vi.mock("@/integrations/supabase/client.server", () => ({
  supabaseAdmin: {
    auth: {
      admin: {
        getUserById: async (id: string) => {
          const r = await h.su.query("select email from auth.users where id = $1", [id]);
          return { data: { user: { email: r.rows[0]?.email } }, error: null };
        },
        generateLink: async ({ email }: { email: string }) => ({
          data: { properties: { hashed_token: `hash-for:${email}` } },
          error: null,
        }),
      },
    },
  },
}));
vi.mock("@supabase/supabase-js", () => ({
  createClient: () => ({
    auth: {
      verifyOtp: async ({ token_hash }: { token_hash: string }) => ({
        data: {
          session: { access_token: `session:${token_hash}`, refresh_token: "r", expires_in: 3600 },
        },
        error: null,
      }),
    },
  }),
}));
vi.mock("@tanstack/react-start/server", () => ({ getRequestHeader: () => h.ip }));

import { quickLogin } from "../../src/server/quick-login.server";

let db: TestDb;
const SECRET = "a-long-test-secret-1";

async function customer(label: string, opts: { approve?: boolean; email?: boolean } = {}) {
  const id = await db.createProfile("customer", label);
  await db.su.query("update auth.users set email = $2 where id = $1", [
    id,
    opts.email === false ? null : `${label}@example.invalid`,
  ]);
  const svc = h.svc;
  const code = (await svc.query("select public.issue_client_code($1) c", [id])).rows[0].c as string;
  await svc.query("select public.set_access_secret($1, $2)", [id, hashSecretCode(SECRET)]);
  if (opts.approve !== false)
    await db.su.query("update public.profiles set status = 'approved' where id = $1", [id]);
  return { id, code };
}
const attempt = (clientCode: string, secretCode: string) => quickLogin({ clientCode, secretCode });
const generic = { code: "unauthenticated", message: "Authentication failed." };

beforeAll(async () => {
  db = await createTestDb();
  await db.setupAdmin();
  h.su = db.su;
  h.svc = await db.as("service_role");
  vi.stubEnv("RATE_LIMIT_KEY_SECRET", "r".repeat(48));
  vi.stubEnv("CLIENT_IP_HEADER", "x-test-client-ip");
  vi.stubEnv("SUPABASE_URL", "http://fake.invalid");
  vi.stubEnv("SUPABASE_PUBLISHABLE_KEY", "fake-publishable");
});
beforeEach(() => {
  h.ip = `198.51.100.${Math.floor(Math.random() * 200) + 1}`; // fresh per-IP bucket per test
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterAll(async () => {
  vi.unstubAllEnvs();
  await db.close();
});

describe("quick login flow (real PostgreSQL)", () => {
  it("issues a session for the right user with a correct code pair", async () => {
    const { code } = await customer("ok");
    const r = await attempt(code, SECRET);
    expect(r.access_token).toBe("session:hash-for:ok@example.invalid");
    expect(r.refresh_token).toBeTruthy();
  });

  it("a wrong secret, an unknown code, an unapproved account and a code without email fail identically", async () => {
    const good = await customer("generic-good");
    const pending = await customer("generic-pending", { approve: false });
    const noEmail = await customer("generic-noemail", { email: false });
    await expect(attempt(good.code, "wrong-secret-xyz")).rejects.toMatchObject(generic);
    await expect(attempt("ZZZZ-ZZZZ-ZZZZ", SECRET)).rejects.toMatchObject(generic);
    await expect(attempt(pending.code, SECRET)).rejects.toMatchObject(generic); // correct secret, not approved
    await expect(attempt(noEmail.code, SECRET)).rejects.toMatchObject(generic);
  });

  it("rejected, suspended and archived accounts cannot sign in", async () => {
    for (const status of ["rejected", "suspended"] as const) {
      const c = await customer(`st-${status}`);
      await db.su.query("update public.profiles set status = $2 where id = $1", [c.id, status]);
      await expect(attempt(c.code, SECRET)).rejects.toMatchObject(generic);
    }
    const arch = await customer("st-archived");
    await db.su.query("update public.profiles set archived_at = now() where id = $1", [arch.id]);
    await expect(attempt(arch.code, SECRET)).rejects.toMatchObject(generic);
  });

  it("locks after the configured failures: even the CORRECT secret is then refused, without revealing the lock", async () => {
    const c = await customer("lockme");
    for (let i = 0; i < POLICY.maxFailedAttempts; i++)
      await expect(attempt(c.code, `wrong-secret-${i}`)).rejects.toMatchObject(generic);
    const row = (
      await db.su.query(
        "select failed_attempts, locked_until from public.access_credentials where user_id = $1",
        [c.id],
      )
    ).rows[0];
    expect(row.failed_attempts).toBe(POLICY.maxFailedAttempts);
    expect(row.locked_until).not.toBeNull();
    await expect(attempt(c.code, SECRET)).rejects.toMatchObject(generic);
    // an expired lock works again
    await db.su.query(
      "update public.access_credentials set locked_until = now() - interval '1 second' where user_id = $1",
      [c.id],
    );
    await expect(attempt(c.code, SECRET)).resolves.toMatchObject({ refresh_token: "r" });
    const after = (
      await db.su.query(
        "select failed_attempts, locked_until from public.access_credentials where user_id = $1",
        [c.id],
      )
    ).rows[0];
    expect(after).toEqual({ failed_attempts: 0, locked_until: null });
  });

  it("the lockout event is audited and contains no secret material", async () => {
    const c = await customer("auditlock");
    for (let i = 0; i < POLICY.maxFailedAttempts; i++)
      await attempt(c.code, `nope-${i}-xxxxx`).catch(() => {});
    const a = (
      await db.su.query(
        "select * from public.audit_logs where action = 'credential.quick_login_locked' and actor_id = $1",
        [c.id],
      )
    ).rows;
    expect(a).toHaveLength(1);
    expect(JSON.stringify(a[0])).not.toMatch(/argon2|nope-|secret_hash/);
  });

  it("rate-limits per IP regardless of which codes are tried", async () => {
    h.ip = "203.0.113.50";
    let limited = 0;
    for (let i = 0; i < POLICY.perIpLimit + 3; i++) {
      try {
        const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        await attempt(`AAAA-AAAA-AAA${alphabet[i]}`, SECRET);
      } catch (e) {
        if ((e as { code?: string }).code === "rate_limited") limited++;
      }
    }
    expect(limited).toBe(3);
  });

  it("rate-limits per Client Code across different IPs", async () => {
    const c = await customer("codelimit");
    let limited = 0;
    for (let i = 0; i < POLICY.perCodeLimit + 2; i++) {
      h.ip = `192.0.2.${i + 1}`;
      try {
        await attempt(c.code, "definitely-wrong-1");
      } catch (e) {
        if ((e as { code?: string }).code === "rate_limited") limited++;
      }
    }
    expect(limited).toBeGreaterThanOrEqual(2);
  });

  it("does not store raw IPs or Client Codes in rate-limit keys", async () => {
    const keys = (await db.su.query("select key from public.rate_limits")).rows
      .map((r) => r.key as string)
      .join("\n");
    expect(keys).toMatch(/ql-ip:[0-9a-f]{64}/);
    expect(keys).not.toMatch(/198\.51\.100|203\.0\.113|AAAA-AAAA/);
  });
});

describe("quick login fails closed while the owner has not configured the security policy", () => {
  it("refuses with configuration_required, without touching the lockout counter or rate limiter", async () => {
    const fresh = await createTestDb(); // migrated but NEVER configured: policy columns are NULL
    const prevSu = h.su;
    const prevSvc = h.svc;
    h.su = fresh.su;
    h.svc = await fresh.as("service_role");
    try {
      const id = await fresh.createProfile("customer", "unconfigured");
      await fresh.su.query("update auth.users set email = 'u@example.invalid' where id = $1", [id]);
      const code = (await h.svc.query("select public.issue_client_code($1) c", [id])).rows[0]
        .c as string;
      await h.svc.query("select public.set_access_secret($1, $2)", [id, hashSecretCode(SECRET)]);
      await fresh.su.query("update public.profiles set status = 'approved' where id = $1", [id]);
      await expect(attempt(code, SECRET)).rejects.toMatchObject({
        code: "configuration_required",
      });
      await expect(attempt(code, "wrong-secret-xyz")).rejects.toMatchObject({
        code: "configuration_required",
      });
      const row = (
        await fresh.su.query(
          "select failed_attempts from public.access_credentials where user_id = $1",
          [id],
        )
      ).rows[0];
      expect(row.failed_attempts).toBe(0);
      expect((await fresh.su.query("select 1 from public.rate_limits")).rowCount).toBe(0);
    } finally {
      h.su = prevSu;
      h.svc = prevSvc;
      await fresh.close();
    }
  });
});
