import type pg from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createTestDb, type TestDb } from "./harness";

// Server-side first-run setup flow (src/server/setup.server.ts) against a REAL
// PostgreSQL database. Only the Supabase Auth admin API is replaced by a minimal fake
// that writes to the test database's auth.users table (no GoTrue server is available
// in this sandbox). All values are TEST FIXTURES.

const h = vi.hoisted(() => ({
  svc: null as unknown as pg.Client,
  su: null as unknown as pg.Client,
  ip: "198.51.100.1",
}));

vi.mock("@/server/rpc.server", () => ({
  adminRpc: async (fn: string, args: Record<string, unknown> = {}) => {
    const keys = Object.keys(args);
    const sql = `select * from public.${fn}(${keys.map((k, i) => `${k}${fn === "complete_first_run_setup" && ["p_settings", "p_notification_channels"].includes(k) ? " => $" + (i + 1) + "::jsonb" : " => $" + (i + 1)}`).join(", ")})`;
    const params = keys.map((k) =>
      typeof args[k] === "object" && args[k] !== null ? JSON.stringify(args[k]) : args[k],
    );
    // Same error translation as the real adminRpc (PostgREST reports the same SQLSTATE).
    const { toAppError } = await import("../../src/lib/errors");
    const r = await h.svc.query(sql, params).catch((e) => {
      throw toAppError(e, `rpc ${fn}`);
    });
    return r.rows[0]?.[fn];
  },
}));
vi.mock("@/integrations/supabase/client.server", () => ({
  supabaseAdmin: {
    auth: {
      admin: {
        createUser: async ({ email }: { email: string }) => {
          try {
            const r = await h.su.query("insert into auth.users (email) values ($1) returning id", [
              email,
            ]);
            return { data: { user: { id: r.rows[0].id } }, error: null };
          } catch {
            return { data: { user: null }, error: { status: 422, message: "exists" } };
          }
        },
        deleteUser: async (id: string) => {
          await h.su.query("delete from auth.users where id = $1", [id]);
          return { error: null };
        },
      },
    },
  },
}));
vi.mock("@tanstack/react-start/server", () => ({ getRequestHeader: () => h.ip }));

import { completeFirstRunSetup } from "../../src/server/setup.server";
import type { FirstRunSetupInput } from "../../src/lib/validation";

const TOKEN = "setup-token-for-tests-".padEnd(40, "x");
const input = (email: string, token = TOKEN): FirstRunSetupInput => ({
  setupToken: token,
  admin: { displayName: "Test Admin", email, password: "a-test-password-1" },
  settings: {
    business_name: "TEST BUSINESS (fixture)",
    timezone: "Africa/Johannesburg",
    currency_code: "ZAR",
    business_day_cutoff: "20:00",
    cart_duration_minutes: 15,
    low_stock_default_threshold: 5,
    availability_check_minutes: 5,
    hide_out_of_stock_enabled: true,
    hide_out_of_stock_after_minutes: 60,
  },
  commission: { rateBps: 1000, rounding: "half_up" },
  notificationChannels: [{ channel: "email", enabled: false }],
});

let db: TestDb;
const count = async (sql: string) => (await db.su.query(sql)).rows[0].n as number;

beforeAll(async () => {
  db = await createTestDb();
  h.su = db.su;
  h.svc = await db.as("service_role");
  vi.stubEnv("RATE_LIMIT_KEY_SECRET", "r".repeat(48));
  vi.stubEnv("CLIENT_IP_HEADER", "x-test-client-ip");
});
beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  h.ip = `198.51.100.${Math.floor(Math.random() * 200) + 1}`;
});
afterAll(async () => {
  vi.unstubAllEnvs();
  await db.close();
});

describe("first-run setup flow (real PostgreSQL)", () => {
  it("is disabled (configuration required) when SETUP_TOKEN is not configured or too short", async () => {
    vi.stubEnv("SETUP_TOKEN", "");
    await expect(completeFirstRunSetup(input("a@example.invalid"))).rejects.toMatchObject({
      code: "configuration_required",
    });
    vi.stubEnv("SETUP_TOKEN", "short");
    await expect(completeFirstRunSetup(input("a@example.invalid", "short"))).rejects.toMatchObject({
      code: "configuration_required",
    });
    expect(await count("select count(*)::int n from auth.users")).toBe(0);
  });

  it("rejects a wrong token without creating any user, profile or setting", async () => {
    vi.stubEnv("SETUP_TOKEN", TOKEN);
    await expect(
      completeFirstRunSetup(input("b@example.invalid", "wrong".padEnd(40, "y"))),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(await count("select count(*)::int n from auth.users")).toBe(0);
    expect(await count("select count(*)::int n from public.profiles")).toBe(0);
    expect(
      await count(
        "select count(*)::int n from public.business_settings where setup_completed_at is not null",
      ),
    ).toBe(0);
  });

  it("rate-limits repeated setup attempts from one address", async () => {
    vi.stubEnv("SETUP_TOKEN", TOKEN);
    h.ip = "203.0.113.77";
    const codes: string[] = [];
    for (let i = 0; i < 12; i++) {
      codes.push(
        await completeFirstRunSetup(input("c@example.invalid", "bad".padEnd(40, String(i)))).then(
          () => "ok",
          (e) => e.code,
        ),
      );
    }
    expect(codes.filter((c) => c === "rate_limited")).toHaveLength(2);
    expect(codes.filter((c) => c === "forbidden")).toHaveLength(10);
  });

  it("an invalid value is rejected by the database and leaves NO orphaned auth user", async () => {
    vi.stubEnv("SETUP_TOKEN", TOKEN);
    const bad = input("d@example.invalid");
    bad.settings.timezone = "Mars/Olympus";
    await expect(completeFirstRunSetup(bad)).rejects.toMatchObject({ code: "invalid_input" });
    expect(await count("select count(*)::int n from auth.users")).toBe(0);
    expect(await count("select count(*)::int n from public.profiles")).toBe(0);
    expect(
      await count(
        "select count(*)::int n from public.business_settings where setup_completed_at is not null",
      ),
    ).toBe(0);
  });

  it("creates the admin, stores the supplied configuration and audits it", async () => {
    vi.stubEnv("SETUP_TOKEN", TOKEN);
    await completeFirstRunSetup(input("owner@example.invalid"));
    const admin = (
      await db.su.query("select p.id, p.kind, p.status from public.profiles p where kind = 'admin'")
    ).rows;
    expect(admin).toHaveLength(1);
    expect(admin[0]).toMatchObject({ kind: "admin", status: "approved" });
    const s = (
      await db.su.query(
        "select business_name, timezone, business_day_cutoff::text cutoff, setup_completed_by from public.business_settings",
      )
    ).rows[0];
    expect(s).toMatchObject({
      business_name: "TEST BUSINESS (fixture)",
      timezone: "Africa/Johannesburg",
      cutoff: "20:00:00",
      setup_completed_by: admin[0].id,
    });
    expect(
      await count("select count(*)::int n from public.audit_logs where action = 'setup.completed'"),
    ).toBe(1);
    const cfg = (
      await db.su.query("select rate_bps, rounding from public.commission_configurations")
    ).rows;
    expect(cfg).toEqual([{ rate_bps: 1000, rounding: "half_up" }]);
  });

  it("cannot be run again, and the failed attempt leaves no orphaned auth user", async () => {
    vi.stubEnv("SETUP_TOKEN", TOKEN);
    const before = await count("select count(*)::int n from auth.users");
    await expect(completeFirstRunSetup(input("second@example.invalid"))).rejects.toMatchObject({
      code: "state_conflict",
    });
    expect(await count("select count(*)::int n from auth.users")).toBe(before);
    expect(await count("select count(*)::int n from public.profiles where kind = 'admin'")).toBe(1);
  });
});

describe("first-run setup race (real PostgreSQL)", () => {
  it("two simultaneous correct submissions produce exactly one administrator and no orphan", async () => {
    const fresh = await createTestDb();
    h.su = fresh.su;
    h.svc = await fresh.as("service_role");
    vi.stubEnv("SETUP_TOKEN", TOKEN);
    const results = await Promise.allSettled([
      completeFirstRunSetup(input("race1@example.invalid")),
      completeFirstRunSetup(input("race2@example.invalid")),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
    expect(rejected.reason.code).toBe("state_conflict");
    const n = async (sql: string) => (await fresh.su.query(sql)).rows[0].n as number;
    expect(await n("select count(*)::int n from public.profiles where kind = 'admin'")).toBe(1);
    expect(await n("select count(*)::int n from auth.users")).toBe(1);
    await fresh.close();
  });
});
