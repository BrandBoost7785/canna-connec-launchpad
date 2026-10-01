// =============================================================================================
//  REAL SUPABASE VERIFICATION SUITE  -  *** NOT EXECUTED YET ***
//
//  Everything here talks to a real Supabase project over HTTP (PostgREST + GoTrue) and to its
//  Postgres over SUPABASE_DB_URL. It was written in a build sandbox that could not reach any
//  Supabase service, so it has never run. Do not cite it as evidence until it has been run
//  against a DEDICATED, DISPOSABLE test project and its output kept.
//
//  Run:   see docs/REAL_SUPABASE_VERIFICATION.md   (bun run test:supabase)
//
//  REAL here:       Supabase Auth (GoTrue) sessions + JWT signing, PostgREST, the grants and RLS of
//                   the actual project, SECURITY DEFINER functions, the app's server flows
//                   (src/server/*.server.ts) running against the real services.
//  NOT mocked:      anything except `getRequestHeader` (the per-request client IP, which only
//                   exists inside an HTTP request).
//  Test data:       created with the prefix "TEST-" under @example.com addresses, no mail is sent
//                   (email_confirm = true, no invite/magic-link e-mail), removed at the end
//                   where possible. Business settings written by first-run setup remain (the
//                   project is disposable: reset it afterwards).
// =============================================================================================
import { randomBytes } from "node:crypto";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { assertSafeToRun, env } from "./env";
import {
  TABLES,
  catalogDeviations,
  expectedAnonFunctions,
  expectedAuthenticatedFunctions,
  expectedServiceFunctions,
} from "./expectations";

const h = vi.hoisted(() => ({ ip: "198.51.100.1" }));
vi.mock("@tanstack/react-start/server", () => ({ getRequestHeader: () => h.ip }));

assertSafeToRun(); // throws (fails the whole suite loudly) unless explicitly configured

const URL_ = env("SUPABASE_URL");
const PUB = env("SUPABASE_PUBLISHABLE_KEY");
const SVC_KEY = env("SUPABASE_SERVICE_ROLE_KEY");
const noSession = { auth: { persistSession: false, autoRefreshToken: false } };

const rid = randomBytes(4).toString("hex");
const email = (label: string) => `test-${label}-${rid}@example.com`;
const strongPassword = () => `Aa1!${randomBytes(18).toString("base64url")}`;

// Values below are TEST FIXTURES for the owner-configured policy; not defaults, not advice.
const POLICY = {
  login_max_failed_attempts: 3,
  login_lock_seconds: 900,
  rate_limit_login_ip_attempts: 200,
  rate_limit_login_ip_window_seconds: 600,
  rate_limit_login_code_attempts: 100,
  rate_limit_login_code_window_seconds: 900,
  secret_code_min_length: 8,
};
const SETTINGS = {
  business_name: "TEST-business (disposable project)",
  timezone: "Africa/Johannesburg",
  currency_code: "ZAR",
  business_day_cutoff: "20:00",
  cart_duration_minutes: 15,
  low_stock_default_threshold: 5,
  availability_check_minutes: 5,
  hide_out_of_stock_enabled: true,
  hide_out_of_stock_after_minutes: 60,
  ...POLICY,
};

const svc: SupabaseClient = createClient(URL_, SVC_KEY, noSession);
const anon: SupabaseClient = createClient(URL_, PUB, noSession);
let db: pg.Client; // postgres superuser: catalog inspection + fixture approval only
const createdUsers: string[] = [];

async function newAuthUser(label: string) {
  const password = strongPassword();
  const { data, error } = await svc.auth.admin.createUser({
    email: email(label),
    password,
    email_confirm: true,
  });
  if (error || !data.user) throw new Error(`createUser(${label}) failed: ${error?.message}`);
  createdUsers.push(data.user.id);
  return { id: data.user.id, email: email(label), password };
}

async function signIn(u: { email: string; password: string }) {
  const c = createClient(URL_, PUB, noSession);
  const { data, error } = await c.auth.signInWithPassword(u);
  if (error || !data.session) throw new Error(`signIn failed: ${error?.message}`);
  return { client: c as SupabaseClient, token: data.session.access_token, userId: data.user.id };
}

const FORBIDDEN = ["42501"]; // PostgREST surfaces "permission denied" with this SQLSTATE

const ids = {} as Record<string, string>;
const cred = {} as Record<string, { email: string; password: string }>;
let adminSession: Awaited<ReturnType<typeof signIn>>;

beforeAll(async () => {
  db = new pg.Client({ connectionString: env("SUPABASE_DB_URL") });
  await db.connect();
  const { data } = await anon.rpc("get_setup_status");
  if ((data as { setup_completed?: boolean } | null)?.setup_completed !== false) {
    throw new Error(
      "The test project is not a fresh foundation install (setup missing/complete). " +
        "Apply the migrations to a FRESH project (tests/supabase-real/apply-migrations.ts).",
    );
  }
  vi.stubEnv("SUPABASE_URL", URL_);
  vi.stubEnv("SUPABASE_PUBLISHABLE_KEY", PUB);
  vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", SVC_KEY);
  vi.stubEnv("RATE_LIMIT_KEY_SECRET", randomBytes(32).toString("hex"));
  vi.stubEnv("CLIENT_IP_HEADER", "x-test-client-ip");
  vi.stubEnv("SETUP_TOKEN", "setup-" + randomBytes(24).toString("hex"));
  vi.stubEnv("SETUP_RATE_LIMIT_ATTEMPTS", "20"); // TEST FIXTURE
  vi.stubEnv("SETUP_RATE_LIMIT_WINDOW_SECONDS", "3600"); // TEST FIXTURE
});

afterAll(async () => {
  for (const id of createdUsers) await svc.auth.admin.deleteUser(id).catch(() => {});
  await db?.end().catch(() => {});
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------------------------
describe("A. catalog of the REAL project: RLS, grants, SECURITY DEFINER hygiene", () => {
  it("every public table has RLS enabled and the set of tables is exactly the foundation set", async () => {
    const d = await catalogDeviations((sql, params) => db.query(sql, params));
    expect(d.tables).toEqual([...TABLES].sort());
    expect(d.tablesWithoutRls).toEqual([]);
  });

  it("anon holds NO privilege on any table; authenticated holds only SELECT on the allow-listed tables", async () => {
    const d = await catalogDeviations((sql, params) => db.query(sql, params));
    expect(d.tablePrivilegeDeviations).toEqual([]);
  });

  it("EXECUTE grants on every public/app function match the intended matrix exactly", async () => {
    const d = await catalogDeviations((sql, params) => db.query(sql, params));
    expect(d.anonFunctions).toEqual(expectedAnonFunctions());
    expect(d.authenticatedFunctions).toEqual(expectedAuthenticatedFunctions());
    expect(d.serviceFunctions).toEqual(expectedServiceFunctions());
  });

  it("every SECURITY DEFINER function pins an empty search_path and is not owned by an API role", async () => {
    const d = await catalogDeviations((sql, params) => db.query(sql, params));
    expect(d.definerCount).toBeGreaterThan(20);
    expect(d.definersWithoutPinnedSearchPath).toEqual([]);
  });

  it("the private `app` schema is not exposed through the API", async () => {
    const { error } = await anon
      .schema("app" as "public")
      .rpc("current_user_has", { p_permission_key: "x" });
    expect(error).not.toBeNull();
    expect(error?.code).toBe("PGRST106");
  });

  it("the foundation permission catalogue is the proposed set, and only the admin role exists", async () => {
    expect((await db.query("select count(*)::int n from public.permissions")).rows[0].n).toBe(26);
    const roles = await db.query("select key from public.roles where archived_at is null");
    expect(roles.rows.map((x) => x.key)).toEqual(["admin"]);
  });
});

// ---------------------------------------------------------------------------------------------
describe("B. anonymous access through the real API", () => {
  it.each(TABLES)("anon cannot SELECT public.%s", async (t) => {
    const { data, error } = await anon.from(t).select("*").limit(1);
    expect(data).toBeNull();
    expect(FORBIDDEN).toContain(error?.code);
  });

  it.each(["profiles", "audit_logs", "roles"])(
    "anon cannot INSERT / UPDATE / DELETE public.%s",
    async (t) => {
      const ins = await anon.from(t).insert({});
      const upd = await anon.from(t).update({}).not("id", "is", null);
      const del = await anon.from(t).delete().not("id", "is", null);
      for (const r of [ins, upd, del]) expect(FORBIDDEN).toContain(r.error?.code);
    },
  );

  it("anon may call only the two public read functions", async () => {
    expect((await anon.rpc("get_setup_status")).error).toBeNull();
    expect((await anon.rpc("get_public_branding")).error).toBeNull();
  });

  it.each([
    ["admin_update_business_settings", { p_patch: { business_name: "x" } }],
    ["admin_create_role", { p_key: "evil", p_name: "evil" }],
    [
      "admin_assign_role",
      { p_user_id: "00000000-0000-0000-0000-000000000000", p_role_key: "admin" },
    ],
    ["my_access", {}],
    ["get_security_policy", {}],
    ["get_quick_login_credential", { p_client_code: "AAAA-AAAA-AAAA" }],
    ["rate_limit_hit", { p_key: "k", p_limit: 1, p_window_seconds: 1 }],
    [
      "create_profile",
      {
        p_user_id: "00000000-0000-0000-0000-000000000000",
        p_kind: "employee",
        p_display_name: "x",
      },
    ],
  ])("anon is denied %s", async (fn, args) => {
    const { error } = await anon.rpc(fn, args as Record<string, unknown>);
    expect(FORBIDDEN).toContain(error?.code);
  });

  it("the publishable key alone cannot call service-only functions even when sent as a Bearer token", async () => {
    const r = await fetch(`${URL_}/rest/v1/rpc/get_security_policy`, {
      method: "POST",
      headers: { apikey: PUB, authorization: `Bearer ${PUB}`, "content-type": "application/json" },
      body: "{}",
    });
    expect([401, 403]).toContain(r.status);
  });
});

// ---------------------------------------------------------------------------------------------
describe("C. first-run setup through the app's real server flow (real Auth admin API)", () => {
  it("creates the first administrator and stores the configuration", async () => {
    const { completeFirstRunSetup } = await import("../../src/server/setup.server");
    const admin = { displayName: "TEST Admin", email: email("admin"), password: strongPassword() };
    cred["admin"] = { email: admin.email, password: admin.password };
    await completeFirstRunSetup({
      setupToken: process.env["SETUP_TOKEN"]!,
      admin,
      settings: SETTINGS,
      commission: { rateBps: 1000, rounding: "half_up" },
      notificationChannels: [{ channel: "email", enabled: false }],
    } as never);
    const { data } = await anon.rpc("get_setup_status");
    expect(data).toMatchObject({ setup_completed: true });
    const p = await db.query("select id, kind, status from public.profiles");
    expect(p.rows).toHaveLength(1);
    expect(p.rows[0]).toMatchObject({ kind: "admin", status: "approved" });
    ids["admin"] = p.rows[0].id as string;
    createdUsers.push(ids["admin"]);
  });

  it("a second setup attempt is refused (state conflict) and creates no user", async () => {
    const { completeFirstRunSetup } = await import("../../src/server/setup.server");
    const before = (await svc.auth.admin.listUsers()).data.users.length;
    await expect(
      completeFirstRunSetup({
        setupToken: process.env["SETUP_TOKEN"]!,
        admin: { displayName: "x", email: email("second"), password: strongPassword() },
        settings: SETTINGS,
        commission: { rateBps: 1000, rounding: "half_up" },
        notificationChannels: [],
      } as never),
    ).rejects.toMatchObject({ code: "state_conflict" });
    expect((await svc.auth.admin.listUsers()).data.users.length).toBe(before);
  });

  it("a wrong setup token is refused", async () => {
    const { completeFirstRunSetup } = await import("../../src/server/setup.server");
    await expect(
      completeFirstRunSetup({
        setupToken: "wrong-" + randomBytes(24).toString("hex"),
        admin: { displayName: "x", email: email("badtoken"), password: strongPassword() },
        settings: SETTINGS,
        commission: { rateBps: 1000, rounding: "half_up" },
        notificationChannels: [],
      } as never),
    ).rejects.toMatchObject({ code: "forbidden" });
  });
});

// ---------------------------------------------------------------------------------------------
describe("D. real Supabase Auth sessions: identity comes from the verified JWT", () => {
  it("valid email/password sign-in yields a real session whose sub is the user", async () => {
    adminSession = await signIn(cred["admin"]!);
    const { data, error } = await adminSession.client.auth.getUser();
    expect(error).toBeNull();
    expect(data.user?.id).toBe(ids["admin"]);
    const payload = JSON.parse(
      Buffer.from(adminSession.token.split(".")[1]!, "base64url").toString(),
    );
    expect(payload.sub).toBe(ids["admin"]);
    expect(payload.role).toBe("authenticated");
  });

  it("invalid credentials are rejected by real Auth", async () => {
    const c = createClient(URL_, PUB, noSession);
    const { data, error } = await c.auth.signInWithPassword({
      email: cred["admin"]!.email,
      password: strongPassword(),
    });
    expect(data.session).toBeNull();
    expect(error).not.toBeNull();
  });

  it("the DB authorization layer resolves the caller from the session (my_access)", async () => {
    const { data, error } = await adminSession.client.rpc("my_access");
    expect(error).toBeNull();
    expect(data).toMatchObject({ has_profile: true, kind: "admin", status: "approved" });
    expect((data as { permissions: string[] }).permissions).toHaveLength(26);
    expect((data as { roles: string[] }).roles).toEqual(["admin"]);
  });

  it("a client cannot claim another identity: tampered / forged / unsigned tokens are rejected", async () => {
    const [h64, p64, sig] = adminSession.token.split(".") as [string, string, string];
    const claims = JSON.parse(Buffer.from(p64, "base64url").toString());
    const call = (token: string) =>
      fetch(`${URL_}/rest/v1/rpc/my_access`, {
        method: "POST",
        headers: {
          apikey: PUB,
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: "{}",
      });
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    // 1. same signature, altered subject
    const tampered = `${h64}.${b64({ ...claims, sub: "00000000-0000-0000-0000-000000000001" })}.${sig}`;
    // 2. claims service_role, signed with a random secret
    const forged = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ ...claims, role: "service_role" })}.${randomBytes(32).toString("base64url")}`;
    // 3. alg none
    const none = `${b64({ alg: "none", typ: "JWT" })}.${b64({ ...claims, role: "service_role" })}.`;
    for (const t of [tampered, forged, none]) expect((await call(t)).status).toBe(401);
  });

  it("user-editable metadata cannot grant privileges", async () => {
    const u = await newAuthUser("meta");
    await svc.rpc("create_profile", {
      p_user_id: u.id,
      p_kind: "customer",
      p_display_name: "TEST meta",
    });
    const s = await signIn(u);
    await s.client.auth.updateUser({
      data: { role: "admin", kind: "admin", permissions: ["settings.manage"] },
    });
    const again = await signIn(u); // fresh token carrying the edited user_metadata
    const { data } = await again.client.rpc("my_access");
    expect(data).toMatchObject({ kind: "customer", permissions: [] });
    const settings = await again.client.from("business_settings").select("*");
    expect(settings.data).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------
describe("E. customer isolation, employee boundaries, escalation attempts (real sessions)", () => {
  let custA: Awaited<ReturnType<typeof signIn>>;
  let custB: Awaited<ReturnType<typeof signIn>>;
  let emp: Awaited<ReturnType<typeof signIn>>;
  let viewer: Awaited<ReturnType<typeof signIn>>;
  const zero = "00000000-0000-0000-0000-000000000000";

  beforeAll(async () => {
    for (const label of ["custa", "custb"]) {
      const u = await newAuthUser(label);
      ids[label] = u.id;
      cred[label] = u;
      expect(
        (
          await svc.rpc("create_profile", {
            p_user_id: u.id,
            p_kind: "customer",
            p_display_name: `TEST ${label}`,
          })
        ).error,
      ).toBeNull();
      expect((await svc.rpc("issue_client_code", { p_user_id: u.id })).error).toBeNull();
    }
    for (const label of ["emp", "viewer"]) {
      const u = await newAuthUser(label);
      ids[label] = u.id;
      cred[label] = u;
      expect(
        (
          await svc.rpc("create_profile", {
            p_user_id: u.id,
            p_kind: "employee",
            p_display_name: `TEST ${label}`,
          })
        ).error,
      ).toBeNull();
    }
    // Admin builds a least-privilege role through the real RBAC functions.
    expect(
      (
        await adminSession.client.rpc("admin_create_role", {
          p_key: "test_viewer",
          p_name: "TEST viewer",
        })
      ).error,
    ).toBeNull();
    expect(
      (
        await adminSession.client.rpc("admin_grant_permission", {
          p_role_key: "test_viewer",
          p_permission_key: "customers.view",
        })
      ).error,
    ).toBeNull();
    expect(
      (
        await adminSession.client.rpc("admin_assign_role", {
          p_user_id: ids["viewer"],
          p_role_key: "test_viewer",
        })
      ).error,
    ).toBeNull();
    // customers need approval (no foundation API for it yet): fixture update as DB owner.
    await db.query("update public.profiles set status = 'approved' where id = any($1)", [
      [ids["custa"], ids["custb"]],
    ]);
    custA = await signIn(cred["custa"]!);
    custB = await signIn(cred["custb"]!);
    emp = await signIn(cred["emp"]!);
    viewer = await signIn(cred["viewer"]!);
  });

  it("customer sees only their own profile and client code", async () => {
    const p = await custA.client.from("profiles").select("id");
    expect(p.error).toBeNull();
    expect(p.data).toEqual([{ id: ids["custa"] }]);
    const c = await custA.client.from("client_codes").select("user_id");
    expect(c.data).toEqual([{ user_id: ids["custa"] }]);
    const other = await custA.client.from("profiles").select("id").eq("id", ids["custb"]);
    expect(other.data).toEqual([]);
  });

  it("customer sees nothing in admin/config/audit tables and is denied credential tables", async () => {
    for (const t of [
      "business_settings",
      "audit_logs",
      "user_roles",
      "roles",
      "permissions",
      "role_permissions",
      "commission_configurations",
    ]) {
      const r = await custA.client.from(t).select("*");
      expect(r.error, t).toBeNull();
      expect(r.data, t).toEqual([]);
    }
    for (const t of ["access_credentials", "rate_limits"]) {
      expect(FORBIDDEN).toContain((await custA.client.from(t).select("*")).error?.code);
    }
  });

  it("customer cannot write: no direct DML on any table, no admin RPC", async () => {
    expect(FORBIDDEN).toContain(
      (
        await custA.client
          .from("profiles")
          .update({ status: "approved", display_name: "x" })
          .eq("id", ids["custa"])
      ).error?.code,
    );
    expect(FORBIDDEN).toContain(
      (await custA.client.from("profiles").update({ display_name: "x" }).eq("id", ids["custb"]))
        .error?.code,
    );
    expect(FORBIDDEN).toContain(
      (await custA.client.from("user_roles").insert({ user_id: ids["custa"] })).error?.code,
    );
    expect(FORBIDDEN).toContain(
      (
        await custA.client
          .from("client_codes")
          .update({ revoked_at: new Date().toISOString() })
          .eq("user_id", ids["custa"])
      ).error?.code,
    );
    for (const [fn, args] of [
      ["admin_update_business_settings", { p_patch: { business_name: "pwned" } }],
      ["admin_assign_role", { p_user_id: ids["custa"], p_role_key: "admin" }],
      ["admin_create_role", { p_key: "x", p_name: "x" }],
    ] as const) {
      expect(FORBIDDEN).toContain((await custA.client.rpc(fn, args)).error?.code);
    }
  });

  it("customer cannot reach service-only functions", async () => {
    for (const [fn, args] of [
      ["get_quick_login_credential", { p_client_code: "AAAA-AAAA-AAAA" }],
      ["set_access_secret", { p_user_id: ids["custa"], p_secret_hash: "x" }],
      ["issue_client_code", { p_user_id: ids["custa"] }],
      ["create_profile", { p_user_id: ids["custa"], p_kind: "employee", p_display_name: "x" }],
      ["rate_limit_hit", { p_key: "k", p_limit: 1, p_window_seconds: 1 }],
      ["get_security_policy", {}],
    ] as const) {
      expect(FORBIDDEN).toContain((await custA.client.rpc(fn, args)).error?.code);
    }
  });

  it("an employee with no role has no permissions and cannot escalate", async () => {
    const me = (await emp.client.rpc("my_access")).data as {
      permissions: string[];
      roles: string[];
    };
    expect(me.permissions).toEqual([]);
    expect(me.roles).toEqual([]);
    for (const [fn, args] of [
      ["admin_assign_role", { p_user_id: ids["emp"], p_role_key: "admin" }],
      ["admin_grant_permission", { p_role_key: "admin", p_permission_key: "settings.manage" }],
      ["admin_create_role", { p_key: "mine", p_name: "mine" }],
      ["admin_update_business_settings", { p_patch: { business_name: "pwned" } }],
    ] as const) {
      expect(FORBIDDEN, fn).toContain((await emp.client.rpc(fn, args)).error?.code);
    }
    expect(FORBIDDEN).toContain(
      (await emp.client.from("user_roles").insert({ user_id: ids["emp"] })).error?.code,
    );
    expect(FORBIDDEN).toContain((await emp.client.from("role_permissions").insert({})).error?.code);
    expect(FORBIDDEN).toContain(
      (await emp.client.from("profiles").update({ kind: "admin" }).eq("id", ids["emp"])).error
        ?.code,
    );
    expect((await emp.client.from("user_roles").select("*")).data).toEqual([]);
    expect((await emp.client.from("audit_logs").select("*")).data).toEqual([]);
    const profiles = await emp.client.from("profiles").select("id");
    expect(profiles.data).toEqual([{ id: ids["emp"] }]);
  });

  it("a least-privilege role (customers.view) widens exactly that read and nothing else", async () => {
    const me = (await viewer.client.rpc("my_access")).data as { permissions: string[] };
    expect(me.permissions).toEqual(["customers.view"]);
    const profiles = await viewer.client.from("profiles").select("id, kind");
    expect(profiles.error).toBeNull();
    const kinds = new Set((profiles.data ?? []).map((p) => p.kind));
    expect(kinds.has("admin")).toBe(false); // sees customers (+ self), never the administrator
    expect((profiles.data ?? []).map((p) => p.id)).toEqual(
      expect.arrayContaining([ids["custa"], ids["custb"], ids["viewer"]]),
    );
    expect((await viewer.client.from("business_settings").select("*")).data).toEqual([]);
    expect((await viewer.client.from("audit_logs").select("*")).data).toEqual([]);
    expect(FORBIDDEN).toContain(
      (
        await viewer.client.rpc("admin_update_business_settings", {
          p_patch: { business_name: "x" },
        })
      ).error?.code,
    );
    expect(FORBIDDEN).toContain(
      (await viewer.client.from("profiles").update({ display_name: "x" }).eq("id", ids["custa"]))
        .error?.code,
    );
  });

  it("settings permissions are admin-only: they cannot even be granted to another role", async () => {
    const r = await adminSession.client.rpc("admin_grant_permission", {
      p_role_key: "test_viewer",
      p_permission_key: "settings.manage",
    });
    expect(FORBIDDEN).toContain(r.error?.code);
  });

  it("an unapproved/unknown permission key is denied (secure deny)", async () => {
    const r = await adminSession.client.rpc("admin_grant_permission", {
      p_role_key: "test_viewer",
      p_permission_key: "made.up_permission",
    });
    expect(r.error?.code).toBe("P0002");
  });

  it("customer B cannot be impersonated by a customer-A session even with a crafted filter", async () => {
    const r = await custA.client
      .from("profiles")
      .select("id")
      .or(`id.eq.${ids["custb"]},id.eq.${zero}`);
    expect(r.data).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------
describe("F. admin-only operations and audit-log access (real sessions)", () => {
  it("the administrator can change settings through the permitted RPC, and it is audited with their identity", async () => {
    const r = await adminSession.client.rpc("admin_update_business_settings", {
      p_patch: { business_name: "TEST-business renamed" },
    });
    expect(r.error).toBeNull();
    const row = await adminSession.client
      .from("business_settings")
      .select("business_name")
      .single();
    expect(row.data?.business_name).toBe("TEST-business renamed");
    const audit = await adminSession.client
      .from("audit_logs")
      .select("actor_id, actor_source, target_table")
      .eq("target_table", "business_settings")
      .eq("actor_id", ids["admin"]);
    expect(audit.error).toBeNull();
    expect((audit.data ?? []).length).toBeGreaterThan(0);
    expect(audit.data![0]).toMatchObject({ actor_source: "user" });
  });

  it("even the administrator has no direct DML grants, cannot edit/delete the audit log, cannot read credentials", async () => {
    expect(FORBIDDEN).toContain(
      (
        await adminSession.client
          .from("business_settings")
          .update({ business_name: "x" })
          .eq("singleton", true)
      ).error?.code,
    );
    expect(FORBIDDEN).toContain(
      (
        await adminSession.client
          .from("audit_logs")
          .update({ action: "tampered" })
          .not("id", "is", null)
      ).error?.code,
    );
    expect(FORBIDDEN).toContain(
      (await adminSession.client.from("audit_logs").delete().not("id", "is", null)).error?.code,
    );
    expect(FORBIDDEN).toContain(
      (
        await adminSession.client
          .from("audit_logs")
          .insert({ actor_source: "user", action: "forged.event" })
      ).error?.code,
    );
    expect(FORBIDDEN).toContain(
      (await adminSession.client.from("access_credentials").select("*")).error?.code,
    );
    expect(FORBIDDEN).toContain(
      (
        await adminSession.client.rpc("create_profile", {
          p_user_id: ids["admin"],
          p_kind: "admin",
          p_display_name: "x",
        })
      ).error?.code,
    );
  });

  it("the audit log cannot be altered even with the service role", async () => {
    const u = await svc.from("audit_logs").update({ action: "tampered" }).not("id", "is", null);
    expect(u.error).not.toBeNull();
    const d = await svc.from("audit_logs").delete().not("id", "is", null);
    expect(d.error).not.toBeNull();
  });

  it("the last active administrator cannot be deactivated", async () => {
    const r = await db
      .query("update public.profiles set status = 'suspended' where id = $1", [ids["admin"]])
      .then(
        () => null,
        (e) => e.code,
      );
    expect(r).toBe("55000");
  });
});

// ---------------------------------------------------------------------------------------------
describe("G. Client Code + Secret Access Code: the app's real server flow against real Auth", () => {
  const SECRET = "A-long-test-secret-" + randomBytes(6).toString("hex");
  let code: string;
  let userId: string;
  const generic = { code: "unauthenticated", message: "Authentication failed." };

  beforeAll(async () => {
    const { hashSecretCode } = await import("../../src/lib/security/secret-code");
    const u = await newAuthUser("ql");
    userId = u.id;
    await svc.rpc("create_profile", {
      p_user_id: u.id,
      p_kind: "customer",
      p_display_name: "TEST ql",
    });
    code = (await svc.rpc("issue_client_code", { p_user_id: u.id })).data as string;
    await svc.rpc("set_access_secret", { p_user_id: u.id, p_secret_hash: hashSecretCode(SECRET) });
    await db.query("update public.profiles set status = 'approved' where id = $1", [u.id]);
  });

  it("a valid pair mints a REAL Supabase session for exactly that user", async () => {
    const { quickLogin } = await import("../../src/server/quick-login.server");
    const s = await quickLogin({ clientCode: code, secretCode: SECRET });
    expect(s.access_token.split(".")).toHaveLength(3);
    expect(s.refresh_token).toBeTruthy();
    // The session is accepted by real Auth and carries the right identity ...
    const c = createClient(URL_, PUB, noSession);
    const { data: set, error } = await c.auth.setSession({
      access_token: s.access_token,
      refresh_token: s.refresh_token,
    });
    expect(error).toBeNull();
    expect(set.user?.id).toBe(userId);
    // ... and the database authorization layer sees that same identity.
    const me = await c.rpc("my_access");
    expect(me.data).toMatchObject({ has_profile: true, kind: "customer", permissions: [] });
    const own = await c.from("profiles").select("id");
    expect(own.data).toEqual([{ id: userId }]);
  });

  it("wrong secret, unknown code and the generic error behaviour are intact", async () => {
    const { quickLogin } = await import("../../src/server/quick-login.server");
    await expect(
      quickLogin({ clientCode: code, secretCode: "definitely-wrong-secret" }),
    ).rejects.toMatchObject(generic);
    await expect(
      quickLogin({ clientCode: "ZZZZ-ZZZZ-ZZZZ", secretCode: SECRET }),
    ).rejects.toMatchObject(generic);
  });

  it("repeated failures lock the account at the OWNER-CONFIGURED threshold, and the lock is generic", async () => {
    const { quickLogin } = await import("../../src/server/quick-login.server");
    for (let i = 0; i < POLICY.login_max_failed_attempts; i++) {
      await expect(
        quickLogin({ clientCode: code, secretCode: "wrong-secret-" + i }),
      ).rejects.toMatchObject(generic);
    }
    const row = await db.query(
      "select failed_attempts, locked_until from public.access_credentials where user_id = $1",
      [userId],
    );
    expect(row.rows[0].locked_until).not.toBeNull();
    // Locked: even the CORRECT secret is refused, with the same generic error.
    await expect(quickLogin({ clientCode: code, secretCode: SECRET })).rejects.toMatchObject(
      generic,
    );
  });

  it("an unapproved account with the correct pair is refused identically", async () => {
    const { quickLogin } = await import("../../src/server/quick-login.server");
    const { hashSecretCode } = await import("../../src/lib/security/secret-code");
    const u = await newAuthUser("pending");
    await svc.rpc("create_profile", {
      p_user_id: u.id,
      p_kind: "customer",
      p_display_name: "TEST pending",
    });
    const c = (await svc.rpc("issue_client_code", { p_user_id: u.id })).data as string;
    await svc.rpc("set_access_secret", { p_user_id: u.id, p_secret_hash: hashSecretCode(SECRET) });
    await expect(quickLogin({ clientCode: c, secretCode: SECRET })).rejects.toMatchObject(generic);
  });
});
