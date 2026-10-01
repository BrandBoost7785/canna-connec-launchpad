import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, sqlState, TEST_SETTINGS, type TestDb } from "./harness";

// Owner-configurable security policy (migration 10) and the permission catalogue's
// secure-deny behaviour. Values below are TEST FIXTURES, not recommendations.

const POLICY_KEYS = [
  "login_max_failed_attempts",
  "login_lock_seconds",
  "rate_limit_login_ip_attempts",
  "rate_limit_login_ip_window_seconds",
  "rate_limit_login_code_attempts",
  "rate_limit_login_code_window_seconds",
  "secret_code_min_length",
] as const;

let db: TestDb;
let fresh: TestDb; // never configured
let adminId: string;

beforeAll(async () => {
  db = await createTestDb();
  adminId = await db.setupAdmin();
  fresh = await createTestDb();
});
afterAll(async () => {
  await db.close();
  await fresh.close();
});

describe("no security policy value is seeded", () => {
  it("every policy column is NULL on a freshly migrated database", async () => {
    const r = await fresh.su.query(
      `select ${POLICY_KEYS.join(", ")} from public.business_settings`,
    );
    for (const k of POLICY_KEYS) expect(r.rows[0][k], k).toBeNull();
  });

  it("get_security_policy fails closed (configuration_required) until configured", async () => {
    const svc = await fresh.as("service_role");
    expect(await sqlState(svc, "select public.get_security_policy()")).toBe("P0001");
  });

  it("lockout recording fails closed until the owner configures it", async () => {
    const svc = await fresh.as("service_role");
    const cust = await fresh.createProfile("customer", "unconfigured");
    await svc.query("select public.set_access_secret($1, $2)", [
      cust,
      "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA",
    ]);
    expect(await sqlState(svc, "select public.record_quick_login_attempt($1, false)", [cust])).toBe(
      "P0001",
    );
  });

  it("setup cannot be completed while any policy value is missing", async () => {
    for (const k of POLICY_KEYS) {
      const t = await createTestDb();
      const settings: Record<string, unknown> = { ...TEST_SETTINGS };
      delete settings[k];
      const admin = await t.authUser("a");
      const svc = await t.as("service_role");
      const code = await sqlState(
        svc,
        "select public.complete_first_run_setup($1,$2,$3::jsonb,$4,$5,$6::jsonb)",
        [admin, "A", JSON.stringify(settings), 1000, "half_up", "[]"],
      );
      expect(code, k).toBe("22023");
      expect(
        (await t.su.query("select count(*)::int n from public.profiles")).rows[0].n,
        `${k}: rolled back`,
      ).toBe(0);
      await t.close();
    }
  });

  it("the CHECK constraint also blocks marking setup complete directly", async () => {
    expect(
      await sqlState(fresh.su, "update public.business_settings set setup_completed_at = now()"),
    ).toBe("23514");
  });
});

describe("policy values are validated, owner-controlled and audited", () => {
  const patch = (k: string, v: unknown) =>
    `select public.admin_update_business_settings('${JSON.stringify({ [k]: v })}')`;

  it.each([
    ["login_max_failed_attempts", 0],
    ["login_max_failed_attempts", 101],
    ["login_lock_seconds", 0],
    ["login_lock_seconds", 86401],
    ["rate_limit_login_ip_attempts", 0],
    ["rate_limit_login_ip_window_seconds", 0],
    ["rate_limit_login_code_attempts", -1],
    ["rate_limit_login_code_window_seconds", 86401],
    ["secret_code_min_length", 0],
    ["secret_code_min_length", 129],
  ])("rejects %s = %s (technical bounds only)", async (k, v) => {
    const c = await db.as("authenticated", adminId);
    expect(await sqlState(c, patch(k, v))).toBe("23514");
  });

  it("an administrator can change a policy value; the change is audited with before/after", async () => {
    const c = await db.asNew("authenticated", adminId);
    await c.query(patch("login_lock_seconds", 1234));
    const row = (
      await db.su.query(
        "select previous_value->>'login_lock_seconds' p, new_value->>'login_lock_seconds' n, actor_id from public.audit_logs where action='business_settings.update' order by id desc limit 1",
      )
    ).rows[0];
    expect(row).toMatchObject({ p: "900", n: "1234", actor_id: adminId });
    await c.query(patch("login_lock_seconds", 900));
  });

  it("settings permissions are administrator-only: a role with another permission cannot change settings or policy", async () => {
    const admin = await db.asNew("authenticated", adminId);
    await admin.query("select public.admin_create_role('orders_only_test', 'Orders only')");
    await admin.query("select public.admin_grant_permission('orders_only_test', 'orders.view')");
    const emp = await db.createProfile("employee", "orders-only");
    await admin.query("select public.admin_assign_role($1, 'orders_only_test')", [emp]);
    const c = await db.asNew("authenticated", emp);
    expect(await sqlState(c, patch("tagline", "x"))).toBe("42501");
    expect(await sqlState(c, patch("login_max_failed_attempts", 99))).toBe("42501");
    expect(await sqlState(c, patch("secret_code_min_length", 1))).toBe("42501");
    // ...and security_settings.manage cannot be handed to a non-admin role to work around it
    expect(
      await sqlState(
        admin,
        "select public.admin_grant_permission('orders_only_test', 'security_settings.manage')",
      ),
    ).toBe("42501");
    const s = (
      await db.su.query("select login_max_failed_attempts n, tagline from public.business_settings")
    ).rows[0];
    expect(s.n).toBe(TEST_SETTINGS.login_max_failed_attempts);
  });

  it("a settings patch containing an unknown key applies NOTHING (atomic, whitelisted)", async () => {
    const admin = await db.asNew("authenticated", adminId);
    expect(
      await sqlState(
        admin,
        `select public.admin_update_business_settings('{"login_lock_seconds":5,"setup_completed_at":"2000-01-01"}')`,
      ),
    ).toBe("22023");
    const s = (await db.su.query("select login_lock_seconds n from public.business_settings"))
      .rows[0];
    expect(s.n).toBe(TEST_SETTINGS.login_lock_seconds);
  });

  it("customers, anonymous callers and employees without any role cannot change or read policy", async () => {
    const cust = await db.createProfile("customer", "pol-cust");
    const nobody = await db.createProfile("employee", "pol-nobody");
    for (const [role, uid] of [
      ["authenticated", cust],
      ["authenticated", nobody],
    ] as const) {
      const c = await db.asNew(role, uid);
      expect(await sqlState(c, patch("login_max_failed_attempts", 99))).toBe("42501");
      expect(await sqlState(c, "select public.get_security_policy()")).toBe("42501");
      expect((await c.query("select 1 from public.business_settings")).rowCount).toBe(0);
    }
    const anon = await db.as("anon");
    expect(await sqlState(anon, "select public.get_security_policy()")).toBe("42501");
  });

  it("get_security_policy is service-only and returns exactly the configured values", async () => {
    const svc = await db.as("service_role");
    const p = (await svc.query("select public.get_security_policy() p")).rows[0].p;
    expect(p).toEqual({
      login_max_failed_attempts: TEST_SETTINGS.login_max_failed_attempts,
      login_lock_seconds: TEST_SETTINGS.login_lock_seconds,
      rate_limit_login_ip_attempts: TEST_SETTINGS.rate_limit_login_ip_attempts,
      rate_limit_login_ip_window_seconds: TEST_SETTINGS.rate_limit_login_ip_window_seconds,
      rate_limit_login_code_attempts: TEST_SETTINGS.rate_limit_login_code_attempts,
      rate_limit_login_code_window_seconds: TEST_SETTINGS.rate_limit_login_code_window_seconds,
      secret_code_min_length: TEST_SETTINGS.secret_code_min_length,
    });
  });
});

describe("permission catalogue: preserved as a proposal, secure-deny for everything unapproved", () => {
  const EXPECTED = [
    "audit.view",
    "cash.confirm",
    "cashup.perform",
    "cashup.review",
    "chat.use",
    "commission.view_own",
    "commissions.manage",
    "customers.manage",
    "customers.view",
    "employees.manage",
    "inventory.adjust",
    "meetups.view",
    "notifications.manage",
    "orders.adjust_cash",
    "orders.review",
    "orders.view",
    "payment_settings.manage",
    "payments.handle",
    "prices.manage",
    "products.manage",
    "promotions.manage",
    "reports.view",
    "roles.manage",
    "sales.view",
    "security_settings.manage",
    "settings.manage",
  ];

  it("contains exactly the 26 proposed keys (none added, removed or renamed)", async () => {
    const r = await fresh.su.query("select key from public.permissions order by key");
    expect(r.rows.map((x) => x.key)).toEqual([...EXPECTED].sort());
    expect(r.rowCount).toBe(26);
  });

  it("a fresh install has only the system admin role, and it is the only holder of permissions", async () => {
    const roles = (await fresh.su.query("select key from public.roles order by key")).rows;
    expect(roles.map((x) => x.key)).toEqual(["admin"]);
    const grants = (
      await fresh.su.query(
        "select count(*)::int n from public.role_permissions rp join public.roles r on r.id = rp.role_id where r.key <> 'admin'",
      )
    ).rows[0].n;
    expect(grants).toBe(0);
  });

  it("unknown or unapproved permission keys are denied, even to an administrator", async () => {
    const c = await db.as("authenticated", adminId);
    expect(
      await sqlState(c, "select public.admin_grant_permission('admin', 'made.up_permission')"),
    ).not.toBeNull();
    const has = await db.su.query("select app.has_permission($1, 'made.up_permission') h", [
      adminId,
    ]);
    expect(has.rows[0].h).toBe(false);
  });

  it("a staff account with no role holds no permission at all", async () => {
    const emp = await db.createProfile("employee", "no-role");
    for (const key of EXPECTED) {
      const r = await db.su.query("select app.has_permission($1, $2) h", [emp, key]);
      expect(r.rows[0].h, key).toBe(false);
    }
  });
});
