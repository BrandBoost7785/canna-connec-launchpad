import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, sqlState, type TestDb } from "./harness";

// Foreign keys, unique and check constraints, verified directly as the table owner
// (so RLS/grants are not what is being exercised here).

let db: TestDb;
beforeAll(async () => {
  db = await createTestDb();
  await db.setupAdmin();
});
afterAll(async () => {
  await db.close();
});

describe("foreign keys", () => {
  it("a profile requires an existing auth user", async () => {
    expect(
      await sqlState(
        db.su,
        "insert into public.profiles (id, kind, status) values (gen_random_uuid(), 'customer', 'pending_approval')",
      ),
    ).toBe("23503");
  });

  it("an auth user with a profile cannot be deleted (RESTRICT)", async () => {
    const id = await db.createProfile("customer", "fk-restrict");
    expect(await sqlState(db.su, "delete from auth.users where id = $1", [id])).toBe("23503");
  });

  it("a profile with dependent rows cannot be removed", async () => {
    const id = await db.createProfile("customer", "fk-dep");
    const svc = await db.as("service_role");
    await svc.query("select public.issue_client_code($1)", [id]);
    expect(await sqlState(db.su, "delete from public.profiles where id = $1", [id])).toBe("23503");
  });

  it("role assignments and grants require real roles, users and permissions", async () => {
    const emp = await db.createProfile("employee", "fk-emp");
    expect(
      await sqlState(
        db.su,
        "insert into public.user_roles (user_id, role_id) values ($1, gen_random_uuid())",
        [emp],
      ),
    ).toBe("23503");
    // unknown user: the BEFORE trigger rejects non-staff/unknown accounts first (42501); FK is the backstop
    expect(
      await sqlState(
        db.su,
        "insert into public.user_roles (user_id, role_id) select gen_random_uuid(), id from public.roles limit 1",
      ),
    ).toBe("42501");
    expect(
      await sqlState(
        db.su,
        "insert into public.role_permissions (role_id, permission_id) select id, gen_random_uuid() from public.roles limit 1",
      ),
    ).toBe("23503");
  });

  it("audit actor must be a real profile", async () => {
    expect(
      await sqlState(
        db.su,
        "insert into public.audit_logs (actor_id, actor_source, action) values (gen_random_uuid(), 'user', 'x.fake')",
      ),
    ).toBe("23503");
  });

  it("commission periods require an existing schedule", async () => {
    expect(
      await sqlState(
        db.su,
        "insert into public.commission_periods (schedule_id, label, timezone, starts_at, ends_at, payout_at) values (gen_random_uuid(), 'x', 'UTC', now(), now() + interval '1 day', now() + interval '1 day')",
      ),
    ).toBe("23503");
  });
});

describe("unique constraints", () => {
  it("role keys are unique", async () => {
    await db.su.query("insert into public.roles (key, name) values ('dupe', 'Dupe')");
    expect(
      await sqlState(db.su, "insert into public.roles (key, name) values ('dupe', 'Dupe 2')"),
    ).toBe("23505");
  });

  it("permission keys are unique", async () => {
    expect(
      await sqlState(
        db.su,
        "insert into public.permissions (key, module, description) values ('orders.view', 'm', 'd')",
      ),
    ).toBe("23505");
  });

  it("active mobile numbers are unique but an archived profile frees its number", async () => {
    const a = await db.authUser("u1");
    const b = await db.authUser("u2");
    const c = await db.authUser("u3");
    await db.su.query(
      "insert into public.profiles (id, kind, status, mobile_e164) values ($1, 'customer', 'pending_approval', '+27831230000')",
      [a],
    );
    expect(
      await sqlState(
        db.su,
        "insert into public.profiles (id, kind, status, mobile_e164) values ($1, 'customer', 'pending_approval', '+27831230000')",
        [b],
      ),
    ).toBe("23505");
    await db.su.query("update public.profiles set archived_at = now() where id = $1", [a]);
    await db.su.query(
      "insert into public.profiles (id, kind, status, mobile_e164) values ($1, 'customer', 'pending_approval', '+27831230000')",
      [c],
    );
  });

  it("the settings table is a strict singleton", async () => {
    expect(
      await sqlState(db.su, "insert into public.business_settings (singleton) values (true)"),
    ).toBe("23505");
    expect(
      await sqlState(db.su, "insert into public.business_settings (singleton) values (false)"),
    ).toBe("23514");
    expect(await sqlState(db.su, "delete from public.business_settings")).toBe("42501");
  });
});

describe("check constraints", () => {
  const bad: [string, string][] = [
    ["role key with uppercase", "insert into public.roles (key, name) values ('Bad', 'x')"],
    ["role key starting with digit", "insert into public.roles (key, name) values ('1bad', 'x')"],
    ["blank role name", "insert into public.roles (key, name) values ('blank', '   ')"],
    [
      "permission key without a dot",
      "insert into public.permissions (key, module, description) values ('nodot', 'm', 'd')",
    ],
    [
      "rate above 100%",
      "insert into public.commission_configurations (rate_bps, rounding, effective_from) values (10001, 'down', now() + interval '99 days')",
    ],
    [
      "negative rate",
      "insert into public.commission_configurations (rate_bps, rounding, effective_from) values (-1, 'down', now() + interval '98 days')",
    ],
    [
      "audit action too short",
      "insert into public.audit_logs (actor_source, action) values ('user', 'x')",
    ],
    [
      "audit actor_source invalid",
      "insert into public.audit_logs (actor_source, action) values ('hacker', 'valid.action')",
    ],
    [
      "negative low-stock threshold",
      "update public.business_settings set low_stock_default_threshold = -1",
    ],
    [
      "cart duration beyond a day",
      "update public.business_settings set cart_duration_minutes = 1441",
    ],
    ["invalid email", "update public.business_settings set contact_email = 'not-an-email'"],
    [
      "non-E.164 contact phone",
      "update public.business_settings set contact_phone = '082 123 4567'",
    ],
    ["hex colour of wrong length", "update public.business_settings set primary_color = '#fff'"],
    [
      "schedule with inverted window",
      "insert into public.commission_period_schedules (label, start_dow, start_time, end_dow, end_time, payout_dow, payout_time) values ('inv', 3, '10:00', 2, '10:00', 3, '10:00')",
    ],
    [
      "period with end before start",
      "insert into public.commission_periods (schedule_id, label, timezone, starts_at, ends_at, payout_at) select gen_random_uuid(), 'x', 'UTC', now() + interval '1 day', now(), now()",
    ],
  ];
  for (const [name, sql] of bad) {
    it(`rejects ${name}`, async () => {
      const code = await sqlState(db.su, sql);
      expect(["23514", "23503"]).toContain(code); // period case fails on FK or check; all others must be CHECK
      if (!name.startsWith("period")) expect(code).toBe("23514");
    });
  }

  it("setup_completed requires the core operational settings (cannot be bypassed)", async () => {
    const fresh = await createTestDb();
    expect(
      await sqlState(fresh.su, "update public.business_settings set setup_completed_at = now()"),
    ).toBe("23514");
    await fresh.close();
  });
});

describe("transactions", () => {
  it("a failed privileged operation rolls back completely (role + grants created in one transaction)", async () => {
    const c = await db.newSuperuserConnection();
    await c.query("begin");
    await c.query("insert into public.roles (key, name) values ('txn_role', 'Txn')");
    const code = await sqlState(
      c,
      "insert into public.role_permissions (role_id, permission_id) select r.id, p.id from public.roles r, public.permissions p where r.key = 'txn_role' and p.key = 'settings.manage'",
    );
    expect(code).toBe("42501");
    await c.query("rollback");
    expect(
      (await db.su.query("select count(*)::int n from public.roles where key = 'txn_role'")).rows[0]
        .n,
    ).toBe(0);
  });

  it("audit rows roll back together with the change they describe", async () => {
    const before = (await db.su.query("select count(*)::int n from public.audit_logs")).rows[0].n;
    const c = await db.newSuperuserConnection();
    await c.query("begin");
    await c.query("insert into public.roles (key, name) values ('txn_audit', 'Txn audit')");
    await c.query("rollback");
    expect((await db.su.query("select count(*)::int n from public.audit_logs")).rows[0].n).toBe(
      before,
    );
  });
});
