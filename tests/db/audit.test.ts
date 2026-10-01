import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, sqlState, type TestDb } from "./harness";

let db: TestDb;
let adminId: string;
let asAdmin: pg.Client;
beforeAll(async () => {
  db = await createTestDb();
  adminId = await db.setupAdmin();
  asAdmin = await db.as("authenticated", adminId);
});
afterAll(async () => {
  await db.close();
});

const latest = async (action: string) =>
  (
    await db.su.query(
      "select * from public.audit_logs where action = $1 order by id desc limit 1",
      [action],
    )
  ).rows[0];
const total = async () =>
  (await db.su.query("select count(*)::int n from public.audit_logs")).rows[0].n as number;

describe("audit log content", () => {
  it("records actor, action, target, previous and new values for a role-permission change", async () => {
    await asAdmin.query("select public.admin_create_role('auditor_test', 'Audit test')");
    await asAdmin.query("select public.admin_grant_permission('auditor_test', 'orders.view')");
    const row = await latest("role_permissions.insert");
    expect(row.actor_id).toBe(adminId);
    expect(row.actor_source).toBe("user");
    expect(row.target_table).toBe("role_permissions");
    expect(row.target_id).toMatch(/^[0-9a-f-]{36}:[0-9a-f-]{36}$/);
    expect(row.previous_value).toBeNull();
    expect(row.new_value.granted_by).toBe(adminId);
    expect(row.occurred_at).toBeInstanceOf(Date);
  });

  it("records a revoke with the previous value", async () => {
    await asAdmin.query("select public.admin_revoke_permission('auditor_test', 'orders.view')");
    const row = await latest("role_permissions.delete");
    expect(row.previous_value).not.toBeNull();
    expect(row.new_value).toBeNull();
    expect(row.actor_id).toBe(adminId);
  });

  it("records employee permission/role changes", async () => {
    const emp = await db.createProfile("employee", "audit-emp");
    await asAdmin.query("select public.admin_assign_role($1, 'auditor_test')", [emp]);
    const row = await latest("user_roles.insert");
    expect(row.target_id.startsWith(emp)).toBe(true);
    await asAdmin.query("select public.admin_revoke_role($1, 'auditor_test')", [emp]);
    expect((await latest("user_roles.delete")).actor_id).toBe(adminId);
  });

  it("records commission configuration and schedule changes", async () => {
    await asAdmin.query("select public.admin_set_commission_configuration(3000, 'down')");
    expect((await latest("commission_configurations.insert")).new_value.rate_bps).toBe(3000);
    await asAdmin.query(
      "select public.admin_save_commission_period_schedule('A', 1::smallint, '00:00', 2::smallint, '00:00', 2::smallint, '00:00')",
    );
    expect((await latest("commission_period_schedules.insert")).actor_id).toBe(adminId);
  });

  it("records account status changes (who, from, to)", async () => {
    const cust = await db.createProfile("customer", "audit-cust");
    await db.su.query("select set_config('app.actor_id', $1, false)", [adminId]);
    await db.su.query("update public.profiles set status = 'approved' where id = $1", [cust]);
    const row = await latest("profiles.update");
    expect(row.previous_value.status).toBe("pending_approval");
    expect(row.new_value.status).toBe("approved");
    expect(row.actor_id).toBe(adminId);
  });
});

describe("audit log integrity", () => {
  it("does not log denied operations", async () => {
    const emp = await db.createProfile("employee", "denied-emp");
    const c = await db.as("authenticated", emp);
    const before = await total();
    expect(await sqlState(c, "select public.admin_create_role('nope', 'Nope')")).toBe("42501");
    expect(await sqlState(c, "update public.profiles set status = 'suspended'")).toBe("42501");
    expect(await total()).toBe(before);
  });

  it("does not log no-op updates", async () => {
    const before = await total();
    await db.su.query("update public.business_settings set business_name = business_name");
    expect(await total()).toBe(before);
  });

  it("cannot be updated, deleted or truncated by anyone, including the database owner", async () => {
    expect(await sqlState(db.su, "update public.audit_logs set action = 'tampered'")).toBe("42501");
    expect(await sqlState(db.su, "delete from public.audit_logs")).toBe("42501");
    expect(await sqlState(db.su, "truncate public.audit_logs")).toBe("42501");
    expect(await sqlState(asAdmin, "update public.audit_logs set action = 'tampered'")).toBe(
      "42501",
    );
    expect(await sqlState(asAdmin, "delete from public.audit_logs")).toBe("42501");
  });

  it("cannot be forged by API roles or called directly", async () => {
    expect(
      await sqlState(
        asAdmin,
        "insert into public.audit_logs (actor_source, action) values ('user', 'forged.event')",
      ),
    ).toBe("42501");
    expect(await sqlState(asAdmin, "select app.write_audit('forged.event')")).toBe("42501");
    const svc = await db.as("service_role");
    expect(await sqlState(svc, "select app.write_audit('forged.event')")).toBe("42501");
  });

  it("attributes actions to the verified JWT subject even if a caller sets app.actor_id", async () => {
    const other = await db.createProfile("employee", "spoof-target");
    const spoofer = await db.asNew("authenticated", adminId);
    await spoofer.query("select set_config('app.actor_id', $1, false)", [other]);
    await spoofer.query(`select public.admin_update_business_settings('{"tagline":"spoof test"}')`);
    const row = await latest("business_settings.update");
    expect(row.actor_id).toBe(adminId);
    expect(row.actor_source).toBe("user");
  });

  it("only users with audit.view can read it", async () => {
    const emp = await db.createProfile("employee", "reader");
    const cust = await db.createProfile("customer", "reader-cust");
    expect(
      (await (await db.as("authenticated", emp)).query("select 1 from public.audit_logs")).rowCount,
    ).toBe(0);
    expect(
      (await (await db.as("authenticated", cust)).query("select 1 from public.audit_logs"))
        .rowCount,
    ).toBe(0);
    expect((await asAdmin.query("select 1 from public.audit_logs")).rowCount).toBeGreaterThan(5);
    const anon = await db.as("anon");
    expect(await sqlState(anon, "select 1 from public.audit_logs")).toBe("42501");
  });
});

describe("secrets never reach the audit log", () => {
  const MARKER = "$argon2id$v=19$m=19456,t=2,p=1$SECRETMARKERSALT$SECRETMARKERHASHVALUE";
  it("audits creation and rotation of a Secret Access Code without its value", async () => {
    const cust = await db.createProfile("customer", "secret-cust");
    const svc = await db.as("service_role");
    await svc.query("select public.set_access_secret($1, $2)", [cust, MARKER]);
    await svc.query("select public.set_access_secret($1, $2)", [cust, MARKER + "2"]);
    const rows = (
      await db.su.query(
        "select * from public.audit_logs where target_table = 'access_credentials' order by id",
      )
    ).rows;
    expect(rows.map((r) => r.action)).toEqual([
      "access_credentials.insert",
      "access_credentials.update",
    ]);
    const everything = JSON.stringify((await db.su.query("select * from public.audit_logs")).rows);
    expect(everything).not.toContain("SECRETMARKER");
    for (const r of rows) {
      expect(r.new_value).not.toHaveProperty("secret_hash");
      expect(r.previous_value ?? {}).not.toHaveProperty("secret_hash");
    }
  });

  it("does not audit every failed login counter bump, but audits the lockout", async () => {
    const cust = await db.createProfile("customer", "lock-cust");
    const svc = await db.as("service_role");
    await svc.query("select public.set_access_secret($1, $2)", [cust, MARKER]);
    const before = await total();
    await svc.query("select public.record_quick_login_attempt($1, false)", [cust]);
    await svc.query("select public.record_quick_login_attempt($1, false)", [cust]);
    expect(await total()).toBe(before);
    await svc.query("select public.record_quick_login_attempt($1, false)", [cust]);
    const row = await latest("credential.quick_login_locked");
    expect(row.actor_id).toBe(cust);
    expect(row.new_value.failed_attempts).toBe(3);
  });
});
