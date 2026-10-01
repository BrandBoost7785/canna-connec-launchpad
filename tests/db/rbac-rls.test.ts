import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, sqlState, type TestDb } from "./harness";

// Authorization is enforced by the database: RLS policies, missing table grants,
// function permission checks and guard triggers. Every test below connects as a
// real non-superuser database role with the JWT claims PostgREST would set.

let db: TestDb;
let adminId: string;
let employeeId: string; // has role "cashier" (orders.view, cash.confirm)
let bareEmployeeId: string; // employee with NO role
let customerA: string;
let customerB: string;
let asAdmin: pg.Client;
let asEmployee: pg.Client;
let asBareEmployee: pg.Client;
let asCustomerA: pg.Client;
let asCustomerB: pg.Client;

beforeAll(async () => {
  db = await createTestDb();
  adminId = await db.setupAdmin();
  employeeId = await db.createProfile("employee", "employee-a");
  bareEmployeeId = await db.createProfile("employee", "employee-bare");
  customerA = await db.createProfile("customer", "customer-a", "+27000000001");
  customerB = await db.createProfile("customer", "customer-b", "+27000000002");

  asAdmin = await db.as("authenticated", adminId);
  await asAdmin.query("select public.admin_create_role('cashier', 'Cashier', 'Test role')");
  await asAdmin.query("select public.admin_grant_permission('cashier', 'orders.view')");
  await asAdmin.query("select public.admin_grant_permission('cashier', 'cash.confirm')");
  await asAdmin.query("select public.admin_assign_role($1, 'cashier')", [employeeId]);

  asEmployee = await db.as("authenticated", employeeId);
  asBareEmployee = await db.as("authenticated", bareEmployeeId);
  asCustomerA = await db.as("authenticated", customerA);
  asCustomerB = await db.as("authenticated", customerB);

  // client codes for the customers (service-only function)
  const svc = await db.as("service_role");
  await svc.query("select public.issue_client_code($1)", [customerA]);
  await svc.query("select public.issue_client_code($1)", [customerB]);
});
afterAll(async () => {
  await db.close();
});

const ids = async (c: pg.Client, sql: string) =>
  (await c.query(sql)).rows.map((r) => r.id ?? r.user_id);

describe("my_access", () => {
  it("reports the roles and permissions granted by the database", async () => {
    const r = await asEmployee.query("select public.my_access() as a");
    expect(r.rows[0].a).toMatchObject({
      has_profile: true,
      kind: "employee",
      status: "approved",
      roles: ["cashier"],
    });
    expect(r.rows[0].a.permissions).toEqual(["cash.confirm", "orders.view"]);
  });

  it("gives an admin every catalogue permission", async () => {
    const a = (await asAdmin.query("select public.my_access() as a")).rows[0].a;
    const total = (await db.su.query("select count(*)::int n from public.permissions")).rows[0].n;
    expect(a.permissions).toHaveLength(total);
  });

  it("gives a customer no permissions", async () => {
    const a = (await asCustomerA.query("select public.my_access() as a")).rows[0].a;
    expect(a).toMatchObject({
      kind: "customer",
      status: "pending_approval",
      roles: [],
      permissions: [],
    });
  });

  it("returns has_profile=false for an auth user with no profile (fails closed)", async () => {
    const stray = await db.authUser("stray");
    const c = await db.as("authenticated", stray);
    const a = (await c.query("select public.my_access() as a")).rows[0].a;
    expect(a).toEqual({ has_profile: false });
    expect(await ids(c, "select id from public.profiles")).toEqual([]);
  });

  it("rejects anonymous callers", async () => {
    const anon = await db.as("anon");
    expect(await sqlState(anon, "select public.my_access()")).toBe("42501");
  });
});

describe("privileged RPCs deny everyone without the permission", () => {
  const calls: [string, string, unknown[]?][] = [
    ["admin_create_role", "select public.admin_create_role('x1', 'X')"],
    ["admin_grant_permission", "select public.admin_grant_permission('cashier', 'sales.view')"],
    ["admin_revoke_permission", "select public.admin_revoke_permission('cashier', 'orders.view')"],
    ["admin_assign_role", "select public.admin_assign_role($1, 'cashier')", ["$bare"]],
    ["admin_revoke_role", "select public.admin_revoke_role($1, 'cashier')", ["$employee"]],
    [
      "admin_update_business_settings",
      'select public.admin_update_business_settings(\'{"business_name":"Hijack"}\')',
    ],
    [
      "admin_set_notification_channel",
      "select public.admin_set_notification_channel('email', true)",
    ],
    [
      "admin_set_commission_configuration",
      "select public.admin_set_commission_configuration(9999, 'up')",
    ],
    [
      "admin_save_commission_period_schedule",
      "select public.admin_save_commission_period_schedule('p', 1::smallint, '00:00', 2::smallint, '00:00', 3::smallint, '00:00')",
    ],
  ];
  const resolve = (p: unknown[] = []) =>
    p.map((x) => (x === "$bare" ? bareEmployeeId : x === "$employee" ? employeeId : x));

  for (const [name, sql, params] of calls) {
    it(`${name}: employee with unrelated permissions is denied`, async () => {
      expect(await sqlState(asEmployee, sql, resolve(params))).toBe("42501");
    });
    it(`${name}: employee with no role is denied`, async () => {
      expect(await sqlState(asBareEmployee, sql, resolve(params))).toBe("42501");
    });
    it(`${name}: customer is denied`, async () => {
      expect(await sqlState(asCustomerA, sql, resolve(params))).toBe("42501");
    });
    it(`${name}: anonymous is denied`, async () => {
      const anon = await db.as("anon");
      expect(await sqlState(anon, sql, resolve(params))).toBe("42501");
    });
  }

  it("nothing changed as a result of the denied calls", async () => {
    const r = await db.su.query("select business_name from public.business_settings");
    expect(r.rows[0].business_name).toBe("TEST BUSINESS (fixture)");
    const roles = await db.su.query("select key from public.roles order by key");
    expect(roles.rows.map((x) => x.key)).toEqual(["admin", "cashier"]);
    const cfg = await db.su.query("select count(*)::int n from public.commission_configurations");
    expect(cfg.rows[0].n).toBe(1);
  });
});

describe("privilege escalation is blocked", () => {
  it("employee cannot assign themselves a role (including admin)", async () => {
    expect(
      await sqlState(asEmployee, "select public.admin_assign_role($1, 'admin')", [employeeId]),
    ).toBe("42501");
    expect(
      await sqlState(
        asEmployee,
        "insert into public.user_roles (user_id, role_id) select $1, id from public.roles where key='admin'",
        [employeeId],
      ),
    ).toBe("42501");
  });

  it("employee cannot change their own kind, status or id", async () => {
    expect(
      await sqlState(asEmployee, "update public.profiles set kind = 'admin' where id = $1", [
        employeeId,
      ]),
    ).toBe("42501");
    expect(
      await sqlState(asEmployee, "update public.profiles set status = 'approved' where id = $1", [
        employeeId,
      ]),
    ).toBe("42501");
  });

  it("customer cannot approve themselves", async () => {
    expect(
      await sqlState(asCustomerA, "update public.profiles set status = 'approved' where id = $1", [
        customerA,
      ]),
    ).toBe("42501");
    const r = await db.su.query("select status from public.profiles where id = $1", [customerA]);
    expect(r.rows[0].status).toBe("pending_approval");
  });

  it("customer cannot probe other users' permissions through internal functions", async () => {
    expect(
      await sqlState(asCustomerA, "select app.has_permission($1, 'settings.manage')", [adminId]),
    ).toBe("42501");
    expect(await sqlState(asCustomerA, "select app.require_permission('settings.manage')")).toBe(
      "42501",
    );
  });

  it("every admin-only permission is refused for a non-admin role, even via a fully authorized admin", async () => {
    const adminOnly = (
      await db.su.query("select key from public.permissions where admin_only order by key")
    ).rows.map((r) => r.key);
    expect(adminOnly.length).toBeGreaterThan(10);
    for (const key of adminOnly) {
      expect(
        await sqlState(asAdmin, "select public.admin_grant_permission('cashier', $1)", [key]),
        key,
      ).toBe("42501");
    }
    // The spec's "employees cannot" list is admin-only: products, prices, inventory, settings, own commission.
    for (const key of [
      "products.manage",
      "prices.manage",
      "inventory.adjust",
      "settings.manage",
      "commissions.manage",
    ]) {
      expect(adminOnly).toContain(key);
    }
  });

  it("roles cannot be assigned to customers", async () => {
    expect(
      await sqlState(asAdmin, "select public.admin_assign_role($1, 'cashier')", [customerA]),
    ).toBe("42501");
  });

  it("the admin role can only be held by admin accounts", async () => {
    expect(
      await sqlState(asAdmin, "select public.admin_assign_role($1, 'admin')", [employeeId]),
    ).toBe("42501");
  });

  it("the system admin role is immutable and cannot lose permissions", async () => {
    expect(
      await sqlState(asAdmin, "select public.admin_revoke_permission('admin', 'audit.view')"),
    ).toBe("42501");
    expect(await sqlState(db.su, "delete from public.roles where key = 'admin'")).toBe("42501");
    expect(await sqlState(db.su, "update public.roles set key = 'root' where key = 'admin'")).toBe(
      "42501",
    );
    expect(
      await sqlState(db.su, "update public.roles set archived_at = now() where key = 'admin'"),
    ).toBe("42501");
  });

  it("account kind is immutable, even for the database owner", async () => {
    expect(
      await sqlState(db.su, "update public.profiles set kind = 'admin' where id = $1", [
        employeeId,
      ]),
    ).toBe("42501");
  });

  it("the last active administrator cannot be removed, suspended or archived", async () => {
    expect(await sqlState(asAdmin, "select public.admin_revoke_role($1, 'admin')", [adminId])).toBe(
      "55000",
    );
    expect(
      await sqlState(db.su, "update public.profiles set status = 'suspended' where id = $1", [
        adminId,
      ]),
    ).toBe("55000");
    expect(
      await sqlState(db.su, "update public.profiles set archived_at = now() where id = $1", [
        adminId,
      ]),
    ).toBe("55000");
  });

  it("staff accounts cannot be in a customer-only status", async () => {
    expect(
      await sqlState(
        db.su,
        "update public.profiles set status = 'pending_approval' where id = $1",
        [employeeId],
      ),
    ).toBe("23514");
  });
});

describe("permission lifecycle", () => {
  it("takes effect immediately on revoke and on grant", async () => {
    const newRole = "temp_role";
    await asAdmin.query("select public.admin_create_role($1, 'Temp')", [newRole]);
    const emp = await db.createProfile("employee", "temp-emp");
    const c = await db.as("authenticated", emp);
    await asAdmin.query("select public.admin_grant_permission($1, 'sales.view')", [newRole]);
    await asAdmin.query("select public.admin_assign_role($1, $2)", [emp, newRole]);
    expect((await c.query("select app.current_user_has('sales.view') as ok")).rows[0].ok).toBe(
      true,
    );
    await asAdmin.query("select public.admin_revoke_permission($1, 'sales.view')", [newRole]);
    expect((await c.query("select app.current_user_has('sales.view') as ok")).rows[0].ok).toBe(
      false,
    );
  });

  it("a suspended employee immediately loses every permission", async () => {
    const before = (await asEmployee.query("select app.current_user_has('orders.view') as ok"))
      .rows[0].ok;
    expect(before).toBe(true);
    await db.su.query("update public.profiles set status = 'suspended' where id = $1", [
      employeeId,
    ]);
    expect(
      (await asEmployee.query("select app.current_user_has('orders.view') as ok")).rows[0].ok,
    ).toBe(false);
    const a = (await asEmployee.query("select public.my_access() as a")).rows[0].a;
    expect(a.permissions).toEqual([]);
    await db.su.query("update public.profiles set status = 'approved' where id = $1", [employeeId]);
    expect(
      (await asEmployee.query("select app.current_user_has('orders.view') as ok")).rows[0].ok,
    ).toBe(true);
  });

  it("an archived role grants nothing", async () => {
    await db.su.query("update public.roles set archived_at = now() where key = 'cashier'");
    expect(
      (await asEmployee.query("select app.current_user_has('orders.view') as ok")).rows[0].ok,
    ).toBe(false);
    await db.su.query("update public.roles set archived_at = null where key = 'cashier'");
  });

  it("an archived profile grants nothing", async () => {
    await db.su.query("update public.profiles set archived_at = now() where id = $1", [employeeId]);
    expect(
      (await asEmployee.query("select app.current_user_has('orders.view') as ok")).rows[0].ok,
    ).toBe(false);
    await db.su.query("update public.profiles set archived_at = null where id = $1", [employeeId]);
  });
});

describe("row level security: customer isolation (BOLA/IDOR)", () => {
  it("a customer sees only their own profile", async () => {
    expect(await ids(asCustomerA, "select id from public.profiles")).toEqual([customerA]);
    expect(await ids(asCustomerB, "select id from public.profiles")).toEqual([customerB]);
  });

  it("guessing another customer's id returns nothing", async () => {
    const r = await asCustomerA.query("select id from public.profiles where id = $1", [customerB]);
    expect(r.rowCount).toBe(0);
  });

  it("a customer cannot update another customer's profile (no privilege)", async () => {
    expect(
      await sqlState(
        asCustomerA,
        "update public.profiles set display_name = 'pwned' where id = $1",
        [customerB],
      ),
    ).toBe("42501");
  });

  it("a customer sees only their own client code", async () => {
    const r = await asCustomerA.query("select user_id, client_code from public.client_codes");
    expect(r.rows).toHaveLength(1);
    expect(r.rows[0].user_id).toBe(customerA);
  });

  it("a customer sees nothing in settings, roles, permissions, audit or commission tables", async () => {
    for (const t of [
      "business_settings",
      "roles",
      "permissions",
      "role_permissions",
      "audit_logs",
      "commission_configurations",
      "commission_period_schedules",
      "commission_periods",
      "notification_channel_settings",
    ]) {
      const r = await asCustomerA.query(`select 1 from public.${t}`);
      expect(r.rowCount, t).toBe(0);
    }
  });

  it("a customer only sees their own user_roles (none)", async () => {
    expect((await asCustomerA.query("select 1 from public.user_roles")).rowCount).toBe(0);
  });
});

describe("row level security: staff scoping", () => {
  it("an employee with no role sees only their own profile", async () => {
    expect(await ids(asBareEmployee, "select id from public.profiles")).toEqual([bareEmployeeId]);
  });

  it("an employee without customers.view cannot see customers", async () => {
    const seen = await ids(asEmployee, "select id from public.profiles");
    expect(seen).toEqual([employeeId]);
  });

  it("customers.view exposes customers but never staff or admin profiles", async () => {
    await asAdmin.query("select public.admin_create_role('support', 'Support')");
    await asAdmin.query("select public.admin_grant_permission('support', 'customers.view')");
    const sup = await db.createProfile("employee", "support-emp");
    await asAdmin.query("select public.admin_assign_role($1, 'support')", [sup]);
    const c = await db.as("authenticated", sup);
    const seen = (await c.query("select id, kind from public.profiles")).rows;
    const kinds = new Set(seen.map((r) => r.kind));
    expect(kinds.has("admin")).toBe(false);
    expect(seen.map((r) => r.id)).toEqual(expect.arrayContaining([customerA, customerB, sup]));
    expect(seen.map((r) => r.id)).not.toContain(adminId);
    expect(seen.map((r) => r.id)).not.toContain(employeeId);
    // but it grants no write access to profiles and no access to credentials
    expect(
      await sqlState(c, "update public.profiles set status = 'approved' where id = $1", [
        customerA,
      ]),
    ).toBe("42501");
    expect(await sqlState(c, "select * from public.access_credentials")).toBe("42501");
  });

  it("the admin sees every profile, role, assignment and the audit log", async () => {
    const all = (await db.su.query("select count(*)::int n from public.profiles")).rows[0].n;
    expect((await asAdmin.query("select id from public.profiles")).rowCount).toBe(all);
    expect((await asAdmin.query("select 1 from public.roles")).rowCount).toBeGreaterThanOrEqual(3);
    expect((await asAdmin.query("select 1 from public.audit_logs")).rowCount).toBeGreaterThan(0);
    expect((await asAdmin.query("select 1 from public.business_settings")).rowCount).toBe(1);
  });

  it("an employee sees only their own role assignment", async () => {
    const r = await asEmployee.query("select user_id from public.user_roles");
    expect(r.rows.map((x) => x.user_id)).toEqual([employeeId]);
  });
});
