import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, sqlState, type TestDb } from "./harness";

// Structural security guarantees, verified against the real catalog of a real
// PostgreSQL database. These tests are the guard-rail for every FUTURE migration:
// a new table or function that is left exposed fails here.

let db: TestDb;
beforeAll(async () => {
  db = await createTestDb();
});
afterAll(async () => {
  await db.close();
});

const AUTHENTICATED_SELECT_TABLES = [
  "audit_logs",
  "business_settings",
  "notification_channel_settings",
  "profiles",
  "permissions",
  "roles",
  "role_permissions",
  "user_roles",
  "commission_configurations",
  "commission_period_schedules",
  "commission_periods",
  "client_codes",
];

const ANON_FUNCTIONS = ["get_public_branding", "get_setup_status"];
const AUTHENTICATED_FUNCTIONS = [
  ...ANON_FUNCTIONS,
  "my_access",
  "business_day_for",
  "current_business_day",
  "admin_create_role",
  "admin_grant_permission",
  "admin_revoke_permission",
  "admin_assign_role",
  "admin_revoke_role",
  "admin_update_business_settings",
  "admin_set_notification_channel",
  "admin_set_commission_configuration",
  "admin_save_commission_period_schedule",
  "admin_deactivate_commission_period_schedule",
].sort();

describe("table security", () => {
  it("has RLS enabled on every table in the public schema", async () => {
    const r = await db.su.query(`
      select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind in ('r','p') and not c.relrowsecurity`);
    expect(r.rows).toEqual([]);
  });

  it("gives anon no privileges at all on any public table", async () => {
    const r = await db.su.query(`
      select c.relname, p.priv from pg_class c join pg_namespace n on n.oid = c.relnamespace
      cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) p(priv)
      where n.nspname = 'public' and c.relkind in ('r','p') and has_table_privilege('anon', c.oid, p.priv)`);
    expect(r.rows).toEqual([]);
  });

  it("gives authenticated NO write privilege on any public table", async () => {
    const r = await db.su.query(`
      select c.relname, p.priv from pg_class c join pg_namespace n on n.oid = c.relnamespace
      cross join (values ('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) p(priv)
      where n.nspname = 'public' and c.relkind in ('r','p') and has_table_privilege('authenticated', c.oid, p.priv)`);
    expect(r.rows).toEqual([]);
  });

  it("limits authenticated SELECT to the reviewed allow-list (credentials and rate limits are unreadable)", async () => {
    const r = await db.su.query(`
      select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind in ('r','p') and has_table_privilege('authenticated', c.oid, 'SELECT')
      order by 1`);
    expect(r.rows.map((x) => x.relname)).toEqual([...AUTHENTICATED_SELECT_TABLES].sort());
  });

  it("gives API roles no sequence privileges", async () => {
    const r = await db.su.query(`
      select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind = 'S'
        and (has_sequence_privilege('anon', c.oid, 'USAGE') or has_sequence_privilege('authenticated', c.oid, 'USAGE'))`);
    expect(r.rows).toEqual([]);
  });
});

describe("function security", () => {
  it("grants EXECUTE to PUBLIC on nothing (no function relies on default privileges)", async () => {
    const r = await db.su.query(`
      select p.oid::regprocedure::text as fn from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname in ('public','app')
        and (p.proacl is null or exists (select 1 from aclexplode(p.proacl) a where a.grantee = 0))`);
    expect(r.rows).toEqual([]);
  });

  it("exposes exactly the reviewed functions to anon", async () => {
    const r = await db.su.query(`
      select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'EXECUTE') order by 1`);
    expect(r.rows.map((x) => x.proname)).toEqual([...ANON_FUNCTIONS].sort());
  });

  it("exposes exactly the reviewed functions to authenticated", async () => {
    const r = await db.su.query(`
      select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'public' and has_function_privilege('authenticated', p.oid, 'EXECUTE') order by 1`);
    expect(r.rows.map((x) => x.proname)).toEqual(AUTHENTICATED_FUNCTIONS);
  });

  it("exposes only app.current_user_has from the internal schema, and only to authenticated", async () => {
    const r = await db.su.query(`
      select p.proname, has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth,
             has_function_privilege('anon', p.oid, 'EXECUTE') as anon
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'app' and (has_function_privilege('authenticated', p.oid, 'EXECUTE')
                                   or has_function_privilege('anon', p.oid, 'EXECUTE'))`);
    expect(r.rows).toEqual([{ proname: "current_user_has", auth: true, anon: false }]);
  });

  it("pins search_path on every SECURITY DEFINER function", async () => {
    const r = await db.su.query(`
      select p.oid::regprocedure::text as fn, p.proconfig
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname in ('public','app') and p.prosecdef
        and not coalesce(p.proconfig::text[] && array['search_path=""'], false)`);
    expect(r.rows).toEqual([]);
  });

  it("does not expose the internal schema to anon", async () => {
    const r = await db.su.query("select has_schema_privilege('anon', 'app', 'USAGE') as u");
    expect(r.rows[0].u).toBe(false);
  });
});

describe("direct table writes are impossible for API roles", () => {
  it("rejects INSERT/UPDATE/DELETE on every protected table for authenticated (even an admin)", async () => {
    const adminId = await db.setupAdmin();
    const asAdmin = await db.as("authenticated", adminId);
    const attempts = [
      "insert into public.roles (key, name) values ('hax', 'Hax')",
      "update public.roles set name = 'x'",
      "delete from public.roles",
      "insert into public.permissions (key, module, description) values ('a.b', 'm', 'd')",
      "update public.profiles set status = 'suspended'",
      "insert into public.user_roles (user_id, role_id) select id, (select id from public.roles limit 1) from public.profiles",
      "insert into public.role_permissions (role_id, permission_id) select r.id, p.id from public.roles r, public.permissions p",
      "update public.business_settings set business_name = 'x'",
      "insert into public.audit_logs (actor_source, action) values ('user', 'fake.event')",
      "delete from public.audit_logs",
      "insert into public.commission_configurations (rate_bps, rounding, effective_from) values (1, 'down', now())",
      "insert into public.client_codes (user_id, client_code) values (gen_random_uuid(), 'AAAA-AAAA-AAAA')",
    ];
    for (const sql of attempts) {
      expect(await sqlState(asAdmin, sql), sql).toBe("42501");
    }
  });

  it("rejects every read of anon", async () => {
    const anon = await db.as("anon");
    for (const t of [
      "profiles",
      "roles",
      "business_settings",
      "audit_logs",
      "access_credentials",
      "rate_limits",
      "client_codes",
    ]) {
      expect(await sqlState(anon, `select * from public.${t}`), t).toBe("42501");
    }
  });

  it("rejects reads of credentials and rate limits even for an admin", async () => {
    const adminId = (await db.su.query("select id from public.profiles where kind = 'admin'"))
      .rows[0].id;
    const asAdmin = await db.as("authenticated", adminId);
    expect(await sqlState(asAdmin, "select * from public.access_credentials")).toBe("42501");
    expect(await sqlState(asAdmin, "select * from public.rate_limits")).toBe("42501");
  });

  it("rejects TRUNCATE of the audit log for every role, including the owner", async () => {
    expect(await sqlState(db.su, "truncate public.audit_logs")).toBe("42501");
  });
});
