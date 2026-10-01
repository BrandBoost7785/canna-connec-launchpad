import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, type TestDb } from "./harness";
import { listMigrationFiles } from "./migrations";

let db: TestDb;
beforeAll(async () => {
  db = await createTestDb();
});
afterAll(async () => {
  await db.close();
});

describe("migrations", () => {
  it("all migration files apply cleanly, in order, to an empty database (global setup)", async () => {
    const files = listMigrationFiles();
    expect(files.length).toBeGreaterThanOrEqual(9);
    const r = await db.su.query(
      "select count(*)::int as n from information_schema.tables where table_schema = 'public'",
    );
    expect(r.rows[0].n).toBeGreaterThan(10);
  });

  it("migration filenames are timestamp-prefixed and unique", () => {
    const files = listMigrationFiles();
    for (const f of files) expect(f).toMatch(/^\d{14}_[a-z0-9_]+\.sql$/);
    expect(new Set(files.map((f) => f.slice(0, 14))).size).toBe(files.length);
  });

  it("creates NO business data: every data table is empty after migrations", async () => {
    const empty = [
      "profiles",
      "user_roles",
      "audit_logs",
      "client_codes",
      "access_credentials",
      "commission_configurations",
      "commission_period_schedules",
      "commission_periods",
      "notification_channel_settings",
      "rate_limits",
    ];
    for (const t of empty) {
      const r = await db.su.query(`select count(*)::int as n from public.${t}`);
      expect(r.rows[0].n, t).toBe(0);
    }
  });

  it("leaves owner-controlled settings unset (NULL) and setup incomplete", async () => {
    const r = await db.su.query("select * from public.business_settings");
    expect(r.rowCount).toBe(1);
    const row = r.rows[0];
    for (const k of [
      "business_name",
      "timezone",
      "currency_code",
      "business_day_cutoff",
      "cart_duration_minutes",
      "low_stock_default_threshold",
      "availability_check_minutes",
      "hide_out_of_stock_after_minutes",
      "payment_provider_key",
      "privacy_policy_text",
      "terms_text",
      "tagline",
      "logo_url",
      "setup_completed_at",
    ]) {
      expect(row[k], k).toBeNull();
    }
  });

  it("seeds only the system admin role and the permission catalogue", async () => {
    const roles = await db.su.query("select key, is_system from public.roles");
    expect(roles.rows).toEqual([{ key: "admin", is_system: true }]);
    const perms = await db.su.query("select count(*)::int as n from public.permissions");
    expect(perms.rows[0].n).toBeGreaterThan(20);
    const adminPerms = await db.su.query(
      "select count(*)::int as n from public.role_permissions rp join public.roles r on r.id = rp.role_id where r.key = 'admin'",
    );
    expect(adminPerms.rows[0].n).toBe(perms.rows[0].n);
  });
});
