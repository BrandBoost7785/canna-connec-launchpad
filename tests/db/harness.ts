import pg from "pg";
import { inject } from "vitest";
import { randomBytes } from "node:crypto";

// ---------------------------------------------------------------------------
// TEST FIXTURES. Everything below exists only inside throw-away test databases
// created from the migrated template. None of it is ever seeded anywhere else.
// ---------------------------------------------------------------------------

export const TEST_SETTINGS = {
  business_name: "TEST BUSINESS (fixture)",
  timezone: "Africa/Johannesburg",
  currency_code: "ZAR",
  business_day_cutoff: "20:00",
  cart_duration_minutes: 15,
  low_stock_default_threshold: 5,
  availability_check_minutes: 15,
  hide_out_of_stock_enabled: true,
  hide_out_of_stock_after_minutes: 45,
} as const;

export type DbRole = "anon" | "authenticated" | "service_role";

function conn(database: string): pg.ClientConfig {
  return {
    host: "127.0.0.1",
    port: inject("pgPort"),
    user: "postgres",
    password: inject("pgPassword"),
    database,
  };
}

export class TestDb {
  private clients: pg.Client[] = [];
  private cache = new Map<string, pg.Client>();
  constructor(
    readonly name: string,
    /** Superuser connection. Used ONLY to arrange fixtures and to inspect catalogs. */
    readonly su: pg.Client,
  ) {}

  /**
   * A connection that behaves like PostgREST: the session is switched to a real
   * non-superuser database role and the JWT claims GUCs are set, exactly as
   * PostgREST does per request. RLS and GRANTs are therefore really enforced.
   */
  async as(role: DbRole, userId?: string): Promise<pg.Client> {
    const key = `${role}:${userId ?? ""}`;
    const cached = this.cache.get(key);
    if (cached) return cached;
    const c = await this.asNew(role, userId);
    this.cache.set(key, c);
    return c;
  }

  /** Same as `as`, but always a brand-new connection (for concurrency tests / session-state tests). */
  async asNew(role: DbRole, userId?: string): Promise<pg.Client> {
    const c = new pg.Client(conn(this.name));
    await c.connect();
    this.clients.push(c);
    const claims: Record<string, string> = { role };
    if (userId) claims["sub"] = userId;
    await c.query("select set_config('request.jwt.claims', $1, false)", [JSON.stringify(claims)]);
    await c.query(`set role ${role}`);
    return c;
  }

  async newSuperuserConnection(): Promise<pg.Client> {
    const c = new pg.Client(conn(this.name));
    await c.connect();
    this.clients.push(c);
    return c;
  }

  async close(): Promise<void> {
    await Promise.all(this.clients.map((c) => c.end().catch(() => {})));
    await this.su.end().catch(() => {});
    const root = new pg.Client(conn("postgres"));
    await root.connect();
    await root.query(`drop database if exists "${this.name}" with (force)`);
    await root.end();
  }

  // ---- fixtures (test data only) ----
  async authUser(label: string): Promise<string> {
    const r = await this.su.query<{ id: string }>(
      "insert into auth.users (email) values ($1) returning id",
      [`${label}-${randomBytes(4).toString("hex")}@test.invalid`],
    );
    return r.rows[0]!.id;
  }

  /** Completes first-run setup through the real service-only function. */
  async setupAdmin(overrides: Record<string, unknown> = {}): Promise<string> {
    const adminId = await this.authUser("admin");
    const svc = await this.as("service_role");
    await svc.query("select public.complete_first_run_setup($1,$2,$3::jsonb,$4,$5,$6::jsonb)", [
      adminId,
      "Test Admin",
      JSON.stringify({ ...TEST_SETTINGS, ...overrides }),
      4000,
      "half_up",
      "[]",
    ]);
    return adminId;
  }

  async createProfile(
    kind: "customer" | "employee",
    label: string,
    mobile?: string,
  ): Promise<string> {
    const id = await this.authUser(label);
    const svc = await this.as("service_role");
    await svc.query("select public.create_profile($1,$2,$3,$4,null)", [
      id,
      kind,
      label,
      mobile ?? null,
    ]);
    return id;
  }
}

export async function createTestDb(): Promise<TestDb> {
  const name = "t_" + randomBytes(6).toString("hex");
  const root = new pg.Client(conn("postgres"));
  await root.connect();
  await root.query(`create database "${name}" template "${inject("templateDb")}"`);
  await root.end();
  const su = new pg.Client(conn(name));
  await su.connect();
  return new TestDb(name, su);
}

/** Runs a statement and returns its SQLSTATE if it fails, or null if it succeeds. */
export async function sqlState(
  c: pg.Client,
  sql: string,
  params: unknown[] = [],
): Promise<string | null> {
  try {
    await c.query(sql, params);
    return null;
  } catch (e) {
    return (e as { code?: string }).code ?? "unknown";
  }
}
