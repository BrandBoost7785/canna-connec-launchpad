import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, sqlState, type TestDb } from "./harness";

let db: TestDb;
beforeAll(async () => {
  db = await createTestDb();
});
afterAll(async () => {
  await db.close();
});

const amount = async (amt: number | string, bps: number, mode: string) =>
  Number(
    (
      await db.su.query(
        "select app.commission_amount($1::bigint, $2, $3::public.money_rounding_mode) as c",
        [amt, bps, mode],
      )
    ).rows[0].c,
  );

describe("commission amount: deterministic integer arithmetic", () => {
  const cases: [number, number, string, number][] = [
    [10000, 4000, "half_up", 4000],
    [999, 4000, "half_up", 400], // 399.6
    [999, 4000, "down", 399],
    [999, 4000, "up", 400],
    [1, 4000, "half_up", 0], // 0.4
    [1, 4000, "up", 1],
    [5, 5000, "half_up", 3], // 2.5
    [5, 5000, "half_even", 2], // 2.5 -> even
    [7, 5000, "half_even", 4], // 3.5 -> even
    [7, 5000, "half_up", 4],
    [7, 5000, "down", 3],
    [0, 4000, "up", 0],
    [12345, 0, "up", 0],
    [12345, 10000, "down", 12345],
  ];
  for (const [a, bps, mode, expected] of cases) {
    it(`${a} @ ${bps}bp (${mode}) = ${expected}`, async () => {
      expect(await amount(a, bps, mode)).toBe(expected);
    });
  }

  it("never overflows on very large amounts (exact numeric arithmetic)", async () => {
    expect(await amount("9000000000000000", 10000, "half_up")).toBe(9000000000000000);
    expect(await amount("9000000000000000", 3333, "down")).toBe(2999700000000000);
  });

  it("is deterministic: identical inputs always give identical results", async () => {
    const r = await db.su.query(
      "select count(distinct app.commission_amount(123457, 3333, 'half_even'))::int as n from generate_series(1, 50)",
    );
    expect(r.rows[0].n).toBe(1);
  });

  it("rejects negative amounts and out-of-range rates", async () => {
    expect(await sqlState(db.su, "select app.commission_amount(-1, 4000, 'half_up')")).toBe(
      "22023",
    );
    expect(await sqlState(db.su, "select app.commission_amount(100, 10001, 'half_up')")).toBe(
      "22023",
    );
    expect(await sqlState(db.su, "select app.commission_amount(100, -1, 'half_up')")).toBe("22023");
  });
});

describe("commission configuration is owner-controlled and versioned", () => {
  let adminId: string;
  let asAdmin: pg.Client;
  let svc: pg.Client;

  it("refuses to calculate before any configuration exists (no hard-coded rate)", async () => {
    svc = await db.as("service_role");
    expect(await sqlState(svc, "select public.calculate_commission_cents(10000, now())")).toBe(
      "P0001",
    );
  });

  it("uses the configured rate after setup", async () => {
    adminId = await db.setupAdmin();
    asAdmin = await db.as("authenticated", adminId);
    const r = await svc.query(
      "select public.calculate_commission_cents(10000, now() + interval '1 second') c",
    );
    expect(Number(r.rows[0].c)).toBe(4000);
  });

  it("does not apply a configuration to timestamps before it took effect", async () => {
    expect(
      await sqlState(
        svc,
        "select public.calculate_commission_cents(10000, now() - interval '1 day')",
      ),
    ).toBe("P0001");
  });

  it("applies a future rate change only from its effective time; older timestamps keep the old rate", async () => {
    await asAdmin.query(
      "select public.admin_set_commission_configuration(2500, 'down', now() + interval '1 hour', 'test')",
    );
    const before = await svc.query(
      "select public.calculate_commission_cents(10000, now() + interval '30 minutes') c",
    );
    const after = await svc.query(
      "select public.calculate_commission_cents(10000, now() + interval '2 hours') c",
    );
    expect(Number(before.rows[0].c)).toBe(4000);
    expect(Number(after.rows[0].c)).toBe(2500);
  });

  it("uses the configured rounding mode", async () => {
    await asAdmin.query(
      "select public.admin_set_commission_configuration(5000, 'half_even', now() + interval '3 hours')",
    );
    const r = await svc.query(
      "select public.calculate_commission_cents(5, now() + interval '4 hours') a, public.calculate_commission_cents(7, now() + interval '4 hours') b",
    );
    expect([Number(r.rows[0].a), Number(r.rows[0].b)]).toEqual([2, 4]);
  });

  it("refuses to rewrite history: no past effective date", async () => {
    expect(
      await sqlState(
        asAdmin,
        "select public.admin_set_commission_configuration(1, 'down', now() - interval '1 day')",
      ),
    ).toBe("22023");
  });

  it("rejects an out-of-range rate and a duplicate effective time", async () => {
    expect(
      await sqlState(asAdmin, "select public.admin_set_commission_configuration(10001, 'down')"),
    ).toBe("23514");
    expect(
      await sqlState(asAdmin, "select public.admin_set_commission_configuration(-1, 'down')"),
    ).toBe("23514");
    await asAdmin.query(
      "select public.admin_set_commission_configuration(1000, 'down', now() + interval '10 hours')",
    );
    expect(
      await sqlState(
        asAdmin,
        "select public.admin_set_commission_configuration(1000, 'down', (select max(effective_from) from public.commission_configurations))",
      ),
    ).toBe("23505");
  });

  it("history is append-only for every role including the owner", async () => {
    expect(await sqlState(db.su, "update public.commission_configurations set rate_bps = 1")).toBe(
      "42501",
    );
    expect(await sqlState(db.su, "delete from public.commission_configurations")).toBe("42501");
    expect(await sqlState(db.su, "truncate public.commission_configurations")).toBe("42501");
  });

  it("an employee cannot change or read-modify their own commission rate", async () => {
    await asAdmin.query("select public.admin_create_role('seller', 'Seller')");
    await asAdmin.query("select public.admin_grant_permission('seller', 'commission.view_own')");
    const emp = await db.createProfile("employee", "seller-emp");
    await asAdmin.query("select public.admin_assign_role($1, 'seller')", [emp]);
    const c = await db.as("authenticated", emp);
    expect(await sqlState(c, "select public.admin_set_commission_configuration(9000, 'up')")).toBe(
      "42501",
    );
    expect(await sqlState(c, "update public.commission_configurations set rate_bps = 9000")).toBe(
      "42501",
    );
    expect(
      await sqlState(
        c,
        "insert into public.commission_configurations (rate_bps, rounding, effective_from) values (9000, 'up', now())",
      ),
    ).toBe("42501");
    // commission.view_own may READ the configuration (their own rate rule)...
    expect(
      (await c.query("select 1 from public.commission_configurations")).rowCount,
    ).toBeGreaterThan(0);
    // ...but the calculation function is server-only.
    expect(await sqlState(c, "select public.calculate_commission_cents(100, now())")).toBe("42501");
  });

  it("the configuration change is audited with the acting administrator", async () => {
    const r = await db.su.query(
      "select actor_id, action, new_value->>'rate_bps' as rate from public.audit_logs where action = 'commission_configurations.insert' order by id",
    );
    expect(r.rowCount).toBeGreaterThanOrEqual(4);
    expect(r.rows.some((x) => x.actor_id === adminId && x.rate === "2500")).toBe(true);
  });
});

describe("commission periods (owner-defined weekly windows; test fixture mirrors the specification's example)", () => {
  // TEST FIXTURE: one reading of the spec's schedule. The real schedule is entered by the owner.
  //   P1: Monday 00:00 -> Friday 14:00, paid Friday 14:00
  //   P2: Friday 14:00 -> Sunday 18:00, paid Sunday 20:00
  // 2026-09-28 is a Monday. Business timezone Africa/Johannesburg (UTC+2).
  let db2: TestDb;
  let adminId: string;
  let asAdmin: pg.Client;
  let svc: pg.Client;

  beforeAll(async () => {
    db2 = await createTestDb();
    adminId = await db2.setupAdmin();
    asAdmin = await db2.as("authenticated", adminId);
    svc = await db2.as("service_role");
    await asAdmin.query(
      "select public.admin_save_commission_period_schedule('Period 1', 1::smallint, '00:00', 5::smallint, '14:00', 5::smallint, '14:00')",
    );
    await asAdmin.query(
      "select public.admin_save_commission_period_schedule('Period 2', 5::smallint, '14:00', 7::smallint, '18:00', 7::smallint, '20:00')",
    );
  });
  afterAll(async () => {
    await db2.close();
  });

  const period = async (ts: string) => {
    const r = await svc.query(
      "select p.label, p.starts_at, p.ends_at, p.payout_at, p.id from public.ensure_commission_period($1::timestamptz) p",
      [ts],
    );
    const row = r.rows[0];
    if (!row || row.id === null) return null;
    return {
      label: row.label as string,
      starts: new Date(row.starts_at).toISOString(),
      ends: new Date(row.ends_at).toISOString(),
      payout: new Date(row.payout_at).toISOString(),
    };
  };

  it("places a Wednesday sale in Period 1 with snapshot boundaries", async () => {
    expect(await period("2026-09-30 10:00:00+02")).toEqual({
      label: "Period 1",
      starts: "2026-09-27T22:00:00.000Z", // Mon 2026-09-28 00:00 SAST
      ends: "2026-10-02T12:00:00.000Z", //   Fri 2026-10-02 14:00 SAST
      payout: "2026-10-02T12:00:00.000Z",
    });
  });

  it("switches at exactly Friday 14:00 (start inclusive, end exclusive)", async () => {
    expect((await period("2026-10-02 13:59:59.999999+02"))?.label).toBe("Period 1");
    expect(await period("2026-10-02 14:00:00+02")).toEqual({
      label: "Period 2",
      starts: "2026-10-02T12:00:00.000Z",
      ends: "2026-10-04T16:00:00.000Z", // Sun 18:00 SAST
      payout: "2026-10-04T18:00:00.000Z", // Sun 20:00 SAST
    });
  });

  it("returns no period in a gap (Sunday 18:00 -> Monday 00:00) rather than inventing one", async () => {
    expect((await period("2026-10-04 17:59:59+02"))?.label).toBe("Period 2");
    expect(await period("2026-10-04 18:00:00+02")).toBeNull();
    expect(await period("2026-10-04 23:59:59+02")).toBeNull();
    expect((await period("2026-10-05 00:00:00+02"))?.label).toBe("Period 1");
  });

  it("creates each concrete period once, even under concurrent requests", async () => {
    const before = (await db2.su.query("select count(*)::int n from public.commission_periods"))
      .rows[0].n;
    const clients = await Promise.all(Array.from({ length: 6 }, () => db2.as("service_role")));
    const results = await Promise.all(
      clients.map((c) =>
        c.query(
          "select id from public.ensure_commission_period('2026-10-14 12:00:00+02'::timestamptz)",
        ),
      ),
    );
    expect(new Set(results.map((r) => r.rows[0].id)).size).toBe(1);
    const after = (await db2.su.query("select count(*)::int n from public.commission_periods"))
      .rows[0].n;
    expect(after).toBe(before + 1);
  });

  it("creates NO period records until a real timestamp is resolved", async () => {
    const fresh = await createTestDb();
    await fresh.setupAdmin();
    expect(
      (await fresh.su.query("select count(*)::int n from public.commission_periods")).rows[0].n,
    ).toBe(0);
    await fresh.close();
  });

  it("rejects overlapping active windows, wrapped windows and invalid days", async () => {
    expect(
      await sqlState(
        asAdmin,
        "select public.admin_save_commission_period_schedule('Overlap', 3::smallint, '00:00', 4::smallint, '00:00', 4::smallint, '00:00')",
      ),
    ).toBe("23P01");
    expect(
      await sqlState(
        asAdmin,
        "select public.admin_save_commission_period_schedule('Wrap', 7::smallint, '22:00', 1::smallint, '02:00', 1::smallint, '03:00')",
      ),
    ).toBe("23514");
    expect(
      await sqlState(
        asAdmin,
        "select public.admin_save_commission_period_schedule('Bad', 0::smallint, '00:00', 1::smallint, '00:00', 1::smallint, '00:00')",
      ),
    ).toBe("23514");
    expect(
      await sqlState(
        asAdmin,
        "select public.admin_save_commission_period_schedule('Period 1', 7::smallint, '19:00', 7::smallint, '21:00', 7::smallint, '21:00')",
      ),
    ).toBe("23505");
  });

  it("concrete periods are immutable and unaffected by later schedule changes", async () => {
    expect(
      await sqlState(
        db2.su,
        "update public.commission_periods set ends_at = ends_at + interval '1 day'",
      ),
    ).toBe("42501");
    expect(await sqlState(db2.su, "delete from public.commission_periods")).toBe("42501");
    const before = await period("2026-09-30 10:00:00+02");
    const p1 = (
      await db2.su.query(
        "select id from public.commission_period_schedules where label = 'Period 1'",
      )
    ).rows[0].id;
    await asAdmin.query("select public.admin_deactivate_commission_period_schedule($1)", [p1]);
    const stored = await db2.su.query(
      "select ends_at from public.commission_periods where label = 'Period 1' and starts_at = $1",
      [before!.starts],
    );
    expect(new Date(stored.rows[0].ends_at).toISOString()).toBe(before!.ends);
  });

  it("an inactive schedule no longer matches new timestamps", async () => {
    expect(await period("2026-10-07 10:00:00+02")).toBeNull();
  });

  it("schedule management is permission-gated", async () => {
    const emp = await db2.createProfile("employee", "p-emp");
    const c = await db2.as("authenticated", emp);
    expect(
      await sqlState(
        c,
        "select public.admin_save_commission_period_schedule('E', 1::smallint, '00:00', 2::smallint, '00:00', 2::smallint, '00:00')",
      ),
    ).toBe("42501");
    expect(
      await sqlState(
        c,
        "insert into public.commission_period_schedules (label, start_dow, start_time, end_dow, end_time, payout_dow, payout_time) values ('E',1,'00:00',2,'00:00',2,'00:00')",
      ),
    ).toBe("42501");
  });
});

describe("commission periods: payout before window end and daylight saving", () => {
  it("rolls the payout to the following week when it is earlier in the week than the window end", async () => {
    const d = await createTestDb();
    const admin = await d.setupAdmin();
    const a = await d.as("authenticated", admin);
    await a.query(
      "select public.admin_save_commission_period_schedule('Early payout', 1::smallint, '00:00', 3::smallint, '12:00', 1::smallint, '09:00')",
    );
    const svc = await d.as("service_role");
    const r = await svc.query(
      "select payout_at from public.ensure_commission_period('2026-09-29 10:00:00+02'::timestamptz)",
    );
    expect(new Date(r.rows[0].payout_at).toISOString()).toBe("2026-10-05T07:00:00.000Z"); // next Monday 09:00 SAST
    await d.close();
  });

  it("evaluates windows on the wall clock of the configured timezone across a DST change", async () => {
    const d = await createTestDb();
    const admin = await d.setupAdmin({ timezone: "America/New_York" });
    const a = await d.as("authenticated", admin);
    await a.query(
      "select public.admin_save_commission_period_schedule('Weekend', 5::smallint, '14:00', 7::smallint, '18:00', 7::smallint, '20:00')",
    );
    const svc = await d.as("service_role");
    // Week of 2026-03-08: US DST starts Sunday 02:00, so the window's two ends have different UTC offsets.
    const r = await svc.query(
      "select starts_at, ends_at, payout_at from public.ensure_commission_period('2026-03-07 12:00:00-05'::timestamptz)",
    );
    expect(new Date(r.rows[0].starts_at).toISOString()).toBe("2026-03-06T19:00:00.000Z"); // Fri 14:00 EST
    expect(new Date(r.rows[0].ends_at).toISOString()).toBe("2026-03-08T22:00:00.000Z"); //   Sun 18:00 EDT
    expect(new Date(r.rows[0].payout_at).toISOString()).toBe("2026-03-09T00:00:00.000Z"); // Sun 20:00 EDT
    await d.close();
  });

  it("raises configuration_required when the business timezone is not configured", async () => {
    const d = await createTestDb();
    expect(await sqlState(d.su, "select * from app.commission_window_for(now())")).toBe("P0001");
    await d.close();
  });
});
