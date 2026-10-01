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

const day = async (c: pg.Client, ts: string, tz = "Africa/Johannesburg", cutoff = "20:00") =>
  (
    await c.query(
      "select to_char(app.business_day_of($1::timestamptz, $2, $3::time), 'YYYY-MM-DD') as d",
      [ts, tz, cutoff],
    )
  ).rows[0].d as string;

describe("business day cutoff (pure function, explicit timezone + cutoff)", () => {
  // Africa/Johannesburg is UTC+2 with no DST.
  it("19:59 belongs to the CURRENT business day", async () => {
    expect(await day(db.su, "2026-09-30 19:59:00+02")).toBe("2026-09-30");
  });

  it("20:00 belongs to the FOLLOWING business day", async () => {
    expect(await day(db.su, "2026-09-30 20:00:00+02")).toBe("2026-10-01");
  });

  it("is exact to the microsecond at the boundary", async () => {
    expect(await day(db.su, "2026-09-30 19:59:59.999999+02")).toBe("2026-09-30");
    expect(await day(db.su, "2026-09-30 20:00:00.000001+02")).toBe("2026-10-01");
  });

  it("uses the business timezone, not the UTC date or the session timezone", async () => {
    // 17:59:59Z = 19:59:59 local; 18:00:00Z = 20:00:00 local
    expect(await day(db.su, "2026-09-30 17:59:59+00")).toBe("2026-09-30");
    expect(await day(db.su, "2026-09-30 18:00:00+00")).toBe("2026-10-01");
    await db.su.query("set timezone = 'Pacific/Kiritimati'");
    expect(await day(db.su, "2026-09-30 17:59:59+00")).toBe("2026-09-30");
    expect(await day(db.su, "2026-09-30 18:00:00+00")).toBe("2026-10-01");
    await db.su.query("reset timezone");
  });

  it("keeps late evening and early morning of the same night in the same business day", async () => {
    expect(await day(db.su, "2026-09-30 23:59:59+02")).toBe("2026-10-01");
    expect(await day(db.su, "2026-10-01 00:00:00+02")).toBe("2026-10-01");
    expect(await day(db.su, "2026-10-01 19:59:59+02")).toBe("2026-10-01");
    expect(await day(db.su, "2026-10-01 20:00:00+02")).toBe("2026-10-02");
  });

  it("rolls over month, year and leap-day boundaries correctly", async () => {
    expect(await day(db.su, "2026-12-31 20:00:00+02")).toBe("2027-01-01");
    expect(await day(db.su, "2026-12-31 19:59:59+02")).toBe("2026-12-31");
    expect(await day(db.su, "2028-02-28 20:00:00+02")).toBe("2028-02-29");
    expect(await day(db.su, "2028-02-29 20:00:00+02")).toBe("2028-03-01");
  });

  it("supports any configured cutoff, e.g. 20:30", async () => {
    expect(await day(db.su, "2026-09-30 20:29:59+02", "Africa/Johannesburg", "20:30")).toBe(
      "2026-09-30",
    );
    expect(await day(db.su, "2026-09-30 20:30:00+02", "Africa/Johannesburg", "20:30")).toBe(
      "2026-10-01",
    );
  });

  it("follows daylight-saving rules of the configured timezone", async () => {
    // New York: DST starts 2026-03-08 (UTC-5 -> UTC-4).
    expect(await day(db.su, "2026-03-08 19:59:00-04", "America/New_York")).toBe("2026-03-08");
    expect(await day(db.su, "2026-03-08 20:00:00-04", "America/New_York")).toBe("2026-03-09");
    expect(await day(db.su, "2026-03-07 20:00:00-05", "America/New_York")).toBe("2026-03-08");
    // DST ends 2026-11-01 (UTC-4 -> UTC-5).
    expect(await day(db.su, "2026-11-01 19:59:00-05", "America/New_York")).toBe("2026-11-01");
    expect(await day(db.su, "2026-11-01 20:00:00-05", "America/New_York")).toBe("2026-11-02");
  });

  it("rejects missing or invalid configuration instead of guessing", async () => {
    expect(await sqlState(db.su, "select app.business_day_of(now(), null, '20:00')")).toBe("P0001");
    expect(
      await sqlState(db.su, "select app.business_day_of(now(), 'Africa/Johannesburg', null)"),
    ).toBe("P0001");
    expect(await sqlState(db.su, "select app.business_day_of(now(), 'Not/AZone', '20:00')")).toBe(
      "22023",
    );
    expect(
      await sqlState(db.su, "select app.business_day_of(now(), 'Africa/Johannesburg', '00:00')"),
    ).toBe("22023");
  });
});

describe("business day bounds", () => {
  it("spans previous day's cutoff (inclusive) to this day's cutoff (exclusive)", async () => {
    const r = await db.su.query(
      "select b.starts_at, b.ends_at from app.business_day_bounds_of(date '2026-10-01', 'Africa/Johannesburg', '20:00') b",
    );
    expect(new Date(r.rows[0].starts_at).toISOString()).toBe("2026-09-30T18:00:00.000Z");
    expect(new Date(r.rows[0].ends_at).toISOString()).toBe("2026-10-01T18:00:00.000Z");
  });

  it("agrees with business_day_of for every instant (property test across 5 timezones, ~40 days each)", async () => {
    const zones = [
      "Africa/Johannesburg",
      "America/New_York",
      "Australia/Lord_Howe",
      "Asia/Kolkata",
      "Pacific/Auckland",
    ];
    for (const tz of zones) {
      const r = await db.su.query(
        `with t as (
           select ts, app.business_day_of(ts, $1, time '20:00') as d
           from generate_series(timestamptz '2026-03-01 00:00+00', timestamptz '2026-04-10 00:00+00', interval '13 minutes') ts
         )
         select count(*)::int as n,
                count(*) filter (where b.starts_at <= t.ts and t.ts < b.ends_at)::int as ok
         from t, lateral app.business_day_bounds_of(t.d, $1, time '20:00') b`,
        [tz],
      );
      expect(r.rows[0].ok, tz).toBe(r.rows[0].n);
      expect(r.rows[0].n).toBeGreaterThan(4000);
    }
  });

  it("the instant of the cutoff starts the next business day and one microsecond earlier does not", async () => {
    const r = await db.su.query(
      `select app.business_day_of(b.ends_at, 'Africa/Johannesburg', '20:00') as at_end,
              app.business_day_of(b.ends_at - interval '1 microsecond', 'Africa/Johannesburg', '20:00') as before_end
       from app.business_day_bounds_of(date '2026-10-01', 'Africa/Johannesburg', '20:00') b`,
    );
    expect(new Date(r.rows[0].at_end).toISOString().slice(0, 10)).toBe(
      "2026-10-01".replace("10-01", "10-02"),
    );
    expect(new Date(r.rows[0].before_end).toISOString().slice(0, 10)).toBe("2026-10-01");
  });
});

describe("configured business day (reads settings; never the client clock)", () => {
  it("raises configuration_required until the owner has configured timezone and cutoff", async () => {
    expect(await sqlState(db.su, "select app.business_day_for(now())")).toBe("P0001");
    expect(await sqlState(db.su, "select app.current_business_day()")).toBe("P0001");
  });

  it("uses the configured settings once first-run setup is complete", async () => {
    const adminId = await db.setupAdmin();
    const c = await db.as("authenticated", adminId);
    const r = await c.query(
      "select to_char(public.business_day_for('2026-09-30 19:59:59+02'::timestamptz), 'YYYY-MM-DD') a, to_char(public.business_day_for('2026-09-30 20:00:00+02'::timestamptz), 'YYYY-MM-DD') b",
    );
    expect(r.rows[0]).toEqual({ a: "2026-09-30", b: "2026-10-01" });
  });

  it("follows an owner change of the cutoff immediately (nothing hard-coded to 20:00)", async () => {
    const adminId = (await db.su.query("select id from public.profiles where kind='admin'")).rows[0]
      .id;
    const c = await db.as("authenticated", adminId);
    await c.query(
      `select public.admin_update_business_settings('{"business_day_cutoff":"21:15"}')`,
    );
    const r = await c.query(
      "select to_char(public.business_day_for('2026-09-30 20:30:00+02'::timestamptz), 'YYYY-MM-DD') a, to_char(public.business_day_for('2026-09-30 21:15:00+02'::timestamptz), 'YYYY-MM-DD') b",
    );
    expect(r.rows[0]).toEqual({ a: "2026-09-30", b: "2026-10-01" });
    await c.query(
      `select public.admin_update_business_settings('{"business_day_cutoff":"20:00"}')`,
    );
  });

  it("current_business_day uses database time and ignores the session timezone", async () => {
    const adminId = (await db.su.query("select id from public.profiles where kind='admin'")).rows[0]
      .id;
    const c = await db.as("authenticated", adminId);
    const expected = (
      await db.su.query(
        "select to_char(app.business_day_of(now(), 'Africa/Johannesburg', '20:00'), 'YYYY-MM-DD') d",
      )
    ).rows[0].d;
    await c.query("set timezone = 'Pacific/Kiritimati'");
    const got = (await c.query("select to_char(public.current_business_day(), 'YYYY-MM-DD') d"))
      .rows[0].d;
    expect(got).toBe(expected);
  });

  it("is not callable anonymously", async () => {
    const anon = await db.as("anon");
    expect(await sqlState(anon, "select public.current_business_day()")).toBe("42501");
  });

  it("refuses an invalid timezone or a 00:00 cutoff at the settings level", async () => {
    const adminId = (await db.su.query("select id from public.profiles where kind='admin'")).rows[0]
      .id;
    const c = await db.as("authenticated", adminId);
    expect(
      await sqlState(
        c,
        `select public.admin_update_business_settings('{"timezone":"Mars/Olympus"}')`,
      ),
    ).toBe("23514");
    expect(
      await sqlState(
        c,
        `select public.admin_update_business_settings('{"business_day_cutoff":"00:00"}')`,
      ),
    ).toBe("23514");
  });
});
