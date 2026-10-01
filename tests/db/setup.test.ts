import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, sqlState, TEST_SETTINGS, type TestDb } from "./harness";

let db: TestDb;
beforeAll(async () => {
  db = await createTestDb();
});
afterAll(async () => {
  await db.close();
});

const setupCall = (
  adminId: string,
  settings: unknown = TEST_SETTINGS,
  bps = 4000,
  rounding = "half_up",
  channels: unknown = [],
) =>
  [
    "select public.complete_first_run_setup($1, $2, $3::jsonb, $4, $5, $6::jsonb)",
    [adminId, "Owner", JSON.stringify(settings), bps, rounding, JSON.stringify(channels)],
  ] as const;

async function counts(d: TestDb) {
  const r = await d.su.query(`select
    (select count(*)::int from public.profiles) profiles,
    (select count(*)::int from public.user_roles) user_roles,
    (select count(*)::int from public.audit_logs) audit,
    (select count(*)::int from public.commission_configurations) commission,
    (select count(*)::int from public.notification_channel_settings) channels,
    (select setup_completed_at is not null from public.business_settings) done,
    (select business_name from public.business_settings) name`);
  return r.rows[0];
}

describe("first-run setup status (public)", () => {
  it("reports setup incomplete and exposes NO invented branding before setup", async () => {
    const anon = await db.as("anon");
    expect((await anon.query("select public.get_setup_status() s")).rows[0].s).toEqual({
      setup_completed: false,
    });
    const b = (await anon.query("select public.get_public_branding() b")).rows[0].b;
    expect(b).toEqual({
      business_name: null,
      tagline: null,
      logo_url: null,
      primary_color: null,
      setup_completed: false,
    });
  });

  it("anonymous and signed-in users cannot run setup", async () => {
    const id = await db.authUser("rogue");
    const [sql, params] = setupCall(id);
    for (const role of ["anon", "authenticated"] as const) {
      const c = await db.as(role, role === "authenticated" ? id : undefined);
      expect(await sqlState(c, sql, [...params]), role).toBe("42501");
    }
    expect((await counts(db)).profiles).toBe(0);
  });
});

describe("first-run setup is atomic: any failure leaves NOTHING behind", () => {
  const failing: [string, unknown, number, string, string][] = [
    [
      "missing required setting",
      { ...TEST_SETTINGS, business_name: undefined },
      4000,
      "half_up",
      "22023",
    ],
    [
      "unknown / smuggled setting (setup_completed_at)",
      { ...TEST_SETTINGS, setup_completed_at: "2020-01-01" },
      4000,
      "half_up",
      "22023",
    ],
    [
      "smuggled setting (setup_completed_by)",
      { ...TEST_SETTINGS, setup_completed_by: "00000000-0000-0000-0000-000000000000" },
      4000,
      "half_up",
      "22023",
    ],
    [
      "invalid timezone (fails AFTER profile + role were inserted)",
      { ...TEST_SETTINGS, timezone: "Mars/Olympus" },
      4000,
      "half_up",
      "23514",
    ],
    ["commission rate above 100%", TEST_SETTINGS, 10001, "half_up", "23514"],
    ["negative commission rate", TEST_SETTINGS, -5, "half_up", "23514"],
    ["invalid rounding mode", TEST_SETTINGS, 4000, "banana", "22P02"],
    [
      "cart duration of 0",
      { ...TEST_SETTINGS, cart_duration_minutes: 0 },
      4000,
      "half_up",
      "23514",
    ],
    [
      "non-numeric cart duration",
      { ...TEST_SETTINGS, cart_duration_minutes: "soon" },
      4000,
      "half_up",
      "22P02",
    ],
    [
      "lowercase currency code",
      { ...TEST_SETTINGS, currency_code: "zar" },
      4000,
      "half_up",
      "23514",
    ],
  ];
  for (const [name, settings, bps, rounding, code] of failing) {
    it(`rejects: ${name}`, async () => {
      const id = await db.authUser("owner");
      const svc = await db.as("service_role");
      const [sql, params] = setupCall(id, settings, bps, rounding);
      expect(await sqlState(svc, sql, [...params])).toBe(code);
      const c = await counts(db);
      expect(c).toMatchObject({
        profiles: 0,
        user_roles: 0,
        audit: 0,
        commission: 0,
        channels: 0,
        done: false,
        name: null,
      });
    });
  }

  it("rejects a non-existent auth user", async () => {
    const svc = await db.as("service_role");
    const [sql, params] = setupCall("00000000-0000-0000-0000-00000000dead");
    expect(await sqlState(svc, sql, [...params])).toBe("22023");
  });

  it("rejects a bad notification channel list atomically", async () => {
    const id = await db.authUser("owner");
    const svc = await db.as("service_role");
    const [sql, params] = setupCall(id, TEST_SETTINGS, 4000, "half_up", [
      { channel: "carrier_pigeon", enabled: true },
    ]);
    expect(await sqlState(svc, sql, [...params])).toBe("22P02");
    expect((await counts(db)).profiles).toBe(0);
  });
});

describe("first-run setup success", () => {
  let adminId: string;
  it("creates the administrator, settings, commission configuration and channel intent in one transaction", async () => {
    adminId = await db.authUser("owner");
    const svc = await db.as("service_role");
    const [sql, params] = setupCall(
      adminId,
      { ...TEST_SETTINGS, privacy_policy_text: null },
      4000,
      "half_up",
      [
        { channel: "in_app", enabled: true },
        { channel: "whatsapp", enabled: false, provider_label: "undecided" },
      ],
    );
    await svc.query(sql, [...params]);

    const p = (
      await db.su.query("select kind, status, display_name from public.profiles where id = $1", [
        adminId,
      ])
    ).rows[0];
    expect(p).toEqual({ kind: "admin", status: "approved", display_name: "Owner" });
    const role = await db.su.query(
      "select r.key from public.user_roles ur join public.roles r on r.id = ur.role_id where ur.user_id = $1",
      [adminId],
    );
    expect(role.rows).toEqual([{ key: "admin" }]);
    const s = (await db.su.query("select * from public.business_settings")).rows[0];
    expect(s).toMatchObject({
      business_name: "TEST BUSINESS (fixture)",
      timezone: "Africa/Johannesburg",
      currency_code: "ZAR",
      cart_duration_minutes: 15,
      setup_completed_by: adminId,
    });
    expect(s.setup_completed_at).not.toBeNull();
    expect(s.payment_provider_key).toBeNull(); // owner decision left open, not invented
    const cc = (
      await db.su.query(
        "select rate_bps, rounding, created_by from public.commission_configurations",
      )
    ).rows;
    expect(cc).toEqual([{ rate_bps: 4000, rounding: "half_up", created_by: adminId }]);
    const ch = (
      await db.su.query(
        "select channel, enabled from public.notification_channel_settings order by channel",
      )
    ).rows;
    expect(ch).toEqual([
      { channel: "in_app", enabled: true },
      { channel: "whatsapp", enabled: false },
    ]);
  });

  it("writes audit records attributed to the new administrator", async () => {
    const r = await db.su.query(
      "select action, actor_id, actor_source from public.audit_logs order by id",
    );
    const actions = r.rows.map((x) => x.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        "profiles.insert",
        "user_roles.insert",
        "business_settings.update",
        "commission_configurations.insert",
        "setup.completed",
      ]),
    );
    expect(r.rows.every((x) => x.actor_id === adminId && x.actor_source === "service")).toBe(true);
  });

  it("makes the public branding and status reflect the configuration", async () => {
    const anon = await db.as("anon");
    expect((await anon.query("select public.get_setup_status() s")).rows[0].s).toEqual({
      setup_completed: true,
    });
    const b = (await anon.query("select public.get_public_branding() b")).rows[0].b;
    expect(b.business_name).toBe("TEST BUSINESS (fixture)");
    expect(Object.keys(b).sort()).toEqual([
      "business_name",
      "logo_url",
      "primary_color",
      "setup_completed",
      "tagline",
    ]);
  });

  it("cannot be run a second time, and does not create a second administrator", async () => {
    const second = await db.authUser("intruder");
    const svc = await db.as("service_role");
    const [sql, params] = setupCall(second, { ...TEST_SETTINGS, business_name: "Hijacked" });
    expect(await sqlState(svc, sql, [...params])).toBe("55000");
    expect(
      (await db.su.query("select count(*)::int n from public.profiles where kind = 'admin'"))
        .rows[0].n,
    ).toBe(1);
    expect(
      (await db.su.query("select business_name from public.business_settings")).rows[0]
        .business_name,
    ).toBe("TEST BUSINESS (fixture)");
  });

  it("setup_completed_at can never be changed afterwards", async () => {
    expect(
      await sqlState(db.su, "update public.business_settings set setup_completed_at = now()"),
    ).toBe("42501");
    expect(
      await sqlState(db.su, "update public.business_settings set setup_completed_at = null"),
    ).toBe("42501");
  });
});

describe("first-run setup has a single winner under concurrency", () => {
  it("lets exactly one of several simultaneous attempts succeed", async () => {
    const d = await createTestDb();
    const ids = await Promise.all(Array.from({ length: 6 }, (_, i) => d.authUser(`racer${i}`)));
    const clients = await Promise.all(ids.map(() => d.as("service_role")));
    const results = await Promise.allSettled(
      ids.map((id, i) => {
        const [sql, params] = setupCall(id, { ...TEST_SETTINGS, business_name: `Racer ${i}` });
        return clients[i]!.query(sql, [...params]);
      }),
    );
    const ok = results.filter((r) => r.status === "fulfilled");
    const failed = results.filter((r): r is PromiseRejectedResult => r.status === "rejected");
    expect(ok).toHaveLength(1);
    expect(failed).toHaveLength(5);
    expect(failed.every((f) => (f.reason as { code?: string }).code === "55000")).toBe(true);
    const c = await counts(d);
    expect(c).toMatchObject({ profiles: 1, user_roles: 1, commission: 1, done: true });
    const winner = (await d.su.query("select id from public.profiles")).rows[0].id;
    const idx = ids.indexOf(winner);
    expect(c.name).toBe(`Racer ${idx}`);
    await d.close();
  });
});

describe("create_profile (service-only)", () => {
  it("creates customers as pending and employees as approved, and never creates admins", async () => {
    const svc = await db.as("service_role");
    const cust = await db.authUser("c");
    const emp = await db.authUser("e");
    const adm = await db.authUser("a");
    await svc.query("select public.create_profile($1, 'customer', 'Cust', '+27820000001', null)", [
      cust,
    ]);
    await svc.query("select public.create_profile($1, 'employee', 'Emp', null, null)", [emp]);
    const r = await db.su.query(
      "select id, kind, status from public.profiles where id in ($1, $2)",
      [cust, emp],
    );
    const by = Object.fromEntries(r.rows.map((x) => [x.id, x]));
    expect(by[cust]).toMatchObject({ kind: "customer", status: "pending_approval" });
    expect(by[emp]).toMatchObject({ kind: "employee", status: "approved" });
    expect(
      await sqlState(svc, "select public.create_profile($1, 'admin', 'Nope', null, null)", [adm]),
    ).toBe("42501");
  });

  it("is unavailable to anon and authenticated", async () => {
    const id = await db.authUser("x");
    for (const role of ["anon", "authenticated"] as const) {
      const c = await db.as(role, role === "authenticated" ? id : undefined);
      expect(
        await sqlState(c, "select public.create_profile($1, 'customer', 'X', null, null)", [id]),
        role,
      ).toBe("42501");
    }
  });

  it("rejects a duplicate mobile number and a malformed one", async () => {
    const svc = await db.as("service_role");
    const a = await db.authUser("m1");
    const b = await db.authUser("m2");
    await svc.query("select public.create_profile($1, 'customer', 'M1', '+27829990001', null)", [
      a,
    ]);
    expect(
      await sqlState(
        svc,
        "select public.create_profile($1, 'customer', 'M2', '+27829990001', null)",
        [b],
      ),
    ).toBe("23505");
    expect(
      await sqlState(
        svc,
        "select public.create_profile($1, 'customer', 'M2', '0829990002', null)",
        [b],
      ),
    ).toBe("23514");
  });
});

describe("admin_update_business_settings", () => {
  it("validates, whitelists and audits every change", async () => {
    const adminId = (await db.su.query("select id from public.profiles where kind = 'admin'"))
      .rows[0].id;
    const c = await db.as("authenticated", adminId);
    await c.query(
      `select public.admin_update_business_settings('{"business_name":"Renamed","tagline":"A tagline","primary_color":"#112233"}')`,
    );
    const s = (
      await db.su.query(
        "select business_name, tagline, primary_color from public.business_settings",
      )
    ).rows[0];
    expect(s).toEqual({ business_name: "Renamed", tagline: "A tagline", primary_color: "#112233" });

    const a = (
      await db.su.query(
        "select previous_value->>'business_name' prev, new_value->>'business_name' nxt, actor_id, actor_source from public.audit_logs where action = 'business_settings.update' order by id desc limit 1",
      )
    ).rows[0];
    expect(a).toEqual({
      prev: "TEST BUSINESS (fixture)",
      nxt: "Renamed",
      actor_id: adminId,
      actor_source: "user",
    });

    expect(
      await sqlState(
        c,
        `select public.admin_update_business_settings('{"setup_completed_at":null}')`,
      ),
    ).toBe("22023");
    expect(
      await sqlState(c, `select public.admin_update_business_settings('{"singleton":false}')`),
    ).toBe("22023");
    expect(await sqlState(c, `select public.admin_update_business_settings('{}')`)).toBe("22023");
    expect(await sqlState(c, `select public.admin_update_business_settings('[]')`)).toBe("22023");
    expect(
      await sqlState(c, `select public.admin_update_business_settings('{"primary_color":"red"}')`),
    ).toBe("23514");
    expect(
      await sqlState(
        c,
        `select public.admin_update_business_settings('{"cart_duration_minutes":0}')`,
      ),
    ).toBe("23514");
    expect(
      await sqlState(
        c,
        `select public.admin_update_business_settings('{"logo_url":"javascript:alert(1)"}')`,
      ),
    ).toBe("23514");
    expect(
      await sqlState(
        c,
        `select public.admin_update_business_settings('{"payment_provider_key":"Bad Key!"}')`,
      ),
    ).toBe("23514");
  });

  it("cannot blank a required operational setting once setup is complete", async () => {
    const adminId = (await db.su.query("select id from public.profiles where kind = 'admin'"))
      .rows[0].id;
    const c = await db.as("authenticated", adminId);
    for (const k of [
      "business_name",
      "timezone",
      "currency_code",
      "business_day_cutoff",
      "cart_duration_minutes",
    ]) {
      expect(
        await sqlState(c, `select public.admin_update_business_settings('{"${k}":null}')`),
        k,
      ).toBe("23514");
    }
  });

  it("lets the owner set optional values (payment provider key, legal text) and clear them again", async () => {
    const adminId = (await db.su.query("select id from public.profiles where kind = 'admin'"))
      .rows[0].id;
    const c = await db.as("authenticated", adminId);
    await c.query(
      `select public.admin_update_business_settings('{"payment_provider_key":"example_provider","privacy_policy_text":"PLACEHOLDER - legal review required","consent_required":true}')`,
    );
    const s = (
      await db.su.query(
        "select payment_provider_key, privacy_policy_text, consent_required from public.business_settings",
      )
    ).rows[0];
    expect(s.payment_provider_key).toBe("example_provider");
    await c.query(`select public.admin_update_business_settings('{"payment_provider_key":null}')`);
    expect(
      (await db.su.query("select payment_provider_key from public.business_settings")).rows[0]
        .payment_provider_key,
    ).toBeNull();
  });

  it("toggles notification channel intent only with notifications.manage", async () => {
    const adminId = (await db.su.query("select id from public.profiles where kind = 'admin'"))
      .rows[0].id;
    const c = await db.as("authenticated", adminId);
    await c.query("select public.admin_set_notification_channel('email', true, 'undecided')");
    expect(
      (
        await db.su.query(
          "select enabled from public.notification_channel_settings where channel = 'email'",
        )
      ).rows[0].enabled,
    ).toBe(true);
    const emp = await db.createProfile("employee", "chan-emp");
    const e = await db.as("authenticated", emp);
    expect(await sqlState(e, "select public.admin_set_notification_channel('sms', true)")).toBe(
      "42501",
    );
  });
});
