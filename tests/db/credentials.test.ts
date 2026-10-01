import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, sqlState, type TestDb } from "./harness";

let db: TestDb;
let svc: pg.Client;
const HASH = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA";
beforeAll(async () => {
  db = await createTestDb();
  await db.setupAdmin();
  svc = await db.as("service_role");
});
afterAll(async () => {
  await db.close();
});

describe("Client Codes", () => {
  it("are non-predictable, correctly formatted and unique across many customers", async () => {
    const ids: string[] = [];
    // TEST FIXTURE customers, created only inside this throw-away database.
    for (let i = 0; i < 150; i++) ids.push(await db.createProfile("customer", `cc${i}`));
    const codes: string[] = [];
    for (const id of ids)
      codes.push((await svc.query("select public.issue_client_code($1) c", [id])).rows[0].c);
    expect(new Set(codes).size).toBe(150);
    for (const c of codes)
      expect(c).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    // Not sequential/sorted: a predictable generator would produce (almost) monotonic codes.
    const sorted = [...codes].sort();
    expect(codes).not.toEqual(sorted);
    // Uses the whole alphabet (sanity check on the modulo mapping).
    const symbols = new Set(codes.join("").replace(/-/g, "").split(""));
    expect(symbols.size).toBeGreaterThanOrEqual(30);
    // Never exposes an internal id: code shares nothing with the user's uuid.
    const r = await db.su.query(
      "select user_id::text u, client_code c from public.client_codes limit 20",
    );
    for (const row of r.rows)
      expect(row.u.replace(/-/g, "").toUpperCase()).not.toContain(row.c.replace(/-/g, ""));
  });

  it("are issued to customers only, once while active", async () => {
    const cust = await db.createProfile("customer", "once");
    const emp = await db.createProfile("employee", "emp-nocode");
    await svc.query("select public.issue_client_code($1)", [cust]);
    expect(await sqlState(svc, "select public.issue_client_code($1)", [cust])).toBe("23505");
    expect(await sqlState(svc, "select public.issue_client_code($1)", [emp])).toBe("42501");
    expect(
      await sqlState(
        svc,
        "select public.issue_client_code('00000000-0000-0000-0000-000000000000')",
      ),
    ).toBe("42501");
  });

  it("are immutable and never deleted; a revoked code is kept and never re-issued", async () => {
    const cust = await db.createProfile("customer", "revoke");
    const code = (await svc.query("select public.issue_client_code($1) c", [cust])).rows[0].c;
    expect(
      await sqlState(
        db.su,
        "update public.client_codes set client_code = 'AAAA-AAAA-AAAA' where user_id = $1",
        [cust],
      ),
    ).toBe("42501");
    expect(
      await sqlState(db.su, "delete from public.client_codes where user_id = $1", [cust]),
    ).toBe("42501");
    await db.su.query("update public.client_codes set revoked_at = now() where user_id = $1", [
      cust,
    ]);
    expect(
      await sqlState(db.su, "update public.client_codes set revoked_at = null where user_id = $1", [
        cust,
      ]),
    ).toBe("42501");
    // revoked code cannot be attached to anyone again
    const other = await db.createProfile("customer", "revoke-other");
    expect(
      await sqlState(
        db.su,
        "insert into public.client_codes (user_id, client_code) values ($1, $2)",
        [other, code],
      ),
    ).toBe("23505");
    // the customer can be issued a replacement
    const replacement = (await svc.query("select public.issue_client_code($1) c", [cust])).rows[0]
      .c;
    expect(replacement).not.toBe(code);
  });

  it("rejects malformed codes at the database level", async () => {
    const cust = await db.createProfile("customer", "badformat");
    for (const bad of [
      "abcd-efgh-ijkl",
      "AAAA-AAAA",
      "AAAA-AAAA-AAAI",
      "AAAAAAAAAAAA",
      "AAAA-AAAA-AAAA-AAAA",
    ]) {
      expect(
        await sqlState(
          db.su,
          "insert into public.client_codes (user_id, client_code) values ($1, $2)",
          [cust, bad],
        ),
        bad,
      ).toBe("23514");
    }
  });

  it("are not readable through the credential lookup once revoked", async () => {
    const cust = await db.createProfile("customer", "lookup");
    const code = (await svc.query("select public.issue_client_code($1) c", [cust])).rows[0].c;
    await svc.query("select public.set_access_secret($1, $2)", [cust, HASH]);
    expect(
      (await svc.query("select * from public.get_quick_login_credential($1)", [code])).rowCount,
    ).toBe(1);
    await db.su.query("update public.client_codes set revoked_at = now() where user_id = $1", [
      cust,
    ]);
    expect(
      (await svc.query("select * from public.get_quick_login_credential($1)", [code])).rowCount,
    ).toBe(0);
  });
});

describe("Secret Access Codes (stored only as a hash)", () => {
  let cust: string;
  let code: string;
  beforeAll(async () => {
    cust = await db.createProfile("customer", "secret");
    code = (await svc.query("select public.issue_client_code($1) c", [cust])).rows[0].c;
  });

  it("rejects values that are not an Argon2id hash (no plaintext storage)", async () => {
    expect(
      await sqlState(svc, "select public.set_access_secret($1, 'my-plain-secret-123')", [cust]),
    ).toBe("23514");
    expect(
      await sqlState(svc, "select public.set_access_secret($1, '$2b$12$bcryptlookingvalue')", [
        cust,
      ]),
    ).toBe("23514");
  });

  it("only customers can have a Secret Access Code", async () => {
    const emp = await db.createProfile("employee", "emp-secret");
    expect(await sqlState(svc, "select public.set_access_secret($1, $2)", [emp, HASH])).toBe(
      "P0002",
    );
  });

  it("stores the hash and returns it only to the service role", async () => {
    await svc.query("select public.set_access_secret($1, $2)", [cust, HASH]);
    const r = await svc.query("select * from public.get_quick_login_credential($1)", [code]);
    expect(r.rows[0]).toMatchObject({
      user_id: cust,
      secret_hash: HASH,
      status: "pending_approval",
      locked_until: null,
    });
    expect(
      (await svc.query("select * from public.get_quick_login_credential('ZZZZ-ZZZZ-ZZZZ')"))
        .rowCount,
    ).toBe(0);
  });

  it("is unreachable for customers, employees, admins and anonymous callers", async () => {
    const admin = (await db.su.query("select id from public.profiles where kind='admin'")).rows[0]
      .id;
    for (const [role, uid] of [
      ["anon", undefined],
      ["authenticated", cust],
      ["authenticated", admin],
    ] as const) {
      const c = await db.as(role, uid);
      expect(await sqlState(c, "select * from public.access_credentials"), `${role} table`).toBe(
        "42501",
      );
      expect(
        await sqlState(c, "select * from public.get_quick_login_credential($1)", [code]),
        `${role} lookup`,
      ).toBe("42501");
      expect(
        await sqlState(c, "select public.set_access_secret($1, $2)", [cust, HASH]),
        `${role} set`,
      ).toBe("42501");
      expect(
        await sqlState(c, "select public.record_quick_login_attempt($1, true)", [cust]),
        `${role} record`,
      ).toBe("42501");
      expect(
        await sqlState(c, "select public.issue_client_code($1)", [cust]),
        `${role} issue`,
      ).toBe("42501");
    }
  });

  it("locks after the configured number of failures, and a success clears the counter", async () => {
    await svc.query("select public.set_access_secret($1, $2)", [cust, HASH]);
    const a = (await svc.query("select public.record_quick_login_attempt($1, false) r", [cust]))
      .rows[0].r;
    expect(a).toMatchObject({ failed_attempts: 1, locked_until: null });
    await svc.query("select public.record_quick_login_attempt($1, false)", [cust]);
    const c = (await svc.query("select public.record_quick_login_attempt($1, false) r", [cust]))
      .rows[0].r;
    expect(c.failed_attempts).toBe(3);
    const lockedUntil = new Date(c.locked_until).getTime();
    expect(lockedUntil).toBeGreaterThan(Date.now() + 800_000);
    expect(lockedUntil).toBeLessThan(Date.now() + 1_000_000);
    const look = await svc.query("select locked_until from public.get_quick_login_credential($1)", [
      code,
    ]);
    expect(look.rows[0].locked_until).not.toBeNull();

    await svc.query("select public.record_quick_login_attempt($1, true)", [cust]);
    const after = (
      await db.su.query(
        "select failed_attempts, locked_until, last_success_at from public.access_credentials where user_id = $1",
        [cust],
      )
    ).rows[0];
    expect(after.failed_attempts).toBe(0);
    expect(after.locked_until).toBeNull();
    expect(after.last_success_at).not.toBeNull();
  });

  it("rotating the secret clears any lock", async () => {
    for (let i = 0; i < 3; i++)
      await svc.query("select public.record_quick_login_attempt($1, false)", [cust]);
    await svc.query("select public.set_access_secret($1, $2)", [cust, HASH + "x"]);
    const r = (
      await db.su.query(
        "select failed_attempts, locked_until from public.access_credentials where user_id = $1",
        [cust],
      )
    ).rows[0];
    expect(r).toEqual({ failed_attempts: 0, locked_until: null });
  });

  it("validates its arguments and unknown users", async () => {
    expect(await sqlState(svc, "select public.record_quick_login_attempt($1, null)", [cust])).toBe(
      "22023",
    );
    expect(await sqlState(svc, "select public.record_quick_login_attempt(null, false)")).toBe(
      "22023",
    );
    expect(
      await sqlState(
        svc,
        "select public.record_quick_login_attempt('00000000-0000-0000-0000-000000000000', false)",
      ),
    ).toBe("P0002");
  });

  it("takes lockout limits ONLY from the owner's configuration, never from the caller", async () => {
    // the old four-argument form (caller-supplied limits) no longer exists
    expect(
      await sqlState(svc, "select public.record_quick_login_attempt($1, false, 1000, 1)", [cust]),
    ).toBe("42883");
    // changing the configured policy changes behaviour
    const admin = (await db.su.query("select id from public.profiles where kind='admin'")).rows[0]
      .id;
    const ac = await db.asNew("authenticated", admin);
    await ac.query(
      `select public.admin_update_business_settings('{"login_max_failed_attempts":1}')`,
    );
    const victim = await db.createProfile("customer", "policy-victim");
    await svc.query("select public.set_access_secret($1, $2)", [victim, HASH]);
    const r = (await svc.query("select public.record_quick_login_attempt($1, false) r", [victim]))
      .rows[0].r;
    expect(r.locked_until).not.toBeNull();
    await ac.query(
      `select public.admin_update_business_settings('{"login_max_failed_attempts":3}')`,
    );
  });

  it("only applies to live accounts: an archived customer cannot be looked up", async () => {
    await db.su.query("update public.profiles set archived_at = now() where id = $1", [cust]);
    expect(
      (await svc.query("select * from public.get_quick_login_credential($1)", [code])).rowCount,
    ).toBe(0);
    await db.su.query("update public.profiles set archived_at = null where id = $1", [cust]);
  });

  it("failed-attempt counting is atomic under concurrent guessing", async () => {
    const victim = await db.createProfile("customer", "concurrent-victim");
    await svc.query("select public.set_access_secret($1, $2)", [victim, HASH]);
    const clients = await Promise.all(Array.from({ length: 12 }, () => db.asNew("service_role")));
    await Promise.all(
      clients.map((c) => c.query("select public.record_quick_login_attempt($1, false)", [victim])),
    );
    const r = (
      await db.su.query(
        "select failed_attempts from public.access_credentials where user_id = $1",
        [victim],
      )
    ).rows[0];
    expect(r.failed_attempts).toBe(12);
  });
});

describe("login identifier resolution (service-only)", () => {
  it("resolves by email (case-insensitive) and by mobile, and not by anything else", async () => {
    const id = await db.authUser("resolve");
    await db.su.query("update auth.users set email = 'Resolve.Me@Test.Invalid' where id = $1", [
      id,
    ]);
    await svc.query("select public.create_profile($1, 'customer', 'R', '+27821112222', null)", [
      id,
    ]);
    const byEmail = await svc.query(
      "select * from public.resolve_login_identifier('resolve.me@test.invalid')",
    );
    expect(byEmail.rows[0]).toMatchObject({
      user_id: id,
      status: "pending_approval",
      kind: "customer",
    });
    const byMobile = await svc.query(
      "select * from public.resolve_login_identifier('+27821112222')",
    );
    expect(byMobile.rows[0].user_id).toBe(id);
    expect(
      (await svc.query("select * from public.resolve_login_identifier('+27829999999')")).rowCount,
    ).toBe(0);
    expect((await svc.query("select * from public.resolve_login_identifier('%@%')")).rowCount).toBe(
      0,
    );
    expect((await svc.query("select * from public.resolve_login_identifier('')")).rowCount).toBe(0);
  });

  it("is not callable by API roles (prevents account enumeration)", async () => {
    const anon = await db.as("anon");
    const auth = await db.as("authenticated", await db.authUser("enum"));
    expect(
      await sqlState(anon, "select * from public.resolve_login_identifier('+27821112222')"),
    ).toBe("42501");
    expect(
      await sqlState(auth, "select * from public.resolve_login_identifier('+27821112222')"),
    ).toBe("42501");
  });
});

describe("rate limiting (shared, database-backed)", () => {
  const hit = async (c: pg.Client, key: string, limit: number, window: number) =>
    (await c.query("select public.rate_limit_hit($1, $2, $3) r", [key, limit, window])).rows[0]
      .r as { allowed: boolean; remaining: number; retry_after_seconds: number };

  it("allows up to the limit then denies, with a retry hint", async () => {
    const key = "test:basic";
    const results = [];
    for (let i = 0; i < 5; i++) results.push(await hit(svc, key, 3, 3600));
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false, false]);
    expect(results.map((r) => r.remaining)).toEqual([2, 1, 0, 0, 0]);
    expect(results[3]!.retry_after_seconds).toBeGreaterThanOrEqual(1);
    expect(results[3]!.retry_after_seconds).toBeLessThanOrEqual(3600);
  });

  it("keeps keys independent", async () => {
    await hit(svc, "test:a", 1, 3600);
    expect((await hit(svc, "test:a", 1, 3600)).allowed).toBe(false);
    expect((await hit(svc, "test:b", 1, 3600)).allowed).toBe(true);
  });

  it("starts a new window after the old one ends", async () => {
    const key = "test:window";
    expect((await hit(svc, key, 1, 1)).allowed).toBe(true);
    expect((await hit(svc, key, 1, 1)).allowed).toBe(false);
    await new Promise((r) => setTimeout(r, 1200));
    expect((await hit(svc, key, 1, 1)).allowed).toBe(true);
  });

  it("is atomic: 25 simultaneous requests with limit 5 allow exactly 5", async () => {
    const clients = await Promise.all(Array.from({ length: 25 }, () => db.asNew("service_role")));
    const rs = await Promise.all(clients.map((c) => hit(c, "test:race", 5, 3600)));
    expect(rs.filter((r) => r.allowed)).toHaveLength(5);
    const stored = (
      await db.su.query("select hits from public.rate_limits where key = 'test:race'")
    ).rows[0].hits;
    expect(stored).toBe(25);
  });

  it("validates its arguments", async () => {
    expect(await sqlState(svc, "select public.rate_limit_hit('', 5, 60)")).toBe("22023");
    expect(await sqlState(svc, "select public.rate_limit_hit('k', 0, 60)")).toBe("22023");
    expect(await sqlState(svc, "select public.rate_limit_hit('k', 5, 0)")).toBe("22023");
    expect(await sqlState(svc, "select public.rate_limit_hit('k', 5, 999999)")).toBe("22023");
    expect(await sqlState(svc, "select public.rate_limit_hit($1, 5, 60)", ["x".repeat(201)])).toBe(
      "22023",
    );
  });

  it("cannot be called, read or reset by API roles", async () => {
    const auth = await db.as("authenticated", await db.authUser("rl"));
    const anon = await db.as("anon");
    for (const c of [auth, anon]) {
      expect(await sqlState(c, "select public.rate_limit_hit('k', 5, 60)")).toBe("42501");
      expect(await sqlState(c, "delete from public.rate_limits")).toBe("42501");
      expect(await sqlState(c, "select * from public.rate_limits")).toBe("42501");
    }
  });
});
