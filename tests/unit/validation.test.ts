import { describe, expect, it } from "vitest";
import {
  clientCodeSchema,
  currencyCodeSchema,
  firstRunSetupSchema,
  isValidTimeZone,
  MAX_SECRET_CODE_LENGTH,
  secretCodeSchemaFor,
  mobileE164Schema,
  passwordLoginSchema,
  quickLoginSchema,
  timeOfDaySchema,
} from "@/lib/validation";

// TEST FIXTURE values only (no real business, person or credential).
const validSetup = () => ({
  setupToken: "t".repeat(40),
  admin: {
    displayName: "Test Admin",
    email: "Admin@Example.INVALID",
    password: "correct horse battery",
  },
  settings: {
    business_name: "TEST BUSINESS",
    timezone: "Africa/Johannesburg",
    currency_code: "ZAR",
    business_day_cutoff: "20:00",
    cart_duration_minutes: 15,
    low_stock_default_threshold: 5,
    availability_check_minutes: 5,
    hide_out_of_stock_enabled: true,
    hide_out_of_stock_after_minutes: 60,
    // security policy: TEST FIXTURE values only
    login_max_failed_attempts: 3,
    login_lock_seconds: 900,
    rate_limit_login_ip_attempts: 20,
    rate_limit_login_ip_window_seconds: 600,
    rate_limit_login_code_attempts: 10,
    rate_limit_login_code_window_seconds: 900,
    secret_code_min_length: 8,
  },
  commission: { rateBps: 1000, rounding: "half_up" },
  notificationChannels: [],
});

describe("primitive validators", () => {
  it("accepts and normalises a Client Code", () => {
    expect(clientCodeSchema.parse(" 7k2m-9xq4-hh3p ")).toBe("7K2M-9XQ4-HH3P");
  });
  it.each([
    "",
    "AAAA-AAAA",
    "AAAA-AAAA-AAAI",
    "AAAA-AAAA-AAAA-AAAA",
    "aaaa_aaaa_aaaa",
    "'; drop table x;--",
  ])("rejects malformed Client Code %j", (v) =>
    expect(clientCodeSchema.safeParse(v).success).toBe(false),
  );
  it.each(["+27821234567", "+14155552671"])("accepts E.164 %s", (v) =>
    expect(mobileE164Schema.safeParse(v).success).toBe(true),
  );
  it.each(["0821234567", "+0821234567", "+27 82 123 4567", "27821234567", "+1234567"])(
    "rejects non-E.164 %s",
    (v) => expect(mobileE164Schema.safeParse(v).success).toBe(false),
  );
  it("validates IANA time zones", () => {
    expect(isValidTimeZone("Africa/Johannesburg")).toBe(true);
    expect(isValidTimeZone("America/New_York")).toBe(true);
    expect(isValidTimeZone("Mars/Olympus")).toBe(false);
    expect(isValidTimeZone("")).toBe(false);
  });
  it("validates times of day", () => {
    expect(timeOfDaySchema.safeParse("20:00").success).toBe(true);
    expect(timeOfDaySchema.safeParse("24:00").success).toBe(false);
    expect(timeOfDaySchema.safeParse("8:00").success).toBe(false);
  });
  it("requires an upper-case ISO currency code", () => {
    expect(currencyCodeSchema.safeParse("ZAR").success).toBe(true);
    expect(currencyCodeSchema.safeParse("zar").success).toBe(false);
    expect(currencyCodeSchema.safeParse("ZARR").success).toBe(false);
  });
});

describe("login schemas", () => {
  it("quick login needs a well-formed code and a non-empty bounded secret (NO minimum length at login)", () => {
    expect(
      quickLoginSchema.safeParse({ clientCode: "7K2M-9XQ4-HH3P", secretCode: "x" }).success,
    ).toBe(true);
    expect(
      quickLoginSchema.safeParse({ clientCode: "7K2M-9XQ4-HH3P", secretCode: "" }).success,
    ).toBe(false);
    expect(
      quickLoginSchema.safeParse({
        clientCode: "7K2M-9XQ4-HH3P",
        secretCode: "x".repeat(MAX_SECRET_CODE_LENGTH + 1),
      }).success,
    ).toBe(false);
    expect(quickLoginSchema.safeParse({ clientCode: "bad", secretCode: "12345678" }).success).toBe(
      false,
    );
  });
  it("secret creation uses the OWNER-configured minimum and has no built-in default", () => {
    expect(secretCodeSchemaFor(12).safeParse("x".repeat(11)).success).toBe(false);
    expect(secretCodeSchemaFor(12).safeParse("x".repeat(12)).success).toBe(true);
    expect(secretCodeSchemaFor(1).safeParse("x").success).toBe(true);
    for (const bad of [0, -1, 1.5, 129, Number.NaN, undefined as unknown as number])
      expect(() => secretCodeSchemaFor(bad)).toThrow();
  });
  it("rejects unknown keys, so a client cannot smuggle in extra fields such as a role", () => {
    const r = quickLoginSchema.safeParse({
      clientCode: "7K2M-9XQ4-HH3P",
      secretCode: "12345678",
      role: "admin",
    });
    expect(r.success).toBe(false);
    const p = passwordLoginSchema.safeParse({
      identifier: "a@b.co",
      password: "12345678",
      kind: "admin",
    });
    expect(p.success).toBe(false);
  });
  it("password login accepts an email or an E.164 mobile", () => {
    expect(
      passwordLoginSchema.safeParse({ identifier: "a@example.com", password: "12345678" }).success,
    ).toBe(true);
    expect(
      passwordLoginSchema.safeParse({ identifier: "+27821234567", password: "12345678" }).success,
    ).toBe(true);
    expect(
      passwordLoginSchema.safeParse({ identifier: "not valid", password: "12345678" }).success,
    ).toBe(false);
  });
});

describe("first-run setup schema", () => {
  it("accepts a complete, valid submission and normalises the email", () => {
    const r = firstRunSetupSchema.parse(validSetup());
    expect(r.admin.email).toBe("admin@example.invalid");
  });

  it("supplies NO defaults: every business value is required", () => {
    for (const key of Object.keys(validSetup().settings)) {
      const s = validSetup();
      delete (s.settings as Record<string, unknown>)[key];
      expect(firstRunSetupSchema.safeParse(s).success, `settings.${key} must be required`).toBe(
        false,
      );
    }
    for (const key of [
      "login_max_failed_attempts",
      "login_lock_seconds",
      "rate_limit_login_ip_attempts",
      "rate_limit_login_ip_window_seconds",
      "rate_limit_login_code_attempts",
      "rate_limit_login_code_window_seconds",
      "secret_code_min_length",
    ])
      expect(Object.keys(validSetup().settings)).toContain(key);
    const noCommission = validSetup() as Record<string, unknown>;
    delete noCommission["commission"];
    expect(firstRunSetupSchema.safeParse(noCommission).success).toBe(false);
  });

  it("rejects browser-supplied privilege, status and unknown fields at every level", () => {
    const cases: Record<string, unknown>[] = [
      { ...validSetup(), role: "admin" },
      { ...validSetup(), admin: { ...validSetup().admin, permissions: ["*"] } },
      { ...validSetup(), admin: { ...validSetup().admin, status: "approved" } },
      { ...validSetup(), settings: { ...validSetup().settings, setup_completed_at: "2020-01-01" } },
      { ...validSetup(), commission: { ...validSetup().commission, effective_from: "1970-01-01" } },
    ];
    for (const c of cases) expect(firstRunSetupSchema.safeParse(c).success).toBe(false);
  });

  it.each([
    ["timezone", "Mars/Olympus"],
    ["currency_code", "zar"],
    ["business_day_cutoff", "25:00"],
    ["cart_duration_minutes", 0],
    ["cart_duration_minutes", 15.5],
    ["cart_duration_minutes", 100000],
    ["low_stock_default_threshold", -1],
    ["business_name", "   "],
    ["hide_out_of_stock_enabled", "yes"],
  ])("rejects invalid settings.%s = %j", (key, value) => {
    const s = validSetup();
    (s.settings as Record<string, unknown>)[key] = value;
    expect(firstRunSetupSchema.safeParse(s).success).toBe(false);
  });

  it.each([-1, 10001, 12.5, Number.NaN])("rejects commission rate %s", (rateBps) => {
    const s = validSetup();
    s.commission.rateBps = rateBps;
    expect(firstRunSetupSchema.safeParse(s).success).toBe(false);
  });
  it("rejects an unknown rounding mode and a short password", () => {
    const a = validSetup();
    (a.commission as Record<string, unknown>)["rounding"] = "banana";
    expect(firstRunSetupSchema.safeParse(a).success).toBe(false);
    // password strength is the authentication service's policy, not invented here
    const b = validSetup();
    b.admin.password = "";
    expect(firstRunSetupSchema.safeParse(b).success).toBe(false);
    b.admin.password = "x".repeat(129);
    expect(firstRunSetupSchema.safeParse(b).success).toBe(false);
  });
});
