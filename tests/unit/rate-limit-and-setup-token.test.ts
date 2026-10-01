import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/integrations/supabase/client.server", () => ({ supabaseAdmin: {} }));
vi.mock("@tanstack/react-start/server", () => ({ getRequestHeader: () => undefined }));

import { AppError } from "@/lib/errors";
import { enforceRateLimit, rateLimitKey } from "@/server/rate-limit.server";
import { secretsMatch } from "@/server/setup.server";
import { getSetupRateLimit, securityPolicySchema } from "@/server/security-policy.server";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("rate-limit keys", () => {
  const secret = "s".repeat(40);
  it("are deterministic HMACs that do not contain the raw subject", async () => {
    const a = await rateLimitKey("ql-ip", "203.0.113.9", secret);
    expect(a).toBe(await rateLimitKey("ql-ip", "203.0.113.9", secret));
    expect(a).toMatch(/^ql-ip:[0-9a-f]{64}$/);
    expect(a).not.toContain("203.0.113.9");
  });
  it("differ by scope, subject and secret", async () => {
    const base = await rateLimitKey("a", "x", secret);
    expect(await rateLimitKey("b", "x", secret)).not.toBe(base);
    expect(await rateLimitKey("a", "y", secret)).not.toBe(base);
    expect(await rateLimitKey("a", "x", "z".repeat(40))).not.toBe(base);
  });
});

describe("rate limiter fails closed", () => {
  it("refuses when RATE_LIMIT_KEY_SECRET is missing", async () => {
    vi.stubEnv("RATE_LIMIT_KEY_SECRET", "");
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(enforceRateLimit("s", "x", { limit: 1, windowSeconds: 1 })).rejects.toMatchObject({
      code: "configuration_required",
    });
  });
  it("refuses when the secret is too short", async () => {
    vi.stubEnv("RATE_LIMIT_KEY_SECRET", "short");
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(enforceRateLimit("s", "x", { limit: 1, windowSeconds: 1 })).rejects.toBeInstanceOf(
      AppError,
    );
  });
  it("refuses (does not allow) when the limiter backend is unreachable", async () => {
    vi.stubEnv("RATE_LIMIT_KEY_SECRET", "k".repeat(40));
    vi.spyOn(console, "error").mockImplementation(() => {});
    // supabaseAdmin is an empty stub => rpc is not a function => backend failure
    await expect(enforceRateLimit("s", "x", { limit: 1, windowSeconds: 1 })).rejects.toMatchObject({
      code: "internal",
    });
  });
});

describe("setup token comparison", () => {
  it("matches only identical tokens", async () => {
    const t = "x".repeat(48);
    expect(await secretsMatch(t, t)).toBe(true);
    expect(await secretsMatch(t + "a", t)).toBe(false);
    expect(await secretsMatch("", t)).toBe(false);
    expect(await secretsMatch("y".repeat(48), t)).toBe(false);
  });
});

describe("setup throttle is deployment-configured, with no built-in default", () => {
  it("is refused (setup disabled) unless both values are valid positive integers", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    for (const [a, w] of [
      ["", ""],
      ["5", ""],
      ["", "60"],
      ["0", "60"],
      ["5", "0"],
      ["abc", "60"],
      ["1.5", "60"],
      ["5", "86401"],
    ]) {
      vi.stubEnv("SETUP_RATE_LIMIT_ATTEMPTS", a);
      vi.stubEnv("SETUP_RATE_LIMIT_WINDOW_SECONDS", w);
      expect(() => getSetupRateLimit(), `${a}/${w}`).toThrowError(
        /configuration|required|Something|configured/i,
      );
    }
  });
  it("returns exactly what the deployer configured", () => {
    vi.stubEnv("SETUP_RATE_LIMIT_ATTEMPTS", "7");
    vi.stubEnv("SETUP_RATE_LIMIT_WINDOW_SECONDS", "123");
    expect(getSetupRateLimit()).toEqual({ limit: 7, windowSeconds: 123 });
  });
});

describe("security policy schema", () => {
  const ok = {
    login_max_failed_attempts: 1,
    login_lock_seconds: 1,
    rate_limit_login_ip_attempts: 1,
    rate_limit_login_ip_window_seconds: 1,
    rate_limit_login_code_attempts: 1,
    rate_limit_login_code_window_seconds: 1,
    secret_code_min_length: 1,
  };
  it("accepts a complete policy and rejects missing, null, zero or non-integer values", () => {
    expect(securityPolicySchema.safeParse(ok).success).toBe(true);
    for (const k of Object.keys(ok)) {
      expect(securityPolicySchema.safeParse({ ...ok, [k]: null }).success, `${k} null`).toBe(false);
      expect(securityPolicySchema.safeParse({ ...ok, [k]: 0 }).success, `${k} 0`).toBe(false);
      expect(securityPolicySchema.safeParse({ ...ok, [k]: 1.5 }).success, `${k} 1.5`).toBe(false);
      const { [k as keyof typeof ok]: _omit, ...rest } = ok;
      expect(securityPolicySchema.safeParse(rest).success, `${k} omitted`).toBe(false);
    }
  });
});
