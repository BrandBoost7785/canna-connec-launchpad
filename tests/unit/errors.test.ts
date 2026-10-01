import { afterEach, describe, expect, it, vi } from "vitest";
import { AppError, codeFromSqlState, publicMessage, toAppError } from "@/lib/errors";

afterEach(() => vi.restoreAllMocks());

describe("SQLSTATE mapping", () => {
  it.each([
    ["42501", "forbidden", 403],
    ["22023", "invalid_input", 400],
    ["23514", "invalid_input", 400],
    ["P0002", "not_found", 404],
    ["23505", "conflict", 409],
    ["55000", "state_conflict", 409],
    ["P0001", "configuration_required", 503],
    ["XX000", "internal", 500],
  ])("%s -> %s (%i)", (state, code, status) => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(codeFromSqlState(state)).toBe(code);
    expect(toAppError({ code: state, message: "x" }).status).toBe(status);
  });
});

describe("safe error messages", () => {
  it("never leaks the raw database message, constraint or SQL", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const raw = {
      code: "XX000",
      message: 'relation "access_credentials" secret_hash violates constraint "x_pkey"',
    };
    const e = toAppError(raw);
    expect(e.message).toBe(publicMessage("internal"));
    expect(e.message).not.toMatch(/access_credentials|secret_hash|constraint|relation/);
  });
  it("logs unexpected errors server-side", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    toAppError(new Error("boom"), "ctx");
    expect(spy).toHaveBeenCalled();
  });
  it("passes AppError through unchanged and carries retry-after", () => {
    const e = new AppError("rate_limited", 42);
    expect(toAppError(e)).toBe(e);
    expect(e.retryAfterSeconds).toBe(42);
    expect(e.status).toBe(429);
  });
  it("handles non-object throwables", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(toAppError("string").code).toBe("internal");
    expect(toAppError(null).code).toBe("internal");
  });
});
