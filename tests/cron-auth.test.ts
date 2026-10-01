import { afterEach, describe, expect, it, vi } from "vitest";
import { authenticateCronRequest } from "@/integrations/supabase/cron-auth";

// Exercises the real bearer-secret check used to protect scheduled-job endpoints.
// No network, no database: this is a pure request/response unit test.
const SECRET = "test-only-current-secret";
const PREVIOUS = "test-only-previous-secret";

function requestWith(authorization?: string) {
  const headers = new Headers();
  if (authorization !== undefined) headers.set("authorization", authorization);
  return new Request("https://example.test/cron", { headers });
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("authenticateCronRequest", () => {
  it("fails closed with 500 when no cron secret is configured", async () => {
    vi.stubEnv("LOVABLE_CRON_SECRET", "");
    const res = await authenticateCronRequest(requestWith(`Bearer ${SECRET}`));
    expect(res?.status).toBe(500);
  });

  it("returns 401 when the Authorization header is missing", async () => {
    vi.stubEnv("LOVABLE_CRON_SECRET", SECRET);
    const res = await authenticateCronRequest(requestWith());
    expect(res?.status).toBe(401);
  });

  it("returns 401 for a non-Bearer scheme", async () => {
    vi.stubEnv("LOVABLE_CRON_SECRET", SECRET);
    const res = await authenticateCronRequest(requestWith(`Basic ${SECRET}`));
    expect(res?.status).toBe(401);
  });

  it("returns 401 for a wrong token", async () => {
    vi.stubEnv("LOVABLE_CRON_SECRET", SECRET);
    const res = await authenticateCronRequest(requestWith("Bearer not-the-secret"));
    expect(res?.status).toBe(401);
  });

  it("allows the request (returns null) for the current secret", async () => {
    vi.stubEnv("LOVABLE_CRON_SECRET", SECRET);
    expect(await authenticateCronRequest(requestWith(`Bearer ${SECRET}`))).toBeNull();
  });

  it("allows the previous secret during rotation", async () => {
    vi.stubEnv("LOVABLE_CRON_SECRET", SECRET);
    vi.stubEnv("LOVABLE_CRON_SECRET_PREVIOUS", PREVIOUS);
    expect(await authenticateCronRequest(requestWith(`Bearer ${PREVIOUS}`))).toBeNull();
  });

  it("rejects an unrelated token even when a previous secret is configured", async () => {
    vi.stubEnv("LOVABLE_CRON_SECRET", SECRET);
    vi.stubEnv("LOVABLE_CRON_SECRET_PREVIOUS", PREVIOUS);
    const res = await authenticateCronRequest(requestWith("Bearer something-else"));
    expect(res?.status).toBe(401);
  });
});
