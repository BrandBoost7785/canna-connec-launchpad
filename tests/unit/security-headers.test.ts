import { describe, expect, it } from "vitest";
import {
  buildCsp,
  buildSecurityHeaders,
  sanitizeFrameAncestors,
  withSecurityHeaders,
} from "@/lib/security/headers";

const prod = { production: true, supabaseUrl: "https://abc.supabase.co" };

describe("security headers", () => {
  it("production sets CSP, HSTS and the standard hardening headers", () => {
    const h = buildSecurityHeaders(prod);
    expect(h["X-Content-Type-Options"]).toBe("nosniff");
    expect(h["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    expect(h["Strict-Transport-Security"]).toMatch(/max-age=31536000/);
    expect(h["Permissions-Policy"]).toContain("camera=()");
    expect(h["Content-Security-Policy"]).toBeDefined();
  });
  it("development omits HSTS and the enforcing CSP (HMR needs inline/ws)", () => {
    const h = buildSecurityHeaders({ production: false });
    expect(h["Strict-Transport-Security"]).toBeUndefined();
    expect(h["Content-Security-Policy"]).toBeUndefined();
    expect(h["X-Content-Type-Options"]).toBe("nosniff");
  });
  it("CSP denies framing by default, blocks plugins and restricts base/form targets", () => {
    const csp = buildCsp(prod);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");
    expect(csp).toContain("default-src 'self'");
    // existing app dependency: Google Fonts (and nothing broader)
    expect(csp).toContain("style-src 'self' 'unsafe-inline' https://fonts.googleapis.com");
    expect(csp).toContain("font-src 'self' data: https://fonts.gstatic.com");
    expect(csp).not.toMatch(/(?:script|default|connect)-src[^;]*\*/);
    expect(csp).toContain("connect-src 'self' https://abc.supabase.co wss://abc.supabase.co");
  });
  it("frame-ancestors is configurable but sanitised", () => {
    expect(sanitizeFrameAncestors("https://a.example https://*.b.example")).toBe(
      "https://a.example https://*.b.example",
    );
    expect(sanitizeFrameAncestors("'self'")).toBe("'self'");
    expect(sanitizeFrameAncestors("*")).toBe("'none'");
    expect(sanitizeFrameAncestors("https://a.example; script-src *")).toBe("'none'");
    expect(sanitizeFrameAncestors("")).toBe("'none'");
    expect(sanitizeFrameAncestors(undefined)).toBe("'none'");
  });
  it("ignores an invalid Supabase URL instead of widening the policy", () => {
    expect(buildCsp({ production: true, supabaseUrl: "not a url" })).toContain(
      "connect-src 'self'",
    );
  });
  it("applies headers to a response, preserving body/status and not overriding existing values", async () => {
    const res = withSecurityHeaders(
      new Response("hello", { status: 201, headers: { "X-Content-Type-Options": "custom" } }),
      prod,
      true,
    );
    expect(res.status).toBe(201);
    expect(await res.text()).toBe("hello");
    expect(res.headers.get("X-Content-Type-Options")).toBe("custom");
    expect(res.headers.get("Strict-Transport-Security")).toBeTruthy();
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });
});
