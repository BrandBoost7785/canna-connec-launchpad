import { describe, expect, it } from "vitest";
import {
  ARGON2_PARAMS,
  dummyVerify,
  hashSecretCode,
  verifySecretCode,
} from "@/lib/security/secret-code";

describe("Secret Access Code hashing (Argon2id)", () => {
  it("produces a PHC-format Argon2id hash with the configured parameters and a random salt", () => {
    const a = hashSecretCode("a-test-secret-1");
    const b = hashSecretCode("a-test-secret-1");
    expect(a).toMatch(
      new RegExp(
        `^\\$argon2id\\$v=19\\$m=${ARGON2_PARAMS.m},t=${ARGON2_PARAMS.t},p=${ARGON2_PARAMS.p}\\$[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+$`,
      ),
    );
    expect(a).not.toBe(b);
    expect(a).not.toContain("a-test-secret-1");
  });
  it("verifies the right secret and rejects wrong ones", () => {
    const h = hashSecretCode("correct-secret");
    expect(verifySecretCode("correct-secret", h)).toBe(true);
    expect(verifySecretCode("correct-secreT", h)).toBe(false);
    expect(verifySecretCode("", h)).toBe(false);
  });
  it("never throws on malformed or hostile stored hashes", () => {
    for (const bad of [
      "",
      "plain",
      "$2b$12$abc",
      "$argon2id$v=19$m=1,t=1,p=1$x$y",
      "$argon2id$v=19$m=99999999,t=2,p=1$c2FsdA$aGFzaA",
      "$argon2id$v=19$m=19456,t=99,p=1$c2FsdA$aGFzaA",
    ]) {
      expect(verifySecretCode("x", bad)).toBe(false);
    }
  });
  it("dummyVerify always returns false", () => {
    expect(dummyVerify("anything")).toBe(false);
  });
});
