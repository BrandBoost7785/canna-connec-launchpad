import { argon2id } from "@noble/hashes/argon2.js";
import { randomBytes } from "@noble/hashes/utils.js";

// Secret Access Codes are stored ONLY as Argon2id hashes (PHC string format).
//
// Parameters follow the OWASP Password Storage Cheat Sheet minimum for Argon2id
// (19 MiB memory, 2 iterations, 1 lane). PBKDF2 is not used because Cloudflare
// Workers caps it at 100,000 iterations.

export const ARGON2_PARAMS = { m: 19456, t: 2, p: 1 } as const;
const DK_LEN = 32;
const SALT_LEN = 16;

const b64 = (bytes: Uint8Array): string => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=+$/, "");
};
const unb64 = (s: string): Uint8Array => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export function hashSecretCode(secret: string): string {
  const salt = randomBytes(SALT_LEN);
  const dk = argon2id(new TextEncoder().encode(secret), salt, { ...ARGON2_PARAMS, dkLen: DK_LEN });
  return `$argon2id$v=19$m=${ARGON2_PARAMS.m},t=${ARGON2_PARAMS.t},p=${ARGON2_PARAMS.p}$${b64(salt)}$${b64(dk)}`;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

const PHC = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

/** Constant-time verification. Returns false (never throws) for malformed stored hashes. */
export function verifySecretCode(secret: string, stored: string): boolean {
  const m = PHC.exec(stored);
  if (!m) return false;
  const [, mem, t, p, salt, hash] = m;
  const memory = Number(mem);
  const iterations = Number(t);
  const lanes = Number(p);
  // Refuse absurd parameters from a corrupted row rather than burning CPU/memory.
  if (memory > 262_144 || iterations > 10 || lanes > 4 || memory < 8 * lanes) return false;
  try {
    const expected = unb64(hash!);
    const dk = argon2id(new TextEncoder().encode(secret), unb64(salt!), {
      m: memory,
      t: iterations,
      p: lanes,
      dkLen: expected.length,
    });
    return timingSafeEqual(dk, expected);
  } catch {
    return false;
  }
}

/**
 * A fixed, valid hash used to spend equivalent time when the Client Code is unknown,
 * so response timing does not reveal whether a Client Code exists.
 */
let dummy: string | undefined;
export function dummyVerify(secret: string): false {
  dummy ??= hashSecretCode("not-a-real-secret-" + b64(randomBytes(8)));
  verifySecretCode(secret, dummy);
  return false;
}
