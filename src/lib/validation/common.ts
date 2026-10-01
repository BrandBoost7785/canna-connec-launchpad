import { z } from "zod";

// Shared, server-side validation primitives. These mirror (never replace) the CHECK
// constraints and function-level validation in the database: the database is the
// final authority, this layer gives early, structured rejection.
//
// Anything the browser sends is untrusted. Roles, permissions, prices, totals,
// discounts, stock, commission values and payment status are NEVER accepted from
// input schemas - there is deliberately no field for them in any schema here.

export const uuidSchema = z.string().uuid();

export const displayNameSchema = z
  .string()
  .transform((v) => v.trim())
  .pipe(z.string().min(1, "Required").max(120));

/** E.164, matching the `profiles.mobile_e164` CHECK constraint. */
export const mobileE164Schema = z
  .string()
  .regex(/^\+[1-9][0-9]{7,14}$/, "Use international format, e.g. +<country code><number>");

export const emailSchema = z
  .string()
  .transform((v) => v.trim().toLowerCase())
  .pipe(z.string().email().max(254));

/** Crockford-style Base32 without I, L, O, U; matches `client_codes` CHECK. */
export const clientCodeSchema = z
  .string()
  .transform((v) => v.trim().toUpperCase())
  .pipe(
    z
      .string()
      .regex(
        /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/,
        "Invalid Client Code format",
      ),
  );

/**
 * Platform upper bound only (limits the CPU/memory an attacker can make Argon2id spend
 * per request). It is NOT a policy value. The MINIMUM length is owner-configured
 * (`business_settings.secret_code_min_length`) and applied when a secret is CREATED -
 * see `secretCodeSchemaFor`. Login deliberately does not enforce a minimum, so a policy
 * change can never lock out existing customers.
 */
export const MAX_SECRET_CODE_LENGTH = 128;

/** Verification-time schema: non-empty, bounded. No minimum length. */
export const secretCodeSchema = z.string().min(1).max(MAX_SECRET_CODE_LENGTH);

/** Creation-time schema using the OWNER-CONFIGURED minimum length (no default). */
export function secretCodeSchemaFor(minLength: number) {
  if (!Number.isInteger(minLength) || minLength < 1 || minLength > MAX_SECRET_CODE_LENGTH) {
    throw new RangeError("secret_code_min_length is not configured to a valid value");
  }
  return z.string().min(minLength, `At least ${minLength} characters`).max(MAX_SECRET_CODE_LENGTH);
}

/**
 * Account passwords: only bounded here. Password strength is enforced by the Supabase
 * Auth project settings (external configuration, see docs/FOUNDATION.md); this app does
 * not invent its own password policy.
 */
export const passwordSchema = z.string().min(1).max(MAX_SECRET_CODE_LENGTH);

export function isValidTimeZone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return tz.length > 0 && tz.length <= 64;
  } catch {
    return false;
  }
}
export const timeZoneSchema = z.string().refine(isValidTimeZone, "Unknown IANA time zone");

/** 24-hour HH:MM (or HH:MM:SS). */
export const timeOfDaySchema = z
  .string()
  .regex(/^([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$/, "Use HH:MM (24-hour)");

/** ISO 4217 style, lowercase is rejected on purpose: stored upper-case. */
export const currencyCodeSchema = z
  .string()
  .regex(/^[A-Z]{3}$/, "Use a 3-letter ISO 4217 code, e.g. ZAR");

export const hexColorSchema = z.string().regex(/^#[0-9a-fA-F]{6}$/, "Use #RRGGBB");

/** Integer minor units (cents); never floating point. */
export const minorUnitsSchema = z.number().int().safe();
