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

export const MIN_SECRET_CODE_LENGTH = 8; // owner decision pending - see docs/SECURITY_NOTES.md
export const MAX_SECRET_CODE_LENGTH = 128;
export const secretCodeSchema = z
  .string()
  .min(MIN_SECRET_CODE_LENGTH, `At least ${MIN_SECRET_CODE_LENGTH} characters`)
  .max(MAX_SECRET_CODE_LENGTH);

export const passwordSchema = z.string().min(MIN_SECRET_CODE_LENGTH).max(MAX_SECRET_CODE_LENGTH);

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
