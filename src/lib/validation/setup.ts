import { z } from "zod";
import {
  currencyCodeSchema,
  displayNameSchema,
  emailSchema,
  hexColorSchema,
  passwordSchema,
  timeOfDaySchema,
  timeZoneSchema,
} from "./common";

// First-run setup. EVERY business value is required input: there are no defaults
// here, so the application never silently decides the business name, time zone,
// cut-off, commission rate, rounding mode or notification provider.

const channelSchema = z
  .object({
    channel: z.enum(["in_app", "push", "email", "sms", "whatsapp"]),
    enabled: z.boolean(),
    provider_label: z.string().trim().min(1).max(80).nullable().optional(),
  })
  .strict();

export const setupSettingsSchema = z
  .object({
    business_name: z.string().trim().min(1).max(120),
    tagline: z.string().trim().max(200).nullable().optional(),
    primary_color: hexColorSchema.nullable().optional(),
    contact_email: emailSchema.nullable().optional(),
    timezone: timeZoneSchema,
    currency_code: currencyCodeSchema,
    business_day_cutoff: timeOfDaySchema,
    cart_duration_minutes: z.number().int().min(1).max(1440),
    low_stock_default_threshold: z.number().int().min(0).max(1_000_000),
    availability_check_minutes: z.number().int().min(0).max(1440),
    hide_out_of_stock_enabled: z.boolean(),
    hide_out_of_stock_after_minutes: z.number().int().min(0).max(525_600),
    // Owner-configured security policy: required, no defaults. The bounds equal the
    // database CHECK constraints (technical sanity limits, not policy).
    login_max_failed_attempts: z.number().int().min(1).max(100),
    login_lock_seconds: z.number().int().min(1).max(86_400),
    rate_limit_login_ip_attempts: z.number().int().min(1).max(100_000),
    rate_limit_login_ip_window_seconds: z.number().int().min(1).max(86_400),
    rate_limit_login_code_attempts: z.number().int().min(1).max(100_000),
    rate_limit_login_code_window_seconds: z.number().int().min(1).max(86_400),
    secret_code_min_length: z.number().int().min(1).max(128),
  })
  .strict();

export const firstRunSetupSchema = z
  .object({
    setupToken: z.string().min(1).max(512),
    admin: z
      .object({
        displayName: displayNameSchema,
        email: emailSchema,
        password: passwordSchema,
      })
      .strict(),
    settings: setupSettingsSchema,
    commission: z
      .object({
        rateBps: z.number().int().min(0).max(10_000),
        rounding: z.enum(["half_up", "half_even", "down", "up"]),
      })
      .strict(),
    notificationChannels: z.array(channelSchema).max(5),
  })
  .strict();

export type FirstRunSetupInput = z.infer<typeof firstRunSetupSchema>;
