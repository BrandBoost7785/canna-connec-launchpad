import { z } from "zod";
import {
  clientCodeSchema,
  emailSchema,
  mobileE164Schema,
  passwordSchema,
  secretCodeSchema,
} from "./common";

/** Quick login with Client Code + Secret Access Code. */
export const quickLoginSchema = z
  .object({ clientCode: clientCodeSchema, secretCode: secretCodeSchema })
  .strict();

/** Email/mobile + password sign-in (staff and any customer who has one). */
export const passwordLoginSchema = z
  .object({
    identifier: z.union([emailSchema, mobileE164Schema]),
    password: passwordSchema,
  })
  .strict();

export type QuickLoginInput = z.infer<typeof quickLoginSchema>;
export type PasswordLoginInput = z.infer<typeof passwordLoginSchema>;
