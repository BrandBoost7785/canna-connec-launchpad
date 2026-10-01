import { createServerFn } from "@tanstack/react-start";
import { toAppError } from "@/lib/errors";
import { firstRunSetupSchema } from "@/lib/validation";

/** Public: whether first-run setup has been completed. Reveals nothing else. */
export const fetchSetupStatus = createServerFn({ method: "GET" }).handler(async () => {
  try {
    const { getSetupStatus } = await import("@/server/setup.server");
    return await getSetupStatus();
  } catch (e) {
    throw toAppError(e, "fetchSetupStatus");
  }
});

/** Public but gated by SETUP_TOKEN + rate limit + one-time database guard. */
export const submitFirstRunSetup = createServerFn({ method: "POST" })
  .validator(firstRunSetupSchema)
  .handler(async ({ data }) => {
    try {
      const { completeFirstRunSetup } = await import("@/server/setup.server");
      await completeFirstRunSetup(data);
      return { ok: true as const };
    } catch (e) {
      throw toAppError(e, "submitFirstRunSetup");
    }
  });
