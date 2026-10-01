import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { toAppError } from "@/lib/errors";
import { quickLoginSchema } from "@/lib/validation";

/** Client Code + Secret Access Code sign-in. Returns session tokens on success. */
export const quickLoginFn = createServerFn({ method: "POST" })
  .validator(quickLoginSchema)
  .handler(async ({ data }) => {
    try {
      const { quickLogin } = await import("@/server/quick-login.server");
      return await quickLogin(data);
    } catch (e) {
      throw toAppError(e, "quickLogin");
    }
  });

/**
 * The caller's own roles/permissions, computed by the database. The browser may use
 * this to render navigation, but it is NEVER the enforcement point.
 */
export const fetchMyAccess = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data, error } = await (
      context.supabase as unknown as {
        rpc: (fn: string) => PromiseLike<{ data: unknown; error: { code?: string } | null }>;
      }
    ).rpc("my_access");
    if (error) throw toAppError(error, "my_access");
    return data as
      | { has_profile: false }
      | {
          has_profile: true;
          kind: "customer" | "employee" | "admin";
          status: string;
          archived: boolean;
          roles: string[];
          permissions: string[];
        };
  });
