import { supabaseAdmin } from "@/integrations/supabase/client.server";
import { toAppError } from "@/lib/errors";

// The generated Supabase `Database` type (src/integrations/supabase/types.ts) is not
// edited by hand, so foundation RPCs are called through this single typed wrapper.
// SERVER ONLY: uses the service-role client. Never import from client code.

type RpcResult = { data: unknown; error: { code?: string; message?: string } | null };
type RpcCaller = { rpc: (fn: string, args?: Record<string, unknown>) => PromiseLike<RpcResult> };

export async function adminRpc<T>(fn: string, args: Record<string, unknown> = {}): Promise<T> {
  const { data, error } = await (supabaseAdmin as unknown as RpcCaller).rpc(fn, args);
  if (error) throw toAppError(error, `rpc ${fn}`);
  return data as T;
}
