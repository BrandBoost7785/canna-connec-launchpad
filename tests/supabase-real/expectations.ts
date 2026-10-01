// Intended grant/RLS matrix of the foundation. Shared by the embedded-PostgreSQL test
// (tests/db/grant-matrix.test.ts, which RUNS) and the real-Supabase suite (NOT YET RUN), so
// both assert exactly the same expectations through the same catalog queries.

export const TABLES = [
  "audit_logs",
  "business_settings",
  "notification_channel_settings",
  "profiles",
  "permissions",
  "roles",
  "role_permissions",
  "user_roles",
  "commission_configurations",
  "commission_period_schedules",
  "commission_periods",
  "client_codes",
  "access_credentials",
  "rate_limits",
];
export const AUTHENTICATED_SELECT = TABLES.filter(
  (t) => !["access_credentials", "rate_limits"].includes(t),
);
export const ANON_FUNCTIONS = ["public.get_setup_status", "public.get_public_branding"];
export const AUTHENTICATED_FUNCTIONS = [
  ...ANON_FUNCTIONS,
  "app.current_user_has",
  "public.my_access",
  "public.business_day_for",
  "public.current_business_day",
  "public.admin_create_role",
  "public.admin_grant_permission",
  "public.admin_revoke_permission",
  "public.admin_assign_role",
  "public.admin_revoke_role",
  "public.admin_update_business_settings",
  "public.admin_set_notification_channel",
  "public.admin_set_commission_configuration",
  "public.admin_save_commission_period_schedule",
  "public.admin_deactivate_commission_period_schedule",
];
export const SERVICE_FUNCTIONS = [
  ...ANON_FUNCTIONS,
  "public.business_day_for",
  "public.current_business_day",
  "public.create_profile",
  "public.issue_client_code",
  "public.set_access_secret",
  "public.get_quick_login_credential",
  "public.record_quick_login_attempt",
  "public.resolve_login_identifier",
  "public.rate_limit_hit",
  "public.ensure_commission_period",
  "public.calculate_commission_cents",
  "public.complete_first_run_setup",
  "public.get_security_policy",
];

type Query = (sql: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }>;

/** Runs the catalog inspection and returns only the DEVIATIONS from the intended matrix. */
export async function catalogDeviations(q: Query) {
  const rls = await q(
    `select c.relname, c.relrowsecurity from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind in ('r','p') order by 1`,
  );
  const privs = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"];
  const tablePrivilegeDeviations: string[] = [];
  for (const t of TABLES)
    for (const p of privs) {
      const r = await q(
        `select has_table_privilege('anon', $1, $2) a, has_table_privilege('authenticated', $1, $2) u`,
        [`public.${t}`, p],
      );
      if (r.rows[0]!["a"]) tablePrivilegeDeviations.push(`anon:${p}:${t}`);
      const allowed = p === "SELECT" && AUTHENTICATED_SELECT.includes(t);
      if (r.rows[0]!["u"] !== allowed)
        tablePrivilegeDeviations.push(`authenticated:${p}:${t}=${r.rows[0]!["u"]}`);
    }
  const fns = await q(
    `select n.nspname || '.' || p.proname as fn,
            has_function_privilege('anon', p.oid, 'EXECUTE') as anon,
            has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated,
            has_function_privilege('service_role', p.oid, 'EXECUTE') as service_role
       from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname in ('public', 'app')
        and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')`,
  );
  const executable = (col: string) =>
    [...new Set(fns.rows.filter((x) => x[col]).map((x) => x["fn"] as string))].sort();
  const definers = await q(
    `select n.nspname || '.' || p.proname as fn, p.proconfig, pg_get_userbyid(p.proowner) as owner
       from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where p.prosecdef and n.nspname in ('public', 'app')`,
  );
  return {
    tables: rls.rows.map((x) => x["relname"] as string),
    tablesWithoutRls: rls.rows
      .filter((x) => !x["relrowsecurity"])
      .map((x) => x["relname"] as string),
    tablePrivilegeDeviations,
    anonFunctions: executable("anon"),
    authenticatedFunctions: executable("authenticated"),
    serviceFunctions: executable("service_role"),
    definerCount: definers.rows.length,
    definersWithoutPinnedSearchPath: definers.rows
      .filter(
        (x) =>
          !((x["proconfig"] as string[] | null) ?? []).includes('search_path=""') ||
          ["anon", "authenticated", "service_role"].includes(x["owner"] as string),
      )
      .map((x) => x["fn"] as string),
  };
}

export const expectedAnonFunctions = () => [...ANON_FUNCTIONS].sort();
export const expectedAuthenticatedFunctions = () => [...new Set(AUTHENTICATED_FUNCTIONS)].sort();
export const expectedServiceFunctions = () => [...new Set(SERVICE_FUNCTIONS)].sort();
