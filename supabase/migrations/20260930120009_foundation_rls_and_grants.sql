-- 001-foundation / migration 9: Row Level Security and explicit grants.
--
-- Model:
--   * RLS is ENABLED on every table in `public`.
--   * API roles (anon, authenticated) get NO write privileges on any table.
--     Writes happen only through SECURITY DEFINER functions (migration 7).
--   * `authenticated` can SELECT only through the policies below.
--   * access_credentials and rate_limits have no policies and no grants: they are
--     reachable only by service_role / SECURITY DEFINER code.
--
-- Every later migration that adds a table MUST enable RLS and grant explicitly;
-- tests/db/security-baseline.test.ts fails the build if a table is left exposed.

-- Harden defaults for objects created by this migration role in the future.
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Tables: enable RLS, remove every privilege, then grant SELECT selectively.
-- ---------------------------------------------------------------------------
alter table public.audit_logs                  enable row level security;
alter table public.business_settings           enable row level security;
alter table public.notification_channel_settings enable row level security;
alter table public.profiles                    enable row level security;
alter table public.permissions                 enable row level security;
alter table public.roles                       enable row level security;
alter table public.role_permissions            enable row level security;
alter table public.user_roles                  enable row level security;
alter table public.commission_configurations   enable row level security;
alter table public.commission_period_schedules enable row level security;
alter table public.commission_periods          enable row level security;
alter table public.client_codes                enable row level security;
alter table public.access_credentials          enable row level security;
alter table public.rate_limits                 enable row level security;

revoke all on all tables in schema public from public, anon, authenticated;
revoke all on all sequences in schema public from public, anon, authenticated;

grant select on
  public.audit_logs, public.business_settings, public.notification_channel_settings,
  public.profiles, public.permissions, public.roles, public.role_permissions, public.user_roles,
  public.commission_configurations, public.commission_period_schedules, public.commission_periods,
  public.client_codes
to authenticated;

-- ---------------------------------------------------------------------------
-- Policies (SELECT only; there are deliberately no INSERT/UPDATE/DELETE policies)
-- ---------------------------------------------------------------------------
create policy profiles_select on public.profiles for select to authenticated
  using (
    id = (select auth.uid())
    or (select app.current_user_has('employees.manage'))
    or (select app.current_user_has('customers.manage'))
    or (kind = 'customer' and (select app.current_user_has('customers.view')))
  );

create policy permissions_select on public.permissions for select to authenticated
  using ((select app.current_user_has('roles.manage')) or (select app.current_user_has('employees.manage')));

create policy roles_select on public.roles for select to authenticated
  using ((select app.current_user_has('roles.manage')) or (select app.current_user_has('employees.manage')));

create policy role_permissions_select on public.role_permissions for select to authenticated
  using ((select app.current_user_has('roles.manage')) or (select app.current_user_has('employees.manage')));

create policy user_roles_select on public.user_roles for select to authenticated
  using (user_id = (select auth.uid()) or (select app.current_user_has('employees.manage')));

create policy business_settings_select on public.business_settings for select to authenticated
  using ((select app.current_user_has('settings.manage')));

create policy notification_channel_settings_select on public.notification_channel_settings for select to authenticated
  using ((select app.current_user_has('settings.manage')) or (select app.current_user_has('notifications.manage')));

create policy audit_logs_select on public.audit_logs for select to authenticated
  using ((select app.current_user_has('audit.view')));

create policy client_codes_select on public.client_codes for select to authenticated
  using (
    user_id = (select auth.uid())
    or (select app.current_user_has('customers.manage'))
    or (select app.current_user_has('customers.view'))
  );

create policy commission_configurations_select on public.commission_configurations for select to authenticated
  using ((select app.current_user_has('commissions.manage')) or (select app.current_user_has('commission.view_own')));

create policy commission_period_schedules_select on public.commission_period_schedules for select to authenticated
  using ((select app.current_user_has('commissions.manage')) or (select app.current_user_has('commission.view_own')));

create policy commission_periods_select on public.commission_periods for select to authenticated
  using ((select app.current_user_has('commissions.manage')) or (select app.current_user_has('commission.view_own')));

-- ---------------------------------------------------------------------------
-- Functions: start from zero, then grant each API function to explicit roles.
-- ---------------------------------------------------------------------------
revoke all on all functions in schema public from public, anon, authenticated, service_role;
revoke all on all functions in schema app    from public, anon, authenticated, service_role;

-- RLS policies evaluate this as the calling role.
grant execute on function app.current_user_has(text) to authenticated;

-- Public, anonymous-safe reads.
grant execute on function public.get_setup_status()   to anon, authenticated, service_role;
grant execute on function public.get_public_branding() to anon, authenticated, service_role;

-- Signed-in users (each checks auth.uid() and permissions internally).
grant execute on function public.my_access()                  to authenticated;
grant execute on function public.business_day_for(timestamptz) to authenticated, service_role;
grant execute on function public.current_business_day()        to authenticated, service_role;
grant execute on function public.admin_create_role(text, text, text)             to authenticated;
grant execute on function public.admin_grant_permission(text, text)              to authenticated;
grant execute on function public.admin_revoke_permission(text, text)             to authenticated;
grant execute on function public.admin_assign_role(uuid, text)                   to authenticated;
grant execute on function public.admin_revoke_role(uuid, text)                   to authenticated;
grant execute on function public.admin_update_business_settings(jsonb)           to authenticated;
grant execute on function public.admin_set_notification_channel(public.notification_channel, boolean, text) to authenticated;
grant execute on function public.admin_set_commission_configuration(integer, public.money_rounding_mode, timestamptz, text) to authenticated;
grant execute on function public.admin_save_commission_period_schedule(text, smallint, time, smallint, time, smallint, time) to authenticated;
grant execute on function public.admin_deactivate_commission_period_schedule(uuid) to authenticated;

-- Service-only (server code that has already authenticated the request).
grant execute on function public.create_profile(uuid, public.user_kind, text, text, uuid) to service_role;
grant execute on function public.issue_client_code(uuid)                        to service_role;
grant execute on function public.set_access_secret(uuid, text)                  to service_role;
grant execute on function public.get_quick_login_credential(text)               to service_role;
grant execute on function public.record_quick_login_attempt(uuid, boolean, integer, integer) to service_role;
grant execute on function public.resolve_login_identifier(text)                 to service_role;
grant execute on function public.rate_limit_hit(text, integer, integer)         to service_role;
grant execute on function public.ensure_commission_period(timestamptz)          to service_role;
grant execute on function public.calculate_commission_cents(bigint, timestamptz) to service_role;
grant execute on function public.complete_first_run_setup(uuid, text, jsonb, integer, public.money_rounding_mode, jsonb) to service_role;
