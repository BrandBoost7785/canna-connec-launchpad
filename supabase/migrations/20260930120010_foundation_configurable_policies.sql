-- 001-foundation / migration 10: owner-configurable security policy; remove developer-chosen rules.
--
-- Corrects values that earlier migrations/Node code fixed as constants although the
-- business owner has not specified them:
--   * failed-login lockout (attempts, duration)
--   * login rate limits (per IP, per Client Code; attempts and window)
--   * minimum Secret Access Code length
--   * the "business-day cut-off must be after 00:00" rule
--
-- All new settings are NULL until the owner configures them. They are REQUIRED to
-- complete first-run setup. While any is NULL the dependent features FAIL CLOSED
-- (`configuration_required`, SQLSTATE P0001). No default is seeded.
--
-- The numeric BOUNDS below (e.g. 1..86400 seconds) are technical sanity limits that
-- keep the functions safe (bounded locks/windows, bounded hashing cost); they are not
-- business rules and every value inside them is the owner's choice.

alter table public.business_settings
  add column login_max_failed_attempts             integer check (login_max_failed_attempts is null or login_max_failed_attempts between 1 and 100),
  add column login_lock_seconds                    integer check (login_lock_seconds is null or login_lock_seconds between 1 and 86400),
  add column rate_limit_login_ip_attempts          integer check (rate_limit_login_ip_attempts is null or rate_limit_login_ip_attempts between 1 and 100000),
  add column rate_limit_login_ip_window_seconds    integer check (rate_limit_login_ip_window_seconds is null or rate_limit_login_ip_window_seconds between 1 and 86400),
  add column rate_limit_login_code_attempts        integer check (rate_limit_login_code_attempts is null or rate_limit_login_code_attempts between 1 and 100000),
  add column rate_limit_login_code_window_seconds  integer check (rate_limit_login_code_window_seconds is null or rate_limit_login_code_window_seconds between 1 and 86400),
  add column secret_code_min_length                integer check (secret_code_min_length is null or secret_code_min_length between 1 and 128);

alter table public.business_settings drop constraint business_settings_complete_requires_core;
alter table public.business_settings add constraint business_settings_complete_requires_core check (
  setup_completed_at is null or (
    business_name is not null
    and timezone is not null
    and currency_code is not null
    and business_day_cutoff is not null
    and cart_duration_minutes is not null
    and low_stock_default_threshold is not null
    and availability_check_minutes is not null
    and hide_out_of_stock_enabled is not null
    and hide_out_of_stock_after_minutes is not null
    and login_max_failed_attempts is not null
    and login_lock_seconds is not null
    and rate_limit_login_ip_attempts is not null
    and rate_limit_login_ip_window_seconds is not null
    and rate_limit_login_code_attempts is not null
    and rate_limit_login_code_window_seconds is not null
    and secret_code_min_length is not null
  )
);

-- A cut-off of 00:00 is now accepted. The rule is applied literally: an instant whose
-- local time is >= the cut-off belongs to the NEXT business day (so with 00:00 every
-- instant does). Whether the owner wants that meaning is recorded as an open question.
alter table public.business_settings drop constraint business_settings_business_day_cutoff_check;

create or replace function app.business_day_of(p_ts timestamptz, p_timezone text, p_cutoff time)
returns date
language plpgsql
stable
set search_path = ''
as $$
declare
  v_local timestamp;
begin
  if p_ts is null or p_timezone is null or p_cutoff is null then
    raise exception 'configuration_required' using errcode = 'P0001',
      detail = 'Business timezone and business-day cutoff must be configured.';
  end if;

  -- An unknown timezone name makes AT TIME ZONE raise SQLSTATE 22023 by itself.
  -- (The settings table validates names strictly against pg_timezone_names.)
  v_local := p_ts at time zone p_timezone;
  if v_local::time >= p_cutoff then
    return v_local::date + 1;
  end if;
  return v_local::date;
end;
$$;

create or replace function app.business_day_bounds_of(p_day date, p_timezone text, p_cutoff time)
returns table (starts_at timestamptz, ends_at timestamptz)
language plpgsql
stable
set search_path = ''
as $$
begin
  if p_day is null or p_timezone is null or p_cutoff is null then
    raise exception 'configuration_required' using errcode = 'P0001';
  end if;
  starts_at := timezone(p_timezone, (p_day - 1)::timestamp + p_cutoff);
  ends_at   := timezone(p_timezone, p_day::timestamp + p_cutoff);
  return next;
end;
$$;

-- Security settings are changed only with `security_settings.manage`.
create or replace function app.apply_settings_patch(p_patch jsonb, p_enforce_permissions boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  c_settings_keys constant text[] := array[
    'business_name', 'tagline', 'logo_url', 'primary_color', 'contact_email', 'contact_phone',
    'timezone', 'currency_code', 'business_day_cutoff',
    'cart_duration_minutes', 'low_stock_default_threshold', 'availability_check_minutes',
    'hide_out_of_stock_enabled', 'hide_out_of_stock_after_minutes',
    'customer_email_required', 'privacy_policy_text', 'terms_text', 'consent_required'];
  c_payment_keys constant text[] := array['payment_provider_key'];
  c_security_keys constant text[] := array[
    'login_max_failed_attempts', 'login_lock_seconds',
    'rate_limit_login_ip_attempts', 'rate_limit_login_ip_window_seconds',
    'rate_limit_login_code_attempts', 'rate_limit_login_code_window_seconds',
    'secret_code_min_length'];
  v_key text;
  v_set text;
  v_rec public.business_settings;
begin
  if p_patch is null or pg_catalog.jsonb_typeof(p_patch) <> 'object' or p_patch = '{}'::jsonb then
    raise exception 'invalid settings patch' using errcode = '22023';
  end if;

  for v_key in select pg_catalog.jsonb_object_keys(p_patch) loop
    if v_key = any (c_settings_keys) then
      if p_enforce_permissions then perform app.require_permission('settings.manage'); end if;
    elsif v_key = any (c_payment_keys) then
      if p_enforce_permissions then perform app.require_permission('payment_settings.manage'); end if;
    elsif v_key = any (c_security_keys) then
      if p_enforce_permissions then perform app.require_permission('security_settings.manage'); end if;
    else
      raise exception 'unknown setting' using errcode = '22023';
    end if;
  end loop;

  v_rec := pg_catalog.jsonb_populate_record(null::public.business_settings, p_patch);

  -- ONE update statement for the whole patch => ONE audit record with the complete
  -- previous/new values. Keys were whitelisted above, and %I quotes identifiers.
  select pg_catalog.string_agg(pg_catalog.format('%I = ($1).%I', k, k), ', ')
    into v_set
  from pg_catalog.jsonb_object_keys(p_patch) as k;

  execute 'update public.business_settings set ' || v_set || ' where singleton' using v_rec;
end;
$$;

-- First-run setup now also requires the owner's security policy.
create or replace function public.complete_first_run_setup(
  p_admin_user_id uuid,
  p_admin_display_name text,
  p_settings jsonb,
  p_commission_rate_bps integer,
  p_commission_rounding public.money_rounding_mode,
  p_notification_channels jsonb default '[]'::jsonb)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  c_required constant text[] := array[
    'business_name', 'timezone', 'currency_code', 'business_day_cutoff', 'cart_duration_minutes',
    'low_stock_default_threshold', 'availability_check_minutes',
    'hide_out_of_stock_enabled', 'hide_out_of_stock_after_minutes',
    'login_max_failed_attempts', 'login_lock_seconds',
    'rate_limit_login_ip_attempts', 'rate_limit_login_ip_window_seconds',
    'rate_limit_login_code_attempts', 'rate_limit_login_code_window_seconds',
    'secret_code_min_length'];
  v_done timestamptz;
  v_key text;
  v_item jsonb;
  v_admin_role uuid;
begin
  if p_admin_user_id is null or not exists (select 1 from auth.users where id = p_admin_user_id) then
    raise exception 'invalid user' using errcode = '22023';
  end if;
  if p_settings is null or pg_catalog.jsonb_typeof(p_settings) <> 'object' then
    raise exception 'invalid settings' using errcode = '22023';
  end if;
  if p_notification_channels is null or pg_catalog.jsonb_typeof(p_notification_channels) <> 'array' then
    raise exception 'invalid notification channels' using errcode = '22023';
  end if;
  foreach v_key in array c_required loop
    if p_settings -> v_key is null or pg_catalog.jsonb_typeof(p_settings -> v_key) = 'null' then
      raise exception 'missing_required_setting' using errcode = '22023', detail = v_key;
    end if;
  end loop;

  -- Single winner: serialize on the settings row.
  select setup_completed_at into v_done from public.business_settings where singleton for update;
  if v_done is not null or exists (select 1 from public.profiles where kind = 'admin') then
    raise exception 'setup_already_completed' using errcode = '55000';
  end if;

  perform pg_catalog.set_config('app.actor_id', p_admin_user_id::text, true);

  insert into public.profiles (id, kind, status, display_name)
  values (p_admin_user_id, 'admin', 'approved', p_admin_display_name);

  select id into v_admin_role from public.roles where key = 'admin' and is_system;
  insert into public.user_roles (user_id, role_id, assigned_by)
  values (p_admin_user_id, v_admin_role, p_admin_user_id);

  perform app.apply_settings_patch(p_settings, false);

  insert into public.commission_configurations (rate_bps, rounding, effective_from, note, created_by)
  values (p_commission_rate_bps, p_commission_rounding, pg_catalog.now(), 'Set during first-run setup', p_admin_user_id);

  for v_item in select * from pg_catalog.jsonb_array_elements(p_notification_channels) loop
    insert into public.notification_channel_settings (channel, enabled, provider_label)
    values ((v_item ->> 'channel')::public.notification_channel,
            coalesce((v_item ->> 'enabled')::boolean, false),
            v_item ->> 'provider_label')
    on conflict (channel) do update
      set enabled = excluded.enabled, provider_label = excluded.provider_label;
  end loop;

  update public.business_settings
     set setup_completed_at = pg_catalog.now(), setup_completed_by = p_admin_user_id
   where singleton;

  perform app.write_audit('setup.completed', 'business_settings', 'singleton', null, null,
    pg_catalog.jsonb_build_object('source', 'first_run_setup'));
end;
$$;

-- ---------------------------------------------------------------------------
-- Service-only: the configured policy for server code (fails closed if unset).
-- ---------------------------------------------------------------------------
create function public.get_security_policy()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  s public.business_settings;
begin
  select * into s from public.business_settings where singleton;
  if s.login_max_failed_attempts is null or s.login_lock_seconds is null
     or s.rate_limit_login_ip_attempts is null or s.rate_limit_login_ip_window_seconds is null
     or s.rate_limit_login_code_attempts is null or s.rate_limit_login_code_window_seconds is null
     or s.secret_code_min_length is null then
    raise exception 'configuration_required' using errcode = 'P0001',
      detail = 'Security policy has not been configured by the business owner.';
  end if;
  return pg_catalog.jsonb_build_object(
    'login_max_failed_attempts', s.login_max_failed_attempts,
    'login_lock_seconds', s.login_lock_seconds,
    'rate_limit_login_ip_attempts', s.rate_limit_login_ip_attempts,
    'rate_limit_login_ip_window_seconds', s.rate_limit_login_ip_window_seconds,
    'rate_limit_login_code_attempts', s.rate_limit_login_code_attempts,
    'rate_limit_login_code_window_seconds', s.rate_limit_login_code_window_seconds,
    'secret_code_min_length', s.secret_code_min_length);
end;
$$;

-- The lockout parameters are read from the configured policy INSIDE the database,
-- not accepted from the caller.
drop function public.record_quick_login_attempt(uuid, boolean, integer, integer);
create function public.record_quick_login_attempt(p_user_id uuid, p_success boolean)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_max integer;
  v_lock integer;
  v_failed integer;
  v_locked timestamptz;
  v_prev_locked timestamptz;
begin
  if p_user_id is null or p_success is null then
    raise exception 'invalid input' using errcode = '22023';
  end if;

  select login_max_failed_attempts, login_lock_seconds into v_max, v_lock
  from public.business_settings where singleton;
  if v_max is null or v_lock is null then
    raise exception 'configuration_required' using errcode = 'P0001',
      detail = 'Login lockout policy has not been configured by the business owner.';
  end if;

  perform pg_catalog.set_config('app.actor_id', p_user_id::text, true);

  if p_success then
    update public.access_credentials
       set failed_attempts = 0, locked_until = null, last_success_at = pg_catalog.now()
     where user_id = p_user_id;
    if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
    perform app.write_audit('credential.quick_login_succeeded', 'access_credentials', p_user_id::text);
    return pg_catalog.jsonb_build_object('locked_until', null);
  end if;

  select locked_until into v_prev_locked from public.access_credentials where user_id = p_user_id for update;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;

  update public.access_credentials
     set failed_attempts = failed_attempts + 1,
         last_failed_at = pg_catalog.now(),
         locked_until = case when failed_attempts + 1 >= v_max
                             then pg_catalog.now() + pg_catalog.make_interval(secs => v_lock)
                             else locked_until end
   where user_id = p_user_id
   returning failed_attempts, locked_until into v_failed, v_locked;

  if v_locked is not null and v_locked is distinct from v_prev_locked then
    perform app.write_audit('credential.quick_login_locked', 'access_credentials', p_user_id::text,
      null, pg_catalog.jsonb_build_object('failed_attempts', v_failed, 'locked_until', v_locked));
  end if;
  return pg_catalog.jsonb_build_object('locked_until', v_locked, 'failed_attempts', v_failed);
end;
$$;

-- Grants (the shared grants migration ran before these objects existed).
revoke all on function public.get_security_policy() from public, anon, authenticated;
revoke all on function public.record_quick_login_attempt(uuid, boolean) from public, anon, authenticated;
grant execute on function public.get_security_policy() to service_role;
grant execute on function public.record_quick_login_attempt(uuid, boolean) to service_role;
