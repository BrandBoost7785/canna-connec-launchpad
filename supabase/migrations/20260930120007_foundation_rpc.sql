-- 001-foundation / migration 7: the API surface (SECURITY DEFINER functions).
--
-- Every function here:
--   * sets search_path = '' and schema-qualifies references,
--   * validates its own input,
--   * for user-callable functions derives the actor from auth.uid() (never from a
--     parameter) and checks a permission via app.require_permission(),
--   * is granted to explicit roles only (see the grants migration).
-- "service-only" functions are executable by service_role exclusively and are
-- called by server code that has already authenticated the request.

-- ===========================================================================
-- Public (anon-safe) reads
-- ===========================================================================
create function public.get_setup_status()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select pg_catalog.jsonb_build_object('setup_completed', s.setup_completed_at is not null)
  from public.business_settings s where s.singleton
$$;

-- Only fields that are public by nature (shown on the login/landing screens).
create function public.get_public_branding()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select pg_catalog.jsonb_build_object(
    'business_name', s.business_name,
    'tagline', s.tagline,
    'logo_url', s.logo_url,
    'primary_color', s.primary_color,
    'setup_completed', s.setup_completed_at is not null
  )
  from public.business_settings s where s.singleton
$$;

-- ===========================================================================
-- Caller's own access summary
-- ===========================================================================
create function public.my_access()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_p public.profiles%rowtype;
  v_roles jsonb;
  v_perms jsonb;
begin
  if v_uid is null then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  select * into v_p from public.profiles where id = v_uid;
  if not found then
    return pg_catalog.jsonb_build_object('has_profile', false);
  end if;

  select coalesce(pg_catalog.jsonb_agg(r.key order by r.key), '[]'::jsonb) into v_roles
  from public.user_roles ur join public.roles r on r.id = ur.role_id and r.archived_at is null
  where ur.user_id = v_uid;

  select coalesce(pg_catalog.jsonb_agg(distinct p.key order by p.key), '[]'::jsonb) into v_perms
  from public.user_roles ur
  join public.roles r on r.id = ur.role_id and r.archived_at is null
  join public.role_permissions rp on rp.role_id = r.id
  join public.permissions p on p.id = rp.permission_id
  where ur.user_id = v_uid
    and v_p.status = 'approved' and v_p.archived_at is null and v_p.kind in ('employee', 'admin');

  return pg_catalog.jsonb_build_object(
    'has_profile', true,
    'kind', v_p.kind,
    'status', v_p.status,
    'archived', v_p.archived_at is not null,
    'roles', v_roles,
    'permissions', v_perms
  );
end;
$$;

-- ===========================================================================
-- Business day (server/database time + configured timezone/cutoff)
-- ===========================================================================
create function public.business_day_for(p_ts timestamptz)
returns date
language sql
stable
security definer
set search_path = ''
as $$
  select app.business_day_for(p_ts)
$$;

create function public.current_business_day()
returns date
language sql
stable
security definer
set search_path = ''
as $$
  select app.current_business_day()
$$;

-- ===========================================================================
-- RBAC administration
-- ===========================================================================
create function public.admin_create_role(p_key text, p_name text, p_description text default null)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := app.require_permission('roles.manage');
begin
  insert into public.roles (key, name, description, created_by)
  values (p_key, p_name, p_description, v_uid);
  return p_key;
end;
$$;

create function public.admin_grant_permission(p_role_key text, p_permission_key text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := app.require_permission('roles.manage');
  v_role uuid;
  v_perm uuid;
begin
  select id into v_role from public.roles where key = p_role_key;
  select id into v_perm from public.permissions where key = p_permission_key;
  if v_role is null or v_perm is null then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  insert into public.role_permissions (role_id, permission_id, granted_by)
  values (v_role, v_perm, v_uid)
  on conflict do nothing;
end;
$$;

create function public.admin_revoke_permission(p_role_key text, p_permission_key text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_role uuid;
  v_perm uuid;
begin
  perform app.require_permission('roles.manage');
  select id into v_role from public.roles where key = p_role_key;
  select id into v_perm from public.permissions where key = p_permission_key;
  if v_role is null or v_perm is null then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  delete from public.role_permissions where role_id = v_role and permission_id = v_perm;
end;
$$;

create function public.admin_assign_role(p_user_id uuid, p_role_key text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := app.require_permission('employees.manage');
  v_role uuid;
begin
  select id into v_role from public.roles where key = p_role_key;
  if v_role is null or not exists (select 1 from public.profiles where id = p_user_id) then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  insert into public.user_roles (user_id, role_id, assigned_by)
  values (p_user_id, v_role, v_uid);
end;
$$;

create function public.admin_revoke_role(p_user_id uuid, p_role_key text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_role uuid;
begin
  perform app.require_permission('employees.manage');
  select id into v_role from public.roles where key = p_role_key;
  if v_role is null then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  delete from public.user_roles where user_id = p_user_id and role_id = v_role;
  if not found then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
end;
$$;

-- ===========================================================================
-- Business settings
-- ===========================================================================
-- Whitelisted, typed patch. Each key requires its own permission when called by a
-- user. Unknown keys (e.g. setup_completed_at, anything else) are rejected.
create function app.apply_settings_patch(p_patch jsonb, p_enforce_permissions boolean)
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

create function public.admin_update_business_settings(p_patch jsonb)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  perform app.apply_settings_patch(p_patch, true);
end;
$$;

create function public.admin_set_notification_channel(p_channel public.notification_channel, p_enabled boolean, p_provider_label text default null)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform app.require_permission('notifications.manage');
  if p_enabled is null then
    raise exception 'invalid input' using errcode = '22023';
  end if;
  insert into public.notification_channel_settings (channel, enabled, provider_label)
  values (p_channel, p_enabled, p_provider_label)
  on conflict (channel) do update
    set enabled = excluded.enabled, provider_label = excluded.provider_label;
end;
$$;

-- ===========================================================================
-- Commission configuration
-- ===========================================================================
create function public.admin_set_commission_configuration(
  p_rate_bps integer, p_rounding public.money_rounding_mode,
  p_effective_from timestamptz default null, p_note text default null)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := app.require_permission('commissions.manage');
  v_from timestamptz := coalesce(p_effective_from, pg_catalog.now());
  v_id uuid;
begin
  -- History is never rewritten: a new rate can only apply from now onwards.
  if v_from < pg_catalog.now() - interval '1 second' then
    raise exception 'effective_from cannot be in the past' using errcode = '22023';
  end if;
  insert into public.commission_configurations (rate_bps, rounding, effective_from, note, created_by)
  values (p_rate_bps, p_rounding, v_from, p_note, v_uid)
  returning id into v_id;
  return v_id;
end;
$$;

create function public.admin_save_commission_period_schedule(
  p_label text,
  p_start_dow smallint, p_start_time time,
  p_end_dow smallint, p_end_time time,
  p_payout_dow smallint, p_payout_time time)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := app.require_permission('commissions.manage');
  v_id uuid;
begin
  insert into public.commission_period_schedules
    (label, start_dow, start_time, end_dow, end_time, payout_dow, payout_time, created_by)
  values (p_label, p_start_dow, p_start_time, p_end_dow, p_end_time, p_payout_dow, p_payout_time, v_uid)
  returning id into v_id;
  return v_id;
end;
$$;

create function public.admin_deactivate_commission_period_schedule(p_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform app.require_permission('commissions.manage');
  update public.commission_period_schedules set active = false where id = p_id and active;
  if not found then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
end;
$$;

-- ===========================================================================
-- SERVICE-ONLY functions (called by authenticated server code)
-- ===========================================================================
create function public.create_profile(
  p_user_id uuid, p_kind public.user_kind, p_display_name text,
  p_mobile_e164 text default null, p_actor_id uuid default null)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_user_id is null or not exists (select 1 from auth.users where id = p_user_id) then
    raise exception 'invalid user' using errcode = '22023';
  end if;
  -- Administrators are only ever created by the first-run setup function.
  if p_kind = 'admin' then
    raise exception 'admin accounts cannot be created here' using errcode = '42501';
  end if;
  if p_actor_id is not null then
    perform pg_catalog.set_config('app.actor_id', p_actor_id::text, true);
  end if;
  insert into public.profiles (id, kind, status, display_name, mobile_e164)
  values (p_user_id, p_kind,
          case when p_kind = 'customer' then 'pending_approval'::public.account_status
               else 'approved'::public.account_status end,
          p_display_name, p_mobile_e164);
end;
$$;

create function public.issue_client_code(p_user_id uuid)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_code text;
  v_attempt int := 0;
  v_constraint text;
begin
  loop
    v_attempt := v_attempt + 1;
    v_code := app.generate_client_code();
    begin
      insert into public.client_codes (user_id, client_code) values (p_user_id, v_code);
      return v_code;
    exception when unique_violation then
      get stacked diagnostics v_constraint = constraint_name;
      -- Collision on the code itself: retry. Any other unique violation (e.g. the
      -- customer already has an active code) is a real conflict.
      if v_constraint is distinct from 'client_codes_client_code_key' or v_attempt >= 5 then
        raise;
      end if;
    end;
  end loop;
end;
$$;

create function public.set_access_secret(p_user_id uuid, p_secret_hash text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from public.profiles where id = p_user_id and kind = 'customer') then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  insert into public.access_credentials (user_id, secret_hash)
  values (p_user_id, p_secret_hash)
  on conflict (user_id) do update
    set secret_hash = excluded.secret_hash, secret_set_at = pg_catalog.now(),
        failed_attempts = 0, locked_until = null;
end;
$$;

create function public.get_quick_login_credential(p_client_code text)
returns table (user_id uuid, secret_hash text, status public.account_status, locked_until timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select p.id, ac.secret_hash, p.status, ac.locked_until
  from public.client_codes cc
  join public.profiles p on p.id = cc.user_id and p.kind = 'customer' and p.archived_at is null
  join public.access_credentials ac on ac.user_id = p.id
  where cc.client_code = p_client_code and cc.revoked_at is null
$$;

create function public.record_quick_login_attempt(
  p_user_id uuid, p_success boolean, p_max_failures integer, p_lock_seconds integer)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_failed integer;
  v_locked timestamptz;
  v_prev_locked timestamptz;
begin
  if p_user_id is null or p_success is null
     or p_max_failures is null or p_max_failures not between 1 and 100
     or p_lock_seconds is null or p_lock_seconds not between 1 and 86400 then
    raise exception 'invalid input' using errcode = '22023';
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
         locked_until = case when failed_attempts + 1 >= p_max_failures
                             then pg_catalog.now() + pg_catalog.make_interval(secs => p_lock_seconds)
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

create function public.resolve_login_identifier(p_identifier text)
returns table (user_id uuid, email text, status public.account_status, kind public.user_kind)
language sql
stable
security definer
set search_path = ''
as $$
  select p.id, u.email::text, p.status, p.kind
  from public.profiles p
  join auth.users u on u.id = p.id
  where p.archived_at is null
    and (
      (p_identifier like '%@%' and pg_catalog.lower(u.email) = pg_catalog.lower(p_identifier))
      or (p_identifier like '+%' and p.mobile_e164 = p_identifier)
    )
  limit 1
$$;

create function public.rate_limit_hit(p_key text, p_limit integer, p_window_seconds integer)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_window timestamptz;
  v_hits integer;
  v_epoch bigint;
begin
  if p_key is null or char_length(p_key) not between 1 and 200
     or p_limit is null or p_limit not between 1 and 100000
     or p_window_seconds is null or p_window_seconds not between 1 and 86400 then
    raise exception 'invalid input' using errcode = '22023';
  end if;

  v_epoch := pg_catalog.floor(extract(epoch from pg_catalog.now()) / p_window_seconds)::bigint * p_window_seconds;
  v_window := pg_catalog.to_timestamp(v_epoch);

  insert into public.rate_limits (key, window_start, hits) values (p_key, v_window, 1)
  on conflict (key, window_start) do update set hits = public.rate_limits.hits + 1
  returning hits into v_hits;

  -- Opportunistic housekeeping.
  if pg_catalog.random() < 0.01 then
    delete from public.rate_limits where window_start < pg_catalog.now() - interval '2 days';
  end if;

  return pg_catalog.jsonb_build_object(
    'allowed', v_hits <= p_limit,
    'remaining', greatest(p_limit - v_hits, 0),
    'retry_after_seconds', greatest(ceil(extract(epoch from (v_window + pg_catalog.make_interval(secs => p_window_seconds) - pg_catalog.now()))), 1)::int
  );
end;
$$;

create function public.ensure_commission_period(p_ts timestamptz)
returns public.commission_periods
language sql
security definer
set search_path = ''
as $$
  select * from app.ensure_commission_period(p_ts)
$$;

create function public.calculate_commission_cents(p_amount_minor bigint, p_sale_at timestamptz)
returns bigint
language sql
stable
security definer
set search_path = ''
as $$
  select app.commission_for_sale(p_amount_minor, p_sale_at)
$$;

-- ---------------------------------------------------------------------------
-- First-run setup: one atomic, single-winner transaction.
-- The Node server has already verified the deployment's SETUP_TOKEN and created
-- the Supabase Auth user; this function makes the DATABASE side race-free.
-- ---------------------------------------------------------------------------
create function public.complete_first_run_setup(
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
    'hide_out_of_stock_enabled', 'hide_out_of_stock_after_minutes'];
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
