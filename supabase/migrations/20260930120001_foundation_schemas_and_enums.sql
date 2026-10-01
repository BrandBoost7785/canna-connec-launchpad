-- 001-foundation / migration 1: schemas, extensions, enums, shared helpers.
--
-- Security model (see SECURITY_NOTES.md):
--   * `public`  is exposed by the Supabase API (PostgREST). Every object here must
--               have RLS enabled and explicit, minimal grants.
--   * `app`     holds internal helpers. It is NOT exposed by the API.
--   * All SECURITY DEFINER functions set `search_path = ''` and schema-qualify
--     every reference.
--
-- This migration creates NO business data.

create schema if not exists app;
comment on schema app is 'Internal helper functions. Not exposed through the API.';
revoke all on schema app from public;
grant usage on schema app to authenticated, service_role;

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------------
-- Enums (explicit values; no free-text core statuses)
-- ---------------------------------------------------------------------------
create type public.user_kind as enum ('customer', 'employee', 'admin');
comment on type public.user_kind is 'Which experience an account belongs to. Immutable once set.';

create type public.account_status as enum ('pending_approval', 'approved', 'rejected', 'suspended');
comment on type public.account_status is 'Account lifecycle state. Customer approval workflow logic arrives in a later checkpoint; the state itself is enforced by RLS/permission checks now.';

create type public.money_rounding_mode as enum ('half_up', 'half_even', 'down', 'up');
comment on type public.money_rounding_mode is 'Rounding applied to minor-unit (integer) money calculations. Chosen by the business owner.';

create type public.notification_channel as enum ('in_app', 'push', 'email', 'sms', 'whatsapp');

-- ---------------------------------------------------------------------------
-- Shared helpers
-- ---------------------------------------------------------------------------
create function app.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := pg_catalog.now();
  return new;
end;
$$;

-- The acting user for audit purposes.
--   * normal API calls: the JWT subject (auth.uid()).
--   * trusted server-side (service_role) RPCs: they may set the transaction-local
--     GUC `app.actor_id` after validating it. A real user JWT always wins.
create function app.actor_id()
returns uuid
language sql
stable
set search_path = ''
as $$
  select coalesce(auth.uid(), nullif(pg_catalog.current_setting('app.actor_id', true), '')::uuid)
$$;

create function app.actor_source()
returns text
language sql
stable
set search_path = ''
as $$
  select case
    when auth.uid() is not null then 'user'
    when coalesce(auth.role(), '') = 'service_role' then 'service'
    else 'system'
  end
$$;
