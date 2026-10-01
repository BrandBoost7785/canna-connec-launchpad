-- =============================================================================
-- TEST-ONLY. NOT a migration. NEVER applied to a real Supabase project.
--
-- A plain PostgreSQL server has no Supabase Auth, no PostgREST and no Supabase
-- roles. This file recreates ONLY the minimum the migrations depend on, copying the
-- real Supabase definitions where they exist:
--   * roles anon / authenticated / service_role (service_role has BYPASSRLS)
--   * schemas auth and extensions
--   * a minimal auth.users table (the real one has many more columns)
--   * auth.uid() / auth.role() / auth.jwt() as defined by Supabase
--   * Supabase's default privileges on `public` (API roles get ALL on new objects),
--     which makes these tests STRICTER: the migrations must actively revoke access.
--
-- What this does NOT prove: GoTrue (Supabase Auth) behaviour, PostgREST request
-- handling, JWT verification, Realtime or Storage. See TESTING_GUIDE.md.
-- =============================================================================

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
end $$;

create schema if not exists extensions;
grant usage on schema extensions to anon, authenticated, service_role;

create schema if not exists auth;
grant usage on schema auth to anon, authenticated, service_role;

create table auth.users (
  id                 uuid primary key default gen_random_uuid(),
  email              text,
  phone              text,
  encrypted_password text,
  raw_user_meta_data jsonb not null default '{}'::jsonb,
  created_at         timestamptz not null default now()
);
create unique index users_email_lower_uq on auth.users (lower(email)) where email is not null;

-- Same definitions as Supabase.
create function auth.uid() returns uuid language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;
create function auth.role() returns text language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;
create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$$;
grant execute on function auth.uid(), auth.role(), auth.jwt() to anon, authenticated, service_role;

-- Supabase's default privileges for objects created by the migration role.
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables    to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
