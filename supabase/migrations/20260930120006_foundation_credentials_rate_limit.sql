-- 001-foundation / migration 6: Client Codes, Secret Access Codes, rate limiting.
--
--   client_codes        : public-ish customer identifier (random, non-predictable).
--   access_credentials  : the Secret Access Code, stored ONLY as an Argon2id hash
--                         produced by the server. No API role can read this table.
--   rate_limits         : fixed-window counters shared by every server instance.

create table public.client_codes (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references public.profiles (id) on delete restrict,
  client_code text not null unique
              check (client_code ~ '^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$'),
  created_at  timestamptz not null default now(),
  revoked_at  timestamptz
);
-- One active code per customer; revoked codes are kept and never re-issued.
create unique index client_codes_one_active_per_user on public.client_codes (user_id) where revoked_at is null;

create function app.client_codes_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_kind public.user_kind;
begin
  if tg_op = 'DELETE' then
    raise exception 'client codes cannot be deleted; revoke them instead' using errcode = '42501';
  end if;
  if tg_op = 'INSERT' then
    select kind into v_kind from public.profiles where id = new.user_id;
    if v_kind is distinct from 'customer' then
      raise exception 'client codes are only issued to customers' using errcode = '42501';
    end if;
    return new;
  end if;
  -- UPDATE: only revocation is permitted.
  if new.client_code is distinct from old.client_code or new.user_id is distinct from old.user_id
     or new.id is distinct from old.id or new.created_at is distinct from old.created_at
     or (old.revoked_at is not null and new.revoked_at is distinct from old.revoked_at) then
    raise exception 'client codes are immutable except for revocation' using errcode = '42501';
  end if;
  return new;
end;
$$;
create trigger client_codes_guard before insert or update or delete on public.client_codes
  for each row execute function app.client_codes_guard();

-- Crockford base32 (no I, L, O, U). 12 random symbols = 60 bits, grouped 4-4-4.
-- Each random byte is reduced modulo 32, which is unbiased because 256 % 32 = 0.
create function app.generate_client_code()
returns text
language plpgsql
volatile
set search_path = ''
as $$
declare
  c_alphabet constant text := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  v_bytes bytea := extensions.gen_random_bytes(12);
  v_out text := '';
  i int;
begin
  for i in 0 .. 11 loop
    v_out := v_out || substr(c_alphabet, (get_byte(v_bytes, i) % 32) + 1, 1);
    if i in (3, 7) then v_out := v_out || '-'; end if;
  end loop;
  return v_out;
end;
$$;

create table public.access_credentials (
  user_id          uuid primary key references public.profiles (id) on delete restrict,
  secret_hash      text not null check (secret_hash like '$argon2id$%'),
  secret_set_at    timestamptz not null default now(),
  failed_attempts  integer not null default 0 check (failed_attempts >= 0),
  locked_until     timestamptz,
  last_failed_at   timestamptz,
  last_success_at  timestamptz,
  updated_at       timestamptz not null default now()
);
comment on table public.access_credentials is 'Secret Access Code hashes. A credential: never selectable through the API, never logged, never audited with its value.';
create trigger access_credentials_updated_at before update on public.access_credentials
  for each row execute function app.set_updated_at();

create table public.rate_limits (
  key           text not null check (char_length(key) between 1 and 200),
  window_start  timestamptz not null,
  hits          integer not null default 0 check (hits >= 0),
  primary key (key, window_start)
);
create index rate_limits_window_idx on public.rate_limits (window_start);
comment on table public.rate_limits is 'Fixed-window counters. Keys are HMACed by the server so no raw IPs or identifiers are stored.';
