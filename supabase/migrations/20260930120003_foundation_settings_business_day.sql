-- 001-foundation / migration 3: business settings + business-day functions.
--
-- Every owner-controlled value is NULL until the owner configures it (first-run
-- setup). Nothing here decides a business name, cutoff, timezone, etc. on the
-- owner's behalf. Once `setup_completed_at` is set, a CHECK constraint guarantees
-- the operational values are present.

create function app.is_valid_timezone(p_name text)
returns boolean
language sql
stable
set search_path = ''
as $$
  select p_name is not null and exists (select 1 from pg_catalog.pg_timezone_names where name = p_name)
$$;

create table public.business_settings (
  singleton                        boolean primary key default true check (singleton),

  -- Branding (no default business name / logo / slogan is invented)
  business_name                    text check (business_name is null or char_length(btrim(business_name)) between 1 and 120),
  tagline                          text check (tagline is null or char_length(tagline) <= 200),
  logo_url                         text check (logo_url is null or (char_length(logo_url) <= 500 and logo_url ~ '^(https://|/)[^\s]+$')),
  primary_color                    text check (primary_color is null or primary_color ~ '^#[0-9A-Fa-f]{6}$'),
  contact_email                    text check (contact_email is null or (char_length(contact_email) <= 254 and contact_email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$')),
  contact_phone                    text check (contact_phone is null or contact_phone ~ '^\+[1-9][0-9]{7,14}$'),

  -- Regional / business day
  timezone                         text check (timezone is null or app.is_valid_timezone(timezone)),
  currency_code                    text check (currency_code is null or currency_code ~ '^[A-Z]{3}$'),
  business_day_cutoff              time check (business_day_cutoff is null or business_day_cutoff > time '00:00'),

  -- Cart / stock / visibility timing (all owner-configurable)
  cart_duration_minutes            integer check (cart_duration_minutes is null or cart_duration_minutes between 1 and 1440),
  low_stock_default_threshold      integer check (low_stock_default_threshold is null or low_stock_default_threshold >= 0),
  availability_check_minutes       integer check (availability_check_minutes is null or availability_check_minutes >= 0),
  hide_out_of_stock_enabled        boolean,
  hide_out_of_stock_after_minutes  integer check (hide_out_of_stock_after_minutes is null or hide_out_of_stock_after_minutes >= 0),

  -- Customer sign-up configuration
  customer_email_required          boolean,

  -- Payment (provider key only; credentials live in environment secrets)
  payment_provider_key             text check (payment_provider_key is null or payment_provider_key ~ '^[a-z][a-z0-9_]{1,39}$'),

  -- Legal placeholders. The business owner must supply legally reviewed text.
  privacy_policy_text              text check (privacy_policy_text is null or char_length(privacy_policy_text) <= 100000),
  terms_text                       text check (terms_text is null or char_length(terms_text) <= 100000),
  consent_required                 boolean,

  setup_completed_at               timestamptz,
  setup_completed_by               uuid,          -- FK added once profiles exist

  created_at                       timestamptz not null default now(),
  updated_at                       timestamptz not null default now(),

  constraint business_settings_complete_requires_core check (
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
    )
  )
);
comment on table public.business_settings is 'Single-row business configuration. All owner-controlled values are NULL until configured.';

-- The single row is configuration scaffolding, not business data.
insert into public.business_settings (singleton) values (true);

create function app.business_settings_guard()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'business_settings row cannot be deleted' using errcode = '42501';
  end if;
  if old.setup_completed_at is not null and new.setup_completed_at is distinct from old.setup_completed_at then
    raise exception 'setup_completed_at cannot be changed once set' using errcode = '42501';
  end if;
  return new;
end;
$$;

create trigger business_settings_guard
  before update or delete on public.business_settings
  for each row execute function app.business_settings_guard();

create trigger business_settings_updated_at
  before update on public.business_settings
  for each row execute function app.set_updated_at();

create table public.notification_channel_settings (
  channel         public.notification_channel primary key,
  enabled         boolean not null default false,
  provider_label  text check (provider_label is null or char_length(provider_label) <= 80),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
comment on table public.notification_channel_settings is 'Owner intent per channel. A channel only becomes operational when real provider credentials are configured (later checkpoint).';

create trigger notification_channel_settings_updated_at
  before update on public.notification_channel_settings
  for each row execute function app.set_updated_at();

-- ---------------------------------------------------------------------------
-- Business day
--   Rule (from the project specification): a sale before the cutoff belongs to the
--   current business day; a sale AT or after the cutoff belongs to the FOLLOWING
--   business day. Time comes from the database, never from the browser.
-- ---------------------------------------------------------------------------
create function app.business_day_of(p_ts timestamptz, p_timezone text, p_cutoff time)
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
  if p_cutoff <= time '00:00' then
    raise exception 'invalid business-day cutoff' using errcode = '22023';
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

-- [starts_at, ends_at) of a business day: from the previous calendar day's cutoff to
-- this calendar day's cutoff, in the business timezone.
create function app.business_day_bounds_of(p_day date, p_timezone text, p_cutoff time)
returns table (starts_at timestamptz, ends_at timestamptz)
language plpgsql
stable
set search_path = ''
as $$
begin
  if p_day is null or p_timezone is null or p_cutoff is null then
    raise exception 'configuration_required' using errcode = 'P0001';
  end if;
  if p_cutoff <= time '00:00' then
    raise exception 'invalid business-day configuration' using errcode = '22023';
  end if;
  starts_at := timezone(p_timezone, (p_day - 1)::timestamp + p_cutoff);
  ends_at   := timezone(p_timezone, p_day::timestamp + p_cutoff);
  return next;
end;
$$;

-- Configured variants (read the settings row; raise `configuration_required` if unset).
create function app.business_day_for(p_ts timestamptz)
returns date
language sql
stable
security definer
set search_path = ''
as $$
  select app.business_day_of(p_ts, s.timezone, s.business_day_cutoff)
  from public.business_settings s
  where s.singleton
$$;

create function app.current_business_day()
returns date
language sql
stable
security definer
set search_path = ''
as $$
  select app.business_day_for(pg_catalog.now())
$$;

create function app.business_day_bounds(p_day date)
returns table (starts_at timestamptz, ends_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select b.starts_at, b.ends_at
  from public.business_settings s,
       lateral app.business_day_bounds_of(p_day, s.timezone, s.business_day_cutoff) b
  where s.singleton
$$;
