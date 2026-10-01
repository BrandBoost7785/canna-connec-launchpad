-- 001-foundation / migration 5: commission configuration, period schedules, period
-- records and deterministic calculation functions.
--
-- NOTHING is seeded. The rate, rounding rule and the period schedule are chosen by
-- the business owner. Commission *records* for individual sales arrive with the
-- sales/orders checkpoints; this migration only provides the configuration and the
-- deterministic functions those records will use.

-- Versioned rate history. Insert-only: past rows are never edited, so any historic
-- commission calculation can be reproduced.
create table public.commission_configurations (
  id              uuid primary key default gen_random_uuid(),
  rate_bps        integer not null check (rate_bps between 0 and 10000),  -- basis points: 4000 = 40.00%
  rounding        public.money_rounding_mode not null,
  effective_from  timestamptz not null,
  note            text check (note is null or char_length(note) <= 300),
  created_by      uuid references public.profiles (id) on delete restrict,
  created_at      timestamptz not null default now(),
  constraint commission_configurations_effective_uq unique (effective_from)
);
comment on column public.commission_configurations.rate_bps is 'Commission rate in basis points (1 bp = 0.01%). Integer; no floating point.';

create function app.commission_configurations_immutable()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'commission configuration history is append-only' using errcode = '42501';
end;
$$;
create trigger commission_configurations_no_change
  before update or delete on public.commission_configurations
  for each row execute function app.commission_configurations_immutable();
create trigger commission_configurations_no_truncate
  before truncate on public.commission_configurations
  for each statement execute function app.commission_configurations_immutable();

-- Weekly windows evaluated in the business timezone. Minutes are measured from
-- Monday 00:00 (ISO week). A window may not wrap across the Sunday/Monday boundary.
create table public.commission_period_schedules (
  id            uuid primary key default gen_random_uuid(),
  label         text not null check (char_length(btrim(label)) between 1 and 80),
  start_dow     smallint not null check (start_dow between 1 and 7),   -- ISO: 1 = Monday ... 7 = Sunday
  start_time    time not null,
  end_dow       smallint not null check (end_dow between 1 and 7),
  end_time      time not null,
  payout_dow    smallint not null check (payout_dow between 1 and 7),
  payout_time   time not null,
  start_minute  integer generated always as ((start_dow - 1) * 1440 + extract(hour from start_time)::int * 60 + extract(minute from start_time)::int) stored,
  end_minute    integer generated always as ((end_dow - 1) * 1440 + extract(hour from end_time)::int * 60 + extract(minute from end_time)::int) stored,
  payout_minute integer generated always as ((payout_dow - 1) * 1440 + extract(hour from payout_time)::int * 60 + extract(minute from payout_time)::int) stored,
  active        boolean not null default true,
  created_by    uuid references public.profiles (id) on delete restrict,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint commission_schedule_window_ordered check (start_minute < end_minute),
  -- Active windows must not overlap each other.
  constraint commission_schedule_no_overlap exclude using gist (int4range(start_minute, end_minute) with &&) where (active)
);
create unique index commission_period_schedules_label_active_uq
  on public.commission_period_schedules (lower(label)) where active;
create trigger commission_period_schedules_updated_at before update on public.commission_period_schedules
  for each row execute function app.set_updated_at();

-- Concrete period instances. Created on demand from a REAL timestamp (never
-- pre-generated/fabricated) and they snapshot their boundaries, so later
-- schedule edits never change history.
create table public.commission_periods (
  id           uuid primary key default gen_random_uuid(),
  schedule_id  uuid not null references public.commission_period_schedules (id) on delete restrict,
  label        text not null,
  timezone     text not null,
  starts_at    timestamptz not null,
  ends_at      timestamptz not null,
  payout_at    timestamptz not null,
  created_at   timestamptz not null default now(),
  constraint commission_periods_ordered check (starts_at < ends_at and ends_at <= payout_at),
  constraint commission_periods_schedule_start_uq unique (schedule_id, starts_at)
);
create index commission_periods_range_idx on public.commission_periods (starts_at, ends_at);

create function app.commission_periods_immutable()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'commission periods are immutable' using errcode = '42501';
end;
$$;
create trigger commission_periods_no_change
  before update or delete on public.commission_periods
  for each row execute function app.commission_periods_immutable();

-- ---------------------------------------------------------------------------
-- Deterministic commission amount, in minor units (integers only).
-- ---------------------------------------------------------------------------
create function app.commission_amount(p_amount_minor bigint, p_rate_bps integer, p_rounding public.money_rounding_mode)
returns bigint
language plpgsql
immutable
set search_path = ''
as $$
declare
  v_num numeric;
  v_q numeric;
  v_r numeric;
begin
  if p_amount_minor is null or p_rate_bps is null or p_rounding is null then
    raise exception 'invalid commission input' using errcode = '22023';
  end if;
  if p_amount_minor < 0 then
    raise exception 'commission amount must not be negative' using errcode = '22023';
  end if;
  if p_rate_bps < 0 or p_rate_bps > 10000 then
    raise exception 'invalid commission rate' using errcode = '22023';
  end if;

  v_num := p_amount_minor::numeric * p_rate_bps::numeric;   -- exact
  v_q := trunc(v_num / 10000);
  v_r := v_num - v_q * 10000;                                 -- 0 .. 9999

  if v_r = 0 then
    return v_q::bigint;
  end if;
  case p_rounding
    when 'down' then return v_q::bigint;
    when 'up' then return (v_q + 1)::bigint;
    when 'half_up' then
      if v_r >= 5000 then return (v_q + 1)::bigint; else return v_q::bigint; end if;
    when 'half_even' then
      if v_r > 5000 then return (v_q + 1)::bigint;
      elsif v_r < 5000 then return v_q::bigint;
      elsif mod(v_q, 2) = 0 then return v_q::bigint;
      else return (v_q + 1)::bigint;
      end if;
  end case;
end;
$$;

-- The configuration in force at a point in time.
create function app.commission_configuration_at(p_at timestamptz)
returns public.commission_configurations
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_row public.commission_configurations;
begin
  select * into v_row
  from public.commission_configurations
  where effective_from <= p_at
  order by effective_from desc
  limit 1;
  if not found then
    raise exception 'configuration_required' using errcode = 'P0001',
      detail = 'No commission configuration is in force for this time.';
  end if;
  return v_row;
end;
$$;

create function app.commission_for_sale(p_amount_minor bigint, p_sale_at timestamptz)
returns bigint
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_cfg public.commission_configurations;
begin
  v_cfg := app.commission_configuration_at(p_sale_at);
  return app.commission_amount(p_amount_minor, v_cfg.rate_bps, v_cfg.rounding);
end;
$$;

-- Window (without creating a record) that contains a timestamp, or no row when the
-- timestamp falls in a gap / no schedule is configured. Boundaries are
-- start-inclusive, end-exclusive, evaluated on the business-timezone wall clock.
create function app.commission_window_for(p_ts timestamptz)
returns table (
  schedule_id uuid, label text, timezone text,
  starts_at timestamptz, ends_at timestamptz, payout_at timestamptz
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_tz text;
  v_local timestamp;
  v_week timestamp;
  v_sec double precision;
  v_s public.commission_period_schedules%rowtype;
  v_payout_local timestamp;
begin
  select s.timezone into v_tz from public.business_settings s where s.singleton;
  if v_tz is null then
    raise exception 'configuration_required' using errcode = 'P0001',
      detail = 'The business timezone must be configured.';
  end if;

  v_local := p_ts at time zone v_tz;
  v_week  := date_trunc('week', v_local);                       -- Monday 00:00 (ISO)
  v_sec   := extract(epoch from (v_local - v_week));

  select * into v_s
  from public.commission_period_schedules cs
  where cs.active and v_sec >= cs.start_minute * 60 and v_sec < cs.end_minute * 60
  limit 1;
  if not found then
    return;
  end if;

  v_payout_local := v_week + (v_s.payout_minute * interval '1 minute');
  if v_s.payout_minute < v_s.end_minute then
    v_payout_local := v_payout_local + interval '7 days';       -- first payout at/after the window end
  end if;

  schedule_id := v_s.id;
  label       := v_s.label;
  timezone    := v_tz;
  starts_at   := timezone(v_tz, v_week + (v_s.start_minute * interval '1 minute'));
  ends_at     := timezone(v_tz, v_week + (v_s.end_minute * interval '1 minute'));
  payout_at   := timezone(v_tz, v_payout_local);
  return next;
end;
$$;

-- Find-or-create the concrete period record for a real timestamp.
create function app.ensure_commission_period(p_ts timestamptz)
returns public.commission_periods
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_w record;
  v_row public.commission_periods;
begin
  select * into v_w from app.commission_window_for(p_ts);
  if v_w.schedule_id is null then
    return null;
  end if;

  insert into public.commission_periods (schedule_id, label, timezone, starts_at, ends_at, payout_at)
  values (v_w.schedule_id, v_w.label, v_w.timezone, v_w.starts_at, v_w.ends_at, v_w.payout_at)
  on conflict (schedule_id, starts_at) do nothing;

  select * into v_row from public.commission_periods
  where schedule_id = v_w.schedule_id and starts_at = v_w.starts_at;
  return v_row;
end;
$$;
