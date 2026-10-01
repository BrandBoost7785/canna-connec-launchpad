-- 001-foundation / migration 2: append-only audit log.
--
-- * Rows are written only by SECURITY DEFINER code (app.write_audit / triggers).
-- * UPDATE, DELETE and TRUNCATE are rejected by triggers for every role.
--   (A database superuser can still disable triggers; see SECURITY_NOTES.md.)

create table public.audit_logs (
  id              bigint generated always as identity primary key,
  occurred_at     timestamptz not null default now(),
  actor_id        uuid,
  actor_source    text not null check (actor_source in ('user', 'service', 'system')),
  action          text not null check (char_length(action) between 3 and 100),
  target_table    text,
  target_id       text,
  previous_value  jsonb,
  new_value       jsonb,
  context         jsonb not null default '{}'::jsonb
);
comment on table public.audit_logs is 'Append-only audit trail. Never edited or deleted by application code.';

create index audit_logs_occurred_at_idx on public.audit_logs (occurred_at desc);
create index audit_logs_actor_idx       on public.audit_logs (actor_id, occurred_at desc);
create index audit_logs_target_idx      on public.audit_logs (target_table, target_id, occurred_at desc);
create index audit_logs_action_idx      on public.audit_logs (action, occurred_at desc);

create function app.audit_logs_immutable()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'audit_logs is append-only' using errcode = '42501';
end;
$$;

create trigger audit_logs_no_update_delete
  before update or delete on public.audit_logs
  for each row execute function app.audit_logs_immutable();

create trigger audit_logs_no_truncate
  before truncate on public.audit_logs
  for each statement execute function app.audit_logs_immutable();

-- Internal writer. Not executable by API roles (see the grants migration).
create function app.write_audit(
  p_action text,
  p_target_table text default null,
  p_target_id text default null,
  p_previous jsonb default null,
  p_new jsonb default null,
  p_context jsonb default '{}'::jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.audit_logs
    (actor_id, actor_source, action, target_table, target_id, previous_value, new_value, context)
  values
    (app.actor_id(), app.actor_source(), p_action, p_target_table, p_target_id,
     p_previous, p_new, coalesce(p_context, '{}'::jsonb));
end;
$$;

-- Generic row-change auditor.
--   TG_ARGV[0]   : comma-separated column(s) forming the target id, e.g. 'id' or 'user_id,role_id'
--   TG_ARGV[1..] : columns to REDACT from the stored previous/new values (secrets).
create function app.audit_row_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_old jsonb;
  v_new jsonb;
  v_id text;
  v_cols text[];
  v_col text;
  v_parts text[] := '{}';
  i int;
begin
  if tg_op in ('UPDATE', 'DELETE') then v_old := to_jsonb(old); end if;
  if tg_op in ('INSERT', 'UPDATE') then v_new := to_jsonb(new); end if;

  for i in 1 .. coalesce(tg_nargs, 0) - 1 loop
    v_col := tg_argv[i];
    if v_old is not null then v_old := v_old - v_col; end if;
    if v_new is not null then v_new := v_new - v_col; end if;
  end loop;

  -- Ignore updates that only touch updated_at.
  if tg_op = 'UPDATE' and (v_old - 'updated_at') = (v_new - 'updated_at') then
    return new;
  end if;

  v_cols := pg_catalog.string_to_array(tg_argv[0], ',');
  foreach v_col in array v_cols loop
    v_parts := v_parts || coalesce(coalesce(v_new, v_old) ->> v_col, '');
  end loop;
  v_id := pg_catalog.array_to_string(v_parts, ':');

  perform app.write_audit(
    pg_catalog.lower(tg_table_name) || '.' || pg_catalog.lower(tg_op),
    tg_table_name, v_id, v_old, v_new,
    pg_catalog.jsonb_build_object('trigger', tg_name)
  );

  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;
