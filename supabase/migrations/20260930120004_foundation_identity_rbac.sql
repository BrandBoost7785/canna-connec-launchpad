-- 001-foundation / migration 4: profiles, roles, permissions and their guards.
--
-- Identity comes from Supabase Auth (auth.users). `profiles` adds the application
-- account (kind + status). Users can NEVER write these tables directly: there are
-- no INSERT/UPDATE/DELETE grants for API roles (see the grants migration). All
-- changes go through SECURITY DEFINER functions that check permissions.

create table public.profiles (
  id            uuid primary key references auth.users (id) on delete restrict,
  kind          public.user_kind not null,
  status        public.account_status not null,
  display_name  text check (display_name is null or char_length(btrim(display_name)) between 1 and 120),
  mobile_e164   text check (mobile_e164 is null or mobile_e164 ~ '^\+[1-9][0-9]{7,14}$'),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  archived_at   timestamptz,
  constraint profiles_staff_status check (kind = 'customer' or status in ('approved', 'suspended'))
);
comment on table public.profiles is 'Application account for each auth user. id is internal and must never be used as a public identifier.';

create unique index profiles_mobile_active_uq on public.profiles (mobile_e164)
  where mobile_e164 is not null and archived_at is null;
create index profiles_kind_status_idx on public.profiles (kind, status) where archived_at is null;

create trigger profiles_updated_at before update on public.profiles
  for each row execute function app.set_updated_at();

alter table public.business_settings
  add constraint business_settings_completed_by_fk
  foreign key (setup_completed_by) references public.profiles (id) on delete restrict;

alter table public.audit_logs
  add constraint audit_logs_actor_fk
  foreign key (actor_id) references public.profiles (id) on delete restrict;

create table public.permissions (
  id           uuid primary key default gen_random_uuid(),
  key          text not null unique check (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
  module       text not null check (char_length(module) between 1 and 60),
  description  text not null check (char_length(description) between 1 and 300),
  -- admin_only permissions can only ever be held by the system `admin` role.
  admin_only   boolean not null default false,
  created_at   timestamptz not null default now()
);
comment on table public.permissions is 'Catalogue of permission keys. Managed by migrations only; not editable through the API.';

create table public.roles (
  id           uuid primary key default gen_random_uuid(),
  key          text not null unique check (key ~ '^[a-z][a-z0-9_]{1,39}$'),
  name         text not null check (char_length(btrim(name)) between 1 and 80),
  description  text check (description is null or char_length(description) <= 300),
  is_system    boolean not null default false,
  archived_at  timestamptz,
  created_by   uuid references public.profiles (id) on delete restrict,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
create trigger roles_updated_at before update on public.roles
  for each row execute function app.set_updated_at();

create table public.role_permissions (
  role_id        uuid not null references public.roles (id) on delete restrict,
  permission_id  uuid not null references public.permissions (id) on delete restrict,
  granted_by     uuid references public.profiles (id) on delete restrict,
  granted_at     timestamptz not null default now(),
  primary key (role_id, permission_id)
);
create index role_permissions_permission_idx on public.role_permissions (permission_id);

create table public.user_roles (
  user_id      uuid not null references public.profiles (id) on delete restrict,
  role_id      uuid not null references public.roles (id) on delete restrict,
  assigned_by  uuid references public.profiles (id) on delete restrict,
  assigned_at  timestamptz not null default now(),
  primary key (user_id, role_id)
);
create index user_roles_role_idx on public.user_roles (role_id);

-- ---------------------------------------------------------------------------
-- Permission checks (the single source of truth for authorization)
-- ---------------------------------------------------------------------------
-- A user holds a permission only when ALL are true: profile is staff
-- (employee/admin), approved, not archived; the role is not archived; the role
-- grants the permission.
create function app.has_permission(p_user uuid, p_key text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles pr
    join public.user_roles ur on ur.user_id = pr.id
    join public.roles r on r.id = ur.role_id and r.archived_at is null
    join public.role_permissions rp on rp.role_id = r.id
    join public.permissions p on p.id = rp.permission_id
    where pr.id = p_user
      and pr.status = 'approved'
      and pr.archived_at is null
      and pr.kind in ('employee', 'admin')
      and p.key = p_key
  )
$$;

-- For RLS policies and API-facing functions: always evaluates the CALLER.
create function app.current_user_has(p_key text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select auth.uid() is not null and app.has_permission(auth.uid(), p_key)
$$;

create function app.require_permission(p_key text)
returns uuid
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null or not app.has_permission(v_uid, p_key) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return v_uid;
end;
$$;

-- ---------------------------------------------------------------------------
-- Guards (defence in depth; these also protect against buggy privileged code)
-- ---------------------------------------------------------------------------
create function app.profiles_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_was_active boolean;
  v_is_active boolean;
begin
  if new.id is distinct from old.id then
    raise exception 'profile id is immutable' using errcode = '42501';
  end if;
  if new.kind is distinct from old.kind then
    raise exception 'account kind is immutable' using errcode = '42501';
  end if;

  -- Never allow the last active administrator to be suspended/archived.
  v_was_active := old.kind = 'admin' and old.status = 'approved' and old.archived_at is null;
  v_is_active  := new.kind = 'admin' and new.status = 'approved' and new.archived_at is null;
  if v_was_active and not v_is_active then
    if not exists (
      select 1 from public.profiles p
      where p.kind = 'admin' and p.status = 'approved' and p.archived_at is null and p.id <> old.id
    ) then
      raise exception 'last_admin' using errcode = '55000',
        detail = 'The last active administrator cannot be deactivated.';
    end if;
  end if;
  return new;
end;
$$;
create trigger profiles_guard before update on public.profiles
  for each row execute function app.profiles_guard();

create function app.roles_guard()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'roles cannot be deleted; archive them instead' using errcode = '42501';
  end if;
  if old.is_system and (new.key is distinct from old.key
                        or new.is_system is distinct from old.is_system
                        or new.archived_at is distinct from old.archived_at) then
    raise exception 'system roles are immutable' using errcode = '42501';
  end if;
  if new.is_system is distinct from old.is_system or new.key is distinct from old.key then
    raise exception 'role key and system flag are immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
create trigger roles_guard before update or delete on public.roles
  for each row execute function app.roles_guard();

create function app.role_permissions_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_role public.roles%rowtype;
  v_admin_only boolean;
begin
  if tg_op = 'DELETE' then
    select * into v_role from public.roles where id = old.role_id;
    if v_role.is_system then
      raise exception 'permissions of system roles cannot be removed' using errcode = '42501';
    end if;
    return old;
  end if;

  select * into v_role from public.roles where id = new.role_id;
  select admin_only into v_admin_only from public.permissions where id = new.permission_id;
  if v_role.archived_at is not null then
    raise exception 'role is archived' using errcode = '22023';
  end if;
  if v_admin_only and not (v_role.is_system and v_role.key = 'admin') then
    raise exception 'admin_only_permission' using errcode = '42501',
      detail = 'This permission can only belong to the administrator role.';
  end if;
  return new;
end;
$$;
create trigger role_permissions_guard before insert or delete on public.role_permissions
  for each row execute function app.role_permissions_guard();

create function app.user_roles_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_kind public.user_kind;
  v_role public.roles%rowtype;
begin
  if tg_op = 'DELETE' then
    select * into v_role from public.roles where id = old.role_id;
    if v_role.key = 'admin' and v_role.is_system then
      if not exists (
        select 1
        from public.user_roles ur
        join public.profiles p on p.id = ur.user_id
        where ur.role_id = old.role_id
          and ur.user_id <> old.user_id
          and p.status = 'approved' and p.archived_at is null
      ) then
        raise exception 'last_admin' using errcode = '55000',
          detail = 'The last active administrator role assignment cannot be removed.';
      end if;
    end if;
    return old;
  end if;

  select kind into v_kind from public.profiles where id = new.user_id;
  select * into v_role from public.roles where id = new.role_id;
  if v_kind is null or v_kind not in ('employee', 'admin') then
    raise exception 'roles can only be assigned to staff accounts' using errcode = '42501';
  end if;
  if v_role.archived_at is not null then
    raise exception 'role is archived' using errcode = '22023';
  end if;
  if v_role.is_system and v_role.key = 'admin' and v_kind <> 'admin' then
    raise exception 'only administrator accounts can hold the admin role' using errcode = '42501';
  end if;
  return new;
end;
$$;
create trigger user_roles_guard before insert or delete on public.user_roles
  for each row execute function app.user_roles_guard();

-- ---------------------------------------------------------------------------
-- Application metadata (NOT business data): the system administrator role and the
-- permission catalogue derived from sections 22-27 of the project specification.
-- The catalogue is a proposal for owner review; see ARCHITECTURE/SECURITY notes.
-- ---------------------------------------------------------------------------
insert into public.roles (key, name, description, is_system)
values ('admin', 'Administrator', 'Holds every permission. Created and protected by the system.', true);

-- Any permission added later is automatically granted to the administrator role.
create function app.grant_permission_to_admin()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.role_permissions (role_id, permission_id)
  select r.id, new.id from public.roles r where r.key = 'admin' and r.is_system
  on conflict do nothing;
  return new;
end;
$$;
create trigger permissions_grant_admin after insert on public.permissions
  for each row execute function app.grant_permission_to_admin();

insert into public.permissions (key, module, description, admin_only) values
  ('customers.view',          'customers',    'View customer accounts and the customer information required to serve orders', false),
  ('customers.manage',        'customers',    'Approve, reject, suspend and reactivate customers',                             true),
  ('orders.view',             'orders',       'View authorized orders',                                                        false),
  ('orders.review',           'orders',       'Accept or reject orders',                                                       false),
  ('orders.adjust_cash',      'orders',       'Adjust eligible cash orders before completion',                                 false),
  ('payments.handle',         'payments',     'Handle the verified payment workflow',                                          false),
  ('cash.confirm',            'payments',     'Confirm cash payment received at meet-up',                                      false),
  ('meetups.view',            'orders',       'View required meet-up information',                                             false),
  ('sales.view',              'sales',        'View sales',                                                                    false),
  ('cashup.perform',          'cash_up',      'Perform and submit the daily cash-up',                                          false),
  ('cashup.review',           'cash_up',      'Review and adjust submitted cash-ups',                                          true),
  ('chat.use',                'chat',         'Use order chat and support chat',                                               false),
  ('commission.view_own',     'commission',   'View own commission',                                                           false),
  ('products.manage',         'catalogue',    'Create and edit products',                                                      true),
  ('prices.manage',           'catalogue',    'Change prices',                                                                 true),
  ('inventory.adjust',        'inventory',    'Adjust stock levels',                                                           true),
  ('promotions.manage',       'promotions',   'Create and edit specials and discounts',                                        true),
  ('reports.view',            'reports',      'View administrative reports',                                                   true),
  ('commissions.manage',      'commission',   'Manage commission configuration, periods and records',                          true),
  ('employees.manage',        'employees',    'Manage employee accounts and role assignments',                                 true),
  ('roles.manage',            'employees',    'Create roles and change role permissions',                                      true),
  ('notifications.manage',    'notifications','Manage notification configuration',                                             true),
  ('audit.view',              'audit',        'View audit logs',                                                               true),
  ('settings.manage',         'settings',     'Change business settings and branding',                                         true),
  ('payment_settings.manage', 'settings',     'Change payment settings',                                                       true),
  ('security_settings.manage','settings',     'Change security settings',                                                      true);
