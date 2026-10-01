-- 001-foundation / migration 8: attach audit triggers.
-- AFTER triggers so foreign keys (audit_logs.actor_id -> profiles) see final state.
-- Permission catalogue seed data (migration 4) is intentionally not audited.

create trigger audit_business_settings after insert or update or delete on public.business_settings
  for each row execute function app.audit_row_change('singleton');
create trigger audit_notification_channel_settings after insert or update or delete on public.notification_channel_settings
  for each row execute function app.audit_row_change('channel');
create trigger audit_profiles after insert or update or delete on public.profiles
  for each row execute function app.audit_row_change('id');
create trigger audit_roles after insert or update or delete on public.roles
  for each row execute function app.audit_row_change('id');
create trigger audit_role_permissions after insert or update or delete on public.role_permissions
  for each row execute function app.audit_row_change('role_id,permission_id');
create trigger audit_user_roles after insert or update or delete on public.user_roles
  for each row execute function app.audit_row_change('user_id,role_id');
create trigger audit_commission_configurations after insert on public.commission_configurations
  for each row execute function app.audit_row_change('id');
create trigger audit_commission_period_schedules after insert or update or delete on public.commission_period_schedules
  for each row execute function app.audit_row_change('id');
create trigger audit_client_codes after insert or update or delete on public.client_codes
  for each row execute function app.audit_row_change('id');

-- Secret Access Code hashes: audit creation and rotation, never the value.
create trigger audit_access_credentials_insert after insert on public.access_credentials
  for each row execute function app.audit_row_change('user_id', 'secret_hash');
create trigger audit_access_credentials_rotate after update on public.access_credentials
  for each row when (old.secret_hash is distinct from new.secret_hash)
  execute function app.audit_row_change('user_id', 'secret_hash');
