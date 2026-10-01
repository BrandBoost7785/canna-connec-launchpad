# 001 Foundation — technical reference

Scope: database foundation, authorization/RLS, Client Code + Secret Access Code authentication primitives, shared
validation, security baseline, business-day and commission-period functions, first-run setup, tests. Nothing from later
phases (shop, cart, orders, employee/admin modules, payments, chat, notifications, PWA) is implemented. This document
does not claim legal compliance (see [SECURITY_NOTES.md](./SECURITY_NOTES.md)).

## Architecture in one paragraph

TanStack Start (React) app, unchanged. The browser never talks to privileged data directly: it calls server functions
(`src/functions/*.functions.ts`) which validate input with zod (`src/lib/validation`) and call PostgreSQL through either
the **caller's own Supabase session** (so RLS and `auth.uid()` apply) or, for service-only operations, the server-only
service-role client (`src/server/*.server.ts`). **All authorization is decided in PostgreSQL** (RLS policies and
`SECURITY DEFINER` functions that check the caller). Frontend guards are never a security control.

## Environment variables

Names only are tracked in `.env.example`. Real values live in your environment / secret manager.

| Variable                                                          | Scope           | Purpose                                                                                      |
| ----------------------------------------------------------------- | --------------- | -------------------------------------------------------------------------------------------- |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_PROJECT_ID` | server          | Project URL and publishable key                                                              |
| `VITE_SUPABASE_*`                                                 | browser-safe    | Same public values for the browser client                                                    |
| `SUPABASE_SERVICE_ROLE_KEY`                                       | **server only** | Bypasses RLS. Used only in `src/server/*.server.ts`. Verified absent from the client bundle. |
| `SETUP_TOKEN`                                                     | **server only** | ≥32 chars. Required to submit `/setup`; setup is disabled while unset.                       |
| `RATE_LIMIT_KEY_SECRET`                                           | **server only** | ≥32 chars. HMAC key for rate-limit keys. Login/setup **fail closed** if missing.             |
| `CLIENT_IP_HEADER`                                                | server          | Header your trusted proxy sets with the real client IP. Unset ⇒ one shared bucket.           |
| `CSP_FRAME_ANCESTORS`                                             | server          | Origins allowed to frame the site (default `'none'`).                                        |
| `LOVABLE_CRON_SECRET(_PREVIOUS)`                                  | **server only** | Existing cron authentication (unchanged).                                                    |

## Supabase setup assumptions (external configuration)

1. Use your **own development project** for development and a separate one for production.
2. **Disable public sign-ups** (Auth → Providers → Email → "Allow new users to sign up" off). Accounts are created only
   by server code. The database does not (and cannot) depend on this setting; it is an external control you must verify.
3. Email provider/SMTP, password policy and JWT expiry are configured in Supabase, not in this repository.
4. Apply the migrations (below). No seed data is applied.
5. The first administrator is created through `/setup` using `SETUP_TOKEN`.

## Migrations

`supabase/migrations/20260930120001…0009_foundation_*.sql`, applied in filename order (Supabase CLI convention: `supabase db push`
or `supabase migration up` against **your dev/staging project first**). They contain **no fake business data**. The only
rows they insert are system definitions: the `admin` system role and the permission catalogue (a **proposal** for owner
review) plus the single empty `business_settings` row with `setup_completed_at = null`.

| #   | File                   | Content                                                                                |
| --- | ---------------------- | -------------------------------------------------------------------------------------- |
| 01  | schemas_and_enums      | `app` schema (not API-exposed), enums                                                  |
| 02  | audit                  | append-only `audit_logs`, `app.write_audit`, actor helpers                             |
| 03  | settings_business_day  | `business_settings` singleton, notification channels, business-day functions           |
| 04  | identity_rbac          | `profiles`, `roles`, `permissions`, `role_permissions`, `user_roles`, guard triggers   |
| 05  | commission             | commission configuration (versioned), period schedules and periods, amount function    |
| 06  | credentials_rate_limit | `client_codes`, `access_credentials` (hash only), `rate_limits`                        |
| 07  | rpc                    | all `SECURITY DEFINER` API/service functions                                           |
| 08  | audit_triggers         | audit triggers (secret hashes redacted)                                                |
| 09  | rls_and_grants         | RLS policies and explicit `REVOKE`/`GRANT` for `anon`, `authenticated`, `service_role` |

Conventions: money is integer minor units; `timestamptz` everywhere; archive (`archived_at`) instead of delete; audit
columns (`created_at`, `updated_at`, `created_by`…) on mutable tables. Error convention (SQLSTATE): `42501` forbidden,
`22023` invalid input, `P0002` not found, `55000` state conflict, `P0001` configuration required, `23505` conflict,
`23514` check violation. Never run migrations against a database you do not own; there are no destructive statements
on existing data, but the order matters and they are not designed to be re-applied.

## Authentication architecture

- Identity = Supabase Auth user. `profiles` (1:1 with `auth.users`, `ON DELETE RESTRICT`) holds `kind`
  (`customer|employee|admin`), `status` and archive state. `kind` is immutable.
- **Client Code**: `XXXX-XXXX-XXXX`, Crockford Base32 (no I/L/O/U), 60 random bits from `gen_random_bytes` (pgcrypto),
  unique, immutable, never reused (revoked codes are kept). Issued by `issue_client_code` (service only).
- **Secret Access Code**: stored **only** as an Argon2id PHC hash (`@noble/hashes`, m=19456 KiB, t=2, p=1). The database
  rejects any value that is not an Argon2id hash. Verification is constant time; unknown Client Codes perform a
  dummy verification to equalise timing.
- `quickLogin` (`src/server/quick-login.server.ts`): rate limit (IP, Client Code) → look up credential → verify → record
  attempt (DB-side lockout counter) → only `approved` accounts proceed → mint a session. Every failure is the same
  generic error.
- The customer approval / sign-up workflow is **not** implemented (owner-defined, later phase). Accounts reach
  `approved` only through an administrator-side change in a later phase.
- Staff/customers with email or mobile + password use standard Supabase Auth (`resolve_login_identifier` helps map a
  mobile number to an email for that flow).
- Administrators are created **only** by `complete_first_run_setup` (one-time, single-winner, service-only). There are no
  default credentials and no master codes.

## Authorization / RLS model

- Every table has RLS enabled. `anon` has no table access. `authenticated` has `SELECT` only where a policy allows; there
  are **no** `INSERT/UPDATE/DELETE` grants to API roles anywhere — writes go only through `SECURITY DEFINER` functions.
- `SECURITY DEFINER` functions: `set search_path = ''`, fully-qualified names, explicit checks
  (`app.require_permission(key)` derives the caller from `auth.uid()`, never from an argument), validated input,
  `EXECUTE` revoked from `PUBLIC`/`anon` and granted to the minimum role. Service-only functions are executable by
  `service_role` only.
- Roles/permissions: a user's permissions come from `user_roles → role_permissions`, counted only while the account is
  `approved`, not archived, and of kind employee/admin. Permissions flagged `admin_only` cannot be granted to non-admin
  roles; the `admin` role is immutable and only administrator accounts can hold it; the last administrator cannot be removed.
- Customers can read only their own profile; no customer-to-customer access exists. Employees cannot escalate: they
  cannot assign roles, edit roles, or change their own status.
- The audit log is append-only (triggers reject UPDATE/DELETE/TRUNCATE, even for the table owner), readable only with
  `audit.view`, and contains no secret material.

## Business day and commission periods

- `business_settings` holds timezone, currency, cut-off time. **Nothing is defaulted**: until `setup_completed_at` is set,
  functions raise `configuration_required`.
- `app.business_day_of(ts, tz, cutoff)`: the local calendar day of `ts`, advanced by one day when local time ≥ cut-off
  (so with a 20:00 cut-off, 19:59:59.999999 belongs to that day and 20:00:00 to the next). Computed in the configured
  IANA zone (DST-safe); public wrappers `business_day_for(ts)` / `current_business_day()` use the configured values.
- Commission: `commission_configurations` are versioned, effective-dated and immutable (new row to change);
  `commission_period_schedules` are owner-defined weekly windows (day-of-week + time); `ensure_commission_period` materialises
  concrete periods (exclusion constraint prevents overlap). **No schedule or percentage is seeded.** Rounding mode is
  a setting chosen at setup. Test windows in the suite are explicitly labelled TEST FIXTURE.

## First-run setup

`/setup` renders an empty form (no prefilled business values). It posts to `submitFirstRunSetup`, which requires
`SETUP_TOKEN`, is rate limited, validates everything, creates the auth user, and calls `complete_first_run_setup`
(single-winner under a row lock). If the database rejects the submission the auth user is removed again. After success
the route only reports "already completed".

## Testing

```sh
bun run test      # unit tests (no DB, no secrets)
bun run test:db   # REAL PostgreSQL 17 via embedded-postgres: migrations, RLS, functions, audit, flows
bun run test:all  # both
```

`test:db` needs no installation beyond `bun install`: `tests/db/pg-server.mjs` starts a throw-away server (PostgreSQL
binaries from the `embedded-postgres` dev dependency; requires a **non-root** user, Linux/macOS/Windows x64/arm64) on a
random local port, builds one migrated template database and clones it per test file. Nothing touches an existing database.

What the DB suite does **not** prove: it runs against a minimal shim of Supabase's roles and `auth` schema
(`tests/db/supabase-shim.sql`), not real GoTrue/PostgREST/Supabase Storage. The shim revokes default privileges more
strictly than Supabase's defaults, so migration 09 revokes explicitly and tests guard against regressions, but you
should still run the migrations against a real Supabase **development** project and repeat the RLS checks there
(see SECURITY_NOTES.md). Session minting after a successful Quick Login is verified only up to the GoTrue call.
