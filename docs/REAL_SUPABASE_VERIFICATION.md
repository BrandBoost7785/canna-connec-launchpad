# Real Supabase verification (NOT YET EXECUTED)

> **Status: not run.** The build sandbox could only reach GitHub and npm; no Supabase project, GoTrue or PostgREST was
> reachable. The suite below was written and type-checked, and its _catalog assertions_ also run (and pass) against the
> embedded PostgreSQL in `tests/db/grant-matrix.test.ts`, but **no result from a real Supabase project exists**. Do not cite
> it as evidence until you have run it and kept the output.

## What it verifies (all through real Supabase services)

| Area                                          | Where                                                                                                                  |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| RLS on, table grants, function EXECUTE matrix | section A, catalog queries on the real project's `pg_catalog` (same expectations as the embedded test)                 |
| `SECURITY DEFINER` hygiene, `app` not exposed | section A (`search_path=""`, non-API owner, `PGRST106` on schema `app`)                                                |
| Anonymous access                              | section B: every table (SELECT/INSERT/UPDATE/DELETE) and every sensitive RPC over PostgREST                            |
| First-run setup, real Auth admin API          | section C: the app's own `completeFirstRunSetup`, repeat and wrong token                                               |
| Real sessions, identity from the JWT          | section D: `signInWithPassword`, invalid credentials, `my_access`, tampered/forged/`alg:none` tokens, user_metadata    |
| Customer isolation, employee boundaries       | section E: own-row only, no cross-customer access, no DML, no admin/service RPC, least-privilege role, escalation      |
| Admin-only operations, audit access           | section F: settings change audited with the admin's identity; no DML even for admin; audit log immutable               |
| Quick-login (Client Code + secret) end to end | section G: the app's `quickLogin` mints a real session; wrong/unknown/locked/unapproved are all the same generic error |

## Safety rules the suite enforces

- Use a **dedicated, disposable** project. Never a production or unknown project.
- It refuses to start unless **all** of these are set, and never prints their values:
  `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_DB_URL` (Postgres connection string),
  `SUPABASE_VERIFY_PROJECT_REF` (must equal the project ref in the URL, or `local`),
  `SUPABASE_VERIFY_CONFIRM=this-is-a-dedicated-disposable-test-project`.
- Credentials come from the shell or from `.env.supabase-test.local` (git-ignored by `.env.*`). Do not commit it.
- The project must be **fresh** (no foundation setup yet). The suite aborts otherwise. It creates users named
  `test-*@example.com` (email-confirmed, no mail sent) and completes first-run setup with **test fixture** values, so reset
  or delete the project afterwards. Users it created are deleted at the end where the database allows.

## How to run

```sh
touch .env.supabase-test.local            # then add ONLY the variables above (test project!)
bun install --frozen-lockfile
bun run test:supabase:migrate                # applies supabase/migrations/*.sql (refuses a non-fresh project)
bun run test:supabase                        # the suite; keep the full output as evidence
```

Also configure the project as production would be: **disable public sign-ups** and note the password policy. Section D
checks real behaviour but cannot see external dashboard settings.

## Running it on GitHub Actions (when the sandbox/your machine cannot reach Supabase)

`.github/workflows/real-supabase-verification.yml` runs, in order: **reset** of the disposable project, **migrate**,
the **browser check against the real backend** (`bun run test:browser:real`, which performs first-run setup through the
real UI), then the **suite**, then a final reset; logs are uploaded as an artifact. The project owner sets the
configuration once (values are never printed by the workflow; the `gh secret set` form prompts and does not echo):

```sh
R=BrandBoost7785/canna-connec-launchpad
gh secret set SUPABASE_TEST_URL              --repo $R
gh secret set SUPABASE_TEST_PUBLISHABLE_KEY  --repo $R
gh secret set SUPABASE_TEST_SERVICE_ROLE_KEY --repo $R
gh secret set SUPABASE_TEST_DB_URL           --repo $R   # the *Session pooler* connection string (runners have no IPv6)
gh variable set SUPABASE_TEST_PROJECT_REF    --repo $R --body <the-dev-project-ref>
gh variable set SUPABASE_VERIFY_CONFIRM      --repo $R --body this-is-a-dedicated-disposable-test-project
gh variable set SUPABASE_VERIFY_ALLOW_RESET  --repo $R --body yes
```

**The reset step deletes the foundation tables/functions/types and every `test-*@example.com` auth user in that
project.** Use only a project that holds nothing you want to keep. (`bun run test:supabase:reset` is the same script.)

## Interpreting results

Any failure is a finding, not a test to be loosened. Particularly likely places for real-vs-shim differences: Supabase's
default privileges on new objects (migration 09 revokes explicitly), PostgREST's exposed-schema list, the `auth.uid()`
implementation, and Auth's handling of `generateLink` / `verifyOtp` for session minting.
