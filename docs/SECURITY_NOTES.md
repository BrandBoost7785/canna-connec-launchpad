# Security notes — 001 Foundation

This is an engineering record of what is enforced, how it was verified, and what is **not** covered. It is not a legal
opinion and makes no claim of regulatory compliance (POPIA, cannabis regulation, age verification, consent). Those
need review by qualified advisers.

## Controls and how they are verified

| Control                                                        | Enforced in                                | Verified by (executed)                                |
| -------------------------------------------------------------- | ------------------------------------------ | ----------------------------------------------------- |
| RLS on every table; `anon` has no table access                 | migration 09                               | `security-baseline`, `rbac-rls` (real roles, real PG) |
| No write grants to API roles; writes only via RPC              | migration 09                               | `security-baseline` (catalog scan), `rbac-rls`        |
| `SECURITY DEFINER` with `search_path=''`, `EXECUTE` least priv | migrations 07/09                           | `security-baseline` (catalog scan of every function)  |
| Permission checks derive caller from `auth.uid()`              | migration 04/07                            | `rbac-rls` (allowed **and** denied cases)             |
| No privilege escalation / last-admin protection                | migration 04                               | `rbac-rls`                                            |
| Audit append-only, secrets redacted, no spoofed actor          | migrations 02/08                           | `audit` tests                                         |
| Argon2id hash only; lockout; rate limits (atomic)              | migrations 06/07, `src/server`             | `credentials`, `quick-login-flow`, unit tests         |
| Business-day cut-off and DST                                   | migration 03                               | `business-day` (µs boundary, NY DST, property test)   |
| Commission config/period rules                                 | migration 05                               | `commission`                                          |
| Setup single-winner, token-gated, no orphan user               | migration 07, `setup.server.ts`            | `setup`, `setup-flow` (incl. concurrent race)         |
| Security headers                                               | `src/lib/security/headers.ts`, `server.ts` | unit tests (headers built/applied)                    |
| Input validation, no client-supplied privilege fields          | `src/lib/validation`                       | unit tests (strict schemas)                           |
| Safe errors (no SQL/constraint leakage)                        | `src/lib/errors.ts`                        | unit tests                                            |

A mutation check was run: nine deliberate defects (status check removed from `has_permission`, permission check removed
from `admin_create_role`, `EXECUTE` granted to `anon`, redaction removed, cut-off `>=`→`>`, client-code format check
removed, audit immutability disabled, RLS opened, write grant added) — every one made the suite fail; the
migrations were restored afterwards.

## Known limitations / residual risks

1. **Shim, not real Supabase.** GoTrue/PostgREST were not available; the DB suite runs real PostgreSQL 17.10 with a shim of
   Supabase roles. Repeat the RLS checks on a real dev project. Migration 09's explicit `REVOKE`s guard against Supabase default
   grants, but only the shim's behaviour was tested.
2. **Session minting is unverified.** After Quick Login succeeds, a session is created via `auth.admin.generateLink` +
   `verifyOtp`. Not exercised against GoTrue. It requires the customer's auth user to have an email (real or an
   internal placeholder — a decision for the account-creation phase).
3. **CSP allows `'unsafe-inline'` scripts/styles** because the framework injects inline bootstrap scripts. XSS is
   therefore mitigated by React escaping, not by CSP. Nonce-based CSP is future work. The production CSP also allows Google Fonts (used by the existing root layout). It was
   **not exercised in a browser** (the dev server omits CSP/HSTS by design; `vite preview` cannot serve this Cloudflare-style
   build), so any other external resource added later must be allow-listed, and the header should be checked on a deployed preview.
4. **Sessions live in browser storage** (Supabase default). XSS ⇒ session theft. CSRF is handled by the framework's
   cross-origin check on server functions plus Bearer-token auth (cookies are not used for auth).
5. **`frame-ancestors 'none'` by default**: the Lovable preview iframe (or any embed) needs `CSP_FRAME_ANCESTORS`.
6. **Superusers can disable audit triggers** or edit tables (database owner is trusted). Restrict database superuser access.
7. **Rate limiting is a fixed window** (bursts at window edges). Without `CLIENT_IP_HEADER` all callers share one IP bucket.
8. **Account enumeration**: Quick Login returns one generic error and equalises hash timing; the rate limiter and
   lockout are the defence against guessing. Timing was not measured.
9. **DST gaps**: if the configured cut-off falls inside a spring-forward gap, local-time comparison follows PostgreSQL's
   `AT TIME ZONE` resolution; behaviour at that single instant was not separately specified.
10. **Committed `.env` in git history** from before Phase 0 contains publishable values only; history was not rewritten.
    Rotate keys if in doubt.
11. **Secret Access Code length** (8–128) and the Argon2 parameters are engineering defaults.

## Owner decisions still required (nothing below was decided by the code)

- Commission: period membership rule (timestamp vs business day), actual weekly period windows and payout times (none
  seeded), rounding mode (chosen at setup).
- Approval of the **permission catalogue** (26 keys, in migration 04) and which are administrator-only.
- Whether `SETUP_TOKEN` is an acceptable first-admin gate.
- Whether pending/rejected/suspended accounts may sign in (currently: only `approved` can Quick Login).
- Lockout policy (currently 5 failures → 15 min), rate limits, minimum Secret Access Code length.
- Mobile format (currently E.164 only), cut-off must be after 00:00, weekly windows cannot wrap Sunday→Monday.
- Payment provider; notification providers; privacy policy / terms text and consent wording.
- Legal review: POPIA, cannabis regulation, age verification, consent, record retention.
