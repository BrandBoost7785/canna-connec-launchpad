// Authentication throttling defaults.
//
// OWNER DECISION PENDING: these numbers are conservative engineering defaults chosen
// by the deployer of this foundation, NOT business rules supplied by the owner. They
// are centralised here (and exported for tests) so they can be reviewed and changed
// in one place; lockout counters live in the database.
export const AUTH_POLICY = {
  /** Consecutive wrong Secret Access Codes before the credential is locked. */
  maxFailedAttempts: 5,
  lockSeconds: 15 * 60,
  /** Fixed-window request limits (see rate_limit_hit). */
  perIpQuickLogin: { limit: 20, windowSeconds: 10 * 60 },
  perClientCodeQuickLogin: { limit: 10, windowSeconds: 15 * 60 },
  perIpSetup: { limit: 10, windowSeconds: 60 * 60 },
} as const;
