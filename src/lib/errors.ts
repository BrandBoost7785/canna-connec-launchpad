// Safe error handling: map database / server failures to a fixed set of messages.
// Raw database messages, SQL, constraint names and stack traces are logged on the
// server only and never returned to the browser.

export type AppErrorCode =
  | "invalid_input"
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "state_conflict"
  | "rate_limited"
  | "configuration_required"
  | "internal";

const PUBLIC_MESSAGES: Record<AppErrorCode, string> = {
  invalid_input: "The submitted information is not valid.",
  unauthenticated: "Authentication failed.",
  forbidden: "You do not have permission to perform this action.",
  not_found: "The requested item was not found.",
  conflict: "This conflicts with existing information.",
  state_conflict: "This action is not available in the current state.",
  rate_limited: "Too many attempts. Please try again later.",
  configuration_required: "This feature requires configuration by the business owner.",
  internal: "Something went wrong. Please try again later.",
};

const STATUS: Record<AppErrorCode, number> = {
  invalid_input: 400,
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  state_conflict: 409,
  rate_limited: 429,
  configuration_required: 503,
  internal: 500,
};

export class AppError extends Error {
  readonly code: AppErrorCode;
  readonly status: number;
  readonly retryAfterSeconds: number | undefined;
  constructor(code: AppErrorCode, retryAfterSeconds?: number) {
    super(PUBLIC_MESSAGES[code]);
    this.name = "AppError";
    this.code = code;
    this.status = STATUS[code];
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** SQLSTATE -> application error code (see the error convention in the migrations). */
export function codeFromSqlState(state: string | undefined | null): AppErrorCode {
  switch (state) {
    case "42501":
      return "forbidden";
    case "22023":
    case "22P02": // invalid_text_representation (bad uuid / enum)
    case "22007":
    case "22008":
    case "23514": // check_violation
    case "23502": // not_null_violation
      return "invalid_input";
    case "P0002":
      return "not_found";
    case "23505":
    case "23P01": // exclusion_violation
    case "23503": // foreign_key_violation
      return "conflict";
    case "55000":
      return "state_conflict";
    case "P0001":
      return "configuration_required";
    default:
      return "internal";
  }
}

/** Convert anything thrown by the data layer into an AppError (the raw error is logged). */
export function toAppError(error: unknown, context?: string): AppError {
  if (error instanceof AppError) return error;
  const state =
    typeof error === "object" && error !== null ? (error as { code?: unknown }).code : undefined;
  const code = typeof state === "string" ? codeFromSqlState(state) : "internal";
  if (code === "internal") {
    console.error(`[error]${context ? ` ${context}` : ""}`, error);
  }
  return new AppError(code);
}

export function publicMessage(code: AppErrorCode): string {
  return PUBLIC_MESSAGES[code];
}
