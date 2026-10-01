// Guard + configuration for the REAL Supabase verification suite.
//
//   *** THIS SUITE HAS NOT BEEN EXECUTED. *** (See docs/REAL_SUPABASE_VERIFICATION.md.)
//   It needs a reachable, DEDICATED, DISPOSABLE Supabase test project, which the build sandbox
//   did not have. Nothing in this directory may be cited as evidence until it has been run.
//
// Credentials are read ONLY from process.env or from the git-ignored file
// `.env.supabase-test.local`. Values are never printed.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const FILE = path.resolve(__dirname, "../../.env.supabase-test.local");

export const CONFIRM_PHRASE = "this-is-a-dedicated-disposable-test-project";

if (existsSync(FILE)) {
  for (const line of readFileSync(FILE, "utf8").split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m || line.trim().startsWith("#")) continue;
    const value = m[2]!.replace(/^(['"])(.*)\1$/, "$2");
    if (process.env[m[1]!] === undefined) process.env[m[1]!] = value;
  }
}

const REQUIRED = [
  "SUPABASE_URL",
  "SUPABASE_PUBLISHABLE_KEY",
  "SUPABASE_SERVICE_ROLE_KEY",
  "SUPABASE_DB_URL",
  "SUPABASE_VERIFY_PROJECT_REF",
  "SUPABASE_VERIFY_CONFIRM",
] as const;

export function assertSafeToRun(): void {
  const missing = REQUIRED.filter((k) => !process.env[k]);
  if (missing.length) {
    throw new Error(
      `Real Supabase verification is NOT configured; missing: ${missing.join(", ")}. ` +
        "See docs/REAL_SUPABASE_VERIFICATION.md. (This suite refuses to run, and is never skipped silently.)",
    );
  }
  if (process.env["SUPABASE_VERIFY_CONFIRM"] !== CONFIRM_PHRASE) {
    throw new Error(
      `Refusing to run: SUPABASE_VERIFY_CONFIRM must equal "${CONFIRM_PHRASE}". ` +
        "This suite creates users and changes configuration; use only a disposable test project.",
    );
  }
  const host = new URL(process.env["SUPABASE_URL"]!).hostname;
  const ref = host.endsWith(".supabase.co") ? (host.split(".")[0] ?? "unknown") : "local";
  if (process.env["SUPABASE_VERIFY_PROJECT_REF"] !== ref) {
    throw new Error(
      "Refusing to run: SUPABASE_VERIFY_PROJECT_REF does not match the project in SUPABASE_URL " +
        '(use "local" for a localhost Supabase CLI stack).',
    );
  }
  const dbHost = new URL(process.env["SUPABASE_DB_URL"]!).hostname;
  if (ref !== "local" && !dbHost.includes(ref)) {
    throw new Error(
      "Refusing to run: SUPABASE_DB_URL does not appear to belong to the same project as SUPABASE_URL.",
    );
  }
}

export const env = (k: (typeof REQUIRED)[number]): string => process.env[k]!;
