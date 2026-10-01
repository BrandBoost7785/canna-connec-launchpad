// Applies supabase/migrations/*.sql to the dedicated test project, in order, each in a
// transaction (like the Supabase CLI). Refuses unless the target is a FRESH project:
// the migrations are not idempotent and this must never touch an already-populated database.
//
//   bun tests/supabase-real/apply-migrations.ts
//
// NOT EXECUTED in the build sandbox.
import pg from "pg";
import { applyMigrations } from "../db/migrations";
import { assertSafeToRun, env } from "./env";

async function main() {
  assertSafeToRun();
  const c = new pg.Client({ connectionString: env("SUPABASE_DB_URL") });
  await c.connect();
  try {
    const exists = await c.query("select to_regclass('public.business_settings') is not null as e");
    if (exists.rows[0].e) {
      throw new Error(
        "public.business_settings already exists: the foundation migrations appear to be applied. " +
          "Use a fresh test project (or reset it) - this script will not touch an existing schema.",
      );
    }
    await applyMigrations(c);
    console.log("foundation migrations applied to the dedicated test project");
  } finally {
    await c.end();
  }
}
main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
