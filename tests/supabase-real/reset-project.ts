// DESTRUCTIVE, for the dedicated disposable test project ONLY.
//
// Removes everything the foundation migrations created, and the `test-*@example.com` auth users
// created by the verification suites, so that the suites can be re-run against a "fresh" project.
// It deliberately does NOT drop the `public` schema: that would also discard Supabase's own
// default privileges for new objects, making the test project less faithful to a real one.
//
//   SUPABASE_VERIFY_ALLOW_RESET=yes bun tests/supabase-real/reset-project.ts
import pg from "pg";
import { assertResetAllowed, env } from "./env";

async function main() {
  assertResetAllowed();
  const c = new pg.Client({ connectionString: env("SUPABASE_DB_URL") });
  await c.connect();
  try {
    await c.query("begin");
    const objs = await c.query(
      `select 'table' as kind, format('%I.%I', n.nspname, c.relname) as name
         from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind in ('r','p','v','m','S')
          and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e')
       union all
       select 'function', format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.prokind in ('f','p')
          and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
       union all
       select 'type', format('%I.%I', n.nspname, t.typname)
         from pg_type t join pg_namespace n on n.oid = t.typnamespace
        where n.nspname = 'public' and t.typtype in ('e','d')
          and not exists (select 1 from pg_depend d where d.objid = t.oid and d.deptype = 'e')`,
    );
    for (const kind of ["function", "table", "type"]) {
      for (const o of objs.rows.filter((r) => r.kind === kind)) {
        const stmt =
          kind === "table"
            ? "drop table if exists"
            : kind === "type"
              ? "drop type if exists"
              : "drop function if exists";
        await c.query(`${stmt} ${o.name} cascade`);
      }
    }
    await c.query("drop schema if exists app cascade");
    // Auth users created by the test suites only (pattern is specific to them).
    await c.query("delete from auth.users where email ~ '^test-[a-z0-9-]+@example\\.com$'");
    await c.query("commit");
    console.log("disposable test project reset (foundation objects and test-* users removed)");
  } catch (e) {
    await c.query("rollback").catch(() => {});
    throw e;
  } finally {
    await c.end();
  }
}
main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
