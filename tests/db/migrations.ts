import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type pg from "pg";

export const MIGRATIONS_DIR = path.resolve(__dirname, "../../supabase/migrations");

export function listMigrationFiles(): string[] {
  return readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort();
}

export async function applySql(client: pg.Client, file: string): Promise<void> {
  await client.query(readFileSync(file, "utf8"));
}

/** Applies every migration in filename order, each in its own transaction (as the Supabase CLI does). */
export async function applyMigrations(client: pg.Client): Promise<void> {
  for (const f of listMigrationFiles()) {
    const sql = readFileSync(path.join(MIGRATIONS_DIR, f), "utf8");
    try {
      await client.query("begin");
      await client.query(sql);
      await client.query("commit");
    } catch (e) {
      await client.query("rollback").catch(() => {});
      throw new Error(`Migration ${f} failed: ${(e as Error).message}`);
    }
  }
}
