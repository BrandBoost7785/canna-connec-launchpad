import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  TABLES,
  catalogDeviations,
  expectedAnonFunctions,
  expectedAuthenticatedFunctions,
  expectedServiceFunctions,
} from "../supabase-real/expectations";
import { createTestDb, type TestDb } from "./harness";

// The same catalog assertions that tests/supabase-real runs against a real Supabase project,
// run here against the embedded PostgreSQL + shim. (Shim-based: it proves the migrations'
// grants are what the expectations say; it does NOT prove Supabase's own defaults.)
let db: TestDb;
beforeAll(async () => {
  db = await createTestDb();
});
afterAll(async () => {
  await db.close();
});

describe("grant / RLS matrix (embedded PostgreSQL)", () => {
  it("matches the intended matrix exactly", async () => {
    const d = await catalogDeviations((sql, params) => db.su.query(sql, params));
    expect(d.tables).toEqual([...TABLES].sort());
    expect(d.tablesWithoutRls).toEqual([]);
    expect(d.tablePrivilegeDeviations).toEqual([]);
    expect(d.anonFunctions).toEqual(expectedAnonFunctions());
    expect(d.authenticatedFunctions).toEqual(expectedAuthenticatedFunctions());
    expect(d.serviceFunctions).toEqual(expectedServiceFunctions());
    expect(d.definerCount).toBeGreaterThan(20);
    expect(d.definersWithoutPinnedSearchPath).toEqual([]);
  });
});
