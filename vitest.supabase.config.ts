import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// REAL Supabase verification suite. Deliberately NOT part of `vitest.config.ts`, `bun run test`,
// `bun run test:db` or CI: it refuses to run unless a dedicated test project is configured.
// See docs/REAL_SUPABASE_VERIFICATION.md.   Run with: bun run test:supabase
export default defineConfig({
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  test: {
    name: "supabase-real",
    environment: "node",
    include: ["tests/supabase-real/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    fileParallelism: false,
    sequence: { concurrent: false },
  },
});
