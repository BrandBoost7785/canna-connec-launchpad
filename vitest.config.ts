import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Standalone config: the app's vite.config.ts wraps TanStack Start / Nitro plugins
// that are not needed (or wanted) when running tests.
//
// Two projects:
//   unit - fast, no database, no network. `bun run test`
//   db   - runs against a REAL PostgreSQL server (embedded-postgres binaries).
//          `bun run test:db`
const alias = { "@": fileURLToPath(new URL("./src", import.meta.url)) };

export default defineConfig({
  resolve: { alias },
  test: {
    projects: [
      {
        resolve: { alias },
        test: {
          name: "unit",
          environment: "node",
          include: ["src/**/*.test.{ts,tsx}", "tests/**/*.test.{ts,tsx}"],
          exclude: ["tests/db/**", "node_modules/**"],
          // Unit tests must never talk to a real backend or read local .env secrets.
          env: { SUPABASE_URL: "", SUPABASE_SERVICE_ROLE_KEY: "" },
        },
      },
      {
        resolve: { alias },
        test: {
          name: "db",
          environment: "node",
          include: ["tests/db/**/*.test.ts"],
          globalSetup: ["tests/db/global-setup.ts"],
          testTimeout: 60_000,
          hookTimeout: 180_000,
        },
      },
    ],
  },
});
