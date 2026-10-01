// Runs a throw-away REAL PostgreSQL server (embedded-postgres binaries) in its OWN
// process. It is deliberately not imported into the vitest process: embedded-postgres
// installs an `async-exit-hook` that calls process.exit(0) and would mask failing
// test runs (a CI false-pass). Protocol: prints one line `READY <json>` when the
// server accepts connections; stops and exits when stdin closes or on SIGTERM/SIGINT.
import EmbeddedPostgres from "embedded-postgres";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });

const dataDir = mkdtempSync(path.join(tmpdir(), "cc-pg-"));
const port = await freePort();
const password = "test-only-" + Math.random().toString(36).slice(2);
const server = new EmbeddedPostgres({
  databaseDir: dataDir,
  user: "postgres",
  password,
  port,
  persistent: false,
  postgresFlags: ["-c", "max_connections=300", "-c", "fsync=off"],
  onLog: () => {},
  onError: () => {},
});

let stopping = false;
async function shutdown(code) {
  if (stopping) return;
  stopping = true;
  try {
    await server.stop();
  } catch {
    /* ignore */
  }
  rmSync(dataDir, { recursive: true, force: true });
  process.exit(code);
}
process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));
process.stdin.on("end", () => shutdown(0));
process.stdin.on("close", () => shutdown(0));
process.stdin.resume();

try {
  await server.initialise();
  await server.start();
  process.stdout.write(`READY ${JSON.stringify({ port, password })}\n`);
} catch (e) {
  console.error("failed to start PostgreSQL:", e);
  await shutdown(1);
}
