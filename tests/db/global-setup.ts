import pg from "pg";
import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { TestProject } from "vitest/node";
import { applyMigrations, applySql } from "./migrations";

// Starts a REAL PostgreSQL server (embedded-postgres binaries, PostgreSQL 17) in a
// child process (see pg-server.mjs), builds one migrated template database, and
// shares the connection info with the tests.

const here = path.dirname(fileURLToPath(import.meta.url));

declare module "vitest" {
  export interface ProvidedContext {
    pgPort: number;
    pgPassword: string;
    templateDb: string;
  }
}

function startServer(): Promise<{ child: ChildProcess; port: number; password: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(here, "pg-server.mjs")], {
      stdio: ["pipe", "pipe", "inherit"],
      cwd: path.join(here, "..", ".."),
    });
    let buf = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error("PostgreSQL did not start within 120s"));
    }, 120_000);
    child.stdout!.on("data", (chunk: Buffer) => {
      buf += chunk.toString();
      const m = /^READY (.+)$/m.exec(buf);
      if (m) {
        clearTimeout(timer);
        const info = JSON.parse(m[1]!) as { port: number; password: string };
        resolve({ child, ...info });
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`PostgreSQL server process exited early (code ${code})`));
    });
  });
}

function stopServer(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve();
    child.once("exit", () => resolve());
    child.kill("SIGTERM");
  });
}

export default async function setup(project: TestProject) {
  const { child, port, password } = await startServer();
  try {
    const admin = new pg.Client({
      host: "127.0.0.1",
      port,
      user: "postgres",
      password,
      database: "postgres",
    });
    await admin.connect();
    await admin.query("create database cc_template");
    await admin.end();

    const tpl = new pg.Client({
      host: "127.0.0.1",
      port,
      user: "postgres",
      password,
      database: "cc_template",
    });
    await tpl.connect();
    try {
      await applySql(tpl, path.join(here, "supabase-shim.sql"));
      await applyMigrations(tpl);
    } finally {
      await tpl.end();
    }
  } catch (e) {
    // Never leave a server running if the migrations are broken.
    await stopServer(child);
    throw e;
  }

  project.provide("pgPort", port);
  project.provide("pgPassword", password);
  project.provide("templateDb", "cc_template");

  return async () => {
    await stopServer(child);
  };
}
