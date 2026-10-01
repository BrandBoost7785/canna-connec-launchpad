// Runtime + real-browser verification of the PRODUCTION BUILD (`.output/`):
//   * real PostgreSQL 17 with the real migrations (embedded-postgres, child process)
//   * the built Cloudflare-style worker running in workerd (via `wrangler dev`)
//   * real headless Chromium (puppeteer-core + @sparticuz/chromium)
//   * BACKEND (selected with BROWSER_BACKEND):
//       - default "stand-in": a STAND-IN for the Supabase HTTP APIs
//         (tests/browser/stand-in-supabase.mjs) over a local PostgreSQL. It is NOT Supabase; this
//         mode says nothing about Supabase compatibility (regression evidence only).
//       - "real": the dedicated DEVELOPMENT Supabase project (same SUPABASE_* variables and
//         guards as tests/supabase-real). Needs a freshly migrated, not-yet-set-up project.
//
// Tooling is installed outside the repository so the project gains no heavy dependency:
//   mkdir -p /tmp/rt && cd /tmp/rt && npm i wrangler@4 @sparticuz/chromium puppeteer-core
//   bun run build && BROWSER_TOOLS_DIR=/tmp/rt bun tests/browser/browser-check.ts
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import pg from "pg";
import { createClient } from "@supabase/supabase-js";
import { applyMigrations, applySql } from "../db/migrations";
import { assertSafeToRun, env as realEnv } from "../supabase-real/env";

const ROOT = path.resolve(__dirname, "../..");
const TOOLS = process.env["BROWSER_TOOLS_DIR"] ?? "/tmp/rt";
const req = createRequire(path.join(TOOLS, "package.json"));
const rnd = (n: number) => randomBytes(n).toString("base64url");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Dbq = { query: (sql: string, params?: unknown[]) => Promise<{ rows: any[] }> };
const results: { name: string; ok: boolean; detail?: string }[] = [];
const check = (name: string, ok: boolean, detail?: string) => {
  results.push({ name, ok, ...(detail ? { detail } : {}) });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  -- ${detail}` : ""}`);
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const REAL = process.env["BROWSER_BACKEND"] === "real";
  if (REAL) assertSafeToRun();
  console.log(
    REAL
      ? "BACKEND: REAL dedicated development Supabase project (credentials not printed)"
      : "BACKEND: STAND-IN for the Supabase HTTP APIs (NOT Supabase) over local PostgreSQL",
  );
  const secrets = {
    serviceKey: REAL ? realEnv("SUPABASE_SERVICE_ROLE_KEY") : "svc_" + rnd(24),
    publishableKey: REAL ? realEnv("SUPABASE_PUBLISHABLE_KEY") : "pub_" + rnd(24),
    setupToken: "setup-" + rnd(40),
    rateKey: "rl-" + rnd(40),
    adminPassword: `Aa1!${rnd(18)}`,
  };
  const SUPABASE_URL = REAL ? realEnv("SUPABASE_URL") : "http://127.0.0.1:54321";
  const adminEmail = REAL
    ? `test-browser-admin-${rnd(4)
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "x")}@example.com`
    : "owner@example.invalid";
  // The browser client is configured at BUILD time with the two PUBLIC values.
  if (process.env["SKIP_BUILD"] !== "1") {
    console.log("building production bundle (public VITE_SUPABASE_* values only) ...");
    const b = spawnSync("bun", ["run", "build"], {
      cwd: ROOT,
      stdio: "ignore",
      env: {
        ...process.env,
        VITE_SUPABASE_URL: SUPABASE_URL,
        VITE_SUPABASE_PUBLISHABLE_KEY: secrets.publishableKey,
      },
    });
    if (b.status !== 0) throw new Error("build failed");
  }
  const children: ChildProcess[] = [];
  const cleanup: (() => Promise<void>)[] = [];

  try {
    // ---- backend ------------------------------------------------------------------------
    let dbq: Dbq;
    if (REAL) {
      const c = new pg.Client({ connectionString: realEnv("SUPABASE_DB_URL") });
      await c.connect();
      cleanup.push(() => c.end());
      dbq = c;
    } else {
      const { startStandIn } = await import("./stand-in-supabase.mjs" as string);
      const pgChild = spawn(process.execPath, [path.join(ROOT, "tests/db/pg-server.mjs")], {
        stdio: ["pipe", "pipe", "inherit"],
        cwd: ROOT,
      });
      children.push(pgChild);
      cleanup.push(async () => {
        pgChild.kill("SIGTERM");
      });
      const info = await new Promise<{ port: number; password: string }>((resolve, reject) => {
        let buf = "";
        pgChild.stdout!.on("data", (c: Buffer) => {
          buf += c.toString();
          const m = /^READY (.+)$/m.exec(buf);
          if (m) resolve(JSON.parse(m[1]!));
        });
        pgChild.on("exit", () => reject(new Error("pg exited")));
      });
      const cfg = (database: string) => ({
        host: "127.0.0.1",
        port: info.port,
        user: "postgres",
        password: info.password,
        database,
      });
      const root = new pg.Client(cfg("postgres"));
      await root.connect();
      await root.query("create database cc_browser");
      await root.end();
      const mig = new pg.Client(cfg("cc_browser"));
      await mig.connect();
      await applySql(mig, path.join(ROOT, "tests/db/supabase-shim.sql"));
      await applyMigrations(mig);
      await mig.end();
      const standIn = await startStandIn({
        port: 54321,
        pgConfig: cfg("cc_browser"),
        serviceKey: secrets.serviceKey,
      });
      cleanup.push(() => standIn.close());
      dbq = standIn.su;
    }
    // Fresh-project guard (real mode): setup must not have happened yet.
    const pre = await dbq.query(
      "select setup_completed_at is not null as done from public.business_settings",
    );
    if (pre.rows[0]?.["done"])
      throw new Error("project is not fresh: setup already completed (reset it)");

    // ---- built worker in workerd ----------------------------------------------------
    // Worker variables go through a git-ignored .dev.vars file (wrangler prints them as "(hidden)"),
    // never through command-line flags.
    const devVars = {
      SUPABASE_URL,
      SUPABASE_SERVICE_ROLE_KEY: secrets.serviceKey,
      SUPABASE_PUBLISHABLE_KEY: secrets.publishableKey,
      SETUP_TOKEN: secrets.setupToken,
      RATE_LIMIT_KEY_SECRET: secrets.rateKey,
      // TEST FIXTURE deployment values (the repository has no defaults for these):
      SETUP_RATE_LIMIT_ATTEMPTS: "50",
      SETUP_RATE_LIMIT_WINDOW_SECONDS: "3600",
      CLIENT_IP_HEADER: "x-test-client-ip",
    };
    const varsFile = path.join(ROOT, ".output/server/.dev.vars");
    writeFileSync(
      varsFile,
      Object.entries(devVars)
        .map(([k, v]) => `${k}=${v}`)
        .join("\n") + "\n",
      { mode: 0o600 },
    );
    const wr = spawn(
      path.join(TOOLS, "node_modules/.bin/wrangler"),
      [
        "dev",
        "-c",
        path.join(ROOT, ".output/server/wrangler.json"),
        "--local",
        "--port",
        "8787",
        "--ip",
        "127.0.0.1",
      ],
      {
        cwd: TOOLS,
        env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false" },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    children.push(wr);
    let wrLog = "";
    wr.stdout!.on("data", (c) => (wrLog += c));
    wr.stderr!.on("data", (c) => (wrLog += c));
    const BASE = "http://127.0.0.1:8787";
    for (let i = 0; i < 90; i++) {
      try {
        const r = await fetch(BASE + "/", { redirect: "manual" });
        if (r.status) break;
      } catch {
        /* not up yet */
      }
      await sleep(1000);
      if (i === 89) throw new Error("worker did not start:\n" + wrLog.slice(-1200));
    }

    // ---- 1. raw HTTP headers --------------------------------------------------------
    const setupRes = await fetch(BASE + "/setup");
    const h = setupRes.headers;
    const csp = h.get("content-security-policy") ?? "";
    check("GET /setup returns 200", setupRes.status === 200, String(setupRes.status));
    check("CSP header present", csp.length > 0, csp);
    check("CSP: frame-ancestors 'none'", /frame-ancestors 'none'/.test(csp));
    check(
      "CSP: object-src 'none', base-uri 'self'",
      /object-src 'none'/.test(csp) && /base-uri 'self'/.test(csp),
    );
    check(
      "CSP: no wildcard source in script/default/connect",
      !/(script|default|connect)-src[^;]*\*/.test(csp),
    );
    check("HSTS header present", /max-age=\d+/.test(h.get("strict-transport-security") ?? ""));
    check("X-Content-Type-Options: nosniff", h.get("x-content-type-options") === "nosniff");
    check("Referrer-Policy present", !!h.get("referrer-policy"));
    check("Permissions-Policy present", !!h.get("permissions-policy"));
    check("Cross-Origin-Opener-Policy present", !!h.get("cross-origin-opener-policy"));
    const rootRes = await fetch(BASE + "/");
    check(
      "GET / (existing landing page) 200 with CSP",
      rootRes.status === 200 && !!rootRes.headers.get("content-security-policy"),
    );

    // ---- 2. real browser ------------------------------------------------------------
    const puppeteer = req("puppeteer-core");
    const chromiumModule = req("@sparticuz/chromium");
    const chromium = chromiumModule.default ?? chromiumModule;
    const inflate = chromiumModule.inflate ?? chromium.inflate;
    const executablePath: string = await chromium.executablePath();
    // On non-Lambda hosts @sparticuz/chromium does not unpack the shared libraries (nss/nspr) it
    // needs; unpack them explicitly and point the loader at them.
    const libDir = path.join(path.dirname(executablePath), "al2023", "lib");
    if (!existsSync(libDir)) {
      await inflate(path.join(TOOLS, "node_modules/@sparticuz/chromium/bin/al2023.tar.br"));
    }
    const browser = await puppeteer.launch({
      args: [...chromium.args, "--no-sandbox"],
      executablePath,
      env: { ...process.env, LD_LIBRARY_PATH: libDir },
      headless: "shell",
    });
    cleanup.push(async () => {
      await browser.close();
    });
    const page = await browser.newPage();
    const violations: string[] = [];
    const consoleErrors: string[] = [];
    const failed: string[] = [];
    const scripts = new Set<string>();
    const serverFnResponses: { url: string; cache: string | null; status: number; body: string }[] =
      [];
    await page.evaluateOnNewDocument(() => {
      document.addEventListener("securitypolicyviolation", (e) => {
        (window as unknown as { __csp: string[] }).__csp ??= [];
        (window as unknown as { __csp: string[] }).__csp.push(
          `${e.violatedDirective} blocked ${e.blockedURI}`,
        );
      });
    });
    page.on("console", (m: { type(): string; text(): string }) => {
      if (m.type() === "error") consoleErrors.push(m.text());
    });
    page.on("requestfailed", (r: { url(): string; failure(): { errorText: string } | null }) =>
      failed.push(`${r.url()} ${r.failure()?.errorText}`),
    );
    page.on(
      "response",
      async (r: {
        url(): string;
        status(): number;
        headers(): Record<string, string>;
        text(): Promise<string>;
      }) => {
        const u = r.url();
        if (/\.js(\?|$)/.test(u)) scripts.add(u);
        if (u.includes("/_serverFn/")) {
          serverFnResponses.push({
            url: u,
            cache: r.headers()["cache-control"] ?? null,
            status: r.status(),
            body: await r.text().catch(() => ""),
          });
        }
      },
    );

    await page.goto(BASE + "/setup", { waitUntil: "networkidle0", timeout: 60000 });
    const fromPage = async () =>
      (await page.evaluate(
        () => (window as unknown as { __csp?: string[] }).__csp ?? [],
      )) as string[];
    violations.push(...(await fromPage()));

    check(
      "setup heading rendered",
      (await page.$eval("h1", (e: Element) => e.textContent)) === "First-run setup",
    );
    const fieldInfo = await page.$$eval("input, select", (els: Element[]) =>
      els.map((e) => ({
        type: (e as HTMLInputElement).type,
        value: (e as HTMLInputElement).value,
      })),
    );
    check("form has many fields", fieldInfo.length >= 20, String(fieldInfo.length));
    check(
      "NO field is prefilled with a value",
      fieldInfo.every((f: { value: string }) => f.value === ""),
    );
    check(
      "password fields use type=password",
      fieldInfo.filter((f: { type: string }) => f.type === "password").length >= 2,
    );
    check(
      "no CSP violations while loading /setup (hydration, styles, scripts)",
      violations.length === 0,
      violations.join(" | "),
    );
    // React hydrated? typing must update state => the controlled input shows our text.
    await page.type('input[type="email"]', "typed@example.invalid");
    check(
      "page is interactive (React hydrated, no inline-script block)",
      (await page.$eval('input[type="email"]', (e: Element) => (e as HTMLInputElement).value)) ===
        "typed@example.invalid",
    );

    // empty submit -> client-side validation message, no network call to server fn
    const before = serverFnResponses.length;
    await page.click('button[type="submit"]');
    await sleep(500);
    const alertText = await page
      .$eval('[role="alert"]', (e: Element) => e.textContent)
      .catch(() => null);
    check(
      "submitting an incomplete form shows a validation message",
      !!alertText,
      String(alertText),
    );
    check("...without calling the server", serverFnResponses.length === before);

    // fill the whole form (TEST FIXTURE values)
    const fill = async (label: string, value: string) => {
      const handle = await page.evaluateHandle((l: string) => {
        const lab = [...document.querySelectorAll("label")].find((x) =>
          x.textContent?.startsWith(l),
        );
        return lab?.parentElement?.querySelector("input,select") ?? null;
      }, label);
      const el = handle.asElement();
      if (!el) throw new Error("field not found: " + label);
      if ((await el.evaluate((n: Element) => n.tagName)) === "SELECT") await el.select(value);
      else {
        await el.click({ clickCount: 3 });
        await el.type(value);
      }
    };
    const fillAll = async (token: string) => {
      await fill("Setup token", token);
      await fill("Display name", "Browser Test Admin");
      await fill("Email", adminEmail);
      await fill("Password", secrets.adminPassword);
      await fill("Business name", "BROWSER TEST BUSINESS");
      await fill("Time zone", "Africa/Johannesburg");
      await fill("Currency code", "ZAR");
      await fill("Business-day cut-off", "20:00");
      await fill("Cart reservation duration", "15");
      await fill("Default low-stock threshold", "5");
      await fill("Availability check interval", "5");
      await fill("Hide out-of-stock products?", "yes");
      await fill("Hide after out of stock", "60");
      await fill("Failed Secret Access Code attempts", "3");
      await fill("Lock duration", "900");
      await fill("Quick-login attempts allowed per IP", "20");
      await fill("…window length for the per-IP", "600");
      await fill("Quick-login attempts allowed per Client Code", "10");
      await fill("…window length for the per-Client-Code", "900");
      await fill("Minimum Secret Access Code length", "8");
      await fill("Commission rate", "1000");
      await fill("Rounding mode", "half_up");
    };
    await page.reload({ waitUntil: "networkidle0" });
    await fillAll("wrong-token-" + rnd(30));
    await page.click('button[type="submit"]');
    await page.waitForFunction(() => document.querySelector('[role="alert"]'), { timeout: 20000 });
    const wrongMsg = await page.$eval('[role="alert"]', (e: Element) => e.textContent ?? "");
    check(
      "wrong setup token -> safe, generic 'no permission' message",
      /permission/i.test(wrongMsg),
      wrongMsg,
    );
    check(
      "error text contains no stack/SQL/secret",
      !/(at |\.ts|select |relation|secret|token|supabase|postgres)/i.test(
        wrongMsg.replace(/setup token/gi, ""),
      ),
      wrongMsg,
    );
    const wrongFn = serverFnResponses.at(-1);
    check(
      "server-function response has Cache-Control: no-store",
      wrongFn?.cache === "no-store",
      String(wrongFn?.cache),
    );
    check(
      "server-function response body leaks no secret",
      !JSON.stringify(wrongFn?.body).includes(secrets.setupToken),
    );
    check(
      "no admin/settings created by the failed attempt",
      (await dbq.query("select count(*)::int n from public.profiles")).rows[0].n === 0,
    );

    // correct token
    await page.reload({ waitUntil: "networkidle0" });
    await fillAll(secrets.setupToken);
    await page.click('button[type="submit"]');
    await page.waitForFunction(() => document.body.innerText.includes("Setup complete"), {
      timeout: 30000,
    });
    check("correct setup token completes setup in the browser", true);

    const adm = (await dbq.query("select p.kind, p.status from public.profiles p")).rows;
    check(
      "exactly one approved admin profile created",
      adm.length === 1 && adm[0].kind === "admin" && adm[0].status === "approved",
    );
    const st = (
      await dbq.query(
        "select business_name, timezone, login_lock_seconds, setup_completed_at is not null as done from public.business_settings",
      )
    ).rows[0];
    check(
      "owner-entered values stored",
      st.business_name === "BROWSER TEST BUSINESS" &&
        st.timezone === "Africa/Johannesburg" &&
        st.login_lock_seconds === 900 &&
        st.done,
    );
    const rl = (await dbq.query("select key from public.rate_limits")).rows
      .map((r: { key: string }) => r.key)
      .join(" ");
    check(
      "rate-limit keys are HMACs (no raw IP stored)",
      /setup-ip:[0-9a-f]{64}/.test(rl) &&
        !/127\.0\.0\.1|unknown/.test(rl.replace(/[0-9a-f]{64}/g, "")),
    );

    await page.goto(BASE + "/setup", { waitUntil: "networkidle0" });
    check(
      "revisiting /setup reports setup already completed",
      (await page.evaluate(() => document.body.innerText)).includes("already been configured"),
    );
    check("form no longer rendered after completion", (await page.$$("input")).length === 0);

    if (REAL) {
      const u = await dbq.query("select id from auth.users where email = $1", [adminEmail]);
      check("REAL Auth: the setup flow created exactly one auth user", u.rows.length === 1);
      const sb = createClient(SUPABASE_URL, secrets.publishableKey, {
        auth: { persistSession: false, autoRefreshToken: false },
      });
      const signed = await sb.auth.signInWithPassword({
        email: adminEmail,
        password: secrets.adminPassword,
      });
      check(
        "REAL Auth: the setup admin can sign in and receives a session",
        !!signed.data.session && !signed.error,
      );
      const prof = await dbq.query("select id from public.profiles");
      check(
        "REAL Auth: session subject equals the profile created by setup",
        signed.data.user?.id === prof.rows[0]?.["id"],
      );
      const me = await sb.rpc("my_access");
      check(
        "REAL PostgREST: my_access resolves the session identity as approved admin",
        (me.data as { kind?: string; status?: string } | null)?.kind === "admin" &&
          (me.data as { status?: string }).status === "approved",
      );
      const handoff = process.env["SUPABASE_VERIFY_BROWSER_SETUP_FILE"];
      if (handoff) {
        mkdirSync(path.dirname(handoff), { recursive: true });
        writeFileSync(
          handoff,
          JSON.stringify({
            email: adminEmail,
            password: secrets.adminPassword,
            id: prof.rows[0]?.["id"],
            setupToken: secrets.setupToken,
          }),
          { mode: 0o600 },
        );
      }
    }

    // ---- 3. no secret in any client-delivered script or HTML ------------------------
    const bundles: string[] = [];
    for (const u of scripts) bundles.push(await (await fetch(u)).text());
    const html = await (await fetch(BASE + "/setup")).text();
    const haystack = bundles.join("\n") + html;
    const mustNotAppear: [string, string][] = [
      ["service key value", secrets.serviceKey],
      ["setup token value", secrets.setupToken],
      ["rate-limit HMAC secret value", secrets.rateKey],
      ["admin password", secrets.adminPassword],
      ["env name SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SERVICE_ROLE_KEY"],
      ["env name RATE_LIMIT_KEY_SECRET", "RATE_LIMIT_KEY_SECRET"],
      ["env name SETUP_TOKEN", "SETUP_TOKEN"],
      ["argon2id hashing code", "argon2id"],
      ["service-only RPC name", "get_quick_login_credential"],
    ];
    for (const [label, needle] of mustNotAppear)
      check(`client bundle/HTML does not contain: ${label}`, !haystack.includes(needle));
    check(`scanned ${scripts.size} client script(s) + HTML`, scripts.size > 0);

    // ---- 4. CSP violations / console over the whole session -------------------------
    violations.push(...(await fromPage()));
    const cspConsole = consoleErrors.filter((e) => /Content Security Policy|Refused to/i.test(e));
    check(
      "no CSP violation events during the whole session",
      violations.length === 0,
      violations.join(" | "),
    );
    check("no CSP-related console errors", cspConsole.length === 0, cspConsole.join(" | "));
    const nonCspFailures = failed.filter((f) => !/googleapis|gstatic/.test(f));
    check(
      "no failed requests other than external fonts (blocked by sandbox egress, not CSP)",
      nonCspFailures.length === 0,
      nonCspFailures.join(" | "),
    );
    const fontReq = failed.filter((f) => /googleapis|gstatic/.test(f));
    console.log(
      `INFO  external font requests attempted (allowed by CSP; network unreachable in sandbox): ${fontReq.length}`,
    );

    // ---- 5. framing is refused ------------------------------------------------------
    const embedder = createServer((_q, s) => {
      s.writeHead(200, { "content-type": "text/html" });
      s.end(`<iframe id="f" src="${BASE}/setup" width="400" height="300"></iframe>`);
    });
    await new Promise<void>((r) => embedder.listen(9000, "127.0.0.1", r));
    const p2 = await browser.newPage();
    const frameErrors: string[] = [];
    p2.on("console", (m: { text(): string }) => frameErrors.push(m.text()));
    await p2.goto("http://127.0.0.1:9000/", { waitUntil: "load" });
    await sleep(1500);
    const frameLoaded = await p2.evaluate(() => {
      const f = document.getElementById("f") as HTMLIFrameElement;
      try {
        return !!f.contentDocument?.body?.innerText?.includes("First-run setup");
      } catch {
        return false; // cross-origin: cannot read => inspect via frames below
      }
    });
    const frames = p2.frames().filter((f: { url(): string }) => f.url().includes(":8787"));
    let framedContent = false;
    for (const f of frames)
      framedContent ||= (
        await f.evaluate(() => document.body?.innerText ?? "").catch(() => "")
      ).includes("First-run setup");
    check(
      "embedding /setup in another origin's iframe is refused (frame-ancestors 'none')",
      !frameLoaded && !framedContent,
      frameErrors.join(" | "),
    );
    embedder.close();
  } finally {
    for (const c of cleanup.reverse()) await c().catch(() => {});
    for (const c of children) c.kill("SIGTERM");
  }

  const failedChecks = results.filter((r) => !r.ok);
  console.log(
    `\nTOTAL ${results.length} checks, ${results.length - failedChecks.length} passed, ${failedChecks.length} failed`,
  );
  process.exit(failedChecks.length ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
