// STAND-IN for the Supabase HTTP APIs, used ONLY by the browser/runtime check.
//
//   NOT REAL SUPABASE. It is a ~100-line translator that exposes just enough of
//   PostgREST (`POST /rest/v1/rpc/<fn>`) and GoTrue admin (`/auth/v1/admin/users`)
//   for the app's first-run setup flow, backed by the REAL PostgreSQL database that
//   has the real migrations applied (functions run as the `service_role` DB role).
//
// It exists so the built application can be driven in a real browser without a
// Supabase project. Nothing it reports counts as Supabase verification.
import { createServer } from "node:http";
import pg from "pg";

export async function startStandIn({ port, pgConfig, serviceKey }) {
  const db = new pg.Client(pgConfig);
  await db.connect();
  await db.query("set role service_role");
  const su = new pg.Client(pgConfig);
  await su.connect();

  const send = (res, status, body) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  const readJson = (req) =>
    new Promise((resolve) => {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => resolve(b ? JSON.parse(b) : {}));
    });
  const log = [];

  const server = createServer(async (req, res) => {
    try {
      const key = req.headers["apikey"] ?? "";
      if (key !== serviceKey) return send(res, 401, { message: "Invalid API key" });
      const url = new URL(req.url, "http://x");
      log.push(`${req.method} ${url.pathname}`);

      const rpc = /^\/rest\/v1\/rpc\/([a-z_]+)$/.exec(url.pathname);
      if (rpc && req.method === "POST") {
        const fn = rpc[1];
        const args = await readJson(req);
        const keys = Object.keys(args);
        const params = keys.map((k) =>
          typeof args[k] === "object" && args[k] !== null ? JSON.stringify(args[k]) : args[k],
        );
        const sql = `select * from public.${fn}(${keys.map((k, i) => `${k} => $${i + 1}`).join(", ")})`;
        try {
          const r = await db.query(sql, params);
          const setReturning = r.fields.length > 1 || r.fields[0]?.name !== fn;
          return send(res, 200, setReturning ? r.rows : (r.rows[0]?.[fn] ?? null));
        } catch (e) {
          await db.query("rollback").catch(() => {});
          return send(res, e.code === "42501" ? 403 : 400, {
            code: e.code,
            message: e.message,
            details: e.detail ?? null,
            hint: null,
          });
        }
      }

      if (url.pathname === "/auth/v1/admin/users" && req.method === "POST") {
        const { email } = await readJson(req);
        try {
          const r = await su.query(
            "insert into auth.users (email) values ($1) returning id, email",
            [email],
          );
          return send(res, 200, { id: r.rows[0].id, email: r.rows[0].email, aud: "authenticated" });
        } catch {
          return send(res, 422, { code: "email_exists", msg: "exists" });
        }
      }
      const del = /^\/auth\/v1\/admin\/users\/([0-9a-f-]{36})$/.exec(url.pathname);
      if (del && req.method === "DELETE") {
        await su.query("delete from auth.users where id = $1", [del[1]]);
        return send(res, 200, {});
      }
      return send(res, 404, { message: "not implemented by the stand-in" });
    } catch (e) {
      return send(res, 500, { message: String(e) });
    }
  });
  await new Promise((r) => server.listen(port, "127.0.0.1", r));
  return {
    log,
    su,
    async close() {
      await new Promise((r) => server.close(r));
      await db.end();
      await su.end();
    },
  };
}
