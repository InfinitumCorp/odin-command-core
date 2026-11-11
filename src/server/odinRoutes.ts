// Console API (all require a session):
//
//   GET  /api/odin/view            current state as a console sees it (no ground truth)
//   GET  /api/odin/stream          Server-Sent Events: a view after every change
//   GET  /api/odin/ledger?from=N   ledger entries from N (up to 1000), for in-browser verification
//   POST /api/odin/command         {...signed command}  -> {} or {error}

import type { IncomingMessage, ServerResponse } from "node:http";
import { contextOf, cookieToken, type AuthService } from "./auth";
import { SubmitError, type CommandServer } from "./commandServer";
import { readJson, send } from "./http";

const MAX_STREAMS = 200;

export function odinRoutes(odin: CommandServer, auth: AuthService) {
  let streams = 0;
  return async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://x");
    const token = cookieToken(req);
    const me = auth.me(token, contextOf(req)); // also enforces a CAC/PIV binding on this connection
    if (!me) return send(res, 401, { error: "not signed in" });
    try {
      if (req.method === "GET" && url.pathname === "/view") return send(res, 200, odin.view());
      if (req.method === "GET" && url.pathname === "/ledger") {
        const from = Math.max(0, Number(url.searchParams.get("from")) || 0);
        return send(res, 200, odin.ledger(from));
      }
      if (req.method === "GET" && url.pathname === "/stream") {
        if (streams >= MAX_STREAMS) return send(res, 503, { error: "too many consoles connected" });
        streams++;
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive", "x-accel-buffering": "no" });
        let last = "";
        const push = () => {
          // Revoked, disabled or expired operators stop receiving the picture at once.
          if (!auth.me(token)) return void res.end();
          const body = JSON.stringify(odin.view());
          if (body !== last) res.write(`data: ${body}\n\n`);
          last = body;
        };
        push();
        const off = odin.subscribe(push);
        const ping = setInterval(() => res.write(": ping\n\n"), 15_000);
        req.on("close", () => {
          off();
          clearInterval(ping);
          streams--;
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/command") {
        if (!(req.headers["content-type"] ?? "").startsWith("application/json")) return send(res, 415, { error: "application/json required" });
        let body: unknown;
        try {
          body = await readJson(req, 16 * 1024);
        } catch {
          return send(res, 400, { error: "invalid request body" });
        }
        return send(res, 200, await odin.submit(me, body));
      }
      send(res, 404, { error: "no such route" });
    } catch (e) {
      if (e instanceof SubmitError) return send(res, e.status, { error: e.message });
      console.error("[odin]", e);
      send(res, 500, { error: "internal error" });
    }
  };
}
