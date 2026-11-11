// Standalone ODIN° server: the built console (dist/) plus every API, without Vite.
//
//   npm run build && npm start
//
//   ODIN_HOST / ODIN_PORT          listen address (default 127.0.0.1:8317)
//   ODIN_TLS_CERT / ODIN_TLS_KEY   PEM files; serve HTTPS (session cookies become Secure)
//   ODIN_TLS_CLIENT_CA             PEM CA bundle (e.g. DoD roots): ask browsers for a CAC/PIV client
//                                  certificate; operators bound to one must present it
//   ODIN_STATE_DIR                 state directory (default .odin/state)
//   ODIN_OPERATOR_STORE            operator registry (default .odin/operators.json)
//   ODIN_SCALVS=off                disable Claude drafting (rule-based options only)
//   ODIN_FEED_TOKEN, ODIN_COT_UDP_PORT, ODIN_COT_UDP_HOST  live feeds (see README)
//   ODIN_ROLE=replica              run as a Firmament replica (node API only, no console)
//   ODIN_FAILOVER=on               Phase 8 automatic failover (needs URLs for two or more peers)
//   ODIN_SYNC_MS / ODIN_ELECTION_MS  replica sync interval and minimum election timeout
//   ODIN_NODE_KEY / ODIN_PEERS     node key and peers files (default .odin/node.json, .odin/peers.json)

import { createServer as createHttp, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttps } from "node:https";
import { existsSync, readFileSync, statSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import { createOdin } from "./app";

const DIST = resolve(process.env.ODIN_DIST ?? "dist");
const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json",
  ".woff2": "font/woff2",
};

function securityHeaders(res: ServerResponse) {
  res.setHeader("content-security-policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader("x-frame-options", "DENY");
  res.setHeader("cross-origin-opener-policy", "same-origin");
}

function serveStatic(req: IncomingMessage, res: ServerResponse) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.statusCode = 405;
    return res.end();
  }
  const path = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname);
  let file = normalize(join(DIST, path));
  if (!file.startsWith(DIST + sep) && file !== DIST) {
    res.statusCode = 400;
    return res.end();
  }
  if (!existsSync(file) || statSync(file).isDirectory()) file = join(DIST, "index.html"); // single-page app
  if (!existsSync(file)) {
    res.statusCode = 503;
    return res.end("console not built: run npm run build");
  }
  res.setHeader("content-type", TYPES[extname(file)] ?? "application/octet-stream");
  res.setHeader("cache-control", file.includes(`${sep}assets${sep}`) ? "public, max-age=31536000, immutable" : "no-cache");
  res.end(req.method === "HEAD" ? undefined : readFileSync(file));
}

const app = await createOdin();

const handler = (req: IncomingMessage, res: ServerResponse) => {
  securityHeaders(res);
  const url = req.url ?? "/";
  for (const [prefix, h] of app.routes) {
    if (url === prefix || url.startsWith(prefix + "/") || url.startsWith(prefix + "?")) {
      req.url = url.slice(prefix.length) || "/";
      return void h(req, res);
    }
  }
  if (url.startsWith("/api/") || app.role === "replica") {
    res.statusCode = 404;
    return res.end();
  }
  serveStatic(req, res);
};

const cert = process.env.ODIN_TLS_CERT;
const key = process.env.ODIN_TLS_KEY;
const clientCa = process.env.ODIN_TLS_CLIENT_CA;
if (clientCa && !(cert && key)) throw new Error("ODIN_TLS_CLIENT_CA needs ODIN_TLS_CERT and ODIN_TLS_KEY");
// rejectUnauthorized is off so unbound operators can still connect without a card; bound
// operators are checked per request against the verified certificate (auth.ts).
const tls = cert && key ? { cert: readFileSync(cert), key: readFileSync(key), ...(clientCa ? { ca: readFileSync(clientCa), requestCert: true, rejectUnauthorized: false } : {}) } : undefined;
const server = tls ? createHttps(tls, handler) : createHttp(handler);
const host = process.env.ODIN_HOST ?? "127.0.0.1";
const port = Number(process.env.ODIN_PORT ?? 8317);
server.listen(port, host, () => console.log(`[odin] ${app.role} serving ${cert ? "https" : "http"}://${host}:${port}`));

const shutdown = () => {
  console.log("[odin] shutting down");
  server.close();
  app.close();
  process.exit(0);
};
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
