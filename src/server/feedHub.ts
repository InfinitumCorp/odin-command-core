// Feed hub: collects reports from every transport and hands them to the command server.
//
//   POST /api/feeds/json   {"reports": [ExternalReport, ...]} or a bare array
//   POST /api/feeds/cot    CoT XML, one or more <event> elements
//   UDP  CoT datagrams     when ODIN_COT_UDP_PORT is set (TAK-style; bound to ODIN_COT_UDP_HOST, default 127.0.0.1)
//
// The command server drains the hub every second (in-process; there is no drain endpoint).
// Ingest needs `Authorization: Bearer $ODIN_FEED_TOKEN` when that variable is set; without it
// only loopback clients may post. The hub does not interpret reports:
// the core validates every one of them (src/core/feeds.ts).

import dgram from "node:dgram";
import type { IncomingMessage, ServerResponse } from "node:http";
import { parseCot } from "./cot";

export interface Batch {
  via: string;
  receivedAt: string;
  reports: unknown[];
  /** Items an adapter could not even turn into a report (e.g. unsupported CoT types). */
  adapterRejected: Array<{ reason: string; uid?: string }>;
}

const MAX_QUEUED_BATCHES = 2000;
const MAX_BODY = 1024 * 1024;

export class FeedHub {
  private queue: Batch[] = [];
  dropped = 0;

  push(batch: Omit<Batch, "receivedAt">) {
    if (!batch.reports.length && !batch.adapterRejected.length) return;
    this.queue.push({ ...batch, receivedAt: new Date().toISOString() });
    while (this.queue.length > MAX_QUEUED_BATCHES) {
      this.queue.shift();
      this.dropped++;
    }
  }

  drain(): { batches: Batch[]; dropped: number } {
    const out = { batches: this.queue, dropped: this.dropped };
    this.queue = [];
    this.dropped = 0;
    return out;
  }

  pushJson(body: unknown, via = "http-json") {
    const reports = Array.isArray(body) ? body : (body as { reports?: unknown })?.reports;
    if (!Array.isArray(reports)) throw new Error('expected an array or {"reports": [...]}');
    this.push({ via, reports, adapterRejected: [] });
    return reports.length;
  }

  pushCot(xml: string, via: string, source: string) {
    const { reports, rejected } = parseCot(xml, source);
    this.push({ via, reports, adapterRejected: rejected });
    return { accepted: reports.length, rejected: rejected.length };
  }
}

const isLoopback = (req: IncomingMessage) => {
  const a = req.socket.remoteAddress ?? "";
  return a === "127.0.0.1" || a === "::1" || a === "::ffff:127.0.0.1";
};

export function authorized(req: IncomingMessage, token = process.env.ODIN_FEED_TOKEN): boolean {
  if (token) return req.headers.authorization === `Bearer ${token}`;
  return isLoopback(req);
}

async function readBody(req: IncomingMessage): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function send(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

export function feedRoutes(hub: FeedHub) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const path = (req.url ?? "").split("?")[0];
    try {
      if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });
      if (!authorized(req)) return send(res, 401, { error: "feed token required" });
      const feedName = String(req.headers["x-odin-feed"] ?? "").slice(0, 32) || undefined;
      if (path === "/json") {
        const n = hub.pushJson(JSON.parse(await readBody(req)), feedName ? `http-json:${feedName}` : "http-json");
        return send(res, 202, { queued: n });
      }
      if (path === "/cot") {
        const source = `cot:${feedName ?? "http"}`;
        return send(res, 202, hub.pushCot(await readBody(req), "http-cot", source));
      }
      return send(res, 404, { error: "unknown feed endpoint" });
    } catch (e) {
      return send(res, 400, { error: e instanceof Error ? e.message : "bad request" });
    }
  };
}

/** Optional TAK-style UDP listener. UDP has no authentication: bind it to a trusted interface. */
export function startCotUdp(hub: FeedHub, port: number, host: string) {
  const sock = dgram.createSocket("udp4");
  sock.on("message", (msg) => hub.pushCot(msg.toString("utf8"), "udp-cot", "cot:udp"));
  sock.on("error", (e) => console.error("[feeds] CoT UDP error:", e.message));
  sock.bind(port, host, () => console.log(`[feeds] CoT UDP listening on ${host}:${port}`));
  return sock;
}
