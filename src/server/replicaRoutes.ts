// Node-to-node API, mounted at /api/replica. Every request must be signed by a node listed in
// this node's peers file (see nodeIdentity.ts); operators' sessions are not accepted here.
//
// On the leader:
//   GET  /records?from=N&limit=M  journal records from N, plus the leader's signed checkpoint
//   GET  /registry                operator ids, roles and public keys (no enrollment data)
//   GET  /checkpoints             the leader's checkpoint and the latest from each replica
//   POST /checkpoint              a replica's signed checkpoint -> everyone's latest
//   POST /alarm                   a replica reports that it halted, and why
// On a replica:
//   GET  /checkpoints             this replica's checkpoint and those it has seen (gossip)
//   GET  /status                  this replica's sync state, halt and notes

import type { IncomingMessage, ServerResponse } from "node:http";
import type { RegistryOperator } from "../core/identity";
import type { CommandServer } from "./commandServer";
import type { FirmamentLeader } from "./firmament";
import { send } from "./http";
import { verifyRequest, type Peer } from "./nodeIdentity";
import { REPLICA_PREFIX, type Replica } from "./replica";

const MAX_BODY = 64 * 1024;

export type Reply = { status: number; body: unknown };
export type Get = (peer: Peer, url: URL) => Promise<Reply> | Reply;
export type Post = (peer: Peer, body: unknown) => Promise<Reply> | Reply;

function readText(req: IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export function nodeRoutes(peers: () => Peer[], get: Record<string, Get>, post: Record<string, Post>) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const rel = req.url ?? "/";
    const url = new URL(rel, "http://x");
    try {
      const body = req.method === "POST" ? await readText(req, MAX_BODY) : "";
      // The client signs the full path it requested; mounting strips the prefix from req.url.
      const peer = await verifyRequest(peers(), req.headers, req.method ?? "GET", REPLICA_PREFIX + rel, body);
      if (!peer) return send(res, 401, { error: "unknown node or bad request signature" });
      const handler = req.method === "GET" ? get[url.pathname] : req.method === "POST" ? post[url.pathname] : undefined;
      if (!handler) return send(res, 404, { error: "no such route" });
      let parsed: unknown;
      if (req.method === "POST") {
        try {
          parsed = JSON.parse(body);
        } catch {
          return send(res, 400, { error: "invalid JSON" });
        }
      }
      const r = req.method === "GET" ? await (handler as Get)(peer, url) : await (handler as Post)(peer, parsed);
      send(res, r.status, r.body);
    } catch (e) {
      if (!res.headersSent) send(res, 400, { error: e instanceof Error ? e.message : "bad request" });
    }
  };
}

/** The leader's node API handlers (also used by a failover node while it leads). */
export function leaderHandlers(odin: CommandServer, firmament: FirmamentLeader, registry: () => RegistryOperator[]): { get: Record<string, Get>; post: Record<string, Post> } {
  return {
    get: {
      "/records": async (p, url) => {
        firmament.touch(p.nodeId);
        const from = Math.max(1, Number(url.searchParams.get("from")) || 1);
        const limit = Math.min(2000, Math.max(1, Number(url.searchParams.get("limit")) || 500));
        const checkpoint = await firmament.ownCheckpoint();
        const records = odin.records(from, limit);
        if (!records.length && !odin.replicable && from <= odin.lastRecord)
          return { status: 409, body: { error: `scenario ${odin.scenario} predates replication; replicas can join from the next scenario` } };
        return { status: 200, body: { scenario: odin.scenario, records, checkpoint, term: odin.term, sealed: firmament.seal() } };
      },
      "/registry": () => ({ status: 200, body: registry() }),
      "/checkpoints": async () => ({ status: 200, body: { checkpoints: await firmament.checkpoints() } }),
    },
    post: {
      "/checkpoint": (p, b) => firmament.accept(p, b),
      "/alarm": (p, b) => firmament.report(p, b),
    },
  };
}

export function leaderReplicaRoutes(odin: CommandServer, firmament: FirmamentLeader, peers: () => Peer[], registry: () => RegistryOperator[]) {
  const h = leaderHandlers(odin, firmament, registry);
  return nodeRoutes(peers, h.get, h.post);
}

export function replicaNodeRoutes(replica: Replica, peers: () => Peer[]) {
  return nodeRoutes(
    peers,
    {
      "/checkpoints": async () => ({ status: 200, body: { checkpoints: await replica.checkpoints() } }),
      "/status": () => ({ status: 200, body: replica.status() }),
    },
    {},
  );
}
