// Wires one ODIN° node. Used by the Vite dev server and by the standalone server
// (src/server/main.ts) alike.
//
//   leader (default)    operator registry and sessions, feed hub, authoritative command server,
//                       console APIs; plus the node API for replicas when peers are configured
//   ODIN_ROLE=replica   follows the leader named in the peers file and serves only the node API
//   ODIN_FAILOVER=on    Phase 8: every node runs the console and the node API; the cluster elects
//                       its leader. The node started without ODIN_ROLE=replica leads term 0.

import { existsSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Plugin } from "vite";
import { authRoutes, createAuth } from "./auth";
import { CommandServer, type Drafter } from "./commandServer";
import { FeedHub, feedRoutes, startCotUdp } from "./feedHub";
import { FirmamentNode } from "./failover";
import { FirmamentLeader } from "./firmament";
import { DEFAULT_NODE_KEY, loadNode, loadPeers } from "./nodeIdentity";
import { odinRoutes } from "./odinRoutes";
import { OperatorStore } from "./operatorStore";
import { Replica, REPLICA_PREFIX } from "./replica";
import { leaderReplicaRoutes, replicaNodeRoutes } from "./replicaRoutes";
import { draftWithClaude, describeFailure } from "./scalvs";

type Handler = (req: IncomingMessage, res: ServerResponse) => Promise<void> | void;

export interface Odin {
  role: "leader" | "replica" | "failover";
  routes: Array<[prefix: string, handler: Handler]>;
  close: () => void;
}

const claudeDrafter: Drafter = async (situation) => {
  try {
    return await draftWithClaude(situation);
  } catch (e) {
    throw new Error(describeFailure(e));
  }
};

const nodeKeyPath = () => process.env.ODIN_NODE_KEY ?? DEFAULT_NODE_KEY;

export async function createOdin(): Promise<Odin> {
  const peersNow = () => loadPeers(); // re-read, so add-peer takes effect without a restart
  if (process.env.ODIN_FAILOVER === "on") return createFailoverNode(peersNow);
  if (process.env.ODIN_ROLE === "replica") {
    if (!existsSync(nodeKeyPath())) throw new Error(`replica needs a node key: run npm run firmament -- init (expected ${nodeKeyPath()})`);
    const node = await loadNode();
    const replica = new Replica({ node, peers: peersNow }).start(Number(process.env.ODIN_SYNC_MS ?? 1000));
    console.log(`[odin] replica ${node.nodeId} following ${replica.leader.nodeId} at ${replica.leader.url}`);
    return { role: "replica", routes: [[REPLICA_PREFIX, replicaNodeRoutes(replica, peersNow)]], close: () => replica.close() };
  }

  const auth = createAuth();
  const hub = new FeedHub();
  const peers = peersNow();
  const node = peers.length ? await loadNode() : undefined;
  let firmament: FirmamentLeader | undefined;
  const odin = new CommandServer({
    registry: () => auth.registry(),
    drainFeeds: () => hub.drain(),
    drafter: process.env.ODIN_SCALVS === "off" ? undefined : claudeDrafter,
    replication: () => firmament?.status(),
    onSignCount: (id, keyId, n) => auth.advanceSignCount(id, keyId, n),
  }).open();
  if (node) {
    firmament = new FirmamentLeader(odin, node, peersNow);
    console.log(`[odin] leader ${node.nodeId}; replicating the Firmament to ${peers.map((p) => p.nodeId).join(", ")}`);
  }
  odin.start();
  const port = Number(process.env.ODIN_COT_UDP_PORT);
  const udp = port ? startCotUdp(hub, port, process.env.ODIN_COT_UDP_HOST ?? "127.0.0.1") : undefined;
  const routes: Odin["routes"] = [
    ["/api/auth", authRoutes(auth)],
    ["/api/feeds", feedRoutes(hub)],
    ["/api/odin", odinRoutes(odin, auth)],
  ];
  if (firmament) routes.push([REPLICA_PREFIX, leaderReplicaRoutes(odin, firmament, peersNow, () => auth.registry())]);
  return {
    role: "leader",
    routes,
    close: () => {
      udp?.close();
      odin.close();
    },
  };
}

/** Phase 8: one node of a cluster that elects its own leader. */
async function createFailoverNode(peersNow: typeof loadPeers): Promise<Odin> {
  if (!existsSync(nodeKeyPath())) throw new Error(`failover needs a node key: run npm run firmament -- init (expected ${nodeKeyPath()})`);
  const peers = peersNow();
  if (peers.length < 2) throw new Error("failover needs at least two peers (three nodes), so a majority survives one failure");
  const missing = peers.filter((p) => !p.url).map((p) => p.nodeId);
  if (missing.length) throw new Error(`failover needs a URL for every peer (missing: ${missing.join(", ")}); add them with npm run firmament -- add-peer ... --url`);
  const storePath = process.env.ODIN_OPERATOR_STORE;
  const auth = createAuth(storePath);
  const hub = new FeedHub();
  const node = await loadNode();
  const syncMs = Number(process.env.ODIN_SYNC_MS ?? 1000);
  const n = new FirmamentNode({
    node,
    peers: peersNow,
    registry: () => auth.registry(),
    bootstrapLeader: process.env.ODIN_ROLE !== "replica",
    syncMs,
    electionMs: Number(process.env.ODIN_ELECTION_MS ?? 5 * syncMs),
    server: {
      drainFeeds: () => hub.drain(),
      drafter: process.env.ODIN_SCALVS === "off" ? undefined : claudeDrafter,
      onSignCount: (id, keyId, k) => auth.advanceSignCount(id, keyId, k),
    },
    // The registry the cluster agreed on becomes this node's operator store.
    onPromote: (pinned) => {
      if (!pinned.length) return console.warn("[odin] elected leader without a pinned registry; keeping the local operator store");
      const r = new OperatorStore(storePath).adoptRegistry(pinned);
      console.log(`[odin] operator store follows the cluster registry: ${r.added} added, ${r.updated} updated, ${r.disabled} disabled`);
    },
  }).start();
  console.log(`[odin] failover node ${node.nodeId} (term ${n.term}, ${n.role}); peers ${peers.map((p) => p.nodeId).join(", ")}; election timeout ${n.electionMs} ms`);
  const port = Number(process.env.ODIN_COT_UDP_PORT);
  const udp = port ? startCotUdp(hub, port, process.env.ODIN_COT_UDP_HOST ?? "127.0.0.1") : undefined;
  return {
    role: "failover",
    routes: [
      ["/api/auth", authRoutes(auth)],
      ["/api/feeds", feedRoutes(hub)],
      ["/api/odin", odinRoutes(n.server, auth)],
      [REPLICA_PREFIX, n.routes()],
    ],
    close: () => {
      udp?.close();
      n.close();
    },
  };
}

/** Dev/preview: mount the deployment on Vite's server, and release it when Vite restarts. */
export function odinPlugin(): Plugin {
  const mount = async (server: { middlewares: { use: (p: string, h: Handler) => void }; httpServer?: { once: (ev: "close", fn: () => void) => void } | null }) => {
    // Tests build their own instances; tooling run through vite-node (e.g. the SCALVS eval)
    // sets ODIN_NO_SERVER so it never opens, or contends for, the live state directory.
    if (process.env.VITEST || process.env.ODIN_NO_SERVER) return;
    const app = await createOdin();
    for (const [prefix, handler] of app.routes) server.middlewares.use(prefix, (req, res) => void handler(req, res));
    server.httpServer?.once("close", app.close);
    process.once("SIGINT", () => (app.close(), process.exit(0)));
    process.once("SIGTERM", () => (app.close(), process.exit(0)));
  };
  return { name: "odin", configureServer: mount, configurePreviewServer: mount };
}
