// Firmament node administration.
//
//   npm run firmament -- init [--id odin-a]                 create this node's key (.odin/node.json)
//   npm run firmament -- show [--json]                      this node's id and public key (safe to share)
//   npm run firmament -- add-peer <peer.json> [--url U] [--leader]
//                                                      trust another node (file from its `show --json`)
//   npm run firmament -- peers                              list configured peers
//   npm run firmament -- remove-peer <node-id>
//   npm run firmament -- status <node-id>                   ask a peer (leader or replica) for its status
//   npm run firmament -- election                           this node's term, vote and known seal (Phase 8)
//   npm run firmament -- promote                            replica -> leader: write an operator store
//                                                      from the replica's pinned registry
//
// Paths follow the server: ODIN_NODE_KEY, ODIN_PEERS, ODIN_STATE_DIR, ODIN_OPERATOR_STORE.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { RegistryOperator } from "../src/core/identity";
import { DEFAULT_STATE_DIR } from "../src/server/commandServer";
import { httpTransport, initNode, loadNode, loadPeers, savePeers, validNodeId, type Peer } from "../src/server/nodeIdentity";
import { OperatorStore } from "../src/server/operatorStore";
import { REPLICA_PREFIX } from "../src/server/replica";
import { isPublicP256Jwk } from "../src/core/identity";

const [cmd, ...rest] = process.argv.slice(2);
const opt = (name: string) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : undefined;
};
const flag = (name: string) => rest.includes(`--${name}`);
const fail = (msg: string): never => {
  console.error(msg);
  process.exit(1);
};

async function main() {
  switch (cmd) {
    case "init": {
      const n = await initNode(undefined, opt("id"));
      console.log(`created node ${n.nodeId} (key ${n.keyId})`);
      console.log(`share its public key with the other nodes:  npm run firmament -- show --json > ${n.nodeId}.pub.json`);
      return;
    }
    case "show": {
      const n = await loadNode();
      if (flag("json")) console.log(JSON.stringify({ nodeId: n.nodeId, publicKeyJwk: n.publicKeyJwk }));
      else console.log(`${n.nodeId}  key ${n.keyId}`);
      return;
    }
    case "add-peer": {
      const file = rest[0];
      if (!file || file.startsWith("--")) fail("usage: add-peer <peer.json> [--url https://host:port] [--leader]");
      const p = JSON.parse(readFileSync(file, "utf8")) as Peer;
      if (!validNodeId(p.nodeId) || !isPublicP256Jwk(p.publicKeyJwk)) fail(`${file} is not a node public key (from \`show --json\`)`);
      const url = opt("url");
      if (url) new URL(url);
      const peers = loadPeers().filter((x) => x.nodeId !== p.nodeId);
      if (flag("leader")) for (const x of peers) delete x.leader;
      peers.push({ nodeId: p.nodeId, publicKeyJwk: { kty: "EC", crv: "P-256", x: p.publicKeyJwk.x, y: p.publicKeyJwk.y }, url, leader: flag("leader") || undefined });
      savePeers(peers);
      console.log(`peer ${p.nodeId} trusted${url ? ` at ${url}` : ""}${flag("leader") ? " (leader)" : ""}; ${peers.length} peer(s)`);
      return;
    }
    case "peers": {
      const peers = loadPeers();
      if (!peers.length) console.log("no peers: this node runs alone and nothing is replicated");
      for (const p of peers) console.log(`${p.nodeId.padEnd(20)} ${p.leader ? "leader " : "       "} ${p.url ?? "(no url)"}`);
      return;
    }
    case "remove-peer": {
      const peers = loadPeers();
      const left = peers.filter((p) => p.nodeId !== rest[0]);
      if (left.length === peers.length) fail(`no peer ${rest[0]}`);
      savePeers(left);
      console.log(`removed ${rest[0]}`);
      return;
    }
    case "status": {
      const peer = loadPeers().find((p) => p.nodeId === rest[0]) ?? fail(`no peer ${rest[0]}`);
      const t = httpTransport(await loadNode());
      // Phase 8 nodes say who they are, which term they are in, and whom they follow.
      const hello = await t.get(peer, `${REPLICA_PREFIX}/hello`).catch(() => undefined);
      if (hello?.status === 200) console.log(JSON.stringify({ hello: hello.body }, null, 2));
      const r = peer.leader ? await t.get(peer, `${REPLICA_PREFIX}/checkpoints`) : await t.get(peer, `${REPLICA_PREFIX}/status`);
      console.log(JSON.stringify(r.body, null, 2));
      return;
    }
    case "election": {
      // This node's durable election state (Phase 8), read from its state directory.
      const dir = process.env.ODIN_STATE_DIR ?? DEFAULT_STATE_DIR;
      const read = (f: string) => (existsSync(join(dir, f)) ? JSON.parse(readFileSync(join(dir, f), "utf8")) : undefined);
      const e = read("election.json") ?? { term: 0 };
      const seal = read("seal.json");
      console.log(`term ${e.term}${e.votedFor ? `, voted for ${e.votedFor}` : ", no vote cast in this term"}`);
      console.log(seal ? `sealed through record ${seal.record} (ledger length ${seal.length}) of scenario ${seal.scenario}` : "no seal recorded yet");
      if (existsSync(join(dir, "ALARM.json"))) console.log(`HALTED: see ${join(dir, "ALARM.json")}`);
      return;
    }
    case "promote": {
      const dir = process.env.ODIN_STATE_DIR ?? DEFAULT_STATE_DIR;
      const pinned = join(dir, "registry.json");
      if (!existsSync(pinned)) fail(`${pinned} not found: promote runs on a replica's machine, against its state directory`);
      if (existsSync(join(dir, "ALARM.json"))) fail(`this replica is halted (${join(dir, "ALARM.json")}); a halted replica must not become leader`);
      const store = new OperatorStore(process.env.ODIN_OPERATOR_STORE);
      if (existsSync(store.path)) fail(`${store.path} already exists; refusing to overwrite an operator store`);
      const ops = (JSON.parse(readFileSync(pinned, "utf8")) as { operators: RegistryOperator[] }).operators;
      const now = new Date().toISOString();
      store.save({ version: 1, operators: ops.map((o) => ({ id: o.id, name: o.name, role: o.role, disabled: o.disabled, createdAt: now, keys: o.keys, failures: 0 })) });
      console.log(`wrote ${store.path} with ${ops.length} operator(s); enrolled keys sign in as before (pending enrollment codes do not carry over).`);
      console.log(`next: stop this replica, point the other replicas' peers files at this node with --leader, and start it without ODIN_ROLE.`);
      return;
    }
    default:
      fail("usage: npm run firmament -- init | show | add-peer | peers | remove-peer | status | election | promote");
  }
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
