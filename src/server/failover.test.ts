// Phase 8: automatic failover. Three FirmamentNodes over real HTTP, with network partitions
// simulated in the transport (a partitioned node can neither send nor be reached).

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GENESIS, verify } from "../core/ledger";
import { keyIdFor, SIGN_ALG, signIntent, type RegistryOperator, type SignedAction } from "../core/identity";
import { sealPoint } from "../core/checkpoint";
import type { State } from "../core/types";
import { CommandServer, SubmitError } from "./commandServer";
import { decideVote, ElectionStore } from "./election";
import { OperatorStore } from "./operatorStore";
import { FirmamentNode } from "./failover";
import { FirmamentLeader, loadSeal } from "./firmament";
import { httpTransport, initNode, type NodeIdentity, type Peer, type Transport } from "./nodeIdentity";
import { Replica, REPLICA_PREFIX } from "./replica";
import { leaderReplicaRoutes } from "./replicaRoutes";

const noop = () => undefined;
let base: string;
let registry: RegistryOperator[];
const cleanup: Array<() => void> = [];

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), "odin-failover-"));
  registry = [];
});
afterEach(() => {
  for (const f of cleanup.splice(0).reverse()) f();
  rmSync(base, { recursive: true, force: true });
});

async function waitFor(cond: () => boolean, ms = 8000, what = "condition") {
  const until = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

async function operator(id: string, role: "commander" | "analyst") {
  const pair = (await crypto.subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const keyId = await keyIdFor(publicKeyJwk);
  registry.push({ id, name: id, role, disabled: false, keys: [{ keyId, publicKeyJwk, addedAt: "2026-01-01T00:00:00Z" }] });
  const sign = (s: State, action: SignedAction, subject: Record<string, string | number | boolean>) =>
    signIntent({ v: 1, operatorId: id, keyId, action, subject, head: s.ledger.at(-1)?.hash ?? GENESIS, signedAt: new Date().toISOString() }, pair.privateKey);
  return { who: { id, keyId }, sign };
}

type H = (req: IncomingMessage, res: ServerResponse) => Promise<void> | void;
async function serve(handler: () => H | undefined): Promise<string> {
  const srv = createServer((req, res) => {
    const url = req.url ?? "/";
    const h = handler();
    if (!h || !url.startsWith(REPLICA_PREFIX)) return void ((res.statusCode = 503), res.end());
    req.url = url.slice(REPLICA_PREFIX.length) || "/";
    void h(req, res);
  });
  srv.keepAliveTimeout = 1;
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  cleanup.push(() => srv.closeAllConnections?.() ?? srv.close());
  return `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
}

const peerOf = (n: NodeIdentity, url?: string, leader?: boolean): Peer => ({ nodeId: n.nodeId, publicKeyJwk: n.publicKeyJwk, url, leader });

/** Drops traffic to or from any node in `cut`. */
function partitioned(inner: Transport, self: string, cut: Set<string>): Transport {
  const check = (p: Peer) => {
    if (cut.has(self) || cut.has(p.nodeId)) throw new Error("network partition");
  };
  return {
    get: async (p, path) => (check(p), inner.get(p, path)),
    post: async (p, path, d) => (check(p), inner.post(p, path, d)),
  };
}

const TIMING = { syncMs: 40, electionMs: 300, stepMs: 60 };

async function cluster() {
  const ids = ["odin-a", "odin-b", "odin-c"];
  const keys = await Promise.all(ids.map((id) => initNode(join(base, `${id}.json`), id)));
  const nodes: Record<string, FirmamentNode> = {};
  const urls: Record<string, string> = {};
  for (const id of ids) urls[id] = await serve(() => nodes[id]?.routes());
  const cut = new Set<string>();
  const make = (i: number) => {
    const me = keys[i];
    const peers = keys.filter((k) => k !== me).map((k) => peerOf(k, urls[k.nodeId]));
    const n = new FirmamentNode({
      dir: join(base, me.nodeId),
      node: me,
      peers: () => peers,
      transport: partitioned(httpTransport(me, 2000), me.nodeId, cut),
      registry: () => registry,
      bootstrapLeader: i === 0,
      log: noop,
      server: { seed: 3 },
      ...TIMING,
    });
    nodes[me.nodeId] = n;
    cleanup.push(() => n.close());
    return n;
  };
  const [a, b, c] = [make(0), make(1), make(2)];
  return { a, b, c, nodes, cut, keys, make, start: () => [a, b, c].forEach((n) => n.start()) };
}

const leaderOf = (k: Awaited<ReturnType<typeof cluster>>) => Object.values(k.nodes).filter((n) => n.role === "leader");
const openDecision = (s: CommandServer) => s.state.decisions.find((d) => d.status === "open" && d.coas[0].actions.length);

describe("automatic failover", () => {
  it("elects a new leader when the leader is cut off; sealed entries survive and commands resume", async () => {
    const k = await cluster();
    const cdr = await operator("CDR-1", "commander");
    k.start();

    // Healthy: a leads with a quorum lease, b and c follow, and an approval gets sealed.
    await waitFor(() => k.a.hasLease, 5000, "a's lease");
    await waitFor(() => !!openDecision(k.a.server), 8000, "a decision");
    const dp = openDecision(k.a.server)!;
    const auth = await cdr.sign(k.a.server.state, "coa.approved", { decision: dp.id, coa: dp.coas[0].id });
    expect(await k.a.server.submit(cdr.who, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth })).toEqual({});
    const approvedAt = k.a.server.state.ledger.length;
    await waitFor(() => k.a.firmament!.status().sealed >= approvedAt, 5000, "the approval to be sealed");
    const sealed = k.a.firmament!.status().sealed;
    const sealedHead = k.a.server.state.ledger[sealed - 1].hash;

    // Cut a off. It loses its lease and refuses commands; b or c is elected in a later term.
    k.cut.add("odin-a");
    await waitFor(() => leaderOf(k).some((n) => n !== k.a), 8000, "a new leader");
    const next = leaderOf(k).find((n) => n !== k.a)!;
    expect(next.term).toBeGreaterThanOrEqual(1);
    expect(next.server.state.ledger[sealed - 1].hash).toBe(sealedHead); // nothing sealed was lost
    expect(next.server.state.ledger.some((e) => e.action === "firmament.leader-elected")).toBe(true);
    const status = (p: Promise<unknown>) => p.then(() => 200, (e) => (e instanceof SubmitError ? e.status : -1));
    expect(await status(k.a.server.submit(cdr.who, { type: "approve", decisionId: "x", coaId: "y", auth }))).toBe(409);
    await waitFor(() => k.a.role === "follower", 3000, "a to step down");

    // The new leader takes commands once its own lease is established.
    await waitFor(() => next.hasLease, 3000, "the new leader's lease");
    await waitFor(() => !!openDecision(next.server), 8000, "a decision on the new leader");
    const dp2 = openDecision(next.server)!;
    const auth2 = await cdr.sign(next.server.state, "coa.approved", { decision: dp2.id, coa: dp2.coas[0].id });
    expect(await next.server.submit(cdr.who, { type: "approve", decisionId: dp2.id, coaId: dp2.coas[0].id, auth: auth2 })).toEqual({});

    // Heal: a finds the new leader, drops the unsealed tail it wrote alone, and catches up.
    const aLast = k.a.server.lastRecord;
    k.cut.delete("odin-a");
    await waitFor(() => k.a.leaderId === next.hello().nodeId && k.a.replica.status().state === "in-sync", 8000, "a to rejoin");
    const tailDropped = k.a.replica.status().notes.some((n) => /dropped records/.test(n.message));
    expect(tailDropped || k.a.server.recordAt(aLast)?.term === next.term || k.a.server.lastRecord >= aLast).toBe(true);
    await waitFor(() => k.a.server.lastRecord >= next.server.lastRecord - 2, 3000, "a to catch up");
    const n = k.a.server.lastRecord;
    expect(k.a.server.recordAt(n)).toEqual(next.server.recordAt(n));
    expect(k.a.server.state.ledger[sealed - 1].hash).toBe(sealedHead);
    expect(verify(k.a.server.state.ledger).ok).toBe(true);
    expect(k.a.replica.halt).toBeUndefined();
  }, 30_000);

  it("a node cut off alone cannot win, does not inflate its term, and rejoins without disruption", async () => {
    const k = await cluster();
    k.start();
    await waitFor(() => k.a.hasLease && k.c.replica.status().state === "in-sync", 5000, "a healthy cluster");
    k.cut.add("odin-c");
    await new Promise((r) => setTimeout(r, 4 * TIMING.electionMs));
    expect(k.c.role).not.toBe("leader");
    expect(k.c.term).toBe(0); // pre-vote failed, so c never started a term
    expect(k.a.role).toBe("leader");
    expect(k.a.hasLease).toBe(true); // a and b are still a majority
    k.cut.delete("odin-c");
    await waitFor(() => k.c.replica.status().state === "in-sync" && k.c.leaderId === "odin-a", 5000, "c to rejoin");
    expect(k.a.term).toBe(0);
    expect(k.a.role).toBe("leader");
  }, 20_000);

  it("no majority, no leader: with two of three nodes down, the survivor neither leads nor accepts commands", async () => {
    const k = await cluster();
    k.start();
    await waitFor(() => k.a.hasLease, 5000, "a's lease");
    k.cut.add("odin-b").add("odin-c");
    await waitFor(() => k.a.role === "follower", 4000, "a to step down");
    await new Promise((r) => setTimeout(r, 3 * TIMING.electionMs));
    expect(Object.values(k.nodes).filter((n) => n.role === "leader")).toEqual([]);
    k.cut.clear();
    await waitFor(() => leaderOf(k).length === 1 && leaderOf(k)[0].hasLease, 8000, "a leader after healing");
  }, 20_000);
});

describe("elections", () => {
  it("votes are durable: one vote per term, even across a restart", () => {
    const dir = join(base, "e");
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    const me = { lastTerm: 1, lastRecord: 10, halted: false, leading: false, sticky: false };
    const s1 = new ElectionStore(dir);
    expect(decideVote(s1, { term: 2, candidate: "odin-b", lastTerm: 1, lastRecord: 10 }, me)).toMatchObject({ granted: true, term: 2 });
    const s2 = new ElectionStore(dir); // restarted
    expect(decideVote(s2, { term: 2, candidate: "odin-c", lastTerm: 1, lastRecord: 12 }, me)).toMatchObject({ granted: false, reason: /already voted/ });
    expect(decideVote(s2, { term: 2, candidate: "odin-b", lastTerm: 1, lastRecord: 10 }, me).granted).toBe(true);
    expect(decideVote(s2, { term: 1, candidate: "odin-c", lastTerm: 9, lastRecord: 99 }, me)).toMatchObject({ granted: false, reason: "stale term" });
  });

  it("votes only for a journal at least as up to date (term first), and not while a leader is alive", () => {
    const dir = join(base, "f");
    mkdirSync(dir, { recursive: true });
    const s = new ElectionStore(dir);
    const me = { lastTerm: 2, lastRecord: 10, halted: false, leading: false, sticky: false };
    expect(decideVote(s, { term: 3, candidate: "x", lastTerm: 1, lastRecord: 50 }, me)).toMatchObject({ granted: false, reason: /behind/ });
    expect(decideVote(s, { term: 4, candidate: "y", lastTerm: 2, lastRecord: 9 }, me)).toMatchObject({ granted: false, reason: /behind/ });
    expect(decideVote(s, { term: 5, candidate: "z", lastTerm: 3, lastRecord: 1 }, { ...me, sticky: true })).toMatchObject({ granted: false, reason: /leader is alive/ });
    expect(s.term).toBe(4); // a sticky node does not even adopt the term
    expect(decideVote(s, { term: 5, candidate: "z", lastTerm: 3, lastRecord: 1, prevote: true }, me).granted).toBe(true);
    expect(s.term).toBe(4); // pre-votes change nothing
    expect(decideVote(s, { term: 5, candidate: "z", lastTerm: 3, lastRecord: 1 }, { ...me, halted: true }).granted).toBe(false);
  });

  it("seals only a point whose record is from the current term (Raft's figure 8)", () => {
    const ledger = Array.from({ length: 10 }, (_, i) => ({ seq: i, hash: i.toString(16).padStart(64, "0") })) as never;
    const peer = (length: number, recordTerm: number) => ({ cp: { v: 1, purpose: "firmament-checkpoint", nodeId: "p", keyId: "k", scenario: 1, record: length, length, head: (length - 1).toString(16).padStart(64, "0"), signedAt: "", recordTerm } }) as never;
    // Leader in term 3 still holds a term-2 entry at 8 that one peer also has: a majority, but not sealable yet.
    expect(sealPoint(ledger, 1, { length: 8, record: 8, recordTerm: 2 }, [peer(8, 2)], 2, 3)).toBeUndefined();
    expect(sealPoint(ledger, 1, { length: 8, record: 8, recordTerm: 2 }, [peer(8, 2)], 2)).toMatchObject({ length: 8 }); // Phase 6 rule
    // Once a term-3 record after it is on a majority, everything up to it is sealed.
    expect(sealPoint(ledger, 1, { length: 10, record: 10, recordTerm: 3 }, [peer(9, 3)], 2, 3)).toMatchObject({ length: 9, recordTerm: 3 });
  });
});

describe("promotion", () => {
  it("a new leader adopts the cluster's registry, keeping local state and never lowering a sign counter", () => {
    const store = new OperatorStore(join(base, "operators.json"));
    const key = (keyId: string, signCount?: number) => ({ keyId, publicKeyJwk: {}, addedAt: "2026-01-01T00:00:00Z", kind: "webauthn" as const, signCount });
    store.save({
      version: 1,
      operators: [
        { id: "CDR-1", name: "old", role: "analyst", disabled: false, createdAt: "", keys: [key("k1", 40)], failures: 3, clientCert: { fingerprint256: "AA", subject: "s", boundAt: "" } },
        { id: "GONE-1", name: "gone", role: "analyst", disabled: false, createdAt: "", keys: [], failures: 0 },
      ],
    });
    const r = store.adoptRegistry([
      { id: "CDR-1", name: "Commander", role: "commander", disabled: false, keys: [key("k1", 12), key("k2")] },
      { id: "NEW-1", name: "new", role: "analyst", disabled: false, keys: [] },
    ]);
    expect(r).toEqual({ added: 1, updated: 1, disabled: 1 });
    const cdr = store.get("CDR-1")!;
    expect([cdr.role, cdr.name, cdr.failures, cdr.clientCert?.fingerprint256]).toEqual(["commander", "Commander", 3, "AA"]);
    expect(cdr.keys.map((k) => [k.keyId, k.signCount])).toEqual([["k1", 40], ["k2", undefined]]);
    expect(store.get("GONE-1")!.disabled).toBe(true);
    expect(store.get("NEW-1")).toBeDefined();
  });
});

describe("rejoining after a failover", () => {
  /** A Phase 6-style leader for term `term`, built from the first `keep` records of another. */
  async function fork(from: CommandServer, keep: number, term: number, dir: string, me: NodeIdentity, peers: Peer[]) {
    const z = new CommandServer({ dir: join(base, dir), role: "replica", registry: () => registry, log: noop }).open();
    cleanup.push(() => z.close());
    for (const r of from.records(1, keep)) z.follow(r);
    z.becomeLeader(term, me.nodeId);
    const f = new FirmamentLeader(z, me, () => peers, { log: noop, failover: () => ({ term, role: "leader", lease: true }) });
    const url = await serve(() => leaderReplicaRoutes(z, f, () => peers, () => registry));
    return { z, url };
  }

  it("drops an unsealed tail from an earlier term, but halts rather than replace a sealed record", async () => {
    const [a, b, c, z] = await Promise.all(["odin-a", "odin-b", "odin-c", "odin-z"].map((id) => initNode(join(base, `${id}.json`), id)));
    const odin = new CommandServer({ dir: join(base, "a"), registry: () => registry, seed: 3, log: noop }).open();
    cleanup.push(() => odin.close());
    odin.term = 1;
    for (let i = 0; i < 20; i++) odin.step();
    const peersA: Peer[] = [];
    const fa = new FirmamentLeader(odin, a, () => peersA, { log: noop, failover: () => ({ term: 1, role: "leader", lease: true }) });
    const urlA = await serve(() => leaderReplicaRoutes(odin, fa, () => peersA, () => registry));
    let leaderB: Peer = peerOf(a, urlA);
    let termB = 1;
    const peersB: Peer[] = [peerOf(a, urlA), peerOf(c), peerOf(z)];
    const rb = new Replica({ dir: join(base, "b"), node: b, peers: () => peersB, log: noop, leader: () => leaderB, term: () => termB, onTerm: (t) => (termB = t) });
    cleanup.push(() => rb.close());
    peersA.push(peerOf(b), peerOf(c));
    await rb.syncOnce(); // b's checkpoint reaches a...
    await rb.syncOnce(); // ...and a's seal (a + b of three) comes back to b
    const sealedRecord = loadSeal(join(base, "b"))!.record;
    expect(sealedRecord).toBeGreaterThan(1);
    for (let i = 0; i < 10; i++) odin.step(); // an unsealed tail on a, then b fetches it too
    await rb.syncOnce();
    expect(rb.server.lastRecord).toBe(odin.lastRecord);
    const sealedNow = loadSeal(join(base, "b"))!.record; // the tail is not sealed yet: a has not seen b's checkpoint of it
    expect(sealedNow).toBeLessThan(rb.server.lastRecord);

    // A new leader for term 2 that kept everything sealed but not b's tail: b drops the tail.
    const ok = await fork(odin, sealedNow, 2, "z1", z, [peerOf(b), peerOf(c)]);
    leaderB = peerOf(z, ok.url);
    peersB[2] = leaderB;
    await rb.syncOnce();
    expect(rb.halt).toBeUndefined();
    expect(termB).toBe(2);
    expect(rb.status().notes.some((n) => /dropped records/.test(n.message))).toBe(true);
    expect(rb.server.recordAt(rb.server.lastRecord)).toEqual(ok.z.recordAt(ok.z.lastRecord));
    expect(rb.server.state.ledger.at(-1)!.hash).toBe(ok.z.state.ledger.at(-1)!.hash);

    // A leader for term 3 whose journal departs before the seal: b refuses and halts.
    const bad = await fork(odin, Math.max(1, loadSeal(join(base, "b"))!.record - 3), 3, "z2", z, [peerOf(b), peerOf(c)]);
    leaderB = peerOf(z, bad.url);
    peersB[2] = leaderB;
    await rb.syncOnce();
    expect(rb.halt?.kind).toBe("sealed-rewrite");
    expect(existsSync(join(base, "b", "ALARM.json"))).toBe(true);
  });
});
