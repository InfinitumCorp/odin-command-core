import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { append, GENESIS, verify } from "../core/ledger";
import { keyIdFor, SIGN_ALG, signIntent, type RegistryOperator, type SignedAction } from "../core/identity";
import type { LedgerEntry, Operator, State } from "../core/types";
import { CommandServer } from "./commandServer";
import { FirmamentLeader } from "./firmament";
import { httpTransport, initNode, nodeCheckpoint, signRequest, verifyRequest, type NodeIdentity, type Peer } from "./nodeIdentity";
import { Replica, REPLICA_PREFIX } from "./replica";
import { leaderReplicaRoutes, replicaNodeRoutes } from "./replicaRoutes";

const subtle = globalThis.crypto.subtle;
const noop = () => undefined;
let base: string;
let registry: RegistryOperator[];
const cleanup: Array<() => void> = [];

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), "odin-firmament-"));
  registry = [];
});
afterEach(() => {
  for (const f of cleanup.splice(0).reverse()) f();
  rmSync(base, { recursive: true, force: true });
});

async function operator(id: string, role: "commander" | "analyst") {
  const pair = (await subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const keyId = await keyIdFor(publicKeyJwk);
  registry.push({ id, name: id, role, disabled: false, keys: [{ keyId, publicKeyJwk, addedAt: "2026-01-01T00:00:00Z" }] });
  const sign = (s: State, action: SignedAction, subject: Record<string, string | number | boolean>, key = pair.privateKey) =>
    signIntent({ v: 1, operatorId: id, keyId, action, subject, head: s.ledger.at(-1)?.hash ?? GENESIS, signedAt: new Date().toISOString() }, key);
  return { who: { id, keyId }, operator: { id, role, keyId } as Operator, sign, pair };
}

function untilDecision(s: CommandServer) {
  for (let i = 0; i < 200 && !s.state.decisions.some((d) => d.status === "open" && d.coas[0].actions.length); i++) s.step();
  return s.state.decisions.find((d) => d.status === "open" && d.coas[0].actions.length)!;
}

type H = (req: IncomingMessage, res: ServerResponse) => Promise<void> | void;
async function serve(handler: H): Promise<string> {
  const srv = createServer((req, res) => {
    const url = req.url ?? "/";
    if (!url.startsWith(REPLICA_PREFIX)) return void ((res.statusCode = 404), res.end());
    req.url = url.slice(REPLICA_PREFIX.length) || "/";
    void handler(req, res);
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  cleanup.push(() => srv.close());
  const addr = srv.address() as { port: number };
  return `http://127.0.0.1:${addr.port}`;
}

const peerOf = (n: NodeIdentity, url?: string, leader?: boolean): Peer => ({ nodeId: n.nodeId, publicKeyJwk: n.publicKeyJwk, url, leader });

/** A leader (odin-a) and two replicas (odin-b, odin-c), each with its own state directory, over real HTTP. */
async function cluster() {
  const [a, b, c] = await Promise.all(["odin-a", "odin-b", "odin-c"].map((id) => initNode(join(base, `${id}.json`), id)));
  const odin = new CommandServer({ dir: join(base, "a"), registry: () => registry, seed: 3, log: noop }).open();
  cleanup.push(() => odin.close());
  const peersA: Peer[] = [];
  const peersB: Peer[] = [];
  const peersC: Peer[] = [];
  const firmament = new FirmamentLeader(odin, a, () => peersA, { log: noop });
  const urlA = await serve(leaderReplicaRoutes(odin, firmament, () => peersA, () => registry));
  const replica = (n: NodeIdentity, peers: Peer[], dir: string) => {
    const r = new Replica({ dir: join(base, dir), node: n, peers: () => peers, log: noop });
    cleanup.push(() => r.close());
    return r;
  };
  const rb = replica(b, peersB, "b");
  const rc = replica(c, peersC, "c");
  const urlB = await serve(replicaNodeRoutes(rb, () => peersB));
  const urlC = await serve(replicaNodeRoutes(rc, () => peersC));
  peersA.push(peerOf(b, urlB), peerOf(c, urlC));
  peersB.push(peerOf(a, urlA, true), peerOf(c, urlC));
  peersC.push(peerOf(a, urlA, true), peerOf(b, urlB));
  return { a, b, c, odin, firmament, rb, rc, urlA, peersA, peersB, peersC, replica };
}

const head = (s: CommandServer) => s.state.ledger.at(-1)!.hash;

describe("replicated Firmament: normal operation", () => {
  it("replicas re-execute the leader's journal to the same state, and a majority seals the ledger", async () => {
    const k = await cluster();
    const cdr = await operator("CDR-1", "commander");
    const dp = untilDecision(k.odin);
    const auth = await cdr.sign(k.odin.state, "coa.approved", { decision: dp.id, coa: dp.coas[0].id });
    expect(await k.odin.submit(cdr.who, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth })).toEqual({});

    let st = k.firmament.status();
    expect(st).toMatchObject({ nodes: 3, quorum: 2, sealed: 0, replicable: true });
    expect(st.peers.map((p) => p.state)).toEqual(["never", "never"]);

    await k.rb.syncOnce();
    expect(k.rb.status()).toMatchObject({ state: "in-sync", head: head(k.odin), length: k.odin.state.ledger.length });
    // Not just the ledger: the hidden ground truth and the PRNG state are reproduced too.
    expect(k.rb.server.state).toEqual(k.odin.state);
    st = k.firmament.status();
    expect(st.sealed).toBe(k.odin.state.ledger.length);
    expect(st.peers.map((p) => p.state)).toEqual(["agrees", "never"]);

    const sealedBefore = st.sealed;
    for (let i = 0; i < 5; i++) k.odin.step();
    expect(k.firmament.status().sealed).toBe(sealedBefore); // new entries wait for a second signature
    await k.rc.syncOnce();
    expect(k.firmament.status().sealed).toBe(k.odin.state.ledger.length);
    await k.rb.syncOnce();
    expect(k.firmament.status().peers.map((p) => p.state)).toEqual(["agrees", "agrees"]);
    expect(k.firmament.status().alarms).toEqual([]);
  });

  it("follows scenario changes, resumes after a restart, and can be promoted to leader", async () => {
    const k = await cluster();
    const cdr = await operator("CDR-1", "commander");
    for (let i = 0; i < 20; i++) k.odin.step();
    await k.rb.syncOnce();
    expect(await k.odin.submit(cdr.who, { type: "close-scenario", seed: 9, auth: await cdr.sign(k.odin.state, "scenario.closed", { seed: 9 }) })).toEqual({});
    for (let i = 0; i < 10; i++) k.odin.step();

    // An empty replica joining late replays the closed scenario from its archived journal, then the new one.
    await k.rc.syncOnce();
    expect(k.rc.status()).toMatchObject({ state: "in-sync", scenario: 2, head: head(k.odin) });
    await k.rb.syncOnce();
    expect(k.rb.status()).toMatchObject({ state: "in-sync", scenario: 2, head: head(k.odin) });
    expect(readdirSync(join(base, "b", "archive")).some((f) => f.endsWith(".journal.jsonl"))).toBe(true);

    k.rb.close();
    const again = k.replica(k.b, k.peersB, "b");
    expect(again.server.lastRecord).toBe(k.odin.lastRecord);
    k.odin.step();
    await again.syncOnce();
    expect(again.status()).toMatchObject({ state: "in-sync", head: head(k.odin) });

    // Promotion: the leader is gone; start a leader on the replica's own state directory.
    again.close();
    const promoted = new CommandServer({ dir: join(base, "b"), registry: () => registry, log: noop }).open();
    cleanup.push(() => promoted.close());
    expect(promoted.state).toEqual(k.odin.state);
    expect(promoted.replicable).toBe(true);
    promoted.step();
    expect(verify(promoted.state.ledger).ok).toBe(true);
  });

  it("a scenario whose journal start is gone is not replicable until the next one", async () => {
    const k = await cluster();
    for (let i = 0; i < 5; i++) k.odin.step();
    k.odin.close();
    writeFileSync(join(base, "a", "journal.jsonl"), ""); // as left by a Phase 4 server, which truncated it
    const legacy = new CommandServer({ dir: join(base, "a"), registry: () => registry, log: noop }).open();
    cleanup.push(() => legacy.close());
    expect(legacy.replicable).toBe(false);
    const f = new FirmamentLeader(legacy, k.a, () => k.peersA, { log: noop });
    const url = await serve(leaderReplicaRoutes(legacy, f, () => k.peersA, () => registry));
    k.peersB[0] = peerOf(k.a, url, true);
    await k.rb.syncOnce();
    expect(k.rb.status().state).toBe("waiting");
    expect(k.rb.status().lastError).toMatch(/predates replication/);
  });
});

describe("replicated Firmament: what one node cannot do unnoticed", () => {
  it("a leader that rewrites its ledger consistently passes its own check but halts every replica", async () => {
    const k = await cluster();
    for (let i = 0; i < 30; i++) k.odin.step();
    await k.rb.syncOnce();
    expect(k.rb.status().state).toBe("in-sync");

    // Edit entry #3 and re-chain every hash after it: a perfectly valid-looking ledger.
    let rewritten: LedgerEntry[] = [];
    for (const e of k.odin.state.ledger) rewritten = append(rewritten, e.t, e.actor, e.action, e.seq === 3 ? { ...e.payload, note: "rewritten" } : e.payload);
    k.odin.state = { ...k.odin.state, ledger: rewritten };
    k.odin.step();
    expect(verify(k.odin.state.ledger).ok).toBe(true);

    await k.rb.syncOnce();
    // b holds the leader's earlier signed head for the same length, so it may catch this as
    // equivocation (two signed heads, one length) before it compares the new head with its own.
    expect(k.rb.status().state).toBe("halted");
    expect(k.rb.status().halt!.kind).toMatch(/^(divergence|equivocation)$/);
    expect(existsSync(join(base, "b", "ALARM.json"))).toBe(true);
    // A replica joining after the rewrite re-executes the journal and catches it too.
    await k.rc.syncOnce();
    expect(k.rc.status().halt?.kind).toBe("divergence");

    // Halted replicas report to the leader on every sync; consoles see it.
    await k.rb.syncOnce();
    const st = k.firmament.status();
    expect(st.peers.find((p) => p.nodeId === "odin-b")!.state).toBe("alarm");
    expect(st.alarms.some((a) => a.kind === `replica-halted:${k.rb.halt!.kind}` && a.node === "odin-b")).toBe(true);

    // The halt survives a restart; clearing it is a deliberate act.
    k.rb.close();
    const restarted = k.replica(k.b, k.peersB, "b");
    expect(restarted.status().state).toBe("halted");
  });

  it("halts on a human action in the journal whose signature does not verify", async () => {
    const k = await cluster();
    const cdr = await operator("CDR-1", "commander");
    const thief = (await subtle.generateKey(SIGN_ALG, false, ["sign"])) as CryptoKeyPair;
    const dp = untilDecision(k.odin);
    await k.rb.syncOnce();
    const forged = await cdr.sign(k.odin.state, "coa.approved", { decision: dp.id, coa: dp.coas[0].id }, thief.privateKey);
    // Written straight into the journal, bypassing submit()'s checks, as a compromised leader could.
    (k.odin as unknown as { record: (c: unknown, o: Operator) => string | undefined }).record({ type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth: forged }, cdr.operator);
    expect(k.odin.state.decisions.find((d) => d.id === dp.id)!.status).toBe("approved");

    await k.rb.syncOnce();
    expect(k.rb.status()).toMatchObject({ state: "halted", halt: { kind: "bad-signature" } });
    expect(k.rb.status().halt!.message).toMatch(/signature does not verify/);
  });

  it("pins operator keys: a key id served with a different public key halts the replica", async () => {
    const k = await cluster();
    await operator("CDR-1", "commander");
    await k.rb.syncOnce();
    const other = (await subtle.generateKey(SIGN_ALG, true, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = await subtle.exportKey("jwk", other.publicKey);
    registry[0].keys[0].publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    await k.rb.syncOnce();
    expect(k.rb.status()).toMatchObject({ state: "halted", halt: { kind: "registry-key-changed" } });

    // A new operator, by contrast, is accepted and noted.
    await operator("ANL-2", "analyst");
    await k.rc.syncOnce();
    await operator("ANL-3", "analyst");
    await k.rc.syncOnce();
    expect(k.rc.status().state).toBe("in-sync");
    expect(k.rc.status().notes.some((n) => /new operator ANL-3/.test(n.message))).toBe(true);
  });

  it("the leader flags a replica that disagrees, runs ahead, or equivocates", async () => {
    const k = await cluster();
    for (let i = 0; i < 10; i++) k.odin.step();
    const tc = httpTransport(k.c);
    const leader = peerOf(k.a, k.urlA, true);
    const L = k.odin.state.ledger;
    const cp = (length: number, h: string) => nodeCheckpoint(k.c, { scenario: k.odin.scenario, record: k.odin.lastRecord, length, head: h });

    expect((await tc.post(leader, `${REPLICA_PREFIX}/checkpoint`, await cp(3, "f".repeat(64)))).status).toBe(200);
    let st = k.firmament.status();
    expect(st.peers.find((p) => p.nodeId === "odin-c")!.state).toBe("disagrees");
    expect(st.alarms.map((a) => a.kind)).toContain("divergence");

    await tc.post(leader, `${REPLICA_PREFIX}/checkpoint`, await cp(3, L[2].hash));
    expect(k.firmament.status().alarms.map((a) => a.kind)).toContain("equivocation");

    await tc.post(leader, `${REPLICA_PREFIX}/checkpoint`, await cp(L.length + 5, "e".repeat(64)));
    st = k.firmament.status();
    expect(st.alarms.map((a) => a.kind)).toContain("replica-ahead");
    expect(st.sealed).toBe(0); // nothing c said counts towards the seal

    // c cannot speak for b: the checkpoint must be from the node that signed the request.
    const asB = await nodeCheckpoint(k.b, { scenario: k.odin.scenario, record: 1, length: 2, head: L[1].hash });
    expect((await tc.post(leader, `${REPLICA_PREFIX}/checkpoint`, asB)).status).toBe(403);
    // Nor forge one in b's name with its own key.
    const forged = { ...asB, cp: { ...asB.cp, nodeId: "odin-c" } };
    expect((await tc.post(leader, `${REPLICA_PREFIX}/checkpoint`, forged)).status).toBe(403);
  });

  it("the node API accepts only configured peers with fresh, valid request signatures", async () => {
    const k = await cluster();
    expect((await fetch(`${k.urlA}${REPLICA_PREFIX}/registry`)).status).toBe(401);
    const stranger = await initNode(join(base, "x.json"), "odin-x");
    expect((await httpTransport(stranger).get(peerOf(k.a, k.urlA), `${REPLICA_PREFIX}/registry`)).status).toBe(401);
    expect((await httpTransport(k.b).get(peerOf(k.a, k.urlA), `${REPLICA_PREFIX}/registry`)).status).toBe(200);

    const path = `${REPLICA_PREFIX}/records?from=1`;
    const h = await signRequest(k.b, "GET", path);
    expect((await verifyRequest(k.peersA, h, "GET", path))?.nodeId).toBe("odin-b");
    expect(await verifyRequest(k.peersA, h, "GET", `${REPLICA_PREFIX}/records?from=2`)).toBeUndefined();
    expect(await verifyRequest(k.peersA, h, "POST", path)).toBeUndefined();
    expect(await verifyRequest(k.peersA, h, "GET", path, "", Date.now() + 120_000)).toBeUndefined();
    const hb = await signRequest(k.b, "POST", `${REPLICA_PREFIX}/checkpoint`, '{"a":1}');
    expect(await verifyRequest(k.peersA, hb, "POST", `${REPLICA_PREFIX}/checkpoint`, '{"a":2}')).toBeUndefined();
    // A replica refuses console commands outright.
    await expect(k.rb.server.submit({ id: "CDR-1", keyId: "k" }, { type: "approve" })).rejects.toThrow(/replica/);
  });
});
