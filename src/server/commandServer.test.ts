import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GENESIS, verify } from "../core/ledger";
import { auditSignatures, keyIdFor, SIGN_ALG, signIntent, type RegistryOperator, type SignedAction } from "../core/identity";
import type { State } from "../core/types";
import { intentBytes, type Intent } from "../core/identity";
import { CommandServer, SubmitError, type CommandServerOptions } from "./commandServer";
import { TestAuthenticator } from "./testAuthenticator";

const subtle = globalThis.crypto.subtle;
let dir: string;
let registry: RegistryOperator[];
const servers: CommandServer[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "odin-state-"));
  registry = [];
});
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
  rmSync(dir, { recursive: true, force: true });
});

function server(opts: Partial<CommandServerOptions> = {}) {
  const s = new CommandServer({ dir, registry: () => registry, seed: 3, log: () => undefined, ...opts }).open();
  servers.push(s);
  return s;
}

async function operator(id: string, role: "commander" | "analyst") {
  const pair = (await subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const keyId = await keyIdFor(publicKeyJwk);
  const reg: RegistryOperator = { id, name: id, role, disabled: false, keys: [{ keyId, publicKeyJwk, addedAt: "2026-01-01T00:00:00Z" }] };
  registry.push(reg);
  const sign = (s: State, action: SignedAction, subject: Record<string, string | number | boolean>, key = pair.privateKey) =>
    signIntent({ v: 1, operatorId: id, keyId, action, subject, head: s.ledger.at(-1)?.hash ?? GENESIS, signedAt: new Date().toISOString() }, key);
  return { reg, who: { id, keyId }, sign, pair };
}

function untilDecision(s: CommandServer) {
  for (let i = 0; i < 200 && !s.state.decisions.some((d) => d.status === "open" && d.coas[0].actions.length); i++) s.step();
  return s.state.decisions.find((d) => d.status === "open" && d.coas[0].actions.length)!;
}

const code = (p: Promise<unknown>) => p.then(() => 200, (e) => (e instanceof SubmitError ? e.status : -1));

describe("command server: enforcement", () => {
  it("only accepts signed console commands from the session's own key", async () => {
    const cdr = await operator("CDR-1", "commander");
    const other = await operator("CDR-2", "commander");
    const s = server();
    const dp = untilDecision(s);
    const approve = (auth?: unknown) => ({ type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth });
    const good = await cdr.sign(s.state, "coa.approved", { decision: dp.id, coa: dp.coas[0].id });

    expect(await code(s.submit(cdr.who, { type: "tick", minutes: 500 }))).toBe(400); // machine commands are server-only
    expect(await code(s.submit(cdr.who, { type: "apply-drafts", decisionId: dp.id, proposals: [], model: "x" }))).toBe(400);
    expect(await code(s.submit(cdr.who, approve()))).toBe(400);
    expect(await code(s.submit(other.who, approve(good)))).toBe(403); // CDR-2's session, CDR-1's signature
    expect(await code(s.submit(cdr.who, approve({ ...good, sig: good.sig.slice(0, -4) + "AAAA" })))).toBe(403);
    const forged = await cdr.sign(s.state, "coa.approved", { decision: dp.id, coa: dp.coas[0].id }, other.pair.privateKey);
    expect(await code(s.submit(cdr.who, approve(forged)))).toBe(403);
    expect(s.state.decisions.find((d) => d.id === dp.id)!.status).toBe("open");

    expect(await s.submit(cdr.who, approve(good))).toEqual({});
    expect(s.state.decisions.find((d) => d.id === dp.id)!.status).toBe("approved");
    expect((await auditSignatures(s.state.ledger, registry)).problems).toEqual([]);
  });

  it("accepts security-key approvals, counts them as hardware, and refuses a cloned key", async () => {
    const key = new TestAuthenticator();
    const publicKeyJwk = key.publicKeyJwk;
    const keyId = await keyIdFor(publicKeyJwk);
    registry.push({ id: "CDR-1", name: "CDR-1", role: "commander", disabled: false, keys: [{ keyId, publicKeyJwk, addedAt: "2026-01-01T00:00:00Z", kind: "webauthn", rpId: "localhost", uv: true }] });
    const counts: number[] = [];
    let last = 0;
    const s = server({
      onSignCount: (_id, _k, n) => {
        if (n <= last) throw new Error("security key counter went backwards");
        counts.push((last = n));
      },
    });
    const dp = untilDecision(s);
    const sign = async (k: TestAuthenticator) => {
      const intent: Intent = { v: 1, operatorId: "CDR-1", keyId, action: "coa.approved", subject: { decision: dp.id, coa: dp.coas[0].id }, head: s.state.ledger.at(-1)!.hash, signedAt: new Date().toISOString() };
      return { intent, ...(await k.sign(intentBytes(intent), "localhost", "http://localhost:5317")) };
    };
    const approve = (auth: unknown) => ({ type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth });
    const who = { id: "CDR-1", keyId };

    const copy = key.clone();
    const good = await sign(key);
    const { webauthn: _w, ...bare } = good;
    expect(await code(s.submit(who, approve(bare)))).toBe(403); // no authenticator evidence
    expect(await s.submit(who, approve(good))).toEqual({});
    expect(counts).toEqual([1]);
    const audit = await auditSignatures(s.state.ledger, registry);
    expect(audit).toMatchObject({ problems: [], hardware: 1 });

    const dp2 = untilDecision(s);
    const intent2: Intent = { v: 1, operatorId: "CDR-1", keyId, action: "coa.approved", subject: { decision: dp2.id, coa: dp2.coas[0].id }, head: s.state.ledger.at(-1)!.hash, signedAt: new Date().toISOString() };
    const cloned = { intent: intent2, ...(await copy.sign(intentBytes(intent2), "localhost", "http://localhost:5317")) };
    expect(await code(s.submit(who, { type: "approve", decisionId: dp2.id, coaId: dp2.coas[0].id, auth: cloned }))).toBe(403);
  });

  it("takes the role from the registry, not from the command", async () => {
    const anl = await operator("ANL-4", "analyst");
    const s = server();
    const auth = await anl.sign(s.state, "operator.signed-in", {});
    await s.submit(anl.who, { type: "set-operator", operator: { id: "ANL-4", role: "commander", keyId: anl.who.keyId }, auth });
    const entry = s.state.ledger.at(-1)!;
    expect(entry.action).toBe("operator.signed-in");
    expect(entry.payload.role).toBe("analyst");

    const dp = untilDecision(s);
    const r = await s.submit(anl.who, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth: await anl.sign(s.state, "coa.approved", { decision: dp.id, coa: dp.coas[0].id }) });
    expect(r.error).toMatch(/Only a commander/);
    expect(s.state.ledger.at(-1)!.action).toBe("approval.denied");
  });

  it("refuses revoked keys and disabled operators immediately", async () => {
    const cdr = await operator("CDR-1", "commander");
    const s = server();
    const clock = async () => s.submit(cdr.who, { type: "set-clock", running: false, speed: 5, auth: await cdr.sign(s.state, "clock.set", { running: false, speed: 5 }) });
    cdr.reg.keys[0].revokedAt = new Date().toISOString();
    expect(await code(clock())).toBe(403);
    cdr.reg.keys[0].revokedAt = undefined;
    cdr.reg.disabled = true;
    expect(await code(clock())).toBe(403);
    cdr.reg.disabled = false;
    expect(await clock()).toEqual({});
    expect(s.state.clock.running).toBe(false);
  });

  it("stops the clock for everyone when a commander pauses it", async () => {
    const cdr = await operator("CDR-1", "commander");
    const s = server();
    s.step();
    await s.submit(cdr.who, { type: "set-clock", running: false, speed: 20, auth: await cdr.sign(s.state, "clock.set", { running: false, speed: 20 }) });
    const t = s.state.t;
    s.step();
    s.step();
    expect(s.state.t).toBe(t);
  });
});

describe("command server: persistence", () => {
  async function busyServer(opts: Partial<CommandServerOptions> = {}) {
    const cdr = await operator("CDR-1", "commander");
    const s = server(opts);
    await s.submit(cdr.who, { type: "set-operator", operator: { id: "CDR-1", role: "commander" }, auth: await cdr.sign(s.state, "operator.signed-in", {}) });
    const dp = untilDecision(s);
    await s.submit(cdr.who, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth: await cdr.sign(s.state, "coa.approved", { decision: dp.id, coa: dp.coas[0].id }) });
    for (let i = 0; i < 30; i++) s.step();
    return { s, cdr };
  }

  it("restores exactly the same state after a clean restart", async () => {
    const { s } = await busyServer({ snapshotEvery: 7 });
    const before = structuredClone(s.state);
    s.close();
    servers.length = 0;
    const again = server();
    expect(again.state).toEqual(before);
    expect(verify(again.state.ledger).ok).toBe(true);
  });

  it("recovers from a crash by replaying the journal, ignoring a torn last line", async () => {
    const { s } = await busyServer({ snapshotEvery: 25 });
    const before = structuredClone(s.state);
    expect(readFileSync(join(dir, "journal.jsonl"), "utf8").length).toBeGreaterThan(0); // records after the last snapshot
    servers.length = 0; // simulate a crash: no close(), no final snapshot
    unlinkSync(join(dir, "LOCK")); // the crashed process is gone
    writeFileSync(join(dir, "journal.jsonl"), readFileSync(join(dir, "journal.jsonl"), "utf8") + '{"n": 99999, "cmd": {"ty');
    const again = server();
    expect(again.state).toEqual(before);
  });

  it("refuses to start on a ledger that was edited on disk", async () => {
    const { s } = await busyServer();
    s.close();
    servers.length = 0;
    const snap = JSON.parse(readFileSync(join(dir, "snapshot.json"), "utf8"));
    snap.state.ledger[2].actor = "SOMEONE-ELSE";
    writeFileSync(join(dir, "snapshot.json"), JSON.stringify(snap));
    expect(() => server()).toThrow(/broken at #2/);
  });

  it("allows only one server per state directory", async () => {
    server();
    expect(() => new CommandServer({ dir, registry: () => registry, log: () => undefined }).open()).toThrow(/in use/);
  });

  it("archives a closed scenario with its signed closing entry and links the next one", async () => {
    const { s, cdr } = await busyServer();
    const oldHead = s.state.ledger.at(-1)!.hash;
    const r = await s.submit(cdr.who, { type: "close-scenario", seed: 42, auth: await cdr.sign(s.state, "scenario.closed", { seed: 42 }) });
    expect(r).toEqual({});
    expect(s.scenario).toBe(2);
    expect(s.state.seed).toBe(42);
    const opened = s.state.ledger.find((e) => e.action === "scenario.opened")!;
    expect(opened.payload.previous).toMatchObject({ scenario: 1 });

    const all = readdirSync(join(dir, "archive"));
    expect(all.filter((f) => f.endsWith(".journal.jsonl"))).toHaveLength(1); // the closed scenario's journal, kept for replicas
    const files = all.filter((f) => !f.endsWith(".journal.jsonl"));
    expect(files).toHaveLength(1);
    const archived = JSON.parse(readFileSync(join(dir, "archive", files[0]), "utf8")).state as State;
    expect(archived.ledger.at(-1)!.action).toBe("scenario.closed");
    expect(archived.ledger.at(-2)!.hash).toBe(oldHead);
    expect((opened.payload.previous as { head: string }).head).toBe(archived.ledger.at(-1)!.hash);
    expect((await auditSignatures(archived.ledger, registry)).problems).toEqual([]);

    s.close();
    servers.length = 0;
    expect(server().scenario).toBe(2);
  });
});

describe("command server: machine inputs", () => {
  it("journals feed batches and validated LLM drafts so replay reproduces them", async () => {
    let feeds = [{ via: "http-json:test", reports: [{ source: "gw", kind: "contact", lat: 38.9, lon: -77.1, confidence: 0.6, detail: "vehicle" }], adapterRejected: [] }];
    const drafter = vi.fn(async (sit: { assets: Array<{ id: string; available: boolean; allowedVerbs: string[] }> }) => {
      const asset = sit.assets.find((a) => a.available && a.allowedVerbs.includes("observe"))!;
      return { model: "stub-model", proposals: [{ title: "Stub look", rationale: "test", risk: "low" as const, actions: [{ assetId: asset.id, verb: "observe" as const, target: { x: 50, y: 50 }, note: "" }] }] };
    });
    const s = server({ drainFeeds: () => ({ batches: feeds.splice(0), dropped: 0 }), drafter: drafter as never });
    s.step();
    expect(s.state.ledger.some((e) => e.action === "feed.ingested")).toBe(true);
    expect(existsSync(join(dir, "journal.jsonl"))).toBe(true);
    untilDecision(s);
    await vi.waitFor(() => expect(s.state.decisions.some((d) => d.drafter.source === "llm")).toBe(true));
    const before = structuredClone(s.state);
    s.close();
    servers.length = 0;
    feeds = [];
    expect(server({ drafter: undefined }).state).toEqual(before);
  });

  it("never sends ground truth to consoles", () => {
    const v = server().view() as unknown as Record<string, unknown>;
    expect(v.truth).toBeUndefined();
    expect(v.rng).toBeUndefined();
    expect(v.ledger).toBeUndefined();
    expect(v.ledgerLength).toBeGreaterThan(0);
  });
});
