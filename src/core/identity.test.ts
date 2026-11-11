import { initialState, run } from "./engine";
import { append, GENESIS, verify } from "./ledger";
import { auditSignatures, keyIdFor, SIGN_ALG, signIntent, type RegistryOperator, type SignedAction, type SignedIntent } from "./identity";
import type { Operator, State } from "./types";

const subtle = globalThis.crypto.subtle;

async function operator(id: string, role: "commander" | "analyst") {
  const pair = (await subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const keyId = await keyIdFor(publicKeyJwk);
  const reg: RegistryOperator = { id, name: id, role, disabled: false, keys: [{ keyId, publicKeyJwk, addedAt: "2026-01-01T00:00:00Z" }] };
  const op: Operator = { id, role, keyId };
  const sign = (s: State, action: SignedAction, subject: Record<string, string | number | boolean>, head = s.ledger.at(-1)?.hash ?? GENESIS) =>
    signIntent({ v: 1, operatorId: id, keyId, action, subject, head, signedAt: new Date().toISOString() }, pair.privateKey);
  return { reg, op, sign };
}

function runUntilDecision(s: State): State {
  for (let i = 0; i < 600 && !s.decisions.some((d) => d.status === "open" && d.coas[0].actions.length); i++) s = run(s, { type: "tick" }).state;
  return s;
}

const openDp = (s: State) => s.decisions.find((d) => d.status === "open" && d.coas[0].actions.length)!;

describe("signed commands (core gate)", () => {
  it("refuses unsigned human commands when signatures are required, but keeps machine input flowing", async () => {
    const cdr = await operator("CDR-1", "commander");
    let s = runUntilDecision(initialState(3, cdr.op, { requireSignatures: true }));
    const dp = openDp(s);
    const r = run(s, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id });
    expect(r.error).toMatch(/must be signed/);
    expect(r.state.decisions.find((d) => d.id === dp.id)!.status).toBe("open");
    expect(run(s, { type: "set-simulation", enabled: false }).error).toMatch(/must be signed/);
    s = run(s, { type: "tick", minutes: 5 }).state; // ticks and feeds are not human actions
    expect(s.t).toBeGreaterThan(dp.t);
  });

  it("accepts a valid signature and records it in the ledger", async () => {
    const cdr = await operator("CDR-1", "commander");
    const s = runUntilDecision(initialState(3, cdr.op, { requireSignatures: true }));
    const dp = openDp(s);
    const auth = await cdr.sign(s, "coa.approved", { decision: dp.id, coa: dp.coas[0].id });
    const r = run(s, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth });
    expect(r.error).toBeUndefined();
    const e = r.state.ledger.find((x) => x.action === "coa.approved")!;
    expect(e.payload.auth).toEqual(auth);
  });

  it("rejects a signature for a different decision, action, operator or unknown ledger head", async () => {
    const cdr = await operator("CDR-1", "commander");
    const other = await operator("CDR-2", "commander");
    const s = runUntilDecision(initialState(3, cdr.op, { requireSignatures: true }));
    const dp = openDp(s);
    const approve = (auth: SignedIntent) => run(s, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth }).error;
    expect(approve(await cdr.sign(s, "coa.approved", { decision: dp.id, coa: "SOMETHING-ELSE" }))).toMatch(/does not cover/);
    expect(approve(await cdr.sign(s, "decision.rejected", { decision: dp.id }))).toMatch(/is for decision.rejected/);
    expect(approve(await other.sign(s, "coa.approved", { decision: dp.id, coa: dp.coas[0].id }))).toMatch(/not from the signed-in operator/);
    expect(approve(await cdr.sign(s, "coa.approved", { decision: dp.id, coa: dp.coas[0].id }, "f".repeat(64)))).toMatch(/ledger state/);
  });

  it("keeps requiring signatures after New scenario", async () => {
    const cdr = await operator("CDR-1", "commander");
    const s = run(initialState(3, cdr.op, { requireSignatures: true }), { type: "reset", seed: 9 }).state;
    expect(s.requireSignatures).toBe(true);
    expect(s.operator).toEqual(cdr.op);
  });
});

describe("signature audit", () => {
  async function signedHistory() {
    const cdr = await operator("CDR-1", "commander");
    const anl = await operator("ANL-4", "analyst");
    let s = initialState(3, cdr.op, { requireSignatures: true });
    s = run(s, { type: "set-operator", operator: cdr.op, auth: await cdr.sign(s, "operator.signed-in", {}) }).state;
    s = runUntilDecision(s);
    const dp = openDp(s);
    s = run(s, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id, auth: await cdr.sign(s, "coa.approved", { decision: dp.id, coa: dp.coas[0].id }) }).state;
    s = run(s, { type: "set-simulation", enabled: false, auth: await cdr.sign(s, "simulation.toggled", { enabled: false }) }).state;
    return { s, cdr, anl, dp, registry: [cdr.reg, anl.reg] };
  }

  it("passes a fully signed history", async () => {
    const { s, registry } = await signedHistory();
    const a = await auditSignatures(s.ledger, registry);
    expect(a.problems).toEqual([]);
    expect(a.signed).toBe(3);
  });

  it("catches a forged approval even when the hash chain is rebuilt to verify", async () => {
    const { s, registry } = await signedHistory();
    const real = s.ledger.find((e) => e.action === "coa.approved")!.payload.auth as SignedIntent;
    // Replay the commander's real signature onto a different decision, re-chained correctly.
    const ledger = append(s.ledger, s.t, "CDR-1", "coa.approved", { decision: "DP-X", coa: "DP-X-A", auth: real });
    expect(verify(ledger).ok).toBe(true);
    const a = await auditSignatures(ledger, registry);
    expect(a.problems).toEqual([{ seq: ledger.length - 1, reason: expect.stringMatching(/signed decision .* does not match DP-X/) }]);
  });

  it("catches an altered signed subject (signature no longer verifies)", async () => {
    const { s, registry } = await signedHistory();
    const i = s.ledger.findIndex((e) => e.action === "simulation.toggled");
    const auth = s.ledger[i].payload.auth as SignedIntent;
    const forged = { ...auth, intent: { ...auth.intent, subject: { enabled: true } } };
    let ledger = s.ledger.slice(0, i);
    ledger = append(ledger, s.ledger[i].t, "CDR-1", "simulation.toggled", { enabled: true, auth: forged });
    const a = await auditSignatures(ledger, registry);
    expect(a.problems.map((p) => p.reason)).toEqual(["signature does not verify"]);
  });

  it("flags unsigned human actions, unknown operators, wrong roles and revoked keys", async () => {
    const { s, anl, cdr, dp, registry } = await signedHistory();
    let ledger = append(s.ledger, s.t, "CDR-1", "decision.rejected", { decision: dp.id, reason: "x" }); // unsigned
    // An analyst's genuine signature on a commander-only action.
    const anlAuth = await anl.sign({ ...s, ledger }, "coa.approved", { decision: "DP-Y", coa: "DP-Y-A" });
    ledger = append(ledger, s.t, "ANL-4", "coa.approved", { decision: "DP-Y", coa: "DP-Y-A", auth: anlAuth });
    const reasons = (await auditSignatures(ledger, registry)).problems.map((p) => p.reason);
    expect(reasons).toEqual(["unsigned human action", "ANL-4 is analyst, action needs commander"]);

    expect((await auditSignatures(s.ledger, [anl.reg])).problems[0].reason).toBe("unknown operator CDR-1");
    const revoked = { ...cdr.reg, keys: cdr.reg.keys.map((k) => ({ ...k, revokedAt: "2026-01-02T00:00:00Z" })) };
    expect((await auditSignatures(s.ledger, [revoked])).problems[0].reason).toBe("key was revoked before signing");
    const rekeyed = { ...cdr.reg, keys: anl.reg.keys };
    expect((await auditSignatures(s.ledger, [rekeyed])).problems[0].reason).toBe("key not registered to this operator");
  });
});
