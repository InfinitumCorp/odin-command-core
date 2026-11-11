import { append, GENESIS } from "./ledger";
import { SIGN_ALG, verifyBytes, intentBytes, keyIdFor, type Intent } from "./identity";
import { compare, findEquivocations, majority, sealedLength, signCheckpoint, verifyCheckpoint, type Checkpoint, type SignedCheckpoint } from "./checkpoint";
import type { LedgerEntry } from "./types";

const subtle = globalThis.crypto.subtle;

async function nodeKey(nodeId: string) {
  const pair = (await subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const keyId = await keyIdFor(pub);
  const sign = (scenario: number, length: number, head: string) =>
    signCheckpoint({ v: 1, purpose: "firmament-checkpoint", nodeId, keyId, scenario, record: length, length, head, signedAt: new Date().toISOString() }, pair.privateKey);
  return { pub, keyId, sign, pair };
}

function ledgerOf(n: number, tag = "x"): LedgerEntry[] {
  let l: LedgerEntry[] = [];
  for (let i = 0; i < n; i++) l = append(l, i, "ODIN", "test", { i, tag });
  return l;
}

describe("Firmament checkpoints", () => {
  it("sign and verify; any change to the statement breaks the signature", async () => {
    const a = await nodeKey("odin-a");
    const l = ledgerOf(5);
    const sc = await a.sign(1, 5, l[4].hash);
    expect(await verifyCheckpoint(sc, a.pub)).toBe(true);
    expect(await verifyCheckpoint({ ...sc, cp: { ...sc.cp, length: 4 } }, a.pub)).toBe(false);
    expect(await verifyCheckpoint({ ...sc, cp: { ...sc.cp, head: l[3].hash } }, a.pub)).toBe(false);
    const b = await nodeKey("odin-b");
    expect(await verifyCheckpoint(sc, b.pub)).toBe(false);
  });

  it("a checkpoint signature cannot be passed off as an operator intent", async () => {
    const a = await nodeKey("odin-a");
    const sc = await a.sign(1, 0, GENESIS);
    const { cp } = sc;
    const intent: Intent = { v: 1, operatorId: cp.nodeId, keyId: cp.keyId, action: "coa.approved", subject: {}, head: cp.head, signedAt: cp.signedAt };
    expect(await verifyBytes(intentBytes(intent), sc.sig, a.pub)).toBe(false);
    expect((cp as Checkpoint).purpose).toBe("firmament-checkpoint");
  });

  it("compares a checkpoint with a ledger", async () => {
    const a = await nodeKey("odin-a");
    const l = ledgerOf(6);
    const fork = ledgerOf(6, "y");
    expect(compare((await a.sign(1, 4, l[3].hash)).cp, 1, l)).toBe("agrees");
    expect(compare((await a.sign(1, 4, fork[3].hash)).cp, 1, l)).toBe("disagrees");
    expect(compare((await a.sign(1, 9, l[5].hash)).cp, 1, l)).toBe("ahead");
    expect(compare((await a.sign(2, 4, l[3].hash)).cp, 1, l)).toBe("other-scenario");
    expect(compare((await a.sign(1, 0, GENESIS)).cp, 1, l)).toBe("agrees");
  });

  it("seals the longest prefix a majority has signed; disagreeing nodes count for nothing", async () => {
    const [b, c, d, e] = await Promise.all(["odin-b", "odin-c", "odin-d", "odin-e"].map(nodeKey));
    const l = ledgerOf(10);
    const fork = ledgerOf(10, "y");
    expect(majority(1)).toBe(1);
    expect(majority(3)).toBe(2);
    expect(majority(4)).toBe(3);
    expect(majority(5)).toBe(3);
    const peers: SignedCheckpoint[] = [await b.sign(1, 8, l[7].hash), await c.sign(1, 5, l[4].hash)];
    expect(sealedLength(l, 1, 10, peers, 2)).toBe(8); // 3 nodes: leader 10, b 8, c 5 -> second largest
    expect(sealedLength(l, 1, 10, peers, 3)).toBe(5);
    const withLiar = [...peers, await d.sign(1, 10, fork[9].hash), await e.sign(1, 12, fork[9].hash)];
    expect(sealedLength(l, 1, 10, withLiar, 3)).toBe(5); // 5 nodes, quorum 3: the forked and "ahead" nodes add nothing
    expect(sealedLength(l, 1, 10, [], 2)).toBe(0);
  });

  it("finds a node that signed two different heads for the same length", async () => {
    const a = await nodeKey("odin-a");
    const b = await nodeKey("odin-b");
    const l = ledgerOf(4);
    const fork = ledgerOf(4, "y");
    const cps = [await a.sign(1, 4, l[3].hash), await b.sign(1, 4, l[3].hash), await a.sign(1, 4, l[3].hash), await a.sign(1, 4, fork[3].hash), await a.sign(2, 4, fork[3].hash)];
    const eq = findEquivocations(cps);
    expect(eq).toHaveLength(1);
    expect(eq[0]).toMatchObject({ nodeId: "odin-a", scenario: 1, length: 4 });
    // The pair is a portable proof: both verify under odin-a's key.
    expect(await verifyCheckpoint(eq[0].a, a.pub)).toBe(true);
    expect(await verifyCheckpoint(eq[0].b, a.pub)).toBe(true);
  });
});
