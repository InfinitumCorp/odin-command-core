// Phase 7: FIDO2 security keys, attestation, the hardware policy and CAC/PIV certificate
// binding, driven end to end with an emulated authenticator (testAuthenticator.ts) and the
// test PKI in __fixtures__/pki (scripts/gen-test-pki.sh).

import { X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, request, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeCbor, encodeCbor } from "../core/cbor";
import { intentBytes, keyIdFor, loginBytes, SIGN_ALG, signLogin, verifyIntent, type Intent, type SignedIntent } from "../core/identity";
import { derToP1363, unb64u } from "../core/webauthn";
import { AuthError, AuthService, peerCertOf, type RequestContext } from "./auth";
import { OperatorStore } from "./operatorStore";
import { pki, PKI_DIR, TestAuthenticator } from "./testAuthenticator";
import { chainToRoot, loadAttestationPolicy, splitPem, type AttestationPolicy } from "./webauthnServer";

const RP = "localhost";
const ORIGIN = "http://localhost:5317";
const NONE: AttestationPolicy = { mode: "none", roots: [] };
const REQUIRE: AttestationPolicy = { mode: "require", roots: [new X509Certificate(pki("att-root.pem"))] };

let dir: string;
let store: OperatorStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "odin-webauthn-"));
  store = new OperatorStore(join(dir, "operators.json"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const service = (opts: ConstructorParameters<typeof AuthService>[1] = {}) => new AuthService(store, { rpId: RP, attestation: NONE, ...opts });
const status = (p: Promise<unknown>) => p.then(() => 200, (e) => (e instanceof AuthError ? e.status : (console.error(e), -1)));
const reason = (p: Promise<unknown>) => p.then(() => "ok", (e: Error) => e.message);

async function enrollKey(auth: AuthService, id: string, key: TestAuthenticator, code = store.add(id, id.startsWith("CDR") ? "commander" : "analyst")) {
  const opts = auth.webauthnBegin({ operatorId: id, code });
  const res = key.create(opts, ORIGIN);
  return auth.enroll({ operatorId: id, code, webauthn: { challenge: opts.challenge, clientDataJSON: res.clientDataJSON, attestationObject: res.attestationObject } });
}

async function loginWith(auth: AuthService, id: string, key: TestAuthenticator, keyId: string, ctx: RequestContext = {}, tweak = {}) {
  const { nonce } = auth.challenge({ operatorId: id });
  const proof = await key.sign(loginBytes({ v: 1, purpose: "odin-login", operatorId: id, keyId, nonce }), RP, ORIGIN, tweak);
  return auth.login({ operatorId: id, keyId, nonce, ...proof }, ctx);
}

describe("security-key enrollment and sign-in", () => {
  it("enrolls a FIDO2 key, signs in with it, and offers its credential id", async () => {
    const auth = service();
    const key = new TestAuthenticator();
    const { keyId, kind } = await enrollKey(auth, "CDR-1", key);
    expect(kind).toBe("webauthn");
    const stored = store.get("CDR-1")!.keys[0];
    expect(stored).toMatchObject({ kind: "webauthn", rpId: RP, uv: true, attestation: { fmt: "none", trusted: false } });
    expect(auth.challenge({ operatorId: "CDR-1" }).credentials).toEqual([{ keyId, credentialId: key.credentialId.toString("base64url"), rpId: RP }]);

    const { me, token } = await loginWith(auth, "CDR-1", key, keyId);
    expect(me).toMatchObject({ id: "CDR-1", keyKind: "webauthn" });
    expect(auth.me(token)?.keyKind).toBe("webauthn");
    expect(store.get("CDR-1")!.keys[0].signCount).toBe(2); // registration counted 1, sign-in 2
    expect(auth.registry()[0].keys[0]).not.toHaveProperty("signCount");
  });

  it("refuses assertions for another site, another message, without touch or PIN, or of the wrong type", async () => {
    const auth = service();
    const key = new TestAuthenticator();
    const { keyId } = await enrollKey(auth, "CDR-1", key);
    expect(await status(loginWith(auth, "CDR-1", key, keyId, {}, { rpId: "evil.example" }))).toBe(401);
    expect(await status(loginWith(auth, "CDR-1", key, keyId, {}, { challenge: "AAAA" }))).toBe(401);
    expect(await status(loginWith(auth, "CDR-1", key, keyId, {}, { type: "webauthn.create" }))).toBe(401);
    key.opts.uv = false;
    expect(await status(loginWith(auth, "CDR-1", key, keyId))).toBe(401);
    key.opts.uv = true;
    key.opts.up = false;
    expect(await status(loginWith(auth, "CDR-1", key, keyId))).toBe(401);
    key.opts.up = true;
    // Five failures lock the operator out, as with browser keys.
    expect(await status(loginWith(auth, "CDR-1", key, keyId))).toBe(401);
    store.recordSuccess("CDR-1");
    expect(await status(loginWith(auth, "CDR-1", key, keyId))).toBe(200);
  });

  it("refuses an assertion made on another origin", async () => {
    const auth = service();
    const key = new TestAuthenticator();
    const { keyId } = await enrollKey(auth, "CDR-1", key);
    const { nonce } = auth.challenge({ operatorId: "CDR-1" });
    const msg = loginBytes({ v: 1, purpose: "odin-login", operatorId: "CDR-1", keyId, nonce });
    const proof = await key.sign(msg, RP, "https://odin.evil.example");
    expect(await status(auth.login({ operatorId: "CDR-1", keyId, nonce, ...proof }))).toBe(401);
  });

  it("does not let a browser-key signature stand in for a security key, or the reverse", async () => {
    const auth = service();
    const hw = new TestAuthenticator();
    const { keyId } = await enrollKey(auth, "CDR-1", hw);
    const { nonce } = auth.challenge({ operatorId: "CDR-1" });
    const msg = loginBytes({ v: 1, purpose: "odin-login", operatorId: "CDR-1", keyId, nonce });
    const proof = await hw.sign(msg, RP, ORIGIN);
    // The DER signature over authData||hash, presented without its evidence, as a plain signature.
    const p1363 = Buffer.from(derToP1363(unb64u(proof.sig))).toString("base64url");
    expect(await status(auth.login({ operatorId: "CDR-1", keyId, nonce, sig: p1363 }))).toBe(401);

    // A browser key with security-key evidence attached.
    const code = store.add("ANL-4", "analyst");
    const pair = (await crypto.subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    const sw = await auth.enroll({ operatorId: "ANL-4", code, publicKeyJwk });
    const c2 = auth.challenge({ operatorId: "ANL-4" });
    const sig = await signLogin({ v: 1, purpose: "odin-login", operatorId: "ANL-4", keyId: sw.keyId, nonce: c2.nonce }, pair.privateKey);
    expect(await status(auth.login({ operatorId: "ANL-4", keyId: sw.keyId, nonce: c2.nonce, sig, webauthn: proof.webauthn }))).toBe(401);
  });

  it("detects a cloned key from its signature counter", async () => {
    const auth = service();
    const key = new TestAuthenticator();
    const { keyId } = await enrollKey(auth, "CDR-1", key);
    const copy = key.clone(); // same secret, counter reset, as a cloned key would be
    await loginWith(auth, "CDR-1", key, keyId);
    await loginWith(auth, "CDR-1", key, keyId);
    expect(await reason(loginWith(auth, "CDR-1", copy, keyId))).toMatch(/counter went backwards/);
  });

  it("accepts keys that never count (counter always 0)", async () => {
    const auth = service();
    const key = new TestAuthenticator({ fixedCounter: 0 });
    const { keyId } = await enrollKey(auth, "CDR-1", key);
    for (let i = 0; i < 3; i++) expect(await status(loginWith(auth, "CDR-1", key, keyId))).toBe(200);
  });
});

describe("registration checks", () => {
  const begin = (auth: AuthService) => {
    const code = store.add("CDR-1", "commander");
    return { code, opts: auth.webauthnBegin({ operatorId: "CDR-1", code }) };
  };
  const submit = (auth: AuthService, code: string, challenge: string, res: { clientDataJSON: string; attestationObject: string }) =>
    reason(auth.enroll({ operatorId: "CDR-1", code, webauthn: { challenge, ...res } }));

  it("needs a valid enrollment code before it issues a challenge", () => {
    const auth = service();
    store.add("CDR-1", "commander");
    expect(() => auth.webauthnBegin({ operatorId: "CDR-1", code: "WRONG-CODE" })).toThrow(/enrollment failed/);
  });

  it("refuses the wrong challenge, ceremony, origin, a missing PIN, and a replayed challenge", async () => {
    const auth = service();
    const { code, opts } = begin(auth);
    const key = new TestAuthenticator();
    expect(await submit(auth, code, opts.challenge, key.create(opts, ORIGIN, { challenge: "other" }))).toMatch(/different challenge/);

    const o2 = auth.webauthnBegin({ operatorId: "CDR-1", code });
    expect(await submit(auth, code, o2.challenge, key.create(o2, ORIGIN, { type: "webauthn.get" }))).toMatch(/not a registration/);
    const o3 = auth.webauthnBegin({ operatorId: "CDR-1", code });
    expect(await submit(auth, code, o3.challenge, key.create(o3, "https://evil.example"))).toMatch(/another site/);
    const o4 = auth.webauthnBegin({ operatorId: "CDR-1", code });
    expect(await submit(auth, code, o4.challenge, new TestAuthenticator({ uv: false }).create(o4, ORIGIN))).toMatch(/PIN/);
    const o5 = auth.webauthnBegin({ operatorId: "CDR-1", code });
    expect(await submit(auth, code, o5.challenge, key.create({ ...o5, rp: { id: "evil.example" } }, ORIGIN))).toMatch(/another site/);

    const o6 = auth.webauthnBegin({ operatorId: "CDR-1", code });
    const good = key.create(o6, ORIGIN);
    expect(await submit(auth, code, o6.challenge, good)).toBe("ok");
    expect(await submit(auth, code, o6.challenge, good)).toMatch(/enrollment failed|expired/); // code and challenge are spent
  });

  it("refuses a non-ES256 credential key", async () => {
    const auth = service();
    const { code, opts } = begin(auth);
    const res = new TestAuthenticator().create(opts, ORIGIN);
    // Rewrite the COSE alg in authData to RS256 (-257): the attestation object stays well formed.
    const att = decodeCbor(unb64u(res.attestationObject)).value as Map<unknown, unknown>;
    const ad = Buffer.from(att.get("authData") as Uint8Array);
    const coseAt = 55 + ((ad[53] << 8) + ad[54]);
    const cose = decodeCbor(ad.subarray(coseAt)).value as Map<number, unknown>;
    cose.set(3, -257);
    att.set("authData", new Uint8Array(Buffer.concat([ad.subarray(0, coseAt), encodeCbor(cose as never)])));
    const attestationObject = Buffer.from(encodeCbor(att as never)).toString("base64url");
    expect(await submit(auth, code, opts.challenge, { clientDataJSON: res.clientDataJSON, attestationObject })).toMatch(/only ES256/);
  });
});

describe("attestation", () => {
  const enrollAs = async (policy: AttestationPolicy, key: TestAuthenticator) => {
    const auth = service({ attestation: policy });
    const code = store.add("CDR-1", "commander");
    const opts = auth.webauthnBegin({ operatorId: "CDR-1", code });
    expect(opts.attestation).toBe(policy.mode === "require" ? "direct" : "none");
    const res = key.create(opts, ORIGIN);
    return reason(auth.enroll({ operatorId: "CDR-1", code, webauthn: { challenge: opts.challenge, ...res } }));
  };

  it("records packed attestation from an approved maker as trusted", async () => {
    expect(await enrollAs(REQUIRE, new TestAuthenticator({ fmt: "packed", aaguid: "0dd1e5a1-0000-4000-8000-000000000001" }))).toBe("ok");
    expect(store.get("CDR-1")!.keys[0].attestation).toMatchObject({ fmt: "packed", trusted: true, aaguid: "0dd1e5a1-0000-4000-8000-000000000001" });
    expect(store.get("CDR-1")!.keys[0].attestation?.subject).toMatch(/ODIN Test Key Model 1/);
  });

  it("accepts fido-u2f attestation chained to an approved root", async () => {
    expect(await enrollAs(REQUIRE, new TestAuthenticator({ fmt: "fido-u2f" }))).toBe("ok");
  });

  it("under ODIN_ATTESTATION=require refuses unknown makers, self attestation and none", async () => {
    expect(await enrollAs(REQUIRE, new TestAuthenticator({ fmt: "packed", attestation: { cert: "rogue-leaf.pem", key: "rogue-leaf.key" } }))).toMatch(/approved root/);
    rmSync(store.path);
    expect(await enrollAs(REQUIRE, new TestAuthenticator({ fmt: "packed-self" }))).toMatch(/approved root/);
    rmSync(store.path);
    expect(await enrollAs(REQUIRE, new TestAuthenticator({ fmt: "none" }))).toMatch(/approved root/);
  });

  it("refuses an attestation signature by the wrong key", async () => {
    // The approved certificate, but signed with an unrelated key.
    expect(await enrollAs(REQUIRE, new TestAuthenticator({ fmt: "packed", attestation: { cert: "att-leaf.pem", key: "rogue-leaf.key" } }))).toMatch(/does not verify/);
  });

  it("refuses a CA certificate as the attestation certificate", async () => {
    expect(await enrollAs(NONE, new TestAuthenticator({ fmt: "packed", attestation: { cert: "att-root.pem", key: "att-root.key" } }))).toMatch(/must not be a CA/);
  });

  it("without require, records self and untrusted attestation but enrolls", async () => {
    expect(await enrollAs(NONE, new TestAuthenticator({ fmt: "packed-self" }))).toBe("ok");
    expect(store.get("CDR-1")!.keys[0].attestation).toMatchObject({ fmt: "packed", trusted: false });
  });

  it("applies an AAGUID allow-list", async () => {
    const policy = { ...NONE, aaguids: ["0dd1e5a1-0000-4000-8000-000000000001"] };
    expect(await enrollAs(policy, new TestAuthenticator({ aaguid: "0dd1e5a1-0000-4000-8000-000000000002" }))).toMatch(/not on the approved list/);
    rmSync(store.path);
    expect(await enrollAs(policy, new TestAuthenticator({ aaguid: "0dd1e5a1-0000-4000-8000-000000000001" }))).toBe("ok");
  });

  it("checks chains: issuer signatures, dates and roots", () => {
    const leaf = new X509Certificate(pki("att-leaf.pem"));
    const root = new X509Certificate(pki("att-root.pem"));
    const rogue = new X509Certificate(pki("rogue-root.pem"));
    expect(chainToRoot([leaf], [root])).toBe(true);
    expect(chainToRoot([leaf, root], [root])).toBe(true);
    expect(chainToRoot([leaf], [rogue])).toBe(false);
    expect(chainToRoot([leaf], [root], new Date("2100-01-01"))).toBe(false);
    expect(chainToRoot([leaf, rogue], [rogue])).toBe(false);
  });

  it("loads the policy from the environment", () => {
    const roots = join(PKI_DIR, "att-root.pem");
    const p = loadAttestationPolicy({ ODIN_ATTESTATION: "require", ODIN_ATTESTATION_ROOTS: roots, ODIN_AAGUIDS: "ABC, def" });
    expect(p).toMatchObject({ mode: "require", aaguids: ["abc", "def"] });
    expect(p.roots).toHaveLength(1);
    expect(() => loadAttestationPolicy({ ODIN_ATTESTATION: "require" })).toThrow(/ROOTS/);
    expect(splitPem(pki("att-root.pem") + pki("att-leaf.pem"))).toHaveLength(2);
  });
});

describe("hardware policy", () => {
  async function softwareEnroll(auth: AuthService, id: string, code: string) {
    const pair = (await crypto.subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    const keyId = await keyIdFor(publicKeyJwk);
    return { pair, keyId, result: () => auth.enroll({ operatorId: id, code, publicKeyJwk }) };
  }

  it("commander policy: commanders need a security key, analysts do not", async () => {
    const auth = service({ requireHardware: "commander" });
    const cdr = await softwareEnroll(auth, "CDR-1", store.add("CDR-1", "commander"));
    expect(await status(cdr.result())).toBe(403);
    const anl = await softwareEnroll(auth, "ANL-4", store.add("ANL-4", "analyst"));
    expect(await status(anl.result())).toBe(200);
    expect(await status(enrollKey(auth, "CDR-1", new TestAuthenticator(), store.reset("CDR-1")))).toBe(200);
  });

  it("existing browser-key sessions and sign-ins stop when the policy or the role changes", async () => {
    const open = service();
    const code = store.add("ANL-4", "analyst");
    const d = await softwareEnroll(open, "ANL-4", code);
    await d.result();
    const signIn = async (auth: AuthService) => {
      const { nonce } = auth.challenge({ operatorId: "ANL-4" });
      const sig = await signLogin({ v: 1, purpose: "odin-login", operatorId: "ANL-4", keyId: d.keyId, nonce }, d.pair.privateKey);
      return auth.login({ operatorId: "ANL-4", keyId: d.keyId, nonce, sig });
    };
    const strict = service({ requireHardware: "commander" });
    const { token } = await signIn(strict);
    expect(strict.me(token)?.id).toBe("ANL-4");
    store.setRole("ANL-4", "commander"); // promoted: now covered by the policy
    expect(strict.me(token)).toBeUndefined();
    expect(await reason(signIn(strict))).toMatch(/must sign in with a FIDO2 security key/);
    expect(await status(signIn(service({ requireHardware: "all" })))).toBe(403);
  });

  it("security-key intents verify against the registry and fail when altered", async () => {
    const auth = service();
    const key = new TestAuthenticator();
    const { keyId } = await enrollKey(auth, "CDR-1", key);
    const regKey = auth.registry()[0].keys[0];
    const intent: Intent = { v: 1, operatorId: "CDR-1", keyId, action: "coa.approved", subject: { decision: "DP-1", coa: "DP-1-A" }, head: "00".repeat(32), signedAt: new Date().toISOString() };
    const si: SignedIntent = { intent, ...(await key.sign(intentBytes(intent), RP, ORIGIN)) };
    expect(await verifyIntent(si, regKey)).toMatchObject({ ok: true, hardware: true, signCount: 2 });
    expect(await verifyIntent({ ...si, intent: { ...intent, subject: { decision: "DP-1", coa: "DP-1-B" } } }, regKey)).toMatchObject({ ok: false, reason: /different message/ });
    expect(await verifyIntent({ intent, sig: si.sig }, regKey)).toMatchObject({ ok: false, reason: /security key required/ });
    // A signed command with a counter that did not advance is refused (wired as CommandServer onSignCount).
    auth.advanceSignCount("CDR-1", keyId, 2);
    expect(() => auth.advanceSignCount("CDR-1", keyId, 2)).toThrow(/counter went backwards/);
  });
});

describe("CAC/PIV certificate binding", () => {
  const fp = (name: string) => new X509Certificate(pki(name)).fingerprint256;

  it("a certificate-bound operator must present that certificate, verified by the CA", async () => {
    const auth = service();
    const key = new TestAuthenticator();
    const { keyId } = await enrollKey(auth, "CDR-1", key);
    store.bindCert("CDR-1", { fingerprint256: fp("cdr1.pem"), subject: "CN=CDR-1 Test Commander" });
    const peer = (name: string, authorized = true) => ({ peer: { fingerprint256: fp(name), subject: "", authorized } });
    expect(await reason(loginWith(auth, "CDR-1", key, keyId))).toMatch(/CAC\/PIV/);
    expect(await reason(loginWith(auth, "CDR-1", key, keyId, peer("other.pem")))).toMatch(/CAC\/PIV/);
    expect(await reason(loginWith(auth, "CDR-1", key, keyId, peer("cdr1.pem", false)))).toMatch(/CAC\/PIV/);
    const { token } = await loginWith(auth, "CDR-1", key, keyId, peer("cdr1.pem"));
    expect(auth.me(token, peer("cdr1.pem"))?.id).toBe("CDR-1");
    expect(auth.me(token, {})).toBeUndefined(); // the session is tied to the certificate too
    store.unbindCert("CDR-1");
    expect(auth.me(token, {})?.id).toBe("CDR-1");
  });

  describe("over mutual TLS", () => {
    let server: Server;
    let port: number;
    beforeAll(async () => {
      server = createServer({ cert: pki("server.pem"), key: pki("server.key"), ca: pki("piv-ca.pem"), requestCert: true, rejectUnauthorized: false }, (req, res) => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(peerCertOf(req) ?? null));
      });
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      port = (server.address() as AddressInfo).port;
    });
    afterAll(() => new Promise<void>((r) => server.close(() => r())));

    const get = (client?: { cert: string; key: string }) =>
      new Promise<{ fingerprint256: string; subject: string; authorized: boolean } | null>((resolve, reject) => {
        const req = request({ host: "127.0.0.1", port, path: "/", servername: "localhost", ca: pki("piv-ca.pem"), ...client }, (res) => {
          let body = "";
          res.on("data", (c) => (body += c));
          res.on("end", () => resolve(JSON.parse(body)));
        });
        req.on("error", reject);
        req.end();
      });

    it("reads the presented certificate and whether the configured CA issued it", async () => {
      expect(await get()).toBeNull();
      const cdr = await get({ cert: pki("cdr1.pem"), key: pki("cdr1.key") });
      expect(cdr).toMatchObject({ fingerprint256: fp("cdr1.pem"), authorized: true });
      expect(cdr!.subject).toMatch(/CN=CDR-1 Test Commander/);
      const rogue = await get({ cert: pki("rogue-leaf.pem"), key: pki("rogue-leaf.key") });
      expect(rogue).toMatchObject({ fingerprint256: fp("rogue-leaf.pem"), authorized: false });
    });
  });
});
