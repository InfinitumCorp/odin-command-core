import { mkdtempSync, rmSync, statSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keyIdFor, SIGN_ALG, signLogin } from "../core/identity";
import { AuthError, AuthService, authRoutes, CHALLENGE_SECONDS, SESSION_COOKIE } from "./auth";
import { LOCKOUT_MINUTES, MAX_FAILURES, OperatorStore } from "./operatorStore";

const subtle = globalThis.crypto.subtle;
let dir: string;
let store: OperatorStore;
let auth: AuthService;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "odin-auth-"));
  store = new OperatorStore(join(dir, "operators.json"));
  auth = new AuthService(store);
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

async function device() {
  const pair = (await subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  return { pair, publicKeyJwk, keyId: await keyIdFor(publicKeyJwk) };
}

async function login(operatorId: string, d: Awaited<ReturnType<typeof device>>) {
  const { nonce } = auth.challenge({ operatorId });
  const sig = await signLogin({ v: 1, purpose: "odin-login", operatorId, keyId: d.keyId, nonce }, d.pair.privateKey);
  return { nonce, sig, result: () => auth.login({ operatorId, keyId: d.keyId, nonce, sig }) };
}

const status = (p: Promise<unknown>) => p.then(() => 200, (e) => (e instanceof AuthError ? e.status : -1));

describe("operator store", () => {
  it("stores only a hash of the enrollment code, in a private file", () => {
    const code = store.add("CDR-1", "commander", "Maj. Example");
    const raw = JSON.stringify(store.load());
    expect(raw).not.toContain(code);
    expect(raw).not.toContain(code.replace(/-/g, ""));
    expect(store.codeMatches(store.get("CDR-1")!, code)).toBe(true);
    expect(store.codeMatches(store.get("CDR-1")!, code.toLowerCase().replace(/-/g, " "))).toBe(true); // forgiving on format
    if (process.platform !== "win32") expect(statSync(store.path).mode & 0o777).toBe(0o600);
  });

  it("validates ids and roles and refuses duplicates", () => {
    expect(() => store.add("cdr 1", "commander")).toThrow(/operator id/);
    expect(() => store.add("CDR-1", "general" as never)).toThrow(/role/);
    store.add("CDR-1", "commander");
    expect(() => store.add("CDR-1", "analyst")).toThrow(/already exists/);
  });

  it("expires enrollment codes", () => {
    const code = store.add("CDR-1", "commander");
    expect(store.codeMatches(store.get("CDR-1")!, code, Date.now() + 25 * 3600_000)).toBe(false);
  });
});

describe("enrollment and sign-in", () => {
  it("enrolls a device once, then signs in with challenge-response", async () => {
    const code = store.add("CDR-1", "commander", "Maj. Example");
    const d = await device();
    expect(await auth.enroll({ operatorId: "CDR-1", code, publicKeyJwk: d.publicKeyJwk })).toEqual({ keyId: d.keyId, kind: "software" });
    // The code is burned.
    const d2 = await device();
    expect(await status(auth.enroll({ operatorId: "CDR-1", code, publicKeyJwk: d2.publicKeyJwk }))).toBe(401);

    const { result } = await login("CDR-1", d);
    const { token, me } = await result();
    expect(me).toEqual({ id: "CDR-1", name: "Maj. Example", role: "commander", keyKind: "software", keyId: d.keyId });
    expect(auth.me(token)).toEqual(me);
  });

  it("refuses private keys, wrong codes and unknown operators with the same answer", async () => {
    const code = store.add("CDR-1", "commander");
    const d = await device();
    const priv = { ...d.publicKeyJwk, d: "secret" };
    expect(await status(auth.enroll({ operatorId: "CDR-1", code, publicKeyJwk: priv }))).toBe(400);
    const wrong = await auth.enroll({ operatorId: "CDR-1", code: "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA", publicKeyJwk: d.publicKeyJwk }).catch((e) => e);
    const unknown = await auth.enroll({ operatorId: "NOBODY", code, publicKeyJwk: d.publicKeyJwk }).catch((e) => e);
    expect(wrong.message).toBe(unknown.message);
    expect(store.get("CDR-1")!.failures).toBe(1);
  });

  it("locks an operator out after repeated failures", async () => {
    const code = store.add("CDR-1", "commander");
    const d = await device();
    for (let i = 0; i < MAX_FAILURES; i++) await status(auth.enroll({ operatorId: "CDR-1", code: "WRONG", publicKeyJwk: d.publicKeyJwk }));
    // Even the right code fails while locked.
    expect(await status(auth.enroll({ operatorId: "CDR-1", code, publicKeyJwk: d.publicKeyJwk }))).toBe(401);
    auth.now = () => Date.now() + (LOCKOUT_MINUTES + 1) * 60_000;
    expect(await status(auth.enroll({ operatorId: "CDR-1", code, publicKeyJwk: d.publicKeyJwk }))).toBe(200);
  });

  it("uses each challenge once, for one operator, within its lifetime", async () => {
    const code = store.add("CDR-1", "commander");
    store.add("ANL-4", "analyst");
    const d = await device();
    await auth.enroll({ operatorId: "CDR-1", code, publicKeyJwk: d.publicKeyJwk });

    const first = await login("CDR-1", d);
    await first.result();
    expect(await status(first.result())).toBe(401); // replay

    const late = await login("CDR-1", d);
    auth.now = () => Date.now() + (CHALLENGE_SECONDS + 1) * 1000;
    expect(await status(late.result())).toBe(401);
    auth.now = Date.now;

    const { nonce } = auth.challenge({ operatorId: "ANL-4" }); // nonce issued to someone else
    const sig = await signLogin({ v: 1, purpose: "odin-login", operatorId: "CDR-1", keyId: d.keyId, nonce }, d.pair.privateKey);
    expect(await status(auth.login({ operatorId: "CDR-1", keyId: d.keyId, nonce, sig }))).toBe(401);
  });

  it("rejects a signature from a key that is not the operator's", async () => {
    const code = store.add("CDR-1", "commander");
    const d = await device();
    await auth.enroll({ operatorId: "CDR-1", code, publicKeyJwk: d.publicKeyJwk });
    const thief = await device();
    const { nonce } = auth.challenge({ operatorId: "CDR-1" });
    const sig = await signLogin({ v: 1, purpose: "odin-login", operatorId: "CDR-1", keyId: d.keyId, nonce }, thief.pair.privateKey);
    expect(await status(auth.login({ operatorId: "CDR-1", keyId: d.keyId, nonce, sig }))).toBe(401);
    expect(store.get("CDR-1")!.failures).toBe(1);
  });

  it("ends sessions at once when an operator is disabled or their keys are reset", async () => {
    const code = store.add("CDR-1", "commander");
    const d = await device();
    await auth.enroll({ operatorId: "CDR-1", code, publicKeyJwk: d.publicKeyJwk });
    const a = await (await login("CDR-1", d)).result();
    store.setRole("CDR-1", "analyst");
    expect(auth.me(a.token)?.role).toBe("analyst"); // role changes apply immediately
    store.setDisabled("CDR-1", true);
    expect(auth.me(a.token)).toBeUndefined();

    store.setDisabled("CDR-1", false);
    const b = await (await login("CDR-1", d)).result();
    store.reset("CDR-1");
    expect(auth.me(b.token)).toBeUndefined();
    expect(await status((await login("CDR-1", d)).result())).toBe(401);
    expect(auth.registry()[0].keys[0].revokedAt).toBeDefined();
  });
});

describe("auth routes over HTTP", () => {
  let server: Server;
  let base: string;
  beforeEach(async () => {
    const handler = authRoutes(auth);
    server = createServer((req, res) => {
      req.url = req.url!.replace(/^\/api\/auth/, "");
      void handler(req, res);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/auth`;
  });
  afterEach(() => new Promise<void>((r) => server.close(() => r())));

  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    fetch(`${base}/${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

  it("sets an HttpOnly, SameSite=Strict session cookie and guards the registry", async () => {
    const code = store.add("CDR-1", "commander");
    const d = await device();
    expect((await post("enroll", { operatorId: "CDR-1", code, publicKeyJwk: d.publicKeyJwk })).status).toBe(200);
    expect((await fetch(`${base}/registry`)).status).toBe(401);

    const { nonce } = await (await post("challenge", { operatorId: "CDR-1" })).json();
    const sig = await signLogin({ v: 1, purpose: "odin-login", operatorId: "CDR-1", keyId: d.keyId, nonce }, d.pair.privateKey);
    const res = await post("login", { operatorId: "CDR-1", keyId: d.keyId, nonce, sig });
    expect(res.status).toBe(200);
    const cookie = res.headers.get("set-cookie")!;
    expect(cookie).toMatch(new RegExp(`^${SESSION_COOKIE}=[\\w-]{43}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800$`));
    const session = cookie.split(";")[0];

    const me = await fetch(`${base}/me`, { headers: { cookie: session } });
    expect((await me.json()).id).toBe("CDR-1");
    const reg = await (await fetch(`${base}/registry`, { headers: { cookie: session } })).json();
    expect(JSON.stringify(reg)).not.toMatch(/hash|salt|failures/);

    await post("logout", {}, { cookie: session });
    expect((await fetch(`${base}/me`, { headers: { cookie: session } })).status).toBe(401);
  });

  it("requires JSON on POST (no simple cross-site form posts)", async () => {
    const res = await fetch(`${base}/challenge`, { method: "POST", headers: { "content-type": "text/plain" }, body: '{"operatorId":"CDR-1"}' });
    expect(res.status).toBe(415);
    expect((await post("challenge", "not an object")).status).toBe(400);
  });
});
