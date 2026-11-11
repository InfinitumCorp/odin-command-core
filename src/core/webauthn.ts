// Hardware-backed signatures (FIDO2 / WebAuthn security keys).
//
// A security key never signs our message directly. It signs
//     authenticatorData || SHA-256(clientDataJSON)
// where clientDataJSON carries a challenge. ODIN sets that challenge to SHA-256 of the exact
// bytes a software key would have signed (the canonical intent, login proof, ...). So a
// hardware signature over an intent is: the intent, plus the authenticator's evidence that a
// person touched a key registered for this site and (with user verification) entered its PIN.
//
// The intent format is unchanged. A SignedIntent from a security key carries a `webauthn`
// block, and its `sig` is the authenticator's DER signature. Verification is shared by the
// server, the replicas and the browser's ledger audit.

import { decodeCbor, type Cbor } from "./cbor";

export interface WebAuthnProof {
  /** base64url of authenticatorData. */
  authenticatorData: string;
  /** base64url of the UTF-8 clientDataJSON. */
  clientDataJSON: string;
}

/** A signature from either kind of key. Software keys: P1363 sig, no webauthn block. */
export interface Proof {
  sig: string;
  webauthn?: WebAuthnProof;
}

export interface HardwareKeyInfo {
  kind?: "software" | "webauthn";
  /** WebAuthn relying party id (the site's domain) the credential is bound to. */
  rpId?: string;
  /** base64url credential id, for allowCredentials when asking the key to sign. */
  credentialId?: string;
  /** User verification (PIN / biometric) was required at registration and is required on every use. */
  uv?: boolean;
  attestation?: { fmt: string; aaguid: string; trusted: boolean; subject?: string };
}

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_AT = 0x40;

// ---------------------------------------------------------------------------
// encoding helpers (self-contained so identity.ts can import this module)

export function b64u(bytes: Uint8Array | ArrayBuffer): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(s: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(new ArrayBuffer(parts.reduce((n, p) => n + p.length, 0)));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

export const digest = async (bytes: Uint8Array, subtle: SubtleCrypto = globalThis.crypto.subtle) =>
  new Uint8Array(await subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>));

const equalBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** The challenge a security key must sign for this message. */
export async function challengeFor(message: Uint8Array, subtle: SubtleCrypto = globalThis.crypto.subtle) {
  return b64u(await digest(message, subtle));
}

/** ECDSA DER (SEQUENCE{INTEGER r, INTEGER s}) to the 64-byte r||s that WebCrypto verifies. */
export function derToP1363(der: Uint8Array): Uint8Array<ArrayBuffer> {
  let p = 0;
  const fail = () => {
    throw new Error("bad DER signature");
  };
  if (der[p++] !== 0x30) fail();
  let len = der[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n !== 1) fail();
    len = der[p++];
  }
  if (p + len !== der.length) fail();
  const int = () => {
    if (der[p++] !== 0x02) fail();
    const n = der[p++];
    if (n < 1 || n > 33 || p + n > der.length) fail();
    let v = der.subarray(p, p + n);
    p += n;
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) fail();
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = int();
  const s = int();
  if (p !== der.length) fail();
  return concat(r, s);
}

// ---------------------------------------------------------------------------
// authenticatorData

export interface AuthData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  credential?: { aaguid: Uint8Array; id: Uint8Array; publicKey: Map<Cbor, Cbor> };
}

export function parseAuthData(a: Uint8Array): AuthData {
  if (a.length < 37) throw new Error("authenticatorData too short");
  const flags = a[32];
  const signCount = ((a[33] << 24) >>> 0) + (a[34] << 16) + (a[35] << 8) + a[36];
  const out: AuthData = { rpIdHash: a.slice(0, 32), flags, signCount };
  if (flags & FLAG_AT) {
    if (a.length < 55) throw new Error("attested credential data truncated");
    const aaguid = a.slice(37, 53);
    const idLen = (a[53] << 8) + a[54];
    if (idLen > 1023 || a.length < 55 + idLen) throw new Error("credential id truncated");
    const id = a.slice(55, 55 + idLen);
    const { value } = decodeCbor(a.subarray(55 + idLen));
    if (!(value instanceof Map)) throw new Error("credential public key is not a COSE map");
    out.credential = { aaguid, id, publicKey: value };
  }
  return out;
}

/** COSE_Key (EC2, ES256, P-256) to a public JWK. Anything else is refused. */
export function coseToJwk(k: Map<Cbor, Cbor>): JsonWebKey {
  const x = k.get(-2);
  const y = k.get(-3);
  if (k.get(1) !== 2 || k.get(3) !== -7 || k.get(-1) !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32)
    throw new Error("only ES256 (ECDSA P-256) security keys are accepted");
  return { kty: "EC", crv: "P-256", x: b64u(x), y: b64u(y) };
}

export const formatAaguid = (g: Uint8Array) =>
  [...g].map((b) => b.toString(16).padStart(2, "0")).join("").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");

/** The origin's host must be the rpId or a subdomain of it (as browsers enforce). */
export function originMatchesRpId(origin: string, rpId: string): boolean {
  try {
    const u = new URL(origin);
    const secure = u.protocol === "https:" || u.hostname === "localhost";
    return secure && (u.hostname === rpId || u.hostname.endsWith(`.${rpId}`));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Verification of a signature over `message` by a registered key of either kind

export interface ProofKey extends HardwareKeyInfo {
  publicKeyJwk: JsonWebKey;
}

const SIGN_ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN_PARAMS = { name: "ECDSA", hash: "SHA-256" } as const;

async function ecdsaVerify(jwk: JsonWebKey, sig: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>, subtle: SubtleCrypto) {
  try {
    const key = await subtle.importKey("jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, SIGN_ALG, false, ["verify"]);
    return await subtle.verify(SIGN_PARAMS, key, sig, data);
  } catch {
    return false;
  }
}

export type ProofCheck = { ok: true; hardware: boolean; signCount?: number } | { ok: false; reason: string };

/**
 * Check `proof` is a valid signature by `key` over `message`. The key's kind decides the
 * method: a software signature is never accepted for a security key, nor the reverse.
 */
export async function checkProof(message: Uint8Array, proof: Proof, key: ProofKey, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<ProofCheck> {
  if (typeof proof?.sig !== "string") return { ok: false, reason: "no signature" };
  if (key.kind !== "webauthn") {
    if (proof.webauthn) return { ok: false, reason: "security-key evidence on a browser key" };
    let sig: Uint8Array<ArrayBuffer>;
    try {
      sig = unb64u(proof.sig);
    } catch {
      return { ok: false, reason: "signature does not verify" };
    }
    return (await ecdsaVerify(key.publicKeyJwk, sig, message as Uint8Array<ArrayBuffer>, subtle)) ? { ok: true, hardware: false } : { ok: false, reason: "signature does not verify" };
  }

  const w = proof.webauthn;
  if (!w || typeof w.authenticatorData !== "string" || typeof w.clientDataJSON !== "string") return { ok: false, reason: "security key required: no authenticator evidence" };
  if (!key.rpId) return { ok: false, reason: "security key has no relying party id" };
  let authData: Uint8Array<ArrayBuffer>, clientBytes: Uint8Array<ArrayBuffer>, sig: Uint8Array<ArrayBuffer>;
  let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try {
    authData = unb64u(w.authenticatorData);
    clientBytes = unb64u(w.clientDataJSON);
    client = JSON.parse(new TextDecoder().decode(clientBytes));
    sig = derToP1363(unb64u(proof.sig));
  } catch {
    return { ok: false, reason: "malformed security-key evidence" };
  }
  if (client.type !== "webauthn.get") return { ok: false, reason: "not a WebAuthn assertion" };
  if (client.challenge !== (await challengeFor(message, subtle))) return { ok: false, reason: "security key signed a different message" };
  if (typeof client.origin !== "string" || !originMatchesRpId(client.origin, key.rpId)) return { ok: false, reason: `signed on another site (${String(client.origin)})` };
  if (client.crossOrigin === true) return { ok: false, reason: "signed inside a cross-origin frame" };
  let ad: AuthData;
  try {
    ad = parseAuthData(authData);
  } catch {
    return { ok: false, reason: "malformed authenticator data" };
  }
  if (!equalBytes(ad.rpIdHash, await digest(new TextEncoder().encode(key.rpId), subtle))) return { ok: false, reason: "authenticator data is for another site" };
  if (!(ad.flags & FLAG_UP)) return { ok: false, reason: "no user presence (key was not touched)" };
  if (key.uv && !(ad.flags & FLAG_UV)) return { ok: false, reason: "no user verification (PIN) on a key that requires it" };
  const signed = concat(authData, await digest(clientBytes, subtle));
  if (!(await ecdsaVerify(key.publicKeyJwk, sig, signed, subtle))) return { ok: false, reason: "signature does not verify" };
  return { ok: true, hardware: true, signCount: ad.signCount };
}
