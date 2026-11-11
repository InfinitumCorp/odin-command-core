// TEST ONLY: a software FIDO2 authenticator that speaks the same bytes as a real security key
// (CBOR attestation objects, authenticator data, DER ECDSA assertions). Used by the tests to
// drive the real server-side checks end to end without hardware.

import { createHash, generateKeyPairSync, randomBytes, sign, X509Certificate, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { encodeCbor, type Cbor } from "../core/cbor";
import { b64u, challengeFor, FLAG_AT, FLAG_UP, FLAG_UV, unb64u, type WebAuthnProof } from "../core/webauthn";

export const PKI_DIR = join(import.meta.dirname, "__fixtures__", "pki");
export const pki = (name: string) => readFileSync(join(PKI_DIR, name), "utf8");

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest();
const u32 = (n: number) => Buffer.from([(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]);

export interface AuthenticatorOptions {
  /** Attestation the key returns at registration. */
  fmt?: "none" | "packed-self" | "packed" | "fido-u2f";
  /** For packed / fido-u2f: the attestation certificate and its key (PKI fixture names). */
  attestation?: { cert: string; key: string };
  aaguid?: string;
  /** Flags this key sets: real keys always set UP; UV only with a PIN. */
  up?: boolean;
  uv?: boolean;
  /** Fixed counter (a key that never counts), or undefined to count up. */
  fixedCounter?: number;
}

export class TestAuthenticator {
  readonly opts: AuthenticatorOptions;
  readonly credentialId = randomBytes(32);
  private priv: KeyObject;
  private pub: JsonWebKey;
  counter = 0;

  /** The credential public key, as the server registers it. */
  get publicKeyJwk(): JsonWebKey {
    return { kty: "EC", crv: "P-256", x: this.pub.x, y: this.pub.y };
  }

  constructor(opts: AuthenticatorOptions = {}) {
    this.opts = { fmt: "none", up: true, uv: true, ...opts };
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.priv = privateKey;
    this.pub = publicKey.export({ format: "jwk" });
  }

  private flags(extra = 0) {
    return (this.opts.up ? FLAG_UP : 0) | (this.opts.uv ? FLAG_UV : 0) | extra;
  }

  private nextCount() {
    if (this.opts.fixedCounter !== undefined) return this.opts.fixedCounter;
    return ++this.counter;
  }

  /** navigator.credentials.create(), as the browser would return it (base64url fields). */
  create(options: { challenge: string; rp: { id: string } }, origin: string, overrides: { type?: string; challenge?: string } = {}) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: overrides.type ?? "webauthn.create", challenge: overrides.challenge ?? options.challenge, origin, crossOrigin: false }));
    const x = unb64u(this.pub.x!);
    const y = unb64u(this.pub.y!);
    const cose = encodeCbor(new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
    const aaguid = Buffer.from((this.opts.aaguid ?? "00000000-0000-0000-0000-000000000000").replace(/-/g, ""), "hex");
    const authData = Buffer.concat([
      sha256(options.rp.id),
      Buffer.from([this.flags(FLAG_AT)]),
      u32(this.nextCount()),
      aaguid,
      Buffer.from([this.credentialId.length >> 8, this.credentialId.length & 255]),
      this.credentialId,
      cose,
    ]);
    const clientHash = sha256(clientDataJSON);
    const attStmt = new Map<Cbor, Cbor>();
    const fmt = this.opts.fmt === "packed-self" ? "packed" : this.opts.fmt!;
    if (this.opts.fmt === "packed-self") {
      attStmt.set("alg", -7);
      attStmt.set("sig", sign("sha256", Buffer.concat([authData, clientHash]), { key: this.priv, dsaEncoding: "der" }));
    } else if (this.opts.fmt === "packed" || this.opts.fmt === "fido-u2f") {
      const att = this.opts.attestation ?? { cert: "att-leaf.pem", key: "att-leaf.key" };
      const certDer = new X509Certificate(pki(att.cert)).raw;
      const data =
        this.opts.fmt === "packed"
          ? Buffer.concat([authData, clientHash])
          : Buffer.concat([Buffer.from([0]), sha256(options.rp.id), clientHash, this.credentialId, Buffer.from([4]), x, y]);
      if (this.opts.fmt === "packed") attStmt.set("alg", -7);
      attStmt.set("sig", sign("sha256", data, { key: pki(att.key), dsaEncoding: "der" }));
      attStmt.set("x5c", [new Uint8Array(certDer)]);
    }
    const attestationObject = encodeCbor(new Map<Cbor, Cbor>([["fmt", fmt], ["attStmt", attStmt], ["authData", new Uint8Array(authData)]]));
    return { rawId: b64u(this.credentialId), clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject) };
  }

  /** navigator.credentials.get() over an ODIN message (login proof or intent bytes). */
  async sign(message: Uint8Array, rpId: string, origin: string, tweak: { type?: string; challenge?: string; rpId?: string } = {}): Promise<{ sig: string; webauthn: WebAuthnProof }> {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: tweak.type ?? "webauthn.get", challenge: tweak.challenge ?? (await challengeFor(message)), origin, crossOrigin: false }));
    const authData = Buffer.concat([sha256(tweak.rpId ?? rpId), Buffer.from([this.flags()]), u32(this.nextCount())]);
    const sig = sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), { key: this.priv, dsaEncoding: "der" });
    return { sig: b64u(sig), webauthn: { authenticatorData: b64u(authData), clientDataJSON: b64u(clientDataJSON) } };
  }

  /** A clone made of this key's secret: same credential, its own counter. */
  clone(): TestAuthenticator {
    const c = Object.create(TestAuthenticator.prototype) as TestAuthenticator;
    Object.assign(c, this, { counter: 0 });
    return c;
  }
}
