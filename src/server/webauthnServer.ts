// Security-key registration (WebAuthn attestation), server side.
//
// The browser asks the security key to create a P-256 credential for this site, with a
// challenge from us. We check what it returns:
//   - clientDataJSON: a create ceremony, our challenge, an origin on our relying party id
//   - authenticatorData: our rpId hash, user present, user verified (PIN), a credential
//   - the credential's public key: ES256 / P-256 only
//   - attestation: what the key says it is. "none" and self attestation are recorded as
//     untrusted. "packed" and "fido-u2f" certificates are checked to a configured root when
//     ODIN_ATTESTATION=require, so only keys from approved makers and models can enroll.
//
//   ODIN_RP_ID               relying party id (default: the host the browser used)
//   ODIN_ATTESTATION         none (default; record what the key says) | require
//   ODIN_ATTESTATION_ROOTS   comma-separated PEM files of trusted attestation roots
//   ODIN_AAGUIDS             optional comma-separated allow-list of authenticator models

import { createPublicKey, verify as nodeVerify, X509Certificate, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { decodeCbor } from "../core/cbor";
import { b64u, coseToJwk, digest, FLAG_AT, FLAG_UP, FLAG_UV, formatAaguid, originMatchesRpId, parseAuthData, unb64u, type HardwareKeyInfo } from "../core/webauthn";

export interface AttestationPolicy {
  mode: "none" | "require";
  roots: X509Certificate[];
  aaguids?: string[];
}

export function loadAttestationPolicy(env = process.env): AttestationPolicy {
  const mode = env.ODIN_ATTESTATION === "require" ? "require" : "none";
  const roots = (env.ODIN_ATTESTATION_ROOTS ?? "")
    .split(",")
    .map((f) => f.trim())
    .filter(Boolean)
    .flatMap((f) => splitPem(readFileSync(f, "utf8")).map((pem) => new X509Certificate(pem)));
  if (mode === "require" && !roots.length) throw new Error("ODIN_ATTESTATION=require needs ODIN_ATTESTATION_ROOTS");
  const aaguids = env.ODIN_AAGUIDS?.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  return { mode, roots, aaguids: aaguids?.length ? aaguids : undefined };
}

export const splitPem = (text: string) => text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];

export interface Registration extends HardwareKeyInfo {
  publicKeyJwk: JsonWebKey;
  signCount: number;
}

export class RegistrationError extends Error {}

const fail = (m: string): never => {
  throw new RegistrationError(m);
};

/** Verify a WebAuthn registration response against the challenge we issued. */
export async function verifyRegistration(
  response: { clientDataJSON?: unknown; attestationObject?: unknown },
  expected: { challenge: string; rpId: string },
  policy: AttestationPolicy,
  now = new Date(),
): Promise<Registration> {
  if (typeof response?.clientDataJSON !== "string" || typeof response.attestationObject !== "string") fail("security key response missing");
  const clientBytes = unb64u(response.clientDataJSON as string);
  let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try {
    client = JSON.parse(new TextDecoder().decode(clientBytes));
  } catch {
    return fail("clientDataJSON is not JSON");
  }
  if (client.type !== "webauthn.create") fail("not a registration");
  if (client.challenge !== expected.challenge) fail("registration answers a different challenge");
  if (typeof client.origin !== "string" || !originMatchesRpId(client.origin, expected.rpId)) fail(`registration made on another site (${String(client.origin)})`);
  if (client.crossOrigin === true) fail("registration inside a cross-origin frame");

  const readable = <T>(f: () => T): T => {
    try {
      return f();
    } catch (e) {
      return fail(e instanceof Error ? e.message : "unreadable security key response");
    }
  };
  const { value: att } = readable(() => decodeCbor(unb64u(response.attestationObject as string)));
  if (!(att instanceof Map)) return fail("attestation object is not a map");
  const fmt = att.get("fmt");
  const attStmt = att.get("attStmt");
  const authDataBytes = att.get("authData");
  if (typeof fmt !== "string" || !(attStmt instanceof Map) || !(authDataBytes instanceof Uint8Array)) return fail("attestation object incomplete");

  const ad = readable(() => parseAuthData(authDataBytes));
  const rpIdHash = await digest(new TextEncoder().encode(expected.rpId));
  if (Buffer.compare(Buffer.from(ad.rpIdHash), Buffer.from(rpIdHash)) !== 0) fail("security key registered for another site");
  if (!(ad.flags & FLAG_UP)) fail("key was not touched (no user presence)");
  if (!(ad.flags & FLAG_UV)) fail("the security key did not verify the user (set a PIN on the key)");
  if (!(ad.flags & FLAG_AT) || !ad.credential) return fail("no credential in the response");
  const credential = ad.credential;
  const publicKeyJwk = readable(() => coseToJwk(credential.publicKey));
  const aaguid = formatAaguid(ad.credential.aaguid);
  if (policy.aaguids && !policy.aaguids.includes(aaguid)) fail(`security key model ${aaguid} is not on the approved list`);

  const clientHash = await digest(clientBytes);
  const signedData = Buffer.concat([authDataBytes, clientHash]);
  const credKey = createPublicKey({ key: { ...publicKeyJwk, ext: true } as never, format: "jwk" });

  let trusted = false;
  let subject: string | undefined;
  if (fmt === "none") {
    if (attStmt.size) fail("attestation 'none' with a statement");
  } else if (fmt === "packed" || fmt === "fido-u2f") {
    const sig = attStmt.get("sig");
    const x5c = attStmt.get("x5c");
    if (!(sig instanceof Uint8Array)) return fail("attestation signature missing");
    if (fmt === "packed" && attStmt.get("alg") !== -7) fail("only ES256 attestation is accepted");
    const certs = Array.isArray(x5c) ? x5c.map((c) => (c instanceof Uint8Array ? new X509Certificate(Buffer.from(c)) : fail("bad attestation certificate"))) : [];
    if (fmt === "fido-u2f" && certs.length !== 1) fail("fido-u2f needs exactly one attestation certificate");
    let data = signedData;
    if (fmt === "fido-u2f") {
      const x = unb64u(publicKeyJwk.x!);
      const y = unb64u(publicKeyJwk.y!);
      data = Buffer.concat([Buffer.from([0]), ad.rpIdHash, clientHash, ad.credential.id, Buffer.from([4]), x, y]);
    }
    const signer: KeyObject = certs.length ? certs[0].publicKey : credKey; // packed without x5c: self attestation
    if (!nodeVerify("sha256", data, signer, sig)) fail("attestation signature does not verify");
    if (certs.length) {
      subject = certs[0].subject.replace(/\n/g, ", ");
      trusted = chainToRoot(certs, policy.roots, now);
      if (certs[0].ca) fail("attestation certificate must not be a CA");
    }
  } else if (policy.mode === "require") {
    fail(`attestation format ${fmt} is not supported`);
  }
  if (policy.mode === "require" && !trusted) fail("this security key's attestation does not chain to an approved root");

  return {
    kind: "webauthn",
    rpId: expected.rpId,
    credentialId: b64u(ad.credential.id),
    uv: true,
    publicKeyJwk,
    signCount: ad.signCount,
    attestation: { fmt, aaguid, trusted, subject },
  };
}

/** Each certificate issued and signed by the next; the last by a trusted root. All in date. */
export function chainToRoot(certs: X509Certificate[], roots: X509Certificate[], now = new Date()): boolean {
  const inDate = (c: X509Certificate) => Date.parse(c.validFrom) <= now.getTime() && now.getTime() <= Date.parse(c.validTo);
  for (let i = 0; i < certs.length; i++) {
    const c = certs[i];
    if (!inDate(c)) return false;
    const next = certs[i + 1];
    if (next) {
      if (!c.checkIssued(next) || !c.verify(next.publicKey)) return false;
      continue;
    }
    return roots.some((r) => inDate(r) && (r.fingerprint256 === c.fingerprint256 || (c.checkIssued(r) && c.verify(r.publicKey))));
  }
  return false;
}
