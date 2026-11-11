// Browser side of operator identity: enroll this device or a security key, sign in, sign commands.

import { GENESIS } from "../../core/ledger";
import { intentBytes, keyIdFor, loginBytes, SIGN_PARAMS, type Intent, type RegistryOperator, type SignedAction, type SignedIntent } from "../../core/identity";
import { b64u, challengeFor, unb64u, type WebAuthnProof } from "../../core/webauthn";
import type { State } from "../../core/types";
import { generateKeyPair, loadKey, saveKey, type StoredKey } from "./keystore";

export interface Me {
  id: string;
  name: string;
  role: "commander" | "analyst";
  keyId: string;
  keyKind: "software" | "webauthn";
}

/** Something that can sign ODIN messages: a browser key or a security key. */
export interface Signer {
  kind: "software" | "webauthn";
  keyId: string;
  sign(message: Uint8Array): Promise<{ sig: string; webauthn?: WebAuthnProof }>;
}

async function call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api/auth/${path}`, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return json as T;
}

export const securityKeysSupported = () => typeof PublicKeyCredential !== "undefined" && !!navigator.credentials?.create;

function describeWebAuthnError(e: unknown): Error {
  const name = e instanceof DOMException ? e.name : "";
  if (name === "NotAllowedError") return new Error("the security key request was cancelled or timed out");
  if (name === "InvalidStateError") return new Error("this security key is already registered for this operator");
  if (name === "SecurityError") return new Error("security keys need HTTPS (or localhost) and a matching site name");
  if (name === "NotSupportedError") return new Error("this security key does not support ES256 with a PIN");
  return e instanceof Error ? e : new Error(String(e));
}

export function signerFor(stored: StoredKey): Signer {
  if (stored.kind === "webauthn") {
    return {
      kind: "webauthn",
      keyId: stored.keyId,
      async sign(message) {
        let cred: PublicKeyCredential | null;
        try {
          cred = (await navigator.credentials.get({
            publicKey: {
              challenge: unb64u(await challengeFor(message)),
              rpId: stored.rpId,
              allowCredentials: [{ type: "public-key", id: unb64u(stored.credentialId) }],
              userVerification: "required",
              timeout: 60_000,
            },
          })) as PublicKeyCredential | null;
        } catch (e) {
          throw describeWebAuthnError(e);
        }
        if (!cred) throw new Error("no security key response");
        const r = cred.response as AuthenticatorAssertionResponse;
        return { sig: b64u(r.signature), webauthn: { authenticatorData: b64u(r.authenticatorData), clientDataJSON: b64u(r.clientDataJSON) } };
      },
    };
  }
  return {
    kind: "software",
    keyId: stored.keyId,
    sign: async (message) => ({ sig: b64u(await crypto.subtle.sign(SIGN_PARAMS, stored.keyPair.privateKey, message as Uint8Array<ArrayBuffer>)) }),
  };
}

/** Generate a key in this browser and bind it to the operator with their one-time code. */
export async function enroll(operatorId: string, code: string): Promise<void> {
  const { keyPair, publicKeyJwk } = await generateKeyPair();
  const { keyId } = await call<{ keyId: string }>("POST", "enroll", { operatorId, code, publicKeyJwk });
  if (keyId !== (await keyIdFor(publicKeyJwk))) throw new Error("server registered a different key");
  await saveKey({ kind: "software", operatorId, keyId, publicKeyJwk, keyPair });
}

interface RegistrationOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
  attestation: AttestationConveyancePreference;
  authenticatorSelection: AuthenticatorSelectionCriteria;
  excludeCredentials: Array<{ type: "public-key"; id: string }>;
  timeout: number;
}

/** Register a FIDO2 security key (touch + PIN) for the operator with their one-time code. */
export async function enrollSecurityKey(operatorId: string, code: string): Promise<void> {
  if (!securityKeysSupported()) throw new Error("this browser does not support security keys");
  const o = await call<RegistrationOptions>("POST", "webauthn/begin", { operatorId, code });
  let cred: PublicKeyCredential | null;
  try {
    cred = (await navigator.credentials.create({
      publicKey: {
        challenge: unb64u(o.challenge),
        rp: o.rp,
        user: { ...o.user, id: unb64u(o.user.id) },
        pubKeyCredParams: o.pubKeyCredParams,
        attestation: o.attestation,
        authenticatorSelection: o.authenticatorSelection,
        excludeCredentials: o.excludeCredentials.map((c) => ({ type: c.type, id: unb64u(c.id) })),
        timeout: o.timeout,
      },
    })) as PublicKeyCredential | null;
  } catch (e) {
    throw describeWebAuthnError(e);
  }
  if (!cred) throw new Error("no security key response");
  const r = cred.response as AuthenticatorAttestationResponse;
  const { keyId } = await call<{ keyId: string }>("POST", "enroll", {
    operatorId,
    code,
    webauthn: { challenge: o.challenge, clientDataJSON: b64u(r.clientDataJSON), attestationObject: b64u(r.attestationObject) },
  });
  // Cross-check the key the server registered, where the browser exposes it.
  let publicKeyJwk: JsonWebKey = {};
  const spki = r.getPublicKey?.();
  if (spki) {
    const k = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", k);
    publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    if ((await keyIdFor(publicKeyJwk)) !== keyId) throw new Error("server registered a different key");
  }
  await saveKey({ kind: "webauthn", operatorId, keyId, publicKeyJwk, credentialId: b64u(cred.rawId), rpId: o.rp.id });
}

export async function signIn(operatorId: string): Promise<{ me: Me; signer: Signer }> {
  const stored = await loadKey(operatorId);
  if (!stored) throw new Error(`this device is not enrolled for ${operatorId}`);
  const signer = signerFor(stored);
  const { nonce } = await call<{ nonce: string }>("POST", "challenge", { operatorId });
  const proof = await signer.sign(loginBytes({ v: 1, purpose: "odin-login", operatorId, keyId: stored.keyId, nonce }));
  const me = await call<Me>("POST", "login", { operatorId, keyId: stored.keyId, nonce, ...proof });
  return { me, signer };
}

/** Resume a session after a reload: the cookie must still be valid and the key still on this device. */
export async function resume(): Promise<{ me: Me; signer: Signer } | undefined> {
  const me = await call<Me>("GET", "me").catch(() => undefined);
  if (!me) return undefined;
  const stored = await loadKey(me.id);
  return stored && stored.keyId === me.keyId ? { me, signer: signerFor(stored) } : undefined;
}

export const signOut = () => call("POST", "logout", {}).catch(() => undefined);
export const fetchRegistry = () => call<RegistryOperator[]>("GET", "registry");
export const fetchPolicy = () => call<{ requireHardware: "off" | "commander" | "all" }>("GET", "policy");

/** Sign an action against the ledger head the operator is looking at. */
export async function signAction(me: Me, signer: Signer, state: State, action: SignedAction, subject: Record<string, string | number | boolean>): Promise<SignedIntent> {
  const intent: Intent = { v: 1, operatorId: me.id, keyId: me.keyId, action, subject, head: state.ledger.at(-1)?.hash ?? GENESIS, signedAt: new Date().toISOString() };
  const proof = await signer.sign(intentBytes(intent));
  return { intent, ...proof };
}
