// Operator signatures. Every human action on the ledger carries an ECDSA P-256 / SHA-256
// signature (FIPS 186-5 approved) over a canonical "intent": who acted, with which key,
// what they did, and the ledger head they saw when they did it.
//
// The hash chain alone proves the record was not edited after the fact, but anyone who
// holds the chain can rebuild it. Signatures prove *who* authorised each step: a rebuilt
// chain cannot carry a valid approval without the commander's private key.
//
// Runs in the browser and in Node (WebCrypto in both).
//
// Since Phase 7 an operator key is either a browser key (non-extractable WebCrypto key) or a
// FIDO2 security key (see webauthn.ts). Both sign the same canonical intent; the registry
// records which kind each key is, and verification follows the registry, never the proof.

import { GENESIS, canonical } from "./ledger";
import { checkProof, type HardwareKeyInfo, type WebAuthnProof } from "./webauthn";
import type { LedgerEntry, Role } from "./types";

export type SignedAction =
  | "coa.approved"
  | "decision.rejected"
  | "coa.redrafted"
  | "simulation.toggled"
  | "operator.signed-in"
  | "clock.set"
  | "scenario.closed";

export interface Intent {
  v: 1;
  operatorId: string;
  keyId: string;
  action: SignedAction;
  /** What the action applies to, e.g. { decision, coa } or { enabled }. */
  subject: Record<string, string | number | boolean>;
  /** Hash of the last ledger entry the operator saw when signing (binds the signature to history). */
  head: string;
  signedAt: string; // ISO-8601
}

export interface SignedIntent {
  intent: Intent;
  /** Browser key: base64url P1363 (r||s). Security key: base64url DER, as the authenticator returned it. */
  sig: string;
  /** Present for security-key signatures: the authenticator's evidence (see webauthn.ts). */
  webauthn?: WebAuthnProof;
}

export const SIGN_ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
export const SIGN_PARAMS = { name: "ECDSA", hash: "SHA-256" } as const;

export const intentBytes = (i: Intent) => new TextEncoder().encode(canonical(i));

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** A public key as the server registers it: EC P-256, public part only. */
export function isPublicP256Jwk(j: unknown): j is JsonWebKey {
  if (!j || typeof j !== "object") return false;
  const k = j as Record<string, unknown>;
  return k.kty === "EC" && k.crv === "P-256" && typeof k.x === "string" && typeof k.y === "string" && k.d === undefined;
}

/** Stable key identifier: first 16 bytes of SHA-256 over the canonical public JWK (RFC 7638 members). */
export async function keyIdFor(jwk: JsonWebKey, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<string> {
  const thumb = canonical({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(thumb));
  return b64url(new Uint8Array(digest).slice(0, 16));
}

export async function signIntent(intent: Intent, privateKey: CryptoKey, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<SignedIntent> {
  const sig = await subtle.sign(SIGN_PARAMS, privateKey, intentBytes(intent));
  return { intent, sig: b64url(sig) };
}

export async function verifyBytes(bytes: Uint8Array<ArrayBuffer>, sig: string, jwk: JsonWebKey, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<boolean> {
  try {
    const key = await subtle.importKey("jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, SIGN_ALG, false, ["verify"]);
    return await subtle.verify(SIGN_PARAMS, key, fromB64url(sig), bytes);
  } catch {
    return false;
  }
}

/** Verify a signed intent against a registered key, of whichever kind the registry says it is. */
export async function verifyIntent(si: SignedIntent, key: RegistryKey, subtle: SubtleCrypto = globalThis.crypto.subtle) {
  return checkProof(intentBytes(si.intent), { sig: si.sig, webauthn: si.webauthn }, key, subtle);
}

/** Browser-key check only (kept for callers that hold a bare JWK). */
export const verifySignature = (si: SignedIntent, jwk: JsonWebKey, subtle: SubtleCrypto = globalThis.crypto.subtle) =>
  !si.webauthn && verifyBytes(intentBytes(si.intent), si.sig, jwk, subtle);

/** What an operator signs to sign in: a server nonce, bound to their id and key. */
export interface LoginProof {
  v: 1;
  purpose: "odin-login";
  operatorId: string;
  keyId: string;
  nonce: string;
}

export const loginBytes = (p: LoginProof) => new TextEncoder().encode(canonical(p));

export async function signLogin(p: LoginProof, privateKey: CryptoKey, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<string> {
  return b64url(await subtle.sign(SIGN_PARAMS, privateKey, loginBytes(p)));
}

// ---------------------------------------------------------------------------
// Ledger audit

export interface RegistryKey extends HardwareKeyInfo {
  keyId: string;
  publicKeyJwk: JsonWebKey;
  addedAt: string;
  revokedAt?: string;
}

export interface RegistryOperator {
  id: string;
  name: string;
  role: Role;
  disabled: boolean;
  keys: RegistryKey[];
}

/**
 * For each human ledger action: which signed action it must carry, who the signer must be,
 * which subject fields must match the entry, and the role required (null: any operator).
 */
interface Rule {
  signed: SignedAction;
  signer: (e: LedgerEntry) => unknown;
  subject: (e: LedgerEntry) => Record<string, unknown>;
  role: Role | null;
}

const RULES: Record<string, Rule> = {
  "coa.approved": { signed: "coa.approved", signer: (e) => e.actor, subject: (e) => ({ decision: e.payload.decision, coa: e.payload.coa }), role: "commander" },
  "approval.denied": { signed: "coa.approved", signer: (e) => e.actor, subject: (e) => ({ decision: e.payload.decision, coa: e.payload.coa }), role: null },
  "decision.rejected": { signed: "decision.rejected", signer: (e) => e.actor, subject: (e) => ({ decision: e.payload.decision }), role: "commander" },
  "rejection.denied": { signed: "decision.rejected", signer: (e) => e.actor, subject: (e) => ({ decision: e.payload.decision }), role: null },
  "coa.redrafted": { signed: "coa.redrafted", signer: (e) => e.payload.requestedBy, subject: (e) => ({ decision: e.payload.decision }), role: null },
  "simulation.toggled": { signed: "simulation.toggled", signer: (e) => e.actor, subject: (e) => ({ enabled: e.payload.enabled }), role: "commander" },
  "operator.signed-in": { signed: "operator.signed-in", signer: (e) => e.actor, subject: () => ({}), role: null },
  "clock.set": { signed: "clock.set", signer: (e) => e.actor, subject: (e) => ({ running: e.payload.running, speed: e.payload.speed }), role: "commander" },
  "scenario.closed": { signed: "scenario.closed", signer: (e) => e.actor, subject: (e) => ({ seed: e.payload.seed }), role: "commander" },
};

export const HUMAN_ACTIONS = Object.keys(RULES);

export interface AuditProblem {
  seq: number;
  reason: string;
}

export interface AuditResult {
  signed: number;
  /** Of those, signed with a FIDO2 security key. */
  hardware: number;
  problems: AuditProblem[];
}

/** The synchronous half of the checks: shape, signer, subject and head. Used by the core too. */
export function intentMatchesEntry(e: LedgerEntry, auth: SignedIntent | undefined, priorHashes: ReadonlySet<string>): string | undefined {
  const rule = RULES[e.action];
  if (!rule) return undefined;
  if (!auth || typeof auth !== "object" || !auth.intent || typeof auth.sig !== "string") return "unsigned human action";
  const i = auth.intent;
  if (i.v !== 1) return "unknown intent version";
  if (i.action !== rule.signed) return `signature is for ${i.action}, entry is ${e.action}`;
  if (i.operatorId !== rule.signer(e)) return `signed by ${i.operatorId}, recorded as ${String(rule.signer(e))}`;
  const want = rule.subject(e);
  for (const [k, v] of Object.entries(want)) if (i.subject?.[k] !== v) return `signed ${k} ${String(i.subject?.[k])} does not match ${String(v)}`;
  if (!priorHashes.has(i.head)) return "signed ledger head is not an earlier entry";
  if (Number.isNaN(Date.parse(i.signedAt))) return "bad signing time";
  return undefined;
}

/**
 * Verify every human action on the ledger against the operator registry: present, signed by
 * the recorded actor with a registered, unrevoked key, cryptographically valid, bound to an
 * earlier ledger head, and made by an operator holding the required role.
 */
export async function auditSignatures(ledger: LedgerEntry[], registry: RegistryOperator[], subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<AuditResult> {
  const problems: AuditProblem[] = [];
  const prior = new Set<string>([GENESIS]);
  const byId = new Map(registry.map((o) => [o.id, o]));
  let signed = 0;
  let hardware = 0;

  for (const e of ledger) {
    const rule = RULES[e.action];
    if (rule) {
      const auth = e.payload.auth as SignedIntent | undefined;
      const mismatch = intentMatchesEntry(e, auth, prior);
      if (mismatch) problems.push({ seq: e.seq, reason: mismatch });
      else {
        const op = byId.get(auth!.intent.operatorId);
        const key = op?.keys.find((k) => k.keyId === auth!.intent.keyId);
        if (!op) problems.push({ seq: e.seq, reason: `unknown operator ${auth!.intent.operatorId}` });
        else if (!key) problems.push({ seq: e.seq, reason: "key not registered to this operator" });
        else if (key.revokedAt && Date.parse(key.revokedAt) <= Date.parse(auth!.intent.signedAt)) problems.push({ seq: e.seq, reason: "key was revoked before signing" });
        else if (rule.role && op.role !== rule.role) problems.push({ seq: e.seq, reason: `${op.id} is ${op.role}, action needs ${rule.role}` });
        else {
          const check = await verifyIntent(auth!, key, subtle);
          if (!check.ok) problems.push({ seq: e.seq, reason: check.reason });
          else {
            signed++;
            if (check.hardware) hardware++;
          }
        }
      }
    }
    prior.add(e.hash);
  }
  return { signed, hardware, problems };
}
