// Operator authentication. Passwordless: an operator signs with either a non-extractable
// ECDSA P-256 key in their browser, or (Phase 7) a FIDO2 security key. The server only ever
// sees public keys.
//
//   POST /api/auth/webauthn/begin  {operatorId, code}            -> registration options for a security key
//   POST /api/auth/enroll     {operatorId, code, publicKeyJwk}     bind a browser key with a one-time code
//                             {operatorId, code, webauthn:{challenge, clientDataJSON, attestationObject}}
//                                                                  bind a security key
//   POST /api/auth/challenge  {operatorId}                         -> {nonce, keys} (2 min, single use)
//   POST /api/auth/login      {operatorId, keyId, nonce, sig, webauthn?}  -> session cookie + operator
//   GET  /api/auth/me                                              -> operator for this session
//   POST /api/auth/logout
//   GET  /api/auth/registry   (session) public keys and roles, for auditing ledger signatures
//
// Policy (environment):
//   ODIN_REQUIRE_HARDWARE  off (default) | commander | all: roles that must use a security key.
//                          Enforced at enrollment, sign-in and on every request.
//   ODIN_RP_ID, ODIN_ATTESTATION, ODIN_ATTESTATION_ROOTS, ODIN_AAGUIDS: see webauthnServer.ts
//   CAC/PIV: an operator bound to a TLS client certificate (`operator.ts bind-cert`) must present
//   it, verified by the server's ODIN_TLS_CLIENT_CA, on sign-in and on every console request.
//
// Sessions are opaque random tokens in an HttpOnly, SameSite=Strict cookie, held in memory
// (a server restart signs everyone out). POSTs must be application/json, which forces a CORS
// preflight for any cross-origin caller.

import { randomBytes, webcrypto } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { TLSSocket } from "node:tls";
import { isPublicP256Jwk, keyIdFor, loginBytes, type RegistryOperator } from "../core/identity";
import { checkProof, type WebAuthnProof } from "../core/webauthn";
import { DEFAULT_STORE_PATH, OperatorStore, StoreError, type OperatorKey, type OperatorRecord } from "./operatorStore";
import { readJson, send } from "./http";
import { loadAttestationPolicy, RegistrationError, verifyRegistration, type AttestationPolicy } from "./webauthnServer";

export const SESSION_COOKIE = "odin_session";
export const SESSION_HOURS = 8;
export const CHALLENGE_SECONDS = 120;
const MAX_CHALLENGES = 10_000;

const subtle = webcrypto.subtle as unknown as SubtleCrypto;
const token = () => randomBytes(32).toString("base64url");

export type HardwarePolicy = "off" | "commander" | "all";

export interface Session {
  operatorId: string;
  keyId: string;
  expires: number;
}

export interface Me {
  id: string;
  name: string;
  role: OperatorRecord["role"];
  keyId: string;
  /** Kind of key this session signs with. */
  keyKind: "software" | "webauthn";
}

/** The TLS client certificate on this connection, if any (CAC/PIV via mutual TLS). */
export interface PeerCert {
  fingerprint256: string;
  subject: string;
  authorized: boolean;
}

export interface RequestContext {
  /** Host the browser used (for the default relying party id). */
  host?: string;
  peer?: PeerCert;
}

export class AuthError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const str = (v: unknown, max = 256): v is string => typeof v === "string" && v.length > 0 && v.length <= max;
const normFp = (f: string) => f.toUpperCase().replace(/[^0-9A-F]/g, "");

export function peerCertOf(req: IncomingMessage): PeerCert | undefined {
  const sock = req.socket as TLSSocket;
  if (typeof sock.getPeerCertificate !== "function") return undefined;
  const c = sock.getPeerCertificate();
  if (!c || !c.fingerprint256) return undefined;
  const subject = c.subject ? Object.entries(c.subject).map(([k, v]) => `${k}=${v}`).join(", ") : "";
  return { fingerprint256: c.fingerprint256, subject, authorized: sock.authorized === true };
}

export const contextOf = (req: IncomingMessage): RequestContext => ({ host: req.headers.host, peer: peerCertOf(req) });

export interface AuthOptions {
  requireHardware?: HardwarePolicy;
  rpId?: string;
  attestation?: AttestationPolicy;
}

export class AuthService {
  readonly store: OperatorStore;
  readonly requireHardware: HardwarePolicy;
  private rpId?: string;
  private attestation: AttestationPolicy;
  private sessions = new Map<string, Session>();
  private challenges = new Map<string, { operatorId: string; expires: number }>();
  private registrations = new Map<string, { operatorId: string; rpId: string; expires: number }>();
  now: () => number = Date.now;

  constructor(store: OperatorStore, opts: AuthOptions = {}) {
    this.store = store;
    this.requireHardware = opts.requireHardware ?? "off";
    this.rpId = opts.rpId;
    this.attestation = opts.attestation ?? { mode: "none", roots: [] };
  }

  /** Must this role sign with a security key? */
  needsHardware(role: OperatorRecord["role"]) {
    return this.requireHardware === "all" || (this.requireHardware === "commander" && role === "commander");
  }

  /** An operator who may act now: exists, enabled, not locked out. */
  private usable(id: string): OperatorRecord | undefined {
    const o = this.store.get(id);
    return o && !o.disabled && !this.store.isLocked(o, this.now()) ? o : undefined;
  }

  private enrollFailed(o?: OperatorRecord): never {
    // Same answer for unknown, disabled, locked, wrong and expired, so the endpoint does not
    // reveal which operator ids exist.
    if (o) this.store.recordFailure(o.id);
    throw new AuthError(401, "enrollment failed: check the operator id and code, or ask for a new code");
  }

  private resolveRpId(ctx: RequestContext): string {
    const rp = this.rpId ?? ctx.host?.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
    if (!rp || !/^[a-z0-9.-]+$/i.test(rp)) throw new AuthError(400, "cannot determine the relying party id; set ODIN_RP_ID");
    return rp.toLowerCase();
  }

  /** Step 1 of security-key enrollment: check the code, issue a registration challenge. */
  webauthnBegin(body: unknown, ctx: RequestContext = {}) {
    const b = (body ?? {}) as Record<string, unknown>;
    if (!str(b.operatorId, 32) || !str(b.code, 64)) throw new AuthError(400, "operatorId and code are required");
    const o = this.usable(b.operatorId);
    if (!o || !this.store.codeMatches(o, b.code, this.now())) this.enrollFailed(o);
    const now = this.now();
    for (const [c, r] of this.registrations) if (r.expires <= now) this.registrations.delete(c);
    if (this.registrations.size >= MAX_CHALLENGES) throw new AuthError(429, "too many pending enrollments, try again shortly");
    const rpId = this.resolveRpId(ctx);
    const challenge = token();
    this.registrations.set(challenge, { operatorId: o.id, rpId, expires: now + CHALLENGE_SECONDS * 1000 });
    return {
      challenge,
      rp: { id: rpId, name: "ODIN° Command Core" },
      user: { id: Buffer.from(o.id).toString("base64url"), name: o.id, displayName: o.name },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      attestation: this.attestation.mode === "require" ? "direct" : "none",
      authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
      excludeCredentials: o.keys.filter((k) => k.kind === "webauthn" && k.credentialId && !k.revokedAt).map((k) => ({ type: "public-key", id: k.credentialId })),
      timeout: CHALLENGE_SECONDS * 1000,
    };
  }

  async enroll(body: unknown, _ctx: RequestContext = {}): Promise<{ keyId: string; kind: "software" | "webauthn" }> {
    const b = (body ?? {}) as Record<string, unknown>;
    if (!str(b.operatorId, 32) || !str(b.code, 64)) throw new AuthError(400, "operatorId and code are required");
    const o = this.usable(b.operatorId);
    if (!o || !this.store.codeMatches(o, b.code, this.now())) this.enrollFailed(o);

    let key: Omit<OperatorKey, "addedAt">;
    if (b.webauthn) {
      const w = b.webauthn as Record<string, unknown>;
      const reg = str(w.challenge, 64) ? this.registrations.get(w.challenge) : undefined;
      if (reg) this.registrations.delete(w.challenge as string);
      if (!reg || reg.operatorId !== o.id || reg.expires <= this.now()) throw new AuthError(400, "security-key enrollment expired; start again");
      try {
        const r = await verifyRegistration(w, { challenge: w.challenge as string, rpId: reg.rpId }, this.attestation, new Date(this.now()));
        key = { keyId: await keyIdFor(r.publicKeyJwk, subtle), ...r };
      } catch (e) {
        if (e instanceof RegistrationError) throw new AuthError(400, `security key refused: ${e.message}`);
        throw new AuthError(400, "security key response could not be read");
      }
    } else {
      if (!isPublicP256Jwk(b.publicKeyJwk)) throw new AuthError(400, "a public P-256 key or a security-key response is required");
      if (this.needsHardware(o.role)) throw new AuthError(403, `operators with role ${o.role} must enroll a FIDO2 security key`);
      const jwk = b.publicKeyJwk as JsonWebKey;
      const publicKeyJwk = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
      key = { keyId: await keyIdFor(publicKeyJwk, subtle), publicKeyJwk, kind: "software" };
    }
    try {
      this.store.bindKey(o.id, key);
    } catch (e) {
      throw e instanceof StoreError ? new AuthError(409, e.message) : e;
    }
    return { keyId: key.keyId, kind: key.kind === "webauthn" ? "webauthn" : "software" };
  }

  /**
   * Issued for any id so the endpoint does not reveal which operators exist. For an operator
   * with security keys it also lists their credential ids, so the browser can ask for the
   * right key. (Unknown ids get an empty list, the same as an operator with only browser keys.)
   */
  challenge(body: unknown): { nonce: string; expiresIn: number; credentials: Array<{ keyId: string; credentialId: string; rpId: string }> } {
    const b = (body ?? {}) as Record<string, unknown>;
    if (!str(b.operatorId, 32)) throw new AuthError(400, "operatorId required");
    const now = this.now();
    for (const [n, c] of this.challenges) if (c.expires <= now) this.challenges.delete(n);
    if (this.challenges.size >= MAX_CHALLENGES) throw new AuthError(429, "too many pending sign-ins, try again shortly");
    const nonce = token();
    this.challenges.set(nonce, { operatorId: b.operatorId, expires: now + CHALLENGE_SECONDS * 1000 });
    const o = this.store.get(b.operatorId);
    const credentials = (o?.keys ?? [])
      .filter((k) => k.kind === "webauthn" && !k.revokedAt && k.credentialId && k.rpId)
      .map((k) => ({ keyId: k.keyId, credentialId: k.credentialId!, rpId: k.rpId! }));
    return { nonce, expiresIn: CHALLENGE_SECONDS, credentials };
  }

  /** CAC/PIV: an operator bound to a client certificate must be on a connection that presents it. */
  private certOk(o: OperatorRecord, ctx: RequestContext) {
    if (!o.clientCert) return true;
    const p = ctx.peer;
    return !!p && p.authorized && normFp(p.fingerprint256) === normFp(o.clientCert.fingerprint256);
  }

  async login(body: unknown, ctx: RequestContext = {}): Promise<{ token: string; me: Me }> {
    const b = (body ?? {}) as Record<string, unknown>;
    if (!str(b.operatorId, 32) || !str(b.keyId, 64) || !str(b.nonce, 64) || !str(b.sig, 200)) throw new AuthError(400, "operatorId, keyId, nonce and sig required");
    const fail = new AuthError(401, "sign-in failed");
    const ch = this.challenges.get(b.nonce);
    this.challenges.delete(b.nonce); // single use, even when the attempt fails
    if (!ch || ch.operatorId !== b.operatorId || ch.expires <= this.now()) throw fail;
    const o = this.usable(b.operatorId);
    if (!o) throw fail;
    const key = o.keys.find((k) => k.keyId === b.keyId && !k.revokedAt);
    const proof = { v: 1 as const, purpose: "odin-login" as const, operatorId: o.id, keyId: b.keyId, nonce: b.nonce };
    const check = key ? await checkProof(loginBytes(proof), { sig: b.sig, webauthn: b.webauthn as WebAuthnProof | undefined }, key, subtle) : undefined;
    if (!key || !check?.ok) {
      this.store.recordFailure(o.id);
      throw fail;
    }
    if (this.needsHardware(o.role) && key.kind !== "webauthn") throw new AuthError(403, `role ${o.role} must sign in with a FIDO2 security key`);
    if (!this.certOk(o, ctx)) throw new AuthError(403, "this operator must present their CAC/PIV certificate");
    if (check.hardware && check.signCount !== undefined) {
      try {
        this.store.advanceSignCount(o.id, key.keyId, check.signCount);
      } catch (e) {
        throw new AuthError(403, e instanceof Error ? e.message : "security key refused");
      }
    }
    this.store.recordSuccess(o.id);
    const t = token();
    this.sessions.set(t, { operatorId: o.id, keyId: key.keyId, expires: this.now() + SESSION_HOURS * 3600_000 });
    return { token: t, me: this.meOf(o, key) };
  }

  private meOf(o: OperatorRecord, key: OperatorKey): Me {
    return { id: o.id, name: o.name, role: o.role, keyId: key.keyId, keyKind: key.kind === "webauthn" ? "webauthn" : "software" };
  }

  /**
   * The operator behind a session token, re-read from the registry so role changes, disabling,
   * key revocation and the hardware policy apply at once. With a request context, a
   * certificate-bound operator must be on a connection presenting that certificate.
   */
  me(t: string | undefined, ctx?: RequestContext): Me | undefined {
    if (!t) return undefined;
    const s = this.sessions.get(t);
    if (!s) return undefined;
    const o = s.expires > this.now() ? this.store.get(s.operatorId) : undefined;
    const key = o?.keys.find((k) => k.keyId === s.keyId && !k.revokedAt);
    if (!o || o.disabled || !key || (this.needsHardware(o.role) && key.kind !== "webauthn")) {
      this.sessions.delete(t);
      return undefined;
    }
    if (ctx && !this.certOk(o, ctx)) return undefined;
    return this.meOf(o, key);
  }

  /** Security-key counter from a signed command (throws on a counter that went backwards). */
  advanceSignCount(operatorId: string, keyId: string, count: number) {
    this.store.advanceSignCount(operatorId, keyId, count);
  }

  logout(t: string | undefined) {
    if (t) this.sessions.delete(t);
  }

  /** Public registry for signature audits: ids, roles, public keys and key kinds. No enrollment hashes or counters. */
  registry(): RegistryOperator[] {
    return this.store.list().map((o) => ({
      id: o.id,
      name: o.name,
      role: o.role,
      disabled: o.disabled,
      keys: o.keys.map(({ signCount: _c, ...k }) => k),
    }));
  }
}

export function cookieToken(req: IncomingMessage): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === SESSION_COOKIE) return v.join("=");
  }
  return undefined;
}

const isHttps = (req: IncomingMessage) => !!(req.socket as { encrypted?: boolean }).encrypted;

function sessionCookie(req: IncomingMessage, value: string, maxAge: number) {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${isHttps(req) ? "; Secure" : ""}`;
}

/** Request handler for the routes above. `req.url` is relative to /api/auth. */
export function authRoutes(auth: AuthService) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const path = (req.url ?? "/").split("?")[0];
    const ctx = contextOf(req);
    try {
      if (req.method === "POST" && !(req.headers["content-type"] ?? "").startsWith("application/json")) throw new AuthError(415, "application/json required");
      if (req.method === "POST" && path === "/webauthn/begin") return send(res, 200, auth.webauthnBegin(await readJson(req, 1024), ctx));
      if (req.method === "POST" && path === "/enroll") return send(res, 200, await auth.enroll(await readJson(req, 16384), ctx));
      if (req.method === "POST" && path === "/challenge") return send(res, 200, auth.challenge(await readJson(req, 1024)));
      if (req.method === "POST" && path === "/login") {
        const { token: t, me } = await auth.login(await readJson(req, 4096), ctx);
        res.setHeader("set-cookie", sessionCookie(req, t, SESSION_HOURS * 3600));
        return send(res, 200, me);
      }
      if (req.method === "POST" && path === "/logout") {
        auth.logout(cookieToken(req));
        res.setHeader("set-cookie", sessionCookie(req, "", 0));
        return send(res, 200, { ok: true });
      }
      if (req.method === "GET" && path === "/me") {
        const me = auth.me(cookieToken(req), ctx);
        return me ? send(res, 200, me) : send(res, 401, { error: "not signed in" });
      }
      if (req.method === "GET" && path === "/registry") {
        if (!auth.me(cookieToken(req), ctx)) return send(res, 401, { error: "not signed in" });
        return send(res, 200, auth.registry());
      }
      if (req.method === "GET" && path === "/policy") return send(res, 200, { requireHardware: auth.requireHardware });
      send(res, 404, { error: "no such auth route" });
    } catch (e) {
      if (e instanceof AuthError) return send(res, e.status, { error: e.message });
      if (e instanceof SyntaxError || (e instanceof Error && e.message === "body too large")) return send(res, 400, { error: "invalid request body" });
      console.error("[auth]", e);
      send(res, 500, { error: "internal error" });
    }
  };
}

export function createAuth(path = process.env.ODIN_OPERATOR_STORE ?? DEFAULT_STORE_PATH) {
  const policy = process.env.ODIN_REQUIRE_HARDWARE;
  return new AuthService(new OperatorStore(path), {
    requireHardware: policy === "commander" || policy === "all" ? policy : "off",
    rpId: process.env.ODIN_RP_ID,
    attestation: loadAttestationPolicy(),
  });
}
