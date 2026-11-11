// Operator registry: who may use ODIN°, in which role, and which public keys they sign with.
// Stored as JSON (mode 0600) at .odin/operators.json. It holds no private keys and no
// plaintext enrollment codes, only scrypt hashes of one-time codes.
//
// Self-contained (Node built-ins only) so the admin CLI can run it with plain `node`.

import { randomBytes, randomInt, scryptSync, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export type Role = "commander" | "analyst";
export const ROLES: Role[] = ["commander", "analyst"];

export interface OperatorKey {
  keyId: string;
  publicKeyJwk: JsonWebKey;
  addedAt: string;
  revokedAt?: string;
  /** "webauthn": a FIDO2 security key (Phase 7). Absent or "software": a browser key. */
  kind?: "software" | "webauthn";
  rpId?: string;
  credentialId?: string;
  uv?: boolean;
  attestation?: { fmt: string; aaguid: string; trusted: boolean; subject?: string };
  /** Last signature counter seen from a security key (clone detection). */
  signCount?: number;
}

/** A CAC/PIV (or other) TLS client certificate the operator must present when signing in. */
export interface CertBinding {
  fingerprint256: string;
  subject: string;
  boundAt: string;
}

export interface Enrollment {
  salt: string; // hex
  hash: string; // hex scrypt(code, salt)
  expiresAt: string;
}

export interface OperatorRecord {
  id: string;
  name: string;
  role: Role;
  disabled: boolean;
  createdAt: string;
  enrollment?: Enrollment;
  keys: OperatorKey[];
  clientCert?: CertBinding;
  failures: number;
  lockedUntil?: string;
}

interface StoreFile {
  version: 1;
  operators: OperatorRecord[];
}

export const DEFAULT_STORE_PATH = ".odin/operators.json";
export const ENROLLMENT_TTL_HOURS = 24;
export const MAX_FAILURES = 5;
export const LOCKOUT_MINUTES = 15;

const ID_RE = /^[A-Z][A-Z0-9-]{1,31}$/;
// Crockford base32: no I, L, O, U, so codes survive being read aloud or retyped.
const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export class StoreError extends Error {}

/** 25 base32 characters (125 bits) in five groups, e.g. 7K3QF-...; shown once, never stored. */
export function newEnrollmentCode(): string {
  const chars = Array.from({ length: 25 }, () => CODE_ALPHABET[randomInt(CODE_ALPHABET.length)]);
  return chars.join("").match(/.{5}/g)!.join("-");
}

const normaliseCode = (c: string) => c.toUpperCase().replace(/[^0-9A-Z]/g, "");

function hashCode(code: string, salt: Buffer): Buffer {
  return scryptSync(normaliseCode(code), salt, 32, { N: 16384, r: 8, p: 1 });
}

export class OperatorStore {
  readonly path: string;

  constructor(path: string = DEFAULT_STORE_PATH) {
    this.path = path;
  }

  load(): StoreFile {
    if (!existsSync(this.path)) return { version: 1, operators: [] };
    const f = JSON.parse(readFileSync(this.path, "utf8")) as StoreFile;
    if (f.version !== 1 || !Array.isArray(f.operators)) throw new StoreError(`unrecognised operator store at ${this.path}`);
    return f;
  }

  /** Atomic replace so a crash never leaves a half-written registry. */
  save(f: StoreFile) {
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(f, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  /**
   * Phase 8: a node elected leader takes the registry the cluster agreed on (the one it pinned
   * while following) as authoritative: operators, roles, disabled flags and keys come from it;
   * local-only state (failure counts, lockouts, certificate bindings, pending enrollments) is
   * kept for operators that remain. Operators missing from the pinned registry are disabled.
   * Returns what changed, for the log.
   */
  adoptRegistry(pinned: Array<Pick<OperatorRecord, "id" | "name" | "role" | "disabled" | "keys">>): { added: number; updated: number; disabled: number } {
    const f = this.load();
    const now = new Date().toISOString();
    const out = { added: 0, updated: 0, disabled: 0 };
    const byId = new Map(f.operators.map((o) => [o.id, o]));
    for (const p of pinned) {
      const o = byId.get(p.id);
      if (!o) {
        f.operators.push({ id: p.id, name: p.name, role: p.role, disabled: p.disabled, createdAt: now, keys: p.keys, failures: 0 });
        out.added++;
        continue;
      }
      // Never lower a security key's signature counter: that would weaken clone detection.
      const keys = p.keys.map((k) => {
        const mine = o.keys.find((x) => x.keyId === k.keyId)?.signCount;
        return mine !== undefined && mine > (k.signCount ?? 0) ? { ...k, signCount: mine } : k;
      });
      if (JSON.stringify([o.name, o.role, o.disabled, o.keys]) !== JSON.stringify([p.name, p.role, p.disabled, keys])) out.updated++;
      Object.assign(o, { name: p.name, role: p.role, disabled: p.disabled, keys });
    }
    const ids = new Set(pinned.map((p) => p.id));
    for (const o of f.operators)
      if (!ids.has(o.id) && !o.disabled) {
        o.disabled = true;
        out.disabled++;
      }
    this.save(f);
    return out;
  }

  list(): OperatorRecord[] {
    return this.load().operators;
  }

  get(id: string): OperatorRecord | undefined {
    return this.load().operators.find((o) => o.id === id);
  }

  private update<T>(id: string, fn: (o: OperatorRecord) => T): T {
    const f = this.load();
    const o = f.operators.find((x) => x.id === id);
    if (!o) throw new StoreError(`no operator ${id}`);
    const out = fn(o);
    this.save(f);
    return out;
  }

  private issueCode(o: OperatorRecord): string {
    const code = newEnrollmentCode();
    const salt = randomBytes(16);
    o.enrollment = {
      salt: salt.toString("hex"),
      hash: hashCode(code, salt).toString("hex"),
      expiresAt: new Date(Date.now() + ENROLLMENT_TTL_HOURS * 3600_000).toISOString(),
    };
    o.failures = 0;
    o.lockedUntil = undefined;
    return code;
  }

  /** Create an operator and return their one-time enrollment code. */
  add(id: string, role: Role, name = id): string {
    if (!ID_RE.test(id)) throw new StoreError("operator id: 2-32 chars, A-Z, 0-9 and '-', starting with a letter");
    if (!ROLES.includes(role)) throw new StoreError(`role must be one of ${ROLES.join(", ")}`);
    const f = this.load();
    if (f.operators.some((o) => o.id === id)) throw new StoreError(`operator ${id} already exists`);
    const o: OperatorRecord = { id, name, role, disabled: false, createdAt: new Date().toISOString(), keys: [], failures: 0 };
    const code = this.issueCode(o);
    f.operators.push(o);
    this.save(f);
    return code;
  }

  /** Revoke every key and issue a fresh code (lost device, suspected compromise). */
  reset(id: string): string {
    return this.update(id, (o) => {
      const now = new Date().toISOString();
      for (const k of o.keys) k.revokedAt ??= now;
      return this.issueCode(o);
    });
  }

  setRole(id: string, role: Role) {
    if (!ROLES.includes(role)) throw new StoreError(`role must be one of ${ROLES.join(", ")}`);
    this.update(id, (o) => void (o.role = role));
  }

  setDisabled(id: string, disabled: boolean) {
    this.update(id, (o) => void (o.disabled = disabled));
  }

  isLocked(o: OperatorRecord, now = Date.now()) {
    return !!o.lockedUntil && Date.parse(o.lockedUntil) > now;
  }

  recordFailure(id: string) {
    this.update(id, (o) => {
      o.failures += 1;
      if (o.failures >= MAX_FAILURES) {
        o.lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60_000).toISOString();
        o.failures = 0;
      }
    });
  }

  recordSuccess(id: string) {
    this.update(id, (o) => {
      o.failures = 0;
      o.lockedUntil = undefined;
    });
  }

  /** Constant-time check of a one-time code. Does not consume it. */
  codeMatches(o: OperatorRecord, code: string, now = Date.now()): boolean {
    if (!o.enrollment || Date.parse(o.enrollment.expiresAt) <= now) return false;
    const expected = Buffer.from(o.enrollment.hash, "hex");
    const got = hashCode(code, Buffer.from(o.enrollment.salt, "hex"));
    return expected.length === got.length && timingSafeEqual(expected, got);
  }

  /**
   * Record a security key's signature counter. A counter that does not move forward means two
   * devices hold the same credential (a cloned key), so the use is refused. Keys that always
   * report 0 do not keep a counter and are exempt.
   */
  advanceSignCount(id: string, keyId: string, count: number) {
    this.update(id, (o) => {
      const k = o.keys.find((x) => x.keyId === keyId);
      if (!k) throw new StoreError("unknown key");
      if (count === 0 && !k.signCount) return;
      if (count <= (k.signCount ?? 0)) throw new StoreError("security key counter went backwards: possible cloned key. The key is refused; reset the operator.");
      k.signCount = count;
    });
  }

  bindCert(id: string, cert: Omit<CertBinding, "boundAt">) {
    this.update(id, (o) => void (o.clientCert = { ...cert, boundAt: new Date().toISOString() }));
  }

  unbindCert(id: string) {
    this.update(id, (o) => void (o.clientCert = undefined));
  }

  /** Bind a public key and burn the enrollment code. */
  bindKey(id: string, key: Omit<OperatorKey, "addedAt">) {
    this.update(id, (o) => {
      if (o.keys.some((k) => k.keyId === key.keyId && !k.revokedAt)) throw new StoreError("key already registered");
      o.keys.push({ ...key, addedAt: new Date().toISOString() });
      o.enrollment = undefined;
      o.failures = 0;
      o.lockedUntil = undefined;
    });
  }
}
