// Operator signing keys, kept in this browser's IndexedDB as non-extractable CryptoKeys, or
// (Phase 7) a reference to a FIDO2 security key registered for this operator.
// Script on the page can ask the browser to *use* the private key, but can never read it
// out, so a stolen copy of the database or a copied session cookie cannot sign elsewhere.

import { SIGN_ALG } from "../../core/identity";

export interface SoftwareKey {
  kind?: "software";
  operatorId: string;
  keyId: string;
  publicKeyJwk: JsonWebKey;
  keyPair: CryptoKeyPair;
}

/** A FIDO2 security key: only a reference is stored here; the private key never leaves the device. */
export interface SecurityKeyRef {
  kind: "webauthn";
  operatorId: string;
  keyId: string;
  publicKeyJwk: JsonWebKey;
  credentialId: string;
  rpId: string;
}

export type StoredKey = SoftwareKey | SecurityKeyRef;

const DB = "odin-keys";
const STORE = "keys";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE, { keyPath: "operatorId" });
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = fn(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

/** New P-256 key pair. The private key is created non-extractable and never leaves the browser. */
export async function generateKeyPair(): Promise<{ keyPair: CryptoKeyPair; publicKeyJwk: JsonWebKey }> {
  const keyPair = (await crypto.subtle.generateKey(SIGN_ALG, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return { keyPair, publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}

export const saveKey = (k: StoredKey) => tx("readwrite", (s) => s.put(k));
export const loadKey = (operatorId: string) => tx<StoredKey | undefined>("readonly", (s) => s.get(operatorId));
export const enrolledIds = () => tx("readonly", (s) => s.getAllKeys()).then((ks) => ks.map(String).sort());
