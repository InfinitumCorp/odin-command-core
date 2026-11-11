// Firmament Network (MIL) stand-in: an append-only, hash-chained record of every
// decision and order. Each entry commits to the previous entry's hash, so editing
// or deleting any past entry breaks verification from that point on.

import { sha256 } from "./sha256";
import type { LedgerEntry } from "./types";

export const GENESIS = "0".repeat(64);

/** Deterministic JSON: object keys sorted, so the same entry always hashes the same. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`)
    .join(",")}}`;
}

function hashEntry(e: Omit<LedgerEntry, "hash">): string {
  return sha256(canonical({ seq: e.seq, t: e.t, actor: e.actor, action: e.action, payload: e.payload, prev: e.prev }));
}

export function append(
  ledger: LedgerEntry[],
  t: number,
  actor: string,
  action: string,
  payload: Record<string, unknown>,
): LedgerEntry[] {
  const prev = ledger.length ? ledger[ledger.length - 1].hash : GENESIS;
  const base = { seq: ledger.length, t, actor, action, payload, prev };
  return [...ledger, { ...base, hash: hashEntry(base) }];
}

export type Verification = { ok: true; length: number } | { ok: false; brokenAt: number; reason: string };

export function verify(ledger: LedgerEntry[]): Verification {
  let prev = GENESIS;
  for (let i = 0; i < ledger.length; i++) {
    const e = ledger[i];
    if (e.seq !== i) return { ok: false, brokenAt: i, reason: "sequence gap" };
    if (e.prev !== prev) return { ok: false, brokenAt: i, reason: "chain link mismatch" };
    if (hashEntry(e) !== e.hash) return { ok: false, brokenAt: i, reason: "entry contents altered" };
    prev = e.hash;
  }
  return { ok: true, length: ledger.length };
}
